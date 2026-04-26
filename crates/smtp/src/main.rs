use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::net::TcpListener;
use tracing::{error, info};

use stoa_smtp::{
    config::Config, nntp_client::NntpClientConfig, queue::NntpQueue, server::run_server,
    session::new_sieve_cache, sieve_admin, store, tls::build_tls_acceptor,
};

fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" {
            if let Some(path) = args.get(i + 1) {
                return PathBuf::from(path);
            }
            eprintln!("error: --config requires a path argument");
            std::process::exit(1);
        }
        i += 1;
    }
    eprintln!("error: --config <path> is required");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let config_path = parse_args();

    let config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: failed to load config from {}: {}",
                config_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log.level));

    if config.log.format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let listener_25 = match TcpListener::bind(&config.listen.port_25).await {
        Ok(l) => l,
        Err(e) => {
            error!("failed to bind port_25 {}: {e}", config.listen.port_25);
            std::process::exit(1);
        }
    };

    let listener_587 = match TcpListener::bind(&config.listen.port_587).await {
        Ok(l) => l,
        Err(e) => {
            error!("failed to bind port_587 {}: {e}", config.listen.port_587);
            std::process::exit(1);
        }
    };

    // Bind the optional SMTPS (port 465 implicit TLS) listener and build the
    // TLS acceptor.  Both must succeed or startup aborts — a partially-bound
    // server would silently drop SMTPS connections.
    let listener_smtps = if let Some(ref smtps_addr) = config.listen.smtps_addr {
        let cert_path = config.tls.cert_path.as_deref().unwrap_or("");
        let key_path = config.tls.key_path.as_deref().unwrap_or("");
        let acceptor = if key_path.starts_with("secretx:") {
            let store = match secretx::from_uri(key_path) {
                Ok(s) => s,
                Err(e) => {
                    error!("tls.key_path: invalid secretx URI: {e}");
                    std::process::exit(1);
                }
            };
            let secret = match store.get().await {
                Ok(v) => v,
                Err(e) => {
                    error!("tls.key_path: secretx retrieval failed: {e}");
                    std::process::exit(1);
                }
            };
            match stoa_smtp::tls::build_tls_acceptor_with_key_bytes(
                cert_path,
                secret.as_bytes(),
                key_path,
            ) {
                Ok(a) => a,
                Err(e) => {
                    error!("failed to build SMTPS TLS acceptor: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            match build_tls_acceptor(cert_path, key_path) {
                Ok(a) => a,
                Err(e) => {
                    error!("failed to build SMTPS TLS acceptor: {e}");
                    std::process::exit(1);
                }
            }
        };
        match TcpListener::bind(smtps_addr).await {
            Ok(l) => Some((l, acceptor)),
            Err(e) => {
                error!("failed to bind smtps_addr {smtps_addr}: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Open the Sieve delivery database only when local users are configured.
    let pool = if !config.users.is_empty() {
        match store::open(&config.database.path).await {
            Ok(p) => {
                info!(path = %config.database.path, "Sieve delivery database opened");
                Some(p)
            }
            Err(e) => {
                error!("failed to open database {}: {e}", config.database.path);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    info!(
        port_25 = %config.listen.port_25,
        port_587 = %config.listen.port_587,
        smtps = %config.listen.smtps_addr.as_deref().unwrap_or("disabled"),
        max_connections = config.limits.max_connections,
        "stoa-smtp starting"
    );

    // Create the durable NNTP queue and start the drain task.
    let nntp_queue = match NntpQueue::new(&config.delivery.queue_dir) {
        Ok(q) => q,
        Err(e) => {
            error!(
                "failed to create NNTP queue dir {}: {e}",
                config.delivery.queue_dir
            );
            std::process::exit(1);
        }
    };
    let retry_interval = Duration::from_secs(config.delivery.nntp_retry_secs);
    let nntp_config = NntpClientConfig {
        addr: config.reader.nntp_addr.clone(),
        username: config.reader.nntp_username.clone(),
        password: config.reader.nntp_password.clone(),
        max_retries: config.reader.nntp_max_retries,
    };
    Arc::clone(&nntp_queue).start_drain(nntp_config, retry_interval);

    let config = Arc::new(config);

    // Create the Sieve script cache (shared by sessions and the admin API).
    let sieve_cache = if pool.is_some() {
        Some(new_sieve_cache())
    } else {
        None
    };

    // Start the Sieve admin HTTP API when local users are configured.
    if let Some(ref admin_pool) = pool {
        let admin_config = Arc::clone(&config);
        let admin_pool = admin_pool.clone();
        let admin_cache = sieve_cache
            .clone()
            .expect("cache is Some when pool is Some");
        if let Err(e) = sieve_admin::start_sieve_admin_server(admin_config, admin_pool, admin_cache)
        {
            eprintln!("error: sieve admin server: {e}");
            std::process::exit(1);
        }
    }

    tokio::select! {
        _ = run_server(listener_25, listener_587, listener_smtps, config, nntp_queue, pool, sieve_cache) => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
    }

    info!("stoa-smtp stopped");
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
