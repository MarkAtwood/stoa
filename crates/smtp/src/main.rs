use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::net::TcpListener;
use tracing::{error, info};

use usenet_ipfs_smtp::{
    config::Config,
    queue::NntpQueue,
    server::run_server,
    session::new_sieve_cache,
    sieve_admin, store,
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
        max_connections = config.limits.max_connections,
        "usenet-ipfs-smtp starting"
    );

    // Create the durable NNTP queue and start the drain task.
    let nntp_queue = match NntpQueue::new(&config.delivery.queue_dir) {
        Ok(q) => q,
        Err(e) => {
            error!("failed to create NNTP queue dir {}: {e}", config.delivery.queue_dir);
            std::process::exit(1);
        }
    };
    let retry_interval = Duration::from_secs(config.delivery.nntp_retry_secs);
    Arc::clone(&nntp_queue).start_drain(config.reader.nntp_addr.clone(), retry_interval);

    let config = Arc::new(config);

    // Create the Sieve script cache (shared by sessions and the admin API).
    let sieve_cache = if pool.is_some() { Some(new_sieve_cache()) } else { None };

    // Start the Sieve admin HTTP API when local users are configured.
    if let Some(ref admin_pool) = pool {
        let admin_config = Arc::clone(&config);
        let admin_pool = admin_pool.clone();
        let admin_cache = sieve_cache.clone().expect("cache is Some when pool is Some");
        if let Err(e) = sieve_admin::start_sieve_admin_server(admin_config, admin_pool, admin_cache)
        {
            eprintln!("error: sieve admin server: {e}");
            std::process::exit(1);
        }
    }

    tokio::select! {
        _ = run_server(listener_25, listener_587, config, nntp_queue, pool, sieve_cache) => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
    }

    info!("usenet-ipfs-smtp stopped");
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
