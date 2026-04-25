use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use stoa_reader::{
    admin::start_admin_server,
    config::Config,
    session::lifecycle::run_session,
    store::{backfill::backfill_overview, server_stores::ServerStores},
    tls::TlsAcceptor,
};

fn parse_args() -> (PathBuf, bool) {
    let args: Vec<String> = std::env::args().collect();

    // Subcommand dispatch: `stoa-reader keygen --output <path> [--force]`
    if args.get(1).map(|s| s.as_str()) == Some("keygen") {
        cmd_keygen(&args[2..]);
    }

    let mut config_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                if let Some(path) = args.get(i + 1) {
                    config_path = Some(PathBuf::from(path));
                    i += 2;
                } else {
                    eprintln!("error: --config requires a path argument");
                    std::process::exit(1);
                }
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    match config_path {
        Some(p) => (p, check_only),
        None => {
            eprintln!("error: --config <path> is required");
            std::process::exit(1);
        }
    }
}

async fn run_startup_checks(config: &Config) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    // Kubo reachability check (skipped for non-Kubo backends).
    if let Some(url) = config.kubo_api_url() {
        let url = url.to_owned();
        let client = stoa_core::ipfs::KuboHttpClient::new(&url);
        match tokio::time::timeout(Duration::from_secs(5), client.node_id()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                errors.push(format!(
                    "Kubo unreachable at {url}: {e} — is 'ipfs daemon' running?"
                ));
            }
            Err(_) => {
                errors.push(format!(
                    "Kubo unreachable at {url}: timed out after 5s — is 'ipfs daemon' running?"
                ));
            }
        }
    }

    // TLS file readability check.
    if let Some(cert) = config.tls.cert_path.as_deref() {
        if let Err(e) = std::fs::read(cert) {
            errors.push(format!("TLS file unreadable: {cert}: {e}"));
        }
    }
    if let Some(key) = config.tls.key_path.as_deref() {
        if let Err(e) = std::fs::read(key) {
            errors.push(format!("TLS file unreadable: {key}: {e}"));
        }
    }

    // Signing key check.
    if let Some(path) = config.operator.signing_key_path.as_deref() {
        if let Err(e) = stoa_core::signing::load_signing_key(std::path::Path::new(path)) {
            errors.push(e.to_string());
        }
    }

    // Admin bind address check.
    if config.admin.enabled {
        match TcpListener::bind(&config.admin.addr).await {
            Ok(_) => {}
            Err(e) => {
                errors.push(format!(
                    "Admin address {} already in use or invalid: {e}",
                    config.admin.addr
                ));
            }
        }
    }

    errors
}

/// Handle `stoa-reader keygen --output <path> [--force]`.
///
/// Generates a random 32-byte Ed25519 seed, writes it to `<path>` (mode 0600),
/// and prints the public key hex + HLC node ID to stdout.  Exits 0 on success,
/// 1 on any error.  Never returns — always calls `std::process::exit`.
fn cmd_keygen(args: &[String]) -> ! {
    let mut output: Option<&str> = None;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                output = args.get(i + 1).map(|s| s.as_str());
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => {
                eprintln!("error: unknown keygen argument: {other}");
                std::process::exit(1);
            }
        }
    }
    let output_path = match output {
        Some(p) => std::path::Path::new(p),
        None => {
            eprintln!("error: keygen requires --output <path>");
            std::process::exit(1);
        }
    };
    let key = stoa_core::signing::generate_signing_key();
    if let Err(e) = stoa_core::signing::write_signing_key(&key, output_path, force) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
    let node_id = stoa_core::signing::hlc_node_id(&key);
    let node_id_hex = hex::encode(node_id);
    println!("public_key: {pubkey_hex}");
    println!("node_id:    {node_id_hex}");
    println!("key_file:   {}", output_path.display());
    std::process::exit(0);
}

#[tokio::main]
async fn main() {
    let (config_path, check_only) = parse_args();

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

    let check_errors = run_startup_checks(&config).await;
    if !check_errors.is_empty() {
        for msg in &check_errors {
            eprintln!("error: {msg}");
        }
        std::process::exit(1);
    }
    if check_only {
        println!("startup checks passed");
        std::process::exit(0);
    }

    // Enforce signing_key_path for non-loopback deployments (zn0k).
    if config.operator.signing_key_path.is_none()
        && !stoa_reader::config::is_loopback_addr(&config.listen.addr)
    {
        eprintln!(
            "error: operator.signing_key_path must be set when listening on a non-loopback \
             address ({}). Run `stoa-reader keygen --output <path>` to generate \
             a key, then set [operator] signing_key_path in your config.",
            config.listen.addr
        );
        std::process::exit(1);
    }

    info!(
        listen_addr = %config.listen.addr,
        max_connections = config.limits.max_connections,
        "stoa-reader starting"
    );

    let listener = match TcpListener::bind(&config.listen.addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("failed to bind to {}: {}", config.listen.addr, e);
            std::process::exit(1);
        }
    };

    let semaphore = Arc::new(Semaphore::new(config.limits.max_connections));
    let stores = Arc::new(match ServerStores::new_with_ipfs(&config).await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to initialise stores: {e}");
            std::process::exit(1);
        }
    });

    let backfilled = backfill_overview(
        &stores.article_numbers,
        &stores.overview_store,
        stores.ipfs_store.as_ref(),
    )
    .await;
    if backfilled > 0 {
        info!(count = backfilled, "overview index backfill complete");
    }

    let config = Arc::new(config);

    // Load TLS acceptor once at startup. Cert load errors are fatal; they
    // are not discovered per-connection.
    let tls_acceptor: Option<Arc<TlsAcceptor>> = match (
        config.tls.cert_path.as_deref(),
        config.tls.key_path.as_deref(),
    ) {
        (Some(cert), Some(key)) => match stoa_reader::tls::load_tls_acceptor(cert, key) {
            Ok(a) => {
                info!(cert = cert, "TLS acceptor loaded");
                Some(Arc::new(a))
            }
            Err(e) => {
                error!("Failed to load TLS acceptor: {e}");
                std::process::exit(1);
            }
        },
        _ => None,
    };

    // Optional admin HTTP server.
    if config.admin.enabled {
        let admin_addr: std::net::SocketAddr = match config.admin.addr.parse() {
            Ok(a) => a,
            Err(e) => {
                error!("invalid admin.addr '{}': {}", config.admin.addr, e);
                std::process::exit(1);
            }
        };
        if let Err(e) = start_admin_server(
            admin_addr,
            std::time::Instant::now(),
            config.admin.admin_token.clone(),
            config.admin.rate_limit_rpm,
        ) {
            error!("{e}");
            std::process::exit(1);
        }
    }

    // Optional NNTPS listener (implicit TLS, port 563 by convention).
    let tls_listener_future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        if let Some(ref tls_addr) = config.tls.tls_addr {
            let tls_listener = match TcpListener::bind(tls_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("failed to bind NNTPS listener to {}: {}", tls_addr, e);
                    std::process::exit(1);
                }
            };
            info!(tls_addr = %tls_addr, "NNTPS (implicit TLS) listener started");
            let nntps_acceptor = match tls_acceptor.clone() {
                Some(a) => a,
                None => {
                    error!("NNTPS listener configured but no TLS cert/key provided");
                    std::process::exit(1);
                }
            };
            Box::pin(accept_loop_tls(
                tls_listener,
                Arc::clone(&semaphore),
                config.clone(),
                stores.clone(),
                nntps_acceptor,
            ))
        } else {
            Box::pin(std::future::pending())
        };

    // Retain handles for the drain phase after shutdown signal.
    let semaphore_drain = Arc::clone(&semaphore);
    let max_connections = config.limits.max_connections;
    let drain_timeout_secs = config.limits.drain_timeout_secs.unwrap_or(30);

    tokio::select! {
        _ = accept_loop(listener, semaphore, config, stores, tls_acceptor) => {}
        _ = tls_listener_future => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
    }

    // Drain: wait for all in-flight sessions to release their semaphore permits.
    let active = max_connections - semaphore_drain.available_permits();
    if active > 0 {
        info!(active_connections = active, "draining active connections");
        let drain_result = tokio::time::timeout(
            std::time::Duration::from_secs(drain_timeout_secs),
            semaphore_drain.acquire_many(max_connections as u32),
        )
        .await;
        match drain_result {
            Ok(_) => {
                info!("all connections drained cleanly");
            }
            Err(_) => {
                let remaining = max_connections - semaphore_drain.available_permits();
                warn!(
                    remaining_connections = remaining,
                    "drain timeout exceeded, forcing exit"
                );
                std::process::exit(1);
            }
        }
    }

    info!("stoa-reader stopped");
}

async fn accept_loop(
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    config: Arc<Config>,
    stores: Arc<ServerStores>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) {
    loop {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                warn!("semaphore closed, stopping accept loop");
                break;
            }
        };

        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!("accept error: {}", e);
                drop(permit);
                continue;
            }
        };

        let config = config.clone();
        let stores = stores.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            run_session(stream, false, &config, stores, tls_acceptor).await;
            info!(%peer_addr, "connection closed");
        });
    }
}

/// Accept loop for NNTPS (implicit TLS, port 563).
///
/// Each accepted TCP stream is passed to `run_session` with `is_tls = true`,
/// which performs the TLS handshake before the NNTP greeting.
async fn accept_loop_tls(
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    config: Arc<Config>,
    stores: Arc<ServerStores>,
    tls_acceptor: Arc<TlsAcceptor>,
) {
    loop {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                warn!("semaphore closed, stopping NNTPS accept loop");
                break;
            }
        };

        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!("NNTPS accept error: {}", e);
                drop(permit);
                continue;
            }
        };

        let config = config.clone();
        let stores = stores.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            run_session(stream, true, &config, stores, Some(tls_acceptor)).await;
            info!(%peer_addr, "NNTPS connection closed");
        });
    }
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    // SAFETY: signal() is safe to call; it only registers an OS signal handler.
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
