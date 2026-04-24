use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use usenet_ipfs_reader::{
    admin::start_admin_server,
    config::Config,
    session::lifecycle::run_session,
    store::{backfill::backfill_overview, server_stores::ServerStores},
    tls::TlsAcceptor,
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

    let listener = match TcpListener::bind(&config.listen.addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("failed to bind to {}: {}", config.listen.addr, e);
            std::process::exit(1);
        }
    };

    info!(
        listen_addr = %config.listen.addr,
        max_connections = config.limits.max_connections,
        "usenet-ipfs-reader starting"
    );

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
        (Some(cert), Some(key)) => match usenet_ipfs_reader::tls::load_tls_acceptor(cert, key) {
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
            let sem2 = Arc::new(Semaphore::new(config.limits.max_connections));
            Box::pin(accept_loop_tls(
                tls_listener,
                sem2,
                config.clone(),
                stores.clone(),
                nntps_acceptor,
            ))
        } else {
            Box::pin(std::future::pending())
        };

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

    info!("usenet-ipfs-reader stopped");
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
