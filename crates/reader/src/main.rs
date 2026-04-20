use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

mod config;
use config::Config;

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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config_path = parse_args();

    let config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to load config from {}: {}", config_path.display(), e);
            std::process::exit(1);
        }
    };

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

    tokio::select! {
        _ = accept_loop(listener, semaphore) => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
    }

    info!("usenet-ipfs-reader stopped");
}

async fn accept_loop(listener: TcpListener, semaphore: Arc<Semaphore>) {
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

        tokio::spawn(async move {
            let _permit = permit; // released when session task ends
            info!(%peer_addr, "session started");
            // Session stub: log and drop — full NNTP state machine is future work.
            drop(stream);
            info!(%peer_addr, "session ended");
        });
    }
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    // SAFETY: signal() is safe to call; it only registers an OS signal handler.
    let mut stream = signal(SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    stream.recv().await;
}
