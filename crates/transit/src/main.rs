mod config;

use config::Config;
use std::path::PathBuf;
use tracing::{error, info};

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

    info!(
        listen_addr = %config.listen.addr,
        peer_count = config.peers.addresses.len(),
        group_count = config.groups.names.len(),
        "usenet-ipfs-transit starting"
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
    }

    info!("usenet-ipfs-transit stopped");
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    // SAFETY: signal() is safe to call; it only registers an OS signal handler.
    let mut stream = signal(SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    stream.recv().await;
}
