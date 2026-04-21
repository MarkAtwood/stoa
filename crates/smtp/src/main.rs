use std::{path::PathBuf, sync::Arc};

use tokio::net::TcpListener;
use tracing::{error, info, warn};

use usenet_ipfs_smtp::{config::Config, queue::MessageQueue, server::run_server};

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

    info!(
        port_25 = %config.listen.port_25,
        port_587 = %config.listen.port_587,
        max_connections = config.limits.max_connections,
        "usenet-ipfs-smtp starting"
    );

    let config = Arc::new(config);
    let (queue, mut rx) = MessageQueue::new();

    // Drain the incoming message queue.  In v1 we log each message; routing to
    // newsgroups / JMAP mailboxes is implemented in the zzo.3 / zzo.5 epics.
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            warn!(
                from = %msg.envelope_from,
                to = ?msg.envelope_to,
                bytes = msg.raw_bytes.len(),
                "queued message (delivery not yet implemented)"
            );
        }
    });

    tokio::select! {
        _ = run_server(listener_25, listener_587, config, queue) => {}
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
