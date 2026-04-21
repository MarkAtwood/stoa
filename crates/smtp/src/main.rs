use std::{path::PathBuf, sync::Arc};

use tokio::net::TcpListener;
use tracing::{error, info, warn};

use usenet_ipfs_smtp::{
    config::Config,
    nntp_client, routing, store,
    queue::{IncomingMessage, MessageQueue},
    server::run_server,
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

    let config = Arc::new(config);
    let (queue, mut rx) = MessageQueue::new();

    let routing_config = Arc::clone(&config);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            route_message(msg, &routing_config).await;
        }
    });

    tokio::select! {
        _ = run_server(listener_25, listener_587, config, queue, pool) => {}
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

async fn route_message(msg: IncomingMessage, config: &Config) {
    if let Some(list_id) = routing::extract_list_id(&msg.raw_bytes) {
        if let Some(newsgroup) = routing::apply_routing_rules(&list_id, &config.list_routing) {
            let article = routing::add_newsgroups_header(&msg.raw_bytes, &newsgroup);
            match nntp_client::post_article(&config.reader.nntp_addr, &article).await {
                Ok(()) => {
                    info!(list_id = %list_id, newsgroup = %newsgroup, "routed to newsgroup");
                }
                Err(e) => {
                    warn!(list_id = %list_id, newsgroup = %newsgroup, "NNTP POST failed: {e}");
                }
            }
            return;
        }
    }
    warn!(
        from = %msg.envelope_from,
        to = ?msg.envelope_to,
        "no routing rule matched — message dropped"
    );
}
