use std::{path::PathBuf, sync::Arc, time::Instant};

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr as _;
use tracing::info;
use usenet_ipfs_auth::CredentialStore;
use usenet_ipfs_mail::{config::Config, server::AppState, token_store::TokenStore};

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
    let start_time = Instant::now();
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

    let addr = match config.listen.addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: invalid listen addr '{}': {e}", config.listen.addr);
            std::process::exit(1);
        }
    };

    info!(listen_addr = %addr, "usenet-ipfs-mail starting");

    let mut credential_store = CredentialStore::from_credentials(&config.auth.users);
    if let Some(ref path) = config.auth.credential_file {
        if let Err(e) = credential_store.merge_from_file(path) {
            eprintln!("error: failed to load credential file '{}': {}", path, e);
            std::process::exit(1);
        }
    }

    let db_url = format!("sqlite:{}", config.database.path);
    let db_opts = match SqliteConnectOptions::from_str(&db_url) {
        Ok(o) => o.create_if_missing(true),
        Err(e) => {
            eprintln!(
                "error: invalid database path '{}': {}",
                config.database.path, e
            );
            std::process::exit(1);
        }
    };
    let pool = match SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(db_opts)
        .await
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!(
                "error: failed to open database '{}': {}",
                config.database.path, e
            );
            std::process::exit(1);
        }
    };

    if let Err(e) = usenet_ipfs_mail::migrations::run_migrations(&pool).await {
        eprintln!("error: database migration failed: {}", e);
        std::process::exit(1);
    }

    let token_store = Arc::new(TokenStore::new(pool));

    let state = Arc::new(AppState {
        start_time,
        jmap: None,
        credential_store: Arc::new(credential_store),
        auth_config: Arc::new(config.auth),
        token_store,
        base_url: config.listen.base_url.clone(),
    });

    let shutdown = async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received CTRL-C, shutting down");
            }
            _ = sigterm() => {
                info!("received SIGTERM, shutting down");
            }
        }
    };

    if let Err(e) = usenet_ipfs_mail::server::run_server(addr, state, shutdown).await {
        eprintln!("error: server failed: {e}");
        std::process::exit(1);
    }

    info!("usenet-ipfs-mail stopped");
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
