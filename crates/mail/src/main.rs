use std::{path::PathBuf, sync::Arc, time::Instant};

use stoa_auth::CredentialStore;
use stoa_mail::{config::Config, server::AppState, token_store::TokenStore};
use tracing::info;

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
    sqlx::any::install_default_drivers();
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

    info!(listen_addr = %addr, "stoa-mail starting");

    let mut credential_store = CredentialStore::from_credentials(&config.auth.users);
    if let Some(ref path) = config.auth.credential_file {
        if path.starts_with("secretx:") {
            let store = match secretx::from_uri(path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: auth.credential_file: invalid secretx URI: {e}");
                    std::process::exit(1);
                }
            };
            let secret = match store.get().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: auth.credential_file: secretx retrieval failed: {e}");
                    std::process::exit(1);
                }
            };
            let content = match secret.as_str() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: auth.credential_file: secretx value not valid UTF-8: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = credential_store.merge_from_content(path, content) {
                eprintln!("error: failed to parse credential file from secretx: {e}");
                std::process::exit(1);
            }
        } else if let Err(e) = credential_store.merge_from_file(path) {
            eprintln!("error: failed to load credential file '{}': {}", path, e);
            std::process::exit(1);
        }
    }

    if let Err(e) = stoa_mail::migrations::run_migrations(&config.database.url).await {
        eprintln!("error: database migration failed: {}", e);
        std::process::exit(1);
    }

    let pool = match stoa_core::db_pool::try_open_any_pool(&config.database.url, 5).await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!(
                "error: failed to open database '{}': {}",
                config.database.url, e
            );
            std::process::exit(1);
        }
    };

    let token_store = Arc::new(TokenStore::new(pool));

    let oidc_store = if config.auth.oidc_providers.is_empty() {
        None
    } else {
        Some(Arc::new(stoa_auth::OidcStore::new(
            config.auth.oidc_providers.clone(),
        )))
    };

    let state = Arc::new(AppState {
        start_time,
        jmap: None,
        credential_store: Arc::new(credential_store),
        auth_config: Arc::new(config.auth),
        token_store,
        oidc_store,
        base_url: config.listen.base_url.clone(),
        cors: config.cors.clone(),
        slow_jmap_threshold_ms: config.log.slow_jmap_threshold_ms,
        activitypub_config: config.activitypub,
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

    if let Err(e) = stoa_mail::server::run_server(addr, state, shutdown).await {
        eprintln!("error: server failed: {e}");
        std::process::exit(1);
    }

    info!("stoa-mail stopped");
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
