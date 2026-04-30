use std::{path::PathBuf, sync::Arc, time::Instant};

use stoa_mail::{
    config::{Config, LogFormat},
    server::AppState,
    token_store::TokenStore,
};
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

    if config.log.format == LogFormat::Json {
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

    let credential_store = match stoa_auth::build_credential_store(
        &config.auth.users,
        config.auth.credential_file.as_deref(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to build credential store: {e}");
            std::process::exit(1);
        }
    };

    match (config.tls.cert_path.as_deref(), config.tls.key_path.as_deref()) {
        (Some(cert), Some(key)) => {
            if key.starts_with("secretx:") {
                let store = match secretx::from_uri(key) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("error: tls.key_path: invalid secretx URI: {e}");
                        std::process::exit(1);
                    }
                };
                let secret = match store.get().await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("error: tls.key_path: secretx retrieval failed: {e}");
                        std::process::exit(1);
                    }
                };
                if let Err(e) =
                    stoa_tls::load_tls_server_config_with_key_bytes(cert, secret.as_bytes(), key)
                {
                    eprintln!("error: failed to load TLS configuration: {e}");
                    std::process::exit(1);
                }
            } else if let Err(e) = stoa_tls::load_tls_server_config(cert, key) {
                eprintln!("error: failed to load TLS configuration: {e}");
                std::process::exit(1);
            }
            info!(cert, "TLS configuration loaded");
        }
        _ => {}
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
        activitypub: None,
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
