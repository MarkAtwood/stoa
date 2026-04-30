use std::{path::PathBuf, sync::Arc};

use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use stoa_imap::{
    config::{Config, LogFormat},
    listener::{run_plain_listener, run_tls_listener},
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

    if config.log.format == LogFormat::Json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    info!(addr = %config.listen.addr, "stoa-imap starting");

    // Open SQLite pool and run migrations.
    let db_url = format!("sqlite:{}?mode=rwc", config.database.path);
    let pool = match sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            error!(
                "failed to open IMAP database at {}: {e}",
                config.database.path
            );
            std::process::exit(1);
        }
    };

    if let Err(e) = sqlx::migrate!("./migrations").run(&*pool).await {
        error!("IMAP database migration failed: {e}");
        std::process::exit(1);
    }

    // Build TLS acceptor if cert and key are configured.
    let tls_acceptor: Option<Arc<TlsAcceptor>> = match (
        config.tls.cert_path.as_deref(),
        config.tls.key_path.as_deref(),
    ) {
        (Some(cert), Some(key)) => match stoa_tls::load_tls_server_config(cert, key) {
            Ok(server_config) => {
                info!(cert, "IMAP TLS acceptor loaded");
                Some(Arc::new(TlsAcceptor::from(server_config)))
            }
            Err(e) => {
                error!("failed to load TLS configuration: {e}");
                std::process::exit(1);
            }
        },
        _ => None,
    };

    // Semaphore enforces config.limits.max_connections across both listeners.
    let semaphore = Arc::new(Semaphore::new(config.limits.max_connections));

    // Build the credential store once; all sessions share it so the dummy
    // hash is computed only once rather than per-connection.
    let credential_store = Arc::new(match build_credential_store(&config.auth).await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to build credential store: {e}");
            std::process::exit(1);
        }
    });
    let config = Arc::new(config);

    // Optional IMAPS (implicit TLS) listener.
    let tls_future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        if config.listen.tls_addr.is_some() {
            match tls_acceptor.clone() {
                Some(acceptor) => Box::pin(run_tls_listener(
                    config.clone(),
                    acceptor,
                    pool.clone(),
                    semaphore.clone(),
                    credential_store.clone(),
                )),
                None => {
                    error!("listen.tls_addr is set but tls.cert_path/key_path are not configured");
                    std::process::exit(1);
                }
            }
        } else {
            Box::pin(std::future::pending())
        };

    tokio::select! {
        _ = run_plain_listener(config.clone(), pool, semaphore, credential_store) => {}
        _ = tls_future => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
    }

    info!("stoa-imap stopped");
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}

/// Error returned by [`build_credential_store`].
#[derive(Debug, thiserror::Error)]
enum BuildStoreError {
    #[error(transparent)]
    Credentials(#[from] stoa_auth::CredentialStoreError),
    #[error("{0}")]
    Secretx(String),
}

/// Build a `CredentialStore` from the `[auth]` section of the config.
///
/// Loads inline `users` first, then merges any entries from `credential_file`
/// (file entries override inline entries with the same username).
///
/// `credential_file` may be either a filesystem path or a `secretx:` URI.
/// When it is a `secretx:` URI, the secret is fetched and its text content is
/// parsed as a credential file; no filesystem access is performed.
async fn build_credential_store(
    auth: &stoa_imap::config::AuthConfig,
) -> Result<stoa_auth::CredentialStore, String> {
    build_credential_store_inner(auth)
        .await
        .map_err(|e| e.to_string())
}

async fn build_credential_store_inner(
    auth: &stoa_imap::config::AuthConfig,
) -> Result<stoa_auth::CredentialStore, BuildStoreError> {
    let mut store = stoa_auth::CredentialStore::from_credentials(&auth.users);
    if let Some(path) = &auth.credential_file {
        if path.starts_with("secretx:") {
            let secret_store = secretx::from_uri(path).map_err(|e| {
                BuildStoreError::Secretx(format!("auth.credential_file: invalid secretx URI: {e}"))
            })?;
            let secret = secret_store.get().await.map_err(|e| {
                BuildStoreError::Secretx(format!(
                    "auth.credential_file: secretx retrieval failed: {e}"
                ))
            })?;
            let content = secret.as_str().map_err(|e| {
                BuildStoreError::Secretx(format!(
                    "auth.credential_file: secretx value not valid UTF-8: {e}"
                ))
            })?;
            store.merge_from_content(path, content)?;
        } else {
            store.merge_from_file(path)?;
        }
    }
    Ok(store)
}
