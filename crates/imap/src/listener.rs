//! TCP accept loops for plain IMAP and implicit-TLS IMAPS connections.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::{config::Config, session::run_session_plain, session::run_session_tls};

/// Run the plain-text IMAP listener on `config.listen.addr`.
///
/// Each accepted connection is spawned as a new tokio task calling
/// [`run_session_plain`].  Accepts forever; returns only on bind failure
/// (which panics at startup).
pub async fn run_plain_listener(config: Arc<Config>, pool: Arc<sqlx::SqlitePool>) {
    let listener = match TcpListener::bind(&config.listen.addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %config.listen.addr, "failed to bind IMAP listener: {e}");
            panic!("fatal: could not bind IMAP plain listener");
        }
    };
    info!(addr = %config.listen.addr, "IMAP plain listener ready");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let config = config.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    run_session_plain(stream, peer, config, pool).await;
                });
            }
            Err(e) => error!("IMAP plain accept error: {e}"),
        }
    }
}

/// Run the implicit-TLS IMAPS listener on `config.listen.tls_addr`.
///
/// Each accepted connection undergoes a TLS handshake before being handed
/// to [`run_session_tls`].  If the handshake fails the connection is dropped
/// with a warning.  Called only when `config.listen.tls_addr` is `Some`.
pub async fn run_tls_listener(
    config: Arc<Config>,
    tls_acceptor: Arc<TlsAcceptor>,
    pool: Arc<sqlx::SqlitePool>,
) {
    let addr = match config.listen.tls_addr.as_deref() {
        Some(a) => a,
        None => {
            error!("run_tls_listener called but listen.tls_addr is not configured");
            return;
        }
    };

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(%addr, "failed to bind IMAPS listener: {e}");
            panic!("fatal: could not bind IMAP TLS listener");
        }
    };
    info!(%addr, "IMAPS TLS listener ready");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let config = config.clone();
                let pool = pool.clone();
                let acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            run_session_tls(tls_stream, peer, config, pool).await;
                        }
                        Err(e) => warn!(%peer, "IMAPS TLS handshake failed: {e}"),
                    }
                });
            }
            Err(e) => error!("IMAPS TLS accept error: {e}"),
        }
    }
}
