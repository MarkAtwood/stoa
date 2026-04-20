//! TLS acceptor for the NNTP listener.
//!
//! When TLS is configured, wraps the TCP stream in a rustls ServerConnection.
//! The `NntpStream` enum unifies plain and TLS streams so the session handler
//! does not need to know which variant is active.

use std::{fs::File, io::BufReader, sync::Arc};

use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};

/// Errors produced during TLS setup or handshake.
#[derive(Debug)]
pub enum TlsError {
    /// Failed to read or parse the certificate file.
    CertLoad(String, std::io::Error),
    /// Failed to read or parse the private key file.
    KeyLoad(String, std::io::Error),
    /// Failed to build the rustls `ServerConfig`.
    Config(rustls::Error),
    /// TLS handshake with the client failed.
    Handshake(std::io::Error),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::CertLoad(path, e) => {
                write!(f, "failed to load TLS certificate from '{path}': {e}")
            }
            TlsError::KeyLoad(path, e) => {
                write!(f, "failed to load TLS private key from '{path}': {e}")
            }
            TlsError::Config(e) => write!(f, "TLS server config error: {e}"),
            TlsError::Handshake(e) => write!(f, "TLS handshake failed: {e}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::CertLoad(_, e) | TlsError::KeyLoad(_, e) | TlsError::Handshake(e) => {
                Some(e)
            }
            TlsError::Config(e) => Some(e),
        }
    }
}

/// A rustls-backed TLS acceptor for incoming TCP connections.
pub struct TlsAcceptor {
    inner: tokio_rustls::TlsAcceptor,
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

/// Build a `TlsAcceptor` from PEM certificate and private-key files.
///
/// The resulting `ServerConfig` requires TLS 1.2 or higher; TLS 1.0 and 1.1
/// are not offered.
pub fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, TlsError> {
    // --- Load certificate chain ---
    let cert_file = File::open(cert_path)
        .map_err(|e| TlsError::CertLoad(cert_path.to_string(), e))?;
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::CertLoad(cert_path.to_string(), e))?;

    // --- Load private key ---
    let key_file = File::open(key_path)
        .map_err(|e| TlsError::KeyLoad(key_path.to_string(), e))?;
    let private_key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| TlsError::KeyLoad(key_path.to_string(), e))?
        .ok_or_else(|| {
            TlsError::KeyLoad(
                key_path.to_string(),
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key found in PEM"),
            )
        })?;

    // --- Build ServerConfig with minimum TLS 1.2 ---
    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)
    .map_err(TlsError::Config)?;

    Ok(TlsAcceptor {
        inner: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
    })
}

/// Perform the TLS handshake on an already-accepted TCP stream.
pub async fn accept_tls(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, TlsError> {
    acceptor.inner.accept(stream).await.map_err(TlsError::Handshake)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_tls_acceptor_missing_cert_returns_error() {
        let result = load_tls_acceptor("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertLoad(path, _) => assert!(path.contains("cert.pem")),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn tls_error_display_is_informative() {
        let e = TlsError::CertLoad(
            "/foo/cert.pem".into(),
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        );
        let msg = e.to_string();
        assert!(msg.contains("/foo/cert.pem"), "display: {msg}");
    }
}
