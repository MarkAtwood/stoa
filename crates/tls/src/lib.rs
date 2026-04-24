//! Shared TLS configuration loader for stoa servers.
//!
//! Provides a single implementation of PEM certificate and private-key
//! loading, shared by the SMTP, JMAP, and NNTP reader crates. Centralising
//! the logic here means a rustls API change (version bump, different PEM
//! loading API) is applied in one place.

use std::{fs::File, io::BufReader, sync::Arc};

use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};

/// Errors produced while loading TLS configuration from PEM files.
#[derive(Debug)]
pub enum TlsError {
    /// Failed to open or parse the certificate file.
    CertLoad(String, std::io::Error),
    /// Failed to open or parse the private key file.
    KeyLoad(String, std::io::Error),
    /// Failed to build the rustls `ServerConfig`.
    Config(rustls::Error),
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
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::CertLoad(_, e) | TlsError::KeyLoad(_, e) => Some(e),
            TlsError::Config(e) => Some(e),
        }
    }
}

/// Load PEM certificate and private-key files and return a
/// `rustls::ServerConfig` wrapped in an `Arc`.
///
/// The resulting config requires TLS 1.2 or higher; TLS 1.0 and 1.1 are not
/// offered. Client authentication is not requested (use
/// [`load_cert_chain`] and [`load_private_key`] if you need to customise the
/// client-auth verifier, as the NNTP reader does for mutual TLS).
pub fn load_tls_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_chain = load_cert_chain(cert_path)?;
    let private_key = load_private_key(key_path)?;

    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)
    .map_err(TlsError::Config)?;

    Ok(Arc::new(config))
}

/// Load a PEM certificate chain from `cert_path`.
///
/// Exposed for crates (e.g. the NNTP reader) that need to supply a custom
/// client-auth verifier and therefore must build their own `ServerConfig`.
pub fn load_cert_chain(
    cert_path: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TlsError> {
    let file = File::open(cert_path).map_err(|e| TlsError::CertLoad(cert_path.to_string(), e))?;
    certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertLoad(cert_path.to_string(), e))
}

/// Load a PEM private key from `key_path`.
///
/// Exposed for crates that need to build their own `ServerConfig`.
pub fn load_private_key(
    key_path: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TlsError> {
    let file = File::open(key_path).map_err(|e| TlsError::KeyLoad(key_path.to_string(), e))?;
    private_key(&mut BufReader::new(file))
        .map_err(|e| TlsError::KeyLoad(key_path.to_string(), e))?
        .ok_or_else(|| {
            TlsError::KeyLoad(
                key_path.to_string(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no private key found in PEM",
                ),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_tls_server_config_missing_cert_returns_error() {
        let result = load_tls_server_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
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
