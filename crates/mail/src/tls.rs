//! TLS configuration for the JMAP HTTP server.
//!
//! Delegates PEM loading to `usenet-ipfs-tls`. In v1, TLS wrapping of the
//! axum listener is not yet active; this module exists so `load_tls_config`
//! can be called at startup to validate the paths before the server accepts
//! connections.

pub use usenet_ipfs_tls::TlsError;
use usenet_ipfs_tls::load_tls_server_config;

use rustls::ServerConfig;
use std::sync::Arc;

/// Load PEM certificate and private-key files and return a `rustls::ServerConfig`.
///
/// The resulting config requires TLS 1.2 or higher; TLS 1.0 and 1.1 are not
/// offered.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, TlsError> {
    load_tls_server_config(cert_path, key_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_tls_config_missing_cert_returns_error() {
        let result = load_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
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
