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
    /// Failed to parse certificate contents (e.g. DER decode, x509 parse).
    CertParse(String),
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
            TlsError::CertParse(e) => write!(f, "certificate parse error: {e}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::CertLoad(_, e) | TlsError::KeyLoad(_, e) => Some(e),
            TlsError::Config(e) => Some(e),
            TlsError::CertParse(_) => None,
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

/// Load a PEM private key from raw bytes (e.g. resolved from a secrets manager).
///
/// `label` is used in error messages — pass the secretx URI (or any string that
/// identifies the key source) so operators know which secret caused the failure.
/// This is the in-memory equivalent of [`load_private_key`], for callers that
/// hold the PEM bytes directly rather than a file path.
pub fn load_private_key_from_bytes(
    pem_bytes: &[u8],
    label: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TlsError> {
    use std::io::Cursor;
    private_key(&mut BufReader::new(Cursor::new(pem_bytes)))
        .map_err(|e| TlsError::KeyLoad(label.to_string(), e))?
        .ok_or_else(|| {
            TlsError::KeyLoad(
                label.to_string(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no private key found in PEM",
                ),
            )
        })
}

/// Load a TLS `ServerConfig` from a certificate file and private key bytes.
///
/// `key_label` identifies the key source in error messages (typically the
/// `secretx:` URI used to retrieve the key).
///
/// Equivalent to [`load_tls_server_config`] but the private key is supplied as
/// PEM bytes rather than a file path.  Use this when the key was retrieved from
/// a secrets manager (e.g. via a `secretx:` URI) rather than the filesystem.
pub fn load_tls_server_config_with_key_bytes(
    cert_path: &str,
    key_pem_bytes: &[u8],
    key_label: &str,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_chain = load_cert_chain(cert_path)?;
    let private_key = load_private_key_from_bytes(key_pem_bytes, key_label)?;
    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)
    .map_err(TlsError::Config)?;
    Ok(Arc::new(config))
}

/// Return the Unix timestamp (seconds) of the NotAfter date of the first
/// certificate in a PEM certificate chain file.
///
/// Used at startup to emit expiry warnings and populate the
/// `tls_cert_expiry_seconds` Prometheus gauge.  Returns an error if the file
/// cannot be read, contains no certificates, or cannot be parsed as DER.
pub fn cert_not_after(cert_path: &str) -> Result<i64, TlsError> {
    let certs = load_cert_chain(cert_path)?;
    let first = certs
        .into_iter()
        .next()
        .ok_or_else(|| TlsError::CertParse(format!("no certificates found in '{cert_path}'")))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&first).map_err(|e| {
        TlsError::CertParse(format!("failed to parse certificate '{cert_path}': {e}"))
    })?;
    Ok(parsed.validity().not_after.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed cert and return (cert_pem_bytes, key_pem_bytes) as Vec<u8>.
    #[cfg(test)]
    fn generate_self_signed_pem() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem().into_bytes();
        let key_pem = cert.key_pair.serialize_pem().into_bytes();
        (cert_pem, key_pem)
    }

    /// load_private_key_from_bytes parses a PEM private key generated by rcgen.
    #[test]
    fn load_private_key_from_bytes_parses_valid_pem() {
        let (_cert_pem, key_pem) = generate_self_signed_pem();
        let result = load_private_key_from_bytes(&key_pem, "test-label");
        assert!(
            result.is_ok(),
            "must parse a valid PEM key: {:?}",
            result.err()
        );
    }

    /// load_private_key_from_bytes returns a KeyLoad error for empty bytes.
    #[test]
    fn load_private_key_from_bytes_empty_returns_error() {
        let result = load_private_key_from_bytes(&[], "test-label");
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::KeyLoad(label, _) => assert_eq!(label, "test-label"),
            e => panic!("unexpected error type: {e}"),
        }
    }

    /// load_tls_server_config_with_key_bytes builds a valid ServerConfig from
    /// a cert file and inline key bytes.
    ///
    /// Requires a CryptoProvider — installs ring as the default for this test.
    #[test]
    fn load_tls_server_config_with_key_bytes_success() {
        // ring::default_provider().install_default() is idempotent — safe to call multiple times.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::TempDir::new().unwrap();
        let (cert_pem, key_pem) = generate_self_signed_pem();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        let result = load_tls_server_config_with_key_bytes(
            cert_path.to_str().unwrap(),
            &key_pem,
            "test-label",
        );
        assert!(
            result.is_ok(),
            "must build ServerConfig: {:?}",
            result.err()
        );
    }

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

    /// cert_not_after extracts the NotAfter timestamp from a self-signed cert.
    ///
    /// Asserts the returned Unix timestamp is in the future and is a plausible
    /// date (after 2024-01-01, i.e. > 1704067200).
    #[test]
    fn cert_not_after_returns_future_timestamp() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert_pem, _) = generate_self_signed_pem();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();

        let expiry = cert_not_after(cert_path.to_str().unwrap())
            .expect("cert_not_after must succeed for valid cert");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            expiry > now,
            "NotAfter must be in the future; expiry={expiry}, now={now}"
        );
        assert!(
            expiry > 1_704_067_200,
            "NotAfter must be after 2024-01-01; expiry={expiry}"
        );
    }

    /// cert_not_after returns an error for a nonexistent path.
    #[test]
    fn cert_not_after_missing_file_returns_error() {
        let result = cert_not_after("/nonexistent/cert.pem");
        assert!(result.is_err(), "must return Err for nonexistent cert path");
    }
}
