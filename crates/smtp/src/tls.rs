//! TLS configuration loader for the SMTP listener.
//!
//! Loads a PEM certificate chain and private key from disk and builds a
//! `rustls::ServerConfig` suitable for wrapping accepted TCP streams.

use std::{fs::File, io::BufReader, sync::Arc};

use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};

/// Errors produced while loading TLS configuration.
#[derive(Debug)]
pub enum TlsError {
    /// Failed to read or parse the certificate file.
    CertLoad(String),
    /// Failed to read or parse the private key file.
    KeyLoad(String),
    /// Failed to build the rustls `ServerConfig`.
    ConfigBuild(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::CertLoad(msg) => write!(f, "failed to load TLS certificate: {msg}"),
            TlsError::KeyLoad(msg) => write!(f, "failed to load TLS private key: {msg}"),
            TlsError::ConfigBuild(msg) => write!(f, "TLS server config error: {msg}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// Build a `rustls::ServerConfig` from PEM certificate and private-key files.
///
/// The returned `ServerConfig` requires TLS 1.2 or higher.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, TlsError> {
    // --- Load certificate chain ---
    let cert_file = File::open(cert_path)
        .map_err(|e| TlsError::CertLoad(format!("cannot open '{cert_path}': {e}")))?;
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::CertLoad(format!("cannot parse '{cert_path}': {e}")))?;

    // --- Load private key ---
    let key_file = File::open(key_path)
        .map_err(|e| TlsError::KeyLoad(format!("cannot open '{key_path}': {e}")))?;
    let private_key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| TlsError::KeyLoad(format!("cannot parse '{key_path}': {e}")))?
        .ok_or_else(|| TlsError::KeyLoad(format!("no private key found in '{key_path}'")))?;

    // --- Build ServerConfig with minimum TLS 1.2 ---
    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)
    .map_err(|e| TlsError::ConfigBuild(e.to_string()))?;

    Ok(Arc::new(config))
}

/// Returns `true` if both `cert_path` and `key_path` are set in the config.
pub fn tls_configured(config: &crate::config::Config) -> bool {
    config.tls.cert_path.is_some() && config.tls.key_path.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_tls_config_missing_cert_returns_cert_load_error() {
        let result = load_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertLoad(msg) => assert!(msg.contains("cert.pem")),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn tls_error_display_is_informative() {
        let e = TlsError::CertLoad("/foo/cert.pem: not found".into());
        let msg = e.to_string();
        assert!(msg.contains("cert.pem"), "display: {msg}");
    }

    #[test]
    fn tls_configured_both_set() {
        use crate::config::{
            Config, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, ReaderConfig, TlsConfig,
        };
        let cfg = Config {
            listen: ListenConfig {
                port_25: "0.0.0.0:25".into(),
                port_587: "0.0.0.0:587".into(),
            },
            hostname: "localhost".into(),
            tls: TlsConfig {
                cert_path: Some("/etc/ssl/cert.pem".into()),
                key_path: Some("/etc/ssl/key.pem".into()),
            },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
        };
        assert!(tls_configured(&cfg));
    }

    #[test]
    fn tls_configured_neither_set() {
        use crate::config::{
            Config, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, ReaderConfig, TlsConfig,
        };
        let cfg = Config {
            listen: ListenConfig {
                port_25: "0.0.0.0:25".into(),
                port_587: "0.0.0.0:587".into(),
            },
            hostname: "localhost".into(),
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
        };
        assert!(!tls_configured(&cfg));
    }
}
