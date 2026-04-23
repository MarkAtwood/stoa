use serde::Deserialize;
use std::path::Path;

// Config fields are read from TOML; server logic will consume them as epics are implemented.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub limits: LimitsConfig,
    pub auth: AuthConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub operator: OperatorConfig,
    #[serde(default)]
    pub search: SearchConfig,
}

/// Operator identity configuration.
#[derive(Debug, Deserialize, Default)]
pub struct OperatorConfig {
    /// Path to the 32-byte raw Ed25519 operator signing key seed file.
    ///
    /// The file must contain exactly 32 bytes (the Ed25519 seed / private scalar).
    /// If unset, an ephemeral key is generated at startup — articles signed by
    /// different process instances will have different keys and cannot be
    /// cross-verified.  Set this for any production deployment.
    #[serde(default)]
    pub signing_key_path: Option<String>,
}

/// Full-text search configuration (Tantivy-backed).
#[derive(Debug, Deserialize, Clone)]
pub struct SearchConfig {
    /// Directory where Tantivy index is stored. None = search disabled.
    pub index_dir: Option<String>,
    /// Max total index size in bytes before old entries are evicted (soft limit).
    #[serde(default = "SearchConfig::default_max_index_bytes")]
    pub max_index_bytes: u64,
    /// Max bytes of body text indexed per article (truncate beyond this).
    #[serde(default = "SearchConfig::default_body_index_max_bytes")]
    pub body_index_max_bytes: usize,
    /// Max length of a SEARCH query string (bytes) before rejecting with syntax error.
    #[serde(default = "SearchConfig::default_max_query_len")]
    pub max_query_len: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            index_dir: None,
            max_index_bytes: Self::default_max_index_bytes(),
            body_index_max_bytes: Self::default_body_index_max_bytes(),
            max_query_len: Self::default_max_query_len(),
        }
    }
}

impl SearchConfig {
    fn default_max_index_bytes() -> u64 {
        10_737_418_240 // 10 GiB
    }

    fn default_body_index_max_bytes() -> usize {
        102_400 // 100 KiB
    }

    fn default_max_query_len() -> usize {
        4096
    }
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub addr: String,
}

#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    pub command_timeout_secs: u64,
}

fn default_max_connections() -> usize {
    100
}

#[derive(Debug, Deserialize)]
pub struct UserCredential {
    pub username: String,
    pub password: String,
}

/// A TLS client certificate pinned to a username.
///
/// When a client presents a certificate whose SHA-256 fingerprint matches
/// `sha256_fingerprint`, the session is authenticated as `username` without
/// requiring a password. Only valid on NNTPS (port 563) connections.
#[derive(Debug, Deserialize, Clone)]
pub struct ClientCertEntry {
    /// SHA-256 fingerprint of the leaf certificate DER, formatted as
    /// `"sha256:<64-hex-chars>"`.  Case-insensitive on input.
    pub sha256_fingerprint: String,
    /// Username to authenticate when this certificate is presented.
    pub username: String,
}

/// A trusted CA issuer for client certificate chain authentication.
///
/// When a client presents a certificate signed by one of these CAs, the leaf
/// certificate's Common Name (CN) is used as the authenticated username.
/// Only valid on NNTPS (port 563) connections.
#[derive(Debug, Deserialize, Clone)]
pub struct TrustedIssuerEntry {
    /// Path to a PEM-encoded CA certificate.  The CA's public key is extracted
    /// at startup and used for Ed25519 signature verification.
    pub cert_path: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub required: bool,
    /// User accounts for AUTHINFO USER/PASS authentication.
    ///
    /// If empty and `required = false` and `credential_file` is unset, all
    /// credential attempts succeed (development mode).
    #[serde(default)]
    pub users: Vec<UserCredential>,
    /// Path to a file of `username:bcrypt_hash` credential pairs.
    ///
    /// Each non-blank, non-comment line must be `username:$2b$...`. Lines
    /// starting with `#` are ignored. Loaded at startup and merged with the
    /// inline `users` list.
    #[serde(default)]
    pub credential_file: Option<String>,
    /// TLS client certificate pins.
    ///
    /// Each entry maps a certificate SHA-256 fingerprint to a username.
    /// When a client presents a matching certificate over TLS, the session
    /// is authenticated without a password exchange.
    #[serde(default)]
    pub client_certs: Vec<ClientCertEntry>,
    /// Trusted CA issuers for client certificate chain authentication.
    ///
    /// When a client presents a certificate signed by one of these CAs, the
    /// leaf certificate's CN is used as the username — no password required.
    /// Attempted only after fingerprint-based auth has been tried first.
    /// Only valid on NNTPS (port 563) connections.
    #[serde(default)]
    pub trusted_issuers: Vec<TrustedIssuerEntry>,
}

impl AuthConfig {
    /// Returns `true` when no credentials are configured and auth is not
    /// required — the development / open-access mode.
    pub fn is_dev_mode(&self) -> bool {
        !self.required && self.users.is_empty() && self.credential_file.is_none()
    }
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Bind address for the NNTPS listener (implicit TLS, port 563 by convention).
    ///
    /// When set, a second TCP listener is started at this address and every
    /// connection is wrapped in TLS before any NNTP bytes are exchanged.
    /// Requires `cert_path` and `key_path` to also be set.
    pub tls_addr: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    /// Whether the admin HTTP endpoint is enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Address to bind the admin HTTP endpoint.
    /// Default: 127.0.0.1:9090 (loopback-only).
    #[serde(default = "default_admin_addr")]
    pub addr: String,
    /// Bearer token for admin endpoint authentication.
    ///
    /// Required when `addr` is a non-loopback address — the server refuses to
    /// start on a reachable interface without a token (fail-closed).
    /// Optional on loopback; omitting it leaves the endpoint open to any local
    /// process, which is acceptable in a trusted environment.
    #[serde(default)]
    pub admin_token: Option<String>,
}

fn default_admin_addr() -> String {
    "127.0.0.1:9090".to_string()
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: default_admin_addr(),
            admin_token: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    /// Log level filter (e.g. "info", "debug", "usenet_ipfs_reader=debug").
    /// Defaults to "info". Also overridden by the RUST_LOG env var.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: "text" (human-readable) or "json" (structured).
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(msg) => write!(f, "I/O error: {}", msg),
            ConfigError::Parse(msg) => write!(f, "parse error: {}", msg),
            ConfigError::Validation(msg) => write!(f, "validation error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_file(path: &Path) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let config: Config =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.addr.is_empty() {
            return Err(ConfigError::Validation(
                "listen.addr must not be empty".into(),
            ));
        }
        if self.limits.max_connections == 0 {
            return Err(ConfigError::Validation(
                "limits.max_connections must be greater than 0".into(),
            ));
        }
        match (&self.tls.cert_path, &self.tls.key_path) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ConfigError::Validation(
                    "tls.cert_path and tls.key_path must both be set or both be absent".into(),
                ));
            }
            _ => {}
        }
        if self.tls.tls_addr.is_some()
            && (self.tls.cert_path.is_none() || self.tls.key_path.is_none())
        {
            return Err(ConfigError::Validation(
                "tls.tls_addr requires tls.cert_path and tls.key_path to be set".into(),
            ));
        }
        Ok(())
    }
}

/// Returns true if the given bind address is a loopback address.
pub fn is_loopback_addr(addr: &str) -> bool {
    // Parse host from "host:port"
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    // Strip brackets from IPv6 [::1]
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost",
    }
}

/// Validate admin configuration.
///
/// Returns `Err` if `addr` is non-loopback and no `admin_token` is set —
/// an unauthenticated admin endpoint on a reachable interface is a security
/// footgun that the server must not start with (fail-closed).
/// Returns `Ok(())` if the configuration is safe.
pub fn check_admin_addr(admin: &AdminConfig) -> Result<(), String> {
    if !is_loopback_addr(&admin.addr) && admin.admin_token.is_none() {
        Err(format!(
            "admin endpoint at '{}' is on a non-loopback interface but \
             admin.admin_token is not configured — refusing to start an \
             unauthenticated admin server",
            admin.addr
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    const VALID_TOML: &str = r#"
[listen]
addr = "127.0.0.1:119"

[limits]
max_connections = 50
command_timeout_secs = 30

[auth]
required = false

[tls]
cert_path = "/etc/ssl/certs/server.pem"
key_path = "/etc/ssl/private/server.key"
"#;

    #[test]
    fn parse_valid_config() {
        let f = write_toml(VALID_TOML);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.addr, "127.0.0.1:119");
        assert_eq!(cfg.limits.max_connections, 50);
        assert_eq!(cfg.limits.command_timeout_secs, 30);
        assert!(!cfg.auth.required);
        assert_eq!(
            cfg.tls.cert_path.as_deref(),
            Some("/etc/ssl/certs/server.pem")
        );
    }

    #[test]
    fn default_max_connections_applied() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
command_timeout_secs = 60

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.limits.max_connections, 100);
    }

    #[test]
    fn missing_listen_section_is_parse_error() {
        let toml = r#"
[limits]
max_connections = 10
command_timeout_secs = 60

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn zero_max_connections_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 0
command_timeout_secs = 60

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn mismatched_tls_fields_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 10
command_timeout_secs = 60

[auth]
required = false

[tls]
cert_path = "/etc/ssl/certs/server.pem"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn no_tls_fields_is_valid() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 10
command_timeout_secs = 60

[auth]
required = false

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("no TLS is valid");
        assert!(cfg.tls.cert_path.is_none());
        assert!(cfg.tls.key_path.is_none());
    }

    #[test]
    fn io_error_on_missing_file() {
        let err =
            Config::from_file(Path::new("/nonexistent/path/reader.toml")).expect_err("should fail");
        assert!(matches!(err, ConfigError::Io(_)));
    }

    #[test]
    fn loopback_127_is_safe() {
        assert!(is_loopback_addr("127.0.0.1:9090"));
    }

    #[test]
    fn loopback_localhost_is_safe() {
        assert!(is_loopback_addr("localhost:9090"));
    }

    #[test]
    fn ipv6_loopback_is_safe() {
        assert!(is_loopback_addr("[::1]:9090"));
    }

    #[test]
    fn non_loopback_without_token_is_err() {
        let admin = AdminConfig {
            enabled: true,
            addr: "0.0.0.0:9090".to_string(),
            admin_token: None,
        };
        let result = check_admin_addr(&admin);
        assert!(result.is_err(), "non-loopback without token must be Err");
        assert!(
            result.unwrap_err().contains("non-loopback"),
            "error message must mention non-loopback"
        );
    }

    #[test]
    fn non_loopback_with_token_is_ok() {
        let admin = AdminConfig {
            enabled: true,
            addr: "0.0.0.0:9090".to_string(),
            admin_token: Some("secret".to_string()),
        };
        assert!(
            check_admin_addr(&admin).is_ok(),
            "non-loopback with token must be Ok"
        );
    }

    #[test]
    fn default_addr_is_loopback() {
        let admin = AdminConfig::default();
        assert!(
            is_loopback_addr(&admin.addr),
            "default addr must be loopback"
        );
        assert!(
            check_admin_addr(&admin).is_ok(),
            "default config must be Ok"
        );
    }

    #[test]
    fn search_config_defaults_to_disabled() {
        let cfg = SearchConfig::default();
        assert!(
            cfg.index_dir.is_none(),
            "search must be disabled by default"
        );
        assert_eq!(cfg.body_index_max_bytes, 102_400);
        assert_eq!(cfg.max_query_len, 4096);
    }
}
