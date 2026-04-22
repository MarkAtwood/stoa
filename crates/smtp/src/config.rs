use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub reader: ReaderConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub sieve_admin: SieveAdminConfig,
    /// DNS resolver to use for SPF/DKIM/DMARC/ARC lookups.
    ///
    /// Valid values: `"system"` (reads `/etc/resolv.conf`), `"cloudflare"`,
    /// `"google"`, `"quad9"`.  Defaults to `"system"` so that split-horizon
    /// DNS and air-gapped deployments work correctly out of the box.
    #[serde(default = "default_dns_resolver")]
    pub dns_resolver: String,
}

fn default_dns_resolver() -> String {
    "system".to_string()
}

/// A local mailbox user.  `email` is matched against RCPT TO addresses.
#[derive(Debug, Deserialize, Clone)]
pub struct UserConfig {
    pub username: String,
    pub email: String,
}

fn default_db_path() -> String {
    "smtp.db".to_string()
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// File path for the SQLite database, or `:memory:` for in-process testing.
    #[serde(default = "default_db_path")]
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { path: default_db_path() }
    }
}

fn default_sieve_admin_bind() -> String {
    "127.0.0.1:4190".to_string()
}

fn default_max_script_bytes() -> u64 {
    65_536
}

/// Configuration for the HTTP Sieve script management API.
///
/// The API listens on `bind` (default `127.0.0.1:4190`) and requires no
/// credentials — access control is enforced by the bind address.
/// Binding to a non-loopback address without additional network-level
/// protection (firewall, VPN) exposes script read/write to any host with
/// HTTP access.  A warning is logged at startup unless
/// `allow_non_loopback = true` is set explicitly.
#[derive(Debug, Deserialize)]
pub struct SieveAdminConfig {
    #[serde(default = "default_sieve_admin_bind")]
    pub bind: String,
    /// Maximum size of a Sieve script in bytes (default 64 KiB).
    #[serde(default = "default_max_script_bytes")]
    pub max_script_bytes: u64,
    /// Suppress the non-loopback warning.  Set to `true` only when you have
    /// verified that the admin API is protected by a firewall or reverse proxy
    /// with its own authentication.
    #[serde(default)]
    pub allow_non_loopback: bool,
    /// Optional bearer token for HTTP authentication.
    ///
    /// When set, every request must include `Authorization: Bearer <token>`.
    /// Strongly recommended when `bind` is a non-loopback address.
    /// If unset, all requests are allowed (loopback-only access control).
    #[serde(default)]
    pub bearer_token: Option<String>,
}

impl Default for SieveAdminConfig {
    fn default() -> Self {
        Self {
            bind: default_sieve_admin_bind(),
            max_script_bytes: default_max_script_bytes(),
            allow_non_loopback: false,
            bearer_token: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ReaderConfig {
    #[serde(default = "default_nntp_addr")]
    pub nntp_addr: String,
}

fn default_nntp_addr() -> String {
    "127.0.0.1:119".to_string()
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            nntp_addr: default_nntp_addr(),
        }
    }
}

fn default_queue_dir() -> String {
    "smtp-queue".to_string()
}

fn default_nntp_retry_secs() -> u64 {
    60
}

/// Configuration for the durable NNTP injection queue.
#[derive(Debug, Deserialize)]
pub struct DeliveryConfig {
    /// Directory for queued outbound NNTP articles. Created on startup if absent.
    #[serde(default = "default_queue_dir")]
    pub queue_dir: String,
    /// Seconds between retry scans when NNTP delivery fails. Defaults to 60.
    #[serde(default = "default_nntp_retry_secs")]
    pub nntp_retry_secs: u64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            queue_dir: default_queue_dir(),
            nntp_retry_secs: default_nntp_retry_secs(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub port_25: String,
    pub port_587: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

fn default_max_message_bytes() -> u64 {
    26_214_400
}

fn default_max_recipients() -> usize {
    100
}

fn default_command_timeout_secs() -> u64 {
    300
}

fn default_max_connections() -> usize {
    100
}

#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: u64,
    #[serde(default = "default_max_recipients")]
    pub max_recipients: usize,
    #[serde(default = "default_command_timeout_secs")]
    pub command_timeout_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: default_max_message_bytes(),
            max_recipients: default_max_recipients(),
            command_timeout_secs: default_command_timeout_secs(),
            max_connections: default_max_connections(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    /// Log level filter (e.g. "info", "debug").
    /// Defaults to "info". Also overridden by the RUST_LOG env var.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: "text" (human-readable) or "json" (structured).
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_hostname() -> String {
    "localhost".to_string()
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
        if self.hostname.is_empty() {
            return Err(ConfigError::Validation("hostname must not be empty".into()));
        }
        if self.listen.port_25.is_empty() {
            return Err(ConfigError::Validation(
                "listen.port_25 must not be empty".into(),
            ));
        }
        if self.listen.port_587.is_empty() {
            return Err(ConfigError::Validation(
                "listen.port_587 must not be empty".into(),
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
        match self.dns_resolver.as_str() {
            "system" | "cloudflare" | "google" | "quad9" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "unknown dns_resolver '{other}'; valid values: system, cloudflare, google, quad9"
                )));
            }
        }
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

    #[test]
    fn parse_minimal_valid_toml() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.port_25, "0.0.0.0:25");
        assert_eq!(cfg.listen.port_587, "0.0.0.0:587");
        assert_eq!(cfg.hostname, "localhost");
    }

    #[test]
    fn defaults_applied() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.limits.max_message_bytes, 26_214_400);
        assert_eq!(cfg.limits.max_recipients, 100);
        assert_eq!(cfg.limits.command_timeout_secs, 300);
        assert_eq!(cfg.limits.max_connections, 100);
        assert_eq!(cfg.log.level, "info");
        assert_eq!(cfg.log.format, "json");
    }

    #[test]
    fn tls_both_or_neither_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[tls]
cert_path = "/etc/ssl/certs/smtp.pem"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn empty_hostname_fails_validation() {
        let toml = r#"
hostname = ""

[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }
}
