use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

pub use usenet_ipfs_auth::AuthConfig;

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
    /// SMTP AUTH PLAIN credentials.  Optional; when absent AUTH is not
    /// advertised and no credentials are accepted.
    #[serde(default)]
    pub auth: AuthConfig,
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
        Self {
            path: default_db_path(),
        }
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
    /// Optional AUTHINFO USER credential for submission to the local NNTP reader.
    #[serde(default)]
    pub nntp_username: Option<String>,
    /// Optional AUTHINFO PASS credential for submission to the local NNTP reader.
    #[serde(default)]
    pub nntp_password: Option<String>,
    /// Maximum retry attempts on transient 436 failures (default: 3).
    #[serde(default = "default_nntp_max_retries")]
    pub nntp_max_retries: u32,
}

fn default_nntp_addr() -> String {
    "127.0.0.1:119".to_string()
}

fn default_nntp_max_retries() -> u32 {
    3
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            nntp_addr: default_nntp_addr(),
            nntp_username: None,
            nntp_password: None,
            nntp_max_retries: default_nntp_max_retries(),
        }
    }
}

fn default_relay_port() -> u16 {
    587
}

fn default_true() -> bool {
    true
}

/// Configuration for a single outbound SMTP relay peer.
///
/// At least one relay peer must be configured for outbound email delivery.
/// If `smtp_relay_peers` is empty, delivery is a no-op (no error at startup;
/// messages are queued but never sent).
///
/// # Security
/// `password` is never serialized back to TOML output and never appears in
/// `Debug` output — it is always shown as `<redacted>`.
#[derive(Clone, Deserialize, Serialize)]
pub struct SmtpRelayPeerConfig {
    /// Hostname or IP address of the relay MTA.
    pub host: String,
    /// TCP port. Defaults to 587 (submission with STARTTLS).
    #[serde(default = "default_relay_port")]
    pub port: u16,
    /// Whether to use TLS (STARTTLS on submission, or implicit TLS on 465).
    /// Defaults to `true`.
    #[serde(default = "default_true")]
    pub tls: bool,
    /// SMTP AUTH username, if the relay requires authentication.
    #[serde(default)]
    pub username: Option<String>,
    /// SMTP AUTH password. Never serialized; never logged.
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
}

impl fmt::Debug for SmtpRelayPeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpRelayPeerConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl SmtpRelayPeerConfig {
    /// Returns `"host:port"` for use in log messages and connection targets.
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn default_queue_dir() -> String {
    "smtp-queue".to_string()
}

fn default_nntp_retry_secs() -> u64 {
    60
}

fn default_smtp_relay_queue_dir() -> String {
    "smtp-relay-queue".to_string()
}

fn default_smtp_relay_retry_secs() -> u64 {
    60
}

fn default_peer_down_secs() -> u64 {
    300
}

/// Configuration for the durable NNTP injection queue and outbound SMTP relay.
#[derive(Debug, Deserialize)]
pub struct DeliveryConfig {
    /// Directory for queued outbound NNTP articles. Created on startup if absent.
    #[serde(default = "default_queue_dir")]
    pub queue_dir: String,
    /// Seconds between retry scans when NNTP delivery fails. Defaults to 60.
    #[serde(default = "default_nntp_retry_secs")]
    pub nntp_retry_secs: u64,
    /// Outbound SMTP relay peers. If empty, no SMTP relay delivery is performed.
    #[serde(default)]
    pub smtp_relay_peers: Vec<SmtpRelayPeerConfig>,
    /// Directory for queued outbound SMTP relay messages. Created on startup if absent.
    #[serde(default = "default_smtp_relay_queue_dir")]
    pub smtp_relay_queue_dir: String,
    /// Seconds between retry scans when SMTP relay delivery fails. Defaults to 60.
    #[serde(default = "default_smtp_relay_retry_secs")]
    pub smtp_relay_retry_secs: u64,
    /// Seconds a peer is kept in the "down" state after a delivery failure before
    /// being retried. Defaults to 300.
    #[serde(default = "default_peer_down_secs")]
    pub smtp_peer_down_secs: u64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            queue_dir: default_queue_dir(),
            nntp_retry_secs: default_nntp_retry_secs(),
            smtp_relay_peers: Vec::new(),
            smtp_relay_queue_dir: default_smtp_relay_queue_dir(),
            smtp_relay_retry_secs: default_smtp_relay_retry_secs(),
            smtp_peer_down_secs: default_peer_down_secs(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub port_25: String,
    pub port_587: String,
    /// Optional SMTPS listener address for implicit TLS on port 465.
    ///
    /// When set, a third TCP listener is bound at this address.  Clients must
    /// initiate TLS immediately (no STARTTLS upgrade).  Requires
    /// `tls.cert_path` and `tls.key_path` to be set.
    #[serde(default)]
    pub smtps_addr: Option<String>,
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

fn default_sieve_eval_timeout_ms() -> u64 {
    5_000
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
    /// Maximum time allowed for Sieve script evaluation per message (milliseconds).
    /// Evaluation that exceeds this limit is aborted and treated as Keep (fail-safe).
    #[serde(default = "default_sieve_eval_timeout_ms")]
    pub sieve_eval_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: default_max_message_bytes(),
            max_recipients: default_max_recipients(),
            command_timeout_secs: default_command_timeout_secs(),
            max_connections: default_max_connections(),
            sieve_eval_timeout_ms: default_sieve_eval_timeout_ms(),
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
        if self.listen.smtps_addr.is_some()
            && (self.tls.cert_path.is_none() || self.tls.key_path.is_none())
        {
            return Err(ConfigError::Validation(
                "listen.smtps_addr requires tls.cert_path and tls.key_path to be set".into(),
            ));
        }
        match self.dns_resolver.as_str() {
            "system" | "cloudflare" | "google" | "quad9" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "unknown dns_resolver '{other}'; valid values: system, cloudflare, google, quad9"
                )));
            }
        }
        for peer in &self.delivery.smtp_relay_peers {
            if peer.host.is_empty() {
                return Err(ConfigError::Validation(
                    "smtp relay peer host must not be empty".into(),
                ));
            }
            if peer.port == 0 {
                return Err(ConfigError::Validation(
                    "smtp relay peer port must be > 0".into(),
                ));
            }
            match (&peer.username, &peer.password) {
                (Some(_), None) => {
                    return Err(ConfigError::Validation(
                        "smtp relay peer has username but no password".into(),
                    ));
                }
                (None, Some(_)) => {
                    return Err(ConfigError::Validation(
                        "smtp relay peer has password but no username".into(),
                    ));
                }
                _ => {}
            }
        }
        if !self.delivery.smtp_relay_peers.is_empty()
            && self.delivery.smtp_relay_queue_dir.trim().is_empty()
        {
            return Err(ConfigError::Validation(
                "delivery.smtp_relay_queue_dir must not be empty when relay peers are configured"
                    .into(),
            ));
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
    fn smtps_addr_without_tls_fails_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
smtps_addr = "0.0.0.0:465"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn smtps_addr_with_tls_passes_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
smtps_addr = "0.0.0.0:465"

[tls]
cert_path = "/etc/ssl/certs/smtp.pem"
key_path = "/etc/ssl/private/smtp.key"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.smtps_addr.as_deref(), Some("0.0.0.0:465"));
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

    #[test]
    fn relay_peers_empty_default() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert!(cfg.delivery.smtp_relay_peers.is_empty());
        assert_eq!(cfg.delivery.smtp_relay_queue_dir, "smtp-relay-queue");
        assert_eq!(cfg.delivery.smtp_relay_retry_secs, 60);
        assert_eq!(cfg.delivery.smtp_peer_down_secs, 300);
    }

    #[test]
    fn relay_peer_defaults() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[[delivery.smtp_relay_peers]]
host = "smtp.example.com"
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.delivery.smtp_relay_peers.len(), 1);
        assert_eq!(cfg.delivery.smtp_relay_peers[0].port, 587);
        assert!(cfg.delivery.smtp_relay_peers[0].tls);
        assert_eq!(
            cfg.delivery.smtp_relay_peers[0].host_port(),
            "smtp.example.com:587"
        );
    }

    #[test]
    fn relay_peer_debug_redacts_password() {
        let peer = SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: true,
            username: Some("user".to_string()),
            password: Some("supersecret".to_string()),
        };
        let debug_str = format!("{:?}", peer);
        assert!(!debug_str.contains("supersecret"));
        assert!(debug_str.contains("redacted"));
    }

    #[test]
    fn relay_peer_username_without_password_fails_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[[delivery.smtp_relay_peers]]
host = "smtp.example.com"
username = "user"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("password")),
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn relay_peer_empty_host_fails_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[[delivery.smtp_relay_peers]]
host = ""
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn relay_peers_with_empty_queue_dir_fails_validation() {
        let toml = r#"
[listen]
port_25 = "0.0.0.0:25"
port_587 = "0.0.0.0:587"

[delivery]
smtp_relay_queue_dir = "   "

[[delivery.smtp_relay_peers]]
host = "smtp.example.com"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("smtp_relay_queue_dir"))
            }
            other => panic!("expected Validation, got {other}"),
        }
    }
}
