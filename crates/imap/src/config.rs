use serde::Deserialize;
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub database: DatabaseConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    pub auth: AuthConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    /// Plain-text IMAP bind address (port 143 by convention).
    /// STARTTLS upgrade is offered here if TLS is configured.
    pub addr: String,
    /// Implicit TLS (IMAPS) bind address (port 993 by convention).
    /// Optional; requires tls.cert_path and tls.key_path.
    pub tls_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Path to the SQLite database file.
    pub path: String,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum simultaneous IMAP connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Seconds of inactivity before a session is torn down (RFC 3501 §5.4).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Maximum literal size accepted (bytes). Applies to APPEND and LOGIN.
    #[serde(default = "default_max_literal_bytes")]
    pub max_literal_bytes: u64,
}

fn default_max_connections() -> usize {
    200
}

fn default_idle_timeout_secs() -> u64 {
    1800 // 30 minutes per RFC 3501 §5.4
}

fn default_max_literal_bytes() -> u64 {
    10 * 1024 * 1024 // 10 MiB
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            idle_timeout_secs: default_idle_timeout_secs(),
            max_literal_bytes: default_max_literal_bytes(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UserCredential {
    pub username: String,
    /// bcrypt hash of the user's password. Plaintext passwords are NOT accepted.
    /// Generate with: `python3 -c "import bcrypt; print(bcrypt.hashpw(b'pass', bcrypt.gensalt()).decode())"`
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    /// IMAP AUTHENTICATE mechanisms to advertise.
    /// Supported: "PLAIN", "LOGIN".
    /// LOGIN is disabled before STARTTLS/TLS (LOGINDISABLED capability).
    #[serde(default = "default_mechanisms")]
    pub mechanisms: Vec<String>,
    /// Inline user accounts. The `password` field must be a bcrypt hash.
    #[serde(default)]
    pub users: Vec<UserCredential>,
}

fn default_mechanisms() -> Vec<String> {
    vec!["PLAIN".to_string(), "LOGIN".to_string()]
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM-encoded server certificate chain.
    pub cert_path: Option<String>,
    /// Path to the PEM-encoded private key.
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_addr")]
    pub addr: String,
    #[serde(default)]
    pub admin_token: Option<String>,
}

fn default_admin_addr() -> String {
    "127.0.0.1:9092".to_string()
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
    #[serde(default = "default_log_level")]
    pub level: String,
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
            ConfigError::Io(msg) => write!(f, "I/O error: {msg}"),
            ConfigError::Parse(msg) => write!(f, "parse error: {msg}"),
            ConfigError::Validation(msg) => write!(f, "validation error: {msg}"),
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
        if self.database.path.is_empty() {
            return Err(ConfigError::Validation(
                "database.path must not be empty".into(),
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
        if self.listen.tls_addr.is_some()
            && (self.tls.cert_path.is_none() || self.tls.key_path.is_none())
        {
            return Err(ConfigError::Validation(
                "listen.tls_addr requires tls.cert_path and tls.key_path to be set".into(),
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

    const VALID_TOML: &str = r#"
[listen]
addr = "127.0.0.1:143"

[database]
path = "/var/lib/stoa/imap.db"

[limits]
max_connections = 50
idle_timeout_secs = 900
max_literal_bytes = 5242880

[auth]
users = [{ username = "alice", password = "hunter2" }]

[tls]
"#;

    #[test]
    fn parse_valid_config() {
        let f = write_toml(VALID_TOML);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.addr, "127.0.0.1:143");
        assert_eq!(cfg.database.path, "/var/lib/stoa/imap.db");
        assert_eq!(cfg.limits.max_connections, 50);
        assert_eq!(cfg.limits.idle_timeout_secs, 900);
        assert_eq!(cfg.auth.users.len(), 1);
        assert_eq!(cfg.auth.users[0].username, "alice");
    }

    #[test]
    fn defaults_applied_when_omitted() {
        let toml = r#"
[listen]
addr = "0.0.0.0:143"

[database]
path = "/tmp/imap.db"

[auth]

[tls]
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("defaults should parse");
        assert_eq!(cfg.limits.max_connections, 200);
        assert_eq!(cfg.limits.idle_timeout_secs, 1800);
        assert_eq!(cfg.limits.max_literal_bytes, 10 * 1024 * 1024);
        assert_eq!(cfg.auth.mechanisms, vec!["PLAIN", "LOGIN"]);
    }

    #[test]
    fn empty_listen_addr_is_validation_error() {
        let toml = r#"
[listen]
addr = ""

[database]
path = "/tmp/imap.db"

[auth]

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn zero_max_connections_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:143"

[database]
path = "/tmp/imap.db"

[limits]
max_connections = 0

[auth]

[tls]
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn tls_addr_without_cert_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:143"
tls_addr = "0.0.0.0:993"

[database]
path = "/tmp/imap.db"

[auth]

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
addr = "0.0.0.0:143"

[database]
path = "/tmp/imap.db"

[auth]

[tls]
cert_path = "/etc/ssl/server.pem"
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn io_error_on_missing_file() {
        let err =
            Config::from_file(Path::new("/nonexistent/path/imap.toml")).expect_err("should fail");
        assert!(matches!(err, ConfigError::Io(_)));
    }
}
