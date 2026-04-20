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
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub addr: String,
}

// command_timeout_secs will be used by the session command reader (not yet implemented).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    pub command_timeout_secs: u64,
}

fn default_max_connections() -> usize {
    100
}

// AuthConfig fields will be used by the AUTHINFO command handler (not yet implemented).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub required: bool,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

// AdminConfig fields will be used by the admin HTTP endpoint (not yet implemented).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    /// Address to bind the admin HTTP endpoint.
    /// Default: 127.0.0.1:9090 (loopback-only).
    /// Setting to a non-loopback address without authentication is warned at startup.
    #[serde(default = "default_admin_addr")]
    pub addr: String,
    /// If true, suppress the non-loopback warning (use only if you know what you're doing).
    #[serde(default)]
    pub allow_non_loopback: bool,
}

fn default_admin_addr() -> String {
    "127.0.0.1:9090".to_string()
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            addr: default_admin_addr(),
            allow_non_loopback: false,
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
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.addr.is_empty() {
            return Err(ConfigError::Validation("listen.addr must not be empty".into()));
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

/// Check admin configuration and emit a warning if admin is bound non-locally.
///
/// Returns Some(warning_message) if the admin address is not loopback and
/// allow_non_loopback is not set. Returns None if the configuration is safe.
pub fn check_admin_addr(admin: &AdminConfig) -> Option<String> {
    if !is_loopback_addr(&admin.addr) && !admin.allow_non_loopback {
        Some(format!(
            "WARNING: admin endpoint bound to non-loopback address '{}' \
             without authentication. Set admin.allow_non_loopback = true in \
             config to suppress this warning, or bind to 127.0.0.1.",
            admin.addr
        ))
    } else {
        None
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
        assert_eq!(cfg.tls.cert_path.as_deref(), Some("/etc/ssl/certs/server.pem"));
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
        let err = Config::from_file(Path::new("/nonexistent/path/reader.toml"))
            .expect_err("should fail");
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
    fn non_loopback_triggers_warning() {
        let admin = AdminConfig {
            addr: "0.0.0.0:9090".to_string(),
            allow_non_loopback: false,
        };
        let warning = check_admin_addr(&admin);
        assert!(warning.is_some(), "non-loopback should trigger warning");
        assert!(warning.unwrap().contains("WARNING"), "warning should say WARNING");
    }

    #[test]
    fn non_loopback_with_flag_no_warning() {
        let admin = AdminConfig {
            addr: "0.0.0.0:9090".to_string(),
            allow_non_loopback: true,
        };
        assert!(check_admin_addr(&admin).is_none(), "allow_non_loopback should suppress warning");
    }

    #[test]
    fn default_addr_is_loopback() {
        let admin = AdminConfig::default();
        assert!(is_loopback_addr(&admin.addr), "default addr must be loopback");
        assert!(check_admin_addr(&admin).is_none(), "default config must not warn");
    }
}
