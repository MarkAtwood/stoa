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
}
