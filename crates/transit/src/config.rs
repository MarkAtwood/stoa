use serde::Deserialize;
use std::path::Path;

// Config fields are read from TOML; server logic will consume them as epics are implemented.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub peers: PeersConfig,
    pub groups: GroupsConfig,
    pub ipfs: IpfsConfig,
    pub pinning: PinningConfig,
    pub gc: GcConfig,
    #[serde(default)]
    pub admin: AdminConfig,
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

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub addr: String,
}

#[derive(Debug, Deserialize)]
pub struct PeersConfig {
    pub addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroupsConfig {
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct IpfsConfig {
    pub api_url: String,
}

#[derive(Debug, Deserialize)]
pub struct PinningConfig {
    pub rules: Vec<String>,
}

// GC fields are read from config for future use by the GC scheduler (not yet implemented).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct GcConfig {
    pub schedule: String,
    pub max_age_days: u64,
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
        if self.ipfs.api_url.is_empty() {
            return Err(ConfigError::Validation("ipfs.api_url must not be empty".into()));
        }
        if self.pinning.rules.is_empty() {
            return Err(ConfigError::Validation(
                "pinning.rules must not be empty; at least one pinning rule is required".into(),
            ));
        }
        for name in &self.groups.names {
            validate_group_name(name)?;
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

/// Validates that a group name conforms to RFC 3977 syntax.
/// Group names consist of dot-separated components, each component
/// containing only lowercase letters, digits, '+', '-', and '_'.
fn validate_group_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::Validation("group name must not be empty".into()));
    }
    for component in name.split('.') {
        if component.is_empty() {
            return Err(ConfigError::Validation(format!(
                "group name '{name}' has an empty component"
            )));
        }
        for ch in component.chars() {
            if !matches!(ch, 'a'..='z' | '0'..='9' | '+' | '-' | '_') {
                return Err(ConfigError::Validation(format!(
                    "group name '{name}' contains invalid character '{ch}'"
                )));
            }
        }
    }
    Ok(())
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
addr = "0.0.0.0:119"

[peers]
addresses = ["192.0.2.1:119", "192.0.2.2:119"]

[groups]
names = ["comp.lang.rust", "alt.test"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;

    #[test]
    fn parse_valid_config() {
        let f = write_toml(VALID_TOML);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.listen.addr, "0.0.0.0:119");
        assert_eq!(cfg.peers.addresses.len(), 2);
        assert_eq!(cfg.groups.names, vec!["comp.lang.rust", "alt.test"]);
        assert_eq!(cfg.ipfs.api_url, "http://127.0.0.1:5001");
        assert_eq!(cfg.pinning.rules, vec!["pin-all"]);
        assert_eq!(cfg.gc.schedule, "0 3 * * *");
        assert_eq!(cfg.gc.max_age_days, 30);
    }

    #[test]
    fn missing_listen_section_is_parse_error() {
        let toml = r#"
[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn empty_pinning_rules_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = []

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn invalid_group_name_uppercase() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = ["Comp.Lang.Rust"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn invalid_group_name_empty_component() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = ["comp..rust"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("should fail");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn io_error_on_missing_file() {
        let err = Config::from_file(Path::new("/nonexistent/path/config.toml"))
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
