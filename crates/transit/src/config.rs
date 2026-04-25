use serde::Deserialize;
use std::path::Path;

use crate::block_cache::CacheConfig;
use crate::retention::policy::{PinPolicy, PolicyValidationError};
use crate::retention::remote_pin_client::PinningApiKey;
use crate::staging::StagingConfig;

// ── Backend config (pluggable block store) ────────────────────────────────────

/// Selects the IPFS block storage backend.
///
/// Use `[backend]` with a `type` key instead of the legacy `[ipfs]` section
/// to activate a specific backend.  `[ipfs]` is retained for backward
/// compatibility; when both are present `[backend]` takes precedence.
#[derive(Debug, Deserialize, Clone)]
pub struct BackendConfig {
    /// Backend discriminator.  Supported values: `"kubo"`, `"s3"`, `"filesystem"`.
    #[serde(rename = "type")]
    pub backend_type: BackendType,
    /// Kubo-specific settings.  Required when `type = "kubo"`.
    #[serde(default)]
    pub kubo: Option<KuboBackendConfig>,
    /// S3-specific settings (not yet implemented).
    #[serde(default)]
    pub s3: Option<S3BackendConfig>,
    /// Filesystem-specific settings (not yet implemented).
    #[serde(default)]
    pub filesystem: Option<FsBackendConfig>,
    /// LMDB-specific settings.  Required when `type = "lmdb"`.
    #[serde(default)]
    pub lmdb: Option<LmdbBackendConfig>,
}

/// Backend type discriminator.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    Kubo,
    S3,
    Filesystem,
    Lmdb,
}

/// Configuration for the Kubo HTTP RPC backend.
#[derive(Debug, Deserialize, Clone)]
pub struct KuboBackendConfig {
    /// Kubo daemon HTTP RPC API URL (e.g. `"http://127.0.0.1:5001"`).
    pub api_url: String,
}

/// Placeholder — S3 backend not yet implemented.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct S3BackendConfig {}

/// Placeholder — filesystem backend not yet implemented.
#[derive(Debug, Deserialize, Clone)]
pub struct FsBackendConfig {
    /// Root directory for block files.
    pub path: String,
}

/// Configuration for the LMDB block store backend.
#[derive(Debug, Deserialize, Clone)]
pub struct LmdbBackendConfig {
    /// Directory for the LMDB environment.  Created at startup if absent.
    pub path: String,
    /// Virtual address space reservation in GiB.  Default: 1024 (1 TiB).
    /// Does not pre-allocate disk space on 64-bit systems.
    #[serde(default = "default_lmdb_map_size_gb")]
    pub map_size_gb: u64,
}

fn default_lmdb_map_size_gb() -> u64 {
    1024
}

// Config fields are read from TOML; server logic will consume them as epics are implemented.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub peers: PeersConfig,
    pub groups: GroupsConfig,
    /// Legacy Kubo connection settings.  Retained for backward compatibility.
    /// New deployments should use `[backend]` instead.
    #[serde(default)]
    pub ipfs: IpfsConfig,
    /// Pluggable block store backend.  When present, takes precedence over `[ipfs]`.
    #[serde(default)]
    pub backend: Option<BackendConfig>,
    pub pinning: PinningConfig,
    pub gc: GcConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub operator: OperatorConfig,
    #[serde(default)]
    pub peering: PeeringConfig,
    /// TLS for the inbound peering TCP listener.  Optional; plain TCP is used
    /// when this section is absent (suitable for LAN / loopback peering).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// IPNS publishing configuration.  Optional; IPNS publishing is disabled by default.
    #[serde(default)]
    pub ipns: IpnsConfig,
    /// Write-ahead staging area.  Optional; omit to use the in-memory
    /// ingestion queue only (current default behaviour).
    #[serde(default)]
    pub staging: Option<StagingConfig>,
    /// Local LRU block cache for IPFS content.  Optional; omit to disable.
    #[serde(default)]
    pub cache: Option<CacheConfig>,
}

/// Operator identity configuration.
///
/// Controls the Ed25519 signing key used to sign articles before they are
/// written to IPFS and to derive the stable HLC node_id.
///
/// If `signing_key_path` is absent, an ephemeral key is generated at startup.
/// This is safe for development but breaks article signature verification across
/// restarts and makes HLC timestamps non-comparable between daemon instances.
/// Set this in production.
#[derive(Debug, Deserialize, Default)]
pub struct OperatorConfig {
    /// Path to the PEM-encoded Ed25519 operator signing key.
    ///
    /// The file must contain a PKCS#8 DER (`PRIVATE KEY` PEM label, 48 bytes)
    /// or a raw 32-byte seed in PEM form.  Use `transit keygen` to create one.
    ///
    /// If absent, an ephemeral key is generated each startup (dev mode only).
    #[serde(default)]
    pub signing_key_path: Option<String>,
    /// Local FQDN for the `Path:` header (Son-of-RFC-1036 §3.3).
    #[serde(default)]
    pub hostname: Option<String>,
}

/// IPNS publishing configuration.
///
/// When `enabled` is true, the transit daemon publishes a signed IPNS record
/// after each article ingestion.  The record points to a JSON index block that
/// maps every active newsgroup to its most-recently-ingested article CID.
/// The stable IPNS address is derived from the node's libp2p peer identity key.
#[derive(Debug, Deserialize)]
pub struct IpnsConfig {
    /// Publish IPNS records after each article ingestion.  Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum interval between consecutive IPNS publishes, in seconds.
    /// Prevents excessive DHT traffic on high-volume ingest.  Default: 3600.
    #[serde(default = "default_ipns_republish_interval")]
    pub republish_interval_secs: u64,
}

fn default_ipns_republish_interval() -> u64 {
    3600
}

impl Default for IpnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            republish_interval_secs: default_ipns_republish_interval(),
        }
    }
}

/// SQLite database configuration.
///
/// Three separate SQLite files are required because `sqlx` validates that every
/// previously-applied migration is still present in the migrator; mixing schemas
/// in a single pool would cause `VersionMissing` errors.
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Path for the core-schema database (msgid_map, group_log).
    /// Created if it does not exist. Default: `transit_core.db`.
    #[serde(default = "default_core_db_path")]
    pub core_path: String,
    /// Path for the transit-schema database (peers, peer_groups, articles).
    /// Created if it does not exist. Default: `transit.db`.
    #[serde(default = "default_db_path")]
    pub path: String,
    /// Path for the verify-schema database (article_verifications, seen_keys).
    /// Created if it does not exist. Default: `transit_verify.db`.
    #[serde(default = "default_verify_db_path")]
    pub verify_path: String,
    /// SQLite connection pool size for the transit database. Default: 8.
    #[serde(default = "default_db_pool_size")]
    pub pool_size: u32,
}

fn default_core_db_path() -> String {
    "transit_core.db".to_string()
}

fn default_db_path() -> String {
    "transit.db".to_string()
}

fn default_verify_db_path() -> String {
    "transit_verify.db".to_string()
}

fn default_db_pool_size() -> u32 {
    8
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            core_path: default_core_db_path(),
            path: default_db_path(),
            verify_path: default_verify_db_path(),
            pool_size: default_db_pool_size(),
        }
    }
}

// AdminConfig fields will be used by the admin HTTP endpoint (not yet implemented).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    /// Address to bind the admin HTTP endpoint.
    /// Default: 127.0.0.1:9090 (loopback-only).
    /// A non-loopback address without a bearer token is rejected at startup (fail-closed).
    #[serde(default = "default_admin_addr")]
    pub addr: String,
    /// Optional bearer token for admin endpoint authentication.
    /// Required when addr is a non-loopback address — the server refuses to start
    /// on a reachable interface without a token (fail-closed).
    /// Optional on loopback; omitting it leaves the endpoint open to local processes.
    #[serde(default)]
    pub bearer_token: Option<String>,
    /// Maximum requests per minute per IP (default 60). 0 = unlimited.
    #[serde(default = "default_rate_limit_rpm")]
    pub rate_limit_rpm: u32,
}

fn default_admin_addr() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_rate_limit_rpm() -> u32 {
    60
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            addr: default_admin_addr(),
            bearer_token: None,
            rate_limit_rpm: default_rate_limit_rpm(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    /// Log level filter (e.g. "info", "debug", "stoa_transit=debug").
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

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub addr: String,
}

/// TLS configuration for the inbound peering TCP listener.
///
/// When present, the peering listener wraps every accepted connection with
/// rustls before handing it to the session handler.  Plain TCP peers that do
/// not speak TLS will fail the handshake and be dropped.
///
/// Leave this section absent to accept plain TCP connections (LAN or loopback
/// peering, or when a TLS terminator sits in front of the daemon).
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain (leaf first).
    pub cert_path: String,
    /// Path to the PEM-encoded private key.
    pub key_path: String,
}

/// One entry in the structured `[[peers.peer]]` table.
#[derive(Debug, Deserialize, Default)]
pub struct PeerEntry {
    /// Socket address of the peer (IP:port or hostname:port).
    pub addr: String,
    /// Connect with TLS. Requires `cert_sha256`. Default: false.
    #[serde(default)]
    pub tls: bool,
    /// Pinned SHA-256 fingerprint of the peer's DER certificate.
    ///
    /// Required when `tls = true`. Format: colon-separated lowercase hex bytes,
    /// e.g. `"aa:bb:cc:..."`. Validation rejects `tls = true` without this field.
    #[serde(default)]
    pub cert_sha256: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PeersConfig {
    /// Legacy flat list of peer addresses (backward-compatible).
    ///
    /// Entries here are equivalent to `[[peers.peer]]` with `tls = false` and
    /// no cert pin.  Supported for existing configs; new deployments should use
    /// the structured `peer` table instead.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Structured per-peer table with optional TLS and cert-pin metadata.
    ///
    /// Use `[[peers.peer]]` in TOML to add entries.  Validated at startup:
    /// `tls = true` without `cert_sha256` is rejected.
    #[serde(default)]
    pub peer: Vec<PeerEntry>,
}

#[derive(Debug, Deserialize)]
pub struct GroupsConfig {
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct IpfsConfig {
    // Default is empty. Previously "http://127.0.0.1:5001" was implied; config
    // validation now rejects an empty api_url when no [backend] is present.
    // Upgrade: add `[ipfs]\napi_url = "http://127.0.0.1:5001"` or use [backend].
    pub api_url: String,
}

/// Configuration for one external IPFS pinning service.
///
/// External services implement the IPFS Remote Pinning API spec
/// (https://ipfs.github.io/pinning-services-api-spec/).
/// Compatible services include Pinata, web3.storage, Filebase, and others.
#[derive(Debug, Deserialize)]
pub struct ExternalPinServiceConfig {
    /// Human-readable name (used in logs and the admin API). Must be unique.
    pub name: String,
    /// Base URL of the Remote Pinning API endpoint. Must use HTTPS.
    /// Example: `"https://api.pinata.cloud/psa"`
    pub endpoint: String,
    /// Bearer token for authenticating with the pinning service.
    pub api_key: PinningApiKey,
    /// HTTP connect timeout in seconds. Must be ≥ 1. Default: 10.
    #[serde(default = "default_pin_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// HTTP request timeout in seconds. Must be ≥ 1. Default: 30.
    #[serde(default = "default_pin_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Optional glob patterns for newsgroup names to include.
    /// Empty means "pin articles from all groups". Patterns are matched
    /// against each newsgroup in the article's Newsgroups header.
    /// Example: `["comp.*", "sci.*"]`
    #[serde(default)]
    pub groups: Vec<String>,
    /// Maximum submission attempts per CID before marking as failed. Default: 5.
    #[serde(default = "default_pin_max_attempts")]
    pub max_attempts: u32,
}

fn default_pin_connect_timeout_secs() -> u64 {
    10
}

fn default_pin_request_timeout_secs() -> u64 {
    30
}

fn default_pin_max_attempts() -> u32 {
    5
}

#[derive(Debug, Deserialize)]
pub struct PinningConfig {
    pub rules: Vec<String>,
    /// External IPFS pinning services to replicate articles to.
    /// Uses the IPFS Remote Pinning API spec. Optional; default empty.
    #[serde(default)]
    pub external_services: Vec<ExternalPinServiceConfig>,
}

// GC fields are read from config for future use by the GC scheduler (not yet implemented).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct GcConfig {
    pub schedule: String,
    pub max_age_days: u64,
}

/// Peering session tuning parameters.
#[derive(Debug, Deserialize)]
pub struct PeeringConfig {
    /// Ingestion queue capacity (max queued articles before backpressure). Default: 1024.
    #[serde(default = "default_ingestion_queue_capacity")]
    pub ingestion_queue_capacity: usize,
    /// Per-IP rate limit: sustained articles/second. Default: 100.
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: f64,
    /// Per-IP rate limit burst: max burst articles. Default: 200.
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u64,
    /// Trusted peer public keys for ed25519 challenge-response authentication.
    ///
    /// Each entry must be of the form `"ed25519:<64-lowercase-hex-digits>"`.
    /// When non-empty, every inbound peering connection must complete the
    /// mutual handshake with a key in this list before any NNTP bytes are
    /// exchanged.  Connections that fail or time out are dropped silently.
    ///
    /// When empty (the default) authentication is skipped — the port MUST be
    /// firewalled to trusted peers in that case.
    #[serde(default)]
    pub trusted_peers: Vec<String>,
    /// Seconds to wait for the ingestion queue to drain after a shutdown
    /// signal before forcing exit.  Default: 30.
    #[serde(default)]
    pub drain_timeout_secs: Option<u64>,
}

fn default_ingestion_queue_capacity() -> usize {
    1024
}

fn default_rate_limit_rps() -> f64 {
    100.0
}

fn default_rate_limit_burst() -> u64 {
    200
}

impl Default for PeeringConfig {
    fn default() -> Self {
        Self {
            ingestion_queue_capacity: default_ingestion_queue_capacity(),
            rate_limit_rps: default_rate_limit_rps(),
            rate_limit_burst: default_rate_limit_burst(),
            trusted_peers: Vec::new(),
            drain_timeout_secs: None,
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

    /// Returns the effective Kubo API URL: `[backend.kubo.api_url]` when a Kubo
    /// backend is configured, otherwise `[ipfs.api_url]`.  Returns `None` when
    /// a non-Kubo backend is selected (no connectivity check is needed).
    pub fn kubo_api_url(&self) -> Option<&str> {
        if let Some(backend) = &self.backend {
            match &backend.backend_type {
                BackendType::Kubo => backend.kubo.as_ref().map(|k| k.api_url.as_str()),
                _ => None,
            }
        } else if !self.ipfs.api_url.is_empty() {
            Some(self.ipfs.api_url.as_str())
        } else {
            None
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.addr.is_empty() {
            return Err(ConfigError::Validation(
                "listen.addr must not be empty".into(),
            ));
        }
        // Require either [backend] or a non-empty [ipfs.api_url].
        match &self.backend {
            Some(backend) => match &backend.backend_type {
                BackendType::Kubo => {
                    if backend.kubo.is_none() {
                        return Err(ConfigError::Validation(
                            "backend.type = 'kubo' requires a [backend.kubo] section".into(),
                        ));
                    }
                }
                BackendType::Lmdb => {
                    if backend.lmdb.is_none() {
                        return Err(ConfigError::Validation(
                            "backend.type = 'lmdb' requires a [backend.lmdb] section".into(),
                        ));
                    }
                    if let Some(lmdb) = &backend.lmdb {
                        if lmdb.map_size_gb == 0 {
                            return Err(ConfigError::Validation(
                                "backend.lmdb.map_size_gb must be ≥ 1".into(),
                            ));
                        }
                        // Mirror the overflow check in LmdbBlockDb::open().
                        const GIB: u64 = 1024 * 1024 * 1024;
                        let platform_max_gb = usize::MAX as u64 / GIB;
                        if lmdb.map_size_gb > platform_max_gb {
                            return Err(ConfigError::Validation(format!(
                                "backend.lmdb.map_size_gb {} exceeds platform maximum {}",
                                lmdb.map_size_gb, platform_max_gb
                            )));
                        }
                    }
                }
                // S3 and Filesystem are declared in the enum for future use but are not
                // yet implemented.  Reject them at config load time so the daemon fails
                // fast with a clear message instead of panicking in the factory function.
                BackendType::S3 | BackendType::Filesystem => {
                    return Err(ConfigError::Validation(
                        "backend.type 's3' and 'filesystem' are not yet implemented; \
                         use 'kubo' or 'lmdb'"
                            .into(),
                    ));
                }
            },
            None => {
                if self.ipfs.api_url.is_empty() {
                    return Err(ConfigError::Validation(
                        "either [backend] or [ipfs] with a non-empty api_url is required".into(),
                    ));
                }
            }
        }
        if self.pinning.rules.is_empty() {
            return Err(ConfigError::Validation(
                "pinning.rules must not be empty; at least one pinning rule is required".into(),
            ));
        }
        for name in &self.groups.names {
            validate_group_name(name)?;
        }
        for peer in &self.peers.peer {
            if peer.tls && peer.cert_sha256.is_none() {
                return Err(ConfigError::Validation(format!(
                    "peers.peer entry '{}': tls = true requires cert_sha256 to be set",
                    peer.addr
                )));
            }
        }
        // Validate external pinning service entries.
        let mut seen_service_names: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for svc in &self.pinning.external_services {
            if svc.name.is_empty() {
                return Err(ConfigError::Validation(
                    "pinning.external_services: service name must not be empty".into(),
                ));
            }
            if !seen_service_names.insert(svc.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services: duplicate service name '{}'",
                    svc.name
                )));
            }
            if !svc.endpoint.starts_with("https://") {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services '{}': endpoint must use HTTPS, got '{}'",
                    svc.name, svc.endpoint
                )));
            }
            if svc.connect_timeout_secs == 0 {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services '{}': connect_timeout_secs must be ≥ 1",
                    svc.name
                )));
            }
            if svc.request_timeout_secs == 0 {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services '{}': request_timeout_secs must be ≥ 1",
                    svc.name
                )));
            }
            if svc.max_attempts == 0 {
                return Err(ConfigError::Validation(format!(
                    "pinning.external_services '{}': max_attempts must be ≥ 1",
                    svc.name
                )));
            }
        }

        // Fail fast if the signing key path is configured but unreadable.
        // Better to catch this at startup than discover it when an article arrives.
        if let Some(ref path) = self.operator.signing_key_path {
            std::fs::metadata(path).map_err(|e| {
                ConfigError::Validation(format!(
                    "operator.signing_key_path '{path}' is not accessible: {e}"
                ))
            })?;
        }
        Ok(())
    }
}

/// Validates a [`PinPolicy`] at startup, returning an error if the policy is
/// malformed. This is a thin wrapper around [`PinPolicy::validate`] so that
/// startup code can call a single named function.
pub fn validate_retention_policy(policy: &PinPolicy) -> Result<(), PolicyValidationError> {
    policy.validate()
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
/// Returns `Err` if `addr` is non-loopback and no `bearer_token` is set —
/// an unauthenticated admin endpoint on a reachable interface is a security
/// footgun that the server must not start with (fail-closed).
/// Returns `Ok(())` if the configuration is safe.
pub fn check_admin_addr(admin: &AdminConfig) -> Result<(), String> {
    if !is_loopback_addr(&admin.addr) && admin.bearer_token.is_none() {
        Err(format!(
            "admin endpoint at '{}' is on a non-loopback interface but \
             bearer_token is not configured — refusing to start an \
             unauthenticated admin server",
            admin.addr
        ))
    } else {
        Ok(())
    }
}

/// Validates that a group name conforms to RFC 3977 syntax.
/// Group names consist of dot-separated components, each component
/// containing only lowercase letters, digits, '+', '-', and '_'.
fn validate_group_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::Validation(
            "group name must not be empty".into(),
        ));
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
        let err =
            Config::from_file(Path::new("/nonexistent/path/config.toml")).expect_err("should fail");
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
            addr: "0.0.0.0:9090".to_string(),
            bearer_token: None,
            rate_limit_rpm: 60,
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
            addr: "0.0.0.0:9090".to_string(),
            bearer_token: Some("secret".to_string()),
            rate_limit_rpm: 60,
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

    /// New structured [[peers.peer]] tables parse correctly alongside
    /// the legacy addresses list.
    #[test]
    fn structured_peer_table_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = ["192.0.2.1:119"]

[[peers.peer]]
addr = "192.0.2.2:119"
tls = true
cert_sha256 = "aa:bb:cc"

[[peers.peer]]
addr = "192.0.2.3:119"

[groups]
names = ["comp.test"]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.peers.addresses.len(), 1);
        assert_eq!(cfg.peers.peer.len(), 2);
        let tls_peer = &cfg.peers.peer[0];
        assert_eq!(tls_peer.addr, "192.0.2.2:119");
        assert!(tls_peer.tls);
        assert_eq!(tls_peer.cert_sha256.as_deref(), Some("aa:bb:cc"));
        let plain_peer = &cfg.peers.peer[1];
        assert_eq!(plain_peer.addr, "192.0.2.3:119");
        assert!(!plain_peer.tls);
    }

    /// tls = true without cert_sha256 must fail validation.
    #[test]
    fn tls_without_cert_sha256_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[[peers.peer]]
addr = "192.0.2.10:119"
tls = true

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
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    #[test]
    fn external_pin_service_parses() {
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
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "secret-token"
groups = ["comp.*"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("should parse");
        assert_eq!(cfg.pinning.external_services.len(), 1);
        let svc = &cfg.pinning.external_services[0];
        assert_eq!(svc.name, "pinata");
        assert_eq!(svc.endpoint, "https://api.pinata.cloud/psa");
        assert_eq!(svc.groups, vec!["comp.*"]);
        assert_eq!(svc.connect_timeout_secs, 10);
        assert_eq!(svc.request_timeout_secs, 30);
        assert_eq!(svc.max_attempts, 5);
        // api_key must be redacted in Debug output
        assert!(!format!("{:?}", svc.api_key).contains("secret-token"));
    }

    #[test]
    fn external_pin_service_http_endpoint_rejected() {
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
rules = ["pin-all"]

[[pinning.external_services]]
name = "insecure"
endpoint = "http://api.pinata.cloud/psa"
api_key = "token"

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("HTTP endpoint should fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    #[test]
    fn external_pin_service_duplicate_name_rejected() {
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
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "token-1"

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.web3.storage/pins"
api_key = "token-2"

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err =
            Config::from_file(f.path()).expect_err("duplicate service name should fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    #[test]
    fn external_pin_service_zero_timeout_rejected() {
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
rules = ["pin-all"]

[[pinning.external_services]]
name = "pinata"
endpoint = "https://api.pinata.cloud/psa"
api_key = "token"
connect_timeout_secs = 0

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("zero timeout should fail validation");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] section with type = "kubo" parses and validation passes.
    #[test]
    fn backend_kubo_section_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "kubo"

[backend.kubo]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("backend.kubo config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be present");
        assert_eq!(backend.backend_type, BackendType::Kubo);
        let kubo = backend.kubo.as_ref().expect("backend.kubo must be present");
        assert_eq!(kubo.api_url, "http://127.0.0.1:5001");
        // kubo_api_url() returns the backend.kubo url.
        assert_eq!(cfg.kubo_api_url(), Some("http://127.0.0.1:5001"));
    }

    /// [backend] with type = "kubo" but no [backend.kubo] subsection is rejected.
    #[test]
    fn backend_kubo_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "kubo"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing backend.kubo must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] section with type = "lmdb" and a [backend.lmdb] subsection parses.
    #[test]
    fn backend_lmdb_section_parses() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "lmdb"

[backend.lmdb]
path = "/tmp/test-lmdb"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let cfg = Config::from_file(f.path()).expect("backend.lmdb config must parse");
        let backend = cfg.backend.as_ref().expect("backend must be present");
        assert_eq!(backend.backend_type, BackendType::Lmdb);
        let lmdb = backend.lmdb.as_ref().expect("backend.lmdb must be present");
        assert_eq!(lmdb.path, "/tmp/test-lmdb");
        assert_eq!(lmdb.map_size_gb, 1024, "default map_size_gb must be 1024");
        // No Kubo connectivity check needed for LMDB.
        assert_eq!(cfg.kubo_api_url(), None);
    }

    /// [backend] with type = "lmdb" but no [backend.lmdb] subsection is rejected.
    #[test]
    fn backend_lmdb_without_subsection_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "lmdb"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing backend.lmdb must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend] with type = "s3" is rejected as not yet implemented.
    #[test]
    fn backend_s3_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "s3"

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path())
            .expect_err("s3 backend must fail with not-yet-implemented error");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// [backend.lmdb] with map_size_gb = 0 is rejected.
    #[test]
    fn backend_lmdb_map_size_zero_rejected() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[backend]
type = "lmdb"

[backend.lmdb]
path = "/tmp/test"
map_size_gb = 0

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("map_size_gb = 0 must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// Missing both [backend] and [ipfs] is a validation error.
    #[test]
    fn missing_both_backend_and_ipfs_is_validation_error() {
        let toml = r#"
[listen]
addr = "0.0.0.0:119"

[peers]
addresses = []

[groups]
names = []

[pinning]
rules = ["pin-all"]

[gc]
schedule = "0 3 * * *"
max_age_days = 30
"#;
        let f = write_toml(toml);
        let err = Config::from_file(f.path()).expect_err("missing ipfs and backend must fail");
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }
}
