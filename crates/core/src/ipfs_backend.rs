//! Shared IPFS block-store backend configuration types.
//!
//! Both `stoa-transit` and `stoa-reader` use these types in their TOML
//! configs.  Centralising them here ensures that adding a new backend type
//! or field requires exactly one edit instead of one per binary.

use serde::Deserialize;

// ── Backend config (pluggable block store) ────────────────────────────────────

/// Selects the IPFS block storage backend.
///
/// Use `[backend]` with a `type` key instead of the legacy `[ipfs]` section
/// to activate a specific backend.  `[ipfs]` is retained for backward
/// compatibility; when both are present `[backend]` takes precedence.
#[derive(Debug, Deserialize, Clone)]
pub struct BackendConfig {
    /// Backend discriminator.  Supported values: `"kubo"`, `"lmdb"`.
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
    /// Directory for the local block cache.  Created at startup if absent.
    /// Omit to disable caching.
    #[serde(default)]
    pub cache_path: Option<String>,
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
