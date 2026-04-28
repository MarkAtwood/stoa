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
    /// Backend discriminator.  Supported values: `"kubo"`, `"lmdb"`, `"filesystem"`, `"sqlite"`.
    #[serde(rename = "type")]
    pub backend_type: BackendType,
    /// Kubo-specific settings.  Required when `type = "kubo"`.
    #[serde(default)]
    pub kubo: Option<KuboBackendConfig>,
    /// S3-specific settings.  Required when `type = "s3"`.
    #[serde(default)]
    pub s3: Option<S3BackendConfig>,
    /// Filesystem-specific settings.  Required when `type = "filesystem"`.
    #[serde(default)]
    pub filesystem: Option<FsBackendConfig>,
    /// LMDB-specific settings.  Required when `type = "lmdb"`.
    #[serde(default)]
    pub lmdb: Option<LmdbBackendConfig>,
    /// SQLite-specific settings.  Required when `type = "sqlite"`.
    #[serde(default)]
    pub sqlite: Option<SqliteBackendConfig>,
}

/// Backend type discriminator.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    Kubo,
    S3,
    Filesystem,
    Lmdb,
    Sqlite,
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

/// Configuration for the S3-compatible object storage backend.
///
/// Supports AWS S3, MinIO, Backblaze B2, Wasabi, and any S3-compatible service.
///
/// ## Object layout
///
/// Blocks are stored as `<prefix>/<cid-base32-lowercase>` objects.
/// The default prefix is `blocks`.  CID encoding matches the CIDv1 `Display`
/// (multibase base32 lowercase), providing a stable key contract.
///
/// ## Credentials
///
/// `access_key_id` and `secret_access_key` accept literal values or
/// `secretx://` URIs (e.g. `secretx://env/AWS_SECRET_ACCESS_KEY`).
/// Omit both to use instance-profile / IRSA credentials on AWS.
///
/// ## MinIO / local S3
///
/// Set `endpoint` to your MinIO address and `allow_http = true` when TLS
/// is not configured locally.
///
/// ## GC
///
/// Blocks are deleted by the transit GC via explicit `DELETE` requests.
/// Reclaim storage with S3 lifecycle rules as a belt-and-suspenders fallback.
#[derive(Debug, Deserialize, Clone)]
pub struct S3BackendConfig {
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region (e.g. `"us-east-1"`).  Required for AWS; any string for MinIO.
    pub region: String,
    /// Custom endpoint URL.  Required for MinIO and other S3-compatible services.
    /// Example: `"http://127.0.0.1:9000"`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Access key ID.  Literal value or `secretx://` URI.
    /// Omit to use instance-profile credentials.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// Secret access key.  Literal value or `secretx://` URI.
    /// Omit to use instance-profile credentials.
    #[serde(default)]
    pub secret_access_key: Option<String>,
    /// Object key prefix.  Defaults to `"blocks"`.
    /// Use this to share a bucket between multiple stoa instances.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Allow plain HTTP connections.  Defaults to `false`.
    /// Set `true` for MinIO without TLS.
    #[serde(default)]
    pub allow_http: Option<bool>,
}

/// Configuration for the filesystem block store backend.
///
/// ## Directory layout
///
/// Block files are stored flat (no subdirectories) as
/// `<path>/<cid-base32-lowercase>.block`.  This layout is a stable on-disk
/// contract.  Stale `*.block.tmp` write-ahead files from crashed writes are
/// harmless and can be removed with `find <path> -name "*.block.tmp" -delete`.
///
/// ## Disk sizing
///
/// A typical NNTP text article is 1–50 KiB.  Budget roughly 1 KiB overhead
/// per block for filesystem metadata.  For 1 M articles at an average of
/// 5 KiB each, expect ~6 GiB.
///
/// ## GC
///
/// The transit daemon's `gc.max_age_days` controls which articles are
/// unpinned.  For the filesystem backend `delete()` is immediate (unlike
/// Kubo's deferred unpin).  To also remove blocks from the filesystem
/// on a cron schedule:
/// ```text
/// find <path> -name "*.block" -mtime +N -delete
/// ```
/// where `N` is your `max_age_days` value.
#[derive(Debug, Deserialize, Clone)]
pub struct FsBackendConfig {
    /// Root directory for block files.  Created at startup if absent.
    pub path: String,
    /// Soft cap on total stored bytes.  When the total size of all `.block`
    /// files in the directory exceeds this value, `put` operations return an
    /// error so the pipeline can shed load rather than filling the disk
    /// silently.  Omit to disable.
    #[serde(default)]
    pub max_bytes: Option<u64>,
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

/// Configuration for the SQLite BLOB block store backend.
///
/// ## Schema
///
/// A `blocks` table is created (or verified) at startup:
/// ```sql
/// CREATE TABLE IF NOT EXISTS blocks (
///     cid       TEXT    NOT NULL PRIMARY KEY,
///     codec     INTEGER NOT NULL,
///     data      BLOB    NOT NULL,
///     byte_size INTEGER NOT NULL,
///     stored_at INTEGER NOT NULL  -- unix milliseconds
/// );
/// ```
///
/// ## Sizing
///
/// SQLite performs well up to ~50–100 GB.  For larger deployments, use the
/// LMDB backend.  WAL mode is enabled by default for concurrent reads.
///
/// ## GC
///
/// The transit daemon's `gc.max_age_days` issues `DELETE FROM blocks WHERE
/// cid = ?` for each expired article.  Reclaim space with `VACUUM` or
/// `PRAGMA incremental_vacuum` after large GC runs.
#[derive(Debug, Deserialize, Clone)]
pub struct SqliteBackendConfig {
    /// Path to the SQLite database file.  Created at startup if absent.
    pub path: String,
}
