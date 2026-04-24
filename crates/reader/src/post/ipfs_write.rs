//! IPFS block write abstraction and CID recording for the POST pipeline.
//!
//! `IpfsBlockStore` abstracts raw block storage so that tests can use an
//! in-memory implementation (`MemIpfsStore`) without a running Kubo node.
//! The production implementation is [`KuboBlockStore`].

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::session::response::Response;
use usenet_ipfs_core::{ipld::builder::build_article, msgid_map::MsgIdMap};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during IPFS block operations.
#[derive(Debug)]
pub enum IpfsWriteError {
    NotReachable(String),
    WriteFailed(String),
    NotFound(String),
}

impl std::fmt::Display for IpfsWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpfsWriteError::NotReachable(msg) => write!(f, "IPFS node not reachable: {msg}"),
            IpfsWriteError::WriteFailed(msg) => write!(f, "IPFS write failed: {msg}"),
            IpfsWriteError::NotFound(msg) => write!(f, "IPFS block not found: {msg}"),
        }
    }
}

impl std::error::Error for IpfsWriteError {}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over IPFS raw block storage.
///
/// In production: backed by a Kubo daemon via [`KuboBlockStore`]. In tests: backed by [`MemIpfsStore`].
#[async_trait]
pub trait IpfsBlockStore: Send + Sync {
    /// Write a raw block to IPFS. Returns the CID of the stored block.
    async fn put_raw_block(&self, data: &[u8]) -> Result<Cid, IpfsWriteError>;

    /// Store a block with a pre-computed CID (e.g. DAG-CBOR blocks from
    /// `build_article`).  The caller is responsible for ensuring `cid` matches
    /// the content of `data`.
    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError>;

    /// Read a raw block from IPFS by CID. Returns the block bytes.
    async fn get_raw_block(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError>;

    /// Mark `cid` for deletion.
    ///
    /// The default implementation signals that deletion is deferred — callers
    /// must not assume the block is gone until `get_raw_block` returns `NotFound`.
    /// Override to provide backend-specific behaviour.
    async fn delete(
        &self,
        _cid: &Cid,
    ) -> Result<usenet_ipfs_core::ipfs::DeletionOutcome, IpfsWriteError> {
        Ok(usenet_ipfs_core::ipfs::DeletionOutcome::Deferred {
            readable_for_approx_secs: None,
        })
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation (for tests)
// ---------------------------------------------------------------------------

/// In-memory IPFS block store for use in unit tests.
///
/// Computes CIDv1 RAW SHA2-256 on `put_raw_block`, stores the block keyed by
/// the CID's raw bytes, and returns the same bytes on `get_raw_block`.
pub struct MemIpfsStore {
    blocks: tokio::sync::RwLock<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemIpfsStore {
    pub fn new() -> Self {
        Self {
            blocks: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MemIpfsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IpfsBlockStore for MemIpfsStore {
    async fn put_raw_block(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        self.blocks
            .write()
            .await
            .insert(cid.to_bytes(), data.to_vec());
        Ok(cid)
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        self.blocks.write().await.insert(cid.to_bytes(), data);
        Ok(())
    }

    async fn get_raw_block(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        self.blocks
            .read()
            .await
            .get(&cid.to_bytes())
            .cloned()
            .ok_or_else(|| IpfsWriteError::NotFound(cid.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Production Kubo implementation
// ---------------------------------------------------------------------------

/// IPFS block store backed by a Kubo daemon via its HTTP RPC API.
///
/// Optionally wraps a local filesystem cache: blocks are read from disk on
/// cache hits and written through to both disk and Kubo on puts. The cache
/// directory holds one file per CID (named by the CID's string representation).
/// No LRU eviction is performed; disk management is the operator's responsibility.
pub struct KuboBlockStore {
    client: usenet_ipfs_core::ipfs::KuboHttpClient,
    cache_dir: Option<std::path::PathBuf>,
}

impl KuboBlockStore {
    /// Create a store targeting the Kubo daemon at `api_url`.
    ///
    /// If `cache_dir` is `Some`, blocks are cached in that directory.
    /// The directory must already exist.
    pub fn new(api_url: &str, cache_dir: Option<std::path::PathBuf>) -> Self {
        Self {
            client: usenet_ipfs_core::ipfs::KuboHttpClient::new(api_url),
            cache_dir,
        }
    }

    fn cache_path(&self, cid: &Cid) -> Option<std::path::PathBuf> {
        self.cache_dir.as_ref().map(|dir| dir.join(cid.to_string()))
    }

    async fn cache_get(&self, cid: &Cid) -> Option<Vec<u8>> {
        let path = self.cache_path(cid)?;
        tokio::fs::read(&path).await.ok()
    }

    async fn cache_put(&self, cid: &Cid, bytes: &[u8]) {
        if let Some(path) = self.cache_path(cid) {
            if let Err(e) = tokio::fs::write(&path, bytes).await {
                tracing::warn!(cid = %cid, "block cache write failed: {e}");
            }
        }
    }
}

#[async_trait]
impl IpfsBlockStore for KuboBlockStore {
    async fn put_raw_block(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let cid = self
            .client
            .block_put(data, 0x55)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        self.cache_put(&cid, data).await;
        Ok(cid)
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        self.client
            .block_put(&data, cid.codec())
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        self.cache_put(&cid, &data).await;
        Ok(())
    }

    async fn get_raw_block(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        if let Some(bytes) = self.cache_get(cid).await {
            return Ok(bytes);
        }
        match self
            .client
            .block_get(cid)
            .await
            .map_err(|e| IpfsWriteError::NotReachable(e.to_string()))?
        {
            Some(bytes) => {
                self.cache_put(cid, &bytes).await;
                Ok(bytes)
            }
            None => Err(IpfsWriteError::NotFound(cid.to_string())),
        }
    }

    /// Unpin `cid` from Kubo. The block remains readable until `ipfs repo gc` runs.
    async fn delete(
        &self,
        cid: &Cid,
    ) -> Result<usenet_ipfs_core::ipfs::DeletionOutcome, IpfsWriteError> {
        self.client
            .pin_rm(cid)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(usenet_ipfs_core::ipfs::DeletionOutcome::Deferred {
            readable_for_approx_secs: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Store factory
// ---------------------------------------------------------------------------

/// Construct the IPFS block store from configuration.
///
/// Prefers `config.backend` when present; falls back to the legacy `config.ipfs`
/// section for backward compatibility.
///
/// Returns `Err` for backends that are not yet implemented.
pub fn build_block_store(
    config: &crate::config::Config,
) -> Result<std::sync::Arc<dyn IpfsBlockStore>, String> {
    use std::sync::Arc;
    if let Some(backend) = &config.backend {
        use crate::config::BackendType;
        match backend.backend_type {
            BackendType::Kubo => {
                let kubo_cfg = backend
                    .kubo
                    .as_ref()
                    .ok_or("backend.type = 'kubo' requires a [backend.kubo] section")?;
                let cache_dir = kubo_cfg.cache_path.as_ref().map(std::path::PathBuf::from);
                Ok(Arc::new(KuboBlockStore::new(&kubo_cfg.api_url, cache_dir)))
            }
            BackendType::Lmdb => {
                let lmdb_cfg = backend
                    .lmdb
                    .as_ref()
                    .ok_or("backend.type = 'lmdb' requires a [backend.lmdb] section")?;
                let store = super::lmdb_store::LmdbBlockStore::open(
                    std::path::Path::new(&lmdb_cfg.path),
                    lmdb_cfg.map_size_gb,
                )
                .map_err(|e| format!("LMDB store init failed: {e}"))?;
                Ok(Arc::new(store))
            }
            BackendType::S3 => Err("S3 backend is not yet implemented".to_string()),
            BackendType::Filesystem => Err("filesystem backend is not yet implemented".to_string()),
        }
    } else {
        // Backward-compat: use legacy [ipfs] section.
        let cache_dir = config
            .ipfs
            .cache_path
            .as_ref()
            .map(std::path::PathBuf::from);
        Ok(Arc::new(KuboBlockStore::new(
            &config.ipfs.api_url,
            cache_dir,
        )))
    }
}

// ---------------------------------------------------------------------------
// Pipeline functions
// ---------------------------------------------------------------------------

/// Write a signed article to IPFS and record the Message-ID → CID mapping.
///
/// Steps:
/// 1. Write block to IPFS via `ipfs_store.put_raw_block(article_bytes)`.
///    The returned CID is CIDv1 RAW SHA2-256 of `article_bytes`.
/// 2. Insert `(message_id, cid)` into `msgid_map` (idempotent).
/// 3. Return `Ok(cid)` on success.
/// 4. Return `Err(441 response)` if the IPFS write fails; `msgid_map` is
///    **not** updated in that case.
pub async fn write_article_to_ipfs(
    ipfs_store: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
    article_bytes: &[u8],
    message_id: &str,
) -> Result<Cid, Response> {
    let cid = ipfs_store
        .put_raw_block(article_bytes)
        .await
        .map_err(|e| Response::new(441, format!("Posting failed: IPFS write error: {e}")))?;

    msgid_map
        .insert(message_id, &cid)
        .await
        .map_err(|e| Response::new(441, format!("Posting failed: storage error: {e}")))?;

    Ok(cid)
}

/// Write a signed article to IPFS as a proper IPLD block set and record the
/// Message-ID → root CID mapping.
///
/// Uses [`build_article`] to construct DAG-CBOR root (codec 0x71) plus raw
/// header/body/MIME sub-blocks.  Every block is stored via [`put_block`] so
/// that the root CID carries the correct DAG-CBOR codec required by
/// [`verify_entry`].
///
/// Steps:
/// 1. Split `article_bytes` into header and body sections.
/// 2. Call [`build_article`] to produce the IPLD block set.
/// 3. Store every block via `ipfs_store.put_block(cid, data)`.
/// 4. Insert `(message_id, root_cid)` into `msgid_map` (idempotent).
/// 5. Return `Ok(root_cid)` on success.
pub async fn write_ipld_article_to_ipfs(
    ipfs_store: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
    article_bytes: &[u8],
    message_id: &str,
    newsgroups: Vec<String>,
    hlc_timestamp: u64,
) -> Result<Cid, Response> {
    // Split header and body.
    let (header_bytes, body_bytes) = split_header_body(article_bytes);

    // Build the IPLD block set.
    let built = build_article(
        &header_bytes,
        &body_bytes,
        message_id.to_owned(),
        newsgroups,
        hlc_timestamp,
    )
    .map_err(|e| Response::new(441, format!("Posting failed: IPLD build error: {e}")))?;

    // Store all blocks.
    for (cid, data) in built.blocks {
        ipfs_store
            .put_block(cid, data)
            .await
            .map_err(|e| Response::new(441, format!("Posting failed: IPFS write error: {e}")))?;
    }

    // Record Message-ID → root CID mapping.
    msgid_map
        .insert(message_id, &built.root_cid)
        .await
        .map_err(|e| Response::new(441, format!("Posting failed: storage error: {e}")))?;

    Ok(built.root_cid)
}

/// Split raw article bytes at the first blank line separator.
///
/// Returns `(header_bytes, body_bytes)`.  The separator itself is consumed.
/// If no blank line is found, returns `(article_bytes, [])`.
fn split_header_body(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    for i in 0..bytes.len().saturating_sub(3) {
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return (bytes[..i].to_vec(), bytes[i + 4..].to_vec());
        }
    }
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i..].starts_with(b"\n\n") {
            return (bytes[..i].to_vec(), bytes[i + 2..].to_vec());
        }
    }
    (bytes.to_vec(), vec![])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use usenet_ipfs_core::msgid_map::MsgIdMap;

    async fn make_msgid_map() -> MsgIdMap {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        usenet_ipfs_core::migrations::run_migrations(&pool)
            .await
            .unwrap();
        MsgIdMap::new(pool)
    }

    /// Failure injection wrapper for `IpfsBlockStore`.
    ///
    /// Wraps a `MemIpfsStore` and injects failures based on a configurable
    /// policy. For use in tests only.
    struct FailingIpfsStore {
        inner: MemIpfsStore,
        /// If `Some(n)`, fail on every call whose 1-indexed count is divisible
        /// by `n`.
        fail_every_n: Option<u64>,
        call_count: std::sync::atomic::AtomicU64,
        /// If `true`, every call fails regardless of `fail_every_n`.
        always_fail: bool,
    }

    impl FailingIpfsStore {
        fn always_fail() -> Self {
            Self {
                inner: MemIpfsStore::new(),
                fail_every_n: None,
                call_count: std::sync::atomic::AtomicU64::new(0),
                always_fail: true,
            }
        }

        fn fail_every_n(n: u64) -> Self {
            Self {
                inner: MemIpfsStore::new(),
                fail_every_n: Some(n),
                call_count: std::sync::atomic::AtomicU64::new(0),
                always_fail: false,
            }
        }

        /// Increment the call counter and return `true` if this call should
        /// be failed according to the configured policy.
        fn should_fail(&self) -> bool {
            if self.always_fail {
                return true;
            }
            if let Some(n) = self.fail_every_n {
                let count = self
                    .call_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                return count % n == 0;
            }
            false
        }
    }

    #[async_trait]
    impl IpfsBlockStore for FailingIpfsStore {
        async fn put_raw_block(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
            if self.should_fail() {
                return Err(IpfsWriteError::WriteFailed("injected failure".into()));
            }
            self.inner.put_raw_block(data).await
        }

        async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
            if self.should_fail() {
                return Err(IpfsWriteError::WriteFailed("injected failure".into()));
            }
            self.inner.put_block(cid, data).await
        }

        async fn get_raw_block(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
            if self.should_fail() {
                return Err(IpfsWriteError::WriteFailed("injected failure".into()));
            }
            self.inner.get_raw_block(cid).await
        }
    }

    #[tokio::test]
    async fn write_returns_stable_cid() {
        let store = MemIpfsStore::new();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let cid1 = store.put_raw_block(data).await.unwrap();
        let cid2 = store.put_raw_block(data).await.unwrap();

        assert_eq!(cid1, cid2, "same bytes must produce the same CID");
    }

    #[tokio::test]
    async fn write_records_in_msgid_map() {
        let store = MemIpfsStore::new();
        let map = make_msgid_map().await;
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";
        let msgid = "<test-record@example.com>";

        let cid = write_article_to_ipfs(&store, &map, data, msgid)
            .await
            .unwrap();

        let found = map.lookup_by_msgid(msgid).await.unwrap();
        assert_eq!(
            found,
            Some(cid),
            "msgid_map must record the CID after write"
        );
    }

    #[tokio::test]
    async fn write_then_get_block() {
        let store = MemIpfsStore::new();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let cid = store.put_raw_block(data).await.unwrap();
        let retrieved = store.get_raw_block(&cid).await.unwrap();

        assert_eq!(retrieved, data, "retrieved bytes must match written bytes");
    }

    #[tokio::test]
    async fn ipfs_failure_does_not_record_msgid() {
        let store = FailingIpfsStore::always_fail();
        let map = make_msgid_map().await;
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";
        let msgid = "<test-failure@example.com>";

        let result = write_article_to_ipfs(&store, &map, data, msgid).await;
        assert!(result.is_err(), "IPFS failure must return Err");
        assert_eq!(result.unwrap_err().code, 441);

        let found = map.lookup_by_msgid(msgid).await.unwrap();
        assert!(
            found.is_none(),
            "msgid_map must not be updated when IPFS write fails"
        );
    }

    #[tokio::test]
    async fn cid_uses_raw_codec() {
        let store = MemIpfsStore::new();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let cid = store.put_raw_block(data).await.unwrap();

        assert_eq!(cid.codec(), 0x55, "CID codec must be RAW (0x55)");
    }

    #[tokio::test]
    async fn always_fail_store_returns_error() {
        let store = FailingIpfsStore::always_fail();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let result = store.put_raw_block(data).await;
        assert!(
            result.is_err(),
            "always_fail store must return Err on every call"
        );
    }

    #[tokio::test]
    async fn fail_every_n_fails_on_nth_call() {
        let store = FailingIpfsStore::fail_every_n(2);
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        // Call 1 (count=1, 1%2 != 0): should succeed.
        let result1 = store.put_raw_block(data).await;
        assert!(result1.is_ok(), "call 1 must succeed with fail_every_n=2");

        // Call 2 (count=2, 2%2 == 0): should fail.
        let result2 = store.put_raw_block(data).await;
        assert!(result2.is_err(), "call 2 must fail with fail_every_n=2");

        // Call 3 (count=3, 3%2 != 0): should succeed.
        let result3 = store.put_raw_block(data).await;
        assert!(result3.is_ok(), "call 3 must succeed with fail_every_n=2");
    }

    #[tokio::test]
    async fn non_failing_store_roundtrip() {
        let store = MemIpfsStore::new();
        let data = b"From: user@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";

        let cid = store.put_raw_block(data).await.unwrap();
        let retrieved = store.get_raw_block(&cid).await.unwrap();

        assert_eq!(
            retrieved, data,
            "MemIpfsStore put/get roundtrip must be exact"
        );
    }
}
