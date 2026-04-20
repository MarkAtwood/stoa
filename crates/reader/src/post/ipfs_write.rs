//! IPFS block write abstraction and CID recording for the POST pipeline.
//!
//! `IpfsBlockStore` abstracts raw block storage so that tests can use an
//! in-memory implementation (`MemIpfsStore`) without a running IPFS node.
//! The production implementation backed by `rust-ipfs` will be wired in
//! when the daemon is set up.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::session::response::Response;
use usenet_ipfs_core::msgid_map::MsgIdMap;

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
/// In production: backed by `rust-ipfs`. In tests: backed by `MemIpfsStore`.
#[async_trait]
pub trait IpfsBlockStore: Send + Sync {
    /// Write a raw block to IPFS. Returns the CID of the stored block.
    async fn put_raw_block(&self, data: &[u8]) -> Result<Cid, IpfsWriteError>;

    /// Read a raw block from IPFS by CID. Returns the block bytes.
    async fn get_raw_block(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError>;
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
        Self { blocks: tokio::sync::RwLock::new(std::collections::HashMap::new()) }
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
        self.blocks.write().await.insert(cid.to_bytes(), data.to_vec());
        Ok(cid)
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
// Pipeline function
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
    let cid = ipfs_store.put_raw_block(article_bytes).await.map_err(|e| {
        Response::new(441, format!("Posting failed: IPFS write error: {e}"))
    })?;

    msgid_map.insert(message_id, &cid).await.map_err(|e| {
        Response::new(441, format!("Posting failed: storage error: {e}"))
    })?;

    Ok(cid)
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
        usenet_ipfs_core::migrations::run_migrations(&pool).await.unwrap();
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
                let count =
                    self.call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
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

        let cid = write_article_to_ipfs(&store, &map, data, msgid).await.unwrap();

        let found = map.lookup_by_msgid(msgid).await.unwrap();
        assert_eq!(found, Some(cid), "msgid_map must record the CID after write");
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
        assert!(found.is_none(), "msgid_map must not be updated when IPFS write fails");
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
        assert!(result.is_err(), "always_fail store must return Err on every call");
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

        assert_eq!(retrieved, data, "MemIpfsStore put/get roundtrip must be exact");
    }
}
