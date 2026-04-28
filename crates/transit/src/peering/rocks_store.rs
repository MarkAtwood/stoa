//! RocksDB block store backend for the transit daemon.
//!
//! All blocking RocksDB operations are dispatched via
//! [`tokio::task::spawn_blocking`] so they do not stall the async runtime.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::{path::Path, sync::Arc};
use tokio::task;

use stoa_core::ipfs::DeletionOutcome;

use crate::peering::pipeline::{IpfsError, IpfsStore};

/// IPFS block store backed by RocksDB.
///
/// ## Key format
///
/// Keys are raw CID bytes (`cid.to_bytes()`, 36 bytes for CIDv1 SHA-256).
/// The binary representation is preferred over the base32 string form:
/// - It is 36 bytes vs ~59 bytes for the string, reducing index size.
/// - It avoids codec round-trips on every lookup.
/// - It is the canonical form used by IPFS/IPLD tooling.
///
/// All IPFS tools can decode the binary CID, so debuggability is not lost.
pub struct RocksStore {
    db: Arc<rocksdb::DB>,
}

impl RocksStore {
    /// Open or create the RocksDB database at `path`.
    ///
    /// `cache_size_mb` sets the LRU block cache size (default: 64 MiB).
    /// A Bloom filter is always enabled on the default column family so that
    /// negative lookups (transit nodes checking whether they already have a
    /// block) are cheap without a disk read.
    pub fn open(path: &Path, cache_size_mb: Option<u64>) -> Result<Self, String> {
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_bloom_filter(10.0, false);
        let cache_bytes = cache_size_mb.unwrap_or(64) as usize * 1024 * 1024;
        let cache = rocksdb::Cache::new_lru_cache(cache_bytes);
        block_opts.set_block_cache(&cache);

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_block_based_table_factory(&block_opts);

        let db = rocksdb::DB::open(&opts, path)
            .map_err(|e| format!("RocksDB open failed at '{}': {e}", path.display()))?;
        Ok(Self { db: Arc::new(db) })
    }
}

impl std::fmt::Debug for RocksStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RocksStore({})", self.db.path().display())
    }
}

#[async_trait]
impl IpfsStore for RocksStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let db = Arc::clone(&self.db);
        let data = data.to_vec();
        task::spawn_blocking(move || {
            let digest = Code::Sha2_256.digest(&data);
            let cid = Cid::new_v1(0x55, digest);
            db.put(cid.to_bytes(), &data)
                .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
            Ok(cid)
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        let db = Arc::clone(&self.db);
        let cid_bytes = cid.to_bytes();
        task::spawn_blocking(move || {
            db.get(cid_bytes)
                .map_err(|e| IpfsError::ReadFailed(e.to_string()))
        })
        .await
        .map_err(|e| IpfsError::ReadFailed(e.to_string()))?
    }

    /// Remove `cid` from RocksDB.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: deleting a
    /// CID that does not exist writes a tombstone but succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsError> {
        let db = Arc::clone(&self.db);
        let cid_bytes = cid.to_bytes();
        task::spawn_blocking(move || {
            db.delete(cid_bytes)
                .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
            Ok(DeletionOutcome::Immediate)
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_store() -> (RocksStore, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = RocksStore::open(tmp.path(), Some(1)).expect("open RocksDB");
        (store, tmp)
    }

    #[tokio::test]
    async fn round_trip_put_and_get() {
        let (store, _tmp) = open_test_store();
        let data = b"hello, RocksDB transit store";
        let cid = store.put_raw(data).await.expect("put");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(
            retrieved,
            Some(data.to_vec()),
            "retrieved bytes must match stored bytes"
        );
    }

    #[tokio::test]
    async fn put_is_idempotent() {
        let (store, _tmp) = open_test_store();
        let data = b"idempotent write";
        let cid1 = store.put_raw(data).await.expect("put 1");
        let cid2 = store.put_raw(data).await.expect("put 2");
        assert_eq!(cid1, cid2, "same content must produce same CID");
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let (store, _tmp) = open_test_store();
        let digest = Code::Sha2_256.digest(b"not stored");
        let cid = Cid::new_v1(0x55, digest);
        let result = store.get_raw(&cid).await.expect("get");
        assert!(result.is_none(), "missing block must return None");
    }

    #[tokio::test]
    async fn delete_removes_block_immediately() {
        let (store, _tmp) = open_test_store();
        let data = b"to be deleted";
        let cid = store.put_raw(data).await.expect("put");

        assert!(store.get_raw(&cid).await.expect("get before").is_some());

        let outcome = store.delete(&cid).await.expect("delete");
        assert_eq!(outcome, DeletionOutcome::Immediate);

        assert!(
            store.get_raw(&cid).await.expect("get after").is_none(),
            "block must be gone after delete"
        );
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let (store, _tmp) = open_test_store();
        let data = b"double delete";
        let cid = store.put_raw(data).await.expect("put");
        store.delete(&cid).await.expect("delete 1");
        store.delete(&cid).await.expect("delete 2 should not error");
    }

    #[tokio::test]
    async fn delete_nonexistent_cid_succeeds() {
        let (store, _tmp) = open_test_store();
        let digest = Code::Sha2_256.digest(b"never stored");
        let cid = Cid::new_v1(0x55, digest);
        store
            .delete(&cid)
            .await
            .expect("delete of missing CID must succeed");
    }

    #[tokio::test]
    async fn concurrent_reads_no_contention() {
        let (store, _tmp) = open_test_store();
        let data = b"concurrent read data";
        let cid = store.put_raw(data).await.expect("put");
        let store = Arc::new(store);

        let mut handles = Vec::new();
        for _ in 0..10 {
            let store = Arc::clone(&store);
            let cid = cid.clone();
            handles.push(tokio::spawn(async move { store.get_raw(&cid).await }));
        }

        for handle in handles {
            let result = handle.await.expect("task").expect("get");
            assert_eq!(result, Some(data.to_vec()));
        }
    }
}
