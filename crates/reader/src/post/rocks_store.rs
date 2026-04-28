//! RocksDB block store backend for the reader daemon.
//!
//! All blocking RocksDB operations are dispatched via
//! [`tokio::task::spawn_blocking`] so they do not stall the async runtime.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::{path::Path, sync::Arc};
use tokio::task;

use stoa_core::ipfs::DeletionOutcome;

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};

/// IPFS block store backed by RocksDB.
///
/// ## Key format
///
/// Keys are raw CID bytes (`cid.to_bytes()`, 36 bytes for CIDv1 SHA-256).
/// The binary representation is preferred over the base32 string form:
/// - It is 36 bytes vs ~59 bytes for the string, reducing index size.
/// - It avoids codec round-trips on every lookup.
/// - It is the canonical form used by IPFS/IPLD tooling.
/// All IPFS tools can decode the binary CID, so debuggability is not lost.
pub struct RocksBlockStore {
    db: Arc<rocksdb::DB>,
}

impl RocksBlockStore {
    /// Open or create the RocksDB database at `path`.
    ///
    /// `cache_size_mb` sets the LRU block cache size (default: 64 MiB).
    /// A Bloom filter is always enabled on the default column family so that
    /// negative lookups (checking whether a block is already stored) are
    /// cheap without a disk read.
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

impl std::fmt::Debug for RocksBlockStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RocksBlockStore({})", self.db.path().display())
    }
}

#[async_trait]
impl IpfsBlockStore for RocksBlockStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let db = Arc::clone(&self.db);
        let data = data.to_vec();
        task::spawn_blocking(move || {
            let digest = Code::Sha2_256.digest(&data);
            let cid = Cid::new_v1(0x55, digest);
            db.put(cid.to_bytes(), &data)
                .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
            Ok(cid)
        })
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        let db = Arc::clone(&self.db);
        let cid_bytes = cid.to_bytes();
        task::spawn_blocking(move || {
            db.put(cid_bytes, &data)
                .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))
        })
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        let db = Arc::clone(&self.db);
        let cid_string = cid.to_string();
        let cid_bytes = cid.to_bytes();
        task::spawn_blocking(move || {
            db.get(&cid_bytes)
                .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
                .ok_or_else(|| IpfsWriteError::NotFound(cid_string))
        })
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
    }

    /// Remove `cid` from RocksDB.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: deleting a
    /// CID that does not exist writes a tombstone but succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsWriteError> {
        let db = Arc::clone(&self.db);
        let cid_bytes = cid.to_bytes();
        task::spawn_blocking(move || {
            db.delete(cid_bytes)
                .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
            Ok(DeletionOutcome::Immediate)
        })
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_store() -> (RocksBlockStore, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = RocksBlockStore::open(tmp.path(), Some(1)).expect("open RocksDB");
        (store, tmp)
    }

    #[tokio::test]
    async fn round_trip_put_raw_and_get() {
        let (store, _tmp) = open_test_store();
        let data = b"reader RocksDB round trip";
        let cid = store.put_raw(data).await.expect("put");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn put_block_and_get() {
        let (store, _tmp) = open_test_store();
        let data = b"dag-cbor block";
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x71, digest);
        store
            .put_block(cid.clone(), data.to_vec())
            .await
            .expect("put_block");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let (store, _tmp) = open_test_store();
        let digest = Code::Sha2_256.digest(b"not stored");
        let cid = Cid::new_v1(0x55, digest);
        let result = store.get_raw(&cid).await;
        assert!(
            matches!(result, Err(IpfsWriteError::NotFound(_))),
            "missing block must return NotFound: {result:?}"
        );
    }

    #[tokio::test]
    async fn delete_removes_block_immediately() {
        let (store, _tmp) = open_test_store();
        let data = b"to be deleted";
        let cid = store.put_raw(data).await.expect("put");

        let outcome = store.delete(&cid).await.expect("delete");
        assert_eq!(outcome, DeletionOutcome::Immediate);

        let result = store.get_raw(&cid).await;
        assert!(
            matches!(result, Err(IpfsWriteError::NotFound(_))),
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
    async fn delete_nonexistent_succeeds() {
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
        let data = b"concurrent reader data";
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
            assert_eq!(result, data.to_vec());
        }
    }
}
