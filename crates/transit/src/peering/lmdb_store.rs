//! LMDB block store backend for the transit daemon.
//!
//! Delegates all LMDB I/O to [`stoa_lmdb::LmdbBlockDb`] (the FFI
//! boundary crate that contains the single `unsafe` call to open the
//! environment).  All blocking LMDB operations are dispatched via
//! [`tokio::task::spawn_blocking`] so they do not stall the async runtime.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::{path::Path, sync::Arc};
use tokio::task;

use stoa_core::ipfs::DeletionOutcome;
use stoa_lmdb::LmdbBlockDb;

use crate::peering::pipeline::{IpfsError, IpfsStore};

/// IPFS block store backed by LMDB.
pub struct LmdbStore {
    db: Arc<LmdbBlockDb>,
}

impl LmdbStore {
    /// Open or create the LMDB environment at `path`.
    ///
    /// `map_size_gb` sets the virtual address space reservation in GiB
    /// (default: 1024 for production; use 1 in tests).
    pub fn open(path: &Path, map_size_gb: u64) -> Result<Self, String> {
        Ok(Self {
            db: Arc::new(LmdbBlockDb::open(path, map_size_gb)?),
        })
    }
}

#[async_trait]
impl IpfsStore for LmdbStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let db = Arc::clone(&self.db);
        let data = data.to_vec();
        task::spawn_blocking(move || {
            let digest = Code::Sha2_256.digest(&data);
            let cid = Cid::new_v1(0x55, digest);
            db.put(&cid.to_bytes(), &data)
                .map_err(|e| IpfsError::WriteFailed(e))?;
            Ok(cid)
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        let db = Arc::clone(&self.db);
        let cid_bytes = cid.to_bytes();
        task::spawn_blocking(move || {
            db.get(&cid_bytes).map_err(|e| IpfsError::WriteFailed(e))
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }

    /// Remove `cid` from LMDB.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: deleting a
    /// CID that does not exist succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsError> {
        let db = Arc::clone(&self.db);
        let cid_bytes = cid.to_bytes();
        task::spawn_blocking(move || {
            db.delete(&cid_bytes)
                .map_err(|e| IpfsError::WriteFailed(e))?;
            Ok(DeletionOutcome::Immediate)
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_store() -> (LmdbStore, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = LmdbStore::open(tmp.path(), 1).expect("open LMDB");
        (store, tmp)
    }

    #[tokio::test]
    async fn round_trip_put_and_get() {
        let (store, _tmp) = open_test_store();
        let data = b"hello, LMDB transit store";
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
