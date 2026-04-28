//! Filesystem block store backend for the reader daemon.
//!
//! Stores one file per block under a configured directory.  Files are named
//! `<cid-base32>.block` (e.g. `bafkreib…abc.block`).  Writes are atomic:
//! data lands in `<cid>.block.tmp` and is renamed into place so that a crash
//! mid-write cannot leave a corrupt block file visible to readers.
//!
//! All blocking file I/O is dispatched via [`tokio::task::spawn_blocking`]
//! to avoid stalling the async runtime.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::{path::Path, sync::Arc};
use tokio::task;

use stoa_core::ipfs::DeletionOutcome;

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};

/// IPFS block store backed by a plain filesystem directory.
pub struct FsBlockStore {
    path: Arc<std::path::PathBuf>,
}

impl FsBlockStore {
    /// Open (or create) the block store at `path`.
    ///
    /// Creates `path` if absent.  Returns `Err` if the directory cannot be
    /// created or is not writable.
    pub fn open(path: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(path).map_err(|e| {
            format!(
                "filesystem store: cannot create directory {}: {e}",
                path.display()
            )
        })?;
        let probe = path.join(".stoa_write_probe");
        std::fs::write(&probe, b"").map_err(|e| {
            format!(
                "filesystem store: directory {} is not writable: {e}",
                path.display()
            )
        })?;
        let _ = std::fs::remove_file(&probe);
        Ok(Self {
            path: Arc::new(path.to_path_buf()),
        })
    }

    fn write_block_sync(path: &std::path::Path, cid: &Cid, data: &[u8]) -> Result<(), IpfsWriteError> {
        let filename = cid.to_string();
        let block_path = path.join(format!("{filename}.block"));
        if block_path.exists() {
            return Ok(());
        }
        let tmp_path = path.join(format!("{filename}.block.tmp"));
        std::fs::write(&tmp_path, data)
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        std::fs::rename(&tmp_path, &block_path)
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl IpfsBlockStore for FsBlockStore {
    /// Write `data` to a file named `<cid>.block`, computing the CID from the data.
    ///
    /// Idempotent: if the file already exists the data is not rewritten.
    /// Uses an atomic temp-then-rename write.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let path = Arc::clone(&self.path);
        let data = data.to_vec();
        task::spawn_blocking(move || {
            let digest = Code::Sha2_256.digest(&data);
            let cid = Cid::new_v1(0x55, digest);
            Self::write_block_sync(&path, &cid, &data)?;
            Ok(cid)
        })
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
    }

    /// Store a block with a caller-supplied pre-computed CID.
    ///
    /// The caller is responsible for ensuring `cid` matches `data`.
    /// Idempotent: if the file already exists the data is not rewritten.
    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        let path = Arc::clone(&self.path);
        task::spawn_blocking(move || Self::write_block_sync(&path, &cid, &data))
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        let path = Arc::clone(&self.path);
        let cid_str = cid.to_string();
        task::spawn_blocking(move || {
            let block_path = path.join(format!("{cid_str}.block"));
            match std::fs::read(&block_path) {
                Ok(data) => Ok(data),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Err(IpfsWriteError::NotFound(cid_str))
                }
                Err(e) => Err(IpfsWriteError::WriteFailed(e.to_string())),
            }
        })
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
    }

    /// Remove the block file for `cid`.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: if the file does
    /// not exist the call succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsWriteError> {
        let path = Arc::clone(&self.path);
        let filename = cid.to_string();
        task::spawn_blocking(move || {
            let block_path = path.join(format!("{filename}.block"));
            match std::fs::remove_file(&block_path) {
                Ok(()) => Ok(DeletionOutcome::Immediate),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Ok(DeletionOutcome::Immediate)
                }
                Err(e) => Err(IpfsWriteError::WriteFailed(e.to_string())),
            }
        })
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_store() -> (FsBlockStore, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = FsBlockStore::open(tmp.path()).expect("open FsBlockStore");
        (store, tmp)
    }

    #[tokio::test]
    async fn round_trip_put_raw_and_get() {
        let (store, _tmp) = open_test_store();
        let data = b"reader filesystem round trip";
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
    async fn put_is_idempotent() {
        let (store, _tmp) = open_test_store();
        let data = b"idempotent write";
        let cid1 = store.put_raw(data).await.expect("put 1");
        let cid2 = store.put_raw(data).await.expect("put 2");
        assert_eq!(cid1, cid2, "same content must produce same CID");
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
        store.delete(&cid).await.expect("delete 2 must not error");
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
    async fn block_file_exists_on_disk_after_put() {
        let (store, tmp) = open_test_store();
        let data = b"check file on disk";
        let cid = store.put_raw(data).await.expect("put");
        let filename = format!("{}.block", cid);
        let block_path = tmp.path().join(&filename);
        assert!(block_path.exists(), "block file must exist on disk: {filename}");
    }

    #[tokio::test]
    async fn tmp_file_absent_after_successful_put() {
        let (store, tmp) = open_test_store();
        let data = b"check no tmp file";
        let cid = store.put_raw(data).await.expect("put");
        let tmp_path = tmp.path().join(format!("{}.block.tmp", cid));
        assert!(
            !tmp_path.exists(),
            ".tmp file must be removed after successful rename"
        );
    }

    #[tokio::test]
    async fn stale_tmp_file_does_not_prevent_put() {
        let (store, tmp) = open_test_store();
        let data = b"stale tmp test";
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        let tmp_path = tmp.path().join(format!("{}.block.tmp", cid));
        std::fs::write(&tmp_path, b"truncated garbage").expect("write stale tmp");
        let result_cid = store.put_raw(data).await.expect("put after stale tmp");
        assert_eq!(result_cid, cid);
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn open_creates_directory() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let subdir = tmp.path().join("new").join("subdir");
        assert!(!subdir.exists());
        FsBlockStore::open(&subdir).expect("open must create the directory");
        assert!(subdir.exists());
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
