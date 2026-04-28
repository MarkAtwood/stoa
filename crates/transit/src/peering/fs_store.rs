//! Filesystem block store backend for the transit daemon.
//!
//! ## Storage format (stable contract)
//!
//! Files are stored as `<root>/<cid-base32-lowercase>.block`.
//!
//! Example: `bafkreib4pqtikzdjlj4zigobmd63lig7u6oxlug24snlr6atjlmlza45dq.block`
//!
//! The CID is encoded as [multibase](https://github.com/multiformats/multibase)
//! base32 lowercase (the default `Display` for CIDv1).  The `.block` suffix is
//! a stable contract — existing stores cannot be renamed without a migration.
//!
//! The directory layout is **flat** (no subdirectory sharding).  For large
//! deployments with millions of blocks, consider using the LMDB backend instead.
//!
//! ## Atomic writes
//!
//! Each `put_raw` call writes data to a unique per-write temporary file
//! `<cid>.<seq>.block.tmp`, then renames it to `<cid>.block`.  Rename is
//! POSIX-atomic so a crash mid-write cannot leave a partial block visible to
//! readers.  The per-write unique name (`<seq>` from a module-level counter)
//! prevents concurrent puts of the same CID from racing on the same `.tmp`
//! path.  On Linux, `rename(2)` atomically replaces the destination, so two
//! concurrent puts of the same CID both succeed and produce identical content.
//!
//! Stale `*.block.tmp` files left by a crash are harmless and are never
//! mistaken for complete blocks.
//!
//! All blocking file I/O is dispatched via [`tokio::task::spawn_blocking`]
//! to avoid stalling the async runtime.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{path::Path, sync::Arc};
use tokio::task;

use stoa_core::ipfs::DeletionOutcome;

use crate::peering::pipeline::{IpfsError, IpfsStore};

/// Monotonically increasing counter used to generate unique `.tmp` filenames.
/// Relaxed ordering is sufficient — we only need uniqueness within a process.
static WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

/// IPFS block store backed by a plain filesystem directory.
pub struct FsStore {
    path: Arc<std::path::PathBuf>,
    /// Optional soft cap on total stored bytes.  Checked before each write.
    max_bytes: Option<u64>,
}

impl FsStore {
    /// Open (or create) the block store at `path`.
    ///
    /// `max_bytes`: if `Some`, refuse puts when the total size of `.block`
    /// files in the directory exceeds this value.
    ///
    /// Creates `path` if absent.  Verifies the directory is writable by
    /// writing and immediately removing a sentinel file.  Returns `Err` if
    /// the directory cannot be created or written to.
    pub fn open(path: &Path, max_bytes: Option<u64>) -> Result<Self, String> {
        std::fs::create_dir_all(path).map_err(|e| {
            format!(
                "filesystem store: cannot create directory {}: {e}",
                path.display()
            )
        })?;
        // Write a probe to catch read-only mounts at startup rather than on the
        // first article ingest.  Failure is reported clearly here; ignoring the
        // probe removal is intentional — the file is tiny and harmless.
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
            max_bytes,
        })
    }

    /// Sum the sizes of all `.block` files in the store directory.
    fn dir_bytes_used(path: &Path) -> u64 {
        std::fs::read_dir(path)
            .map(|iter| {
                iter.filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".block"))
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0)
    }
}

#[async_trait]
impl IpfsStore for FsStore {
    /// Write `data` to a file named `<cid>.block`.
    ///
    /// Idempotent: if the file already exists the data is not rewritten and
    /// the same CID is returned.  Uses an atomic temp-then-rename write with
    /// a unique per-call tmp filename so concurrent puts of the same CID do
    /// not race on the same temp file.
    ///
    /// If `max_bytes` was configured and the current directory total would
    /// exceed it, returns `IpfsError::WriteFailed`.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let path = Arc::clone(&self.path);
        let data = data.to_vec();
        let max_bytes = self.max_bytes;
        task::spawn_blocking(move || {
            let digest = Code::Sha2_256.digest(&data);
            let cid = Cid::new_v1(0x55, digest);
            let filename = cid.to_string();
            let block_path = path.join(format!("{filename}.block"));
            if block_path.exists() {
                return Ok(cid);
            }
            if let Some(cap) = max_bytes {
                let used = Self::dir_bytes_used(&path);
                if used + data.len() as u64 > cap {
                    return Err(IpfsError::WriteFailed(format!(
                        "filesystem store soft cap exceeded: {used} + {} bytes > {cap} byte limit",
                        data.len()
                    )));
                }
            }
            // Unique tmp name prevents concurrent puts for the same CID from
            // clobbering each other's temp files.
            let seq = WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp_path = path.join(format!("{filename}.{seq}.block.tmp"));
            std::fs::write(&tmp_path, &data).map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
            // On Linux rename(2) atomically replaces the destination; if a
            // concurrent writer already placed the block, this is a harmless
            // overwrite with identical content.
            std::fs::rename(&tmp_path, &block_path)
                .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
            Ok(cid)
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        let path = Arc::clone(&self.path);
        let filename = cid.to_string();
        task::spawn_blocking(move || {
            let block_path = path.join(format!("{filename}.block"));
            match std::fs::read(&block_path) {
                Ok(data) => Ok(Some(data)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(IpfsError::WriteFailed(e.to_string())),
            }
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }

    /// Remove the block file for `cid`.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: if the file does
    /// not exist the call succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsError> {
        let path = Arc::clone(&self.path);
        let filename = cid.to_string();
        task::spawn_blocking(move || {
            let block_path = path.join(format!("{filename}.block"));
            match std::fs::remove_file(&block_path) {
                Ok(()) => Ok(DeletionOutcome::Immediate),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Ok(DeletionOutcome::Immediate)
                }
                Err(e) => Err(IpfsError::WriteFailed(e.to_string())),
            }
        })
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_store() -> (FsStore, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = FsStore::open(tmp.path(), None).expect("open FsStore");
        (store, tmp)
    }

    #[tokio::test]
    async fn round_trip_put_and_get() {
        let (store, _tmp) = open_test_store();
        let data = b"hello, filesystem transit store";
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
        store.delete(&cid).await.expect("delete 2 must not error");
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
    async fn block_file_exists_on_disk_after_put() {
        let (store, tmp) = open_test_store();
        let data = b"check file on disk";
        let cid = store.put_raw(data).await.expect("put");
        let filename = format!("{}.block", cid);
        let block_path = tmp.path().join(&filename);
        assert!(
            block_path.exists(),
            "block file must exist on disk: {filename}"
        );
    }

    #[tokio::test]
    async fn no_tmp_files_after_successful_put() {
        let (store, tmp) = open_test_store();
        let data = b"check no tmp files";
        store.put_raw(data).await.expect("put");
        let leftover: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("readdir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".block.tmp"))
            .collect();
        assert!(
            leftover.is_empty(),
            "no .block.tmp files should remain after successful put: {leftover:?}"
        );
    }

    #[tokio::test]
    async fn stale_tmp_file_does_not_prevent_put() {
        let (store, tmp) = open_test_store();
        let data = b"stale tmp test";
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        // Simulate a crash mid-write: a stale .block.tmp file with garbage.
        // (The old naming convention; current code uses unique seq-keyed names.)
        let stale_path = tmp.path().join(format!("{}.block.tmp", cid));
        std::fs::write(&stale_path, b"truncated garbage").expect("write stale tmp");
        // put_raw uses a fresh unique name, so the stale file is ignored.
        let result_cid = store.put_raw(data).await.expect("put after stale tmp");
        assert_eq!(result_cid, cid);
        let retrieved = store.get_raw(&cid).await.expect("get").expect("Some");
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn soft_cap_rejects_put_when_exceeded() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        // Cap of 10 bytes — first 10-byte write fits, second is rejected.
        let store = FsStore::open(tmp.path(), Some(10)).expect("open with cap");
        let data_a = b"0123456789"; // exactly 10 bytes
        store.put_raw(data_a).await.expect("first put within cap");
        let data_b = b"one more byte!";
        let result = store.put_raw(data_b).await;
        assert!(
            matches!(result, Err(IpfsError::WriteFailed(_))),
            "put exceeding soft cap must fail: {result:?}"
        );
    }

    #[tokio::test]
    async fn soft_cap_allows_idempotent_put_of_existing_block() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = FsStore::open(tmp.path(), Some(10)).expect("open with cap");
        let data = b"0123456789"; // exactly 10 bytes
        store.put_raw(data).await.expect("first put within cap");
        // Re-putting the same block must succeed (idempotent, no new bytes stored).
        store
            .put_raw(data)
            .await
            .expect("idempotent re-put must succeed even at cap");
    }

    #[tokio::test]
    async fn open_creates_directory() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let subdir = tmp.path().join("new").join("subdir");
        assert!(!subdir.exists());
        FsStore::open(&subdir, None).expect("open must create the directory");
        assert!(subdir.exists());
    }

    #[tokio::test]
    async fn concurrent_same_cid_puts_both_succeed() {
        // Two concurrent put_raw calls for the same CID must both return Ok —
        // no spurious WriteFailed from tmp-file collisions.
        let (store, _tmp) = open_test_store();
        let data = b"concurrent same cid";
        let store = Arc::new(store);
        let s1 = Arc::clone(&store);
        let s2 = Arc::clone(&store);
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { s1.put_raw(data).await }),
            tokio::spawn(async move { s2.put_raw(data).await }),
        );
        let cid1 = r1.expect("task1").expect("put1 must succeed");
        let cid2 = r2.expect("task2").expect("put2 must succeed");
        assert_eq!(cid1, cid2, "both concurrent puts must return the same CID");
        assert!(
            store.get_raw(&cid1).await.expect("get").is_some(),
            "block must be readable after concurrent puts"
        );
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
