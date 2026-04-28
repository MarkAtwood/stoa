//! Git object database block store backend for the reader daemon.
//!
//! Stores article blocks as git blob objects in a bare git repository.
//! A SQLite database maps each CID to its git object ID (OID) so blocks
//! can be retrieved by CID.
//!
//! ## SHA-1 vs SHA-256
//!
//! The `git2` crate (libgit2) does not currently expose SHA-256 object format
//! (`extensions.objectFormat = sha256`) in its public Rust API — libgit2-sys
//! has disabled this feature as experimental.  The repository therefore uses
//! SHA-1 object IDs internally.  CIDs (external keys) are SHA-256 based;
//! the git OID is an implementation detail stored in the SQLite index.
//! When upstream libgit2-sys enables SHA-256, this backend will be upgraded.
//!
//! ## Deletion and GC
//!
//! `delete()` removes the CID from the SQLite index but leaves the git object
//! in the ODB.  The object becomes unreachable and will be pruned by
//! `git gc --prune=<date>` run by the operator.  `delete()` therefore returns
//! [`DeletionOutcome::Deferred`].  After GC, `get_raw()` returns `NotFound`.
//!
//! ## Thread safety
//!
//! `git2::Repository` is `Send` but not `Sync`.  All git operations are
//! dispatched via `tokio::task::spawn_blocking` to avoid blocking the async
//! runtime on ODB I/O.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use sqlx::sqlite::SqliteConnectOptions;
use std::sync::Arc;

use stoa_core::ipfs::DeletionOutcome;
use stoa_core::ipfs_backend::GitSha256BackendConfig;

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};

/// IPFS block store backed by a bare git repository and a SQLite CID→OID index.
#[derive(Clone)]
pub struct GitObjectBlockStore {
    /// Bare git repository.  Wrapped in `Arc<Mutex>` for shared ownership
    /// across `spawn_blocking` closures.
    repo: Arc<std::sync::Mutex<git2::Repository>>,
    pool: sqlx::SqlitePool,
}

impl GitObjectBlockStore {
    /// Open or create the git backend at the paths in `cfg`.
    ///
    /// - Opens the bare git repo at `cfg.repo_path`, creating it if absent.
    /// - Opens the SQLite index at `cfg.index_db`, creating the
    ///   `git_block_index` table if absent.
    /// - Returns `Err` if either path is inaccessible or the DB schema
    ///   is incompatible.
    pub async fn new(cfg: &GitSha256BackendConfig) -> Result<Self, String> {
        // Open or init the bare git repo.  All ops go through the git2 ODB;
        // no `git` binary is required at runtime.
        let repo_path = cfg.repo_path.clone();
        let repo = tokio::task::spawn_blocking(move || {
            if std::path::Path::new(&repo_path).exists() {
                git2::Repository::open_bare(&repo_path)
                    .map_err(|e| format!("git backend: open repo '{}': {e}", repo_path))
            } else {
                let mut opts = git2::RepositoryInitOptions::new();
                opts.bare(true);
                git2::Repository::init_opts(&repo_path, &opts)
                    .map_err(|e| format!("git backend: init repo '{}': {e}", repo_path))
            }
        })
        .await
        .map_err(|e| format!("git backend: spawn_blocking failed: {e}"))??;

        // Open or create the SQLite index.
        let opts = SqliteConnectOptions::new()
            .filename(&cfg.index_db)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .map_err(|e| format!("git backend: open index '{}': {e}", cfg.index_db))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS git_block_index (
                cid     TEXT NOT NULL PRIMARY KEY,
                git_oid TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .map_err(|e| format!("git backend: create index table: {e}"))?;

        // Verify schema compatibility.
        sqlx::query("SELECT cid, git_oid FROM git_block_index LIMIT 0")
            .execute(&pool)
            .await
            .map_err(|e| format!("git backend: index schema incompatible: {e}"))?;

        Ok(Self {
            repo: Arc::new(std::sync::Mutex::new(repo)),
            pool,
        })
    }

    /// Write `data` as a git blob.  Returns the git OID string (40 hex chars).
    async fn write_blob(&self, data: Vec<u8>) -> Result<String, IpfsWriteError> {
        let repo = Arc::clone(&self.repo);
        tokio::task::spawn_blocking(move || {
            let repo = repo.lock().unwrap();
            let oid = repo
                .blob(&data)
                .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
            Ok::<String, IpfsWriteError>(oid.to_string())
        })
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(format!("spawn_blocking: {e}")))?
    }

    /// Read a git blob by OID.  Returns `NotFound` if the OID is not in the ODB.
    async fn read_blob(&self, git_oid: &str, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        let repo = Arc::clone(&self.repo);
        let oid_str = git_oid.to_string();
        let cid_str = cid.to_string();
        tokio::task::spawn_blocking(move || {
            let oid = git2::Oid::from_str(&oid_str)
                .map_err(|_| IpfsWriteError::NotFound(cid_str.clone()))?;
            let repo = repo.lock().unwrap();
            let blob = repo
                .find_blob(oid)
                .map_err(|_| IpfsWriteError::NotFound(cid_str))?;
            Ok::<Vec<u8>, IpfsWriteError>(blob.content().to_vec())
        })
        .await
        .map_err(|e| IpfsWriteError::ReadFailed(format!("spawn_blocking: {e}")))?
    }
}

#[async_trait]
impl IpfsBlockStore for GitObjectBlockStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        let oid_str = self.write_blob(data.to_vec()).await?;
        sqlx::query("INSERT OR IGNORE INTO git_block_index (cid, git_oid) VALUES (?, ?)")
            .bind(cid.to_string())
            .bind(&oid_str)
            .execute(&self.pool)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(cid)
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        let oid_str = self.write_blob(data).await?;
        sqlx::query("INSERT OR IGNORE INTO git_block_index (cid, git_oid) VALUES (?, ?)")
            .bind(cid.to_string())
            .bind(&oid_str)
            .execute(&self.pool)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT git_oid FROM git_block_index WHERE cid = ?")
                .bind(cid.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| IpfsWriteError::ReadFailed(e.to_string()))?;
        let (git_oid,) = row.ok_or_else(|| IpfsWriteError::NotFound(cid.to_string()))?;
        self.read_blob(&git_oid, cid).await
    }

    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsWriteError> {
        // Remove from index.  The git object stays in the ODB until `git gc`.
        sqlx::query("DELETE FROM git_block_index WHERE cid = ?")
            .bind(cid.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(DeletionOutcome::Deferred {
            readable_for_approx_secs: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoa_core::ipfs_backend::GitSha256BackendConfig;
    use tempfile::TempDir;

    async fn make_store(tmp: &TempDir) -> GitObjectBlockStore {
        let cfg = GitSha256BackendConfig {
            repo_path: tmp.path().join("repo.git").to_str().unwrap().to_string(),
            index_db: tmp.path().join("index.db").to_str().unwrap().to_string(),
        };
        GitObjectBlockStore::new(&cfg)
            .await
            .expect("store init must succeed")
    }

    #[tokio::test]
    async fn round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp).await;
        let data = b"stoa git backend round-trip test";
        let cid = store.put_raw(data).await.expect("put_raw");
        let got = store.get_raw(&cid).await.expect("get_raw");
        assert_eq!(got, data.as_slice());
    }

    #[tokio::test]
    async fn idempotent_put() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp).await;
        let data = b"idempotent block";
        let cid = store.put_raw(data).await.expect("first put");
        // Second put of identical data must not error (INSERT OR IGNORE).
        store
            .put_block(cid, data.to_vec())
            .await
            .expect("second put must succeed");
        let got = store.get_raw(&cid).await.expect("get after idempotent put");
        assert_eq!(got, data.as_slice());
    }

    #[tokio::test]
    async fn delete_removes_from_index() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp).await;
        let data = b"block to delete";
        let cid = store.put_raw(data).await.expect("put");

        let outcome = store.delete(&cid).await.expect("delete");
        assert!(
            matches!(outcome, DeletionOutcome::Deferred { .. }),
            "git delete must be Deferred"
        );

        // After deletion the CID is gone from the index → NotFound.
        match store.get_raw(&cid).await {
            Err(IpfsWriteError::NotFound(_)) => {}
            other => panic!("expected NotFound after delete, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_missing_is_ok() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp).await;
        use multihash_codetable::{Code, MultihashDigest};
        let phantom = Cid::new_v1(
            0x55,
            Code::Sha2_256.digest(b"phantom-block-never-written"),
        );
        // Deleting a CID not in the index must succeed (idempotent).
        store.delete(&phantom).await.expect("delete missing must be Ok");
    }

    /// Verify the git OID stored in the index is the correct SHA-1 blob hash.
    ///
    /// git computes the blob hash as: `sha1("blob " + len + "\0" + content)`.
    /// `git2::Oid::hash_object` implements this without writing to disk,
    /// providing an independent oracle for the mapping test.
    #[tokio::test]
    async fn git_oid_matches_blob_hash() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp).await;
        let data = b"hash mapping verification payload";
        let cid = store.put_raw(data).await.expect("put_raw");

        // Retrieve the stored OID from the index.
        let (stored_oid,): (String,) =
            sqlx::query_as("SELECT git_oid FROM git_block_index WHERE cid = ?")
                .bind(cid.to_string())
                .fetch_one(&store.pool)
                .await
                .expect("index row must exist");

        // Compute the expected blob hash using git2's built-in formula.
        let expected_oid = tokio::task::spawn_blocking(move || {
            git2::Oid::hash_object(git2::ObjectType::Blob, data)
                .expect("hash_object must succeed")
                .to_string()
        })
        .await
        .expect("spawn_blocking");

        assert_eq!(
            stored_oid, expected_oid,
            "stored git OID must match the expected blob hash"
        );
    }
}
