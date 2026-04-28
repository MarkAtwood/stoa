//! SQLite BLOB block store backend for the transit daemon.
//!
//! Stores raw block bytes in a `blocks` table keyed by CID string.
//! Uses SQLx with WAL journal mode for concurrent read access.
//! Zero new dependencies — SQLx is already required for article metadata.
//!
//! All writes are transactional and synchronous with respect to the caller.
//! `delete()` returns [`DeletionOutcome::Immediate`]: the row is gone as soon
//! as the DELETE transaction commits.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use sqlx::{Row, sqlite::SqliteConnectOptions};
use std::path::Path;

use stoa_core::ipfs::DeletionOutcome;

use crate::peering::pipeline::{IpfsError, IpfsStore};

/// IPFS block store backed by a SQLite database.
pub struct SqliteStore {
    pool: sqlx::SqlitePool,
}

impl SqliteStore {
    /// Open (or create) the SQLite block store at `path`.
    ///
    /// Creates the file and runs the `blocks` table migration if absent.
    /// Enables WAL journal mode for concurrent reader access.
    pub async fn open(path: &Path) -> Result<Self, String> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .map_err(|e| format!("sqlite store: failed to open {}: {e}", path.display()))?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocks (
                cid       TEXT    NOT NULL PRIMARY KEY,
                codec     INTEGER NOT NULL,
                data      BLOB    NOT NULL,
                byte_size INTEGER NOT NULL,
                stored_at INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .map_err(|e| format!("sqlite store: failed to create blocks table: {e}"))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl IpfsStore for SqliteStore {
    /// Write `data` to the blocks table.
    ///
    /// Idempotent: `INSERT OR IGNORE` — if a row with the same CID already
    /// exists the insert is silently skipped and the same CID is returned.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        let cid_str = cid.to_string();
        let codec = cid.codec() as i64;
        let byte_size = data.len() as i64;
        let stored_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        sqlx::query(
            "INSERT OR IGNORE INTO blocks (cid, codec, data, byte_size, stored_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&cid_str)
        .bind(codec)
        .bind(data)
        .bind(byte_size)
        .bind(stored_at)
        .execute(&self.pool)
        .await
        .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
        Ok(cid)
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        let cid_str = cid.to_string();
        let row = sqlx::query("SELECT data FROM blocks WHERE cid = ?1")
            .bind(&cid_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
        Ok(row.map(|r| r.get::<Vec<u8>, _>("data")))
    }

    /// Remove the row for `cid`.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: deleting a CID
    /// that does not exist succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsError> {
        let cid_str = cid.to_string();
        sqlx::query("DELETE FROM blocks WHERE cid = ?1")
            .bind(&cid_str)
            .execute(&self.pool)
            .await
            .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
        Ok(DeletionOutcome::Immediate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr as _;

    async fn make_test_store() -> SqliteStore {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocks (
                cid       TEXT    NOT NULL PRIMARY KEY,
                codec     INTEGER NOT NULL,
                data      BLOB    NOT NULL,
                byte_size INTEGER NOT NULL,
                stored_at INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        SqliteStore { pool }
    }

    #[tokio::test]
    async fn round_trip_put_and_get() {
        let store = make_test_store().await;
        let data = b"hello, sqlite transit store";
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
        let store = make_test_store().await;
        let data = b"idempotent write";
        let cid1 = store.put_raw(data).await.expect("put 1");
        let cid2 = store.put_raw(data).await.expect("put 2");
        assert_eq!(cid1, cid2, "same content must produce same CID");
        // Only one row must exist.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks WHERE cid = ?1")
            .bind(cid1.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "idempotent put must not create duplicate rows");
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = make_test_store().await;
        let digest = Code::Sha2_256.digest(b"not stored");
        let cid = Cid::new_v1(0x55, digest);
        let result = store.get_raw(&cid).await.expect("get");
        assert!(result.is_none(), "missing block must return None");
    }

    #[tokio::test]
    async fn delete_removes_row_immediately() {
        let store = make_test_store().await;
        let data = b"to be deleted";
        let cid = store.put_raw(data).await.expect("put");

        assert!(store.get_raw(&cid).await.expect("get before").is_some());

        let outcome = store.delete(&cid).await.expect("delete");
        assert_eq!(outcome, DeletionOutcome::Immediate);

        assert!(
            store.get_raw(&cid).await.expect("get after").is_none(),
            "row must be gone after delete"
        );
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let store = make_test_store().await;
        let data = b"double delete";
        let cid = store.put_raw(data).await.expect("put");
        store.delete(&cid).await.expect("delete 1");
        store.delete(&cid).await.expect("delete 2 must not error");
    }

    #[tokio::test]
    async fn delete_nonexistent_cid_succeeds() {
        let store = make_test_store().await;
        let digest = Code::Sha2_256.digest(b"never stored");
        let cid = Cid::new_v1(0x55, digest);
        store
            .delete(&cid)
            .await
            .expect("delete of missing CID must succeed");
    }

    #[tokio::test]
    async fn open_creates_db_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("blocks.db");
        assert!(!db_path.exists());
        SqliteStore::open(&db_path).await.expect("open must create db file");
        assert!(db_path.exists(), "database file must exist after open");
    }
}
