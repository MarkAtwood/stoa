//! SQLite BLOB block store backend for the reader daemon.
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
use sqlx::{sqlite::SqliteConnectOptions, Row};
use std::path::Path;

use stoa_core::ipfs::DeletionOutcome;

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};

/// IPFS block store backed by a SQLite database.
#[derive(Debug)]
pub struct SqliteBlockStore {
    pool: sqlx::SqlitePool,
}

impl SqliteBlockStore {
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
        // Fail fast if an existing table has an incompatible schema rather than
        // discovering the mismatch at first article ingest.
        sqlx::query("SELECT cid, codec, data, byte_size, stored_at FROM blocks LIMIT 0")
            .execute(&pool)
            .await
            .map_err(|e| format!("sqlite store: blocks table schema is incompatible: {e}"))?;
        // Stamp schema version 1 on first open; reject future-version databases.
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .map_err(|e| format!("sqlite store: failed to read schema version: {e}"))?;
        match version {
            0 => sqlx::query("PRAGMA user_version = 1")
                .execute(&pool)
                .await
                .map_err(|e| format!("sqlite store: failed to set schema version: {e}"))
                .map(|_| ())?,
            1 => {}
            v => {
                return Err(format!(
                    "sqlite store: unsupported schema version {v} (expected 1)"
                ))
            }
        }
        Ok(Self { pool })
    }

    async fn insert_block(
        pool: &sqlx::SqlitePool,
        cid: &Cid,
        data: &[u8],
    ) -> Result<(), IpfsWriteError> {
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
        .execute(pool)
        .await
        .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl IpfsBlockStore for SqliteBlockStore {
    /// Write `data` to the blocks table, computing the CID from the data.
    ///
    /// Idempotent: `INSERT OR IGNORE` — if a row with the same CID already
    /// exists the insert is silently skipped and the same CID is returned.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        Self::insert_block(&self.pool, &cid, data).await?;
        Ok(cid)
    }

    /// Store a block with a caller-supplied pre-computed CID.
    ///
    /// The caller is responsible for ensuring `cid` matches `data`.
    /// Idempotent: `INSERT OR IGNORE`.
    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        Self::insert_block(&self.pool, &cid, &data).await
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        let cid_str = cid.to_string();
        let row = sqlx::query("SELECT data FROM blocks WHERE cid = ?1")
            .bind(&cid_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        row.map(|r| r.get::<Vec<u8>, _>("data"))
            .ok_or(IpfsWriteError::NotFound(cid_str))
    }

    /// Remove the row for `cid`.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: deleting a CID
    /// that does not exist succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsWriteError> {
        let cid_str = cid.to_string();
        sqlx::query("DELETE FROM blocks WHERE cid = ?1")
            .bind(&cid_str)
            .execute(&self.pool)
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(DeletionOutcome::Immediate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr as _;

    async fn make_test_store() -> SqliteBlockStore {
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
        SqliteBlockStore { pool }
    }

    #[tokio::test]
    async fn round_trip_put_raw_and_get() {
        let store = make_test_store().await;
        let data = b"reader sqlite round trip";
        let cid = store.put_raw(data).await.expect("put");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn put_block_and_get() {
        let store = make_test_store().await;
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
        let store = make_test_store().await;
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
        let store = make_test_store().await;
        let data = b"idempotent write";
        let cid1 = store.put_raw(data).await.expect("put 1");
        let cid2 = store.put_raw(data).await.expect("put 2");
        assert_eq!(cid1, cid2, "same content must produce same CID");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks WHERE cid = ?1")
            .bind(cid1.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "idempotent put must not create duplicate rows");
    }

    #[tokio::test]
    async fn delete_removes_row_immediately() {
        let store = make_test_store().await;
        let data = b"to be deleted";
        let cid = store.put_raw(data).await.expect("put");

        let outcome = store.delete(&cid).await.expect("delete");
        assert_eq!(outcome, DeletionOutcome::Immediate);

        let result = store.get_raw(&cid).await;
        assert!(
            matches!(result, Err(IpfsWriteError::NotFound(_))),
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
    async fn delete_nonexistent_succeeds() {
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
        SqliteBlockStore::open(&db_path)
            .await
            .expect("open must create db file");
        assert!(db_path.exists(), "database file must exist after open");
    }

    #[tokio::test]
    async fn open_detects_incompatible_schema() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("bad.db");
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .unwrap()
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE blocks (cid TEXT NOT NULL PRIMARY KEY, data BLOB NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        drop(pool);
        let err = SqliteBlockStore::open(&db_path)
            .await
            .expect_err("incompatible schema must fail at open");
        assert!(
            err.contains("incompatible"),
            "error must mention incompatibility: {err}"
        );
    }

    #[tokio::test]
    async fn open_rejects_future_schema_version() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("future.db");
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .unwrap()
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE blocks (
                cid TEXT NOT NULL PRIMARY KEY,
                codec INTEGER NOT NULL,
                data BLOB NOT NULL,
                byte_size INTEGER NOT NULL,
                stored_at INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("PRAGMA user_version = 99")
            .execute(&pool)
            .await
            .unwrap();
        drop(pool);
        let err = SqliteBlockStore::open(&db_path)
            .await
            .expect_err("future schema version must fail at open");
        assert!(
            err.contains("unsupported schema version"),
            "error must mention schema version: {err}"
        );
    }
}
