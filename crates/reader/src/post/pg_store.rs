//! PostgreSQL BYTEA block store backend for the reader daemon.
//!
//! Stores raw block bytes as `BYTEA` rows in a `blocks` table keyed by CID
//! string.  Zero additional infrastructure for operators already running
//! Aurora/PostgreSQL for metadata.
//!
//! All writes are idempotent: `INSERT … ON CONFLICT (cid) DO NOTHING`.
//! `delete()` returns [`DeletionOutcome::Immediate`]: the row is removed
//! atomically when the DELETE transaction commits.

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use sqlx::Row as _;
use std::sync::Arc;

use stoa_core::ipfs::DeletionOutcome;
use stoa_core::ipfs_backend::PgBlobBackendConfig;

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};

/// IPFS block store backed by a PostgreSQL BYTEA column.
#[derive(Debug)]
pub struct PgBlockStore {
    pool: Arc<sqlx::PgPool>,
}

impl PgBlockStore {
    /// Open the PostgreSQL block store.
    ///
    /// Creates the `blocks` table if it does not exist.  Verifies schema
    /// compatibility on an existing table.  Returns `Err` if the connection
    /// fails or the schema is incompatible.
    pub async fn new(cfg: &PgBlobBackendConfig) -> Result<Self, String> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&cfg.database_url)
            .await
            .map_err(|e| format!("pg block store: failed to connect: {e}"))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocks (
                cid       TEXT   NOT NULL PRIMARY KEY,
                codec     BIGINT NOT NULL,
                data      BYTEA  NOT NULL,
                byte_size BIGINT NOT NULL,
                stored_at BIGINT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .map_err(|e| format!("pg block store: failed to create blocks table: {e}"))?;

        // Verify schema compatibility before accepting traffic.
        sqlx::query("SELECT cid, codec, data, byte_size, stored_at FROM blocks LIMIT 0")
            .execute(&pool)
            .await
            .map_err(|e| format!("pg block store: blocks table schema is incompatible: {e}"))?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    /// Construct with a caller-supplied pool.  Intended for unit tests.
    pub fn new_with_pool(pool: Arc<sqlx::PgPool>) -> Self {
        Self { pool }
    }

    async fn insert_block(
        pool: &sqlx::PgPool,
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
            "INSERT INTO blocks (cid, codec, data, byte_size, stored_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (cid) DO NOTHING",
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
impl IpfsBlockStore for PgBlockStore {
    /// Write `data` to the blocks table, computing the CID from the data.
    ///
    /// Idempotent: `INSERT … ON CONFLICT (cid) DO NOTHING`.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        Self::insert_block(&self.pool, &cid, data).await?;
        Ok(cid)
    }

    /// Store a block with a caller-supplied pre-computed CID.
    ///
    /// The caller is responsible for ensuring `cid` matches `data`.
    /// Idempotent: `INSERT … ON CONFLICT (cid) DO NOTHING`.
    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        Self::insert_block(&self.pool, &cid, &data).await
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        let cid_str = cid.to_string();
        let row = sqlx::query("SELECT data FROM blocks WHERE cid = $1")
            .bind(&cid_str)
            .fetch_optional(self.pool.as_ref())
            .await
            .map_err(|e| IpfsWriteError::ReadFailed(e.to_string()))?;
        row.map(|r| r.get::<Vec<u8>, _>("data"))
            .ok_or_else(|| IpfsWriteError::NotFound(cid_str))
    }

    /// Remove the row for `cid`.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: deleting a CID
    /// that does not exist succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsWriteError> {
        let cid_str = cid.to_string();
        sqlx::query("DELETE FROM blocks WHERE cid = $1")
            .bind(&cid_str)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(DeletionOutcome::Immediate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    /// Build a test store backed by a real PostgreSQL database.
    ///
    /// Requires `TEST_PG_URL` to be set (e.g.
    /// `TEST_PG_URL=postgres://user:pass@localhost/stoa_test`).
    /// Tests are skipped when the variable is absent.
    async fn make_pg_store() -> Option<PgBlockStore> {
        let url = match std::env::var("TEST_PG_URL") {
            Ok(u) => u,
            Err(_) => return None,
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("TEST_PG_URL connection must succeed");
        // Fresh table for each test invocation via a unique schema.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocks (
                cid       TEXT   NOT NULL PRIMARY KEY,
                codec     BIGINT NOT NULL,
                data      BYTEA  NOT NULL,
                byte_size BIGINT NOT NULL,
                stored_at BIGINT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("create table");
        // Truncate to keep tests independent.
        sqlx::query("TRUNCATE blocks").execute(&pool).await.expect("truncate");
        Some(PgBlockStore::new_with_pool(Arc::new(pool)))
    }

    #[tokio::test]
    async fn round_trip_put_raw_and_get() {
        let store = match make_pg_store().await {
            Some(s) => s,
            None => return,
        };
        let data = b"postgres block store round trip";
        let cid = store.put_raw(data).await.expect("put");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn put_block_and_get() {
        let store = match make_pg_store().await {
            Some(s) => s,
            None => return,
        };
        let data = b"dag-cbor block";
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x71, digest);
        store.put_block(cid.clone(), data.to_vec()).await.expect("put_block");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let store = match make_pg_store().await {
            Some(s) => s,
            None => return,
        };
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
        let store = match make_pg_store().await {
            Some(s) => s,
            None => return,
        };
        let data = b"idempotent write";
        let cid1 = store.put_raw(data).await.expect("put 1");
        let cid2 = store.put_raw(data).await.expect("put 2 must not error");
        assert_eq!(cid1, cid2, "same content must produce same CID");
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM blocks WHERE cid = $1")
                .bind(cid1.to_string())
                .fetch_one(store.pool.as_ref())
                .await
                .unwrap();
        assert_eq!(count, 1, "idempotent put must not create duplicate rows");
    }

    #[tokio::test]
    async fn delete_removes_row_immediately() {
        let store = match make_pg_store().await {
            Some(s) => s,
            None => return,
        };
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
    async fn delete_nonexistent_succeeds() {
        let store = match make_pg_store().await {
            Some(s) => s,
            None => return,
        };
        let digest = Code::Sha2_256.digest(b"never stored");
        let cid = Cid::new_v1(0x55, digest);
        store.delete(&cid).await.expect("delete of missing CID must succeed");
    }
}
