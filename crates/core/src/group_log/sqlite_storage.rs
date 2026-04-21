use cid::Cid;
use sqlx::SqlitePool;

use crate::article::GroupName;
use crate::error::StorageError;
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};

/// SQLite-backed `LogStorage` implementation.
pub struct SqliteLogStorage {
    pool: SqlitePool,
}

impl SqliteLogStorage {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn db_err(e: sqlx::Error) -> StorageError {
    StorageError::Database(e.to_string())
}

fn cid_to_bytes(cid: &Cid) -> Vec<u8> {
    cid.to_bytes()
}

fn cid_from_bytes(bytes: &[u8]) -> Result<Cid, StorageError> {
    Cid::try_from(bytes).map_err(|e| StorageError::Database(format!("invalid CID bytes: {e}")))
}

// ── trait impl ───────────────────────────────────────────────────────────────

impl LogStorage for SqliteLogStorage {
    async fn insert_entry(&self, id: LogEntryId, entry: LogEntry) -> Result<(), StorageError> {
        let id_bytes = id.as_bytes().as_slice().to_vec();
        let article_cid_bytes = cid_to_bytes(&entry.article_cid);
        // HLC timestamps are u64 wall-ms since UNIX epoch.  SQLite stores
        // integers as i64.  A timestamp > i64::MAX (year ~292 million CE) cannot
        // be stored without truncation, so we return a hard error rather than
        // silently corrupting the ordering invariant.
        let ts = i64::try_from(entry.hlc_timestamp).map_err(|_| {
            StorageError::Database(format!(
                "HLC timestamp {} exceeds i64::MAX — cannot store in SQLite",
                entry.hlc_timestamp
            ))
        })?;

        // Begin the transaction first so the duplicate check and both inserts
        // are fully atomic.  We do NOT pre-check for duplicates outside the
        // transaction — that creates a TOCTOU window where a concurrent insert
        // can slip in between the check and the INSERT, causing a confusing DB
        // error instead of DuplicateEntry.  Instead, we attempt the INSERT
        // directly and translate a UNIQUE constraint violation to DuplicateEntry.
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        let insert_result = sqlx::query(
            "INSERT INTO log_entries (id, hlc_timestamp, article_cid, operator_signature)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&id_bytes)
        .bind(ts)
        .bind(&article_cid_bytes)
        .bind(&entry.operator_signature)
        .execute(&mut *tx)
        .await;

        match insert_result {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(StorageError::DuplicateEntry(id));
            }
            Err(e) => return Err(db_err(e)),
        }

        for parent_cid in &entry.parent_cids {
            let parent_bytes = cid_to_bytes(parent_cid);
            sqlx::query(
                "INSERT OR IGNORE INTO log_entry_parents (entry_id, parent_id) VALUES (?, ?)",
            )
            .bind(&id_bytes)
            .bind(&parent_bytes)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn get_entry(&self, id: &LogEntryId) -> Result<Option<LogEntry>, StorageError> {
        let id_bytes = id.as_bytes().as_slice().to_vec();

        let row: Option<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT hlc_timestamp, article_cid, operator_signature
             FROM log_entries WHERE id = ?",
        )
        .bind(&id_bytes)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let Some((ts, cid_bytes, sig)) = row else {
            return Ok(None);
        };

        let article_cid = cid_from_bytes(&cid_bytes)?;

        // Fetch parent CIDs.
        let parent_rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT parent_id FROM log_entry_parents WHERE entry_id = ?")
                .bind(&id_bytes)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;

        let mut parent_cids = Vec::with_capacity(parent_rows.len());
        for (pb,) in parent_rows {
            parent_cids.push(cid_from_bytes(&pb)?);
        }

        Ok(Some(LogEntry {
            hlc_timestamp: ts as u64,
            article_cid,
            operator_signature: sig,
            parent_cids,
        }))
    }

    async fn has_entry(&self, id: &LogEntryId) -> Result<bool, StorageError> {
        let id_bytes = id.as_bytes().as_slice().to_vec();
        let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT id FROM log_entries WHERE id = ?")
            .bind(&id_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    async fn list_tips(&self, group: &GroupName) -> Result<Vec<LogEntryId>, StorageError> {
        let rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT tip_id FROM group_tips WHERE group_name = ?")
                .bind(group.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;

        let mut ids = Vec::with_capacity(rows.len());
        for (bytes,) in rows {
            if bytes.len() != 32 {
                return Err(StorageError::Database(format!(
                    "corrupt tip_id: expected 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            ids.push(LogEntryId::from_bytes(arr));
        }
        Ok(ids)
    }

    async fn set_tips(&self, group: &GroupName, tips: &[LogEntryId]) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        sqlx::query("DELETE FROM group_tips WHERE group_name = ?")
            .bind(group.as_str())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        for tip in tips {
            let tip_bytes = tip.as_bytes().as_slice().to_vec();
            sqlx::query("INSERT INTO group_tips (group_name, tip_id) VALUES (?, ?)")
                .bind(group.as_str())
                .bind(&tip_bytes)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        }

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn entry_count(&self, group: &GroupName) -> Result<u64, StorageError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM group_tips WHERE group_name = ?")
            .bind(group.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.0 as u64)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_log::storage_tests;
    use crate::migrations::run_migrations;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn make_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .expect("in-memory pool");
        run_migrations(&pool).await.expect("migrations");
        pool
    }

    #[tokio::test]
    async fn sqlite_insert_and_get() {
        let pool = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_insert_and_get(&s).await;
    }

    #[tokio::test]
    async fn sqlite_get_missing_returns_none() {
        let pool = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_get_missing_returns_none(&s).await;
    }

    #[tokio::test]
    async fn sqlite_has_entry() {
        let pool = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_has_entry(&s).await;
    }

    #[tokio::test]
    async fn sqlite_set_and_list_tips() {
        let pool = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_set_and_list_tips(&s).await;
    }

    #[tokio::test]
    async fn sqlite_entry_count() {
        let pool = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_entry_count(&s).await;
    }

    #[tokio::test]
    async fn sqlite_duplicate_insert_rejected() {
        let pool = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_duplicate_insert_rejected(&s).await;
    }

    #[tokio::test]
    async fn sqlite_tips_are_group_scoped() {
        let pool = make_pool().await;
        let s = SqliteLogStorage::new(pool);
        storage_tests::test_tips_are_group_scoped(&s).await;
    }
}
