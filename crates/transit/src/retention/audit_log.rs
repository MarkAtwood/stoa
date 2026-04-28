//! Append-only GC audit log stored in SQLite.
//!
//! Records every unpin event. Never deletes or updates rows.
//! Schema: gc_audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,
//!                        cid TEXT NOT NULL,
//!                        group_name TEXT NOT NULL,
//!                        ingested_at_ms INTEGER NOT NULL,
//!                        gc_at_ms INTEGER NOT NULL,
//!                        reason TEXT NOT NULL)

use sqlx::AnyPool;
use stoa_core::error::StorageError;

/// A single GC audit record.
#[derive(Debug, Clone)]
pub struct GcAuditRecord {
    pub cid: String,
    pub group_name: String,
    pub ingested_at_ms: u64,
    pub gc_at_ms: u64,
    pub reason: String,
}

/// Append a GC audit record. Never updates existing records.
pub async fn append_audit_record(
    pool: &AnyPool,
    record: &GcAuditRecord,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO gc_audit_log (cid, group_name, ingested_at_ms, gc_at_ms, reason) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&record.cid)
    .bind(&record.group_name)
    .bind(record.ingested_at_ms as i64)
    .bind(record.gc_at_ms as i64)
    .bind(&record.reason)
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

/// Count audit records (for tests).
pub async fn count_audit_records(pool: &AnyPool) -> Result<i64, StorageError> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM gc_audit_log")
        .fetch_one(pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(count)
}
