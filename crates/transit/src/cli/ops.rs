//! Operator CLI subcommands: status, pin, unpin, gc-run, peer-list.
//!
//! These functions operate directly against the local SQLite database.
//! No running daemon is required; they are suitable for use from a
//! maintenance shell or init script.

use sqlx::SqlitePool;
use usenet_ipfs_core::error::StorageError;

use crate::cli::peers::OutputFormat;
use crate::retention::policy::{ArticleInfo, PinPolicy, PolicyEngine};

/// Print daemon status: peer count, article count from msgid_map, pinned CID count.
///
/// All counts are read directly from SQLite. If a table does not exist
/// (first run before migrations), the count is reported as 0.
pub async fn cmd_status(pool: &SqlitePool, format: OutputFormat) -> Result<String, StorageError> {
    let article_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM msgid_map")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let peer_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM peers WHERE blacklisted_until IS NULL OR blacklisted_until = 0",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    ensure_pinned_cids_table(pool).await?;

    let pinned_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pinned_cids")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    match format {
        OutputFormat::Table => Ok(format!(
            "peers (active):  {peer_count}\n\
             articles:        {article_count}\n\
             pinned CIDs:     {pinned_count}\n"
        )),
        OutputFormat::Json => {
            let v = serde_json::json!({
                "peers_active": peer_count,
                "articles": article_count,
                "pinned_cids": pinned_count,
            });
            Ok(serde_json::to_string_pretty(&v).unwrap())
        }
    }
}

/// Record a CID as operator-pinned in the pinned_cids table.
///
/// The CID string must be valid (base32/base58 multibase CIDv0 or CIDv1).
/// Returns `"pinned: {cid}"` on success.
pub async fn cmd_pin(pool: &SqlitePool, cid_str: &str) -> Result<String, StorageError> {
    cid_str
        .parse::<cid::Cid>()
        .map_err(|e| StorageError::Database(format!("invalid CID '{cid_str}': {e}")))?;

    ensure_pinned_cids_table(pool).await?;

    let now_ms = now_ms();
    sqlx::query(
        "INSERT OR IGNORE INTO pinned_cids (cid, pinned_at_ms) VALUES (?1, ?2)",
    )
    .bind(cid_str)
    .bind(now_ms)
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    Ok(format!("pinned: {cid_str}\n"))
}

/// Remove a CID from the operator-pinned table.
///
/// Returns `"unpinned: {cid}"` if found and removed, or `"not pinned: {cid}"` if absent.
pub async fn cmd_unpin(pool: &SqlitePool, cid_str: &str) -> Result<String, StorageError> {
    ensure_pinned_cids_table(pool).await?;

    let result = sqlx::query("DELETE FROM pinned_cids WHERE cid = ?1")
        .bind(cid_str)
        .execute(pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        Ok(format!("not pinned: {cid_str}\n"))
    } else {
        Ok(format!("unpinned: {cid_str}\n"))
    }
}

/// Run a GC cycle immediately using the given policy.
///
/// Scans all entries in `pinned_cids`, evaluates each against the policy engine
/// (using a dummy `ArticleInfo` since article metadata is not stored in that table),
/// and removes those that fail the policy check.
///
/// Returns a summary string of the form `"gc-run: {scanned} scanned, {unpinned} unpinned\n"`.
pub async fn cmd_gc_run(pool: &SqlitePool, policy: &PinPolicy) -> Result<String, StorageError> {
    ensure_pinned_cids_table(pool).await?;

    let rows: Vec<String> = sqlx::query_scalar("SELECT cid FROM pinned_cids")
        .fetch_all(pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

    let scanned = rows.len();
    let now_ms_val = now_ms() as u64;
    let engine = PolicyEngine::new(policy.clone(), now_ms_val);

    let dummy_info = ArticleInfo {
        group: "unknown".to_string(),
        date_ms: now_ms_val,
        byte_count: 0,
    };

    let mut unpinned = 0usize;
    for cid_str in &rows {
        if !engine.should_pin(&dummy_info) {
            sqlx::query("DELETE FROM pinned_cids WHERE cid = ?1")
                .bind(cid_str)
                .execute(pool)
                .await
                .map_err(|e| StorageError::Database(e.to_string()))?;
            unpinned += 1;
        }
    }

    Ok(format!("gc-run: {scanned} scanned, {unpinned} unpinned\n"))
}

/// `transit peer-list`: display all peers with score and status.
///
/// Delegates to the peer CLI implementation.
pub use crate::cli::peers::cmd_peer_list;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Create the pinned_cids table if it does not exist.
async fn ensure_pinned_cids_table(pool: &SqlitePool) -> Result<(), StorageError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pinned_cids (\
            cid TEXT PRIMARY KEY NOT NULL, \
            pinned_at_ms INTEGER NOT NULL\
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

/// Current Unix time in milliseconds.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

    async fn make_pool() -> SqlitePool {
        let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:cli_ops_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::new()
            .filename(&url)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn status_on_empty_db_table() {
        let pool = make_pool().await;
        let result = cmd_status(&pool, OutputFormat::Table).await.unwrap();
        assert!(
            result.contains("peers") || result.contains("articles"),
            "status output: {result}"
        );
    }

    #[tokio::test]
    async fn status_on_empty_db_json() {
        let pool = make_pool().await;
        let result = cmd_status(&pool, OutputFormat::Json).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["peers_active"], 0);
        assert_eq!(v["articles"], 0);
        assert_eq!(v["pinned_cids"], 0);
    }

    #[tokio::test]
    async fn pin_unpin_roundtrip() {
        let pool = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";

        let pin_result = cmd_pin(&pool, cid_str).await.unwrap();
        assert!(pin_result.contains("pinned"), "pin result: {pin_result}");

        let unpin_result = cmd_unpin(&pool, cid_str).await.unwrap();
        assert!(
            unpin_result.contains("unpinned"),
            "unpin result: {unpin_result}"
        );
    }

    #[tokio::test]
    async fn unpin_not_pinned() {
        let pool = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";
        let result = cmd_unpin(&pool, cid_str).await.unwrap();
        assert!(
            result.contains("not pinned"),
            "should say not pinned: {result}"
        );
    }

    #[tokio::test]
    async fn pin_is_idempotent() {
        let pool = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";
        cmd_pin(&pool, cid_str).await.unwrap();
        let second = cmd_pin(&pool, cid_str).await.unwrap();
        assert!(second.contains("pinned"), "second pin result: {second}");
    }

    #[tokio::test]
    async fn gc_run_empty() {
        let pool = make_pool().await;
        let policy = PinPolicy {
            pin_all_groups: false,
            pin_groups: vec![],
            max_age_days: None,
            max_size_bytes: None,
        };
        let result = cmd_gc_run(&pool, &policy).await.unwrap();
        assert!(result.contains("gc-run"), "gc result: {result}");
        assert!(
            result.contains("0 scanned"),
            "should be 0 scanned: {result}"
        );
    }

    #[tokio::test]
    async fn gc_run_unpins_when_policy_rejects_all() {
        let pool = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";
        cmd_pin(&pool, cid_str).await.unwrap();

        let policy = PinPolicy {
            pin_all_groups: false,
            pin_groups: vec![],
            max_age_days: None,
            max_size_bytes: None,
        };
        let result = cmd_gc_run(&pool, &policy).await.unwrap();
        assert!(result.contains("1 scanned"), "should be 1 scanned: {result}");
        assert!(
            result.contains("1 unpinned"),
            "should be 1 unpinned: {result}"
        );
    }

    #[tokio::test]
    async fn gc_run_preserves_when_policy_accepts_all() {
        let pool = make_pool().await;
        let cid_str = "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm";
        cmd_pin(&pool, cid_str).await.unwrap();

        let policy = PinPolicy {
            pin_all_groups: true,
            pin_groups: vec![],
            max_age_days: None,
            max_size_bytes: None,
        };
        let result = cmd_gc_run(&pool, &policy).await.unwrap();
        assert!(result.contains("1 scanned"), "should be 1 scanned: {result}");
        assert!(
            result.contains("0 unpinned"),
            "should be 0 unpinned: {result}"
        );
    }

    #[tokio::test]
    async fn invalid_cid_rejected() {
        let pool = make_pool().await;
        let result = cmd_pin(&pool, "not-a-valid-cid").await;
        assert!(result.is_err(), "invalid CID should fail");
    }
}
