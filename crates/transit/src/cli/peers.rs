//! Peer management CLI subcommand implementations.
//!
//! These functions contain the logic for the `transit peer-*` subcommands.
//! They accept an `AnyPool` and return formatted output strings.
//! Actual argument parsing (clap) is wired in the binary; these functions
//! are pure business logic, testable without a CLI framework.

use crate::peering::blacklist::unblacklist;
use crate::peering::peer_registry::{peer_score, PeerRecord, PeerRegistry};
use sqlx::AnyPool;
use stoa_core::error::StorageError;

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
}

/// Format a peer status string from blacklist state.
fn peer_status(record: &PeerRecord, now_ms: i64) -> &'static str {
    match record.blacklisted_until_ms {
        Some(until) if until > now_ms => "blacklisted",
        _ => "active",
    }
}

/// `transit peer-list`: display all peers with score and status.
///
/// Returns a formatted string (table or JSON) for display.
pub async fn cmd_peer_list(
    pool: &AnyPool,
    now_ms: i64,
    format: OutputFormat,
) -> Result<String, StorageError> {
    let rows = sqlx::query(
        "SELECT peer_id, address, last_seen, articles_accepted, articles_rejected, \
         consecutive_failures, blacklisted_until, configured FROM peers ORDER BY last_seen DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    use sqlx::Row;
    let records: Vec<PeerRecord> = rows
        .into_iter()
        .map(|r| PeerRecord {
            peer_id: r.get(0),
            address: r.get(1),
            last_seen_ms: r.get(2),
            articles_accepted: r.get(3),
            articles_rejected: r.get(4),
            consecutive_failures: r.get(5),
            blacklisted_until_ms: r.get(6),
            configured: r.get::<i64, _>(7) != 0,
        })
        .collect();

    match format {
        OutputFormat::Table => {
            if records.is_empty() {
                return Ok("No peers registered.\n".to_string());
            }
            let mut out = format!(
                "{:<52} {:<20} {:>6} {:<12} {:<10}\n",
                "PEER_ID", "ADDRESS", "SCORE", "STATUS", "LAST_SEEN_MS"
            );
            out.push_str(&"-".repeat(106));
            out.push('\n');
            for r in &records {
                let score = peer_score(r);
                let status = peer_status(r, now_ms);
                out.push_str(&format!(
                    "{:<52} {:<20} {:>6.3} {:<12} {:<10}\n",
                    &r.peer_id, &r.address, score, status, r.last_seen_ms
                ));
            }
            Ok(out)
        }
        OutputFormat::Json => {
            let entries: Vec<serde_json::Value> = records
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "peer_id": r.peer_id,
                        "address": r.address,
                        "score": peer_score(r),
                        "status": peer_status(r, now_ms),
                        "last_seen_ms": r.last_seen_ms,
                        "articles_accepted": r.articles_accepted,
                        "articles_rejected": r.articles_rejected,
                        "consecutive_failures": r.consecutive_failures,
                        "blacklisted_until_ms": r.blacklisted_until_ms,
                        "configured": r.configured,
                    })
                })
                .collect();
            Ok(serde_json::to_string_pretty(&entries).unwrap())
        }
    }
}

/// `transit peer-score <peer_id>`: show detailed metrics for one peer.
pub async fn cmd_peer_score(
    pool: &AnyPool,
    peer_id: &str,
    now_ms: i64,
) -> Result<String, StorageError> {
    let registry = PeerRegistry::new(pool.clone());
    match registry.get(peer_id).await? {
        None => Ok(format!("Peer '{peer_id}' not found.\n")),
        Some(r) => {
            let score = peer_score(&r);
            let status = peer_status(&r, now_ms);
            Ok(format!(
                "peer_id:              {}\n\
                 address:              {}\n\
                 score:                {:.4}\n\
                 status:               {}\n\
                 articles_accepted:    {}\n\
                 articles_rejected:    {}\n\
                 consecutive_failures: {}\n\
                 last_seen_ms:         {}\n\
                 configured:           {}\n",
                r.peer_id,
                r.address,
                score,
                status,
                r.articles_accepted,
                r.articles_rejected,
                r.consecutive_failures,
                r.last_seen_ms,
                r.configured,
            ))
        }
    }
}

/// `transit peer-blacklist <peer_id> [duration_secs]`: manually blacklist a peer.
///
/// Returns a human-readable result string.
pub async fn cmd_peer_blacklist(
    pool: &AnyPool,
    peer_id: &str,
    now_ms: i64,
    duration_secs: i64,
) -> Result<String, StorageError> {
    let blacklisted_until = now_ms + duration_secs * 1000;
    let result = sqlx::query(
        "UPDATE peers SET blacklisted_until = ?, consecutive_failures = 20 WHERE peer_id = ?",
    )
    .bind(blacklisted_until)
    .bind(peer_id)
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    if result.rows_affected() == 0 {
        return Ok(format!("Peer '{peer_id}' not found.\n"));
    }
    Ok(format!(
        "Peer '{peer_id}' blacklisted until {blacklisted_until} ms.\n"
    ))
}

/// `transit peer-unblacklist <peer_id>`: clear blacklist for a peer.
pub async fn cmd_peer_unblacklist(pool: &AnyPool, peer_id: &str) -> Result<String, StorageError> {
    unblacklist(pool, peer_id).await?;
    Ok(format!("Peer '{peer_id}' unblacklisted.\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::AnyPool;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let _ = n;
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    async fn insert_peer(pool: &AnyPool, peer_id: &str, accepted: i64, rejected: i64) {
        sqlx::query(
            "INSERT INTO peers (peer_id, address, articles_accepted, articles_rejected, last_seen) \
             VALUES (?, '127.0.0.1:119', ?, ?, 0)",
        )
        .bind(peer_id)
        .bind(accepted)
        .bind(rejected)
        .execute(pool)
        .await
        .unwrap();
    }

    const NOW: i64 = 1_700_000_000_000i64;

    #[tokio::test]
    async fn peer_list_empty() {
        let (pool, _tmp) = make_pool().await;
        let output = cmd_peer_list(&pool, NOW, OutputFormat::Table)
            .await
            .unwrap();
        assert!(output.contains("No peers"));
    }

    #[tokio::test]
    async fn peer_list_table_contains_peer() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "12D3KooWExample", 100, 5).await;
        let output = cmd_peer_list(&pool, NOW, OutputFormat::Table)
            .await
            .unwrap();
        assert!(output.contains("12D3KooWExample"));
        assert!(output.contains("active"));
    }

    #[tokio::test]
    async fn peer_list_json_is_valid() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "12D3KooWExample", 10, 0).await;
        let output = cmd_peer_list(&pool, NOW, OutputFormat::Json).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
        assert_eq!(parsed[0]["peer_id"], "12D3KooWExample");
    }

    #[tokio::test]
    async fn peer_score_unknown() {
        let (pool, _tmp) = make_pool().await;
        let output = cmd_peer_score(&pool, "nonexistent", NOW).await.unwrap();
        assert!(output.contains("not found"));
    }

    #[tokio::test]
    async fn peer_score_known() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "peer1", 100, 0).await;
        let output = cmd_peer_score(&pool, "peer1", NOW).await.unwrap();
        assert!(output.contains("peer1"));
        assert!(output.contains("score"));
    }

    #[tokio::test]
    async fn peer_blacklist_and_unblacklist() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "peer1", 0, 0).await;
        let result = cmd_peer_blacklist(&pool, "peer1", NOW, 3600).await.unwrap();
        assert!(result.contains("blacklisted"));
        let result2 = cmd_peer_unblacklist(&pool, "peer1").await.unwrap();
        assert!(result2.contains("unblacklisted"));
    }
}
