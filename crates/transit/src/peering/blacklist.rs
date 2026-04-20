//! Automatic peer blacklisting based on consecutive failure threshold.
//!
//! When a peer's `consecutive_failures` exceeds the configured threshold,
//! `check_and_blacklist` sets `blacklisted_until = now + duration`.
//! Blacklist entries expire automatically; `is_blacklisted` returns false
//! once the timestamp passes.

use sqlx::SqlitePool;
use usenet_ipfs_core::error::StorageError;

/// Configuration for the blacklist policy.
#[derive(Debug, Clone)]
pub struct BlacklistConfig {
    /// Number of consecutive failures before blacklisting (default: 10).
    pub failure_threshold: i64,
    /// How long to blacklist the peer in seconds (default: 3600 = 1 hour).
    pub duration_secs: i64,
}

impl Default for BlacklistConfig {
    fn default() -> Self {
        Self { failure_threshold: 10, duration_secs: 3600 }
    }
}

/// Check a peer's consecutive_failures and blacklist if threshold is exceeded.
///
/// If `consecutive_failures >= config.failure_threshold`, sets
/// `blacklisted_until = now_ms + config.duration_secs * 1000` in the DB.
///
/// Returns `true` if the peer was newly blacklisted, `false` otherwise.
/// Logs at `warn` level when blacklisting occurs.
pub async fn check_and_blacklist(
    pool: &SqlitePool,
    peer_id: &str,
    now_ms: i64,
    config: &BlacklistConfig,
) -> Result<bool, StorageError> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT consecutive_failures FROM peers WHERE peer_id = ?1",
    )
    .bind(peer_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    let failures = match row {
        Some((f,)) => f,
        None => return Ok(false),
    };

    if failures >= config.failure_threshold {
        let blacklisted_until = now_ms + config.duration_secs * 1000;
        sqlx::query(
            "UPDATE peers SET blacklisted_until = ?1 WHERE peer_id = ?2",
        )
        .bind(blacklisted_until)
        .bind(peer_id)
        .execute(pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        tracing::warn!(
            peer_id = %peer_id,
            consecutive_failures = failures,
            blacklisted_until_ms = blacklisted_until,
            "peer blacklisted after exceeding failure threshold"
        );
        return Ok(true);
    }

    Ok(false)
}

/// Check if a peer is currently blacklisted.
///
/// Returns `true` if `blacklisted_until > now_ms`.
/// Expired blacklist entries (where `blacklisted_until <= now_ms`) return `false`.
pub async fn is_blacklisted(
    pool: &SqlitePool,
    peer_id: &str,
    now_ms: i64,
) -> Result<bool, StorageError> {
    let row: Option<(Option<i64>,)> = sqlx::query_as(
        "SELECT blacklisted_until FROM peers WHERE peer_id = ?1",
    )
    .bind(peer_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    Ok(match row {
        Some((Some(until),)) => until > now_ms,
        _ => false,
    })
}

/// Manually unblacklist a peer (operator action).
///
/// Sets `blacklisted_until = NULL` for the given peer_id.
/// Logs at `info` level. No-op if peer is not blacklisted.
pub async fn unblacklist(
    pool: &SqlitePool,
    peer_id: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE peers SET blacklisted_until = NULL, consecutive_failures = 0 WHERE peer_id = ?1",
    )
    .bind(peer_id)
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    tracing::info!(peer_id = %peer_id, "peer manually unblacklisted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    async fn make_pool() -> SqlitePool {
        let n = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let url = format!("file:blacklist_test_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url).unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        pool
    }

    async fn insert_peer(pool: &SqlitePool, peer_id: &str, failures: i64) {
        sqlx::query(
            "INSERT INTO peers (peer_id, address, consecutive_failures) VALUES (?1, '127.0.0.1:119', ?2)",
        )
        .bind(peer_id)
        .bind(failures)
        .execute(pool)
        .await
        .unwrap();
    }

    const NOW: i64 = 1_700_000_000_000i64;

    #[tokio::test]
    async fn not_blacklisted_below_threshold() {
        let pool = make_pool().await;
        insert_peer(&pool, "peer1", 5).await;
        let config = BlacklistConfig { failure_threshold: 10, duration_secs: 3600 };
        let result = check_and_blacklist(&pool, "peer1", NOW, &config).await.unwrap();
        assert!(!result, "5 failures < threshold=10, should not blacklist");
        assert!(!is_blacklisted(&pool, "peer1", NOW).await.unwrap());
    }

    #[tokio::test]
    async fn blacklisted_at_threshold() {
        let pool = make_pool().await;
        insert_peer(&pool, "peer1", 10).await;
        let config = BlacklistConfig { failure_threshold: 10, duration_secs: 3600 };
        let result = check_and_blacklist(&pool, "peer1", NOW, &config).await.unwrap();
        assert!(result, "10 failures >= threshold=10, should blacklist");
        assert!(is_blacklisted(&pool, "peer1", NOW).await.unwrap());
    }

    #[tokio::test]
    async fn blacklist_expires_after_duration() {
        let pool = make_pool().await;
        insert_peer(&pool, "peer1", 20).await;
        let config = BlacklistConfig { failure_threshold: 10, duration_secs: 3600 };
        check_and_blacklist(&pool, "peer1", NOW, &config).await.unwrap();

        let future_ms = NOW + 3600 * 1000 + 1;
        assert!(
            !is_blacklisted(&pool, "peer1", future_ms).await.unwrap(),
            "blacklist should have expired"
        );
    }

    #[tokio::test]
    async fn manual_unblacklist_clears_entry() {
        let pool = make_pool().await;
        insert_peer(&pool, "peer1", 20).await;
        let config = BlacklistConfig::default();
        check_and_blacklist(&pool, "peer1", NOW, &config).await.unwrap();
        assert!(is_blacklisted(&pool, "peer1", NOW).await.unwrap());

        unblacklist(&pool, "peer1").await.unwrap();
        assert!(!is_blacklisted(&pool, "peer1", NOW).await.unwrap());
    }

    #[tokio::test]
    async fn unknown_peer_not_blacklisted() {
        let pool = make_pool().await;
        let result =
            check_and_blacklist(&pool, "unknown", NOW, &BlacklistConfig::default()).await.unwrap();
        assert!(!result);
        assert!(!is_blacklisted(&pool, "unknown", NOW).await.unwrap());
    }
}
