//! Periodic sampler for per-group Prometheus gauges.
//!
//! Queries the `articles` table once per interval and updates three gauges:
//!
//! | Metric                          | Source                              |
//! |---------------------------------|-------------------------------------|
//! | `group_log_entries_total{group}`| `COUNT(*)` from `articles`          |
//! | `group_storage_bytes{group}`    | `SUM(byte_count)` from `articles`   |
//! | `group_last_activity_timestamp` | `MAX(ingested_at_ms)` from `articles`|
//!
//! Note: `group_log_lag{group,peer}` is not yet implemented; it requires
//! per-session peer-state tracking that was removed with gossipsub.
//!
//! **High-cardinality guard**: if more than [`HIGH_CARDINALITY_LIMIT`] distinct
//! groups are active, the gauges are not updated and a warning is emitted.
//! This prevents unbounded Prometheus label explosion.

use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;

/// Maximum number of distinct groups before per-group gauges are suppressed.
pub const HIGH_CARDINALITY_LIMIT: usize = 500;

/// Spawn-and-forget background task: samples per-group metrics every `interval`.
pub async fn run_group_metrics_sampler(pool: Arc<SqlitePool>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Err(e) = sample_group_metrics(&pool).await {
            tracing::warn!("group metrics sampling failed: {e}");
        }
    }
}

/// Run one sampling pass.  Exported for testing.
pub async fn sample_group_metrics(pool: &SqlitePool) -> Result<usize, String> {
    // Single query for all three metrics; GROUP BY is O(articles) either way.
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT group_name,
                COUNT(*),
                COALESCE(SUM(byte_count), 0),
                COALESCE(MAX(ingested_at_ms), 0)
         FROM articles
         GROUP BY group_name
         ORDER BY group_name",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("articles GROUP BY query failed: {e}"))?;

    let group_count = rows.len();

    if group_count > HIGH_CARDINALITY_LIMIT {
        tracing::warn!(
            group_count,
            limit = HIGH_CARDINALITY_LIMIT,
            "per-group metrics suppressed: active group count exceeds limit"
        );
        return Ok(group_count);
    }

    for (group_name, count, total_bytes, last_at_ms) in &rows {
        crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&[group_name])
            .set(*count as f64);

        crate::metrics::GROUP_STORAGE_BYTES
            .with_label_values(&[group_name])
            .set(*total_bytes as f64);

        // Convert milliseconds to seconds for a standard Unix-epoch gauge.
        crate::metrics::GROUP_LAST_ACTIVITY_TIMESTAMP
            .with_label_values(&[group_name])
            .set(*last_at_ms as f64 / 1000.0);
    }

    Ok(group_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;

    async fn make_pool() -> SqlitePool {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        pool
    }

    async fn insert_article(
        pool: &SqlitePool,
        cid: &str,
        group: &str,
        ingested_at_ms: i64,
        byte_count: i64,
    ) {
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(cid)
        .bind(group)
        .bind(ingested_at_ms)
        .bind(byte_count)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sample_empty_db_returns_zero_groups() {
        let pool = make_pool().await;
        let n = sample_group_metrics(&pool).await.unwrap();
        assert_eq!(n, 0, "empty articles table should return 0 groups");
    }

    #[tokio::test]
    async fn sample_single_group_sets_gauges() {
        let pool = make_pool().await;
        insert_article(&pool, "<a@t>", "comp.lang.rust", 1_700_000_000_000, 1024).await;
        insert_article(&pool, "<b@t>", "comp.lang.rust", 1_700_000_001_000, 2048).await;

        let n = sample_group_metrics(&pool).await.unwrap();
        assert_eq!(n, 1);

        let entries = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["comp.lang.rust"])
            .get();
        assert_eq!(entries, 2.0, "expected 2 entries for comp.lang.rust");

        let bytes = crate::metrics::GROUP_STORAGE_BYTES
            .with_label_values(&["comp.lang.rust"])
            .get();
        assert_eq!(bytes, 3072.0, "expected 3072 bytes for comp.lang.rust");

        let last_ts = crate::metrics::GROUP_LAST_ACTIVITY_TIMESTAMP
            .with_label_values(&["comp.lang.rust"])
            .get();
        assert!(
            (last_ts - 1_700_000_001.0).abs() < 0.001,
            "expected last activity ~1700000001s, got {last_ts}"
        );
    }

    #[tokio::test]
    async fn sample_multiple_groups() {
        let pool = make_pool().await;
        insert_article(&pool, "<c1@t>", "alt.test", 1_000_000_000_000, 512).await;
        insert_article(&pool, "<c2@t>", "sci.math", 1_000_000_002_000, 256).await;
        insert_article(&pool, "<c3@t>", "sci.math", 1_000_000_004_000, 256).await;

        let n = sample_group_metrics(&pool).await.unwrap();
        assert_eq!(n, 2, "expected 2 distinct groups");

        let alt_entries = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["alt.test"])
            .get();
        assert_eq!(alt_entries, 1.0);

        let sci_entries = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["sci.math"])
            .get();
        assert_eq!(sci_entries, 2.0);
    }

    #[tokio::test]
    async fn high_cardinality_guard_suppresses_updates() {
        let pool = make_pool().await;

        // Insert articles in more than HIGH_CARDINALITY_LIMIT distinct groups.
        // Each group gets one article; group names are "g.0", "g.1", ..., "g.N".
        let n_groups = HIGH_CARDINALITY_LIMIT + 1;
        for i in 0..n_groups {
            let cid = format!("<hc-{i}@t>");
            let group = format!("g.{i}");
            insert_article(&pool, &cid, &group, 1_000_000_000_000 + i as i64, 100).await;
        }

        let n = sample_group_metrics(&pool).await.unwrap();
        assert_eq!(n, n_groups, "returned group count must match inserts");

        // Gauges for group "g.0" must NOT have been updated (guard suppressed).
        // They will be absent (0.0 default) because these are new label values.
        let entries = crate::metrics::GROUP_LOG_ENTRIES_TOTAL
            .with_label_values(&["g.0"])
            .get();
        assert_eq!(
            entries, 0.0,
            "gauge must not be set when cardinality guard fires"
        );
    }
}
