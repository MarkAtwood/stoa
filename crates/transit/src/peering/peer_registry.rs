//! Peer registry: persistent store for known peers and their health metrics.

use sqlx::AnyPool;
use stoa_core::error::StorageError;

/// A record in the peer registry.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerRecord {
    pub peer_id: String,
    pub address: String,
    pub last_seen_ms: i64,
    pub articles_accepted: i64,
    pub articles_rejected: i64,
    pub consecutive_failures: i64,
    pub blacklisted_until_ms: Option<i64>,
    pub configured: bool,
}

pub struct PeerRegistry {
    pool: AnyPool,
}

impl PeerRegistry {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Insert or update a peer record (upsert on peer_id).
    pub async fn upsert(&self, record: &PeerRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO peers (peer_id, address, last_seen, articles_accepted, \
             articles_rejected, consecutive_failures, blacklisted_until, configured) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(peer_id) DO UPDATE SET \
             address=excluded.address, \
             last_seen=excluded.last_seen, \
             articles_accepted=excluded.articles_accepted, \
             articles_rejected=excluded.articles_rejected, \
             consecutive_failures=excluded.consecutive_failures, \
             blacklisted_until=excluded.blacklisted_until, \
             configured=excluded.configured",
        )
        .bind(&record.peer_id)
        .bind(&record.address)
        .bind(record.last_seen_ms)
        .bind(record.articles_accepted)
        .bind(record.articles_rejected)
        .bind(record.consecutive_failures)
        .bind(record.blacklisted_until_ms)
        .bind(record.configured as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    /// Look up a peer by its peer_id string.
    pub async fn get(&self, peer_id: &str) -> Result<Option<PeerRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT peer_id, address, last_seen, articles_accepted, articles_rejected, \
             consecutive_failures, blacklisted_until, configured FROM peers WHERE peer_id = ?",
        )
        .bind(peer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row.map(|r| {
            use sqlx::Row;
            PeerRecord {
                peer_id: r.get("peer_id"),
                address: r.get("address"),
                last_seen_ms: r.get("last_seen"),
                articles_accepted: r.get("articles_accepted"),
                articles_rejected: r.get("articles_rejected"),
                consecutive_failures: r.get("consecutive_failures"),
                blacklisted_until_ms: r.get("blacklisted_until"),
                configured: r.get::<i64, _>("configured") != 0,
            }
        }))
    }

    /// Ensure a peer record exists without overwriting existing data.
    ///
    /// Inserts a minimal row (peer_id, address, last_seen) with all counters at
    /// their defaults if no row for this peer_id is present yet.  No-op if the
    /// peer is already registered.  Call this on first TCP contact so that
    /// `record_accepted`, `record_rejected`, and `is_blacklisted` have a row to
    /// operate on.
    pub async fn ensure_registered(
        &self,
        peer_id: &str,
        address: &str,
        now_ms: i64,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO peers (peer_id, address, last_seen) VALUES (?, ?, ?) \
             ON CONFLICT (peer_id) DO NOTHING",
        )
        .bind(peer_id)
        .bind(address)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    /// Record a successful article ingestion from a peer.
    pub async fn record_accepted(&self, peer_id: &str, now_ms: i64) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE peers SET articles_accepted = articles_accepted + 1, \
             consecutive_failures = 0, last_seen = ? WHERE peer_id = ?",
        )
        .bind(now_ms)
        .bind(peer_id)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    /// Record a rejected article from a peer (increment consecutive_failures).
    pub async fn record_rejected(&self, peer_id: &str, now_ms: i64) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE peers SET articles_rejected = articles_rejected + 1, \
             consecutive_failures = MIN(consecutive_failures + 1, 20), last_seen = ? WHERE peer_id = ?",
        )
        .bind(now_ms)
        .bind(peer_id)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    /// List all peers not currently blacklisted (blacklisted_until IS NULL or in the past).
    pub async fn list_active(&self, now_ms: i64) -> Result<Vec<PeerRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT peer_id, address, last_seen, articles_accepted, articles_rejected, \
             consecutive_failures, blacklisted_until, configured FROM peers \
             WHERE blacklisted_until IS NULL OR blacklisted_until <= ? \
             ORDER BY last_seen DESC",
        )
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        use sqlx::Row;
        Ok(rows
            .into_iter()
            .map(|r| PeerRecord {
                peer_id: r.get("peer_id"),
                address: r.get("address"),
                last_seen_ms: r.get("last_seen"),
                articles_accepted: r.get("articles_accepted"),
                articles_rejected: r.get("articles_rejected"),
                consecutive_failures: r.get("consecutive_failures"),
                blacklisted_until_ms: r.get("blacklisted_until"),
                configured: r.get::<i64, _>("configured") != 0,
            })
            .collect())
    }
}

/// Maximum consecutive failures before the score bottoms out.
/// Prevents score calculation from being affected by unbounded counter growth.
pub const MAX_CONSECUTIVE_FAILURES: i64 = 20;

/// Compute a health score for a peer record.
///
/// Score formula:
/// - Start at 1.0 (perfect health)
/// - Reduce by accept_rate penalty: if total articles > 0, accept_rate = accepted / (accepted + rejected)
///   penalty = (1.0 - accept_rate) * 0.5  (a peer with 0% accept rate loses 0.5 points)
/// - Reduce by consecutive failures: penalty = min(consecutive_failures, MAX_CONSECUTIVE_FAILURES)
///   / MAX_CONSECUTIVE_FAILURES * 0.5
/// - Clamp result to [0.0, 1.0]
///
/// If no articles have been exchanged (both accepted and rejected == 0),
/// the accept_rate component is 0 (no penalty from accept rate).
pub fn peer_score(record: &PeerRecord) -> f64 {
    let total = record.articles_accepted + record.articles_rejected;

    let accept_penalty = if total > 0 {
        let accept_rate = record.articles_accepted as f64 / total as f64;
        (1.0 - accept_rate) * 0.5
    } else {
        0.0
    };

    let failures_capped = record.consecutive_failures.min(MAX_CONSECUTIVE_FAILURES);
    let failure_penalty = (failures_capped as f64 / MAX_CONSECUTIVE_FAILURES as f64) * 0.5;

    (1.0 - accept_penalty - failure_penalty).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn make_registry() -> (PeerRegistry, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (PeerRegistry::new(pool), tmp)
    }

    fn make_record(peer_id: &str) -> PeerRecord {
        PeerRecord {
            peer_id: peer_id.to_string(),
            address: "192.0.2.1:119".to_string(),
            last_seen_ms: 1700000000000,
            articles_accepted: 0,
            articles_rejected: 0,
            consecutive_failures: 0,
            blacklisted_until_ms: None,
            configured: false,
        }
    }

    #[tokio::test]
    async fn upsert_and_get_roundtrip() {
        let (reg, _tmp) = make_registry().await;
        let record = make_record("12D3KooWExample");
        reg.upsert(&record).await.unwrap();
        let got = reg
            .get("12D3KooWExample")
            .await
            .unwrap()
            .expect("should exist");
        assert_eq!(got.peer_id, "12D3KooWExample");
        assert_eq!(got.address, "192.0.2.1:119");
        assert!(!got.configured);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let (reg, _tmp) = make_registry().await;
        assert!(reg.get("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn record_accepted_increments_counter() {
        let (reg, _tmp) = make_registry().await;
        reg.upsert(&make_record("peer1")).await.unwrap();
        reg.record_accepted("peer1", 1700000001000).await.unwrap();
        let got = reg.get("peer1").await.unwrap().unwrap();
        assert_eq!(got.articles_accepted, 1);
        assert_eq!(got.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn record_rejected_increments_consecutive_failures() {
        let (reg, _tmp) = make_registry().await;
        reg.upsert(&make_record("peer1")).await.unwrap();
        reg.record_rejected("peer1", 1700000001000).await.unwrap();
        reg.record_rejected("peer1", 1700000002000).await.unwrap();
        let got = reg.get("peer1").await.unwrap().unwrap();
        assert_eq!(got.articles_rejected, 2);
        assert_eq!(got.consecutive_failures, 2);
    }

    #[tokio::test]
    async fn list_active_excludes_blacklisted() {
        let (reg, _tmp) = make_registry().await;
        let now_ms = 1700000000000i64;

        let active = make_record("active_peer");
        reg.upsert(&active).await.unwrap();

        let mut blacklisted = make_record("blacklisted_peer");
        blacklisted.blacklisted_until_ms = Some(now_ms + 3_600_000); // blacklisted for 1h
        reg.upsert(&blacklisted).await.unwrap();

        let active_peers = reg.list_active(now_ms).await.unwrap();
        assert_eq!(active_peers.len(), 1);
        assert_eq!(active_peers[0].peer_id, "active_peer");
    }

    #[tokio::test]
    async fn upsert_is_idempotent() {
        let (reg, _tmp) = make_registry().await;
        let mut record = make_record("peer1");
        reg.upsert(&record).await.unwrap();
        record.articles_accepted = 99;
        reg.upsert(&record).await.unwrap();
        let got = reg.get("peer1").await.unwrap().unwrap();
        assert_eq!(got.articles_accepted, 99);
    }

    #[test]
    fn peer_score_perfect_health() {
        let mut record = make_record("peer1");
        record.articles_accepted = 100;
        record.articles_rejected = 0;
        record.consecutive_failures = 0;
        let score = peer_score(&record);
        assert!(
            (score - 1.0).abs() < 0.01,
            "perfect peer should score ~1.0, got {score}"
        );
    }

    #[test]
    fn peer_score_zero_accept_rate_loses_half() {
        let mut record = make_record("peer1");
        record.articles_accepted = 0;
        record.articles_rejected = 100;
        record.consecutive_failures = 0;
        let score = peer_score(&record);
        // accept_penalty = (1.0 - 0.0) * 0.5 = 0.5; failure_penalty = 0 → score = 0.5
        assert!(
            (score - 0.5).abs() < 0.01,
            "0% accept rate should score 0.5, got {score}"
        );
    }

    #[test]
    fn peer_score_max_failures_loses_half() {
        let mut record = make_record("peer1");
        record.articles_accepted = 100;
        record.articles_rejected = 0;
        record.consecutive_failures = MAX_CONSECUTIVE_FAILURES;
        let score = peer_score(&record);
        // accept_penalty = 0.0; failure_penalty = 1.0 * 0.5 = 0.5 → score = 0.5
        assert!(
            (score - 0.5).abs() < 0.01,
            "max failures should score 0.5, got {score}"
        );
    }

    #[test]
    fn peer_score_zero_accepts_max_failures_scores_zero() {
        let mut record = make_record("peer1");
        record.articles_accepted = 0;
        record.articles_rejected = 100;
        record.consecutive_failures = MAX_CONSECUTIVE_FAILURES;
        let score = peer_score(&record);
        assert!(score <= 0.01, "worst peer should score ~0.0, got {score}");
    }

    #[test]
    fn peer_score_high_accept_beats_low_accept() {
        let mut high = make_record("high");
        high.articles_accepted = 100;
        high.articles_rejected = 0;

        let mut low = make_record("low");
        low.articles_accepted = 50;
        low.articles_rejected = 50;

        assert!(
            peer_score(&high) > peer_score(&low),
            "100% accept rate should score higher than 50%: {} vs {}",
            peer_score(&high),
            peer_score(&low)
        );
    }

    #[test]
    fn peer_score_no_articles_not_penalized() {
        let record = make_record("new_peer");
        // No articles exchanged: no accept_rate penalty.
        let score = peer_score(&record);
        assert!(
            (score - 1.0).abs() < 0.01,
            "new peer with no history should score 1.0, got {score}"
        );
    }

    #[test]
    fn consecutive_failures_capped_at_max() {
        let mut record = make_record("peer1");
        record.consecutive_failures = MAX_CONSECUTIVE_FAILURES + 100; // way over cap
        let score = peer_score(&record);
        // Should be treated the same as MAX_CONSECUTIVE_FAILURES.
        let mut record2 = make_record("peer2");
        record2.consecutive_failures = MAX_CONSECUTIVE_FAILURES;
        let score2 = peer_score(&record2);
        assert!(
            (score - score2).abs() < 0.001,
            "scores should be identical when failures exceed cap: {score} vs {score2}"
        );
    }
}
