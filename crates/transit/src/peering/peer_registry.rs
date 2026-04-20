//! Peer registry: persistent store for known peers and their health metrics.

use sqlx::SqlitePool;
use usenet_ipfs_core::error::StorageError;

/// A record in the peer registry.
#[derive(Debug, Clone)]
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
    pool: SqlitePool,
}

impl PeerRegistry {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert or update a peer record (upsert on peer_id).
    pub async fn upsert(&self, record: &PeerRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO peers (peer_id, address, last_seen, articles_accepted, \
             articles_rejected, consecutive_failures, blacklisted_until, configured) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
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
             consecutive_failures, blacklisted_until, configured FROM peers WHERE peer_id = ?1",
        )
        .bind(peer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row.map(|r| {
            use sqlx::Row;
            PeerRecord {
                peer_id: r.get(0),
                address: r.get(1),
                last_seen_ms: r.get(2),
                articles_accepted: r.get(3),
                articles_rejected: r.get(4),
                consecutive_failures: r.get(5),
                blacklisted_until_ms: r.get(6),
                configured: r.get::<i64, _>(7) != 0,
            }
        }))
    }

    /// Record a successful article ingestion from a peer.
    pub async fn record_accepted(&self, peer_id: &str, now_ms: i64) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE peers SET articles_accepted = articles_accepted + 1, \
             consecutive_failures = 0, last_seen = ?1 WHERE peer_id = ?2",
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
             consecutive_failures = consecutive_failures + 1, last_seen = ?1 WHERE peer_id = ?2",
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
             WHERE blacklisted_until IS NULL OR blacklisted_until <= ?1 \
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
                peer_id: r.get(0),
                address: r.get(1),
                last_seen_ms: r.get(2),
                articles_accepted: r.get(3),
                articles_rejected: r.get(4),
                consecutive_failures: r.get(5),
                blacklisted_until_ms: r.get(6),
                configured: r.get::<i64, _>(7) != 0,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    async fn make_registry() -> PeerRegistry {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        PeerRegistry::new(pool)
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
        let reg = make_registry().await;
        let record = make_record("12D3KooWExample");
        reg.upsert(&record).await.unwrap();
        let got = reg.get("12D3KooWExample").await.unwrap().expect("should exist");
        assert_eq!(got.peer_id, "12D3KooWExample");
        assert_eq!(got.address, "192.0.2.1:119");
        assert!(!got.configured);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let reg = make_registry().await;
        assert!(reg.get("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn record_accepted_increments_counter() {
        let reg = make_registry().await;
        reg.upsert(&make_record("peer1")).await.unwrap();
        reg.record_accepted("peer1", 1700000001000).await.unwrap();
        let got = reg.get("peer1").await.unwrap().unwrap();
        assert_eq!(got.articles_accepted, 1);
        assert_eq!(got.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn record_rejected_increments_consecutive_failures() {
        let reg = make_registry().await;
        reg.upsert(&make_record("peer1")).await.unwrap();
        reg.record_rejected("peer1", 1700000001000).await.unwrap();
        reg.record_rejected("peer1", 1700000002000).await.unwrap();
        let got = reg.get("peer1").await.unwrap().unwrap();
        assert_eq!(got.articles_rejected, 2);
        assert_eq!(got.consecutive_failures, 2);
    }

    #[tokio::test]
    async fn list_active_excludes_blacklisted() {
        let reg = make_registry().await;
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
        let reg = make_registry().await;
        let mut record = make_record("peer1");
        reg.upsert(&record).await.unwrap();
        record.articles_accepted = 99;
        reg.upsert(&record).await.unwrap();
        let got = reg.get("peer1").await.unwrap().unwrap();
        assert_eq!(got.articles_accepted, 99);
    }
}
