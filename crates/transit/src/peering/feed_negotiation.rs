//! Feed negotiation: tracking which groups each peer serves.
//!
//! On connection, the transit daemon exchanges group lists with peers.
//! This module stores and queries that per-peer group data so that
//! IHAVE/TAKETHIS is only forwarded to peers that serve the group.

use sqlx::{AnyPool, QueryBuilder};
use stoa_core::error::StorageError;

/// Record the full group list served by a peer (replaces previous entry).
///
/// Deletes all previous `peer_groups` rows for `peer_id`, then inserts
/// the new list. Wrapped in a transaction for atomicity.
pub async fn update_peer_groups(
    pool: &AnyPool,
    peer_id: &str,
    groups: &[&str],
    now_ms: i64,
) -> Result<(), StorageError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

    sqlx::query("DELETE FROM peer_groups WHERE peer_id = ?")
        .bind(peer_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

    if !groups.is_empty() {
        let mut qb: QueryBuilder<sqlx::Any> =
            QueryBuilder::new("INSERT INTO peer_groups (peer_id, group_name, updated_at) ");
        qb.push_values(groups.iter(), |mut b, group| {
            b.push_bind(peer_id).push_bind(*group).push_bind(now_ms);
        });
        qb.build()
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

/// Return all groups served by a specific peer.
pub async fn groups_for_peer(pool: &AnyPool, peer_id: &str) -> Result<Vec<String>, StorageError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT group_name FROM peer_groups WHERE peer_id = ? ORDER BY group_name")
            .bind(peer_id)
            .fetch_all(pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(rows.into_iter().map(|(g,)| g).collect())
}

/// Return all peers that serve a given group.
///
/// Use this to route IHAVE: only forward articles in `group_name` to
/// peers returned by this function.
pub async fn peers_serving_group(
    pool: &AnyPool,
    group_name: &str,
) -> Result<Vec<String>, StorageError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT peer_id FROM peer_groups WHERE group_name = ? ORDER BY peer_id")
            .bind(group_name)
            .fetch_all(pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(rows.into_iter().map(|(p,)| p).collect())
}

/// Check if a specific peer serves a specific group.
pub async fn peer_serves_group(
    pool: &AnyPool,
    peer_id: &str,
    group_name: &str,
) -> Result<bool, StorageError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM peer_groups WHERE peer_id = ? AND group_name = ?")
            .bind(peer_id)
            .bind(group_name)
            .fetch_optional(pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(row.is_some())
}

/// Remove all group associations for a peer (on disconnect or peer removal).
pub async fn clear_peer_groups(pool: &AnyPool, peer_id: &str) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM peer_groups WHERE peer_id = ?")
        .bind(peer_id)
        .execute(pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    async fn insert_peer(pool: &AnyPool, peer_id: &str) {
        sqlx::query("INSERT INTO peers (peer_id, address) VALUES (?, '127.0.0.1:119')")
            .bind(peer_id)
            .execute(pool)
            .await
            .unwrap();
    }

    const NOW: i64 = 1700000000000i64;

    #[tokio::test]
    async fn update_and_query_groups() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "peer1").await;
        let groups = &["comp.lang.rust", "sci.math", "alt.test"];
        update_peer_groups(&pool, "peer1", groups, NOW)
            .await
            .unwrap();

        let result = groups_for_peer(&pool, "peer1").await.unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"comp.lang.rust".to_string()));
        assert!(result.contains(&"sci.math".to_string()));
        assert!(result.contains(&"alt.test".to_string()));
    }

    #[tokio::test]
    async fn update_replaces_previous_groups() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "peer1").await;
        update_peer_groups(&pool, "peer1", &["comp.lang.rust", "sci.math"], NOW)
            .await
            .unwrap();
        update_peer_groups(&pool, "peer1", &["alt.test"], NOW)
            .await
            .unwrap();

        let result = groups_for_peer(&pool, "peer1").await.unwrap();
        assert_eq!(result, vec!["alt.test"]);
    }

    #[tokio::test]
    async fn peers_serving_group_returns_correct_peers() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "peer1").await;
        insert_peer(&pool, "peer2").await;
        insert_peer(&pool, "peer3").await;

        update_peer_groups(&pool, "peer1", &["comp.lang.rust", "sci.math"], NOW)
            .await
            .unwrap();
        update_peer_groups(&pool, "peer2", &["comp.lang.rust"], NOW)
            .await
            .unwrap();
        update_peer_groups(&pool, "peer3", &["alt.test"], NOW)
            .await
            .unwrap();

        let serving_comp = peers_serving_group(&pool, "comp.lang.rust").await.unwrap();
        assert_eq!(serving_comp.len(), 2);
        assert!(serving_comp.contains(&"peer1".to_string()));
        assert!(serving_comp.contains(&"peer2".to_string()));
        assert!(!serving_comp.contains(&"peer3".to_string()));
    }

    #[tokio::test]
    async fn peer_serves_group_true_and_false() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "peer1").await;
        update_peer_groups(&pool, "peer1", &["comp.lang.rust"], NOW)
            .await
            .unwrap();

        assert!(peer_serves_group(&pool, "peer1", "comp.lang.rust")
            .await
            .unwrap());
        assert!(!peer_serves_group(&pool, "peer1", "sci.math").await.unwrap());
    }

    #[tokio::test]
    async fn clear_peer_groups_removes_all() {
        let (pool, _tmp) = make_pool().await;
        insert_peer(&pool, "peer1").await;
        update_peer_groups(&pool, "peer1", &["comp.lang.rust", "alt.test"], NOW)
            .await
            .unwrap();
        clear_peer_groups(&pool, "peer1").await.unwrap();
        assert!(groups_for_peer(&pool, "peer1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn unknown_peer_returns_empty_groups() {
        let (pool, _tmp) = make_pool().await;
        let result = groups_for_peer(&pool, "unknown").await.unwrap();
        assert!(result.is_empty());
    }
}
