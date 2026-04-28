//! Per-instance identity management (usenet-ipfs-ky62.5).
//!
//! `ensure_instance_node_id` inserts a random 8-byte value for `hostname`
//! into `transit_instance_id` at startup (INSERT ... ON CONFLICT DO NOTHING),
//! then reads back the stored value.  Multiple transit daemons sharing a
//! signing key each get a distinct, stable HLC node_id as long as they run
//! on different hostnames.
//!
//! For single-instance SQLite deployments the same logic applies: the value
//! is generated on first startup and reused across restarts.

use rand_core::{OsRng, RngCore};
use sqlx::AnyPool;

/// Ensure this instance has a stable 8-byte node_id stored in `pool`.
///
/// Generates random bytes and attempts `INSERT ... ON CONFLICT DO NOTHING`
/// keyed by `hostname`.  If a row already exists (restart case), the stored
/// value wins.  Returns the 8-byte node_id, ready for `HlcClock::new`.
pub async fn ensure_instance_node_id(pool: &AnyPool, hostname: &str) -> [u8; 8] {
    let mut fresh = [0u8; 8];
    OsRng.fill_bytes(&mut fresh);
    let fresh_hex = hex::encode(fresh);

    let _ = sqlx::query(
        "INSERT INTO transit_instance_id (key, value) VALUES (?, ?) \
         ON CONFLICT (key) DO NOTHING",
    )
    .bind(hostname)
    .bind(&fresh_hex)
    .execute(pool)
    .await;

    match sqlx::query_scalar::<_, String>("SELECT value FROM transit_instance_id WHERE key = ?")
        .bind(hostname)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(stored)) => {
            if let Ok(b) = hex::decode(&stored) {
                let mut id = [0u8; 8];
                let n = b.len().min(8);
                id[..n].copy_from_slice(&b[..n]);
                return id;
            }
            fresh
        }
        Ok(None) => fresh,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "instance_id: database read failed, falling back to ephemeral random ID \
                — node identity will not persist across restarts"
            );
            fresh
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (pool, tmp)
    }

    #[tokio::test]
    async fn node_id_is_stable_across_calls() {
        let (pool, _tmp) = make_pool().await;
        let id1 = ensure_instance_node_id(&pool, "host.example").await;
        let id2 = ensure_instance_node_id(&pool, "host.example").await;
        assert_eq!(
            id1, id2,
            "same hostname must return same node_id on repeat calls"
        );
    }

    #[tokio::test]
    async fn different_hostnames_get_different_node_ids() {
        let (pool, _tmp) = make_pool().await;
        let id_a = ensure_instance_node_id(&pool, "host-a.example").await;
        let id_b = ensure_instance_node_id(&pool, "host-b.example").await;
        assert_ne!(
            id_a, id_b,
            "different hostnames must get different node_ids"
        );
    }

    #[tokio::test]
    async fn node_id_is_nonzero() {
        let (pool, _tmp) = make_pool().await;
        let id = ensure_instance_node_id(&pool, "nonzero.test").await;
        assert_ne!(id, [0u8; 8], "node_id must not be all zeros");
    }
}
