//! Persist and load the HLC clock state across restarts (usenet-ipfs-gq0z).
//!
//! A single row in `hlc_checkpoint` stores the last emitted timestamp.
//! On startup, `load_hlc_checkpoint` reads it; `HlcClock::new_seeded` then
//! ensures the first `send()` after restart is above the persisted value.
//!
//! A background task calls `save_hlc_checkpoint` every 30 seconds.

use sqlx::AnyPool;
use stoa_core::hlc::HlcTimestamp;

/// Load the persisted HLC checkpoint.
///
/// Returns `Ok(None)` on first run (table row does not exist yet).
pub async fn load_hlc_checkpoint(pool: &AnyPool) -> Result<Option<HlcTimestamp>, sqlx::Error> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT wall_ms, logical FROM hlc_checkpoint WHERE id = 1")
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(wall_ms, logical)| HlcTimestamp {
        wall_ms: wall_ms as u64,
        logical: logical as u32,
        // node_id is not stored; it will be overwritten by new_seeded().
        node_id: [0u8; 8],
    }))
}

/// Upsert the HLC checkpoint row.
///
/// Best-effort: errors are logged but not propagated to the caller.
pub async fn save_hlc_checkpoint(
    pool: &AnyPool,
    ts: HlcTimestamp,
    now_ms: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO hlc_checkpoint (id, wall_ms, logical, saved_at) \
         VALUES (1, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET \
           wall_ms  = excluded.wall_ms, \
           logical  = excluded.logical, \
           saved_at = excluded.saved_at",
    )
    .bind(ts.wall_ms as i64)
    .bind(ts.logical as i64)
    .bind(now_ms as i64)
    .execute(pool)
    .await?;
    Ok(())
}
