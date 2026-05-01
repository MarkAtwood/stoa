//! GC executor: runs GC on a set of candidates and writes audit records.

use cid::Cid;
use sqlx::AnyPool;
use stoa_core::error::StorageError;
use stoa_core::msgid_map::MsgIdMap;

use crate::retention::audit_log::{append_audit_record, GcAuditRecord};
use crate::retention::pin_client::PinClient;

/// The reason an article was selected for GC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcReason {
    /// No retention policy rule matched the article; it falls outside all pin windows.
    NoMatchingRule,
}

impl std::fmt::Display for GcReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcReason::NoMatchingRule => f.write_str("no_matching_rule"),
        }
    }
}

/// A GC candidate with full metadata needed for the audit record.
#[derive(Debug, Clone)]
pub struct GcExecutorCandidate {
    pub cid: Cid,
    pub group_name: String,
    pub ingested_at_ms: u64,
    pub byte_count: usize,
    pub gc_reason: GcReason,
}

/// A failed-unpin record from a GC executor run.
#[derive(Debug)]
pub struct GcExecutorError {
    pub cid: String,
    pub reason: String,
}

/// GC executor result.
#[derive(Debug, Default)]
pub struct GcExecutorResult {
    pub unpinned: usize,
    pub failed: usize,
    pub bytes_reclaimed: u64,
    pub errors: Vec<GcExecutorError>,
}

/// Run GC: unpin each candidate, delete its DB records, and write an audit
/// record.
///
/// After a successful unpin the CID is removed from:
/// - `articles` (transit pool): prevents the same CID from being selected as
///   a GC candidate on every subsequent run.
/// - `msgid_map` (core pool): allows the same Message-ID to be re-ingested
///   from another peer after the content has been pruned.
///
/// `transit_pool` and `core_pool` may be `None` in unit-test contexts where no
/// database is available; in that case the DB cleanup steps are skipped.
///
/// Deletion failures are logged as warnings but do not abort the GC run.
/// Failed unpins are counted but also do not abort the run.
pub async fn run_gc_executor<P: PinClient>(
    candidates: &[GcExecutorCandidate],
    pin_client: &P,
    transit_pool: Option<&AnyPool>,
    core_pool: Option<&AnyPool>,
    now_ms: u64,
) -> Result<GcExecutorResult, StorageError> {
    let msgid_map = core_pool.map(|p| MsgIdMap::new(p.clone()));
    let mut result = GcExecutorResult::default();
    for candidate in candidates {
        match pin_client.unpin(&candidate.cid).await {
            Ok(()) => {
                let cid_str = candidate.cid.to_string();
                if let Some(tp) = transit_pool {
                    // Remove from the articles table so the CID is no longer
                    // offered as a GC candidate on the next run.
                    if let Err(e) = sqlx::query("DELETE FROM articles WHERE cid = ?")
                        .bind(&cid_str)
                        .execute(tp)
                        .await
                    {
                        tracing::warn!(cid = %candidate.cid, "GC: failed to delete articles row: {e}");
                    }

                    // Remove from msgid_map so the message-id can be re-ingested.
                    if let Some(ref mm) = msgid_map {
                        if let Err(e) = mm.delete_by_cid(&candidate.cid).await {
                            tracing::warn!(cid = %candidate.cid, "GC: failed to delete msgid_map row: {e}");
                        }
                    }

                    let record = GcAuditRecord {
                        cid: cid_str,
                        group_name: candidate.group_name.clone(),
                        ingested_at_ms: candidate.ingested_at_ms,
                        gc_at_ms: now_ms,
                        reason: candidate.gc_reason.to_string(),
                    };
                    if let Err(e) = append_audit_record(tp, &record).await {
                        tracing::warn!(cid = %candidate.cid, "GC: failed to write audit record: {e}");
                    }
                }
                result.unpinned += 1;
                result.bytes_reclaimed += candidate.byte_count as u64;
            }
            Err(e) => {
                tracing::warn!(cid = %candidate.cid, "GC unpin failed: {e}");
                result.failed += 1;
                result.errors.push(GcExecutorError {
                    cid: candidate.cid.to_string(),
                    reason: e.to_string(),
                });
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::audit_log::count_audit_records;
    use crate::retention::pin_client::MemPinClient;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    fn make_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    async fn make_transit_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    async fn make_core_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    #[tokio::test]
    async fn gc_executor_unpins_and_writes_audit_records() {
        let (transit_pool, _tmp1) = make_transit_pool().await;
        let (core_pool, _tmp2) = make_core_pool().await;
        let pin_client = MemPinClient::new();
        let now_ms = 1_700_000_000_000u64;

        let candidates: Vec<GcExecutorCandidate> = (0..10u8)
            .map(|i| {
                let cid = make_cid(&[i]);
                GcExecutorCandidate {
                    cid: cid.clone(),
                    group_name: "comp.lang.rust".to_string(),
                    ingested_at_ms: now_ms - 86_400_000,
                    byte_count: 1024,
                    gc_reason: GcReason::NoMatchingRule,
                }
            })
            .collect();

        // Insert into articles table and pin all candidates.
        for c in &candidates {
            let cid_str = c.cid.to_string();
            sqlx::query(
                "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(&cid_str)
            .bind(&c.group_name)
            .bind(c.ingested_at_ms as i64)
            .bind(1024i64)
            .execute(&transit_pool)
            .await
            .unwrap();
            pin_client.pin(&c.cid).await.unwrap();
        }

        let result = run_gc_executor(
            &candidates,
            &pin_client,
            Some(&transit_pool),
            Some(&core_pool),
            now_ms,
        )
        .await
        .unwrap();
        assert_eq!(result.unpinned, 10);
        assert_eq!(result.failed, 0);
        assert_eq!(result.bytes_reclaimed, 10 * 1024);

        let audit_count = count_audit_records(&transit_pool).await.unwrap();
        assert_eq!(audit_count, 10, "should have 10 audit records");

        // All articles rows must be gone after GC.
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM articles")
            .fetch_one(&transit_pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "articles table must be empty after GC");
    }

    #[tokio::test]
    async fn gc_executor_failed_unpin_not_audited() {
        let (transit_pool, _tmp1) = make_transit_pool().await;
        let (core_pool, _tmp2) = make_core_pool().await;
        let pin_client = MemPinClient::new();
        // Force error on all operations
        *pin_client.force_error.write().unwrap() = Some("injected".to_string());

        let cid = make_cid(b"test");
        let candidates = vec![GcExecutorCandidate {
            cid,
            group_name: "alt.test".to_string(),
            ingested_at_ms: 0,
            byte_count: 512,
            gc_reason: GcReason::NoMatchingRule,
        }];

        let result = run_gc_executor(
            &candidates,
            &pin_client,
            Some(&transit_pool),
            Some(&core_pool),
            0,
        )
        .await
        .unwrap();
        assert_eq!(result.failed, 1);
        assert_eq!(result.unpinned, 0);
        assert_eq!(result.errors.len(), 1);

        let audit_count = count_audit_records(&transit_pool).await.unwrap();
        assert_eq!(audit_count, 0, "failed unpins should not be audited");
    }

    #[tokio::test]
    async fn gc_executor_empty_candidates_returns_zero() {
        let (transit_pool, _tmp1) = make_transit_pool().await;
        let (core_pool, _tmp2) = make_core_pool().await;
        let pin_client = MemPinClient::new();
        let result = run_gc_executor(&[], &pin_client, Some(&transit_pool), Some(&core_pool), 0)
            .await
            .unwrap();
        assert_eq!(result.unpinned, 0);
        assert_eq!(result.failed, 0);
    }
}
