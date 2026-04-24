//! GC executor: runs GC on a set of candidates and writes audit records.

use cid::Cid;
use sqlx::SqlitePool;
use stoa_core::error::StorageError;

use crate::retention::audit_log::{append_audit_record, ensure_audit_table, GcAuditRecord};
use crate::retention::pin_client::PinClient;

/// A GC candidate with full metadata needed for the audit record.
#[derive(Debug, Clone)]
pub struct GcExecutorCandidate {
    pub cid: Cid,
    pub group_name: String,
    pub ingested_at_ms: u64,
    pub gc_reason: String,
}

/// GC executor result.
#[derive(Debug, Default)]
pub struct GcExecutorResult {
    pub unpinned: usize,
    pub failed: usize,
}

/// Run GC: unpin each candidate and write an audit record.
///
/// Audit records are written AFTER successful unpin. Failed unpins are counted
/// but do not abort the run.
pub async fn run_gc_executor<P: PinClient>(
    candidates: &[GcExecutorCandidate],
    pin_client: &P,
    pool: &SqlitePool,
    now_ms: u64,
) -> Result<GcExecutorResult, StorageError> {
    ensure_audit_table(pool).await?;
    let mut result = GcExecutorResult::default();
    for candidate in candidates {
        match pin_client.unpin(&candidate.cid).await {
            Ok(()) => {
                let record = GcAuditRecord {
                    cid: candidate.cid.to_string(),
                    group_name: candidate.group_name.clone(),
                    ingested_at_ms: candidate.ingested_at_ms,
                    gc_at_ms: now_ms,
                    reason: candidate.gc_reason.clone(),
                };
                if let Err(e) = append_audit_record(pool, &record).await {
                    tracing::warn!(cid = %candidate.cid, "failed to write GC audit record: {e}");
                }
                result.unpinned += 1;
            }
            Err(e) => {
                tracing::warn!(cid = %candidate.cid, "GC unpin failed: {e}");
                result.failed += 1;
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
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::sync::atomic::AtomicUsize;

    static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn make_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    async fn make_pool() -> sqlx::SqlitePool {
        let n = DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let url = format!("file:gc_exec_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::new()
            .filename(&url)
            .create_if_missing(true);
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn gc_executor_unpins_and_writes_audit_records() {
        let pool = make_pool().await;
        let pin_client = MemPinClient::new();
        let now_ms = 1_700_000_000_000u64;

        let candidates: Vec<GcExecutorCandidate> = (0..10u8)
            .map(|i| {
                let cid = make_cid(&[i]);
                GcExecutorCandidate {
                    cid: cid.clone(),
                    group_name: "comp.lang.rust".to_string(),
                    ingested_at_ms: now_ms - 86_400_000,
                    gc_reason: "no_matching_rule".to_string(),
                }
            })
            .collect();

        // Pin all candidates first
        for c in &candidates {
            pin_client.pin(&c.cid).await.unwrap();
        }

        let result = run_gc_executor(&candidates, &pin_client, &pool, now_ms)
            .await
            .unwrap();
        assert_eq!(result.unpinned, 10);
        assert_eq!(result.failed, 0);

        let audit_count = count_audit_records(&pool).await.unwrap();
        assert_eq!(audit_count, 10, "should have 10 audit records");
    }

    #[tokio::test]
    async fn gc_executor_failed_unpin_not_audited() {
        let pool = make_pool().await;
        let pin_client = MemPinClient::new();
        // Force error on all operations
        *pin_client.force_error.write().unwrap() = Some("injected".to_string());

        let cid = make_cid(b"test");
        let candidates = vec![GcExecutorCandidate {
            cid,
            group_name: "alt.test".to_string(),
            ingested_at_ms: 0,
            gc_reason: "no_matching_rule".to_string(),
        }];

        let result = run_gc_executor(&candidates, &pin_client, &pool, 0)
            .await
            .unwrap();
        assert_eq!(result.failed, 1);
        assert_eq!(result.unpinned, 0);

        let audit_count = count_audit_records(&pool).await.unwrap();
        assert_eq!(audit_count, 0, "failed unpins should not be audited");
    }

    #[tokio::test]
    async fn gc_executor_empty_candidates_returns_zero() {
        let pool = make_pool().await;
        let pin_client = MemPinClient::new();
        let result = run_gc_executor(&[], &pin_client, &pool, 0).await.unwrap();
        assert_eq!(result.unpinned, 0);
        assert_eq!(result.failed, 0);
    }
}
