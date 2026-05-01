//! GC scheduler and unpin executor.
//!
//! `GcRunner::run_once` iterates a list of `GcCandidate` articles,
//! evaluates each against the `PolicyEngine`, and unpins those that
//! don't pass. The `start_gc_scheduler` function runs `run_once` on
//! a `tokio::time::interval`.
//!
//! When `gc_lock` is `Some(pool)` (PostgreSQL deployments), each scheduled
//! run is guarded by `pg_try_advisory_lock(GC_ADVISORY_LOCK_ID)`.  If the
//! lock cannot be acquired another instance is already running GC, so the
//! current run is skipped.  The lock is released immediately after the run
//! completes.

use cid::Cid;
use sqlx::AnyPool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::retention::audit_log::{append_audit_record, GcAuditRecord};
use crate::retention::gc_candidates::GcArticleRecord;
use crate::retention::pin_client::PinClient;
use crate::retention::policy::{ArticleMeta, PinPolicy};

/// PostgreSQL session-level advisory lock ID reserved for the GC scheduler.
///
/// Chosen to be memorable and unlikely to collide with application locks:
/// derived from the epic ID (ky62) and purpose (GC = 1).
pub const GC_ADVISORY_LOCK_ID: i64 = 6_200_000_001;

/// Try to acquire a PostgreSQL session-level advisory lock.
///
/// Returns `true` if the lock was acquired (or if `pool` is `None`, i.e.
/// this is a SQLite deployment where locking is not needed).
/// Returns `false` if another session already holds the lock.
async fn try_gc_lock(pool: Option<&AnyPool>) -> bool {
    let pool = match pool {
        Some(p) => p,
        None => return true,
    };
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock(?)")
        .bind(GC_ADVISORY_LOCK_ID)
        .fetch_one(pool)
        .await
        .unwrap_or(false)
}

/// Release the PostgreSQL advisory lock acquired by `try_gc_lock`.
///
/// No-op when `pool` is `None`.
async fn release_gc_lock(pool: Option<&AnyPool>) {
    let pool = match pool {
        Some(p) => p,
        None => return,
    };
    let _ = sqlx::query("SELECT pg_advisory_unlock(?)")
        .bind(GC_ADVISORY_LOCK_ID)
        .execute(pool)
        .await;
}

/// Metrics for the GC run.
#[derive(Debug, Default)]
pub struct GcMetrics {
    /// Total articles unpinned across all GC runs.
    pub gc_articles_unpinned_total: AtomicU64,
    /// Duration of the last GC run in milliseconds.
    pub last_run_duration_ms: AtomicU64,
}

impl GcMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

/// An article candidate for GC evaluation.
#[derive(Debug, Clone)]
pub struct GcCandidate {
    /// Content identifier.
    pub cid: Cid,
    /// Newsgroup the article belongs to.
    pub group: String,
    /// Unix timestamp in milliseconds when the article was ingested locally.
    /// Used (not the peer-supplied Date header) so the grace period protects
    /// newly-arrived articles regardless of their stated publication date.
    pub ingested_at_ms: u64,
    /// Article size in bytes.
    pub byte_count: usize,
}

impl From<GcArticleRecord> for GcCandidate {
    fn from(r: GcArticleRecord) -> Self {
        GcCandidate {
            cid: r.cid,
            group: r.group,
            ingested_at_ms: r.ingested_at_ms,
            byte_count: r.byte_count,
        }
    }
}

/// GC runner that evaluates candidates against the policy and unpins rejects.
pub struct GcRunner<P: PinClient> {
    pin_client: P,
    policy: PinPolicy,
    metrics: Arc<GcMetrics>,
    /// Directory for per-run JSON report files.  `None` disables file writing.
    report_dir: Option<String>,
    /// Last completed GC report.  Shared with the admin endpoint.
    last_report: Arc<tokio::sync::RwLock<Option<crate::retention::gc_report::GcReport>>>,
}

impl<P: PinClient> GcRunner<P> {
    pub fn new(pin_client: P, policy: PinPolicy, metrics: Arc<GcMetrics>) -> Self {
        Self {
            pin_client,
            policy,
            metrics,
            report_dir: None,
            last_report: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Configure the report directory and return `self` (builder pattern).
    pub fn with_report_dir(mut self, dir: Option<String>) -> Self {
        self.report_dir = dir;
        self
    }

    /// Return a clone of the shared last-report handle.
    ///
    /// Pass this to `AdminPools.last_gc_report` so `GET /admin/gc/last-run`
    /// can return the most recent report without reading a file.
    pub fn last_report_handle(
        &self,
    ) -> Arc<tokio::sync::RwLock<Option<crate::retention::gc_report::GcReport>>> {
        Arc::clone(&self.last_report)
    }

    /// Run one GC pass over `candidates`.
    ///
    /// For each candidate, evaluates `PolicyEngine::should_pin`. If the
    /// article should NOT be pinned, calls `unpin()`. On a successful unpin
    /// the row is deleted from the `articles` table (when `transit_pool` is
    /// `Some`) so the CID is not re-selected as a GC candidate on the next
    /// run. Errors from `unpin()` or the DELETE are logged as warnings and do
    /// not abort the GC run.
    ///
    /// **Caller responsibility (zmn9.38):** the advisory lock must be held for
    /// the entire duration of this call — including the articles-table cleanup
    /// — and released only after this method returns.
    ///
    /// After the pass, builds a [`GcReport`], stores it as the last-run report,
    /// optionally writes it to the configured report directory, and emits a
    /// structured INFO log event (`event=gc_complete`).
    ///
    /// Returns the count of articles unpinned in this run.
    ///
    /// [`GcReport`]: crate::retention::gc_report::GcReport
    pub async fn run_once(
        &self,
        candidates: &[GcCandidate],
        now_ms: u64,
        transit_pool: Option<&AnyPool>,
    ) -> u64 {
        use crate::retention::gc_report::{ms_to_datetime, new_run_id, GcReport, GcReportError};

        let started_at = ms_to_datetime(now_ms);
        let run_id = new_run_id();
        let start = std::time::Instant::now();
        let ms_per_day = 24u64 * 60 * 60 * 1000;
        let mut unpinned = 0u64;
        let mut bytes_reclaimed = 0u64;
        let mut errors: Vec<GcReportError> = Vec::new();

        // Count distinct groups in the candidate set.
        let groups_scanned = {
            let mut seen = std::collections::HashSet::new();
            for c in candidates {
                seen.insert(c.group.as_str());
            }
            seen.len()
        };

        for candidate in candidates {
            let age_days = now_ms
                .saturating_sub(candidate.ingested_at_ms)
                .checked_div(ms_per_day)
                .unwrap_or(0);
            let meta = ArticleMeta {
                group: candidate.group.clone(),
                size_bytes: candidate.byte_count,
                age_days,
            };
            if !self.policy.should_pin(&meta) {
                match self.pin_client.unpin(&candidate.cid).await {
                    Ok(()) => {
                        tracing::info!(
                            cid = %candidate.cid,
                            group = %candidate.group,
                            "GC: unpinned article"
                        );
                        unpinned += 1;
                        bytes_reclaimed += candidate.byte_count as u64;

                        // Delete the articles row so this CID is not
                        // re-selected as a GC candidate on the next run
                        // (zmn9.31). This runs inside the advisory-lock
                        // window (zmn9.38).
                        if let Some(pool) = transit_pool {
                            let cid_str = candidate.cid.to_string();
                            if let Err(e) =
                                sqlx::query("DELETE FROM articles WHERE cid = ?")
                                    .bind(&cid_str)
                                    .execute(pool)
                                    .await
                            {
                                tracing::warn!(
                                    cid = %candidate.cid,
                                    "GC: failed to delete articles row: {e}"
                                );
                            }
                            let record = GcAuditRecord {
                                cid: cid_str,
                                group_name: candidate.group.clone(),
                                ingested_at_ms: candidate.ingested_at_ms,
                                gc_at_ms: now_ms,
                                reason: "no_matching_rule".to_string(),
                            };
                            if let Err(e) = append_audit_record(pool, &record).await {
                                tracing::warn!(
                                    cid = %candidate.cid,
                                    "GC: failed to write audit record: {e}"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            cid = %candidate.cid,
                            "GC: unpin failed: {e}"
                        );
                        errors.push(GcReportError {
                            cid: candidate.cid.to_string(),
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;
        let completed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let completed_at = ms_to_datetime(completed_at_ms);

        self.metrics
            .gc_articles_unpinned_total
            .fetch_add(unpinned, Ordering::Relaxed);
        self.metrics
            .last_run_duration_ms
            .store(elapsed_ms, Ordering::Relaxed);

        // Update global Prometheus counters.
        crate::metrics::GC_RUNS_TOTAL.inc();
        crate::metrics::GC_ARTICLES_DELETED_TOTAL.inc_by(unpinned);
        crate::metrics::GC_BYTES_RECLAIMED_TOTAL.inc_by(bytes_reclaimed);

        let policy_desc = format!("{} pin rule(s)", self.policy.rule_count());
        let report = GcReport {
            run_id,
            started_at,
            completed_at,
            policy: policy_desc,
            groups_scanned,
            articles_evaluated: candidates.len(),
            articles_deleted: unpinned as usize,
            bytes_reclaimed,
            errors,
        };

        tracing::info!(
            event = "gc_complete",
            run_id = %report.run_id,
            groups_scanned,
            articles_evaluated = candidates.len(),
            articles_deleted = unpinned,
            bytes_reclaimed,
            elapsed_ms,
            "GC run complete"
        );

        // Write report to file (if configured).
        if let Some(ref dir) = self.report_dir {
            report.write_to_dir(dir).await;
        }

        // Update in-memory last-run report.
        *self.last_report.write().await = Some(report);

        unpinned
    }

    /// Format Prometheus metrics text.
    pub fn prometheus_text(&self) -> String {
        let total = self
            .metrics
            .gc_articles_unpinned_total
            .load(Ordering::Relaxed);
        let dur = self.metrics.last_run_duration_ms.load(Ordering::Relaxed);
        format!(
            "# HELP gc_articles_unpinned_total Total articles unpinned by GC\n\
             # TYPE gc_articles_unpinned_total counter\n\
             gc_articles_unpinned_total {total}\n\
             # HELP gc_last_run_duration_ms Duration of the last GC run\n\
             # TYPE gc_last_run_duration_ms gauge\n\
             gc_last_run_duration_ms {dur}\n"
        )
    }
}

/// Start a background GC task that runs every `interval`.
///
/// The `candidates_fn` closure is called before each GC run to fetch
/// the current list of candidates. This decouples the GC scheduler from
/// the storage backend.
///
/// `gc_lock`: when `Some(pool)` (PostgreSQL deployments), each run is
/// guarded by a `pg_try_advisory_lock`.  If the lock is held by another
/// instance the run is skipped with a debug log.  For SQLite pass `None`.
///
/// `transit_pool`: when `Some`, the articles-table row for each unpinned
/// CID is deleted inside the advisory-lock window (fixes zmn9.31 and zmn9.38).
pub async fn start_gc_scheduler<P, F, Fut>(
    runner: GcRunner<P>,
    interval: Duration,
    candidates_fn: F,
    gc_lock: Option<AnyPool>,
    transit_pool: Option<AnyPool>,
) where
    P: PinClient + 'static,
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Vec<GcCandidate>> + Send,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip the immediate first tick
        loop {
            ticker.tick().await;

            if !try_gc_lock(gc_lock.as_ref()).await {
                tracing::debug!("GC: advisory lock held by another instance, skipping this run");
                continue;
            }

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let candidates = candidates_fn().await;

            // The advisory lock is held for the entire run_once call,
            // including the articles-table cleanup inside it (zmn9.38).
            runner
                .run_once(&candidates, now_ms, transit_pool.as_ref())
                .await;

            // Only release the lock after all cleanup is complete (zmn9.38).
            release_gc_lock(gc_lock.as_ref()).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::pin_client::MemPinClient;
    use crate::retention::policy::{PinAction, PinPolicy, PinRule};
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    fn make_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    const NOW_MS: u64 = 1_700_000_000_000u64;

    fn make_candidate(n: u8, group: &str, age_days: u64) -> GcCandidate {
        let age_ms = age_days * 24 * 60 * 60 * 1000;
        GcCandidate {
            cid: make_cid(&[n]),
            group: group.to_string(),
            ingested_at_ms: NOW_MS.saturating_sub(age_ms),
            byte_count: 1024,
        }
    }

    fn pin_sci_math() -> PinPolicy {
        PinPolicy::new(vec![PinRule {
            groups: "sci.math".to_string(),
            max_age_days: None,
            max_article_bytes: None,
            action: PinAction::Pin,
        }])
    }

    fn pin_all() -> PinPolicy {
        PinPolicy::new(vec![PinRule {
            groups: "all".to_string(),
            max_age_days: None,
            max_article_bytes: None,
            action: PinAction::Pin,
        }])
    }

    #[tokio::test]
    async fn gc_unpins_articles_not_in_policy() {
        let pin_client = MemPinClient::new();
        let candidates: Vec<GcCandidate> = (0..5)
            .map(|i| make_candidate(i, "comp.lang.rust", 0))
            .collect();
        for c in &candidates {
            pin_client.pin(&c.cid).await.unwrap();
        }

        // Policy: only pin sci.math. All 5 are comp.lang.rust → all unpinned.
        let metrics = GcMetrics::new();
        let runner = GcRunner::new(pin_client, pin_sci_math(), metrics.clone());
        let unpinned = runner.run_once(&candidates, NOW_MS, None).await;

        assert_eq!(unpinned, 5, "all 5 should be unpinned");
        assert_eq!(
            metrics.gc_articles_unpinned_total.load(Ordering::Relaxed),
            5
        );
    }

    #[tokio::test]
    async fn gc_preserves_pinned_articles() {
        let pin_client = MemPinClient::new();
        let candidates = vec![
            make_candidate(0, "sci.math", 0),
            make_candidate(1, "sci.math", 0),
            make_candidate(2, "comp.lang.rust", 0),
            make_candidate(3, "comp.lang.rust", 0),
            make_candidate(4, "comp.lang.rust", 0),
        ];
        for c in &candidates {
            pin_client.pin(&c.cid).await.unwrap();
        }

        let metrics = GcMetrics::new();
        let runner = GcRunner::new(pin_client, pin_sci_math(), metrics.clone());
        let unpinned = runner.run_once(&candidates, NOW_MS, None).await;

        assert_eq!(
            unpinned, 3,
            "only 3 comp.lang.rust articles should be unpinned"
        );
    }

    #[tokio::test]
    async fn gc_pin_all_skips_all_unpin() {
        let pin_client = MemPinClient::new();
        let candidates: Vec<GcCandidate> = (0..5)
            .map(|i| make_candidate(i, "comp.lang.rust", 0))
            .collect();
        for c in &candidates {
            pin_client.pin(&c.cid).await.unwrap();
        }

        let metrics = GcMetrics::new();
        let runner = GcRunner::new(pin_client, pin_all(), metrics.clone());
        let unpinned = runner.run_once(&candidates, NOW_MS, None).await;

        assert_eq!(unpinned, 0, "pin all means nothing is unpinned");
    }

    #[test]
    fn prometheus_text_contains_metric_names() {
        let metrics = GcMetrics::new();
        let runner = GcRunner::new(MemPinClient::new(), PinPolicy::new(vec![]), metrics);
        let text = runner.prometheus_text();
        assert!(text.contains("gc_articles_unpinned_total"));
        assert!(text.contains("gc_last_run_duration_ms"));
    }

    // ── Retention reporting tests (usenet-ipfs-dlug) ──────────────────────────

    /// After a GC run that deletes articles, `last_report_handle` holds a report
    /// with `articles_deleted` equal to the unpin count.
    #[tokio::test]
    async fn gc_last_report_populated_after_delete_run() {
        let pin_client = MemPinClient::new();
        let candidates: Vec<GcCandidate> = (0..3)
            .map(|i| make_candidate(i, "comp.lang.rust", 60))
            .collect();
        for c in &candidates {
            pin_client.pin(&c.cid).await.unwrap();
        }

        let metrics = GcMetrics::new();
        // Policy: pin sci.math only → all comp.lang.rust articles unpinned.
        let runner = GcRunner::new(pin_client, pin_sci_math(), metrics);
        let handle = runner.last_report_handle();

        assert!(
            handle.read().await.is_none(),
            "report must be None before first run"
        );

        runner.run_once(&candidates, NOW_MS, None).await;

        let report = handle.read().await;
        let report = report.as_ref().expect("report must be Some after run");
        assert_eq!(report.articles_deleted, 3, "must record 3 deletions");
        assert_eq!(report.articles_evaluated, 3);
        assert!(!report.run_id.is_empty(), "run_id must be populated");
        assert_eq!(
            report.started_at.timezone(),
            chrono::Utc,
            "started_at must be UTC"
        );
    }

    /// A GC run that deletes nothing still writes a report with `articles_deleted=0`.
    #[tokio::test]
    async fn gc_last_report_written_when_nothing_deleted() {
        let pin_client = MemPinClient::new();
        let candidates: Vec<GcCandidate> =
            (0..2).map(|i| make_candidate(i, "sci.math", 0)).collect();
        for c in &candidates {
            pin_client.pin(&c.cid).await.unwrap();
        }

        let metrics = GcMetrics::new();
        // Policy pins sci.math → nothing deleted.
        let runner = GcRunner::new(pin_client, pin_sci_math(), metrics);
        let handle = runner.last_report_handle();

        runner.run_once(&candidates, NOW_MS, None).await;

        let report = handle.read().await;
        let report = report
            .as_ref()
            .expect("report must be Some even with zero deletions");
        assert_eq!(
            report.articles_deleted, 0,
            "zero-delete run must record articles_deleted=0"
        );
        assert_eq!(report.articles_evaluated, 2);
        assert!(report.errors.is_empty(), "no errors expected");
    }

    /// `with_report_dir` causes a JSON file to be written to the configured directory.
    #[tokio::test]
    async fn gc_run_writes_report_file_to_dir() {
        let pin_client = MemPinClient::new();
        let candidates: Vec<GcCandidate> = vec![make_candidate(0, "comp.lang.rust", 60)];
        pin_client.pin(&candidates[0].cid).await.unwrap();

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let dir = tmp.path().to_str().unwrap().to_string();

        let metrics = GcMetrics::new();
        let runner =
            GcRunner::new(pin_client, pin_sci_math(), metrics).with_report_dir(Some(dir.clone()));

        runner.run_once(&candidates, NOW_MS, None).await;

        let mut entries = tokio::fs::read_dir(&dir).await.expect("readdir");
        let entry = entries
            .next_entry()
            .await
            .expect("ok")
            .expect("report file must exist");
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            name.ends_with(".json"),
            "report file must have .json extension: {name}"
        );
        let content = tokio::fs::read_to_string(entry.path())
            .await
            .expect("read report file");
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(
            v["articles_deleted"], 1,
            "report must record 1 deletion: {content}"
        );
    }
}
