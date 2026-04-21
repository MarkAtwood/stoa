//! GC scheduler and unpin executor.
//!
//! `GcRunner::run_once` iterates a list of `GcCandidate` articles,
//! evaluates each against the `PolicyEngine`, and unpins those that
//! don't pass. The `start_gc_scheduler` function runs `run_once` on
//! a `tokio::time::interval`.

use cid::Cid;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::retention::pin_client::PinClient;
use crate::retention::policy::{ArticleMeta, PinPolicy};

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
    /// Unix timestamp in milliseconds from the article's Date header.
    pub date_ms: u64,
    /// Article size in bytes.
    pub byte_count: usize,
}

/// GC runner that evaluates candidates against the policy and unpins rejects.
pub struct GcRunner<P: PinClient> {
    pin_client: P,
    policy: PinPolicy,
    metrics: Arc<GcMetrics>,
}

impl<P: PinClient> GcRunner<P> {
    pub fn new(pin_client: P, policy: PinPolicy, metrics: Arc<GcMetrics>) -> Self {
        Self {
            pin_client,
            policy,
            metrics,
        }
    }

    /// Run one GC pass over `candidates`.
    ///
    /// For each candidate, evaluates `PolicyEngine::should_pin`. If the
    /// article should NOT be pinned, calls `unpin()`. Errors from `unpin()`
    /// are logged as warnings and do not abort the GC run.
    ///
    /// Returns the count of articles unpinned in this run.
    pub async fn run_once(&self, candidates: &[GcCandidate], now_ms: u64) -> u64 {
        let start = std::time::Instant::now();
        let ms_per_day = 24u64 * 60 * 60 * 1000;
        let mut unpinned = 0u64;

        for candidate in candidates {
            let age_days = now_ms
                .saturating_sub(candidate.date_ms)
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
                    }
                    Err(e) => {
                        tracing::warn!(
                            cid = %candidate.cid,
                            "GC: unpin failed: {e}"
                        );
                    }
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;
        self.metrics
            .gc_articles_unpinned_total
            .fetch_add(unpinned, Ordering::Relaxed);
        self.metrics
            .last_run_duration_ms
            .store(elapsed_ms, Ordering::Relaxed);

        tracing::info!(unpinned, elapsed_ms, "GC run complete");
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
pub async fn start_gc_scheduler<P, F, Fut>(
    runner: GcRunner<P>,
    interval: Duration,
    candidates_fn: F,
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
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let candidates = candidates_fn().await;
            runner.run_once(&candidates, now_ms).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::pin_client::MemPinClient;
    use crate::retention::policy::{PinPolicy, PinRule};
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
            date_ms: NOW_MS.saturating_sub(age_ms),
            byte_count: 1024,
        }
    }

    fn pin_sci_math() -> PinPolicy {
        PinPolicy::new(vec![PinRule {
            groups: "sci.math".to_string(),
            max_age_days: None,
            max_article_bytes: None,
            action: "pin".to_string(),
        }])
    }

    fn pin_all() -> PinPolicy {
        PinPolicy::new(vec![PinRule {
            groups: "all".to_string(),
            max_age_days: None,
            max_article_bytes: None,
            action: "pin".to_string(),
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
        let unpinned = runner.run_once(&candidates, NOW_MS).await;

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
        let unpinned = runner.run_once(&candidates, NOW_MS).await;

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
        let unpinned = runner.run_once(&candidates, NOW_MS).await;

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
}
