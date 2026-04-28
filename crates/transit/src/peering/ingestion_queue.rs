//! Bounded ingestion queue with back-pressure signaling.
//!
//! Articles from peering connections are buffered here before the
//! store-and-forward pipeline processes them. When the queue is full
//! (by article count or total byte size), new articles receive a 436
//! response (RFC 4644 "Transfer not possible; try again later").
//! The drain threshold (80%) prevents oscillation.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// An article pending ingestion.
#[derive(Debug)]
pub struct QueuedArticle {
    /// The raw article bytes (headers + body).
    pub bytes: Vec<u8>,
    /// The validated Message-ID.
    pub message_id: String,
}

/// Prometheus-style queue metrics (in-process; no external dependency).
pub struct QueueMetrics {
    /// Current queue depth (article count).
    pub depth_current: AtomicUsize,
    /// Maximum article count before backpressure is applied.
    pub depth_max: usize,
    /// Current total bytes of article data waiting in the queue.
    pub bytes_current: AtomicU64,
    /// Maximum total bytes before backpressure is applied.
    pub bytes_max: u64,
    /// Total articles accepted into the queue.
    pub accepted_total: AtomicU64,
    /// Total articles rejected due to queue full (depth or bytes limit).
    pub rejected_full_total: AtomicU64,
}

impl QueueMetrics {
    fn new(max_depth: usize, max_bytes: u64) -> Self {
        Self {
            depth_current: AtomicUsize::new(0),
            depth_max: max_depth,
            bytes_current: AtomicU64::new(0),
            bytes_max: max_bytes,
            accepted_total: AtomicU64::new(0),
            rejected_full_total: AtomicU64::new(0),
        }
    }

    pub fn current_depth(&self) -> usize {
        self.depth_current.load(Ordering::Relaxed)
    }

    pub fn is_full(&self) -> bool {
        self.current_depth() >= self.depth_max
    }

    /// True if adding `article_bytes` more bytes would exceed the bytes high-water mark.
    pub fn is_bytes_overloaded(&self, article_bytes: usize) -> bool {
        self.bytes_current.load(Ordering::Relaxed) + article_bytes as u64 > self.bytes_max
    }

    /// True if queue has drained below the 80% threshold after being full.
    pub fn below_drain_threshold(&self) -> bool {
        self.current_depth() * 10 < self.depth_max * 8
    }
}

/// Sender half of the ingestion queue.
pub struct IngestionSender {
    tx: mpsc::Sender<QueuedArticle>,
    metrics: Arc<QueueMetrics>,
}

impl IngestionSender {
    /// Try to enqueue an article.
    ///
    /// Uses `try_send` so the capacity check and the enqueue are atomic with
    /// respect to the channel — no TOCTOU between a separate `is_full()` read
    /// and the actual send.
    ///
    /// # DECISION (rbe3.34): try_send is mandatory; is_full()+send() is incorrect
    ///
    /// Two concurrent TAKETHIS handlers that both observe `is_full() == false`
    /// would both call `send().await`, pushing depth beyond the configured
    /// limit.  `try_send` is atomic at the channel level: the capacity check
    /// and the enqueue happen together.  Do NOT replace with `is_full()+send()`.
    ///
    /// Returns `Ok(())` if accepted, `Err("436 ...")` if either high-water mark is exceeded.
    pub async fn try_enqueue(&self, article: QueuedArticle) -> Result<(), &'static str> {
        let article_bytes = article.bytes.len();
        // Bytes high-water mark check (soft limit; checked before channel try_send).
        if self.metrics.is_bytes_overloaded(article_bytes) {
            self.metrics
                .rejected_full_total
                .fetch_add(1, Ordering::Relaxed);
            crate::metrics::INGEST_BACKPRESSURE_TOTAL.inc();
            return Err("436 Transfer not possible; try again later\r\n");
        }
        match self.tx.try_send(article) {
            Ok(()) => {
                self.metrics.depth_current.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_current
                    .fetch_add(article_bytes as u64, Ordering::Relaxed);
                self.metrics.accepted_total.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics
                    .rejected_full_total
                    .fetch_add(1, Ordering::Relaxed);
                crate::metrics::INGEST_BACKPRESSURE_TOTAL.inc();
                Err("436 Transfer not possible; try again later\r\n")
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Receiver dropped — queue is shutting down.
                Err("431 Ingestion queue unavailable\r\n")
            }
        }
    }

    /// Snapshot: current queue depth.
    pub fn depth(&self) -> usize {
        self.metrics.current_depth()
    }

    /// Snapshot: max queue depth.
    pub fn max_depth(&self) -> usize {
        self.metrics.depth_max
    }

    /// Snapshot: queue is below the 80% drain threshold.
    pub fn below_drain_threshold(&self) -> bool {
        self.metrics.below_drain_threshold()
    }

    /// Read-only reference to metrics.
    pub fn metrics(&self) -> &QueueMetrics {
        &self.metrics
    }

    /// Clone the shared metrics `Arc` for external monitoring (e.g. drain timeout log).
    pub fn clone_metrics(&self) -> Arc<QueueMetrics> {
        Arc::clone(&self.metrics)
    }
}

/// Receiver half of the ingestion queue.
pub struct IngestionReceiver {
    rx: mpsc::Receiver<QueuedArticle>,
    metrics: Arc<QueueMetrics>,
}

impl IngestionReceiver {
    /// Receive the next article. Returns `None` if all senders have dropped.
    pub async fn recv(&mut self) -> Option<QueuedArticle> {
        let article = self.rx.recv().await?;
        self.metrics.depth_current.fetch_sub(1, Ordering::Relaxed);
        self.metrics
            .bytes_current
            .fetch_sub(article.bytes.len() as u64, Ordering::Relaxed);
        Some(article)
    }
}

/// Create an ingestion queue with the given depth limit and bytes limit.
///
/// `max_depth` — maximum article count before backpressure (436) is applied.
/// `max_bytes` — maximum total bytes before backpressure (436) is applied.
pub fn ingestion_queue(max_depth: usize, max_bytes: u64) -> (IngestionSender, IngestionReceiver) {
    let metrics = Arc::new(QueueMetrics::new(max_depth, max_bytes));
    let (tx, rx) = mpsc::channel(max_depth);
    let sender = IngestionSender {
        tx,
        metrics: Arc::clone(&metrics),
    };
    let receiver = IngestionReceiver { rx, metrics };
    (sender, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_article(n: u64) -> QueuedArticle {
        QueuedArticle {
            bytes: format!("Article {n}").into_bytes(),
            message_id: format!("<{n}@example.com>"),
        }
    }

    fn make_article_bytes(n: u64, size: usize) -> QueuedArticle {
        QueuedArticle {
            bytes: vec![b'X'; size],
            message_id: format!("<{n}@example.com>"),
        }
    }

    #[tokio::test]
    async fn queue_accepts_up_to_capacity() {
        let (sender, _rx) = ingestion_queue(3, u64::MAX);
        assert!(sender.try_enqueue(make_article(1)).await.is_ok());
        assert!(sender.try_enqueue(make_article(2)).await.is_ok());
        assert!(sender.try_enqueue(make_article(3)).await.is_ok());
        // 4th should fail with 436 (queue full).
        let result = sender.try_enqueue(make_article(4)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().starts_with("436"));
    }

    #[tokio::test]
    async fn queue_depth_tracked_on_enqueue() {
        let (sender, _rx) = ingestion_queue(10, u64::MAX);
        assert_eq!(sender.depth(), 0);
        sender.try_enqueue(make_article(1)).await.unwrap();
        assert_eq!(sender.depth(), 1);
        sender.try_enqueue(make_article(2)).await.unwrap();
        assert_eq!(sender.depth(), 2);
    }

    #[tokio::test]
    async fn queue_depth_decreases_on_recv() {
        let (sender, mut receiver) = ingestion_queue(10, u64::MAX);
        sender.try_enqueue(make_article(1)).await.unwrap();
        sender.try_enqueue(make_article(2)).await.unwrap();
        assert_eq!(sender.depth(), 2);

        receiver.recv().await.expect("should receive article 1");
        assert_eq!(sender.depth(), 1);

        receiver.recv().await.expect("should receive article 2");
        assert_eq!(sender.depth(), 0);
    }

    #[tokio::test]
    async fn rejected_articles_increment_counter() {
        let (sender, _rx) = ingestion_queue(1, u64::MAX);
        sender.try_enqueue(make_article(1)).await.unwrap(); // fills queue
        sender.try_enqueue(make_article(2)).await.unwrap_err(); // rejected
        sender.try_enqueue(make_article(3)).await.unwrap_err(); // rejected
        assert_eq!(
            sender.metrics().rejected_full_total.load(Ordering::Relaxed),
            2
        );
    }

    #[tokio::test]
    async fn drain_threshold_fires_at_80_percent() {
        let (sender, mut receiver) = ingestion_queue(10, u64::MAX);
        // Fill to 100%.
        for i in 1..=10 {
            sender.try_enqueue(make_article(i)).await.unwrap();
        }
        assert!(
            !sender.below_drain_threshold(),
            "full queue should not be below threshold"
        );
        // Drain to 70% (7 items).
        for _ in 0..3 {
            receiver.recv().await.unwrap();
        }
        // 7/10 = 70%, which is < 80%, so threshold should be cleared.
        assert!(
            sender.below_drain_threshold(),
            "70% fill should be below 80% drain threshold"
        );
    }

    #[tokio::test]
    async fn fill_queue_verify_436_drain_verify_resumption() {
        // Acceptance test: fill → 436 → drain → resume.
        let (sender, mut receiver) = ingestion_queue(5, u64::MAX);

        // Fill queue.
        for i in 1..=5 {
            assert!(sender.try_enqueue(make_article(i)).await.is_ok());
        }

        // Additional enqueues return 436.
        for i in 6..=10 {
            let result = sender.try_enqueue(make_article(i)).await;
            assert!(result.is_err(), "article {i} should be rejected");
            assert!(result.unwrap_err().contains("436"));
        }

        // Drain queue.
        for _ in 0..5 {
            assert!(receiver.recv().await.is_some());
        }

        // Queue is now empty; new enqueues should succeed again.
        assert!(sender.try_enqueue(make_article(100)).await.is_ok());
        assert_eq!(sender.depth(), 1);
    }

    /// Bytes high-water mark triggers 436 backpressure independently of depth.
    #[tokio::test]
    async fn bytes_limit_triggers_backpressure() {
        // Queue depth allows 100 articles but total bytes is capped at 50.
        let (sender, _rx) = ingestion_queue(100, 50);
        // First 5 articles of 10 bytes each fill 50 bytes exactly.
        for i in 1..=5 {
            assert!(
                sender.try_enqueue(make_article_bytes(i, 10)).await.is_ok(),
                "article {i} should be accepted"
            );
        }
        // Next article (10 bytes) would push bytes to 60 — exceeds limit.
        let result = sender.try_enqueue(make_article_bytes(6, 10)).await;
        assert!(
            result.is_err(),
            "should be rejected when bytes limit exceeded"
        );
        assert!(result.unwrap_err().contains("436"));
    }

    /// Bytes counter decrements on recv, allowing more articles after drain.
    #[tokio::test]
    async fn bytes_counter_decrements_on_recv() {
        let (sender, mut receiver) = ingestion_queue(100, 50);
        // Fill to byte limit.
        for i in 1..=5 {
            sender.try_enqueue(make_article_bytes(i, 10)).await.unwrap();
        }
        // Should be rejected now.
        assert!(sender.try_enqueue(make_article_bytes(6, 10)).await.is_err());
        // Drain one article (10 bytes).
        receiver.recv().await.unwrap();
        // Now there is room for one more.
        assert!(
            sender.try_enqueue(make_article_bytes(7, 10)).await.is_ok(),
            "should be accepted after draining one article"
        );
    }

    /// Regression test for stoa-76h: concurrent TAKETHIS flood must never
    /// exceed queue capacity or deadlock.
    ///
    /// Before the TOCTOU fix (is_full() + tx.send().await), two racing tasks could
    /// both observe depth < capacity and both proceed, pushing depth past capacity.
    /// `try_send` is atomic at the channel level, so this cannot happen.
    #[tokio::test]
    async fn concurrent_enqueue_never_exceeds_capacity() {
        use std::sync::Arc;

        let capacity = 10usize;
        let n_senders = 100usize;
        let (sender, _rx) = ingestion_queue(capacity, u64::MAX);
        let sender = Arc::new(sender);

        let handles: Vec<_> = (0..n_senders)
            .map(|i| {
                let s = Arc::clone(&sender);
                tokio::spawn(async move { s.try_enqueue(make_article(i as u64)).await })
            })
            .collect();

        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for h in handles {
            match h.await.unwrap() {
                Ok(()) => accepted += 1,
                Err(_) => rejected += 1,
            }
        }

        assert_eq!(
            accepted + rejected,
            n_senders,
            "all tasks must complete (no hangs)"
        );
        assert!(
            accepted <= capacity,
            "accepted {accepted} exceeds capacity {capacity}"
        );
        assert!(
            sender.depth() <= capacity,
            "depth {} exceeds capacity {capacity}",
            sender.depth()
        );
        assert_eq!(
            sender
                .metrics()
                .accepted_total
                .load(std::sync::atomic::Ordering::Relaxed),
            accepted as u64,
            "accepted_total counter must match observed accepts"
        );
    }
}
