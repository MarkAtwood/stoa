//! Bounded ingestion queue with back-pressure signaling.
//!
//! Articles from peering connections are buffered here before the
//! store-and-forward pipeline processes them. When the queue is full,
//! new articles receive a 431 response and the peer is asked to retry.
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
    /// Current queue depth.
    pub depth_current: AtomicUsize,
    /// Maximum configured queue depth.
    pub depth_max: usize,
    /// Total articles accepted into the queue.
    pub accepted_total: AtomicU64,
    /// Total articles rejected with 431 due to full queue.
    pub rejected_full_total: AtomicU64,
}

impl QueueMetrics {
    fn new(max: usize) -> Self {
        Self {
            depth_current: AtomicUsize::new(0),
            depth_max: max,
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
    /// Returns `Ok(())` if accepted, `Err("431 ...")` if the queue is full.
    pub async fn try_enqueue(&self, article: QueuedArticle) -> Result<(), &'static str> {
        match self.tx.try_send(article) {
            Ok(()) => {
                self.metrics.depth_current.fetch_add(1, Ordering::Relaxed);
                self.metrics.accepted_total.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics
                    .rejected_full_total
                    .fetch_add(1, Ordering::Relaxed);
                Err("431 Ingestion queue full, try again later\r\n")
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
        Some(article)
    }
}

/// Create an ingestion queue with the given maximum depth.
pub fn ingestion_queue(max_depth: usize) -> (IngestionSender, IngestionReceiver) {
    let metrics = Arc::new(QueueMetrics::new(max_depth));
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

    #[tokio::test]
    async fn queue_accepts_up_to_capacity() {
        let (sender, _rx) = ingestion_queue(3);
        assert!(sender.try_enqueue(make_article(1)).await.is_ok());
        assert!(sender.try_enqueue(make_article(2)).await.is_ok());
        assert!(sender.try_enqueue(make_article(3)).await.is_ok());
        // 4th should fail (queue full).
        let result = sender.try_enqueue(make_article(4)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().starts_with("431"));
    }

    #[tokio::test]
    async fn queue_depth_tracked_on_enqueue() {
        let (sender, _rx) = ingestion_queue(10);
        assert_eq!(sender.depth(), 0);
        sender.try_enqueue(make_article(1)).await.unwrap();
        assert_eq!(sender.depth(), 1);
        sender.try_enqueue(make_article(2)).await.unwrap();
        assert_eq!(sender.depth(), 2);
    }

    #[tokio::test]
    async fn queue_depth_decreases_on_recv() {
        let (sender, mut receiver) = ingestion_queue(10);
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
        let (sender, _rx) = ingestion_queue(1);
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
        let (sender, mut receiver) = ingestion_queue(10);
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
    async fn fill_queue_verify_431_drain_verify_resumption() {
        // Acceptance test: fill → 431 → drain → resume.
        let (sender, mut receiver) = ingestion_queue(5);

        // Fill queue.
        for i in 1..=5 {
            assert!(sender.try_enqueue(make_article(i)).await.is_ok());
        }

        // Additional enqueues return 431.
        for i in 6..=10 {
            let result = sender.try_enqueue(make_article(i)).await;
            assert!(result.is_err(), "article {i} should be rejected");
            assert!(result.unwrap_err().contains("431"));
        }

        // Drain queue.
        for _ in 0..5 {
            assert!(receiver.recv().await.is_some());
        }

        // Queue is now empty; new enqueues should succeed again.
        assert!(sender.try_enqueue(make_article(100)).await.is_ok());
        assert_eq!(sender.depth(), 1);
    }

    /// Regression test for usenet-ipfs-76h: concurrent TAKETHIS flood must never
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
        let (sender, _rx) = ingestion_queue(capacity);
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
