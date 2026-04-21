//! Gossipsub backpressure: per-hierarchy rate limiting and drop counting.
//!
//! Callers consult `BackpressureGuard::check_and_consume` before publishing
//! to the gossipsub swarm. If the check fails, the message is dropped and
//! the drop counter is incremented. The caller logs the drop and continues.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// In-process counter for dropped gossipsub messages.
///
/// Exposed as `gossip_messages_dropped_total` in Prometheus text format.
pub struct DropCounter {
    total: AtomicU64,
}

impl DropCounter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total: AtomicU64::new(0),
        })
    }

    pub fn increment(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Format as Prometheus text exposition.
    pub fn prometheus_text(&self) -> String {
        format!(
            "# HELP gossip_messages_dropped_total Messages dropped due to gossipsub backpressure\n\
             # TYPE gossip_messages_dropped_total counter\n\
             gossip_messages_dropped_total {}\n",
            self.total()
        )
    }
}

impl Default for DropCounter {
    fn default() -> Self {
        Self {
            total: AtomicU64::new(0),
        }
    }
}

/// Token bucket for a single hierarchy's publish rate.
struct HierarchyBucket {
    capacity: f64,
    rate: f64,
    tokens: f64,
    last_refill: Instant,
}

impl HierarchyBucket {
    fn new(rate: f64, capacity: u64) -> Self {
        Self {
            capacity: capacity as f64,
            rate,
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-hierarchy outbound publish rate limiter.
///
/// Call `check_publish` before sending a gossipsub message for a group.
/// If it returns `false`, drop the message and increment the drop counter.
pub struct BackpressureGuard {
    /// Token bucket per hierarchy (e.g. "comp", "sci").
    buckets: HashMap<String, HierarchyBucket>,
    /// Messages per second per hierarchy.
    rate: f64,
    /// Burst capacity per hierarchy.
    capacity: u64,
    /// Drop counter shared with the caller for metrics.
    pub drop_counter: Arc<DropCounter>,
}

impl BackpressureGuard {
    /// Create a new guard.
    ///
    /// - `rate`: messages per second allowed per hierarchy
    /// - `capacity`: burst size per hierarchy
    pub fn new(rate: f64, capacity: u64) -> Self {
        Self {
            buckets: HashMap::new(),
            rate,
            capacity,
            drop_counter: DropCounter::new(),
        }
    }

    /// Check whether publishing a message for `group_name` is permitted.
    ///
    /// Returns `true` if allowed (token consumed), `false` if the hierarchy
    /// bucket is exhausted (caller must drop and increment counter).
    ///
    /// Extracts the hierarchy from the first dot-delimited component.
    pub fn check_publish(&mut self, group_name: &str) -> bool {
        let hierarchy = group_name
            .split('.')
            .next()
            .unwrap_or(group_name)
            .to_owned();
        let rate = self.rate;
        let capacity = self.capacity;
        let bucket = self
            .buckets
            .entry(hierarchy)
            .or_insert_with(|| HierarchyBucket::new(rate, capacity));
        bucket.try_consume()
    }

    /// Check and consume, incrementing the drop counter on failure.
    ///
    /// Returns `true` if the message was allowed, `false` if dropped.
    pub fn check_and_record(&mut self, group_name: &str) -> bool {
        if self.check_publish(group_name) {
            true
        } else {
            self.drop_counter.increment();
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn drop_counter_starts_at_zero() {
        let c = DropCounter::new();
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn drop_counter_increments() {
        let c = DropCounter::new();
        c.increment();
        c.increment();
        assert_eq!(c.total(), 2);
    }

    #[test]
    fn drop_counter_prometheus_text_contains_metric_name() {
        let c = DropCounter::new();
        c.increment();
        let text = c.prometheus_text();
        assert!(text.contains("gossip_messages_dropped_total"));
        assert!(
            text.contains('1'),
            "counter value must appear in prometheus text"
        );
    }

    #[test]
    fn backpressure_allows_burst_then_drops() {
        let mut guard = BackpressureGuard::new(1.0, 3);
        // Burst of 3 allowed.
        assert!(guard.check_publish("comp.lang.rust"));
        assert!(guard.check_publish("comp.lang.rust"));
        assert!(guard.check_publish("comp.lang.rust"));
        // 4th is dropped.
        assert!(!guard.check_publish("comp.lang.rust"));
    }

    #[test]
    fn backpressure_hierarchies_are_independent() {
        let mut guard = BackpressureGuard::new(1.0, 1);
        assert!(guard.check_publish("comp.lang.rust")); // comp bucket: 0 tokens
        assert!(guard.check_publish("sci.math")); // sci bucket: still full
        assert!(!guard.check_publish("comp.lang.rust")); // comp exhausted
    }

    #[test]
    fn check_and_record_increments_drop_counter() {
        let mut guard = BackpressureGuard::new(1.0, 1);
        assert!(guard.check_and_record("comp.lang.rust")); // allowed
        assert!(!guard.check_and_record("comp.lang.rust")); // dropped
        assert_eq!(guard.drop_counter.total(), 1);
        assert!(!guard.check_and_record("comp.lang.rust")); // dropped again
        assert_eq!(guard.drop_counter.total(), 2);
    }

    #[test]
    fn high_rate_publish_drops_are_counted() {
        // Publish at 10x rate limit. capacity=1, so 1 allowed, 9 dropped.
        let mut guard = BackpressureGuard::new(1.0, 1);
        for _ in 0..10 {
            guard.check_and_record("comp.lang.rust");
        }
        assert_eq!(guard.drop_counter.total(), 9, "9 of 10 should be dropped");
    }

    #[test]
    fn refill_allows_publish_after_delay() {
        let mut guard = BackpressureGuard::new(1000.0, 1);
        assert!(guard.check_publish("comp.lang.rust")); // drain
        assert!(!guard.check_publish("comp.lang.rust")); // empty

        // Manually advance the bucket's last_refill to simulate elapsed time.
        let bucket = guard.buckets.get_mut("comp").unwrap();
        bucket.last_refill = Instant::now() - Duration::from_millis(5);

        // 5ms at 1000/s = 5 tokens refilled, capped at capacity=1.
        assert!(
            guard.check_publish("comp.lang.rust"),
            "should have refilled"
        );
    }
}
