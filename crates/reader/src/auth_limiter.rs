//! Per-IP authentication failure tracking for fail2ban-compatible lockout detection.
//!
//! [`AuthFailureTracker`] counts authentication failures per source IP within a
//! sliding time window and signals when an IP crosses the lockout threshold.
//! The signal is a return value from [`AuthFailureTracker::record_failure`]; the
//! caller is responsible for emitting the log event.
//!
//! The tracker is bounded: at most `max_entries` unique IPs are held in memory.
//! When the table is full, the entry with the oldest window-start timestamp is
//! evicted to make room for the new IP.  Eviction uses a min-heap with lazy
//! deletion for O(log n) amortized cost.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Default maximum number of unique source IPs tracked simultaneously.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Tracks per-IP authentication failure counts within a sliding window.
///
/// Constructed once at startup and shared across NNTP sessions via
/// `Arc<tokio::sync::Mutex<AuthFailureTracker>>`.
#[derive(Debug)]
pub struct AuthFailureTracker {
    /// Per-IP state: (failure_count_in_window, window_start).
    entries: HashMap<IpAddr, (u32, Instant)>,
    /// Min-heap of (window_start, ip) for O(log n) oldest-first eviction.
    ///
    /// May contain stale entries: removed IPs (`record_success`) or IPs whose
    /// window has reset (heap timestamp < current entry timestamp).  Lazy
    /// deletion skips stale heap entries during eviction.
    eviction_heap: BinaryHeap<Reverse<(Instant, IpAddr)>>,
    max_entries: usize,
    /// Number of failures within `window` that triggers a lockout signal.
    threshold: u32,
    /// Length of the sliding failure window.
    window: Duration,
}

impl AuthFailureTracker {
    /// Create a new tracker.
    ///
    /// `threshold`: failure count within `window` that triggers lockout.
    /// `window`: sliding window duration.
    /// `max_entries`: cap on the number of tracked IPs (oldest evicted when full).
    pub fn new(threshold: u32, window: Duration, max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(256)),
            eviction_heap: BinaryHeap::new(),
            max_entries,
            threshold,
            window,
        }
    }

    /// Record a failed authentication attempt from `ip`.
    ///
    /// Returns `true` exactly once per window when the failure count reaches
    /// `threshold` — the caller should emit an `auth_lockout` log event.
    /// Returns `false` for all other calls (below threshold, or already past it).
    pub fn record_failure(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();

        if let Some(entry) = self.entries.get_mut(&ip) {
            if now.duration_since(entry.1) > self.window {
                // Window expired; start a new one with this failure.
                *entry = (1, now);
                // Push updated timestamp; old heap entry becomes stale (lazy delete).
                self.eviction_heap.push(Reverse((now, ip)));
                return 1 == self.threshold;
            }
            entry.0 += 1;
            return entry.0 == self.threshold;
        }

        // New IP: evict oldest live entry if at capacity.
        if self.entries.len() >= self.max_entries {
            // Pop heap entries until we find one that matches a live map entry.
            loop {
                match self.eviction_heap.pop() {
                    None => break,
                    Some(Reverse((ts, victim_ip))) => {
                        if let Some((_, entry_ts)) = self.entries.get(&victim_ip) {
                            if *entry_ts == ts {
                                // Live entry with matching timestamp — evict it.
                                self.entries.remove(&victim_ip);
                                break;
                            }
                            // Stale: timestamp updated (window reset) — skip.
                        }
                        // Stale: entry was removed via record_success — skip.
                    }
                }
            }
        }

        self.entries.insert(ip, (1, now));
        self.eviction_heap.push(Reverse((now, ip)));
        1 == self.threshold
    }

    /// Record a successful authentication from `ip`, resetting its failure count.
    pub fn record_success(&mut self, ip: IpAddr) {
        // Removing from the HashMap is sufficient.  The eviction_heap entry
        // becomes stale and will be skipped during the next eviction pass.
        self.entries.remove(&ip);
    }

    /// Return the current failure count for `ip`, or 0 if not tracked.
    pub fn failure_count(&self, ip: IpAddr) -> u32 {
        self.entries.get(&ip).map_or(0, |(count, _)| *count)
    }

    /// Return the number of IPs currently tracked.
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn below_threshold_returns_false() {
        let mut tracker = AuthFailureTracker::new(5, Duration::from_secs(60), 100);
        for _ in 0..4 {
            assert!(!tracker.record_failure(ip("1.2.3.4")));
        }
        assert_eq!(tracker.failure_count(ip("1.2.3.4")), 4);
    }

    #[test]
    fn at_threshold_returns_true_once() {
        let mut tracker = AuthFailureTracker::new(5, Duration::from_secs(60), 100);
        for _ in 0..4 {
            tracker.record_failure(ip("1.2.3.4"));
        }
        // 5th failure: at threshold
        assert!(
            tracker.record_failure(ip("1.2.3.4")),
            "5th failure must return true"
        );
        // 6th and beyond: past threshold, must not re-trigger
        assert!(
            !tracker.record_failure(ip("1.2.3.4")),
            "6th failure must return false"
        );
        assert!(
            !tracker.record_failure(ip("1.2.3.4")),
            "7th failure must return false"
        );
    }

    #[test]
    fn threshold_of_one_triggers_on_first_failure() {
        let mut tracker = AuthFailureTracker::new(1, Duration::from_secs(60), 100);
        assert!(tracker.record_failure(ip("10.0.0.1")));
    }

    #[test]
    fn success_resets_failure_count() {
        let mut tracker = AuthFailureTracker::new(5, Duration::from_secs(60), 100);
        tracker.record_failure(ip("1.2.3.4"));
        tracker.record_failure(ip("1.2.3.4"));
        assert_eq!(tracker.failure_count(ip("1.2.3.4")), 2);
        tracker.record_success(ip("1.2.3.4"));
        assert_eq!(tracker.failure_count(ip("1.2.3.4")), 0);
        // After reset, threshold fires again at 5
        for _ in 0..4 {
            assert!(!tracker.record_failure(ip("1.2.3.4")));
        }
        assert!(tracker.record_failure(ip("1.2.3.4")));
    }

    #[test]
    fn distinct_ips_tracked_independently() {
        let mut tracker = AuthFailureTracker::new(3, Duration::from_secs(60), 100);
        tracker.record_failure(ip("1.1.1.1"));
        tracker.record_failure(ip("2.2.2.2"));
        tracker.record_failure(ip("3.3.3.3"));
        assert_eq!(tracker.failure_count(ip("1.1.1.1")), 1);
        assert_eq!(tracker.failure_count(ip("2.2.2.2")), 1);
        assert_eq!(tracker.failure_count(ip("3.3.3.3")), 1);
    }

    #[test]
    fn evicts_when_at_capacity() {
        let mut tracker = AuthFailureTracker::new(100, Duration::from_secs(60), 3);
        // Fill capacity with 3 distinct IPs.
        tracker.record_failure(ip("10.0.0.1"));
        tracker.record_failure(ip("10.0.0.2"));
        tracker.record_failure(ip("10.0.0.3"));
        assert_eq!(tracker.tracked_count(), 3);
        // Adding a 4th evicts the oldest.
        tracker.record_failure(ip("10.0.0.4"));
        assert_eq!(tracker.tracked_count(), 3, "must not exceed max_entries");
    }

    #[test]
    fn window_expiry_resets_count() {
        // Use a zero-duration window so every call after the first starts a new window.
        let mut tracker = AuthFailureTracker::new(2, Duration::ZERO, 100);
        // First failure: count=1, threshold=2 → false
        assert!(!tracker.record_failure(ip("1.2.3.4")));
        // Window immediately expired (Duration::ZERO); reset to 1 → threshold=2 → false
        assert!(!tracker.record_failure(ip("1.2.3.4")));
        assert_eq!(
            tracker.failure_count(ip("1.2.3.4")),
            1,
            "window reset keeps count at 1"
        );
    }
}
