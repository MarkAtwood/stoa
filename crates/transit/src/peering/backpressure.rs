//! IPFS write latency monitor with exponential moving average backpressure.
//!
//! Tracks IPFS write latency using an EMA (α=0.1) and activates backpressure
//! (reduces effective queue high-water mark to 50%) when the EMA exceeds a
//! configurable threshold. Recovers automatically when latency drops.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const EMA_ALPHA: f64 = 0.1; // smoothing factor: ~10 samples to stabilize

/// IPFS write latency monitor with EMA-based backpressure.
///
/// Thread-safe: the EMA is stored in an `AtomicU64` (integer microseconds).
/// `backpressure_active()` reads the gauge without locking.
pub struct IpfsLatencyMonitor {
    /// EMA of write latency in milliseconds (packed into u64 as f64 bits).
    ema_us: AtomicU64,
    /// Threshold in milliseconds above which backpressure activates.
    threshold_ms: u64,
    /// Whether backpressure is currently active.
    active: AtomicBool,
    /// Total samples recorded.
    sample_count: AtomicU64,
}

impl IpfsLatencyMonitor {
    /// Create a new monitor.
    ///
    /// - `threshold_ms`: IPFS write p99 latency threshold in ms (default 500)
    pub fn new(threshold_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            ema_us: AtomicU64::new(f64::to_bits(0.0)),
            threshold_ms,
            active: AtomicBool::new(false),
            sample_count: AtomicU64::new(0),
        })
    }

    /// Create with the default 500ms threshold.
    pub fn new_default() -> Arc<Self> {
        Self::new(500)
    }

    /// Record an IPFS write latency sample in milliseconds.
    ///
    /// Updates the EMA and re-evaluates the backpressure state.
    pub fn record_latency_ms(&self, latency_ms: f64) {
        // Update EMA.
        let prev_bits = self.ema_us.load(Ordering::Relaxed);
        let prev = f64::from_bits(prev_bits);
        let count = self.sample_count.fetch_add(1, Ordering::Relaxed);

        // For the first sample, initialize EMA = sample directly.
        let new_ema = if count == 0 {
            latency_ms
        } else {
            EMA_ALPHA * latency_ms + (1.0 - EMA_ALPHA) * prev
        };

        // Store as f64 bits in AtomicU64.
        self.ema_us.store(f64::to_bits(new_ema), Ordering::Relaxed);

        // Update backpressure state.
        let was_active = self.active.load(Ordering::Relaxed);
        let threshold = self.threshold_ms as f64;

        if !was_active && new_ema > threshold {
            self.active.store(true, Ordering::Release);
            tracing::warn!(
                ema_ms = new_ema,
                threshold_ms = threshold,
                "IPFS write latency EMA exceeded threshold — backpressure active"
            );
        } else if was_active && new_ema <= threshold {
            self.active.store(false, Ordering::Release);
            tracing::info!(
                ema_ms = new_ema,
                threshold_ms = threshold,
                "IPFS write latency recovered — backpressure cleared"
            );
        }
    }

    /// Whether backpressure is currently active.
    ///
    /// When true, callers should reduce ingestion queue high-water mark to 50%.
    pub fn backpressure_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Current EMA latency in milliseconds.
    pub fn ema_ms(&self) -> f64 {
        f64::from_bits(self.ema_us.load(Ordering::Relaxed))
    }

    /// Effective queue high-water mark fraction.
    ///
    /// Returns 1.0 (full capacity) when normal, 0.5 (50%) under backpressure.
    pub fn queue_hwm_fraction(&self) -> f64 {
        if self.backpressure_active() {
            0.5
        } else {
            1.0
        }
    }

    /// Format the current state as Prometheus text for the `ipfs_backpressure_active` gauge.
    pub fn prometheus_text(&self) -> String {
        let value = if self.backpressure_active() { 1 } else { 0 };
        format!(
            "# HELP ipfs_backpressure_active 1 if IPFS write latency EMA exceeds threshold\n\
             # TYPE ipfs_backpressure_active gauge\n\
             ipfs_backpressure_active {value}\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_no_backpressure() {
        let monitor = IpfsLatencyMonitor::new(500);
        assert!(!monitor.backpressure_active());
        assert_eq!(monitor.ema_ms(), 0.0);
        assert_eq!(monitor.queue_hwm_fraction(), 1.0);
    }

    #[test]
    fn single_high_latency_sample_activates_backpressure() {
        let monitor = IpfsLatencyMonitor::new(500);
        // First sample: EMA = sample value.
        monitor.record_latency_ms(600.0);
        assert!(
            monitor.backpressure_active(),
            "600ms > 500ms threshold must activate backpressure"
        );
        assert_eq!(monitor.queue_hwm_fraction(), 0.5);
    }

    #[test]
    fn low_latency_samples_do_not_activate_backpressure() {
        let monitor = IpfsLatencyMonitor::new(500);
        for _ in 0..50 {
            monitor.record_latency_ms(10.0);
        }
        assert!(
            !monitor.backpressure_active(),
            "10ms latency must not trigger backpressure"
        );
    }

    #[test]
    fn backpressure_recovers_after_latency_drops() {
        let monitor = IpfsLatencyMonitor::new(500);
        // Activate with a high first sample.
        monitor.record_latency_ms(1000.0);
        assert!(monitor.backpressure_active());

        // Feed many low-latency samples to drag EMA below threshold.
        for _ in 0..100 {
            monitor.record_latency_ms(1.0);
        }
        assert!(
            !monitor.backpressure_active(),
            "EMA should recover below 500ms after 100 low samples: ema={}",
            monitor.ema_ms()
        );
    }

    #[test]
    fn ema_is_smoothed_not_instantaneous() {
        let monitor = IpfsLatencyMonitor::new(500);
        // Two moderate samples: EMA should be < 200 (not jumping to 200 immediately).
        monitor.record_latency_ms(200.0);
        let after_first = monitor.ema_ms();
        monitor.record_latency_ms(0.0);
        let after_second = monitor.ema_ms();
        // After first sample EMA=200, after second EMA = 0.1*0 + 0.9*200 = 180.
        assert!(after_second < after_first, "EMA should decrease after a low sample");
        assert!(
            (after_second - 180.0).abs() < 1.0,
            "EMA after second sample should be ~180ms"
        );
    }

    #[test]
    fn prometheus_text_reflects_active_state() {
        let monitor = IpfsLatencyMonitor::new(500);
        monitor.record_latency_ms(1000.0);
        let text = monitor.prometheus_text();
        assert!(text.contains("ipfs_backpressure_active 1"));
    }

    #[test]
    fn prometheus_text_reflects_inactive_state() {
        let monitor = IpfsLatencyMonitor::new(500);
        monitor.record_latency_ms(10.0);
        let text = monitor.prometheus_text();
        assert!(text.contains("ipfs_backpressure_active 0"));
    }

    #[test]
    fn queue_hwm_fraction_full_when_normal() {
        let monitor = IpfsLatencyMonitor::new(500);
        assert_eq!(monitor.queue_hwm_fraction(), 1.0);
    }
}
