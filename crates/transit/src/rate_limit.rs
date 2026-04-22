//! Shared token-bucket rate limiters for the transit daemon.
//!
//! Two rate limiters are provided:
//!
//! - [`AdminRateLimiter`] — per-IP, RPM-based, shared across all admin HTTP
//!   connections.  Keyed by [`IpAddr`] so IPv6 zone IDs are never included in
//!   the key.  Idle entries are evicted after one hour.
//!
//! - [`PeerRateLimiter`] — per-IP article-ingestion limiter for NNTP peering
//!   sessions.  Configured with tokens/second and burst capacity; carries an
//!   [`ExhaustionAction`] that tells the session handler what to do when the
//!   budget is exhausted.  Fully-refilled entries are evicted on each check.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

// ── Admin rate limiter ────────────────────────────────────────────────────────

struct AdminRateLimitState {
    /// Tokens available (fractional).
    tokens: f64,
    /// Last refill time.
    last_refill: Instant,
}

/// Per-IP RPM-based token-bucket rate limiter for the admin HTTP server.
///
/// Keyed by [`IpAddr`] (never by socket-address string) so that IPv6 zone IDs
/// are not included in the key and connections from the same host share a
/// single budget.  Idle entries (no request for one hour) are evicted on each
/// call to bound the `HashMap` size.
pub struct AdminRateLimiter {
    /// Max requests per minute.
    pub(crate) rpm: u32,
    /// Per-IP state.
    state: std::sync::Mutex<HashMap<IpAddr, AdminRateLimitState>>,
}

impl AdminRateLimiter {
    /// Create a new limiter.  `rpm == 0` means unlimited.
    pub fn new(rpm: u32) -> Self {
        Self {
            rpm,
            state: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    ///
    /// Always returns `true` when `rpm == 0`.  Idle entries (last seen more
    /// than one hour ago) are evicted from the map on each call.
    pub fn check_and_consume(&self, ip: IpAddr) -> bool {
        if self.rpm == 0 {
            return true;
        }
        let mut state = self.state.lock().unwrap();
        let tokens_per_sec = self.rpm as f64 / 60.0;
        let max_tokens = self.rpm as f64;
        let now = Instant::now();

        let allowed;
        {
            let entry = state.entry(ip).or_insert(AdminRateLimitState {
                tokens: max_tokens,
                last_refill: now,
            });
            let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
            entry.tokens = (entry.tokens + elapsed * tokens_per_sec).min(max_tokens);
            entry.last_refill = now;
            if entry.tokens >= 1.0 {
                entry.tokens -= 1.0;
                allowed = true;
            } else {
                allowed = false;
            }
        }

        // Evict entries idle for more than one hour to bound HashMap size.
        let evict_before = now - std::time::Duration::from_secs(3600);
        state.retain(|_, v| v.last_refill >= evict_before);

        allowed
    }
}

// ── Peering rate limiter ──────────────────────────────────────────────────────

/// What happens when the token bucket is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustionAction {
    /// Return a 431 "try again later" response to the peer.
    Respond431,
    /// Drop the connection.
    DropConnection,
}

/// Per-IP token bucket for one peer.
pub struct TokenBucket {
    /// Maximum tokens (burst size).
    capacity: f64,
    /// Tokens per second.
    rate: f64,
    /// Current token count (can be fractional for sub-second precision).
    tokens: f64,
    /// Last time tokens were refilled.
    pub(crate) last_refill: Instant,
    /// What to do when exhausted.
    pub exhaustion_action: ExhaustionAction,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// - `rate`: articles per second (e.g. 10.0)
    /// - `capacity`: burst size (e.g. 20)
    /// - `action`: what happens on exhaustion
    pub fn new(rate: f64, capacity: u64, action: ExhaustionAction) -> Self {
        Self {
            capacity: capacity as f64,
            rate,
            tokens: capacity as f64,
            last_refill: Instant::now(),
            exhaustion_action: action,
        }
    }

    /// Attempt to consume one token. Returns `true` if allowed, `false` if exhausted.
    ///
    /// Refills tokens based on elapsed time before checking.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    pub(crate) fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }

    /// Returns `Some` if the request should be rejected, `None` if allowed.
    pub fn check_and_consume(&mut self) -> Option<RateLimitResult> {
        if self.try_consume() {
            None
        } else {
            Some(RateLimitResult::Exhausted(self.exhaustion_action))
        }
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    Exhausted(ExhaustionAction),
}

/// Registry of per-peer token buckets, keyed by [`IpAddr`].
///
/// Keyed by `IpAddr` (not by socket-address string) so that IPv6 zone IDs
/// are not included in the key and multiple simultaneous connections from one
/// host share a single rate-limit budget.  Fully-refilled buckets are evicted
/// on each call to bound the `HashMap` size.
pub struct PeerRateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    rate: f64,
    capacity: u64,
    action: ExhaustionAction,
}

impl PeerRateLimiter {
    pub fn new(rate: f64, capacity: u64, action: ExhaustionAction) -> Self {
        Self {
            buckets: HashMap::new(),
            rate,
            capacity,
            action,
        }
    }

    /// Check and consume one article slot for the given peer IP.
    ///
    /// Creates a new bucket for the peer if not seen before.  Evicts
    /// fully-refilled buckets from other peers on each call to bound the
    /// `HashMap` to only actively-rate-limited peers.
    pub fn check(&mut self, peer_ip: IpAddr) -> Option<RateLimitResult> {
        let rate = self.rate;
        let capacity = self.capacity;
        let action = self.action;
        let bucket = self
            .buckets
            .entry(peer_ip)
            .or_insert_with(|| TokenBucket::new(rate, capacity, action));
        let result = bucket.check_and_consume();
        // Evict buckets that have fully refilled — they impose no rate constraint
        // and retaining them wastes memory. A fresh full bucket is equivalent.
        let cap = capacity as f64;
        self.buckets.retain(|_, b| {
            b.refill();
            b.tokens < cap
        });
        result
    }

    /// Remove the bucket for a peer (e.g. on disconnect).
    pub fn remove_peer(&mut self, peer_ip: IpAddr) {
        self.buckets.remove(&peer_ip);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── AdminRateLimiter ──────────────────────────────────────────────────────

    #[test]
    fn admin_limiter_allows_under_limit() {
        let limiter = AdminRateLimiter::new(60);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.check_and_consume(ip));
    }

    #[test]
    fn admin_limiter_blocks_when_exhausted() {
        let limiter = AdminRateLimiter::new(2);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.check_and_consume(ip));
        assert!(limiter.check_and_consume(ip));
        assert!(!limiter.check_and_consume(ip));
    }

    #[test]
    fn admin_limiter_zero_means_unlimited() {
        let limiter = AdminRateLimiter::new(0);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..1000 {
            assert!(limiter.check_and_consume(ip));
        }
    }

    #[test]
    fn admin_limiter_different_ips_independent() {
        let limiter = AdminRateLimiter::new(1);
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        assert!(limiter.check_and_consume(ip1));
        assert!(!limiter.check_and_consume(ip1));
        assert!(limiter.check_and_consume(ip2));
    }

    // ── TokenBucket ───────────────────────────────────────────────────────────

    #[test]
    fn bucket_starts_full_and_allows_burst() {
        let mut bucket = TokenBucket::new(1.0, 5, ExhaustionAction::Respond431);
        for _ in 0..5 {
            assert!(bucket.try_consume(), "should allow burst");
        }
        assert!(!bucket.try_consume(), "should reject after burst exhausted");
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut bucket = TokenBucket::new(1000.0, 1, ExhaustionAction::Respond431);
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume());
        bucket.last_refill = Instant::now() - Duration::from_millis(5);
        assert!(bucket.try_consume(), "should have refilled");
    }

    #[test]
    fn check_and_consume_returns_none_when_allowed() {
        let mut bucket = TokenBucket::new(10.0, 10, ExhaustionAction::Respond431);
        assert!(bucket.check_and_consume().is_none());
    }

    #[test]
    fn check_and_consume_returns_some_when_exhausted() {
        let mut bucket = TokenBucket::new(1.0, 1, ExhaustionAction::Respond431);
        assert!(bucket.check_and_consume().is_none());
        let result = bucket.check_and_consume();
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            RateLimitResult::Exhausted(ExhaustionAction::Respond431)
        );
    }

    // ── PeerRateLimiter ───────────────────────────────────────────────────────

    #[test]
    fn peer_rate_limiter_tracks_multiple_peers() {
        let mut limiter = PeerRateLimiter::new(1.0, 2, ExhaustionAction::Respond431);
        let ip_a: IpAddr = "192.0.2.1".parse().unwrap();
        let ip_b: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(limiter.check(ip_a).is_none());
        assert!(limiter.check(ip_a).is_none());
        assert!(limiter.check(ip_a).is_some());
        assert!(limiter.check(ip_b).is_none());
    }

    #[test]
    fn high_rate_send_rejection_count() {
        let mut limiter = PeerRateLimiter::new(1.0, 1, ExhaustionAction::Respond431);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for _ in 0..10 {
            match limiter.check(ip) {
                None => accepted += 1,
                Some(_) => rejected += 1,
            }
        }
        assert_eq!(accepted, 1, "only first should be accepted");
        assert_eq!(rejected, 9, "remaining 9 should be rejected");
    }
}
