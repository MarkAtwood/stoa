use std::collections::HashMap;
use std::time::Instant;

/// Evict fully-refilled buckets every N calls to amortize O(n) retain cost.
const EVICT_INTERVAL: u64 = 64;

/// What happens when the token bucket is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustionAction {
    /// Return 431 "try again later" response to the peer.
    Respond431,
    /// Drop the connection.
    DropConnection,
}

/// Per-peer token bucket rate limiter.
///
/// Tokens refill at `rate` tokens/second, up to `capacity` (burst size).
/// Each article consumes one token.
pub struct TokenBucket {
    /// Maximum tokens (burst size).
    capacity: f64,
    /// Tokens per second.
    rate: f64,
    /// Current token count (can be fractional for sub-second precision).
    tokens: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
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

    /// Attempt to consume one token. Returns true if allowed, false if exhausted.
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
    fn refill(&mut self) {
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

/// Registry of per-peer token buckets, keyed by peer IP address.
pub struct PeerRateLimiter {
    buckets: HashMap<std::net::IpAddr, TokenBucket>,
    rate: f64,
    capacity: u64,
    action: ExhaustionAction,
    call_count: u64,
}

impl PeerRateLimiter {
    pub fn new(rate: f64, capacity: u64, action: ExhaustionAction) -> Self {
        Self {
            buckets: HashMap::new(),
            rate,
            capacity,
            action,
            call_count: 0,
        }
    }

    /// Check and consume one article slot for the given peer.
    /// Creates a new bucket for the peer if not seen before.
    ///
    /// Evicts fully-refilled buckets every EVICT_INTERVAL calls to amortize
    /// the O(n) retain cost across many articles from many peers.
    ///
    /// Returns `None` (allow) if the peer address cannot be parsed, rather
    /// than falling back to 0.0.0.0 which would conflate all bad-address peers
    /// into a single shared bucket. An unparseable address is logged as a
    /// warning.
    pub fn check(&mut self, peer_addr: &str) -> Option<RateLimitResult> {
        use std::net::{IpAddr, SocketAddr};
        let ip: IpAddr = match peer_addr
            .parse::<SocketAddr>()
            .map(|sa| sa.ip())
            .or_else(|_| peer_addr.parse::<IpAddr>())
        {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(peer_addr, "rate limiter: unparseable peer address, skipping");
                return None;
            }
        };
        let rate = self.rate;
        let capacity = self.capacity;
        let action = self.action;
        let bucket = self
            .buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(rate, capacity, action));
        let result = bucket.check_and_consume();
        self.call_count = self.call_count.wrapping_add(1);
        if self.call_count % EVICT_INTERVAL == 0 {
            let cap = capacity as f64;
            self.buckets.retain(|_, b| {
                b.refill();
                b.tokens < cap
            });
        }
        result
    }

    /// Remove the bucket for a peer (e.g. on disconnect).
    ///
    /// If the peer address cannot be parsed no bucket will exist to remove;
    /// this is a no-op in that case (consistent with `check` not inserting one).
    pub fn remove_peer(&mut self, peer_addr: &str) {
        use std::net::{IpAddr, SocketAddr};
        let ip: IpAddr = match peer_addr
            .parse::<SocketAddr>()
            .map(|sa| sa.ip())
            .or_else(|_| peer_addr.parse::<IpAddr>())
        {
            Ok(ip) => ip,
            Err(_) => return,
        };
        self.buckets.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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

    #[test]
    fn peer_rate_limiter_tracks_multiple_peers() {
        let mut limiter = PeerRateLimiter::new(1.0, 2, ExhaustionAction::Respond431);
        assert!(limiter.check("192.0.2.1").is_none());
        assert!(limiter.check("192.0.2.1").is_none());
        assert!(limiter.check("192.0.2.1").is_some());

        assert!(limiter.check("192.0.2.2").is_none());
    }

    #[test]
    fn high_rate_send_rejection_count() {
        let mut limiter = PeerRateLimiter::new(1.0, 1, ExhaustionAction::Respond431);
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for _ in 0..10 {
            match limiter.check("192.0.2.1") {
                None => accepted += 1,
                Some(_) => rejected += 1,
            }
        }
        assert_eq!(accepted, 1, "only first should be accepted");
        assert_eq!(rejected, 9, "remaining 9 should be rejected");
    }
}
