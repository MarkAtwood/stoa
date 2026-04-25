/// Token-bucket rate limiter for per-IP request throttling.
///
/// Shared between the reader and transit admin HTTP servers. Each IP address
/// gets its own bucket. Entries idle for more than one hour are evicted on
/// the next call to bound `HashMap` size.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct RateLimitState {
    /// Tokens available (fractional).
    tokens: f64,
    /// Last refill time.
    last_refill: Instant,
}

pub struct RateLimiter {
    /// Max requests per minute. 0 = unlimited.
    rpm: u32,
    /// Per-IP state.
    state: Mutex<HashMap<IpAddr, RateLimitState>>,
}

impl RateLimiter {
    pub fn new(rpm: u32) -> Self {
        Self {
            rpm,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    /// Always returns true when rpm == 0 (unlimited).
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
            // Inner block: drop the `entry` borrow before state.retain() needs &mut state.
            let entry = state.entry(ip).or_insert(RateLimitState {
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

    /// Returns the configured rpm limit (used to compute Retry-After).
    pub fn rpm(&self) -> u32 {
        self.rpm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_limit() {
        let limiter = RateLimiter::new(60);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check_and_consume(ip), "first request must be allowed");
    }

    #[test]
    fn blocks_when_exhausted() {
        let limiter = RateLimiter::new(2); // 2 tokens max
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check_and_consume(ip));
        assert!(limiter.check_and_consume(ip));
        assert!(!limiter.check_and_consume(ip), "third request must be blocked");
    }

    #[test]
    fn zero_means_unlimited() {
        let limiter = RateLimiter::new(0);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..1000 {
            assert!(limiter.check_and_consume(ip));
        }
    }

    #[test]
    fn different_ips_are_independent() {
        let limiter = RateLimiter::new(1);
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        assert!(limiter.check_and_consume(ip1));
        assert!(!limiter.check_and_consume(ip1)); // ip1 exhausted
        assert!(limiter.check_and_consume(ip2)); // ip2 still has token
    }

}
