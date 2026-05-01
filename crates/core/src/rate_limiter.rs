/// Token-bucket rate limiter for per-IP request throttling.
///
/// Shared between the reader and transit admin HTTP servers. Each IP address
/// gets its own bucket. Entries idle for more than one hour are evicted on
/// the next call to bound `HashMap` size.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Evict idle entries every 1024 calls to amortize O(n) scan cost.
const EVICT_INTERVAL: u64 = 1024;
/// Evict entries idle longer than one hour.
const IDLE_TTL: Duration = Duration::from_secs(3600);
/// Hard cap on the number of tracked IPs. When reached, trigger immediate
/// eviction before inserting a new entry, preventing unbounded growth under
/// DDoS from many distinct source addresses.
const MAX_ENTRIES: usize = 65_536;

struct RateLimitState {
    /// Tokens available (fractional).
    tokens: f64,
    /// Last refill time.
    last_refill: Instant,
}

struct Inner {
    map: HashMap<IpAddr, RateLimitState>,
    /// Monotonically increasing call counter; wraps at u64::MAX (harmless).
    call_count: u64,
}

pub struct RateLimiter {
    /// Max requests per minute. 0 = unlimited.
    rpm: u32,
    /// Per-IP state.
    state: Mutex<Inner>,
}

impl RateLimiter {
    pub fn new(rpm: u32) -> Self {
        Self {
            rpm,
            state: Mutex::new(Inner {
                map: HashMap::new(),
                // Start at 1 so the first call does not trigger an eviction
                // scan over an empty map (0 % EVICT_INTERVAL == 0 is true).
                call_count: 1,
            }),
        }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    /// Always returns true when rpm == 0 (unlimited).
    pub fn check_and_consume(&self, ip: IpAddr) -> bool {
        if self.rpm == 0 {
            return true;
        }
        let mut inner = self.state.lock().expect("rate limiter lock poisoned");
        let tokens_per_sec = self.rpm as f64 / 60.0;
        let max_tokens = self.rpm as f64;
        let now = Instant::now();

        let allowed;
        {
            // Inner block: drop the `entry` borrow before eviction needs &mut inner.map.
            let entry = inner.map.entry(ip).or_insert(RateLimitState {
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

        // Evict idle entries periodically or when the map hits the hard cap.
        // Periodic eviction: every EVICT_INTERVAL calls amortizes the O(n) scan.
        // Cap eviction: prevents unbounded growth under DDoS from many distinct IPs.
        inner.call_count = inner.call_count.wrapping_add(1);
        if inner.call_count % EVICT_INTERVAL == 0 || inner.map.len() > MAX_ENTRIES {
            let evict_before = now - IDLE_TTL;
            inner.map.retain(|_, v| v.last_refill >= evict_before);
        }

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
        assert!(
            limiter.check_and_consume(ip),
            "first request must be allowed"
        );
    }

    #[test]
    fn blocks_when_exhausted() {
        let limiter = RateLimiter::new(2); // 2 tokens max
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check_and_consume(ip));
        assert!(limiter.check_and_consume(ip));
        assert!(
            !limiter.check_and_consume(ip),
            "third request must be blocked"
        );
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
