//! MTA-STS policy cache backed by the `mta_sts_cache` SQLite table (migration 0014).
//!
//! Policies are cached as plain strings so callers are not forced to depend on
//! the `stoa_smtp` config types.  The `mode` column stores one of the three
//! RFC 8461 mode strings: `"none"`, `"testing"`, or `"enforce"`.
//! `mx_patterns` is serialised as a JSON array (`["*.mx.example.com"]`).
//! Timestamps are stored as RFC 3339 strings and returned as `DateTime<Utc>`.

use chrono::{DateTime, Utc};

/// A cached MTA-STS policy row as read from the database.
#[derive(Debug, Clone)]
pub struct CachedMtaStsPolicy {
    pub domain: String,
    pub policy_id: String,
    /// One of `"none"`, `"testing"`, or `"enforce"` (RFC 8461 §3.2).
    pub mode: String,
    pub mx_patterns: Vec<String>,
    pub max_age_secs: i64,
    pub fetched_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Persistent cache for fetched MTA-STS policies.
pub struct MtaStsCache {
    pool: sqlx::AnyPool,
}

impl MtaStsCache {
    /// Wrap an existing connection pool.
    pub fn new(pool: sqlx::AnyPool) -> Self {
        Self { pool }
    }

    /// Return the cached policy for `domain`, or `None` if absent or expired.
    pub async fn get(&self, domain: &str) -> Result<Option<CachedMtaStsPolicy>, sqlx::Error> {
        let row: Option<(String, String, String, String, i64, String, String)> = sqlx::query_as(
            "SELECT domain, policy_id, mode, mx_patterns, max_age_secs, fetched_at, expires_at
             FROM mta_sts_cache
             WHERE domain = ?",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;

        let (domain, policy_id, mode, mx_json, max_age_secs, fetched_str, expires_str) = match row {
            None => return Ok(None),
            Some(r) => r,
        };

        let fetched_at = parse_rfc3339(&fetched_str)?;
        let expires_at = parse_rfc3339(&expires_str)?;

        // Treat expired entries as absent; the caller should re-fetch.
        if expires_at <= Utc::now() {
            return Ok(None);
        }

        let mx_patterns: Vec<String> =
            serde_json::from_str(&mx_json).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        Ok(Some(CachedMtaStsPolicy {
            domain,
            policy_id,
            mode,
            mx_patterns,
            max_age_secs,
            fetched_at,
            expires_at,
        }))
    }

    /// Insert or replace the cached policy for `domain`.
    ///
    /// `fetched_at` is set to `Utc::now()`; `expires_at` is `now + max_age_secs`.
    pub async fn store(
        &self,
        domain: &str,
        policy_id: &str,
        mode: &str,
        mx_patterns: &[String],
        max_age_secs: u32,
    ) -> Result<(), sqlx::Error> {
        let mx_json =
            serde_json::to_string(mx_patterns).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;

        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(i64::from(max_age_secs));

        let fetched_str = now.to_rfc3339();
        let expires_str = expires_at.to_rfc3339();

        sqlx::query(
            "INSERT INTO mta_sts_cache
                 (domain, policy_id, mode, mx_patterns, max_age_secs, fetched_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(domain) DO UPDATE SET
                 policy_id    = excluded.policy_id,
                 mode         = excluded.mode,
                 mx_patterns  = excluded.mx_patterns,
                 max_age_secs = excluded.max_age_secs,
                 fetched_at   = excluded.fetched_at,
                 expires_at   = excluded.expires_at",
        )
        .bind(domain)
        .bind(policy_id)
        .bind(mode)
        .bind(&mx_json)
        .bind(max_age_secs as i64)
        .bind(&fetched_str)
        .bind(&expires_str)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Return `true` if `entry` is still valid for the observed DNS `policy_id`.
    ///
    /// An entry is valid when both conditions hold:
    /// 1. `entry.policy_id` matches the current DNS `_mta-sts` TXT record value.
    /// 2. `entry.expires_at` is in the future.
    ///
    /// If the DNS policy_id has rotated (policy was updated by the remote domain)
    /// the cache entry must be discarded even if it has not yet expired.
    pub fn is_valid(entry: &CachedMtaStsPolicy, dns_policy_id: &str) -> bool {
        entry.policy_id == dns_policy_id && entry.expires_at > Utc::now()
    }
}

/// Parse an RFC 3339 timestamp string into `DateTime<Utc>`.
///
/// Maps `chrono::ParseError` to `sqlx::Error::Decode` so callers only deal
/// with `sqlx::Error`.
fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, sqlx::Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_cache() -> (MtaStsCache, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (MtaStsCache::new(pool), tmp)
    }

    // T1: store then get returns the cached entry.
    //
    // Oracle: the value written must be the value read back.
    // mx_patterns round-trips through JSON; timestamps are derived from wall
    // clock but expiry is checked relative to the same clock.
    #[tokio::test]
    async fn store_and_get_returns_entry() {
        let (cache, _tmp) = make_cache().await;
        cache
            .store(
                "example.com",
                "policy-abc",
                "enforce",
                &["*.mx.example.com".to_string()],
                86400,
            )
            .await
            .expect("store");

        let entry = cache
            .get("example.com")
            .await
            .expect("get")
            .expect("should be present");

        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.policy_id, "policy-abc");
        assert_eq!(entry.mode, "enforce");
        assert_eq!(entry.mx_patterns, vec!["*.mx.example.com".to_string()]);
        assert_eq!(entry.max_age_secs, 86400);
    }

    // T2: get for an unknown domain returns None.
    //
    // Oracle: a SELECT that matches no rows must return None, not an error.
    #[tokio::test]
    async fn get_unknown_domain_returns_none() {
        let (cache, _tmp) = make_cache().await;
        let result = cache.get("unknown.example.com").await.expect("get");
        assert!(result.is_none());
    }

    // T3: a second store for the same domain replaces the first.
    //
    // Oracle: ON CONFLICT UPDATE must overwrite every column, so the second
    // store's values are the canonical answer.
    #[tokio::test]
    async fn store_overwrites_existing_entry() {
        let (cache, _tmp) = make_cache().await;

        cache
            .store(
                "example.com",
                "policy-v1",
                "testing",
                &["mx1.example.com".to_string()],
                3600,
            )
            .await
            .expect("first store");

        cache
            .store(
                "example.com",
                "policy-v2",
                "enforce",
                &["mx2.example.com".to_string()],
                7200,
            )
            .await
            .expect("second store");

        let entry = cache
            .get("example.com")
            .await
            .expect("get")
            .expect("should be present");

        assert_eq!(entry.policy_id, "policy-v2");
        assert_eq!(entry.mode, "enforce");
        assert_eq!(entry.mx_patterns, vec!["mx2.example.com".to_string()]);
        assert_eq!(entry.max_age_secs, 7200);
    }

    // T4: is_valid returns true when policy_id matches and not expired.
    //
    // Oracle: entry.expires_at set to a future timestamp; dns_policy_id matches.
    #[test]
    fn is_valid_matching_id_and_not_expired() {
        let entry = CachedMtaStsPolicy {
            domain: "example.com".to_string(),
            policy_id: "abc".to_string(),
            mode: "enforce".to_string(),
            mx_patterns: vec![],
            max_age_secs: 86400,
            fetched_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(3600),
        };
        assert!(MtaStsCache::is_valid(&entry, "abc"));
    }

    // T5: is_valid returns false when policy_id does not match.
    //
    // Oracle: a rotated DNS policy must invalidate the cache even if unexpired.
    #[test]
    fn is_valid_mismatched_policy_id() {
        let entry = CachedMtaStsPolicy {
            domain: "example.com".to_string(),
            policy_id: "old".to_string(),
            mode: "enforce".to_string(),
            mx_patterns: vec![],
            max_age_secs: 86400,
            fetched_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(3600),
        };
        assert!(!MtaStsCache::is_valid(&entry, "new"));
    }

    // T6: is_valid returns false when the entry is expired.
    //
    // Oracle: expires_at set in the past; is_valid must return false.
    #[test]
    fn is_valid_expired_entry() {
        let entry = CachedMtaStsPolicy {
            domain: "example.com".to_string(),
            policy_id: "abc".to_string(),
            mode: "enforce".to_string(),
            mx_patterns: vec![],
            max_age_secs: 1,
            fetched_at: Utc::now() - chrono::Duration::seconds(7200),
            expires_at: Utc::now() - chrono::Duration::seconds(3600),
        };
        assert!(!MtaStsCache::is_valid(&entry, "abc"));
    }

    // T7: get returns None for an entry whose expires_at is in the past.
    //
    // Oracle: the get() method filters expired rows server-side.
    // We write directly via raw SQL with an already-past expires_at to avoid
    // any timing dependency.
    #[tokio::test]
    async fn get_returns_none_for_expired_entry() {
        let (cache, _tmp) = make_cache().await;

        let past = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        sqlx::query(
            "INSERT INTO mta_sts_cache
                 (domain, policy_id, mode, mx_patterns, max_age_secs, fetched_at, expires_at)
             VALUES ('expired.example.com', 'pid', 'none', '[]', 60, ?, ?)",
        )
        .bind(&past)
        .bind(&past)
        .execute(&cache.pool)
        .await
        .expect("raw insert");

        let result = cache.get("expired.example.com").await.expect("get");
        assert!(result.is_none(), "expired entry must not be returned");
    }

    // T8: multiple mx_patterns round-trip through JSON correctly.
    //
    // Oracle: serde_json serialises Vec<String> to a JSON array; deserialising
    // it must recover the original slice in the original order.
    #[tokio::test]
    async fn mx_patterns_round_trip() {
        let (cache, _tmp) = make_cache().await;
        let patterns = vec![
            "*.mx.example.com".to_string(),
            "mx1.example.com".to_string(),
            "mx2.example.com".to_string(),
        ];
        cache
            .store("example.com", "pid", "testing", &patterns, 3600)
            .await
            .expect("store");

        let entry = cache
            .get("example.com")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(entry.mx_patterns, patterns);
    }
}
