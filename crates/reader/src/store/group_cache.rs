//! In-memory TTL cache for group metadata.
//!
//! Reduces SQLite round-trips for frequently-queried group statistics. Entries
//! expire after the configured TTL and are lazily evicted on read. Writers must
//! call [`GroupMetadataCache::invalidate`] or [`GroupMetadataCache::invalidate_all`]
//! to ensure readers see fresh data.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Cached metadata for a single newsgroup.
#[derive(Debug, Clone)]
pub struct GroupMetadata {
    pub name: String,
    pub count: u64,
    pub low: u64,
    pub high: u64,
    pub description: String,
}

struct CacheEntry {
    metadata: GroupMetadata,
    inserted_at: Instant,
}

/// In-memory TTL cache for group metadata.
pub struct GroupMetadataCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl GroupMetadataCache {
    /// Create a new cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Create with a default 5-second TTL.
    pub fn new_default() -> Self {
        Self::new(Duration::from_secs(5))
    }

    /// Get metadata for a group if cached and not expired.
    ///
    /// Returns `None` on cache miss or if the entry has exceeded the TTL.
    pub async fn get(&self, group_name: &str) -> Option<GroupMetadata> {
        let entries = self.entries.read().await;
        let entry = entries.get(group_name)?;
        if entry.inserted_at.elapsed() >= self.ttl {
            return None;
        }
        Some(entry.metadata.clone())
    }

    /// Insert or update metadata for a group.
    pub async fn insert(&self, metadata: GroupMetadata) {
        let mut entries = self.entries.write().await;
        entries.insert(
            metadata.name.clone(),
            CacheEntry {
                metadata,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Invalidate the cache entry for a single group (call on write).
    pub async fn invalidate(&self, group_name: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(group_name);
    }

    /// Invalidate all entries (call on any write that affects multiple groups).
    pub async fn invalidate_all(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_meta(name: &str) -> GroupMetadata {
        GroupMetadata {
            name: name.to_string(),
            count: 42,
            low: 1,
            high: 42,
            description: format!("Test group {name}"),
        }
    }

    #[tokio::test]
    async fn cache_miss_returns_none() {
        let cache = GroupMetadataCache::new_default();
        assert!(cache.get("comp.lang.rust").await.is_none());
    }

    #[tokio::test]
    async fn cache_hit_returns_value() {
        let cache = GroupMetadataCache::new_default();
        let meta = make_meta("comp.lang.rust");
        cache.insert(meta).await;

        let result = cache.get("comp.lang.rust").await;
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.name, "comp.lang.rust");
        assert_eq!(result.count, 42);
        assert_eq!(result.low, 1);
        assert_eq!(result.high, 42);
        assert_eq!(result.description, "Test group comp.lang.rust");
    }

    #[tokio::test]
    async fn cache_expired_returns_none() {
        let cache = GroupMetadataCache::new(Duration::from_millis(1));
        cache.insert(make_meta("comp.lang.rust")).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(cache.get("comp.lang.rust").await.is_none());
    }

    #[tokio::test]
    async fn invalidate_removes_entry() {
        let cache = GroupMetadataCache::new_default();
        cache.insert(make_meta("comp.lang.rust")).await;
        cache.invalidate("comp.lang.rust").await;
        assert!(cache.get("comp.lang.rust").await.is_none());
    }

    #[tokio::test]
    async fn invalidate_all_clears_cache() {
        let cache = GroupMetadataCache::new_default();
        cache.insert(make_meta("comp.lang.rust")).await;
        cache.insert(make_meta("alt.test")).await;
        cache.insert(make_meta("sci.math")).await;
        cache.invalidate_all().await;
        assert!(cache.get("comp.lang.rust").await.is_none());
        assert!(cache.get("alt.test").await.is_none());
        assert!(cache.get("sci.math").await.is_none());
    }

    #[tokio::test]
    async fn concurrent_reads_dont_deadlock() {
        use std::sync::Arc;

        let cache = Arc::new(GroupMetadataCache::new_default());
        cache.insert(make_meta("comp.lang.rust")).await;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let c = Arc::clone(&cache);
                tokio::spawn(async move { c.get("comp.lang.rust").await })
            })
            .collect();

        for handle in handles {
            let result = handle.await.expect("task panicked");
            assert!(result.is_some());
        }
    }

    #[tokio::test]
    async fn insert_overwrites_existing() {
        let cache = GroupMetadataCache::new_default();

        let first = GroupMetadata {
            name: "comp.lang.rust".to_string(),
            count: 10,
            low: 1,
            high: 10,
            description: "first".to_string(),
        };
        cache.insert(first).await;

        let second = GroupMetadata {
            name: "comp.lang.rust".to_string(),
            count: 99,
            low: 1,
            high: 99,
            description: "second".to_string(),
        };
        cache.insert(second).await;

        let result = cache.get("comp.lang.rust").await.unwrap();
        assert_eq!(result.count, 99);
        assert_eq!(result.description, "second");
    }
}
