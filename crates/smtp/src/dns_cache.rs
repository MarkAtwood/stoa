use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Instant,
};

use mail_auth::{MX, ResolverCache, Txt};

/// A single DNS record cache bucket: maps keys to `(value, valid_until)` pairs.
///
/// On `get`, entries whose `valid_until` has elapsed are removed and `None` is
/// returned.  On `insert`, the new entry replaces any existing entry for the
/// same key.  `remove` unconditionally removes and returns the stored value.
pub(crate) struct Bucket<K, V>(Mutex<HashMap<K, (V, Instant)>>);

impl<K: Hash + Eq, V: Clone> Bucket<K, V> {
    fn new() -> Self {
        Bucket(Mutex::new(HashMap::new()))
    }
}

impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for Bucket<K, V> {
    fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut map = self.0.lock().unwrap();
        let expired = map
            .get(key)
            .is_some_and(|(_, valid_until)| *valid_until <= Instant::now());
        if expired {
            map.remove(key);
            return None;
        }
        map.get(key).map(|(v, _)| v.clone())
    }

    fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().unwrap().remove(key).map(|(v, _)| v)
    }

    fn insert(&self, key: K, value: V, valid_until: Instant) {
        self.0.lock().unwrap().insert(key, (value, valid_until));
    }
}

/// Application-level DNS record cache for the inbound authentication pipeline.
///
/// One shared instance is created at startup and passed by `Arc` reference to
/// every SMTP session.  Cache misses fall through to the underlying
/// `MessageAuthenticator` resolver.  Expired entries are evicted lazily on the
/// first read after their TTL elapses.
///
/// The five buckets match the five `ResolverCache` type parameters required by
/// `mail_auth::Parameters`:
/// - `txt`  — TXT records (SPF, DKIM keys, DMARC policies)
/// - `mx`   — MX records
/// - `ipv4` — A (IPv4 address) records
/// - `ipv6` — AAAA (IPv6 address) records
/// - `ptr`  — PTR (reverse-DNS) records
pub struct DnsCache {
    pub(crate) txt: Bucket<Box<str>, Txt>,
    pub(crate) mx: Bucket<Box<str>, Arc<[MX]>>,
    pub(crate) ipv4: Bucket<Box<str>, Arc<[Ipv4Addr]>>,
    pub(crate) ipv6: Bucket<Box<str>, Arc<[Ipv6Addr]>>,
    pub(crate) ptr: Bucket<IpAddr, Arc<[Box<str>]>>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        DnsCache {
            txt: Bucket::new(),
            mx: Bucket::new(),
            ipv4: Bucket::new(),
            ipv6: Bucket::new(),
            ptr: Bucket::new(),
        }
    }
}
