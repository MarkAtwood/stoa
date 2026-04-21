use std::collections::{HashSet, VecDeque};

use crate::error::StorageError;
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};

/// Error returned by [`backfill`].
#[derive(Debug)]
pub enum BackfillError {
    /// A storage operation failed.
    Storage(StorageError),
    /// The fetch callback returned an error for the given entry ID.
    FetchFailed(String),
}

impl std::fmt::Display for BackfillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::FetchFailed(msg) => write!(f, "fetch failed: {msg}"),
        }
    }
}

impl std::error::Error for BackfillError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::FetchFailed(_) => None,
        }
    }
}

impl From<StorageError> for BackfillError {
    fn from(e: StorageError) -> Self {
        BackfillError::Storage(e)
    }
}

/// Backfill a DAG starting from `want_id`, fetching all ancestors not already
/// in local storage.
///
/// `fetch` is a callback that retrieves a `LogEntry` by its `LogEntryId` from
/// a remote source.  Returns the number of entries fetched and inserted.
///
/// If `want_id` is already present in local storage the function returns
/// `Ok(0)` immediately without issuing any fetch calls.
///
/// # Security requirement for remote fetch
///
/// This function inserts whatever the `fetch` callback returns.  When `fetch`
/// retrieves entries from an untrusted remote peer, the callback **must** call
/// [`crate::group_log::verify::verify_entry`] on each entry before returning
/// it.  Skipping that call means forged or tampered log entries — including
/// ones with invalid operator signatures or phantom parent chains — can enter
/// local storage undetected and be propagated to other peers.
///
/// Algorithm (BFS):
/// 1. If `want_id` already in storage: return `Ok(0)`.
/// 2. Add `want_id` to the queue.
/// 3. While queue non-empty:
///    a. Pop an entry ID.
///    b. If already in storage or visited: skip.
///    c. Mark as visited.
///    d. Call `fetch(entry_id)` — propagates `BackfillError::FetchFailed` on error.
///    e. Insert the entry into storage.
///    f. Enqueue parents not yet in local storage (via CID multihash digest).
/// 4. Return `Ok(entries_fetched_count)`.
pub async fn backfill<S, F, Fut>(
    storage: &S,
    want_id: LogEntryId,
    fetch: F,
) -> Result<usize, BackfillError>
where
    S: LogStorage,
    F: Fn(LogEntryId) -> Fut,
    Fut: std::future::Future<Output = Result<LogEntry, String>>,
{
    if storage.has_entry(&want_id).await? {
        return Ok(0);
    }

    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut queue: VecDeque<LogEntryId> = VecDeque::new();
    let mut fetched_count: usize = 0;

    queue.push_back(want_id);

    while let Some(entry_id) = queue.pop_front() {
        let key = *entry_id.as_bytes();

        if visited.contains(&key) {
            continue;
        }

        if storage.has_entry(&entry_id).await? {
            continue;
        }

        visited.insert(key);

        let entry = fetch(entry_id.clone())
            .await
            .map_err(BackfillError::FetchFailed)?;

        storage
            .insert_entry(entry_id.clone(), entry.clone())
            .await?;
        fetched_count += 1;

        for parent_cid in &entry.parent_cids {
            let digest_bytes = parent_cid.hash().digest();
            if let Ok(raw) = <[u8; 32]>::try_from(digest_bytes) {
                let parent_id = LogEntryId::from_bytes(raw);
                if !storage.has_entry(&parent_id).await? {
                    queue.push_back(parent_id);
                }
            }
        }
    }

    Ok(fetched_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, Multihash, MultihashDigest};

    use crate::group_log::mem_storage::MemLogStorage;
    use crate::group_log::storage::LogStorage;
    use crate::group_log::types::{LogEntry, LogEntryId};

    /// Derive a `LogEntryId` by SHA-256 hashing an arbitrary seed.
    fn make_entry_id(seed: &[u8]) -> LogEntryId {
        let digest = Code::Sha2_256.digest(seed);
        LogEntryId::from_bytes(
            digest
                .digest()
                .try_into()
                .expect("SHA2-256 digest is always 32 bytes"),
        )
    }

    /// Wrap a `LogEntryId` as a CID so it can appear in `parent_cids`.
    fn entry_id_to_cid(id: &LogEntryId) -> Cid {
        let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
        Cid::new_v1(0x71, mh)
    }

    /// Build a minimal `LogEntry` with the given HLC timestamp, article seed, and
    /// parent CIDs.
    fn make_entry(hlc: u64, article_seed: &[u8], parents: Vec<Cid>) -> LogEntry {
        LogEntry {
            hlc_timestamp: hlc,
            article_cid: Cid::new_v1(0x71, Code::Sha2_256.digest(article_seed)),
            operator_signature: vec![],
            parent_cids: parents,
        }
    }

    /// Build `n` entries in a chain: genesis → e1 → e2 → … → e_{n-1}.
    /// Each entry (except genesis) has one parent.
    ///
    /// Returns `(storage, vec_of_entry_ids)` where index 0 is the genesis and
    /// index `n-1` is the tip.
    async fn make_chain(n: usize) -> (MemLogStorage, Vec<LogEntryId>) {
        assert!(n >= 1, "chain must have at least one entry");
        let storage = MemLogStorage::new();
        let mut ids: Vec<LogEntryId> = Vec::with_capacity(n);

        for i in 0..n {
            let seed = format!("chain-entry-{i}");
            let id = make_entry_id(seed.as_bytes());

            let parents = if i == 0 {
                vec![]
            } else {
                vec![entry_id_to_cid(&ids[i - 1])]
            };

            let entry = make_entry(i as u64 * 1_000, format!("article-{i}").as_bytes(), parents);
            storage
                .insert_entry(id.clone(), entry)
                .await
                .expect("insert chain entry");

            ids.push(id);
        }

        (storage, ids)
    }

    // ── backfill_single_entry ─────────────────────────────────────────────────

    #[tokio::test]
    async fn backfill_single_entry() {
        let (remote, ids) = make_chain(1).await;
        let local = MemLogStorage::new();

        let tip_id = ids[0].clone();

        let count = backfill(&local, tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
            }
        })
        .await
        .expect("backfill should succeed");

        assert_eq!(count, 1, "expected 1 entry fetched");
        assert!(
            local.has_entry(&tip_id).await.unwrap(),
            "entry must be in local storage after backfill"
        );
    }

    // ── backfill_chain_100 ────────────────────────────────────────────────────

    #[tokio::test]
    async fn backfill_chain_100() {
        let (remote, ids) = make_chain(100).await;
        let local = MemLogStorage::new();

        let tip_id = ids[99].clone();

        let count = backfill(&local, tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
            }
        })
        .await
        .expect("backfill should succeed");

        assert_eq!(count, 100, "expected all 100 entries fetched");
        for id in &ids {
            assert!(
                local.has_entry(id).await.unwrap(),
                "entry {id} must be in local storage"
            );
        }
    }

    // ── backfill_idempotent ───────────────────────────────────────────────────

    #[tokio::test]
    async fn backfill_idempotent() {
        let (remote, ids) = make_chain(5).await;
        let local = MemLogStorage::new();

        let tip_id = ids[4].clone();

        let count_first = backfill(&local, tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
            }
        })
        .await
        .expect("first backfill should succeed");

        assert_eq!(count_first, 5, "first backfill must fetch 5 entries");

        let count_second = backfill(&local, tip_id.clone(), |id| {
            let r = &remote;
            async move {
                r.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
            }
        })
        .await
        .expect("second backfill should succeed");

        assert_eq!(
            count_second, 0,
            "second backfill must return 0 (already have tip)"
        );
    }

    // ── backfill_diamond_dag ──────────────────────────────────────────────────
    //
    //  A (genesis, no parents)
    //  ├── B (parent: A)
    //  └── C (parent: A)
    //       └── D (parents: B, C)
    //
    //  Backfill D from an empty local store.  All four entries must be fetched
    //  exactly once.

    #[tokio::test]
    async fn backfill_diamond_dag() {
        let remote = MemLogStorage::new();

        let id_a = make_entry_id(b"diamond-A");
        let id_b = make_entry_id(b"diamond-B");
        let id_c = make_entry_id(b"diamond-C");
        let id_d = make_entry_id(b"diamond-D");

        let entry_a = make_entry(1_000, b"art-A", vec![]);
        let entry_b = make_entry(2_000, b"art-B", vec![entry_id_to_cid(&id_a)]);
        let entry_c = make_entry(2_001, b"art-C", vec![entry_id_to_cid(&id_a)]);
        let entry_d = make_entry(
            3_000,
            b"art-D",
            vec![entry_id_to_cid(&id_b), entry_id_to_cid(&id_c)],
        );

        remote.insert_entry(id_a.clone(), entry_a).await.unwrap();
        remote.insert_entry(id_b.clone(), entry_b).await.unwrap();
        remote.insert_entry(id_c.clone(), entry_c).await.unwrap();
        remote.insert_entry(id_d.clone(), entry_d).await.unwrap();

        let local = MemLogStorage::new();
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fetch_count_clone = fetch_count.clone();

        let count = backfill(&local, id_d.clone(), |id| {
            let remote_ref = &remote;
            let counter = fetch_count_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                remote_ref
                    .get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found: {id}"))
            }
        })
        .await
        .expect("diamond backfill should succeed");

        assert_eq!(count, 4, "all 4 diamond entries must be fetched");
        assert_eq!(
            fetch_count.load(Ordering::SeqCst),
            4,
            "fetch callback must be called exactly 4 times (no duplicates)"
        );
        for (label, id) in [("A", &id_a), ("B", &id_b), ("C", &id_c), ("D", &id_d)] {
            assert!(
                local.has_entry(id).await.unwrap(),
                "entry {label} must be in local storage"
            );
        }
    }

    // ── backfill_fetch_failure ────────────────────────────────────────────────

    #[tokio::test]
    async fn backfill_fetch_failure() {
        let local = MemLogStorage::new();
        let missing_id = make_entry_id(b"does-not-exist");

        let result = backfill(&local, missing_id, |id| async move {
            Err(format!("remote has no entry {id}"))
        })
        .await;

        assert!(
            matches!(result, Err(BackfillError::FetchFailed(_))),
            "expected BackfillError::FetchFailed, got {result:?}"
        );
    }

    // ── backfill_already_local_returns_zero ───────────────────────────────────

    #[tokio::test]
    async fn backfill_already_local_returns_zero() {
        let local = MemLogStorage::new();
        let id = make_entry_id(b"already-local");
        let entry = make_entry(42, b"art-local", vec![]);

        local.insert_entry(id.clone(), entry).await.unwrap();

        let count = backfill(&local, id.clone(), |_id| async move {
            Err("fetch must not be called".to_string())
        })
        .await
        .expect("backfill should succeed");

        assert_eq!(
            count, 0,
            "entry already in local storage: must return Ok(0)"
        );
    }
}
