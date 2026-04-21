//! Deterministic integration tests for the group log CRDT merge and backfill.
//!
//! No randomness and no `SystemTime::now()` are used.  All timestamps are
//! fixed constants and all CIDs are derived from deterministic seed bytes.
//!
//! Independent oracle: the entry IDs produced here are SHA-256 hashes of the
//! canonical byte concatenation defined in `append::compute_entry_id`.  The
//! test assertions check end-to-end CRDT properties (convergence, backfill
//! completeness) rather than replicating the hash function — so the tests are
//! not self-referential.

use std::sync::Arc;

use cid::Cid;
use multihash_codetable::{Code, Multihash, MultihashDigest};

use usenet_ipfs_core::{
    article::GroupName,
    group_log::{
        append::append, backfill, reconcile, LogEntry, LogEntryId, LogStorage, MemLogStorage,
        VerifiedEntry,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a DAG-CBOR CIDv1 whose multihash digest is SHA-256 of `seed`.
/// Used to create article CIDs that are fully deterministic and unique per seed.
fn test_cid(seed: &[u8]) -> Cid {
    Cid::new_v1(0x71, Code::Sha2_256.digest(seed))
}

/// Convert a `LogEntryId` to a CID so it can appear in `parent_cids`.
///
/// Mirrors the convention established in `append.rs`: SHA2-256 multihash
/// (code 0x12) wrapping the 32 raw bytes, DAG-CBOR codec (0x71).
fn entry_id_to_cid(id: &LogEntryId) -> Cid {
    let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
    Cid::new_v1(0x71, mh)
}

/// Append `n` entries to `storage` forming a linear chain.
///
/// Each entry uses the current tips of `group` as its parents, making this a
/// strictly sequential chain.  The HLC wall timestamp is `base_wall_ms + i`
/// for entry `i`, ensuring every entry has a unique, monotonically increasing
/// timestamp within the chain.
///
/// `seed_prefix` is mixed into the article CID seed so that chains built on
/// different replicas produce different article CIDs even when `i` overlaps.
///
/// Returns the `LogEntryId`s in append order (index 0 = first appended).
async fn append_chain(
    storage: &MemLogStorage,
    group: &GroupName,
    base_wall_ms: u64,
    n: usize,
    seed_prefix: &str,
) -> Vec<LogEntryId> {
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        // Collect current tips and express them as parent CIDs.
        let current_tips = storage.list_tips(group).await.expect("list_tips");
        let parent_cids: Vec<Cid> = current_tips.iter().map(entry_id_to_cid).collect();

        let entry = LogEntry {
            hlc_timestamp: base_wall_ms + i as u64,
            article_cid: test_cid(format!("{seed_prefix}-{i}").as_bytes()),
            operator_signature: vec![],
            parent_cids,
        };

        let id = append(storage, group, entry)
            .await
            .unwrap_or_else(|e| panic!("append {seed_prefix}-{i} failed: {e}"));
        ids.push(id);
    }
    ids
}

// ── crdt_merge_and_backfill_convergence ───────────────────────────────────────

/// Full CRDT convergence test with a 50-entry shared trunk, then a 10-entry
/// fork on each replica.
///
/// Scenario
/// --------
/// Phase 1  — Replica A builds a 50-entry chain (entries a-0 … a-49).
/// Phase 2  — Replica B receives a copy of entries 0–39 from A (the shared
///            prefix).  B's tip is set to a-39.
/// Phase 3  — Both replicas diverge:
///            • A already has entries a-40 … a-49 (added in Phase 1).
///            • B appends 10 independent entries b-0 … b-9.
/// Phase 4  — A reconciles against B's tips → A should want B's fork entries.
/// Phase 5  — A backfills the missing entries from B.
/// Phase 6  — B reconciles against A's tips → B should want A's fork entries.
/// Phase 7  — B backfills the missing entries from A.
/// Phase 8  — Convergence: every entry from both forks is present on both
///            replicas.
///
/// The test does NOT assert that the tip sets are identical — each replica's
/// tip is set by its own last `append()` call.  What converges is the entry
/// store: both replicas hold the union of all 60 entries (50 shared + 10 from
/// A's fork + 10 from B's fork).
#[tokio::test]
async fn crdt_merge_and_backfill_convergence() {
    let group = GroupName::new("test.group").unwrap();

    // ── Phase 1: build 50-entry chain on Replica A ───────────────────────────
    let replica_a = Arc::new(MemLogStorage::new());

    // Base wall time for A's entries.  B's fork uses a different base to
    // guarantee distinct article CIDs and therefore distinct entry IDs even
    // when the loop index `i` matches.
    let chain_a = append_chain(&*replica_a, &group, 1_000_000, 50, "a").await;
    assert_eq!(chain_a.len(), 50, "chain_a must have 50 entries");

    // ── Phase 2: copy entries 0–39 to Replica B ──────────────────────────────
    let replica_b = Arc::new(MemLogStorage::new());

    for id in &chain_a[..40] {
        let entry = replica_a
            .get_entry(id)
            .await
            .expect("get_entry from A")
            .unwrap_or_else(|| panic!("entry {id} missing from A"));
        replica_b
            .insert_entry(id.clone(), entry)
            .await
            .expect("insert_entry into B");
    }
    // Set B's tip to the 40th entry (index 39) — the shared prefix boundary.
    replica_b
        .set_tips(&group, &[chain_a[39].clone()])
        .await
        .expect("set_tips on B after copy");

    // Sanity: B has 40 entries and its tip is chain_a[39].
    for id in &chain_a[..40] {
        assert!(
            replica_b.has_entry(id).await.unwrap(),
            "B must have shared entry {id} after copy"
        );
    }
    {
        let b_tips = replica_b.list_tips(&group).await.unwrap();
        assert_eq!(
            b_tips,
            vec![chain_a[39].clone()],
            "B's tip must be chain_a[39]"
        );
    }

    // ── Phase 3: replicas diverge ────────────────────────────────────────────
    // A already has entries a-40 … a-49 from Phase 1.
    let chain_a_fork: Vec<LogEntryId> = chain_a[40..].to_vec();
    assert_eq!(chain_a_fork.len(), 10, "A's fork must have 10 entries");

    // B appends 10 independent entries rooted at chain_a[39].
    // Use wall time 1_100_000 to guarantee different timestamps (and thus
    // different entry IDs) from A's fork entries which start at 1_000_040.
    let chain_b_fork = append_chain(&*replica_b, &group, 1_100_000, 10, "b").await;
    assert_eq!(chain_b_fork.len(), 10, "B's fork must have 10 entries");

    // The two forks must be entirely disjoint.
    for id_a in &chain_a_fork {
        for id_b in &chain_b_fork {
            assert_ne!(id_a, id_b, "A's and B's fork entries must be distinct");
        }
    }

    // ── Phase 4: reconcile A → B ────────────────────────────────────────────
    // "What does B have that A doesn't?"
    let b_tips = replica_b.list_tips(&group).await.unwrap();
    let result_a = reconcile(&*replica_a, &group, &b_tips)
        .await
        .expect("reconcile A→B");

    // A's tip is chain_a[49] and B's tip is chain_b_fork[9].  B's tip is not
    // in A's storage, so A must want it.
    assert!(
        !result_a.want.is_empty(),
        "A must want B's diverged entries; got empty want set"
    );
    for wanted in &result_a.want {
        assert!(
            !replica_a.has_entry(wanted).await.unwrap(),
            "A must not yet have an entry it claims to want: {wanted}"
        );
    }

    // ── Phase 5: backfill A from B ───────────────────────────────────────────
    for want_id in &result_a.want {
        let replica_b_ref = Arc::clone(&replica_b);
        let want_id_clone = want_id.clone();
        backfill(&*replica_a, want_id_clone, |id| {
            let rb = Arc::clone(&replica_b_ref);
            async move {
                rb.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found on B: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await
        .expect("backfill A from B");
    }

    // After backfill, A must have all of B's fork entries.
    for id in &chain_b_fork {
        assert!(
            replica_a.has_entry(id).await.unwrap(),
            "A must have B's fork entry {id} after backfill"
        );
    }

    // ── Phase 6: reconcile B → A ────────────────────────────────────────────
    // "What does A have that B doesn't?"
    let a_tips = replica_a.list_tips(&group).await.unwrap();
    let result_b = reconcile(&*replica_b, &group, &a_tips)
        .await
        .expect("reconcile B→A");

    assert!(
        !result_b.want.is_empty(),
        "B must want A's diverged entries; got empty want set"
    );
    for wanted in &result_b.want {
        assert!(
            !replica_b.has_entry(wanted).await.unwrap(),
            "B must not yet have an entry it claims to want: {wanted}"
        );
    }

    // ── Phase 7: backfill B from A ───────────────────────────────────────────
    for want_id in &result_b.want {
        let replica_a_ref = Arc::clone(&replica_a);
        let want_id_clone = want_id.clone();
        backfill(&*replica_b, want_id_clone, |id| {
            let ra = Arc::clone(&replica_a_ref);
            async move {
                ra.get_entry(&id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("entry not found on A: {id}"))
                    .map(VerifiedEntry::new_for_test)
            }
        })
        .await
        .expect("backfill B from A");
    }

    // ── Phase 8: convergence check ───────────────────────────────────────────
    // Both replicas now hold the union of all 60 entries.

    // All shared-prefix entries (a-0 … a-39) present on both.
    for id in &chain_a[..40] {
        assert!(
            replica_a.has_entry(id).await.unwrap(),
            "A must have shared entry {id}"
        );
        assert!(
            replica_b.has_entry(id).await.unwrap(),
            "B must have shared entry {id}"
        );
    }

    // A's fork entries (a-40 … a-49) present on both after backfill.
    for id in &chain_a_fork {
        assert!(
            replica_a.has_entry(id).await.unwrap(),
            "A must have its own fork entry {id}"
        );
        assert!(
            replica_b.has_entry(id).await.unwrap(),
            "B must have A's fork entry {id} after backfill"
        );
    }

    // B's fork entries (b-0 … b-9) present on both after backfill.
    for id in &chain_b_fork {
        assert!(
            replica_a.has_entry(id).await.unwrap(),
            "A must have B's fork entry {id} after backfill"
        );
        assert!(
            replica_b.has_entry(id).await.unwrap(),
            "B must have its own fork entry {id}"
        );
    }

    // Both tip sets are non-empty (log is not empty on either replica).
    let tips_a = replica_a.list_tips(&group).await.unwrap();
    let tips_b = replica_b.list_tips(&group).await.unwrap();
    assert!(
        !tips_a.is_empty(),
        "A must have at least one tip after convergence"
    );
    assert!(
        !tips_b.is_empty(),
        "B must have at least one tip after convergence"
    );
}

// ── crdt_identical_after_full_sync ────────────────────────────────────────────

/// When both replicas are fully in sync, reconcile must report an empty `want`
/// set on both sides.
///
/// The `have` set is NOT asserted to be empty.  The reconcile algorithm only
/// receives the remote's tip IDs, not its full entry list.  Ancestors that are
/// reachable from local tips but not named in `remote_tips` appear in `have`
/// because from the local node's perspective they are worth offering — the
/// algorithm cannot know the remote already holds them.  The key safety
/// invariant for "fully synced" is that neither side wants anything from the
/// other (`want` is empty on both sides).
#[tokio::test]
async fn crdt_identical_after_full_sync() {
    let group = GroupName::new("test.synced").unwrap();

    // Build a 5-entry chain on A.
    let replica_a = Arc::new(MemLogStorage::new());
    let chain = append_chain(&*replica_a, &group, 2_000_000, 5, "sync").await;
    assert_eq!(chain.len(), 5);

    // Copy all entries to B so both replicas hold exactly the same DAG.
    let replica_b = Arc::new(MemLogStorage::new());
    for id in &chain {
        let entry = replica_a
            .get_entry(id)
            .await
            .expect("get_entry")
            .unwrap_or_else(|| panic!("entry {id} missing from A"));
        replica_b
            .insert_entry(id.clone(), entry)
            .await
            .expect("insert_entry into B");
    }
    replica_b
        .set_tips(&group, &[chain[4].clone()])
        .await
        .expect("set_tips on B");

    // Reconcile A against B's tips.
    // A must not want anything — B's tip is already in A's storage.
    let b_tips = replica_b.list_tips(&group).await.unwrap();
    let result_a = reconcile(&*replica_a, &group, &b_tips)
        .await
        .expect("reconcile A→B");

    assert!(
        result_a.want.is_empty(),
        "A must want nothing from fully-synced B; got: {:?}",
        result_a.want
    );

    // Reconcile B against A's tips.
    // B must not want anything — A's tip is already in B's storage.
    let a_tips = replica_a.list_tips(&group).await.unwrap();
    let result_b = reconcile(&*replica_b, &group, &a_tips)
        .await
        .expect("reconcile B→A");

    assert!(
        result_b.want.is_empty(),
        "B must want nothing from fully-synced A; got: {:?}",
        result_b.want
    );
}

// ── backfill_stops_at_already_present_entries ─────────────────────────────────

/// Backfill must stop traversing a chain the moment it reaches an entry that
/// is already in local storage — it must not re-fetch ancestors the local
/// replica already holds.
///
/// Setup: A has entries 0–9.  B has entries 0–4 (shared prefix) and entry 10
/// (a new tip that chains back through entries 0–9 via the missing 5–9).
/// Backfilling entry 10 into B must fetch exactly entries 5–9 and 10 (6 total)
/// and stop when it reaches entry 4 which B already has.
#[tokio::test]
async fn backfill_stops_at_already_present_entries() {
    let group = GroupName::new("test.stop").unwrap();

    // Build a 10-entry chain on the "remote" side.
    let remote = Arc::new(MemLogStorage::new());
    let chain = append_chain(&*remote, &group, 3_000_000, 10, "stop").await;
    assert_eq!(chain.len(), 10);

    // Append one more entry on the remote (entry 10), chaining off entry 9.
    let extra = append_chain(&*remote, &group, 3_000_010, 1, "stop-extra").await;
    assert_eq!(extra.len(), 1);

    // Build a local replica that only has entries 0–4.
    let local = Arc::new(MemLogStorage::new());
    for id in &chain[..5] {
        let entry = remote
            .get_entry(id)
            .await
            .expect("get_entry")
            .unwrap_or_else(|| panic!("entry {id} missing from remote"));
        local
            .insert_entry(id.clone(), entry)
            .await
            .expect("insert_entry into local");
    }
    local
        .set_tips(&group, &[chain[4].clone()])
        .await
        .expect("set_tips");

    // Backfill the extra tip (entry 10) into local.
    // Expected: fetches entries 5, 6, 7, 8, 9, and 10 = 6 entries total.
    let remote_ref = Arc::clone(&remote);
    let fetched = backfill(&*local, extra[0].clone(), |id| {
        let r = Arc::clone(&remote_ref);
        async move {
            r.get_entry(&id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("entry not found on remote: {id}"))
                .map(VerifiedEntry::new_for_test)
        }
    })
    .await
    .expect("backfill");

    assert_eq!(
        fetched, 6,
        "backfill must fetch exactly 6 entries (entries 5–9 + extra tip)"
    );

    // All entries 0–9 and the extra tip must now be in local storage.
    for id in &chain {
        assert!(
            local.has_entry(id).await.unwrap(),
            "local must have chain entry {id}"
        );
    }
    assert!(
        local.has_entry(&extra[0]).await.unwrap(),
        "local must have the extra tip after backfill"
    );
}
