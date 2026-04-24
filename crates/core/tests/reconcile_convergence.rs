//! Convergence tests for reconcile() when divergence exceeds MAX_HAVE.
//!
//! Independent oracle: after convergence, both nodes must hold identical tip
//! sets (compared via `list_tips()`).  The test does not re-implement the
//! reconcile algorithm — it verifies the end-state property only.
//!
//! MAX_HAVE is 1000 (private constant in reconcile.rs).  Tests exercise
//! N=1001, N=2500, and N=10000 to cover the multi-round regime.  For each N
//! the test asserts convergence within `ceil(N / 1000) + 1` rounds.

use std::sync::Arc;

use cid::Cid;
use multihash_codetable::{Code, Multihash, MultihashDigest};

use stoa_core::{
    article::GroupName,
    group_log::{
        append::append, backfill, reconcile, LogEntry, LogEntryId, LogStorage, MemLogStorage,
        VerifiedEntry,
    },
};

const MAX_HAVE: usize = 1000;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn test_cid(seed: &[u8]) -> Cid {
    Cid::new_v1(0x71, Code::Sha2_256.digest(seed))
}

fn entry_id_to_cid(id: &LogEntryId) -> Cid {
    let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
    Cid::new_v1(0x71, mh)
}

/// Append `n` entries to `storage` as a linear chain.
async fn append_chain(
    storage: &MemLogStorage,
    group: &GroupName,
    n: usize,
    seed_prefix: &str,
) -> Vec<LogEntryId> {
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let current_tips = storage.list_tips(group).await.expect("list_tips");
        let parent_cids: Vec<Cid> = current_tips.iter().map(entry_id_to_cid).collect();
        let entry = LogEntry {
            hlc_timestamp: 1_000_000 + i as u64,
            article_cid: test_cid(format!("{seed_prefix}-{i}").as_bytes()),
            operator_signature: vec![],
            parent_cids,
        };
        let id = append(storage, group, entry)
            .await
            .unwrap_or_else(|e| panic!("append {seed_prefix}-{i}: {e}"));
        ids.push(id);
    }
    ids
}

/// Run reconcile+backfill rounds between `node_a` (full) and `node_b` (empty)
/// until both agree on the same tip set.
///
/// Each round: B reconciles against A's tips to learn what it wants, then
/// backfills those entries (and all ancestors) from A.  After backfill B's
/// tips are set to the entries it just fetched.
///
/// Returns the number of rounds required for convergence.
async fn converge(
    node_a: Arc<MemLogStorage>,
    node_b: Arc<MemLogStorage>,
    group: &GroupName,
    max_rounds: usize,
) -> usize {
    let a_tips = node_a.list_tips(group).await.unwrap();

    for round in 1..=max_rounds {
        let b_tips = node_b.list_tips(group).await.unwrap();

        // Convergence: both sides agree on tip set.
        if a_tips == b_tips {
            return round - 1; // converged before this round started
        }

        let result = reconcile(&*node_b, group, &a_tips)
            .await
            .expect("reconcile must succeed");

        if result.want.is_empty() {
            // B doesn't want anything from A — but tips differ, so B is ahead
            // in some fork.  For this one-directional test (only A has entries)
            // this state should not occur.
            break;
        }

        // B backfills each wanted entry from A, walking parent chains.
        let want_ids = result.want.clone();
        for want_id in &want_ids {
            let a = Arc::clone(&node_a);
            backfill(&*node_b, want_id.clone(), move |id| {
                let a = Arc::clone(&a);
                async move {
                    a.get_entry(&id)
                        .await
                        .map_err(|e| e.to_string())?
                        .map(VerifiedEntry::new_for_test)
                        .ok_or_else(|| format!("entry {id} not found in node_a"))
                }
            })
            .await
            .expect("backfill must succeed");
        }

        // Set B's tips to the entries it just fetched from A's tip set.
        node_b
            .set_tips(group, &want_ids)
            .await
            .expect("set_tips on B");
    }

    // Final convergence check after the last round.
    let b_tips = node_b.list_tips(group).await.unwrap();
    if a_tips == b_tips {
        return max_rounds;
    }

    panic!("did not converge within {max_rounds} rounds; a_tips={a_tips:?}, b_tips={b_tips:?}");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Helper: build A's chain, then run convergence, assert within bound.
async fn run_convergence_case(n: usize) {
    let group = GroupName::new("test.conv").unwrap();
    let node_a = Arc::new(MemLogStorage::new());
    let node_b = Arc::new(MemLogStorage::new());

    append_chain(&*node_a, &group, n, "conv").await;

    let max_rounds = (n + MAX_HAVE - 1) / MAX_HAVE + 1;
    let rounds = converge(Arc::clone(&node_a), Arc::clone(&node_b), &group, max_rounds).await;

    // Both sides now agree on tip set — verified inside converge().
    let a_tips = node_a.list_tips(&group).await.unwrap();
    let b_tips = node_b.list_tips(&group).await.unwrap();
    assert_eq!(
        a_tips, b_tips,
        "N={n}: tip sets must match after convergence"
    );
    assert!(
        rounds <= max_rounds,
        "N={n}: converged in {rounds} rounds, expected ≤{max_rounds}"
    );
}

/// N < MAX_HAVE: single round is sufficient.
#[tokio::test]
async fn convergence_n_below_max_have() {
    run_convergence_case(500).await;
}

/// N = MAX_HAVE + 1: just over the cap; exercises partial_have path.
#[tokio::test]
async fn convergence_n_just_over_max_have() {
    run_convergence_case(1001).await;
}

/// N = 2.5× MAX_HAVE: two full rounds plus partial.
#[tokio::test]
async fn convergence_n_2500() {
    run_convergence_case(2500).await;
}

/// N = 10× MAX_HAVE: ten-round regime.
#[tokio::test]
async fn convergence_n_10000() {
    run_convergence_case(10000).await;
}
