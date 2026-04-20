//! Property-based tests for the group log CRDT.
//!
//! Uses proptest to generate arbitrary diverged group logs and verify
//! reconciliation properties.

use std::collections::HashSet;

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use proptest::prelude::*;
use usenet_ipfs_core::{
    group_log::{
        mem_storage::MemLogStorage,
        reconcile::reconcile,
        storage::LogStorage,
        types::{LogEntry, LogEntryId},
    },
    GroupName,
};

fn make_entry_id(seed: u8) -> LogEntryId {
    let digest = Code::Sha2_256.digest(&[seed]);
    LogEntryId::from_bytes(
        digest
            .digest()
            .try_into()
            .expect("SHA2-256 is 32 bytes"),
    )
}

fn make_entry(hlc: u64) -> LogEntry {
    LogEntry {
        hlc_timestamp: hlc,
        article_cid: Cid::new_v1(0x71, Code::Sha2_256.digest(&[hlc as u8])),
        operator_signature: vec![],
        parent_cids: vec![],
    }
}

fn test_group() -> GroupName {
    GroupName::new("comp.test").unwrap()
}

/// Generate a vec of 0–8 distinct entry seeds (u8 values 0–127).
fn entry_seeds() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0u8..=127u8, 0..=8).prop_map(|mut v| {
        v.sort();
        v.dedup();
        v
    })
}

/// A pair of diverged entry seed sets (A and B may overlap partially).
fn diverged_logs() -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
    (entry_seeds(), entry_seeds())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Commutativity: want(A→B) ⊆ have(B→A) and want(B→A) ⊆ have(A→B).
    ///
    /// The v1 algorithm uses direct-tip-only `want`, so the property is
    /// containment rather than equality: every ID A requests from B is
    /// something B actually has to offer, and vice versa.
    #[test]
    fn reconcile_commutativity((seeds_a, seeds_b) in diverged_logs()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (violation_a, violation_b) = rt.block_on(async {
            let storage_a = MemLogStorage::new();
            let storage_b = MemLogStorage::new();
            let group = test_group();

            let mut tips_a = Vec::new();
            for (i, &seed) in seeds_a.iter().enumerate() {
                let id = make_entry_id(seed);
                storage_a.insert_entry(id.clone(), make_entry(i as u64)).await.unwrap();
                tips_a.push(id);
            }
            if !tips_a.is_empty() {
                storage_a.set_tips(&group, &tips_a).await.unwrap();
            }

            let mut tips_b = Vec::new();
            for (i, &seed) in seeds_b.iter().enumerate() {
                let id = make_entry_id(seed);
                storage_b.insert_entry(id.clone(), make_entry(i as u64)).await.unwrap();
                tips_b.push(id);
            }
            if !tips_b.is_empty() {
                storage_b.set_tips(&group, &tips_b).await.unwrap();
            }

            let result_a = reconcile(&storage_a, &group, &tips_b).await.unwrap();
            let result_b = reconcile(&storage_b, &group, &tips_a).await.unwrap();

            // want(A→B) ⊆ have(B→A)
            let have_b: HashSet<[u8; 32]> =
                result_b.have.iter().map(|id| *id.as_bytes()).collect();
            let violation_a = result_a
                .want
                .iter()
                .find(|id| !have_b.contains(id.as_bytes()))
                .cloned();

            // want(B→A) ⊆ have(A→B)
            let have_a: HashSet<[u8; 32]> =
                result_a.have.iter().map(|id| *id.as_bytes()).collect();
            let violation_b = result_b
                .want
                .iter()
                .find(|id| !have_a.contains(id.as_bytes()))
                .cloned();

            (violation_a, violation_b)
        });

        prop_assert!(
            violation_a.is_none(),
            "commutativity violation: A wants {} but B does not have it",
            violation_a.unwrap()
        );
        prop_assert!(
            violation_b.is_none(),
            "commutativity violation: B wants {} but A does not have it",
            violation_b.unwrap()
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Reconciling a node against its own tip set produces empty want and have.
    #[test]
    fn reconcile_against_self_is_empty(seeds in entry_seeds()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (want, have) = rt.block_on(async {
            let storage = MemLogStorage::new();
            let group = test_group();

            let mut tips = Vec::new();
            for (i, &seed) in seeds.iter().enumerate() {
                let id = make_entry_id(seed);
                storage.insert_entry(id.clone(), make_entry(i as u64)).await.unwrap();
                tips.push(id);
            }
            if !tips.is_empty() {
                storage.set_tips(&group, &tips).await.unwrap();
            }

            let current_tips = storage.list_tips(&group).await.unwrap();
            let result = reconcile(&storage, &group, &current_tips).await.unwrap();
            (result.want, result.have)
        });

        prop_assert!(
            want.is_empty(),
            "reconciling against self must have empty want: {:?}",
            want
        );
        prop_assert!(
            have.is_empty(),
            "reconciling against self must have empty have: {:?}",
            have
        );
    }
}
