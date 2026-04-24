//! Integration tests for provenance-based group log routing.
//!
//! Oracle: expected presence/absence of group log entries is derived from
//! `InjectionSource::is_peerable()`, which is the specification, NOT from
//! reading the routing code under test.
//!
//! Rule: every `is_peerable()` source → log entry written.
//!       `SmtpListId` → no log entry, article still in article_numbers.

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use usenet_ipfs_core::article::GroupName;
use usenet_ipfs_core::group_log::LogStorage;
use usenet_ipfs_core::hlc::HlcClock;
use usenet_ipfs_core::InjectionSource;
use usenet_ipfs_reader::post::log_append::append_to_groups;
use usenet_ipfs_reader::store::server_stores::ServerStores;

/// Build a deterministic test CID from a short label.
fn test_cid(label: &[u8]) -> Cid {
    Cid::new_v1(0x71, Code::Sha2_256.digest(label))
}

/// Generate `n` HLC timestamps using a fixed test clock.
fn test_timestamps(n: usize) -> Vec<u64> {
    let mut clock = HlcClock::new([0x01; 8], 1_000_000);
    (0..n).map(|_| clock.send(1_000_000).wall_ms).collect()
}

// ── Test 1 ───────────────────────────────────────────────────────────────────

/// NntpPost source → group log has one entry.
///
/// Oracle: `NntpPost::is_peerable()` returns `true`; therefore one log tip
/// must exist for the group after `append_to_groups`.
#[tokio::test]
async fn nntp_post_writes_group_log() {
    let stores = ServerStores::new_mem().await;
    let cid = test_cid(b"prov-nntp-post");
    let group = GroupName::new("comp.test").unwrap();
    let groups = vec![group.clone()];
    let timestamps = test_timestamps(1);

    append_to_groups(
        &*stores.log_storage,
        &stores.article_numbers,
        &timestamps,
        &cid,
        &stores.signing_key,
        &groups,
        InjectionSource::NntpPost,
    )
    .await
    .expect("append_to_groups must succeed");

    let tips = stores
        .log_storage
        .list_tips(&group)
        .await
        .expect("list_tips must not fail");
    assert!(
        !tips.is_empty(),
        "NntpPost source must write a group log entry; tips were empty"
    );
}

// ── Test 2 ───────────────────────────────────────────────────────────────────

/// SmtpNewsgroups source → group log entry present.
///
/// Oracle: `SmtpNewsgroups::is_peerable()` returns `true`.
#[tokio::test]
async fn smtp_newsgroups_writes_group_log() {
    let stores = ServerStores::new_mem().await;
    let cid = test_cid(b"prov-smtp-newsgroups");
    let group = GroupName::new("comp.test").unwrap();
    let groups = vec![group.clone()];
    let timestamps = test_timestamps(1);

    append_to_groups(
        &*stores.log_storage,
        &stores.article_numbers,
        &timestamps,
        &cid,
        &stores.signing_key,
        &groups,
        InjectionSource::SmtpNewsgroups,
    )
    .await
    .expect("append_to_groups must succeed");

    let tips = stores
        .log_storage
        .list_tips(&group)
        .await
        .expect("list_tips must not fail");
    assert!(
        !tips.is_empty(),
        "SmtpNewsgroups source must write a group log entry; tips were empty"
    );
}

// ── Test 3 ───────────────────────────────────────────────────────────────────

/// SmtpSieve source → group log entry present.
///
/// Oracle: `SmtpSieve::is_peerable()` returns `true`.
#[tokio::test]
async fn smtp_sieve_writes_group_log() {
    let stores = ServerStores::new_mem().await;
    let cid = test_cid(b"prov-smtp-sieve");
    let group = GroupName::new("comp.test").unwrap();
    let groups = vec![group.clone()];
    let timestamps = test_timestamps(1);

    append_to_groups(
        &*stores.log_storage,
        &stores.article_numbers,
        &timestamps,
        &cid,
        &stores.signing_key,
        &groups,
        InjectionSource::SmtpSieve,
    )
    .await
    .expect("append_to_groups must succeed");

    let tips = stores
        .log_storage
        .list_tips(&group)
        .await
        .expect("list_tips must not fail");
    assert!(
        !tips.is_empty(),
        "SmtpSieve source must write a group log entry; tips were empty"
    );
}

// ── Test 4 ───────────────────────────────────────────────────────────────────

/// SmtpListId source → zero group log entries for this article.
///
/// Oracle: `SmtpListId::is_peerable()` returns `false` — local-only storage.
#[tokio::test]
async fn smtp_listid_no_group_log() {
    let stores = ServerStores::new_mem().await;
    let cid = test_cid(b"prov-smtp-listid-nolog");
    let group = GroupName::new("comp.test").unwrap();
    let groups = vec![group.clone()];
    let timestamps = test_timestamps(1);

    append_to_groups(
        &*stores.log_storage,
        &stores.article_numbers,
        &timestamps,
        &cid,
        &stores.signing_key,
        &groups,
        InjectionSource::SmtpListId,
    )
    .await
    .expect("append_to_groups must succeed");

    let tips = stores
        .log_storage
        .list_tips(&group)
        .await
        .expect("list_tips must not fail");
    assert!(
        tips.is_empty(),
        "SmtpListId must not write a group log entry; got tips: {tips:?}"
    );
}

// ── Test 5 ───────────────────────────────────────────────────────────────────

/// SmtpListId source → article appears in article_numbers (local readers can serve it).
///
/// Oracle: `assign_number` always runs regardless of injection source, so the
/// CID must be retrievable by its assigned article number.
#[tokio::test]
async fn smtp_listid_readable_via_nntp() {
    let stores = ServerStores::new_mem().await;
    let cid = test_cid(b"prov-smtp-listid-readable");
    let group_name = "comp.test";
    let group = GroupName::new(group_name).unwrap();
    let groups = vec![group.clone()];
    let timestamps = test_timestamps(1);

    let result = append_to_groups(
        &*stores.log_storage,
        &stores.article_numbers,
        &timestamps,
        &cid,
        &stores.signing_key,
        &groups,
        InjectionSource::SmtpListId,
    )
    .await
    .expect("append_to_groups must succeed");

    // The article must have been assigned a number.
    assert_eq!(
        result.assignments.len(),
        1,
        "exactly one assignment must be returned"
    );
    let (assigned_group, article_num) = &result.assignments[0];
    assert_eq!(assigned_group, group_name);
    assert_eq!(*article_num, 1, "first article in group must be number 1");

    // Verify the CID is retrievable by number (what NNTP ARTICLE would do).
    let found_cid = stores
        .article_numbers
        .lookup_cid(group_name, *article_num)
        .await
        .expect("lookup_cid must not fail");
    assert_eq!(
        found_cid,
        Some(cid),
        "SmtpListId article must be retrievable by article number"
    );
}

// ── Test 6 ───────────────────────────────────────────────────────────────────

/// Mixed batch: one SmtpListId + one NntpPost article in the same group.
///
/// Expected: exactly one group log entry (the NntpPost); both articles appear
/// in article_numbers.
///
/// Oracle:
/// - NntpPost is peerable → log entry written.
/// - SmtpListId is not peerable → no log entry.
/// - article_numbers always assigned for both.
#[tokio::test]
async fn mixed_batch() {
    let stores = ServerStores::new_mem().await;
    let group_name = "comp.test";
    let group = GroupName::new(group_name).unwrap();
    let groups = vec![group.clone()];

    let cid_listid = test_cid(b"prov-mixed-listid");
    let cid_nntp = test_cid(b"prov-mixed-nntp");

    // Inject SmtpListId article first.
    let r1 = append_to_groups(
        &*stores.log_storage,
        &stores.article_numbers,
        &test_timestamps(1),
        &cid_listid,
        &stores.signing_key,
        &groups,
        InjectionSource::SmtpListId,
    )
    .await
    .expect("SmtpListId append must succeed");

    // Inject NntpPost article second.
    let r2 = append_to_groups(
        &*stores.log_storage,
        &stores.article_numbers,
        &test_timestamps(1),
        &cid_nntp,
        &stores.signing_key,
        &groups,
        InjectionSource::NntpPost,
    )
    .await
    .expect("NntpPost append must succeed");

    // Group log must have exactly one tip (the NntpPost entry).
    let tips = stores
        .log_storage
        .list_tips(&group)
        .await
        .expect("list_tips must not fail");
    assert_eq!(
        tips.len(),
        1,
        "exactly one group log tip expected (NntpPost only); got {tips:?}"
    );

    // Both articles must have article numbers.
    assert_eq!(r1.assignments[0].1, 1, "SmtpListId article must be number 1");
    assert_eq!(r2.assignments[0].1, 2, "NntpPost article must be number 2");

    let found_listid = stores
        .article_numbers
        .lookup_cid(group_name, 1)
        .await
        .expect("lookup must succeed");
    assert_eq!(
        found_listid,
        Some(cid_listid),
        "SmtpListId CID must be in article_numbers"
    );

    let found_nntp = stores
        .article_numbers
        .lookup_cid(group_name, 2)
        .await
        .expect("lookup must succeed");
    assert_eq!(
        found_nntp,
        Some(cid_nntp),
        "NntpPost CID must be in article_numbers"
    );
}

// ── Test 7 ───────────────────────────────────────────────────────────────────

/// Old queue file (no `injection_source` field) deserializes as SmtpSieve,
/// which is peerable and therefore writes a group log entry.
///
/// This test verifies the backward-compatibility contract: queue files written
/// before the injection_source field was added default to SmtpSieve so they
/// are treated as replicated articles rather than silently dropped from the log.
///
/// Oracle: `default_injection_source()` is the serde default — its return
/// value is the specification.  We cross-validate by (a) deserializing a JSON
/// object without the field, (b) asserting the deserialized value equals
/// `SmtpSieve`, and (c) confirming a subsequent `append_to_groups` call with
/// that source produces a group log entry.
#[tokio::test]
async fn old_queue_file_defaults_to_sieve() {
    // Minimal serde wrapper that mirrors the `#[serde(default = "...")]`
    // attribute used on the real NntpEnvelope in usenet-ipfs-smtp.
    #[derive(serde::Deserialize)]
    struct Envelope {
        #[serde(default = "usenet_ipfs_core::default_injection_source")]
        pub injection_source: InjectionSource,
    }

    // JSON that has some other field but no `injection_source` — simulates a
    // queue file written by an older version of the SMTP daemon.
    let json = r#"{"other_field": "value"}"#;
    let envelope: Envelope =
        serde_json::from_str(json).expect("JSON without injection_source must deserialize");

    assert_eq!(
        envelope.injection_source,
        InjectionSource::SmtpSieve,
        "missing injection_source must default to SmtpSieve"
    );

    // Confirm that SmtpSieve is peerable (so old queue files are not silently
    // dropped from the group log).
    assert!(
        envelope.injection_source.is_peerable(),
        "SmtpSieve must be peerable so old queue files write a group log entry"
    );

    // Confirm that append_to_groups with this source actually writes a log entry.
    let stores = ServerStores::new_mem().await;
    let cid = test_cid(b"prov-old-queue-file");
    let group = GroupName::new("comp.test").unwrap();
    let groups = vec![group.clone()];
    let timestamps = test_timestamps(1);

    append_to_groups(
        &*stores.log_storage,
        &stores.article_numbers,
        &timestamps,
        &cid,
        &stores.signing_key,
        &groups,
        envelope.injection_source,
    )
    .await
    .expect("append_to_groups with SmtpSieve must succeed");

    let tips = stores
        .log_storage
        .list_tips(&group)
        .await
        .expect("list_tips must not fail");
    assert!(
        !tips.is_empty(),
        "old queue file source (SmtpSieve) must produce a group log entry"
    );
}
