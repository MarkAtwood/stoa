//! Integration test: pin/unpin/GC round-trip with audit log verification.
//!
//! Stores 20 articles (simulated with MemPinClient), applies a policy that
//! pins 7 of them, runs GC, verifies 13 are unpinned, verifies the audit
//! log has exactly 13 records.

use stoa_transit::retention::{
    audit_log::count_audit_records,
    gc_executor::{run_gc_executor, GcExecutorCandidate, GcReason},
    pin_client::{MemPinClient, PinClient},
    policy::{ArticleMeta, PinAction, PinPolicy, PinRule},
};

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

fn make_cid(data: &[u8]) -> Cid {
    Cid::new_v1(0x71, Code::Sha2_256.digest(data))
}

async fn make_transit_pool(_name: &str) -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_transit::migrations::run_migrations(&url)
        .await
        .unwrap();
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .unwrap();
    (pool, tmp)
}

async fn make_core_pool(_name: &str) -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_core::migrations::run_migrations(&url).await.unwrap();
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
        .await
        .unwrap();
    (pool, tmp)
}

/// Policy that pins articles in sci.* and alt.* groups.
fn selective_policy() -> PinPolicy {
    PinPolicy::new(vec![
        PinRule {
            groups: "sci.*".to_string(),
            max_age_days: None,
            max_article_bytes: None,
            action: PinAction::Pin,
        },
        PinRule {
            groups: "alt.*".to_string(),
            max_age_days: None,
            max_article_bytes: None,
            action: PinAction::Pin,
        },
    ])
}

/// Policy that pins everything.
fn pin_all_policy() -> PinPolicy {
    PinPolicy::new(vec![PinRule {
        groups: "all".to_string(),
        max_age_days: None,
        max_article_bytes: None,
        action: PinAction::Pin,
    }])
}

#[tokio::test]
async fn gc_roundtrip_13_unpinned_7_pinned() {
    let (transit_pool, _tmp1) = make_transit_pool("gc_roundtrip_test").await;
    let (core_pool, _tmp2) = make_core_pool("gc_roundtrip_test").await;
    let pin_client = MemPinClient::new();
    let now_ms = 1_700_000_000_000u64;
    let policy = selective_policy();

    // Create 20 articles: 7 in sci.* or alt.*, 13 in comp.*
    let mut candidates = Vec::new();
    for i in 0u8..7 {
        let group = if i % 2 == 0 { "sci.math" } else { "alt.test" };
        let cid = make_cid(&[i]);
        pin_client.pin(&cid).await.unwrap();
        let meta = ArticleMeta {
            group: group.to_string(),
            size_bytes: 512,
            age_days: 30,
        };
        // Only add to GC candidates those that should NOT be pinned
        if !policy.should_pin(&meta) {
            candidates.push(GcExecutorCandidate {
                cid,
                group_name: group.to_string(),
                ingested_at_ms: now_ms - 86_400_000 * 30,
                gc_reason: GcReason::NoMatchingRule,
            });
        }
    }
    for i in 7u8..20 {
        let group = "comp.lang.rust";
        let cid = make_cid(&[i]);
        pin_client.pin(&cid).await.unwrap();
        let meta = ArticleMeta {
            group: group.to_string(),
            size_bytes: 512,
            age_days: 30,
        };
        if !policy.should_pin(&meta) {
            candidates.push(GcExecutorCandidate {
                cid,
                group_name: group.to_string(),
                ingested_at_ms: now_ms - 86_400_000 * 30,
                gc_reason: GcReason::NoMatchingRule,
            });
        }
    }

    // All 13 comp.lang.rust articles should be GC candidates
    assert_eq!(candidates.len(), 13, "expected 13 GC candidates");

    let result = run_gc_executor(&candidates, &pin_client, &transit_pool, &core_pool, now_ms)
        .await
        .unwrap();
    assert_eq!(result.unpinned, 13, "should unpin 13");
    assert_eq!(result.failed, 0, "no failures expected");

    let audit_count = count_audit_records(&transit_pool).await.unwrap();
    assert_eq!(audit_count, 13, "audit log should have 13 records");

    // Verify the 7 pinned articles are still pinned
    for i in 0u8..7 {
        let cid = make_cid(&[i]);
        let still_pinned = pin_client.is_pinned(&cid).await.unwrap();
        assert!(still_pinned, "article {i} should still be pinned");
    }
}

#[tokio::test]
async fn gc_roundtrip_pin_all_produces_no_candidates() {
    let (transit_pool, _tmp1) = make_transit_pool("gc_roundtrip_pin_all").await;
    let (core_pool, _tmp2) = make_core_pool("gc_roundtrip_pin_all").await;
    let pin_client = MemPinClient::new();
    let now_ms = 1_700_000_000_000u64;
    let policy = pin_all_policy();

    // Pin 20 articles
    for i in 0u8..20 {
        let cid = make_cid(&[100 + i]);
        pin_client.pin(&cid).await.unwrap();
    }

    // With pin-all policy, no candidates
    let candidates: Vec<GcExecutorCandidate> = (0u8..20)
        .filter_map(|i| {
            let group = "comp.lang.rust";
            let meta = ArticleMeta {
                group: group.to_string(),
                size_bytes: 512,
                age_days: 30,
            };
            if policy.should_pin(&meta) {
                None
            } else {
                Some(GcExecutorCandidate {
                    cid: make_cid(&[100 + i]),
                    group_name: group.to_string(),
                    ingested_at_ms: 0,
                    gc_reason: GcReason::NoMatchingRule,
                })
            }
        })
        .collect();

    assert_eq!(candidates.len(), 0, "pin-all should produce 0 candidates");

    let result = run_gc_executor(&candidates, &pin_client, &transit_pool, &core_pool, now_ms)
        .await
        .unwrap();
    assert_eq!(result.unpinned, 0);

    let audit_count = count_audit_records(&transit_pool).await.unwrap();
    assert_eq!(audit_count, 0, "no audit records when nothing unpinned");
}
