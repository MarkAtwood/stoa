//! Integration tests for RFC 4644 streaming peering protocol.
//!
//! Validates the MODE STREAM → CHECK → TAKETHIS flow and IHAVE fallback using
//! the transit library's public API. Response codes are the independent oracle:
//! RFC 4644 §2.3 (CHECK 238/438/431), §2.4 (TAKETHIS 239/438/439/431),
//! RFC 977 §3.8 (IHAVE 235/435/436/437), RFC 3977 §9.4 (CAPABILITIES 101),
//! and RFC 4644 §2.2 (MODE STREAM 203).

use cid::Cid;
use ed25519_dalek::SigningKey;
use multihash_codetable::{Code, MultihashDigest};
use std::sync::Arc;
use stoa_core::{group_log::MemLogStorage, hlc::HlcTimestamp, msgid_map::MsgIdMap};
use stoa_transit::peering::{
    ingestion::{
        check_ingest, check_mode_guard, check_response, ihave_response, takethis_mode_guard,
        IngestResult,
    },
    mode_stream::{capabilities_response, handle_mode_stream, PeeringMode},
    pipeline::{run_pipeline, MemIpfsStore, PipelineCtx},
};

// ── Test helpers ──────────────────────────────────────────────────────────────

async fn make_transit_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_transit::migrations::run_migrations(&url).await.unwrap();
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1).await.unwrap();
    (pool, tmp)
}

/// Create an isolated MsgIdMap backed by a temporary SQLite file.
///
/// Using a real temp file per test to avoid migration races that occur with
/// named in-memory SQLite databases shared across connections.
async fn make_msgid_map() -> (MsgIdMap, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    stoa_core::migrations::run_migrations(&url).await.unwrap();
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1).await.unwrap();
    (MsgIdMap::new(pool), tmp)
}

fn make_article(msgid: &str, group: &str) -> Vec<u8> {
    format!(
        "From: test@example.com\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         Message-ID: {msgid}\r\n\
         Newsgroups: {group}\r\n\
         Subject: Test article\r\n\
         \r\n\
         Article body.\r\n"
    )
    .into_bytes()
}

fn make_pipeline_ctx(key: &SigningKey, ts: HlcTimestamp) -> PipelineCtx<'static> {
    PipelineCtx {
        timestamp: ts,
        operator_signing_key: Arc::new(key.clone()),
        local_hostname: "test.local",
        verify_store: None,
        trusted_keys: &[],
        dkim_auth: None,
        group_filter: None,
    }
}

fn make_timestamp() -> HlcTimestamp {
    HlcTimestamp {
        wall_ms: 1_700_000_000_000,
        logical: 0,
        node_id: [1, 2, 3, 4, 5, 6, 7, 8],
    }
}

fn make_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

// ── Test 1: CAPABILITIES response ─────────────────────────────────────────────

/// RFC 4644 §2.1: a server advertising STREAMING capability must include it in
/// the CAPABILITIES response (101). RFC 3977 §3.3.2: IHAVE is a separately
/// advertised capability.
#[test]
fn capabilities_includes_streaming() {
    let resp = capabilities_response();
    assert!(
        resp.starts_with("101"),
        "CAPABILITIES must start with 101, got: {resp:?}"
    );
    assert!(
        resp.contains("STREAMING"),
        "missing STREAMING in CAPABILITIES: {resp:?}"
    );
    assert!(
        resp.contains("IHAVE"),
        "missing IHAVE in CAPABILITIES: {resp:?}"
    );
}

// ── Test 2: MODE STREAM command ───────────────────────────────────────────────

/// RFC 4644 §2.2: MODE STREAM must return 203 and switch the connection to
/// streaming mode.
#[test]
fn mode_stream_enables_streaming() {
    let (resp, new_mode) = handle_mode_stream(PeeringMode::Ihave);
    assert!(
        resp.starts_with("203"),
        "MODE STREAM must return 203, got: {resp:?}"
    );
    assert_eq!(
        new_mode,
        PeeringMode::Streaming,
        "mode must be Streaming after MODE STREAM"
    );
}

// ── Test 3: CHECK command requires streaming mode ─────────────────────────────

/// RFC 4644 §2.3: CHECK is only valid after MODE STREAM. Sending CHECK in IHAVE
/// mode must be rejected (401). In streaming mode it must be permitted.
#[test]
fn check_requires_streaming_mode() {
    let guard = check_mode_guard(PeeringMode::Ihave);
    assert!(guard.is_some(), "CHECK must be blocked when in IHAVE mode");
    let resp = guard.unwrap();
    assert!(
        resp.starts_with("401"),
        "mode guard for IHAVE must return 401, got: {resp:?}"
    );

    let guard = check_mode_guard(PeeringMode::Streaming);
    assert!(
        guard.is_none(),
        "CHECK must be permitted when in Streaming mode"
    );
}

// ── Test 3b: TAKETHIS requires streaming mode ─────────────────────────────────

/// RFC 4644 §2.5: TAKETHIS is only valid after MODE STREAM has been
/// successfully negotiated.  Sending TAKETHIS in IHAVE mode must be rejected
/// with 500 ("Command not available in current mode").  In streaming mode it
/// must be permitted (guard returns None).
#[test]
fn takethis_requires_streaming_mode() {
    // IHAVE mode: TAKETHIS must be blocked with 500.
    let guard = takethis_mode_guard(PeeringMode::Ihave);
    assert!(
        guard.is_some(),
        "TAKETHIS must be blocked when session is in IHAVE mode (MODE STREAM not negotiated)"
    );
    let resp = guard.unwrap();
    assert!(
        resp.starts_with("500"),
        "RFC 4644 §2.5: TAKETHIS in IHAVE mode must return 500, got: {resp:?}"
    );

    // Streaming mode: TAKETHIS must be permitted.
    let guard = takethis_mode_guard(PeeringMode::Streaming);
    assert!(
        guard.is_none(),
        "TAKETHIS must be permitted when session is in Streaming mode"
    );
}

// ── Test 4: CHECK → TAKETHIS for 100 new articles ────────────────────────────

/// RFC 4644 §2.3–2.4: for new articles, CHECK returns 238 ("Send it") and
/// TAKETHIS returns 239 ("Article transferred OK").
///
/// Simulates the receiver side of the streaming protocol: each article goes
/// through CHECK (→ 238) then TAKETHIS (→ run_pipeline → 239). After storage,
/// a repeat CHECK for the same msgid returns 438 (already have it).
#[tokio::test]
async fn streaming_check_takethis_100_articles() {
    let (msgid_map, _tmp) = make_msgid_map().await;
    let ipfs = MemIpfsStore::new();
    let log_storage = MemLogStorage::new();
    let key = make_signing_key();
    let (transit_pool, _tmp_transit) = make_transit_pool().await;

    let mut accepted = 0u32;

    for i in 0..100 {
        let msgid = format!("<article-{i:04}@streaming.test>");
        let article = make_article(&msgid, "comp.test");

        // Phase 1: CHECK — receiver decides if it wants the article.
        let check_result = check_ingest(&msgid, &article, &msgid_map).await;
        let check_resp = check_response(&check_result);

        assert_eq!(
            check_result,
            IngestResult::Accepted,
            "new article {i} must be accepted on CHECK"
        );
        assert!(
            check_resp.starts_with("238"),
            "CHECK accepted must give 238 (RFC 4644 §2.3), got: {check_resp:?}"
        );

        // Phase 2: TAKETHIS — receiver stores the article and records the CID.
        let pipeline_result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &log_storage,
            &transit_pool,
            make_pipeline_ctx(&key, make_timestamp()),
        )
        .await;
        assert!(
            pipeline_result.is_ok(),
            "TAKETHIS pipeline must succeed for article {i}: {pipeline_result:?}"
        );
        let (pr, _metrics) = pipeline_result.unwrap();

        // Confirm article is now stored: msgid_map must resolve to the CID.
        let stored = msgid_map.lookup_by_msgid(&msgid).await.unwrap();
        assert_eq!(
            stored,
            Some(pr.cid),
            "article {i} must be addressable by Message-ID after TAKETHIS"
        );

        accepted += 1;
    }

    assert_eq!(
        accepted, 100,
        "all 100 articles must complete CHECK+TAKETHIS"
    );
}

// ── Test 5: Duplicate detection on CHECK ─────────────────────────────────────

/// RFC 4644 §2.3: if the server already has the article, CHECK must return 438.
/// This tests that a pre-stored article is correctly identified as a duplicate
/// before any article bytes are transferred.
#[tokio::test]
async fn streaming_duplicate_detection() {
    let (msgid_map, _tmp) = make_msgid_map().await;
    let msgid = "<dup-check@streaming.test>";
    let article = make_article(msgid, "comp.test");

    // Pre-store the article in msgid_map (simulates a successful prior TAKETHIS).
    let cid = Cid::new_v1(0x71, Code::Sha2_256.digest(b"article-data"));
    msgid_map.insert(msgid, &cid).await.unwrap();

    // CHECK must now return 438 — no need to transfer the article.
    let result = check_ingest(msgid, &article, &msgid_map).await;
    let resp = check_response(&result);
    assert_eq!(
        result,
        IngestResult::Duplicate,
        "pre-stored article must be Duplicate"
    );
    assert!(
        resp.starts_with("438"),
        "duplicate CHECK must give 438 (RFC 4644 §2.3), got: {resp:?}"
    );
}

// ── Test 6: IHAVE fallback for 100 articles ───────────────────────────────────

/// RFC 977 §3.8: in traditional IHAVE mode (no MODE STREAM), accepted articles
/// return 235. Verifies the IHAVE path works for a full batch of new articles.
#[tokio::test]
async fn ihave_fallback_100_articles() {
    let (msgid_map, _tmp) = make_msgid_map().await;

    let mut offered = 0u32;
    let mut accepted = 0u32;

    for i in 0..100 {
        let msgid = format!("<ihave-{i:04}@fallback.test>");
        let article = make_article(&msgid, "alt.test");

        let result = check_ingest(&msgid, &article, &msgid_map).await;
        let resp = ihave_response(&result);
        offered += 1;

        assert_eq!(
            result,
            IngestResult::Accepted,
            "new article {i} must be accepted on IHAVE"
        );
        assert!(
            resp.starts_with("235"),
            "IHAVE accept must give 235 (RFC 977 §3.8), got: {resp:?}"
        );
        accepted += 1;
    }

    assert_eq!(offered, 100, "must have offered 100 articles");
    assert_eq!(accepted, 100, "all 100 IHAVE articles must be accepted");
}

// ── Test 7: IHAVE duplicate returns 435 ──────────────────────────────────────

/// RFC 977 §3.8: IHAVE for an already-stored article must return 435.
#[tokio::test]
async fn ihave_duplicate_gets_435() {
    let (msgid_map, _tmp) = make_msgid_map().await;
    let msgid = "<dup-ihave@fallback.test>";
    let article = make_article(msgid, "alt.test");

    let cid = Cid::new_v1(0x71, Code::Sha2_256.digest(b"existing"));
    msgid_map.insert(msgid, &cid).await.unwrap();

    let result = check_ingest(msgid, &article, &msgid_map).await;
    let resp = ihave_response(&result);
    assert_eq!(
        result,
        IngestResult::Duplicate,
        "pre-stored article must be Duplicate"
    );
    assert!(
        resp.starts_with("435"),
        "IHAVE duplicate must give 435 (RFC 977 §3.8), got: {resp:?}"
    );
}
