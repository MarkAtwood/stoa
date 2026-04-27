//! Fault injection tests for malformed article ingestion.
//!
//! Verifies that `check_ingest` never panics on arbitrary input, that malformed
//! articles are rejected with the correct NNTP response code, and that valid
//! articles following malformed ones are still accepted.
//!
//! Independent oracle: RFC 977 §3.8 (IHAVE 435/436/437), RFC 3977 §3.5
//! (reject codes), and the mandatory-header list in RFC 1036 §2.1.

use proptest::prelude::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr as _;
use stoa_core::msgid_map::MsgIdMap;
use stoa_transit::peering::ingestion::{check_ingest, ihave_response, IngestResult};

// ── Test helper ───────────────────────────────────────────────────────────────

/// Create an isolated MsgIdMap backed by a temporary SQLite file.
///
/// Each call produces a unique temp file so parallel tests do not share state.
async fn make_msgid_map() -> (MsgIdMap, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    let opts = SqliteConnectOptions::from_str(&url)
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    stoa_core::migrations::run_migrations(&pool).await.unwrap();
    (MsgIdMap::new(pool), tmp)
}

// ── Proptest: no panic on arbitrary bytes ─────────────────────────────────────

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(500))]

    /// No panic on any arbitrary byte sequence as article body.
    ///
    /// `check_ingest` must return an `IngestResult` variant — never unwind —
    /// regardless of what `article_bytes` contains.  The result may be
    /// `Rejected` (most likely) or `Accepted` (if the bytes happen to contain
    /// all mandatory headers), but must never panic.
    #[test]
    fn no_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..=4096)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (map, _tmp) = make_msgid_map().await;
            let result = check_ingest("<fuzz@test.com>", &bytes, &map).await;
            // Consume the result to ensure the future completes; ignore the variant.
            let _ = result;
        });
    }
}

// ── Proptest: random prefix does not crash ────────────────────────────────────

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(100))]

    /// Arbitrary bytes of any length up to 1 KiB must not cause a panic.
    ///
    /// Complements `no_panic_on_arbitrary_bytes` by using a different Message-ID
    /// and a tighter size range to exercise the header-scanning path on short inputs.
    #[test]
    fn random_prefix_does_not_crash(
        prefix in proptest::collection::vec(proptest::num::u8::ANY, 0..=1024)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (map, _tmp) = make_msgid_map().await;
            let _ = check_ingest("<prefix-test@test.com>", &prefix, &map).await;
        });
    }
}

// ── Unit tests: specific rejection cases ─────────────────────────────────────

/// Completely invalid bytes (NUL, high bytes, control chars) must be rejected
/// with IHAVE code 437, not cause a panic or transient error.
#[tokio::test]
async fn malformed_article_returns_rejected() {
    let (map, _tmp) = make_msgid_map().await;
    let garbage = b"\x00\x01\x02\x03garbage\xff\xfe";
    let result = check_ingest("<malformed@test.com>", garbage, &map).await;
    assert!(
        matches!(result, IngestResult::Rejected(_)),
        "garbage bytes should be Rejected, got: {result:?}"
    );
    let resp = ihave_response(&result);
    assert!(
        resp.starts_with("437"),
        "IHAVE for malformed article must give 437 (RFC 977 §3.8), got: {resp}"
    );
}

/// An empty byte slice must be rejected — the mandatory headers are absent.
#[tokio::test]
async fn empty_article_returns_rejected() {
    let (map, _tmp) = make_msgid_map().await;
    let result = check_ingest("<empty@test.com>", &[], &map).await;
    assert!(
        matches!(result, IngestResult::Rejected(_)),
        "empty bytes should be Rejected, got: {result:?}"
    );
}

/// After processing a malformed article a subsequent valid article must still
/// be accepted.  This confirms there is no shared mutable state (e.g. a
/// poisoned mutex or corrupted iterator) left over from the bad input.
#[tokio::test]
async fn valid_article_after_malformed_is_accepted() {
    let (map, _tmp) = make_msgid_map().await;

    // Malformed first — result is intentionally discarded.
    let _ = check_ingest("<garbage@test.com>", b"not an article at all", &map).await;

    // Valid article immediately after must be accepted.
    let valid_msgid = "<valid-after@test.com>";
    let valid_bytes = format!(
        "From: sender@example.com\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         Message-ID: {valid_msgid}\r\n\
         Newsgroups: alt.test\r\n\
         Subject: Valid after malformed\r\n\
         \r\n\
         Body.\r\n"
    )
    .into_bytes();

    let result = check_ingest(valid_msgid, &valid_bytes, &map).await;
    assert_eq!(
        result,
        IngestResult::Accepted,
        "valid article after malformed should be Accepted, got: {result:?}"
    );
}

/// A Message-ID without angle brackets must be rejected regardless of whether
/// the article body is otherwise well-formed.  The Message-ID is validated
/// before the body is inspected.
#[tokio::test]
async fn invalid_msgid_format_rejected_regardless_of_body() {
    let (map, _tmp) = make_msgid_map().await;

    let valid_body = b"From: x@y.com\r\n\
                       Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
                       Message-ID: <test@x.com>\r\n\
                       Newsgroups: alt.test\r\n\
                       Subject: s\r\n\
                       \r\n\
                       Body.";

    // No angle brackets → invalid Message-ID format.
    let result = check_ingest("no-brackets@example.com", valid_body, &map).await;
    assert!(
        matches!(result, IngestResult::Rejected(_)),
        "Message-ID without angle brackets should be Rejected, got: {result:?}"
    );
}
