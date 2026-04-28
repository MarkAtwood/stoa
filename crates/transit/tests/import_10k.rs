//! Integration test: import 10,000 articles via mbox parse + reindex.
//!
//! Generates a synthetic mbox file with 10,000 articles, parses it with
//! `parse_mbox_file`, then feeds the resulting `(Cid, Vec<u8>)` pairs to
//! `run_reindex`. Verifies all 10,000 Message-IDs appear in msgid_map with
//! non-null CIDs.
//!
//! Note: `run_mbox_import` is not used here because it requires a live
//! transit daemon TCP connection. This test exercises the parse layer
//! (`parse_mbox_file`) and the indexing layer (`run_reindex`) together.

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use stoa_transit::import::{
    mbox::parse_mbox_file,
    reindex::{run_reindex, ReindexConfig},
};
use tempfile::TempDir;

fn make_cid(data: &[u8]) -> Cid {
    Cid::new_v1(0x71, Code::Sha2_256.digest(data))
}

async fn make_pool() -> (sqlx::AnyPool, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    let pool = stoa_core::db_pool::try_open_any_pool(&url, 1).await.unwrap();
    (pool, tmp)
}

/// Write a synthetic mbox file with `count` articles to `dir`.
/// Returns the path to the written file.
fn write_synthetic_mbox(dir: &TempDir, count: usize) -> std::path::PathBuf {
    use std::fmt::Write as _;

    let path = dir.path().join("synthetic.mbox");
    let mut content = String::with_capacity(count * 200);

    for i in 0..count {
        writeln!(
            content,
            "From sender@example.com Mon Jan 01 00:00:00 2024\r"
        )
        .unwrap();
        writeln!(content, "Message-ID: <test-{i}@example.com>\r").unwrap();
        writeln!(content, "Newsgroups: comp.lang.rust\r").unwrap();
        writeln!(content, "Subject: Test article {i}\r").unwrap();
        writeln!(content, "Date: Mon, 01 Jan 2024 00:00:00 +0000\r").unwrap();
        writeln!(content, "\r").unwrap();
        writeln!(content, "Body of article {i}.\r").unwrap();
        writeln!(content).unwrap();
    }

    std::fs::write(&path, &content).unwrap();
    path
}

#[tokio::test]
async fn import_10k_all_message_ids_indexed() {
    let dir = TempDir::new().unwrap();
    let mbox_path = write_synthetic_mbox(&dir, 10_000);

    // Phase 1: parse the mbox file.
    let messages = parse_mbox_file(&mbox_path).await.unwrap();
    assert_eq!(
        messages.len(),
        10_000,
        "mbox parse should produce 10,000 messages"
    );

    // Phase 2: build (Cid, Vec<u8>) pairs for reindex.
    // CID is derived from the raw article bytes so each is unique.
    let articles: Vec<(Cid, Vec<u8>)> = messages
        .into_iter()
        .map(|msg| {
            let cid = make_cid(&msg.raw);
            (cid, msg.raw)
        })
        .collect();

    // Phase 3: run reindex to populate msgid_map.
    let (pool, _tmp) = make_pool().await;
    let config = ReindexConfig {
        dry_run: false,
        progress_interval: 1000,
    };
    let summary = run_reindex(articles, &pool, &config).await.unwrap();

    assert_eq!(
        summary.total_scanned, 10_000,
        "should scan all 10,000 articles"
    );
    assert_eq!(summary.indexed, 10_000, "all 10,000 should be indexed");
    assert_eq!(
        summary.skipped_not_article, 0,
        "no articles should be skipped"
    );
    assert_eq!(summary.skipped_duplicate, 0, "no duplicates expected");

    // Phase 4: verify database state.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM msgid_map")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 10_000,
        "msgid_map should contain exactly 10,000 rows"
    );

    // Spot-check: article 42 must have a non-empty CID.
    let cid_str: Option<String> =
        sqlx::query_scalar("SELECT cid FROM msgid_map WHERE message_id = '<test-42@example.com>'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    let cid_str = cid_str.expect("message_id '<test-42@example.com>' must be in msgid_map");
    assert!(!cid_str.is_empty(), "CID for test-42 must be non-empty");
}
