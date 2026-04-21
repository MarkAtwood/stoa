//! IHAVE pipeline end-to-end throughput and latency benchmark.
//!
//! Section 1 — Throughput: measures articles/second through `run_pipeline`
//! using an in-memory IPFS store and in-memory SQLite pool.
//!
//! Section 2 — Latency: measures p50/p99 per-article latency over 1,000
//! articles using a fresh store. A gossipsub channel is wired so the
//! publish step (step 4 of the pipeline) is included in the measurement.
//! End-to-end latency covers: IPFS write + msgid SQLite insert +
//! log append + gossipsub channel send.
//!
//! Run with:
//!   cargo bench -p usenet-ipfs-transit --bench ihave_throughput

use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::sync::mpsc;
use usenet_ipfs_core::{group_log::MemLogStorage, hlc::HlcTimestamp, msgid_map::MsgIdMap};
use usenet_ipfs_transit::peering::pipeline::{run_pipeline, MemIpfsStore, PipelineCtx};

const ARTICLE_COUNT: usize = 1_000;

/// Build a synthetic RFC 5536-format article with the given index.
fn make_article(i: usize) -> Vec<u8> {
    format!(
        "From sender@example.com Mon Jan 01 00:00:00 2024\r\n\
         Message-ID: <bench-{i}@example.com>\r\n\
         Newsgroups: comp.lang.rust\r\n\
         Subject: Bench article {i}\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         \r\n\
         Body of article {i}.\r\n"
    )
    .into_bytes()
}

async fn make_msgid_pool(db_name: &str) -> sqlx::SqlitePool {
    let url = format!("file:{db_name}?mode=memory&cache=shared");
    let opts = SqliteConnectOptions::new()
        .filename(&url)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("in-memory SQLite pool");
    usenet_ipfs_core::migrations::run_migrations(&pool)
        .await
        .expect("migrations");
    pool
}

#[tokio::main]
async fn main() {
    // ══════════════════════════════════════════════════════════════════════════
    // Section 1 — Throughput
    // ══════════════════════════════════════════════════════════════════════════

    let ipfs = MemIpfsStore::new();
    let pool = make_msgid_pool("ihave_bench_throughput").await;
    let msgid_map = MsgIdMap::new(pool);
    let log_storage = MemLogStorage::new();

    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let timestamp = HlcTimestamp {
        wall_ms: 1_700_000_000_000,
        logical: 0,
        node_id: [1, 2, 3, 4, 5, 6, 7, 8],
    };

    // Pre-build all article bytes so allocation is outside the timed region.
    let articles: Vec<Vec<u8>> = (0..ARTICLE_COUNT).map(make_article).collect();

    let start = Instant::now();

    for article in &articles {
        let ctx = PipelineCtx {
            timestamp,
            operator_signature: signing_key.sign(b""),
            gossip_tx: None,
            sender_peer_id: "bench-peer",
        };
        run_pipeline(article, &ipfs, &msgid_map, &log_storage, ctx)
            .await
            .expect("pipeline must succeed");
    }

    let elapsed = start.elapsed();
    let ms = elapsed.as_millis();
    let rate = ARTICLE_COUNT as f64 / elapsed.as_secs_f64();
    println!("throughput: {rate:.1} articles/sec  ({ARTICLE_COUNT} articles in {ms}ms)");

    // ══════════════════════════════════════════════════════════════════════════
    // Section 2 — Per-article latency (p50 / p99)
    //
    // Uses a fresh store so the latency run is independent of the throughput
    // run. A gossipsub channel (capacity = ARTICLE_COUNT) is wired so step 4
    // (gossipsub channel send) is included. Articles are processed one at a
    // time; the channel is never full, so sends never block.
    //
    // End-to-end latency covers:
    //   IPFS write → msgid SQLite insert → log append → gossipsub channel send
    // ══════════════════════════════════════════════════════════════════════════

    let ipfs2 = MemIpfsStore::new();
    let pool2 = make_msgid_pool("ihave_bench_latency").await;
    let msgid_map2 = MsgIdMap::new(pool2);
    let log_storage2 = MemLogStorage::new();

    // Channel capacity equals ARTICLE_COUNT so no send ever blocks.
    let (gossip_tx, _gossip_rx) = mpsc::channel::<(String, Vec<u8>)>(ARTICLE_COUNT);

    let mut latencies: Vec<Duration> = Vec::with_capacity(ARTICLE_COUNT);

    // Latency articles use a different message-id range to avoid duplicate-key
    // conflicts in the msgid_map (which would surface as errors, not just skips).
    let lat_articles: Vec<Vec<u8>> = (ARTICLE_COUNT..ARTICLE_COUNT * 2)
        .map(make_article)
        .collect();

    for article in &lat_articles {
        let ctx = PipelineCtx {
            timestamp,
            operator_signature: signing_key.sign(b""),
            gossip_tx: Some(&gossip_tx),
            sender_peer_id: "bench-peer",
        };
        let t0 = Instant::now();
        run_pipeline(article, &ipfs2, &msgid_map2, &log_storage2, ctx)
            .await
            .expect("pipeline must succeed");
        latencies.push(t0.elapsed());
    }

    latencies.sort_unstable();
    let p50_us = latencies[499].as_micros();
    let p99_us = latencies[989].as_micros();
    println!("latency p50: {p50_us}µs  p99: {p99_us}µs");
    println!(
        "  (end-to-end: IPFS write + msgid SQLite insert + log append + gossipsub channel send)"
    );
}
