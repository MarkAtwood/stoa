//! NNTP command latency benchmarks.
//!
//! Three measurements, all using in-process handler calls (no TCP layer):
//!
//! 1. ARTICLE fetch latency under 10 concurrent readers (1 000 total fetches).
//! 2. LIST ACTIVE response time with 10 000 groups.
//! 3. RSS memory baseline after loading 10 000 groups + 1 000 articles.

use std::time::Instant;

use usenet_ipfs_reader::session::commands::{
    fetch::{article_response, ArticleContent},
    list::{list_active, GroupInfo},
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_article(i: usize) -> ArticleContent {
    let group_idx = i % 10;
    let group = format!("comp.bench.{group_idx}");
    ArticleContent {
        article_number: i as u64 + 1,
        message_id: format!("<bench-{i}@usenet-ipfs.test>"),
        header_bytes: format!(
            "From: bench@usenet-ipfs.test\r\nSubject: Bench article {i}\r\nNewsgroups: {group}"
        )
        .into_bytes(),
        body_bytes: format!("Body of article {i}. Line two.\r\n").into_bytes(),
        cid: None,
    }
}

fn make_group(i: usize) -> GroupInfo {
    GroupInfo {
        name: format!("comp.bench.{i}"),
        high: 1000,
        low: 1,
        posting_allowed: true,
        description: format!("Benchmark group {i}"),
    }
}

// ── percentile helpers ────────────────────────────────────────────────────────

fn percentile_us(mut samples: Vec<u128>, pct: usize) -> u128 {
    samples.sort_unstable();
    let idx = ((samples.len() * pct).saturating_sub(1)) / 100;
    samples[idx]
}

// ── benchmark 1: ARTICLE fetch latency, 10 concurrent readers ────────────────

async fn bench_article_fetch() {
    const READERS: usize = 10;
    const PER_READER: usize = 100;

    // Pre-build all articles; each task owns a slice of ARTICLES_PER_READER.
    let articles: Vec<ArticleContent> = (0..READERS * PER_READER).map(make_article).collect();
    // Arc so tasks can share without copying.
    let articles = std::sync::Arc::new(articles);

    // Channel to collect per-fetch latencies (µs).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u128>>(READERS);

    for reader_id in 0..READERS {
        let articles = std::sync::Arc::clone(&articles);
        let tx = tx.clone();
        tokio::spawn(async move {
            let start_offset = reader_id * PER_READER;
            let mut latencies = Vec::with_capacity(PER_READER);
            for i in 0..PER_READER {
                let article = &articles[start_offset + i];
                let t0 = Instant::now();
                let resp = article_response(article);
                let elapsed = t0.elapsed().as_micros();
                // Prevent the compiler from optimising away the call.
                std::hint::black_box(resp.code);
                latencies.push(elapsed);
            }
            tx.send(latencies).await.unwrap();
        });
    }
    drop(tx);

    let mut all: Vec<u128> = Vec::with_capacity(READERS * PER_READER);
    while let Some(batch) = rx.recv().await {
        all.extend(batch);
    }

    let p50 = percentile_us(all.clone(), 50);
    let p99 = percentile_us(all, 99);
    println!("ARTICLE p50: {p50}µs  p99: {p99}µs  (10 concurrent readers, 1000 total fetches)");
}

// ── benchmark 2: LIST ACTIVE with 10 000 groups ───────────────────────────────

fn bench_list_active() {
    const GROUPS: usize = 10_000;
    const ITERS: usize = 100;

    let groups: Vec<GroupInfo> = (0..GROUPS).map(make_group).collect();

    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        let resp = list_active(&groups, None);
        let elapsed = t0.elapsed().as_millis();
        std::hint::black_box(resp.code);
        samples.push(elapsed);
    }

    let p50 = {
        let mut s = samples.clone();
        s.sort_unstable();
        s[s.len() / 2]
    };
    println!("LIST ACTIVE p50: {p50}ms  (10000 groups)");
}

// ── benchmark 3: RSS memory baseline ─────────────────────────────────────────

fn rss_baseline() {
    const GROUPS: usize = 10_000;
    const ARTICLES: usize = 1_000;

    // Load data into memory and keep it live until we read RSS.
    let groups: Vec<GroupInfo> = (0..GROUPS).map(make_group).collect();
    let articles: Vec<ArticleContent> = (0..ARTICLES).map(make_article).collect();

    // Touch every element to ensure the allocator actually committed pages.
    let mut sink: u64 = 0;
    for g in &groups {
        sink ^= g.high;
    }
    for a in &articles {
        sink ^= a.article_number;
    }
    std::hint::black_box(sink);

    let status = std::fs::read_to_string("/proc/self/status")
        .expect("/proc/self/status must exist on Linux");

    let rss_kb: u64 = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("VmRSS line must be present and numeric in /proc/self/status");

    println!("RSS under load: {rss_kb} kB");
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    bench_article_fetch().await;
    bench_list_active();
    rss_baseline();
}
