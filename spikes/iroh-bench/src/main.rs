use std::time::{Duration, Instant};

use bytes::Bytes;
use iroh_blobs::store::mem::MemStore;

const ITERATIONS: usize = 1000;
const BLOCK_SIZE: usize = 1024;

fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    let idx = ((sorted.len() as f64) * pct / 100.0).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

fn read_rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().unwrap_or(0);
            }
        }
    }
    0
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = MemStore::new();

    let block: Bytes = vec![0x42u8; BLOCK_SIZE].into();

    // Warm-up: one add/get cycle to let tokio runtime and store settle
    {
        let tag = store.add_slice(&block).await?;
        let _ = store.get_bytes(tag.hash).await?;
    }

    let rss_before_kb = read_rss_kb();

    // --- Add benchmark ---
    let mut add_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
    let mut hashes = Vec::with_capacity(ITERATIONS);

    for _ in 0..ITERATIONS {
        let data = block.clone();
        let t0 = Instant::now();
        let tag = store.add_slice(&data).await?;
        add_times.push(t0.elapsed());
        hashes.push(tag.hash);
    }

    // --- Get benchmark ---
    let mut get_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);

    for hash in &hashes {
        let t0 = Instant::now();
        let data = store.get_bytes(*hash).await?;
        get_times.push(t0.elapsed());
        assert_eq!(data.len(), BLOCK_SIZE, "unexpected retrieved block size");
    }

    let rss_after_kb = read_rss_kb();

    add_times.sort_unstable();
    get_times.sort_unstable();

    let fmt_us = |d: Duration| format!("{:.1} µs", d.as_secs_f64() * 1e6);

    let add_p50 = percentile(&add_times, 50.0);
    let add_p99 = percentile(&add_times, 99.0);
    let add_p999 = percentile(&add_times, 99.9);

    let get_p50 = percentile(&get_times, 50.0);
    let get_p99 = percentile(&get_times, 99.0);
    let get_p999 = percentile(&get_times, 99.9);

    let results = format!(
        "# iroh-blobs benchmark results\n\
         \n\
         - iroh-blobs version: 0.99.0\n\
         - Block size: {BLOCK_SIZE} bytes (1 KB)\n\
         - Iterations: {ITERATIONS}\n\
         - Store: MemStore (in-memory, no external daemon)\n\
         - Hardware: {}\n\
         \n\
         ## Add latency (add_slice)\n\
         \n\
         | Percentile | Latency |\n\
         |---|---|\n\
         | p50 | {} |\n\
         | p99 | {} |\n\
         | p99.9 | {} |\n\
         \n\
         ## Get latency (get_bytes)\n\
         \n\
         | Percentile | Latency |\n\
         |---|---|\n\
         | p50 | {} |\n\
         | p99 | {} |\n\
         | p99.9 | {} |\n\
         \n\
         ## Memory (RSS)\n\
         \n\
         | Metric | Value |\n\
         |---|---|\n\
         | RSS before benchmark | {} KB |\n\
         | RSS after {} adds + gets | {} KB |\n\
         | RSS delta | {} KB |\n\
         \n\
         ## Notes\n\
         \n\
         - All {ITERATIONS} adds produce the same CID (deterministic content-addressing).\n\
         - iroh-blobs uses BLAKE3 for content addressing, not SHA2/CIDv1 multihash.\n\
         - \"Pinning\" in iroh-blobs is managed via tags; holding a TagInfo keeps a blob\n\
           from being garbage-collected. No explicit pin call is required.\n\
         - No IPFS daemon, no network I/O: MemStore is fully in-process.\n\
         ",
        hardware_string(),
        fmt_us(add_p50), fmt_us(add_p99), fmt_us(add_p999),
        fmt_us(get_p50), fmt_us(get_p99), fmt_us(get_p999),
        rss_before_kb,
        ITERATIONS,
        rss_after_kb,
        rss_after_kb.saturating_sub(rss_before_kb),
    );

    print!("{results}");

    std::fs::write("results.md", &results)?;
    eprintln!("Results written to results.md");

    Ok(())
}

fn hardware_string() -> String {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    model
}
