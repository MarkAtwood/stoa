use rust_ipfs::block::BlockCodec;
use rust_ipfs::builder::DefaultIpfsBuilder;
use rust_ipfs::Block;
use ipld_core::cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::time::Instant;

const ITERATIONS: usize = 1000;
const BLOCK_SIZE: usize = 1024;

fn current_rss_kb() -> u64 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse().unwrap_or(0);
                }
            }
        }
    }
    0
}

fn make_block(seed: u8) -> (Cid, Block) {
    let data: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i as u8).wrapping_add(seed)).collect();
    let hash = Code::Sha2_256.digest(&data);
    let cid = Cid::new_v1(BlockCodec::Raw.into(), hash);
    let block = Block::new(cid, data).expect("block hash must be valid");
    (cid, block)
}

fn percentile(sorted: &[u128], pct: f64) -> u128 {
    assert!(!sorted.is_empty());
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[tokio::main]
async fn main() {
    // Build a minimal in-memory IPFS node with no network transports.
    // DefaultIpfsBuilder::new() uses Repo::new_memory() by default.
    let ipfs = DefaultIpfsBuilder::new()
        .start()
        .await
        .expect("IPFS node should start");

    // Pre-generate 256 distinct blocks (cycling seed 0..255) to avoid any
    // deduplication shortcut on repeated identical data.
    let blocks: Vec<(Cid, Block)> = (0u8..=255u8).map(make_block).collect();

    let mut put_latencies_ns: Vec<u128> = Vec::with_capacity(ITERATIONS);
    let mut get_latencies_ns: Vec<u128> = Vec::with_capacity(ITERATIONS);
    let mut max_rss_kb: u64 = 0;

    for i in 0..ITERATIONS {
        let (cid, block) = &blocks[i % blocks.len()];

        let t0 = Instant::now();
        ipfs.put_block(block).await.expect("put_block should succeed");
        put_latencies_ns.push(t0.elapsed().as_nanos());

        let t1 = Instant::now();
        let retrieved = ipfs.get_block(cid).await.expect("get_block should succeed");
        get_latencies_ns.push(t1.elapsed().as_nanos());

        assert_eq!(retrieved.cid(), cid, "retrieved CID must match stored CID");

        let rss = current_rss_kb();
        if rss > max_rss_kb {
            max_rss_kb = rss;
        }
    }

    put_latencies_ns.sort_unstable();
    get_latencies_ns.sort_unstable();

    let put_p50 = percentile(&put_latencies_ns, 50.0);
    let put_p99 = percentile(&put_latencies_ns, 99.0);
    let put_p999 = percentile(&put_latencies_ns, 99.9);

    let get_p50 = percentile(&get_latencies_ns, 50.0);
    let get_p99 = percentile(&get_latencies_ns, 99.0);
    let get_p999 = percentile(&get_latencies_ns, 99.9);

    println!("rust-ipfs 0.15.0 benchmark results");
    println!("iterations:  {}", ITERATIONS);
    println!("block_size:  {} bytes", BLOCK_SIZE);
    println!();
    println!("put_block latency (ns):");
    println!("  p50:  {}", put_p50);
    println!("  p99:  {}", put_p99);
    println!("  p999: {}", put_p999);
    println!();
    println!("get_block latency (ns):");
    println!("  p50:  {}", get_p50);
    println!("  p99:  {}", get_p99);
    println!("  p999: {}", get_p999);
    println!();
    println!("peak RSS: {} KB", max_rss_kb);

    ipfs.exit_daemon().await;
}
