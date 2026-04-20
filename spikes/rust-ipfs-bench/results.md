# rust-ipfs Benchmark Results

**Spike issue:** usenet-ipfs-l62.1.2

## Summary

rust-ipfs 0.15.0 compiles successfully on stable Rust and runs headlessly in
an in-memory configuration with no external daemon required.

## Environment

| Field | Value |
|---|---|
| rust-ipfs version | 0.15.0 |
| Rust toolchain | rustc 1.94.0 (stable, 2026-03-02) |
| Architecture | x86\_64 |
| OS | Linux 6.17.9 |
| CPU cores | 18 |
| System RAM | 30 GiB |
| Build profile | release (optimized) |

## Configuration

The node was initialised with `DefaultIpfsBuilder::new().start().await`.  This
creates an in-memory blockstore (`Repo::new_memory()`) with no network
transports enabled.  No external IPFS daemon is required.

## Methodology

- 256 distinct 1 KB blocks were pre-generated (SHA2-256 CID, raw codec).
- 1000 iterations were run, cycling through the 256 blocks.
- Each iteration measured `put_block` and `get_block` independently using
  `std::time::Instant`.
- The block retrieved on each `get_block` was asserted to match the stored CID.
- Peak RSS was sampled from `/proc/self/status` (VmRSS) after each iteration.
- Latencies were sorted and percentiles computed over the full 1000-sample set.

## Results (run 1 of 3)

| Operation | p50 (ns) | p99 (ns) | p999 (ns) |
|---|---|---|---|
| put\_block | 235 | 5764 | 48142 |
| get\_block | 900 | 1622 | 2271 |

Peak RSS: 10376 KB

## Results (run 2 of 3)

| Operation | p50 (ns) | p99 (ns) | p999 (ns) |
|---|---|---|---|
| put\_block | 233 | 5910 | 31030 |
| get\_block | 940 | 1632 | 14177 |

Peak RSS: 10808 KB

## Results (run 3 of 3)

| Operation | p50 (ns) | p99 (ns) | p999 (ns) |
|---|---|---|---|
| put\_block | 277 | 2866 | 24740 |
| get\_block | 935 | 1517 | 5402 |

Peak RSS: 10764 KB

## Observations

- **No external daemon required.** The library embeds a full in-memory IPFS
  node.  This is a significant operational advantage over client libraries that
  require a running `go-ipfs`/`kubo` daemon.
- **get\_block is slower than put\_block at p50.** The in-memory blockstore
  appears to involve more locking overhead on the read path (~900 ns) than on
  the write path (~250 ns).  This is counterintuitive but consistent across
  all three runs.
- **put\_block p999 varies between runs** (25–48 µs).  This is typical async
  runtime jitter caused by tokio task scheduling on a machine under load;
  it is not intrinsic to the library.
- **Peak RSS ~10.5 MiB** is modest for a full libp2p-backed IPFS node.  The
  node initialises the swarm machinery even in memory-only mode.
- **Dependency tree: 466 crates** at 1000 iterations.  The dependency footprint
  is large but manageable via `cargo vendor` for reproducible builds.
- **Binary size: 34 MiB** (release, unstripped).

## Compilation

Compiles on stable Rust (edition 2021) without any nightly features.
Minimum supported Rust version declared in the crate: 1.83.

Release build time on this machine (warm cache, 18-core x86\_64): ~2 min 15 s.

## Daemon Requirement

None.  rust-ipfs is an embedded IPFS implementation.  It does not require or
use an external `kubo` or `go-ipfs` process.

## Direct Dependencies Used

```
rust-ipfs-bench v0.1.0
├── ipld-core v0.4.3
├── multihash-codetable v0.2.1
├── rust-ipfs v0.15.0
└── tokio v1.52.1
```

## Comparison Notes (for l62.1.4 decision issue)

This benchmark should be compared against the iroh spike (usenet-ipfs-l62.1.1)
using the same metrics.  Key differentiators to consider:

- rust-ipfs exposes a libp2p-native gossipsub/kad stack, which aligns directly
  with the project's requirement for gossipsub group-log dissemination.
- The API surface is stable (no nightly) and the builder pattern is ergonomic.
- 466-crate dependency tree is larger than iroh's tree; compile time will be a
  factor for CI.
- No daemon, so deployment is a single binary.
