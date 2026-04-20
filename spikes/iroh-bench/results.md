# iroh-blobs benchmark results

- iroh-blobs version: 0.99.0
- Block size: 1024 bytes (1 KB)
- Iterations: 1000
- Store: MemStore (in-memory, no external daemon)
- Hardware: Intel(R) Core(TM) Ultra 5 125H

## Add latency (add_slice)

| Percentile | Latency |
|---|---|
| p50 | 38.9 µs |
| p99 | 2296.4 µs |
| p99.9 | 4536.5 µs |

## Get latency (get_bytes)

| Percentile | Latency |
|---|---|
| p50 | 17.6 µs |
| p99 | 59.0 µs |
| p99.9 | 611.0 µs |

## Memory (RSS)

| Metric | Value |
|---|---|
| RSS before benchmark | 4572 KB |
| RSS after 1000 adds + gets | 5324 KB |
| RSS delta | 752 KB |

## Notes

- All 1000 adds produce the same CID (deterministic content-addressing).
- iroh-blobs uses BLAKE3 for content addressing, not SHA2/CIDv1 multihash.
- "Pinning" in iroh-blobs is managed via tags; holding a TagInfo keeps a blob
from being garbage-collected. No explicit pin call is required.
- No IPFS daemon, no network I/O: MemStore is fully in-process.
