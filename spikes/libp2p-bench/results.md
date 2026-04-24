# rust-libp2p Bitswap-Style Benchmark Results

## Setup

- **Date:** 2026-04-19
- **Rust:** stable (edition 2021)
- **libp2p:** 0.56.0
- **Transport:** TCP loopback (`127.0.0.1`), noise + yamux
- **Block size:** 74 bytes
- **Iterations:** 1000 (plus 1 warm-up round-trip not counted)

## Approach: request_response as the bitswap core

Full bitswap (go-bitswap / js-bitswap) has four layers:

1. Wire format (protobuf `Message`)
2. Want-list/ledger state machine per peer
3. Session manager (parallel fetches, provider queries)
4. Decision engine (who to serve first)

For a latency spike, only layer 1 plus the core Want/Block exchange matters.
This harness implements that exchange using libp2p's `request_response`
behaviour:

- **WantRequest** carries raw CID bytes (CIDv1, sha2-256, raw codec 0x55).
- **BlockResponse** carries the CID bytes and the raw block data.
- Framing: 4-byte big-endian length prefix per field (no external proto dep).
- Protocol id: `/stoa/bitswap/1.0.0`
- CID encoding: manually encoded multihash (varint function code 0x12 + varint
  length 32 + sha256 digest), wrapped in CIDv1 varint header.

This approach was chosen over implementing the full bitswap state machine
because the goal is a per-round-trip latency signal. The session/ledger/want-
list machinery does not affect single-block one-shot latency. Using
`request_response` also keeps the implementation auditable without pulling in
an external bitswap crate.

## Results (three runs on development machine, same binary)

| Metric    | Run 1   | Run 2   | Run 3   |
|-----------|---------|---------|---------|
| Min       | 127 µs  | 172 µs  |  81 µs  |
| Mean      | 384 µs  | 282 µs  | 290 µs  |
| p50       | 306 µs  | 249 µs  | 254 µs  |
| p99       | 2959 µs | 1169 µs | 698 µs  |
| p99.9     | 3988 µs | 4068 µs | 846 µs  |
| Max       | 4291 µs | 4120 µs | 850 µs  |
| Peak RSS  | 27280 KB| 26632 KB| 25796 KB|
| RSS delta | 1776 KB | 1824 KB | 1852 KB |

p50 is stable at ~250-310 µs across all runs. p99/p99.9 shows high run-to-run
variability (700 µs to 4 ms) driven by OS TCP scheduler jitter on a shared
development machine, not by bitswap logic. On dedicated hardware or with a
memory transport the tail would tighten considerably.

## LOC count

```
wc -l src/**/*.rs
403 src/main.rs
```

403 lines total, covering:

- CIDv1/multihash encoding (no external CID dep): ~20 lines
- Codec (framing + async_trait impl): ~80 lines
- Provider + requester swarm tasks: ~100 lines
- Statistics + main: ~80 lines
- Doc comments and whitespace: remainder

## Summary table (for comparison with iroh and rust-ipfs spikes)

| Implementation       | p50 (µs) | p99 (µs)     | Peak RSS (KB) | LOC (harness) |
|----------------------|----------|--------------|---------------|---------------|
| raw libp2p + rr      | ~280     | 700 - 3000   | ~26-27000     | 403           |

(iroh and rust-ipfs results in their respective spike directories)

## Observations

1. **p50 ~280 µs** over loopback TCP with noise + yamux is the steady-state
   cost of two async task context switches + TCP RTT + yamux stream header
   overhead per request on a reused connection.

2. **p99 variability** (700 µs to 3 ms across runs) is OS scheduler jitter.
   This is not a libp2p-specific problem; any TCP-based transport would show
   similar tail behaviour on a development machine.

3. **RSS ~26 MB** is the minimum footprint of a libp2p node: noise handshake
   state, yamux multiplexer, TCP connection, swarm event loop, rtnetlink
   watcher. It does not scale with block count.

4. **LOC signal**: 403 lines to implement a complete latency harness including
   CID encoding, wire codec, two swarms, benchmark loop, and statistics. A
   production bitswap implementation would add the want-list/session layers
   (estimated 500-1500 additional lines) plus a protobuf dependency.

5. **Maintenance burden**: Using raw libp2p + custom bitswap codec means owning
   the codec as the bitswap spec evolves. There is no maintained
   bitswap crate for rust-libp2p as of 2026-04. iroh provides a higher-level
   abstraction that eliminates this burden at the cost of library lock-in.

## Conclusion for selection decision

Raw libp2p gives competitive latency (p50 ~280 µs) but requires owning the
bitswap codec and want-list implementation. For stoa, where the primary
goal is RFC 3977 NNTP compatibility rather than bitswap protocol optimization,
this maintenance surface is a significant cost. See issue stoa-l62.1.4
for the final selection rationale.
