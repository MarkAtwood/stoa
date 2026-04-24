# ADR-0002: rust-ipfs 0.15.0 as the Embedded IPFS Client

## Status
Accepted

## Context

The system stores every article as a DAG-CBOR IPLD block addressed by CIDv1
with a SHA-256 multihash. The IPFS client library must satisfy:

1. CIDv1 SHA-256 (not BLAKE3) content addressing, so that CIDs produced locally
   are compatible with the broader IPFS network and verifiable by standard tools.
2. An embedded node model with no external daemon: deployment must be a single
   binary with no dependency on a running `kubo`/`go-ipfs` process.
3. Native libp2p gossipsub support, because the group log dissemination layer is
   built on gossipsub and sharing a libp2p swarm avoids running two separate
   network stacks.

Three options were spiked (results in `spikes/`):

**iroh-blobs 0.99.0** (spike: `spikes/iroh-bench/`)

iroh-blobs uses BLAKE3 for content addressing, not SHA-256/CIDv1. This is a
hard disqualifier: CIDs produced by iroh cannot be verified or exchanged with
standard IPFS tooling, and the group log references article CIDs permanently.
Benchmark results (p50 add 38.9 µs, p50 get 17.6 µs, RSS delta 752 KB) are
fast and memory-efficient, but the hash algorithm incompatibility is
non-negotiable.

**raw libp2p 0.56.0 + custom bitswap codec** (spike: `spikes/libp2p-bench/`)

Using `libp2p::request_response` as the bitswap transport layer produced a
working harness in 403 lines. Loopback TCP p50 round-trip was ~280 µs with p99
varying from 700 µs to 3 ms across runs (OS scheduler jitter). The approach
uses SHA-256 CIDv1 correctly. However, implementing production bitswap requires
the want-list/session/decision-engine layers (estimated 500–1 500 additional
lines) and owning the codec as the bitswap spec evolves. There is no maintained
bitswap crate for rust-libp2p as of 2026-04. For a project where the primary
goal is RFC 3977 NNTP compatibility, that maintenance surface is a significant
ongoing cost.

**rust-ipfs 0.15.0** (spike: `spikes/rust-ipfs-bench/`)

Embedded IPFS node, no external daemon. Benchmarked on stable Rust 1.94.0 with
an in-memory blockstore. Results across three runs: put_block p50 ~250 ns, p99
~5 µs; get_block p50 ~930 ns, p99 ~1.6 µs. Peak RSS ~10.5 MiB. Compiles on
stable Rust (edition 2021, MSRV 1.83). The library exposes a libp2p-native
gossipsub/kad stack, satisfying requirement 3 without a second network stack.
Dependency tree is 466 crates; compile time is ~2 min 15 s on an 18-core
machine (manageable via `cargo vendor`).

## Decision

Use `rust-ipfs` 0.15.0 as the embedded IPFS implementation. The node is
initialised via `DefaultIpfsBuilder` and held as a shared handle inside each
binary. The same libp2p swarm instance is reused for both bitswap block exchange
and gossipsub group-log dissemination.

This decision is recorded in Beads issue stoa-l62.1.4.

## Consequences

- SHA-256 CIDv1 compatibility is preserved throughout the system. CIDs produced
  locally are verifiable by standard IPFS tooling.
- No external daemon to manage. Deployment is a single binary per component.
- The gossipsub and kad-dht stacks come from the same swarm, avoiding two
  separate network stacks and duplicate peer-management state.
- 466-crate dependency tree increases cold build time. Mitigate with
  `cargo vendor` in CI.
- iroh-blobs performance characteristics (faster raw add/get) are not available.
  The rust-ipfs latency figures (p50 sub-microsecond in-process, p50 ~280 µs
  over loopback TCP) are well within NNTP response time budgets.
- If rust-ipfs 0.15.0 becomes unmaintained, the raw libp2p path remains viable
  as a fallback, at the cost of implementing the want-list/session layers.
