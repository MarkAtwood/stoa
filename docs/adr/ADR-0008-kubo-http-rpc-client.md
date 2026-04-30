# ADR-0008: Kubo HTTP RPC Client for IPFS Block Operations

**Status:** Accepted
**Date:** 2026-04-29
**Supersedes:** ADR-0002

---

## Context

ADR-0002 selected `rust-ipfs` 0.15.0 as an embedded IPFS node with no external
daemon dependency. During implementation, three problems surfaced:

1. **Gossipsub coupling.** ADR-0002's justification for rust-ipfs included
   sharing the libp2p swarm with the gossipsub dissemination layer. When
   gossipsub was removed (see ADR-0009), the primary architectural benefit of
   rust-ipfs over a simpler HTTP client disappeared.

2. **Operational complexity.** An embedded IPFS node manages its own datastore,
   swarm keys, peer discovery, and DHT participation. Operators who already run
   Kubo for other purposes would run two embedded IPFS nodes if stoa embedded
   its own. Kubo is the dominant IPFS implementation, widely operated, and has a
   mature HTTP RPC API.

3. **Library maturity.** `rust-ipfs` 0.15.0 lacked production hardening in
   areas needed by stoa: circuit-breaker integration, configurable timeout
   behaviour, and clean separation between block-level and pin-level operations.
   Implementing these on top of the Kubo HTTP API was straightforward.

The Kubo HTTP RPC API (`/api/v0/block/put`, `/api/v0/block/get`,
`/api/v0/pin/add`, `/api/v0/pin/rm`, `/api/v0/name/publish`) is stable,
versioned, and documented. It requires a running `kubo` daemon, but this is
already a standard part of IPFS operator tooling.

---

## Decision

Use a lightweight `KuboHttpClient` (in `stoa-core::ipfs`) that speaks the Kubo
HTTP RPC API over `reqwest`. A `CircuitBreakerKuboClient` wraps it with a
circuit breaker that trips after configurable consecutive failures and exposes
`kubo_circuit_breaker_*` Prometheus metrics.

The `IpfsStore` trait in `stoa-transit` abstracts over all block store backends
(Kubo, LMDB, S3, GCS, Azure, RADOS, WebDAV, RocksDB, SQLite, filesystem).
Kubo is one of ten interchangeable backends, selected at runtime via operator
config.

---

## Consequences

- **Requires external Kubo daemon.** Deployment is no longer a single binary
  for IPFS functionality. Operators run `kubo` (or any Kubo-compatible daemon)
  alongside `stoa-transit` and `stoa-reader`. This is the established pattern
  for IPFS-integrated services.
- **CIDv1 SHA-256 compatibility preserved.** The Kubo API produces and accepts
  standard CIDv1 SHA-256 multihash blocks. No change to the CID scheme.
- **Backend diversity.** The `IpfsStore` abstraction means operators who do not
  want to run Kubo can use LMDB, S3, or another backend. Kubo is not mandatory.
- **Simpler dependency tree.** Replacing `rust-ipfs` 0.15.0 (466 transitive
  crates, ~2 min 15 s cold build) with `reqwest` reduces compile time and
  narrows the dependency surface.
- **Circuit breaker.** `CircuitBreakerKuboClient` prevents Kubo unavailability
  from cascading into transit pipeline stalls. Tripped circuit returns
  `KuboError::CircuitOpen` immediately without waiting for TCP timeout.
