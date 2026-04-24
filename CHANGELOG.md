# Changelog

All notable changes to stoa will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Core crate: article format, CID scheme (DAG-CBOR codec 0x71), Message-ID map (SQLite), ed25519 signing
- Core crate: Merkle-CRDT per-group append-only log with reconcile and backfill
- Core crate: canonical serialization (RFC 8785 canonical JSON conventions)
- Core crate: audit log (AuditEvent enum, AuditLogger with buffered writes)
- Transit daemon: peering (IHAVE, CHECK/TAKETHIS, MODE STREAM), rate limiting, back-pressure
- Transit daemon: store-and-forward pipeline (IPFS → msgid_map → group log → gossipsub)
- Transit daemon: gossipsub topology (per-hierarchy topics `stoa.hier.<hierarchy>`, tip advertisements)
- Transit daemon: DHT-based tip discovery fallback
- Transit daemon: article pinning policy and GC scheduler
- Transit daemon: operator CLI (peer management, pin/unpin, gc-run, audit export, keygen)
- Transit daemon: Prometheus metrics
- Reader daemon: RFC 3977 NNTP command surface (GROUP, ARTICLE, HEAD, BODY, LIST, OVER, POST, CAPABILITIES, AUTHINFO, STARTTLS, HDR, MODE STREAM)
- Reader daemon: group metadata cache (TTL-based)
- Property-based tests: CRDT commutativity, idempotency, convergence (proptest)
- Fault injection tests: IPFS unavailable, malformed articles, store failures
- Developer tooling: justfile, cargo-nextest config, criterion benchmarks

[Unreleased]: https://github.com/MarkAtwood/stoa/compare/HEAD...HEAD
