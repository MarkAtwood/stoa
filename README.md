# usenet-ipfs

A Rust implementation of NNTP transit and reader servers backed by IPFS content-addressed storage and a libp2p gossipsub overlay for group-state reconciliation.

Usenet articles are stored as IPLD blocks in IPFS, addressed by CID. Per-group state is a Merkle-CRDT append-only log reconciled peer-to-peer. Standard newsreader clients — slrn, tin, pan, gnus, Thunderbird — connect to the reader daemon over unmodified RFC 3977 NNTP and do not need to know anything about the underlying storage or transport.

---

## What this is

Two binaries sharing a core library:

| Binary | Role |
|--------|------|
| `usenet-ipfs-transit` | Peering daemon. Accepts articles via IHAVE/TAKETHIS, stores to IPFS, appends to group log, propagates over gossipsub. Admin HTTP endpoint for operator inspection. |
| `usenet-ipfs-reader` | RFC 3977 NNTP server. Serves articles from IPFS to newsreader clients. Synthesizes local sequential article numbers per `(group, server)` instance, maintains an overview index, handles POST. |

`usenet-ipfs-core` (rlib) holds shared types: article format, CID scheme, Message-ID↔CID mapping, the Merkle-CRDT group log, canonical serialization, and signing.

## Architecture

### Article storage

Articles are stored as DAG-CBOR IPLD blocks addressed by their content CID (SHA-256 multihash, CIDv1 codec 0x71). A `message_id → CID` index bridges the legacy Message-ID namespace. Articles are never mutated; retraction is not supported in v1.

### Group state

Each newsgroup has a per-group Merkle-CRDT append-only log. Log entries carry `(hybrid-logical-clock timestamp, article_cid, operator_signature)`. Tips are advertised over gossipsub. Late-joining peers perform DAG backfill by following parent links.

### Gossipsub topology

Gossipsub topics are per-hierarchy, not per-group. `comp.*` is one topic; filtering by group name happens inside it. The naming scheme is `usenet.hier.<hierarchy>` (e.g. `usenet.hier.comp`, `usenet.hier.sci`).

### Article numbers

Local sequential article numbers are synthetic. They are generated at ingress for a specific `(group, reader_server)` instance and stored in SQLite as `(group, local_num) → CID`. They are never network-stable or used as CID pointers.

### Signing

Every article is operator-signed with an ed25519 key before it is written to IPFS or appended to a group log. The POST path validates, signs, writes to IPFS, appends to each group named in `Newsgroups:`, and publishes over gossipsub.

### Retention

Every article in IPFS is either operator-pinned or subject to a declared GC policy. There is no implicit retention. "It's in IPFS" is not a retention strategy.

## Status

**Working implementation.** Both binaries build and run. 730+ tests pass across the workspace (~30K LOC). RFC 3977 conformance is verified by a Python nntplib client test and a two-process transit+reader integration test.

Implemented and tested:
- Full NNTP command set: CAPABILITIES, LIST, GROUP, OVER/XOVER, ARTICLE, HEAD, BODY, POST, IHAVE, QUIT
- Article ingestion pipeline: parse → IPFS write (DAG-CBOR) → group log append → gossipsub publish
- Merkle-CRDT group log with HLC timestamps and ed25519 signatures
- rust-ipfs 0.15.0 node embedded in transit
- Gossipsub swarm with per-hierarchy topic subscription
- Gossip reconciliation: tip advertisement parsing, want/have set computation, v1 stub backfill
- SQLite-backed overview index and article number store
- Admin HTTP endpoint (`/health`, `/stats`, `/log-tip`, `/peers`, `/metrics`)
- AUTHINFO USER/PASS (reader) and optional bearer token (admin endpoint)
- STARTTLS skeleton (TLS infrastructure wired, not yet advertised)

Not yet implemented (tracked as open issues):
- TLS NNTP (STARTTLS)
- Peer block fetch (backfill contacts remote peers; v1 stubs out the fetch)
- Operator key persistence (currently ephemeral; warning emitted at startup)
- GC policy enforcement
- Binary groups, yEnc (deferred)

## Design invariants

These are non-negotiable. Any issue, PR, or design that conflicts with them must be flagged before proceeding.

1. **Reader speaks RFC 3977 verbatim.** No protocol extensions that break standard clients. LIST, GROUP, ARTICLE, HEAD, BODY, OVER/XOVER, POST, IHAVE, NEWGROUPS, NEWNEWS, CAPABILITIES, AUTHINFO, STARTTLS must work with unmodified newsreader clients.
2. **v1 is text-only.** Binary groups, yEnc, and NZB-equivalent manifests are out of scope.
3. **No moderation in v1.** No cancel messages, no NoCeM, no curation feeds.
4. **Gossipsub topics are per-hierarchy.** `comp.*` is one topic; `comp.lang.rust` is filtered inside it.
5. **Article numbers are local and synthetic.** Never treat them as network-stable identifiers.
6. **Retention is explicit.** Every stored article must be covered by a pinning or GC policy.

## Workspace layout

```
usenet-ipfs/
├── Cargo.toml                  workspace manifest
├── crates/
│   ├── core/                   usenet-ipfs-core (rlib): article types, CID scheme,
│   │                           group log (Merkle-CRDT), signing, canonical serialization
│   ├── transit/                usenet-ipfs-transit (bin): peering, gossipsub, IPFS node,
│   │                           pipeline, admin HTTP endpoint
│   ├── reader/                 usenet-ipfs-reader (bin): RFC 3977 NNTP server,
│   │                           article number synthesis, overview index, POST path
│   └── integration-tests/      cross-crate integration and conformance tests
├── spikes/                     IPFS client library benchmark results
├── .beads/                     issue tracker (Dolt-backed)
├── PREPLAN.md                  original epic decomposition
└── docs/
    └── RUNBOOK.md              operator deployment guide
```

## Building

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
```

Requirements: Rust stable toolchain (edition 2021). Runtime: tokio async runtime, sqlx + SQLite, ed25519-dalek, libp2p/gossipsub via rust-ipfs 0.15.0.

See `docs/RUNBOOK.md` for deployment instructions.

## Contributing

The project uses [Beads](https://github.com/beads-dev/beads) for issue tracking. Check `bd ready` for available work. All non-trivial changes must trace to an open issue.

## License

MIT
