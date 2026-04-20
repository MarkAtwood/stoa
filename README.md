# usenet-ipfs

A Rust implementation of NNTP transit and reader servers backed by IPFS content-addressed storage and a libp2p gossipsub overlay for group-state reconciliation.

Usenet articles are stored as IPLD blocks in IPFS, addressed by CID. Per-group state is a Merkle-CRDT append-only log reconciled peer-to-peer. Standard newsreader clients — slrn, tin, pan, gnus, Thunderbird — connect to the reader daemon over unmodified RFC 3977 NNTP and do not need to know anything about the underlying storage or transport.

---

## What this is

Two binaries sharing a core library:

| Binary | Role |
|--------|------|
| `usenet-ipfs-transit` | Peering daemon. Accepts articles via IHAVE/TAKETHIS, stores to IPFS, appends to group log, propagates over gossipsub. Operator CLI for pinning policy, GC, and metrics. |
| `usenet-ipfs-reader` | RFC 3977 NNTP server. Serves articles from IPFS to newsreader clients. Synthesizes local sequential article numbers per `(group, server)` instance, maintains an overview index, handles POST. |

`usenet-ipfs-core` (rlib) holds shared types: article format, CID scheme, Message-ID↔CID mapping, the Merkle-CRDT group log, canonical serialization, and signing.

## Architecture

### Article storage

Articles are stored as IPLD blocks addressed by their content CID. A `message_id → CID` index bridges the legacy Message-ID namespace. Articles are never mutated; retraction is not supported in v1.

### Group state

Each newsgroup has a per-group Merkle-CRDT append-only log. Log entries carry `(hybrid-logical-clock timestamp, article_cid, operator_signature)`. Tips are advertised over gossipsub and via DHT fallback. Late-joining peers perform DAG backfill by following parent links.

### Gossipsub topology

Gossipsub topics are per-hierarchy, not per-group. `comp.*` is one topic; filtering by group name happens inside it. The naming scheme is `usenet.hier.<hierarchy>` (e.g. `usenet.hier.comp`, `usenet.hier.sci`). Per-group topics do not scale past low hundreds of groups per peer.

### Article numbers

Local sequential article numbers are synthetic. They are generated at ingress for a specific `(group, reader_server)` instance and stored in SQLite as `(group, local_num) → CID`. They are never network-stable or used as CID pointers.

### Signing

Every article is operator-signed with an ed25519 key before it is written to IPFS or appended to a group log. The POST path validates, signs, writes to IPFS, appends to each group named in `Newsgroups:`, and publishes over gossipsub.

### Retention

Every article in IPFS is either operator-pinned or subject to a declared GC policy. There is no implicit retention. "It's in IPFS" is not a retention strategy.

## Design invariants

These are non-negotiable. Any issue, PR, or design that conflicts with them must be flagged before proceeding.

1. **Reader speaks RFC 3977 verbatim.** No protocol extensions. LIST, GROUP, ARTICLE, HEAD, BODY, OVER/XOVER, POST, IHAVE, NEWGROUPS, NEWNEWS, CAPABILITIES, AUTHINFO, STARTTLS must work with unmodified newsreader clients.
2. **v1 is text-only.** Binary groups, yEnc, and NZB-equivalent manifests are out of scope. One deferred epic exists as a placeholder.
3. **No moderation in v1.** No cancel messages, no NoCeM, no curation feeds. Filter nothing, moderate nothing.
4. **Gossipsub topics are per-hierarchy.** `comp.*` is one topic; `comp.lang.rust` is filtered inside it.
5. **Article numbers are local and synthetic.** Never treat them as network-stable identifiers.
6. **Retention is explicit.** Every stored article must be covered by a pinning or GC policy.

## Status

**Planning and issue-creation phase.** The Beads issue graph is being built out; no implementation code exists yet. The IPFS client library (iroh vs rust-ipfs vs raw rust-libp2p + custom bitswap) is an open question that will be resolved in a dedicated spike issue before implementation begins.

See `PREPLAN.md` for the full epic decomposition and scope definition.

## Planned workspace layout

```
usenet-ipfs/
├── Cargo.toml              workspace manifest
├── crates/
│   ├── core/               usenet-ipfs-core (rlib)
│   ├── transit/            usenet-ipfs-transit (bin)
│   └── reader/             usenet-ipfs-reader (bin)
└── .beads/                 issue tracker
```

## Building

No code exists yet. This section will be updated when the workspace is initialized. The planned build commands:

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
```

Requirements: Rust edition 2021, stable toolchain. Runtime dependencies: tokio, sqlx + SQLite, ed25519-dalek, libp2p/gossipsub. IPFS client library TBD (spike issue).

## Contributing

The project uses [Beads](https://github.com/beads-dev/beads) for issue tracking. Check `bd ready` for available work. All non-trivial changes must trace to an open issue. See `AGENTS.md` for crate boundaries, architectural rules, and quality gate commands.

## License

MIT
