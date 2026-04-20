# Task: Plan NNTP-over-IPFS as a Beads epic tree

You are planning a greenfield Rust implementation of an NNTP transit server, an NNTP reader server, and the underlying group-state protocol beneath them. Article storage is IPFS (content-addressed by CID). Group state is a per-group Merkle-CRDT append-only log reconciled over libp2p gossipsub. This is a clean-sheet project with no upstream dependencies to reconcile against.

Do not write code. Do not write design documents. Your deliverable is a Beads issue graph, filed directly via the `bd` CLI, that a later agent can drive from `bd ready`.

## Scope

In scope:

- Article format, CIDs, canonical serialization, Message-ID to CID mapping
- Per-group Merkle-CRDT append-only log, tip reconciliation, late-join DAG backfill
- Gossipsub topology with per-hierarchy topic sharding and DHT fallback for tip discovery
- Transit daemon (peering, store-and-forward, pinning, GC, operator CLI, metrics)
- Reader daemon speaking RFC 3977 NNTP unchanged so `slrn`, `tin`, `pan`, `gnus`, Thunderbird work without modification
- Local sequential article number synthesis per `(group, reader_server)` persisted in SQLite
- POST path: validate, sign (operator key, with optional DID-signed payload passthrough), write to IPFS, append to each group log named in `Newsgroups:`, publish
- Legacy NNTP import via `IHAVE` or pull-style `suck`, plus mbox backfill
- Retention via operator pinning, with an explicit GC policy
- Observability: tracing, Prometheus metrics, admin HTTP endpoint
- Interop test harness against real newsreader clients, headless
- Security: threat model doc, spam mitigation spike (PoW stamp vs rate-limited signing), TLS, operator key management

Out of scope for this planning pass (do not file epics for these):

- Corundum integration of any kind (Merkle specs, event streams, curation feeds, DID, canonical serialization, timestamp spec). This is a standalone system for now.
- Moderation, curation feeds, allowlist/denylist. Filter nothing, moderate nothing in v1.
- Packaging, Debian, systemd units, Nix, containers, sample configs.
- Binary groups, yEnc, NZB-equivalent manifests. File one deferred P3 epic as a placeholder and move on.
- Filecoin deal orchestration. Operator pinning only.

## Architectural constraints (do not relitigate)

- Rust, edition 2021 or later
- `tokio` runtime, `sqlx` + SQLite for local state, `ed25519-dalek` for signing
- IPFS client library is an open question: file a spike to choose between `iroh`, `rust-ipfs`, and raw `rust-libp2p` + custom bitswap. Spike has benchmark and decision acceptance criteria.
- Transit and reader are separate binaries sharing a core crate
- Reader speaks RFC 3977 unchanged
- Text-only in v1
- Gossipsub topic-per-group does not scale past low hundreds of groups per peer. Topic sharding (per-hierarchy with in-topic filtering) is a first-class design item.

## Epic structure to file

One root epic. Child epics, in this order:

1. Technology spike: IPFS client library selection (spike + benchmark + decision writeup)
2. Core crate: article format, CID scheme, canonical serialization, Message-ID to CID map, signature verification
3. Core crate: group log (Merkle-CRDT append-only log), tip reconciliation, late-join backfill, hybrid-logical-clock ordering
4. Gossipsub topology: per-hierarchy sharding, tip advertisement, DHT fallback, backpressure
5. Transit daemon: peering config, store-and-forward, pinning policy, GC, metrics, operator CLI
6. Reader daemon, protocol surface: RFC 3977 commands (LIST, GROUP, ARTICLE, HEAD, BODY, OVER/XOVER, POST, IHAVE, NEWGROUPS, NEWNEWS, CAPABILITIES, AUTHINFO, STARTTLS), article number synthesis, overview index
7. Reader daemon, POST path: validation, operator signing, optional DID passthrough, IPFS write, group log append, gossipsub publish
8. Import tooling: legacy NNTP ingestion (IHAVE + pull), mbox backfill, Message-ID to CID indexing
9. Retention: pinning integration, expiration policy per group, GC semantics
10. Observability: tracing, Prometheus metrics, admin HTTP endpoint, log-tip exposure for debug
11. Interop test suite: headless clients (`slrn`, `tin`, `pan`, Thunderbird), RFC 3977 + RFC 5536 conformance harness
12. Security: threat model doc, spam mitigation spike, TLS on NNTP, operator key management
13. Deferred: binary groups / NZB-equivalent manifest (P3, single epic, blocked, placeholder only)

## Per-issue requirements

Every leaf issue must have:

- Title in imperative mood, under 80 characters
- One-paragraph description naming the exact artifact produced (crate, module, binary, doc, test)
- Acceptance criteria as a checklist, testable, no weasel words
- Dependencies declared via `bd dep add` to the issues that must land first. No cycles.
- Priority: P0 for core crate and reader protocol minimum-viable path. P1 for transit, gossipsub topology. P2 for import, retention, observability, interop, security. P3 for deferred.
- Estimate in t-shirt size (S/M/L/XL). Split XL issues before filing unless genuinely atomic spikes.
- Tag with one or more of: `core`, `transit`, `reader`, `protocol`, `ipfs`, `libp2p`, `identity`, `ops`, `interop`, `security`, `spike`, `doc`, `deferred`

## Execution instructions

1. If `.beads/` is absent in the current repo, run `bd init --quiet` first.
2. File the root epic, then each child epic, then leaf issues under each epic, then wire dependencies with `bd dep add`. File epics before the issues that live under them; file issues before the dependencies that reference them.
3. Use `bd create` with `--json` and capture IDs from its output for subsequent dependency wiring. Do not hand-construct IDs.
4. When all issues and dependencies are filed, run `bd ready --json` and show the output so I can see what is immediately workable.
5. Do not close or modify any pre-existing Beads issues.
6. Do not write any code. Do not create design documents. The only artifacts produced by this session are Beads issues and dependency edges.

If any constraint above is ambiguous, stop and ask before filing. Once you start filing, do not pause for confirmation between issues.
