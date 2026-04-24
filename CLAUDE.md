# usenet-ipfs — Project Instructions for AI Agents

Greenfield Rust implementation of an NNTP transit server and NNTP reader server where article storage is IPFS and group state is a Merkle-CRDT append-only log reconciled over libp2p gossipsub. Standalone system; no Corundum integration in v1.

## What This Is

Two binaries sharing a core crate:

- **`usenet-ipfs-transit`** — peering daemon; store-and-forward, pinning policy, GC, metrics
- **`usenet-ipfs-reader`** — RFC 3977 NNTP server; speaks to standard newsreaders (slrn, tin, pan, gnus, Thunderbird) without modification
- **`usenet-ipfs-core`** — shared types: article format, CID scheme, group log, CRDT, protocol

Articles are stored as IPLD blocks addressed by CID. A `message_id → CID` mapping table bridges legacy Usenet Message-IDs. Group state is a Merkle-CRDT append-only log per group; entries are `(timestamp, article_cid, signature, optional_did)`. Local sequential article numbers per `(group, reader_server)` are synthesized on ingress and stored in SQLite as `(group, local_num) → CID`.

## Hard Design Invariants

These are non-negotiable. Do not relitigate them. Raising an exception requires explicit user approval.

1. **Reader server speaks RFC 3977 plus standard IANA-registered extensions.** All RFC 3977 commands must work with unmodified newsreader clients (`LIST`, `GROUP`, `ARTICLE`, `HEAD`, `BODY`, `OVER`/`XOVER`, `POST`, `IHAVE`, `NEWGROUPS`, `NEWNEWS`, `CAPABILITIES`, `AUTHINFO`, `STARTTLS`). Standard additive extensions are permitted — `HDR` (RFC 3977 §8.5), `LIST OVERVIEW.FMT` (RFC 6048), `MODE STREAM`/`CHECK`/`TAKETHIS` (RFC 4644) — because clients probe via `CAPABILITIES` and degrade gracefully. **Permitted leaky extensions:** additive `X-Usenet-IPFS-*` article headers and RFC 3977 §7.2 `X`-prefixed commands that expose only content addressing (CIDs and integrity verification) are allowed, provided they are advertised in `CAPABILITIES` and standard clients degrade gracefully without seeing them. **Prohibited leaky extensions:** anything that exposes peer topology, DHT state, CRDT log internals, pin status, GC policy, or any IPFS infrastructure state. The rule is: a standard newsreader that never sends an `X` command and never reads `X-Usenet-IPFS-*` headers must behave identically to today.
2. **v1 is text-only.** Binary groups and yEnc are out of scope. One deferred epic covers the future CID manifest approach. Do not implement or design yEnc/NZB in any active issue.
3. **No moderation in v1.** No cancel messages, no NoCeM, no curation feeds. Filter nothing, moderate nothing.
4. **Gossipsub topics are per-hierarchy, not per-group.** `comp.*` is one topic; `comp.lang.rust` is filtered inside it. Per-group topics do not scale past low hundreds of groups per peer.
5. **Article numbers are local and synthetic.** Generated at ingress for a specific `(group, reader_server)` instance. Never treat a local article number as a CID pointer or network-stable identifier.
6. **Retention is explicit.** Every article in IPFS must be either operator-pinned or subject to a declared GC policy. "It's in IPFS" is not a retention strategy.

## Build & Test

Project is in planning/issue-creation phase; no code exists yet. Update this section when the workspace is initialized.

```bash
# Once workspace exists:
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
```

## Planned Workspace Layout

```
usenet-ipfs/
├── Cargo.toml              workspace manifest
├── crates/
│   ├── core/               usenet-ipfs-core (rlib): article types, CID scheme,
│   │                       group log (Merkle-CRDT), signing, canonical serialization
│   ├── transit/            usenet-ipfs-transit (bin): peering, store-and-forward,
│   │                       pinning policy, GC, metrics, operator CLI
│   └── reader/             usenet-ipfs-reader (bin): RFC 3977 NNTP server,
│                           article number synthesis, overview index, POST path
├── .beads/                 issue tracker data
├── spikes/                 IPFS client library benchmark results (iroh, rust-ipfs, libp2p)
└── PREPLAN.md              epic decomposition input (do not delete)
```

## Conventions & Patterns

- **Rust edition 2021, resolver v2.** Do not downgrade.
- **`tokio` async runtime throughout.** No sync I/O on the main task pool.
- **`sqlx` + SQLite for local state.** All SQL in dedicated store modules; no SQL scattered through application logic.
- **Signing:** `ed25519-dalek` (fixed choice).
- **IPFS client:** `rust-ipfs` 0.15.0 (selected, spike complete). iroh-blobs disqualified — uses BLAKE3, not SHA-2/CIDv1. raw libp2p + custom bitswap viable but requires owning the bitswap codec. Spike results in `spikes/`, decision recorded in usenet-ipfs-l62.1.4.
- **License: MIT for all production binaries.** `usenet-ipfs-smtp` is now MIT-licensed; it uses `usenet-ipfs-sieve-native` (MIT), not `usenet-ipfs-sieve` (AGPL-3.0-only). The `usenet-ipfs-sieve` crate remains in the workspace but is not linked by any production binary.
- **No `unsafe` outside FFI boundary crates.** If you think you need `unsafe`, stop and ask.
- **Cargo features are additive.** Never enable an algorithm or capability unconditionally in `Cargo.toml`.
- **Error types live in `core`.** Other crates import from there.
- **Gossipsub topic naming:** `usenet.hier.<hierarchy>` (e.g. `usenet.hier.comp`). In-topic filtering by group name.
- **Canonical serialization:** RFC 8785 canonical JSON + Corundum Chapter 31 conventions (sorted keys, NFKC normalization, UTC timestamps with `Z` suffix, no whitespace, trailing zeros stripped from fractional seconds). All signed or hashed objects must serialize deterministically. Test vectors must come from an independent reference implementation (Python `canonicaljson`, js `dag-json`, or equivalent).
- **IPLD codec:** **DAG-CBOR (codec 0x71) selected and final** (spike l62.2.9.10 resolved). DAG-CBOR is more compact, standard for IPFS storage, and Corundum can reference DAG-CBOR CIDs from its DAG-JSON activities — codec of referenced content need not match the referencing document. Implementation: `serde_ipld_dagcbor` 0.6. This choice is irreversible once articles are written to IPFS and referenced in group logs.
- **Future Corundum integration (not v1):** Corundum will define an `rfc822+mime` activity type whose content reference is a usenet-ipfs article root CID. The article IPLD schema must be traversable by standard IPLD tooling and rich enough (message_id, newsgroups, content_type_summary in metadata) for Corundum to render a preview. Design choices made now must not foreclose this extension.

## Test Integrity

- Never modify, skip, or weaken a failing test to make it pass. Fix the code.
- Tests must have an independent oracle: known test vectors from an external source, or cross-validation between two independent implementations.
- A test that encodes/decodes with the same code under test and asserts roundtrip proves nothing.
- RFC 3977 conformance tests must be driven by real unmodified newsreader clients (`slrn`, `tin`, `pan`, Thunderbird) against a live reader process — not mocked.
- IPLD/CID tests must cross-validate against a reference implementation, not just self-verify.

## Security Defaults

- Never log signing keys, seed material, or DID private keys.
- Treat all NNTP input (commands, headers, article bodies) as attacker-controlled.
- Validate article size limits, header field lengths, and group name format at ingress before any storage.
- `message_id` from the NNTP wire is untrusted; validate format before using as a map key or log entry.
- `POST` path: operator signs every article before writing to IPFS. Never write an unsigned article to the group log.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
