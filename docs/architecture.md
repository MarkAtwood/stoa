# usenet-ipfs Architecture

## System Overview

usenet-ipfs is a Rust implementation of two cooperating daemons that replace traditional Usenet spool storage with IPFS content-addressed blocks and replace per-server group state with a Merkle-CRDT append-only log reconciled over libp2p gossipsub.

The workspace contains three crates:

- **`usenet-ipfs-core`** (`crates/core/`) — a library crate shared by both binaries. It owns all canonical types: article IPLD schema, CID derivation, group log types, signing, validation, canonical serialization, the `MsgIdMap` store, the `AuditEvent` store, and all SQLite migrations.

- **`usenet-ipfs-reader`** (`crates/reader/`) — a binary that speaks RFC 3977 NNTP to unmodified newsreader clients (slrn, tin, pan, Thunderbird). It handles the POST path (sign, write, log-append, gossip) and the read path (GROUP, ARTICLE, HEAD, BODY, OVER/XOVER). It maintains its own SQLite database for article numbers, the overview index, and (via core) the group log and msgid map.

- **`usenet-ipfs-transit`** (`crates/transit/`) — a binary that peers with other usenet-ipfs nodes and with traditional NNTP transit peers. It runs the store-and-forward pipeline (IHAVE/TAKETHIS/MODE STREAM, RFC 4644), drives GC against a declared pinning policy, manages the peer registry, and relays gossipsub tip advertisements between nodes.

```
usenet-ipfs/
├── Cargo.toml              workspace manifest
├── crates/
│   ├── core/               rlib: article types, IPLD, group log, signing, stores
│   ├── reader/             bin:  RFC 3977 NNTP server, POST pipeline, article numbers
│   └── transit/            bin:  peering, store-and-forward, GC, peer registry
├── docs/
├── spikes/                 benchmark results (iroh, rust-ipfs, libp2p)
└── .beads/                 issue tracker data
```

### Key Technology Choices

| Concern | Choice | Rationale |
|---|---|---|
| Async runtime | tokio | Required throughout; no sync I/O on task pool |
| IPFS client | rust-ipfs 0.15.0 | Spike-validated; iroh-blobs disqualified (BLAKE3 not SHA-2) |
| IPLD codec | DAG-CBOR (0x71) | Compact, standard for IPFS; CIDs are SHA-256 CIDv1 |
| Local state | sqlx + SQLite | Dedicated store modules; no SQL in application logic |
| Signing | ed25519-dalek | Fixed choice; operator key never logged |
| Canonical serialization | RFC 8785 JSON + Corundum Ch.31 conventions | All signed/hashed objects must be deterministic |

---

## ASCII Architecture Diagram

```
  Newsreader clients             NNTP transit peers
  (slrn, tin, pan,               (other usenet-ipfs
   Thunderbird, ...)              nodes, INN, etc.)
        |                               |
        | NNTP (RFC 3977)               | NNTP (MODE STREAM /
        | port 119 / NNTPS             |  IHAVE / TAKETHIS)
        v                               v
 ┌─────────────────────┐       ┌───────────────────────┐
 │  usenet-ipfs-reader │       │  usenet-ipfs-transit  │
 │                     │       │                       │
 │  session/           │       │  peering/             │
 │    lifecycle.rs     │       │    pipeline.rs        │
 │    dispatch.rs      │       │    mode_stream.rs     │
 │  post/              │       │  retention/           │
 │    pipeline.rs      │       │    gc.rs              │
 │    sign.rs          │       │    policy.rs          │
 │    log_append.rs    │       │  gossip/              │
 │  store/             │       │    tip_advert.rs      │
 │    article_numbers  │       │    swarm.rs           │
 │    overview.rs      │       │  import/              │
 └──────┬──────────────┘       └────────┬──────────────┘
        │                               │
        │  uses usenet-ipfs-core        │  uses usenet-ipfs-core
        │                               │
        └──────────┬────────────────────┘
                   │
        ┌──────────▼──────────────┐
        │   usenet-ipfs-core      │
        │                         │
        │  article.rs             │
        │  ipld/ (root_node,      │
        │    metadata, mime)      │
        │  group_log/             │
        │    types.rs             │
        │    append.rs            │
        │    reconcile.rs         │
        │  msgid_map.rs           │
        │  signing.rs             │
        │  validation.rs          │
        │  audit.rs               │
        │  canonical.rs           │
        │  hlc.rs                 │
        └──────┬──────────────────┘
               │
       ┌───────┴──────────────────────────┐
       │                                  │
       v                                  v
 ┌──────────────┐                 ┌──────────────────┐
 │   SQLite     │                 │   IPFS node      │
 │  (per-proc)  │                 │  (rust-ipfs)     │
 │              │                 │                  │
 │ msgid_map    │                 │  DAG-CBOR blocks │
 │ log_entries  │                 │  (article root,  │
 │ group_tips   │                 │   header block,  │
 │ audit_log    │                 │   body block,    │
 │ article_nums │  (reader only)  │   MIME nodes)    │
 │ overview     │  (reader only)  │                  │
 │ peers        │  (transit only) │                  │
 │ articles     │  (transit only) │                  │
 └──────────────┘                 └──────────────────┘
                                          |
                                 libp2p gossipsub
                                 topic: usenet.hier.<hierarchy>
                                          |
                                  Other usenet-ipfs nodes
```

---

## Data Flow: NNTP POST Path

This is the critical write path. All six steps must complete in order before the reader sends `240 Article received`.

### Step 1: Client sends POST to the reader daemon

The newsreader client opens a TCP connection (optionally upgraded to TLS via STARTTLS or immediate TLS on the configured port). The reader's `session/lifecycle.rs` accept loop dispatches the `POST` command. The session sends `340 Send article to be posted` and then reads the dot-terminated article body from the wire.

### Step 2: Reader validates headers and article body at ingress

`post/validate_headers.rs` and `core/validation.rs` apply ingress checks before any signing or storage:

- Header field lengths and count are within configured limits.
- `Message-ID` format is valid (angle-bracket syntax, no whitespace); the raw wire value is untrusted and rejected if malformed.
- `Newsgroups` lists at least one valid group name (dotted-label syntax, each component `[a-zA-Z][a-zA-Z0-9]*`).
- Article byte count is within `max_article_bytes` (default 1 MiB).
- The `Message-ID` is not already present in the `msgid_map` SQLite table (duplicate rejection, 441 response).

Rejection at this step sends a 4xx response and does not proceed further.

### Step 3: Reader operator-signs canonical bytes with ed25519

`post/sign.rs` serializes the article into its canonical form and calls `core/signing.rs::sign`. The signing key is an operator-configured Ed25519 `SigningKey` (`ed25519-dalek`). The key is never written to any log statement or error message. The resulting 64-byte `Signature` travels with the article through the rest of the pipeline as its authenticity proof.

### Step 4: Reader writes the block to IPFS and records the CID in the Message-ID map

`post/ipfs_write.rs` constructs an `ArticleRootNode` (DAG-CBOR, codec 0x71) containing:
- `header_cid` — CIDv1 SHA-256 of the raw RFC 5536 header bytes
- `body_cid` — CIDv1 SHA-256 of the raw body bytes
- `mime_cid` — optional CID of a parsed MIME sub-tree
- `metadata` — derived fields: `message_id`, `newsgroups`, `hlc_timestamp`, `operator_signature`, `byte_count`, `line_count`, `content_type_summary`

The root node is written to the IPFS node via `rust-ipfs`. The returned CID is inserted into the `msgid_map` SQLite table as `(message_id TEXT, cid BLOB)`. This mapping is bidirectional (there is also a `cid → message_id` index) and is idempotent: re-inserting the same `(message_id, cid)` pair succeeds; a conflicting CID for an existing message-id returns an error.

### Step 5: Reader appends to each named group's Merkle-CRDT log and assigns local article numbers

`post/log_append.rs` calls `core/group_log/append.rs::append` once per group in the `Newsgroups` header. Each call constructs a `LogEntry`:

```
LogEntry {
    hlc_timestamp:      u64  // HLC wall-clock ms
    article_cid:        Cid  // same CID from step 4
    operator_signature: Vec<u8>  // 64-byte ed25519 signature from step 3
    parent_cids:        Vec<Cid> // current tip CIDs (empty = genesis)
}
```

The entry's `LogEntryId` is the SHA-256 of its canonical serialization. The new entry is appended to `log_entries` and `log_entry_parents` in SQLite. `group_tips` is updated atomically to point at the new tip.

After appending, `store/article_numbers.rs::assign_number` assigns a local sequential article number for the `(group_name, cid)` pair. Numbers start at 1 and are stored in `article_numbers (group_name TEXT, article_number INTEGER, cid BLOB)`. This assignment is idempotent: if the pair already has a number it is returned unchanged.

Article numbers are purely local to this reader instance. They are never network-stable identifiers and must never be used as CID pointers. Two reader instances serving the same group will assign different numbers to the same articles.

### Step 6: Reader publishes gossipsub tip advertisement to transit peers

`post/pipeline.rs::publish_tips_after_post` sends one `TipAdvertisement` per group to the gossipsub channel. The topic is `usenet.hier.<hierarchy>`, where `<hierarchy>` is the first dot-separated component of the group name (`comp.lang.rust` → `usenet.hier.comp`). The advertisement payload is JSON:

```json
{
  "group_name": "comp.lang.rust",
  "tip_cids": ["bafyreib..."],
  "hlc_ms": 1700000000000,
  "hlc_logical": 0,
  "hlc_node_id": "0102030405060708",
  "sender_peer_id": "12D3Koo..."
}
```

Tip publication is best-effort: if the gossipsub channel is absent or full the failure is logged as a warning and the POST still succeeds with `240 Article received`.

---

## Data Flow: NNTP Read Path

### Client sends ARTICLE/HEAD/BODY/OVER to the reader

The session dispatch loop routes the command to the appropriate handler. GROUP sets the current group in session context and returns the article number range from `article_numbers` (via `group_range`).

### Reader resolves Message-ID to CID

For commands that accept a `<message-id>` argument, `MsgIdMap::lookup_by_msgid` queries the `msgid_map` table and returns the corresponding CID. For commands that use a local article number, `ArticleNumberStore::lookup_cid` queries `article_numbers` to obtain the CID.

### Reader fetches the block from IPFS

The CID is passed to `rust-ipfs` to retrieve the DAG-CBOR `ArticleRootNode` block. Sub-block CIDs (`header_cid`, `body_cid`) are followed to reconstruct the article wire form. `ARTICLE` returns both headers and body; `HEAD` returns only the header block; `BODY` returns only the body block. When returning `ARTICLE` or `HEAD` responses, the session layer also injects an `X-Usenet-IPFS-CID` header giving the canonical article CID (RAW codec, §12 of the wire format spec). For multi-block DAG articles (v2+), an `X-Usenet-IPFS-Root-CID` header is also injected.

### Reader synthesizes the article number

`ArticleNumberStore::assign_number` is idempotent: if the `(group, cid)` pair already has a local number, that number is returned without inserting a new row. The NNTP response includes the synthesized number as required by RFC 3977.

`OVER`/`XOVER` responses are served from the `overview` table (SQLite), which is populated at ingress time from the article metadata and provides the `subject`, `from`, `date`, `message-id`, `references`, `byte_count`, and `line_count` columns required by RFC 3977 §8.3.

---

## Article Number Synthesis

Article numbers in usenet-ipfs are local and synthetic (design invariant #5). They are generated at ingress for a specific `(group_name, reader_server_instance)` pair and stored in:

```sql
article_numbers (
    group_name     TEXT    NOT NULL,
    article_number INTEGER NOT NULL,
    cid            BLOB    NOT NULL,
    PRIMARY KEY (group_name, article_number)
)
```

Assignment is sequential (MAX + 1, starting at 1) and wrapped in a SQLite transaction so it is serialized. The `group_range` method returns `(1, 0)` for an empty group, which is the RFC 3977 sentinel for an empty group (`low > high`).

Two reader instances serving the same group from the same IPFS+gossipsub state will independently assign different article numbers to the same articles. Clients should use `Message-ID` for cross-server identity; local numbers exist only for the `GROUP`/`ARTICLE`/`OVER` protocol mechanics.

---

## NNTP CID Extensions

The reader exposes five additive extensions that let CID-aware tools (archival
scripts, Corundum indexer, IPFS pinning automation) access content-addressing
metadata over standard NNTP. Standard newsreader clients see no change.

All five are advertised in the `CAPABILITIES` response. The full wire protocol
for each extension is specified in §12 of `docs/wire_format.md`.

### Passive Headers

Two headers are injected into `ARTICLE` and `HEAD` responses without requiring
any client action:

| Header | Value | When present |
|--------|-------|--------------|
| `X-Usenet-IPFS-CID` | Canonical article CID (RAW codec `0x55`) | Whenever CID is in `msgid_map` |
| `X-Usenet-IPFS-Root-CID` | IPLD DAG root CID (DAG-CBOR `0x71`) | Multi-block articles only (v2+); absent for all v1 text articles |

Headers are injected at the session serialisation layer (`session/lifecycle.rs`),
not stored in the IPFS header block.

### Active X-Commands

Three commands are available to clients that confirm capability via `CAPABILITIES`:

**`XCID [<message-id>]`** — returns response code `290 <cid>` for the current
article or any named article. Same missing-context error codes as `STAT` (412,
423, 430).

**`XVERIFY <message-id> <expected-cid> [SIG]`** — verifies the stored CID
matches `expected-cid` and optionally re-verifies the operator ed25519
signature. Responses: `291` (verified), `541` (not found or CID mismatch),
`542` (signature failure). CID re-derivation fetches raw block bytes from IPFS
and recomputes the SHA-256 independently.

**`ARTICLE cid:<cidv1>` (and `HEAD cid:...`, `BODY cid:...`)**  — accepts a
`cid:` prefixed CIDv1 locator as an alternative to `<message-id>` and article
number forms. Looks up directly in the IPFS block store, bypassing `msgid_map`.

### Invariant

A standard newsreader that never sends an `X` command and never reads
`X-Usenet-IPFS-*` headers must have an identical session experience to a server
without these extensions. This is enforced by the CLAUDE.md design invariant.

---

## Group State Reconciliation

### Merkle-CRDT Log

Each group has an independent append-only log stored in three SQLite tables (from `core`):

- `log_entries (id BLOB PK, hlc_timestamp, article_cid, operator_signature)` — one row per log entry.
- `log_entry_parents (entry_id, parent_id)` — the DAG parent links (zero parents = genesis entry; multiple parents = merge entry).
- `group_tips (group_name, tip_id)` — the current frontier tip set per group, replaced atomically on merge.

A `LogEntryId` is the 32-byte SHA-256 of the entry's canonical serialization. An entry's `parent_cids` field points at the entries it was appended on top of. Concurrent appends on different nodes produce a DAG with multiple tips; reconciliation merges these into a single frontier.

### Gossipsub Topics

Topics are per-hierarchy, not per-group. `comp.lang.rust` and `comp.lang.c` both flow on `usenet.hier.comp`. Receivers filter by `group_name` inside the message. This design caps the number of active gossipsub topics at the number of top-level Usenet hierarchies rather than at the number of active groups.

Topic naming: `usenet.hier.<hierarchy>` where `<hierarchy>` is the first dot-separated component of the group name.

### Tip Advertisement

When a node learns a new tip (via POST or via incoming peering), it broadcasts a `TipAdvertisement` JSON message on the relevant hierarchy topic. The advertisement contains the group name, one or more tip CIDs, an HLC timestamp, and the sender's libp2p `PeerId`.

Receivers call `handle_tip_advertisement` which validates the message (non-empty group name, non-empty tip list) and triggers reconciliation if any of the advertised tip CIDs are unknown locally.

### Reconciliation Algorithm

`core/group_log/reconcile.rs::reconcile` computes what to request from and what to offer a remote peer:

- **want**: remote tip IDs that are not present in local storage. The remote knows its own ancestry chain, so naming the tips is sufficient.
- **have**: all entries reachable from local tips via BFS through `parent_cids`, minus any entries already known to the remote.

After reconciliation, the node fetches wanted entries from the remote peer (backfill, `core/group_log/backfill.rs`) and appends them to local storage.

---

## Storage Architecture

Each binary has its own SQLite database. Both import `usenet-ipfs-core` migrations for shared tables.

### Core tables (both binaries via `core/migrations/`)

| Table | Key | Contents |
|---|---|---|
| `msgid_map` | `message_id TEXT PK` | `message_id → cid` bidirectional mapping |
| `log_entries` | `id BLOB PK` | Merkle-CRDT log entry payload |
| `log_entry_parents` | `(entry_id, parent_id)` | DAG parent links |
| `group_tips` | `(group_name, tip_id)` | Current tip frontier per group |
| `audit_log` | `id INTEGER AUTOINCREMENT` | Append-only security event log (no UPDATE/DELETE) |

### Reader-only tables (`reader/migrations/`)

| Table | Key | Contents |
|---|---|---|
| `article_numbers` | `(group_name, article_number)` | Local `article_number → cid` mapping |
| `overview` | (group, article_number) | Pre-computed OVER/XOVER response fields |

### Transit-only tables (`transit/migrations/`)

| Table | Key | Contents |
|---|---|---|
| `peers` | `peer_id TEXT PK` | Known peers: address, stats, blacklist expiry |
| `peer_groups` | `(peer_id, group_name)` | Groups each peer is subscribed to |
| `articles` | `cid TEXT PK` | Article metadata for GC (ingested_at_ms, byte_count) |

### IPFS block storage

Article content lives in IPFS, not in SQLite. Each article is stored as a DAG-CBOR tree:

```
ArticleRootNode (codec 0x71, SHA-256 CIDv1)
├── header_cid  → raw block (RFC 5536 header bytes)
├── body_cid    → raw block (article body bytes)
├── mime_cid    → MIME parsed sub-tree (optional)
└── metadata    → inline: message_id, newsgroups, hlc_timestamp,
                          operator_signature, byte_count, line_count,
                          content_type_summary
```

The metadata fields are embedded in the root node so that Corundum (future integration) and other consumers can render a preview without fetching sub-blocks.

---

## Transit Daemon

### Store-and-Forward

The transit daemon accepts articles via IHAVE, TAKETHIS, and MODE STREAM (RFC 4644). Incoming articles pass through the same `run_pipeline` in `transit/src/peering/pipeline.rs` that the reader uses:

1. Write article bytes to IPFS → CID.
2. Insert `message_id → CID` in `msgid_map`.
3. Append a `LogEntry` to each group in `Newsgroups:`.
4. Publish a `TipAdvertisement` for each group via gossipsub.

Articles that are already known (CID already in `msgid_map`) are accepted idempotently without a second IPFS write.

### Peering

The peer registry (`transit/src/peering/peer_registry.rs`) tracks known peers in the `peers` SQLite table, recording statistics and blacklist state. Peers with repeated failures are temporarily blacklisted (`blacklisted_until` column). Rate limiting (`rate_limit.rs`) and backpressure (`backpressure.rs`) prevent a single peer from overwhelming the ingestion queue.

### Pinning Policy

`retention/policy.rs` implements a rule-based pinning policy configured in TOML. Each `PinRule` specifies:

- `groups`: a group name, a glob prefix (`comp.*`), or `"all"`.
- `max_age_days`: optional upper bound on article age.
- `max_article_bytes`: optional upper bound on article size.
- `action`: `"pin"` or `"skip"`.

Rules are evaluated in declaration order; the first matching rule wins. If no rule matches, the article is not pinned. Pinning is explicit opt-in, not opt-out (design invariant #6: "It's in IPFS" is not a retention strategy).

### Garbage Collection

`retention/gc.rs` and `retention/gc_executor.rs` periodically scan the `articles` table for articles whose CID is not in the operator-pinned set and whose age exceeds the policy threshold. Unpinned articles are unpinned from IPFS and removed from the `articles` table. Each GC run emits a `GcRun` audit event.

### Admin Endpoint

The admin HTTP endpoint (`admin.rs`) binds to `127.0.0.1:9090` by default (loopback-only). Binding to a non-loopback address without explicitly setting `admin.allow_non_loopback = true` in the config triggers a startup warning.

---

## Security

### Operator Signing

Every article written to IPFS is signed by the operator's Ed25519 key before the IPFS write. The `operator_signature` field is embedded in both the `ArticleRootNode.metadata` and the `LogEntry`. An unsigned article is never appended to the group log (design invariant: "Never write an unsigned article to the group log").

The signing key is loaded at startup and held in memory. It is never written to any log statement or included in any error message. Key rotation is supported via a CLI subcommand (`cli/key_rotate.rs`).

### TLS

The reader supports two TLS modes configured via `[tls]` in the config file:

- **Immediate TLS**: both `cert_path` and `key_path` are set; every connection is upgraded to TLS before the NNTP greeting.
- **STARTTLS**: when no TLS is configured, the plain-text session offers STARTTLS, which triggers an in-session upgrade via `tokio-rustls`.

Both `cert_path` and `key_path` must be either both set or both absent; a partial configuration is rejected at startup as a validation error.

### AUTHINFO

The reader supports AUTHINFO USER/PASS authentication (RFC 4643). The `[auth]` config section controls whether authentication is required (`required = true`) and lists user credentials. When `required = false` and the user list is empty, all credential attempts succeed (development mode only).

Authentication attempts are recorded as `AuthAttempt` events in the audit log.

### Audit Log

`core/audit.rs` provides an append-only audit log in SQLite (`audit_log` table). No UPDATE or DELETE ever runs against this table. Security-relevant event types:

| Event | Trigger |
|---|---|
| `ArticleSigned` | Every article signed and written to IPFS |
| `AuthAttempt` | Every AUTHINFO USER/PASS attempt (success or failure) |
| `PeerBlacklisted` | Peer blacklisted due to repeated failures |
| `GcRun` | Periodic garbage collection run completes |
| `AdminAccess` | Admin HTTP endpoint accessed |

The audit logger runs as a background tokio task, batching writes for efficiency. Events are never dropped silently on normal operation; a buffer-full condition logs a warning.

### Input Validation

All NNTP input is treated as attacker-controlled:

- Article size, header count, and header field length are bounded before any parsing.
- `Message-ID` format is validated before use as a map key or log entry.
- Group names are validated against `[a-zA-Z][a-zA-Z0-9]*` per-component syntax.
- Validated inputs pass through `core/validation.rs`; application logic never receives raw wire values for security-sensitive fields.
