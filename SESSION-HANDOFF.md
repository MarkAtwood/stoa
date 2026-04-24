# Session Handoff — 2026-04-23

## What was accomplished this session

### Epics completed

**stoa-9mf (StagingStore)** — committed `dc97378`
- On-disk write-ahead buffer for inbound NNTP articles
- `StagingStore { try_stage(), drain_one(), complete(), pending_count() }`
- SQLite table `transit_staging`; capacity limits (max_bytes 5GiB, max_entries 500K)
- Drain task in transit main: polls `drain_one()` → `run_pipeline()` → `complete()`
- `PeeringShared.staging: Option<Arc<StagingStore>>`; all test initializers updated

**stoa-31v (BlockCache)** — committed `5658f11`
- LRU decorator over `IpfsStore` trait
- `BlockCache { cache_get(), cache_put(), evict_for() }` with SQLite + file backing
- `unix_nanos()` for sub-second LRU ordering (avoids ties in rapid test runs)
- `CacheConfig` wired into `Config` and `main.rs` (wraps ipfs_store after node start)
- SQLite table `transit_block_cache` with `idx_block_cache_lru`

**IMAP SASL-IR** — committed `6fe8b09`
- Added `Capability::SaslIr` to TLS capability list in `crates/imap/src/session/commands.rs`

**stoa-3am (JMAP x-stoa-sig)** — NOT YET COMMITTED
- Added `ipfs_sig: Option<String>` to `Email` struct in `crates/mail/src/email/types.rs`
- Serialized as `"x-stoa-sig"`, omitted when None (`skip_serializing_if`)
- Populated from `root.metadata.operator_signature` via `BASE64URL_NOPAD.encode()` if non-empty
- 3 tests: `ipfs_sig_absent_when_unsigned`, `ipfs_sig_present_when_signed` (oracle: "AQIDBA"), `ipfs_sig_serializes_in_json_and_roundtrips`
- All workspace tests pass (493 tests, 0 failures)

### Issues closed (not blocked, superseded, or resolved)

- **an4** (IMAP X-USENET-IPFS-GET) — superseded. `GET /jmap/download/{accountId}/{CID}/{name}` in `blob.rs` already implements this fully. IMAP X-command blocked by imap-next library.
- **02d** (IMAP X-USENET-IPFS-VERIFY) — superseded. Blob download returns full article bytes including `X-Stoa-Sig` header; `x-stoa-sig` field (3am) exposes sig in Email/get.
- **kuz** (IMAP OBJECTID) — superseded. JMAP `Email.id` IS the CID string natively; `x-stoa-cid` also exposed.

### Upstream action

- Filed **duesee/imap-codec#702** requesting `Capability::Imap4Rev2` for RFC 9051
- `5vw` (IMAP4rev2) updated to note waiting on that issue

---

## Uncommitted work — COMMIT BEFORE NEXT SESSION

```
crates/mail/src/email/types.rs   — x-stoa-sig field (issue 3am)
audit/status.md                  — session log
```

Suggested commit message:
```
feat(jmap): expose x-stoa-sig as Email/get property
```

---

## Open issues (9 total, all ready)

### P2 — Work these first

| ID | Title | Notes |
|----|-------|-------|
| `err` | jmap: wire Mailbox/query into route_method() | Handler exists at `mailbox/query.rs`, just needs a route arm in `server.rs` |
| `65ax` | jmap: wire Email/set (keywords) into route_method() | Handler exists at `email/set.rs`, UserFlagsStore ready; just needs routing |
| `u6hx` | jmap: implement Thread/get | Walk References/In-Reply-To chain; thread ID = CID of earliest ancestor |
| `vcv4` | jmap: implement Email/changes and Mailbox/changes | StateStore exists in `state/version.rs`; wire state into responses, then implement delta queries |

### P3

| ID | Title | Notes |
|----|-------|-------|
| `gbf` | jmap: implement SearchSnippet/get | TantivySearchIndex already wired for Email/query |
| `isiq` | jmap: implement RFC 9404 Blob/get and Blob/copy | Advertise `urn:ietf:params:jmap:blob`; Blob/copy is a no-op (CIDs are global) |
| `o6tg` | jmap: implement JMAP upload endpoint for article submission | POST /jmap/upload/{accountId}/; run through `write_article_to_ipfs()` |

### P3 — Waiting on upstream

| ID | Title | Notes |
|----|-------|-------|
| `5vw` | imap: IMAP4rev2 support (RFC 9051) | Blocked: `Capability::Imap4Rev2` missing from imap-types. Filed duesee/imap-codec#702. Resume when upstream resolves. |

### P4 — Needs human coordination before starting

| ID | Title | Notes |
|----|-------|-------|
| `03z` | [epic] ActivityPub federation | Explicitly says "coordinate before implementing". Design decisions needed: actor type (Group vs Service), HTTP Signatures profile (draft-cavage vs RFC 9421), inbound injection scope, Corundum rfc822+mime alignment. |

---

## Key codebase map

### Mail crate (`crates/mail/src/`)

```
server.rs               — HTTP server; route_method() dispatches Mailbox/get, Email/query, Email/get
                          ADD: Mailbox/query, Email/set, Thread/get, Email/changes, Mailbox/changes arms
jmap/session.rs         — Session resource; advertises capabilities and URLs
jmap/types.rs           — Request/Response/MethodError types
jmap/dispatch.rs        — Generic dispatcher (not currently used; server.rs does inline routing)
blob.rs                 — GET /jmap/download/{accountId}/{blobId}/{name} — CID→RFC 5322 blob delivery
email/get.rs            — Email/get handler
email/query.rs          — Email/query handler (filters: inMailbox, after, before, from, subject, text)
email/set.rs            — Email/set handler (destroy→notPermitted; keywords→UserFlagsStore; NOT WIRED)
email/types.rs          — Email struct with x-stoa-cid, x-stoa-sig custom properties
mailbox/get.rs          — Mailbox/get handler
mailbox/query.rs        — Mailbox/query handler (isSubscribed filter, name sort) — NOT WIRED
mailbox/types.rs        — Mailbox struct; mailbox_id_for_group() = SHA256→base32 of group name
state/version.rs        — StateStore: per-scope monotonic JMAP state integers in SQLite
state/flags.rs          — UserFlagsStore: per-user per-CID $seen/$flagged in SQLite
feed.rs                 — Atom feed handler (independent of JMAP)
```

### Transit crate (`crates/transit/src/`)

```
staging.rs              — StagingStore: write-ahead buffer for inbound articles
block_cache.rs          — BlockCache: LRU decorator over IpfsStore
peering/session.rs      — NNTP peering; enqueue_article() checks staging first
main.rs                 — Startup: wraps IpfsStore with BlockCache if config.cache set;
                          constructs StagingStore if config.staging set; runs drain task
```

### Reader crate (`crates/reader/src/`)

```
post/sign.rs            — sign_article(), verify_article_sig(); OPERATOR_SIG_HEADER
post/did_verify.rs      — verify_did_sig() for X-Stoa-DID-Sig headers
post/ipfs_write.rs      — write_article_to_ipfs() — used by both NNTP POST and JMAP upload
session/lifecycle.rs    — handle_xverify() at line 855; NNTP command handlers
```

---

## Architecture notes (non-obvious things to remember)

- **CID = JMAP Email ID = blobId**: Not a mapping — they are literally the same string. `Email.id`, `Email.blobId`, `Email.x-stoa-cid` all equal the article root CID.
- **Thread ID derivation**: Walk `References`/`In-Reply-To` chain through the overview index, take the CID of the root article. If no chain, threadId = emailId. Not stored — recomputed on demand.
- **StateStore is already wired in SQLite** but responses still return hardcoded "0". Email/changes implementation needs: (a) bump state on article ingest, (b) wire live state into Email/query/get responses, (c) implement changes query against overview index.
- **Mailbox IDs are derived, not stored**: `mailbox_id_for_group("comp.lang.rust")` = SHA256→base26+digits→26 chars. Stable across restarts. Defined in `mailbox/types.rs`.
- **Upload endpoint advertised but not implemented**: Session advertises `/jmap/upload/{accountId}/` but it returns 404. Issue `o6tg` covers this.
- **EventSource advertised but not implemented**: Session advertises eventsource URL. No push support yet. Not in the issue list (deliberately omitted as low priority for newsreader).
- **imap-next X-command limitation**: imap-next 0.3.4 / imap-types 2.0.0-alpha.6 have no `CommandBody::Other` for custom X-commands. This is by design in the library. an4/02d were superseded by JMAP rather than waiting.
- **AGPL note**: `stoa-smtp` is AGPL-3.0 due to `sieve-rs` dependency. Do not add features without understanding the AGPL obligation. Other crates are MIT.

---

## Session close checklist status

- [ ] `git add crates/mail/src/email/types.rs audit/status.md`
- [ ] `git commit -m "feat(jmap): expose x-stoa-sig as Email/get property"`
- [ ] `git push`
- [ ] `bd dolt push` (may fail if no remote configured — non-fatal)
