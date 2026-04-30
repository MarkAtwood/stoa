# Session Handoff — 2026-04-29

## Uncommitted work — COMMIT BEFORE NEXT SESSION

```
Cargo.toml                — secretx 0.3.0 → 0.3.1
crates/mail/Cargo.toml    — aws/azure/gcp features for secretx cloud backends
crates/reader/Cargo.toml  — aws/azure/gcp features for secretx cloud backends
crates/smtp/Cargo.toml    — aws/azure/gcp features for secretx cloud backends
crates/transit/Cargo.toml — aws/azure/gcp features for secretx cloud backends
```

Suggested commit message:
```
chore(deps): secretx 0.3.1; gate cloud backends behind features
```

---

## What was accomplished recently

- **JMAP x-stoa-sig** (`7000af0`) — `Email/get` exposes `x-stoa-sig` from `operator_signature`
- **StagingStore** (`dc97378`) — on-disk write-ahead buffer for inbound NNTP articles
- **BlockCache** (`5658f11`) — LRU decorator over `IpfsStore` (SQLite + file backing)
- **ActivityPub** — full inbound/outbound Create{Note} injection, HTTP Signatures, follower management, WebFinger
- **JMAP** — Mailbox/set subscription, operator role/admin capability gating, Thread/get, Email/changes
- **Multiple backends** — PostgreSQL BYTEA, RADOS, WebDAV, git SHA-256 object store
- **Auth security fix** — `exp` claim must be numeric (GHSA-h395-gr6q-cpjc)
- Round of P0–P3 review fixes across type safety, performance, correctness

---

## Open issues (11, all P3)

### IMAP4rev2 cluster — blocked on upstream
| ID | Title |
|----|-------|
| `5vw` | imap: IMAP4rev2 support (RFC 9051) — waiting on duesee/imap-codec#702 |
| `8vq2` | IMAP4rev2: NAMESPACE, STATUS=SIZE, and SASL-IR support |
| `c34y` | IMAP4rev2: integration test and upstream imap-codec tracking |
| `x638` | IMAP4rev2: ENABLE IMAP4rev2 session mode and capability advertisement |

### ZFS DMU cluster
| ID | Title |
|----|-------|
| `e6xo` | ZFS DMU: evaluate ioctl vs FUSE vs zvol approaches |
| `6btr` | ZFS DMU: document privilege requirements and CI strategy |
| `vl6k` | ZFS DMU userspace object API |
| `kv6k` | ZFS DMU: implement usenet-ipfs-zfs-dmu crate |
| `ilil` | ZFS DMU block store backend |

### DECISION records (open, no work required)
| ID | Title |
|----|-------|
| `okyx` | DECISION: dual-CID model (raw 0x55 + DAG-CBOR 0x71) |
| `rqtv` | DECISION: wildmat uses iterative DP, not regex |

---

## Workspace layout (14 crates)

```
crates/
  auth/              — OIDC, client cert, bearer token validation
  core/              — article types, CID scheme, group log (Merkle-CRDT), signing
  ctl/               — operator CLI
  imap/              — IMAP4rev1 server (imap-next 0.3.4 / imap-types 2.0.0-alpha.6)
  integration-tests/ — end-to-end harness
  lmdb/              — LMDB bindings (only crate permitted to use unsafe)
  mail/              — JMAP server (Email/get/query/set, Mailbox/*, Thread/get, blob download)
  reader/            — RFC 3977 NNTP reader server
  sieve/             — sieve-rs wrapper (AGPL-3.0-only; NOT linked by any production binary)
  sieve-native/      — native Sieve evaluator (MIT)
  smtp/              — SMTP submission (MIT; uses sieve-native, not sieve)
  tls/               — shared TLS config and rustls setup
  transit/           — peering daemon, store-and-forward, pinning, GC, metrics
  verify/            — signature verification utilities
```

---

## Key architecture notes

- **CID = JMAP Email ID = blobId**: `Email.id`, `Email.blobId`, `Email.x-stoa-cid` are the same string.
- **Thread ID**: Walk `References`/`In-Reply-To` through overview index; threadId = CID of root article. Recomputed on demand, not stored.
- **Mailbox IDs are derived**: `mailbox_id_for_group(name)` = SHA256→base26+digits→26 chars. Stable across restarts. Defined in `mailbox/types.rs`.
- **StateStore wired in SQLite**: state integers are live; Email/changes bumps state on article ingest.
- **imap-next X-command limitation**: `CommandBody::Other` not available in imap-types 2.0.0-alpha.6; IMAP X-commands blocked by library design. JMAP superseded the IMAP X-command issues instead.
- **admin servers**: use `subtle::ConstantTimeEq` for bearer token comparison — do not replace with `==`.
- **spawn_blocking**: correct async/sync bridge for LMDB (blocks on write txn serialization).
- **Secrets**: `secretx` abstraction; env/file always compiled in; cloud backends (aws-sm/aws-ssm/azure-kv/gcp-sm) gated behind per-binary Cargo features.
- **sieve / AGPL boundary**: `stoa-sieve` (AGPL) is never linked by production binaries. `stoa-smtp` uses `stoa-sieve-native` (MIT) only.

---

## Session close checklist

- [ ] `git add Cargo.toml crates/mail/Cargo.toml crates/reader/Cargo.toml crates/smtp/Cargo.toml crates/transit/Cargo.toml`
- [ ] `git commit -m "chore(deps): secretx 0.3.1; gate cloud backends behind features"`
- [ ] `git push`
- [ ] `bd dolt push`
