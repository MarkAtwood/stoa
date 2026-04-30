# Changelog

All notable changes to stoa will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Core (`stoa-core`)
- Article IPLD schema: root node, block list, header map, MIME segment tree, metadata (DAG-CBOR codec 0x71)
- CID scheme: CIDv1 SHA-256, `message_id → CID` SQLite map, `cid:` locator support
- Merkle-CRDT per-group append-only log: HLC timestamps, DAG parent links, reconcile and backfill
- Canonical serialization: RFC 8785 JSON conventions (sorted keys, NFKC, UTC with Z suffix)
- ed25519 operator signing and signature verification
- Audit log: `AuditEvent` enum, buffered `AuditLogger`
- Input validation: article size limits, header field lengths, group name format
- Kubo HTTP RPC client (`KuboHttpClient`) with circuit breaker for IPFS block operations
- `DeletionOutcome` enum: `Immediate` vs `Deferred` semantics across backends

#### Transit daemon (`stoa-transit`)
- TCP peering session: IHAVE/CHECK/TAKETHIS, MODE STREAM (RFC 4644) with per-peer rate limiting and back-pressure
- Store-and-forward ingestion pipeline: verify → IPFS → `msgid_map` → group log
- Ten block store backends: LMDB, Kubo (IPFS), S3, GCS (Google Cloud Storage), Azure Blob, RADOS, WebDAV, RocksDB, SQLite, local filesystem
- Retention/GC scheduler: policy engine, GC candidate selection, GC executor, GC report
- IPFS pinning: local Kubo pin, remote pin service client (RFC 8727), remote pin worker
- IPNS publisher for group tip advertisement
- StagingStore: on-disk write-ahead buffer for inbound articles before pipeline commit
- BlockCache: LRU SQLite + file-backed decorator over any block store
- Import tooling: IHAVE push, mbox import, suck/pull from remote server, reindex
- Operator CLI: peer management, pin/unpin, gc-run, audit export, keygen, key rotation, CAR export, backup scheduler
- Prometheus metrics with OpenTelemetry tracing
- HLC timestamp persistence and instance identity
- Secrets via `secretx` abstraction (env/file always compiled; aws-sm/aws-ssm/azure-kv/gcp-sm behind Cargo features)

#### Reader daemon (`stoa-reader`)
- RFC 3977 NNTP command surface: `CAPABILITIES`, `GROUP`, `ARTICLE`, `HEAD`, `BODY`, `STAT`, `NEXT`, `LAST`, `LIST`, `LISTGROUP`, `OVER`/`XOVER`, `HDR`, `POST`, `IHAVE`, `NEWGROUPS`, `NEWNEWS`, `MODE READER`, `AUTHINFO USER/PASS`, `STARTTLS`, `QUIT`
- MODE STREAM / CHECK / TAKETHIS (RFC 4644)
- STARTTLS mid-session TLS upgrade (RFC 4642)
- Auth rate limiting and lockout
- Full-text search (`SEARCH` extension)
- Additive CID extensions: `X-Stoa-CID` / `X-Stoa-Root-CID` article headers, `XCID`, `XVERIFY`, `ARTICLE cid:` (ADR-0007)
- Multiple store backends (same set as transit)
- POST path: operator signing before IPFS write; unsigned articles rejected

#### Mail server (`stoa-mail`, JMAP)
- JMAP Core (RFC 8620): session endpoint, `Echo`, identity
- JMAP Mail (RFC 8621): `Email/get`, `Email/query`, `Email/set`, `Email/changes`
- `Mailbox/get`, `Mailbox/set` (subscription, operator role / admin capability gating)
- `Thread/get` (root CID = thread ID; walk `References` / `In-Reply-To` through overview index)
- Blob download endpoint; `Email.blobId` = `Email.id` = article CID
- `x-stoa-sig` property on `Email/get` (exposes `operator_signature`)
- ActivityPub: inbound/outbound `Create{Note}` injection, HTTP Signatures (RFC 9421), follower management, WebFinger (RFC 7033)

#### SMTP submission (`stoa-smtp`)
- SMTP submission server (RFC 5321 + RFC 6409)
- Native Sieve filtering (`stoa-sieve-native`, MIT-licensed; see ADR-0010)
- Relay client for outbound delivery
- NNTP injection path for posting via SMTP

#### IMAP server (`stoa-imap`)
- IMAP4rev1 command surface (RFC 3501): `LOGIN`, `SELECT`, `EXAMINE`, `FETCH`, `STORE`, `SEARCH`, `COPY`, `UID`, `EXPUNGE`, `CLOSE`, `LOGOUT`, `NOOP`
- IMAP4rev2 (RFC 9051): `ENABLE IMAP4rev2` session latch (RFC 5161), `NAMESPACE` (RFC 2342), `* RECENT` suppression in IMAP4rev2 mode
- `max_command_size` hardened to 8 KiB (config: `limits.max_command_size_bytes`)

#### Auth (`stoa-auth`)
- OIDC bearer token validation (JWT, `exp` numeric claim required)
- Client certificate validation
- Bearer token validation with `subtle::ConstantTimeEq`
- Integration tests against a live auth server

#### Sieve (`stoa-sieve`, `stoa-sieve-native`)
- `stoa-sieve`: `sieve-rs` 0.7 wrapper (AGPL-3.0-only; never linked by production binaries)
- `stoa-sieve-native`: native MIT Sieve evaluator cross-validated against `stoa-sieve` oracle

#### Verify (`stoa-verify`)
- Signature verification utilities; DID passthrough validation

#### TLS (`stoa-tls`)
- Shared `rustls` TLS configuration; acceptor and connector builders

#### Integration tests
- NNTP conformance suite (nntplib, `slrn`-compatible command coverage)
- DID signature end-to-end
- Verify end-to-end
- Admin endpoint tests
- Fault injection: IPFS unavailable, malformed articles, store failures
- JMAP end-to-end
- Property-based CRDT tests: commutativity, idempotency, convergence (proptest)

### Removed
- gossipsub / libp2p topology (removed in commit bcd4026; superseded by TCP IHAVE/TAKETHIS peering — see ADR-0009)
- DHT-based tip discovery fallback (removed with gossipsub)

[Unreleased]: https://github.com/MarkAtwood/stoa/compare/HEAD...HEAD
