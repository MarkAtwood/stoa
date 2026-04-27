# stoa Threat Model

**Date:** 2026-04-19
**Scope:** stoa-transit and stoa-reader daemons, v1
**Status:** Living document — update when attack surface changes

---

## 1. System Overview

Two binaries share a core library crate (`stoa-core`):

- **stoa-transit** — NNTP peering daemon. Accepts IHAVE/CHECK/TAKETHIS from
  peer servers, writes articles to IPFS, maintains a Merkle-CRDT group log over
  libp2p gossipsub. Listens on port 119 (configurable; default `0.0.0.0:119`).
  Operator signing key lives on disk; the transit daemon signs every article
  before writing it to the group log.

- **stoa-reader** — RFC 3977 NNTP server. Accepts connections from standard
  newsreader clients (slrn, tin, pan, Thunderbird). Reads articles from IPFS via
  CID lookup. Synthesizes local sequential article numbers per `(group, reader_server)`
  instance and stores them in SQLite. Listens on port 119 or 563 (TLS).

Both daemons:
- Use a shared SQLite database for `message_id → CID` mappings and article numbers.
- Connect to a local IPFS node via the Kubo HTTP API (default `http://127.0.0.1:5001`).
- Expose an admin HTTP endpoint (default `127.0.0.1:9090`).

Article content is stored exclusively in IPFS as DAG-CBOR blocks (codec 0x71)
addressed by CIDv1. SQLite holds index data only, not article content.

---

## 2. Trust Boundaries

```
                    ┌─────────────────────────────────────────────┐
                    │  Operator host                              │
                    │                                             │
  Peer servers ─────┤→ transit :119  ──→ IPFS node (loopback)   │
  (untrusted)       │      │            SQLite (local file)       │
                    │      ↓                                      │
  Newsreader ───────┤→ reader  :119/563                          │
  clients           │                                             │
  (untrusted)       │  admin endpoint (loopback :9090 default)   │
                    │  operator CLI (local shell)                 │
                    └─────────────────────────────────────────────┘
```

| Boundary | Trust Level | Notes |
|----------|-------------|-------|
| NNTP peer connections (transit :119) | Untrusted | Any NNTP server may connect; no peer authentication in v1 |
| Reader client connections (:119/:563) | Untrusted | End users, potentially anonymous; AUTHINFO optional |
| IPFS node API (`127.0.0.1:5001`) | Trusted | Operator-controlled; assumed same host or private network |
| Admin HTTP endpoint (`:9090`) | Operator-only | Loopback-only by default; see T5 for risk when changed |
| Operator CLI | Trusted | Local shell access; no additional auth layer |
| Signing key file | Highest trust | ed25519 private key; compromise allows forging article signatures |
| SQLite database files | Operator-controlled | Local filesystem; ACL is the only protection |

---

## 3. Threat Actors

**A1 — Malicious NNTP peer**
An attacker who controls or impersonates an NNTP peer server. Can send IHAVE,
CHECK, TAKETHIS, and arbitrary article data. Has TCP-level access to port 119
on the transit daemon. Goal: exhaust resources, inject malformed data, or
store articles that cannot be retrieved.

**A2 — Malicious reader client**
An attacker connecting to the reader daemon via NNTP. Can send any RFC 3977
command with arbitrary arguments, and can POST articles if POST is enabled.
Goal: exhaust CPU/memory, bypass authentication, read articles they should not
see, or inject content.

**A3 — Network attacker (passive)**
An attacker on the network path between peers or between reader and client.
Can observe, replay, or alter traffic if TLS is not in use.

**A4 — Local attacker**
An attacker with limited local access (shared hosting, compromised unprivileged
account). Can attempt to read SQLite databases, access the admin endpoint, or
read the signing key file.

**A5 — Operator misconfiguration**
Not a malicious actor, but a risk class: an operator who changes defaults
(e.g. binds admin endpoint to `0.0.0.0`) without understanding the consequences.
The system should warn loudly rather than silently accept unsafe configurations.

---

## 4. Threats and Mitigations

The STRIDE categories used below: **S**poofing, **T**ampering, **R**epudiation,
**I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege.

---

### T1 — Article flood / disk exhaustion

| Field | Value |
|-------|-------|
| STRIDE | Denial of Service |
| Actor | A1 (malicious peer) |
| Attack | Peer sends a continuous stream of IHAVE/TAKETHIS with unique valid articles, filling IPFS storage and SQLite indexes |
| Impact | Disk exhaustion; service disruption for legitimate readers |
| Current mitigation | GC policy (`max_age_days`, cron schedule) and pinning policy (`pin-all-ingress`) exist in config. No per-peer rate limit or per-peer article count cap is implemented in v1. |
| Residual risk | **Medium.** A single malicious peer can fill disk at line rate. Rate limiting at the TCP/IP layer (firewall, fail2ban) is the only current defense. |
| Recommended follow-up | Implement per-peer connection-level rate limiting (articles/second, bytes/second). Track per-peer ingestion count in SQLite. |

---

### T2 — Oversized article (transit path)

| Field | Value |
|-------|-------|
| STRIDE | Denial of Service |
| Actor | A1 (malicious peer) |
| Attack | Peer sends a single IHAVE/TAKETHIS article larger than `MAX_ARTICLE_BYTES` (1 MiB) |
| Impact | Memory spike for the one article; no persistent impact |
| Current mitigation | **Mitigated.** `check_ingest()` in `crates/transit/src/peering/ingestion.rs` checks the article byte count against `MAX_ARTICLE_BYTES` before mandatory header scan. The check occurs before storage. |
| Residual risk | **Low.** The 1 MiB limit is appropriate for text-only v1. Binary groups are explicitly out of scope. |

---

### T3 — Malformed Message-ID injection

| Field | Value |
|-------|-------|
| STRIDE | Spoofing, Tampering |
| Actor | A1 (malicious peer), A2 (malicious reader client) |
| Attack | Send a Message-ID that passes the weaker transit-side check but is malformed (e.g. `<a@b@c>`, `<@domain>`, embedded whitespace). Article is stored under a malformed key; reader cannot retrieve it. |
| Impact | Stored articles unretrievable via reader; potential key collision in msgid_map if two malformed IDs hash similarly |
| Current mitigation | **Partially mitigated.** The reader-side validator (`is_valid_message_id()` in `crates/core/src/validation.rs`) checks: exactly one `@`, non-empty local and domain parts, no whitespace, no embedded angle brackets. The transit-side validator (`validate_msgid_format()` in `crates/transit/src/peering/ingestion.rs`) only checks: `len() > 3`, starts with `<`, ends with `>`, contains `@` — does not check uniqueness of `@`, emptiness of parts, or whitespace. |
| Residual risk | **Medium.** Articles stored via transit with a malformed Message-ID (e.g. `<a@b@c>`) will be indexed in SQLite but will fail reader-side lookup because the reader validator rejects the key. This is audit Gap 7. The fix is to reuse `is_valid_message_id()` on the transit path. |

---

### T4 — SQL injection via article headers

| Field | Value |
|-------|-------|
| STRIDE | Tampering, Information Disclosure |
| Actor | A1, A2 |
| Attack | Embed SQL metacharacters in a Message-ID, group name, or article number argument; hope the application interpolates them into a query string |
| Impact | Database corruption, data exfiltration, privilege escalation |
| Current mitigation | **Fully mitigated.** All query sites in `crates/core/src/msgid_map.rs`, `crates/reader/src/store/article_numbers.rs`, and `crates/reader/src/store/overview.rs` use `sqlx` parameterized binds (`?` placeholders) exclusively. Static analysis found no `format!(... SQL ...)` patterns anywhere in the codebase. |
| Residual risk | **None** for current query sites. Risk reappears if future code introduces string-interpolated SQL — code review must enforce `sqlx` bind discipline. |

---

### T5 — Admin endpoint exposure

| Field | Value |
|-------|-------|
| STRIDE | Elevation of Privilege |
| Actor | A4 (local attacker), A5 (misconfiguration) |
| Attack | Admin endpoint bound to `0.0.0.0` instead of `127.0.0.1`; any network host can call operator-only APIs (trigger GC, read metrics, modify pinning policy) |
| Impact | Unauthorized operator-level control of daemon; potential data deletion via GC trigger |
| Current mitigation | **Partially mitigated.** Default config binds admin endpoint to `127.0.0.1:9090`. A `check_admin_addr` function warns at startup if a non-loopback address is configured without a `bearer_token`. Authentication is available via `bearer_token` in the admin config. |
| Residual risk | **Medium** when `addr` is non-loopback with no `bearer_token` and no firewall. The warning does not prevent the bind — it only notifies. An operator who ignores the warning has an unauthenticated admin endpoint exposed to the network. |
| Recommended follow-up | When binding to a non-loopback address, always set `bearer_token` and document this clearly in the operator setup guide. |

---

### T6 — Operator signing key theft

| Field | Value |
|-------|-------|
| STRIDE | Spoofing |
| Actor | A4 (local attacker) |
| Attack | Read the ed25519 private key file from disk; use it to forge article signatures attributed to this operator |
| Impact | Attacker can sign and publish articles in any newsgroup as if authored by this operator; forged signatures are accepted by all peers |
| Current mitigation | **Mitigated.** Key file is created with mode 0600 (owner read-only). Operator documentation specifies this requirement. Key is not logged at any point (security default enforced in CLAUDE.md). |
| Residual risk | **Low** under normal conditions. Residual risk is local root access or backup exposure. Hardware security module (HSM) or OS keychain integration is not implemented in v1 and is not required for the threat model. |

---

### T7 — Replay attacks on signed articles

| Field | Value |
|-------|-------|
| STRIDE | Spoofing |
| Actor | A1 (malicious peer), A3 (network attacker) |
| Attack | Capture a valid signed article from the gossipsub network and resubmit it to a transit peer or reader POST path, either verbatim or with a modified timestamp |
| Impact | Duplicate articles appear in groups; potentially pollutes article number sequences |
| Current mitigation | **Mitigated.** Article signatures include the Message-ID field as part of the signed payload. Duplicate Message-IDs are rejected at ingestion (`MsgIdMap::insert()` returns an error on collision; `check_ingest()` checks this before writing). A replayed article with the same Message-ID will be rejected as a duplicate. An attacker who modifies any signed field (including timestamp) invalidates the signature. |
| Residual risk | **Low.** An attacker who has the signing key (see T6) could construct a new article with a new Message-ID. That is key theft, not replay — see T6. |

---

### T8 — Wildmat regex denial of service

| Field | Value |
|-------|-------|
| STRIDE | Denial of Service |
| Actor | A2 (malicious reader client) |
| Attack | Send `LIST ACTIVE *.*.*.*.*.*.*.*` or similar pattern with many consecutive `*` wildcards against a server with many groups. The recursive `wildmat_match()` function in `crates/reader/src/session/commands/list.rs` has O(2^n) worst-case backtracking per group name. |
| Impact | CPU exhaustion on the reader daemon; one connection can block the event loop or starve other clients |
| Current mitigation | **Not mitigated.** The wildmat string is accepted from the client subject only to the 512-byte command line limit. No pattern complexity limit, no iteration cap, no memoization. The command timeout (`command_timeout_secs = 30` in reader config) provides partial protection — a session that takes too long will be killed — but the CPU damage occurs before the timeout fires. |
| Residual risk | **Medium.** This is audit Gap 4. A single client connection can cause significant CPU consumption. The fix is to replace the recursive matcher with an iterative or memoized implementation, or to impose a maximum `*` count on the wildmat pattern before matching. |

---

### T9 — POST body buffered before size check

| Field | Value |
|-------|-------|
| STRIDE | Denial of Service |
| Actor | A2 (malicious reader client) |
| Attack | Send a POST command followed by an arbitrarily large dot-terminated body (e.g., several gigabytes). `read_dot_terminated()` in `crates/reader/src/session/commands/post.rs` reads the entire stream into a `Vec<u8>` before the 1 MiB size check in `complete_post()`. |
| Impact | **High.** Memory exhaustion. A single TCP connection can consume all available RAM, causing OOM kill of the reader daemon or the entire host. |
| Current mitigation | **Not mitigated.** The size limit exists but is applied post-read. There is no incremental byte count check inside `read_dot_terminated()`. This is audit Gap 6. |
| Residual risk | **High.** This is the highest-severity open gap in the current codebase. An anonymous client (if POST is open, or any authenticated client) can crash the daemon with a single large POST. |
| Recommended follow-up | Enforce the size limit incrementally inside `read_dot_terminated()`: accumulate a byte counter and return an error as soon as the limit is exceeded, before the full body is in memory. The fix is contained to one function. |

---

### T10 — Gossipsub peer spoofing

| Field | Value |
|-------|-------|
| STRIDE | Spoofing |
| Actor | A1, A3 |
| Attack | Inject gossipsub messages purporting to be from a known peer, or publish unsolicited group log entries to a gossipsub topic |
| Impact | Malformed group log entries; phantom articles appearing in the CRDT |
| Current mitigation | **Mitigated.** libp2p gossipsub signs every published message with the publishing peer's libp2p identity key. `StrictSign` validation mode rejects messages with invalid or missing signatures. Gossipsub topic filtering (per-hierarchy, not per-group) means off-topic messages are dropped at the gossipsub layer. Additionally, every group log entry carries an operator ed25519 signature over `(timestamp, article_cid, message_id)` — a valid gossipsub message with an invalid operator signature is rejected at the application layer. |
| Residual risk | **Low.** An attacker who can forge a libp2p identity key and an operator signing key simultaneously would need to compromise both. These are independent keys with independent storage. |

---

## 5. Security Invariants

These invariants must never be violated by any code change. Violations are
bugs, not tradeoffs.

**I1 — No unsigned article in IPFS or group log**
An article MUST be signed by the operator ed25519 key before it is written to
IPFS or appended to the Merkle-CRDT group log. The signing step is not
optional, not skippable, and not conditional on any configuration flag.

**I2 — No plaintext password in any log**
AUTHINFO PASS passwords must never appear in log output at any level (debug,
info, warn, error). The password field is zeroed or dropped before any logging
of the AUTHINFO command.

**I3 — Admin endpoint requires authentication when non-loopback**
If the admin endpoint is bound to any address other than `127.0.0.1` or `::1`,
authentication (at minimum a shared secret Bearer token) MUST be required on
every request. This invariant is not currently enforced in code (v1 limitation)
but is required before any non-loopback deployment.

**I4 — Message-ID validated before storage**
A Message-ID string from the NNTP wire is untrusted. It MUST pass
`is_valid_message_id()` from `crates/core/src/validation.rs` before it is used
as a key in `MsgIdMap`, as a field in `ArticleHeader`, or as an argument to
any SQL query. The transit-side `validate_msgid_format()` is weaker and does
not satisfy this invariant — see T3 and audit Gap 7.

**I5 — Article size enforced before memory allocation**
The 1 MiB (`MAX_ARTICLE_BYTES`) limit MUST be enforced incrementally during
read, not after the full body is in memory. This invariant is currently violated
on the POST path — see T9 and audit Gap 6.

**I6 — No shell execution of user-supplied data**
No user-supplied string (NNTP command argument, article header, article body)
may be passed to `std::process::Command`, `exec()`, or any shell interpreter
at any point in the stack. This is verified clean for the current codebase.

---

## 6. Out of Scope for v1

The following threat classes are acknowledged but explicitly out of scope for
the v1 implementation.

**OOS1 — Transit-to-transit authentication**
All NNTP peers are accepted without authentication in v1. Peer authentication
(e.g. TLS client certificates, shared secrets) is a v2 concern. Operators
should restrict port 119 at the firewall to known peer IP addresses as a
compensating control.

**OOS2 — End-to-end article encryption**
Article content is stored in IPFS as plaintext DAG-CBOR blocks. CIDs are
deterministic — anyone who knows the CID can retrieve the content from the
IPFS DHT. No encryption of article content is planned for v1. Operators
who require confidentiality must not use public IPFS pinning.

**OOS3 — Anti-spam and content filtering**
No moderation, no cancel messages, no spam scoring. The system stores and
forwards all articles received from peers that pass structural validation.
Content policy enforcement is an operator-layer concern (firewall rules,
peer selection).

**OOS4 — Distributed denial of service (DDoS)**
Large-scale volumetric attacks against port 119 are not addressed by
application-layer controls. Standard network-layer mitigations apply
(upstream rate limiting, IP blocklists, BGP blackholing).

**OOS5 — Gossipsub Sybil attacks**
libp2p gossipsub peers can be created cheaply. A Sybil attacker who controls
many peer identities can attempt to monopolize gossipsub message propagation.
This is a known limitation of permissionless gossipsub and is not addressed
in v1.

---

## 7. Open Gaps Requiring Code Fixes

This section cross-references the input validation audit findings that
represent actionable engineering work, ranked by severity.

| Priority | Gap | Threat | File | Fix Summary |
|----------|-----|--------|------|-------------|
| High | Gap 6 | T9 | `crates/reader/src/session/commands/post.rs` | Enforce 1 MiB limit inside `read_dot_terminated()` incrementally |
| Medium | Gap 4 | T8 | `crates/reader/src/session/commands/list.rs` | Replace recursive `wildmat_match()` with iterative or memoized implementation; cap `*` count |
| Medium | Gap 7 | T3 | `crates/transit/src/peering/ingestion.rs` | Replace `validate_msgid_format()` with shared `is_valid_message_id()` from core |
| Low | Gap 1 | — | `crates/reader/src/session/dispatch.rs` | Return 411 (no such group) when `GroupName::new()` fails; do not advance to GroupSelected |
| Low | Gap 2 | T3 | `crates/reader/src/session/command.rs` | Call `is_valid_message_id()` in `parse_article_ref()` before constructing Command variant |
| Low | Gap 3 | — | `crates/reader/src/session/command.rs` | Return 501 syntax error on unparseable range instead of silently coercing to 0 |
| Low | Gap 5 | — | `crates/reader/src/session/command.rs` | Validate date/time tokens in NEWGROUPS and NEWNEWS at parse time |
