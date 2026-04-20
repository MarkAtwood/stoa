# Spike: Rate-Limited Operator Signing as Spam Mitigation

**Status:** Decision reached — see Recommendation
**Date:** 2026-04-20
**Scope:** `usenet-ipfs-reader` POST path; `usenet-ipfs-transit` IHAVE/TAKETHIS path
**Beads issue:** usenet-ipfs-l62.12.6

---

## Background

The operator ed25519 key signs every article before it is written to IPFS and
appended to the Merkle-CRDT group log (security invariant I1 in `docs/threat_model.md`).
This is unconditional today: any POST that passes structural validation triggers
`sign_article()` and a write to IPFS.

An abused POST endpoint means the operator's own signing key is used to flood the
network with spam at whatever rate the TCP stack allows. Rate-limited signing caps
the blast radius: an attacker who controls the POST endpoint (or a credential for it)
can only push N articles per minute into the signed article stream.

This spike evaluates three design options, compares implementation cost, and makes
a go/no-go recommendation.

---

## What Rate-Limited Signing Means

The operator signing key signs at most N articles per minute (configurable). Articles
that arrive while the budget is exhausted are rejected immediately with NNTP response
`441 Posting failed` and a human-readable reason string. No queuing; the client bears
the retry burden.

The limit is applied per authenticated identity: per client IP address for unauthenticated
POST, per AUTHINFO username when `AUTHINFO USER/PASS` is in use. This ensures a single
abusive source cannot crowd out all other posters.

The IHAVE/TAKETHIS path in the transit daemon carries a separate question; see the
IHAVE Interaction section below.

---

## Design Options

### Option A: Token Bucket at POST Handler (Recommended)

A token bucket per client identity sits inside `session/commands/post.rs`, before the
call to `sign_article()`. Each identity is allocated a bucket of depth `burst_capacity`
that refills at `post_rate_limit_rpm / 60` tokens per second. A POST request consumes
one token; when the bucket is empty the request is rejected immediately.

```
POST received
    → identify client (IP or AUTHINFO username)
    → acquire token from per-identity bucket
        → bucket empty: reply 441, return
    → validate article structure
    → sign_article()
    → write to IPFS
    → reply 240
```

**Pros:**
- In-process; no inter-process communication, no new dependencies.
- Sub-microsecond rejection when bucket is empty — no resource consumption before the
  check.
- Per-identity: a spammer with one credential cannot starve legitimate users.
- The `governor` crate (MIT licensed, zero unsafe, already common in the tokio ecosystem)
  provides a production-quality `RateLimiter<NotKeyed, InMemoryState, ...>` and a
  `DefaultKeyedRateLimiter<K>` that handles the per-key case.
- Default configuration (`post_rate_limit_rpm = 60`, burst of 5) allows a human poster
  to post 5 articles rapidly then 1/minute sustained — effectively unlimited for human
  use, prohibitive for automation.

**Cons:**
- State is in-process: the limit is per reader-daemon instance. A spammer with connections
  to two reader instances on different hosts is not cross-limited. Multi-instance deployments
  need a shared rate limit (Redis, or a shared SQLite table) which adds complexity. This is
  acceptable for v1 where single-host is the common case.
- A distributed spammer rotating IPs bypasses a per-IP limit. This is explicitly
  acknowledged — see Limitations.

**Implementation cost:** Low. The `governor` crate is ~800 lines of safe Rust. Wiring
requires adding one `Arc<DefaultKeyedRateLimiter<IpAddr>>` (or `String` for username-keyed)
to the per-session or server state, then a two-line check before `sign_article()`.

---

### Option B: Signing Queue with Worker

Articles are placed in an in-process channel. A single signing worker goroutine reads
from the channel, signs articles, and writes to IPFS at a controlled rate. POST returns
a queued acknowledgement.

NNTP does not have an equivalent of HTTP 202 Accepted. RFC 3977 §6.3 says the server
MUST reply `240 Article received OK` when the article has been accepted, and MUST NOT
reply until the operation is complete. There is no standard "queued, check back later"
response. Returning `240` before the article is signed and written would violate the
protocol: the client would re-POST on reconnect if it sees `240` but the article never
appears. Returning `441` from the queue side leaves the client with no way to distinguish
transient failure from permanent rejection.

**Verdict: Not appropriate for NNTP.** The protocol semantics require synchronous
completion. Option A's synchronous reject is the correct NNTP idiom.

---

### Option C: Separate Signing Service (Unix Socket)

POST handler sends article data to a local signing daemon via a Unix domain socket.
The signing daemon owns the private key, applies rate limiting, signs if the budget
allows, and returns the signature or a refusal.

**Pros:**
- Private key never lives in the reader process memory — smaller attack surface for key
  extraction.
- Rate limit state is centralized across multiple reader instances sharing the socket.

**Cons:**
- Adds a new daemon, a new socket protocol, a new failure mode. If the signing daemon
  crashes, all POST operations fail.
- The latency cost is a Unix socket round-trip per POST — ~10–50 µs on a local socket,
  not a real concern, but it adds complexity without proportionate benefit for v1.
- Key isolation benefit overlaps with OS file permissions (mode 0600) already required
  for the key file. For the threat model in scope (single-operator, single-host), file
  permissions are sufficient.

**Verdict:** Appropriate for multi-instance or high-security deployments. Deferred to
a future hardening epic. Out of scope for v1.

---

## Comparison Summary

| Criterion                        | Option A: Token Bucket | Option B: Queue | Option C: Signing Svc |
|----------------------------------|------------------------|-----------------|----------------------|
| NNTP protocol correctness        | Yes                    | No              | Yes                  |
| New process / daemon             | No                     | No              | Yes                  |
| New crate dependency             | `governor` (small)     | None            | None                 |
| Per-identity limiting            | Yes                    | Yes             | Yes                  |
| Multi-instance rate sharing      | No (v1 acceptable)     | N/A             | Yes                  |
| Key isolation                    | No change              | No change       | Yes                  |
| Implementation effort            | Low (~20 lines)        | N/A             | High (new daemon)    |

---

## Interaction with ed25519-dalek Signing

The current signing flow in the reader daemon:

```
session/commands/post.rs
    → validate_article_structure()
    → sign::sign_article(&article, &operator_key)   ← ed25519-dalek
    → ipfs_client.write_block(signed_article)
    → group_log.append(log_entry)
    → "240 Article received OK"
```

With Option A, the token bucket check is inserted before `sign_article()`:

```
session/commands/post.rs
    → validate_article_structure()
    → rate_limiter.check_key(&client_identity)      ← new
        → Err: "441 Posting rate limit exceeded\r\n", return
    → sign::sign_article(&article, &operator_key)
    → ipfs_client.write_block(signed_article)
    → group_log.append(log_entry)
    → "240 Article received OK"
```

No change to the signing algorithm, key representation, or key management. The
`ed25519-dalek` API surface and the `sign_article()` function signature are untouched.
Security invariant I1 (every article signed before IPFS write) is preserved: the only
code path that reaches `sign_article()` is the path where a token was successfully
acquired.

---

## IHAVE / TAKETHIS Interaction

IHAVE and TAKETHIS arrive on the transit daemon's peering port (`:119`), not the reader's
POST path. They represent articles originating from *peer servers*, not end-user clients.

Rate-limiting IHAVE/TAKETHIS with the same operator-signing bucket would cap the transit
daemon's ingestion rate, which is the wrong behavior: a busy peer feed can legitimately
deliver thousands of articles per minute during a catch-up sync.

**The POST rate limit MUST NOT apply to the IHAVE/TAKETHIS path.** The two paths are
already in separate binaries (reader vs transit) with separate config structs and separate
signing call sites, so there is no shared state to accidentally cross. This is confirmed
by inspection: `crates/transit/src/peering/ingestion.rs` calls `sign_article()` directly
in the transit process; `crates/reader/src/session/commands/post.rs` calls it in the
reader process.

If transit-side ingestion rate limiting is needed, it belongs to the per-peer rate limiting
work already tracked as epic `usenet-ipfs-l62.5.5` (Transit: back-pressure and per-peer
rate limiting), with its own separate token bucket and config knob.

---

## Comparison with Hashcash (usenet-ipfs-l62.12.5)

Hashcash imposes a CPU cost on the *poster* proportional to the desired bit-difficulty.
Rate-limited signing imposes a wall-clock rate limit on the *server's signing key*
regardless of the poster's compute.

| Property                          | Rate-limited signing           | Hashcash PoW                           |
|-----------------------------------|--------------------------------|----------------------------------------|
| Spam deterrent mechanism          | Signing budget exhaustion      | Client-side CPU cost                   |
| Newsreader client compatibility   | Transparent (no client change) | Requires client to compute and attach  |
|                                   |                                | `X-Hashcash:` header — not supported   |
|                                   |                                | by slrn, tin, Thunderbird              |
| GPU/ASIC resistance               | Not applicable                 | Low (SHA-1 basis, cheap on GPU)        |
| Distributed spammer evasion       | Per-IP limit is bypassed       | PoW cost still paid per article        |
| Implementation complexity         | Low                            | Medium (stamp generation + validation) |
| Operator config burden            | One integer in config.toml     | Bit-difficulty tuning + documentation  |
| RFC 3977 compliance impact        | None                           | None (header is ignored by other       |
|                                   |                                | servers if unknown)                    |

The Hashcash spike's key finding is client compatibility: standard newsreaders do not
generate `X-Hashcash:` headers. An operator who enables Hashcash enforcement breaks
legitimate clients unless they provide a custom posting agent. Rate-limited signing has
no client-visible behavior change; clients that hit the limit receive a standard `441`
they already handle.

The two mitigations are complementary rather than exclusive, but for v1, rate-limited
signing is strictly easier to deploy and does not require any client cooperation.

---

## Effectiveness and Limitations

**Effective against:**
- A single automated client hammering POST from a fixed IP or single credential.
- Accidents: a misconfigured client in a retry loop that would otherwise flood the
  operator's signing key.

**Not effective against:**
- Distributed spammers rotating source IPs (botnet scenario). The per-IP bucket is
  bypassed trivially.
- Slow spam: an attacker who stays under the rate limit indefinitely. Content analysis
  (out of scope for v1 per OOS3 in the threat model) is the appropriate tool.
- Spam originating from the transit (IHAVE) path rather than the reader POST path.

These limitations are accepted. Rate-limited signing is a first-order defense against
naive automation, not a comprehensive spam filter.

---

## Implementation Cost

**New dependency:** `governor = "0.6"` (MIT/Apache-2.0, no unsafe, no proc macros,
no async runtime dependency). The `DefaultKeyedRateLimiter` handles the per-IP-keyed
case with a `DashMap`-backed store. Alternatively, a `tokio::sync::Mutex<HashMap<...>>`
with a manual token refill is feasible in ~40 lines if a new crate dependency is
unwanted, at the cost of less-precise refill timing.

**Config change:** One field added to `reader/src/config.rs`:

```rust
pub struct PostConfig {
    pub post_rate_limit_rpm: u32,  // 0 = unlimited; default 60
    pub post_rate_burst: u32,      // default 5
}
```

**Wire-in sketch** (`crates/reader/src/session/commands/post.rs`):

```rust
pub async fn handle_post(
    state: &mut SessionState,
    rate_limiter: &DefaultKeyedRateLimiter<IpAddr>,
) -> Result<Response> {
    let client_ip = state.peer_addr.ip();

    // Rate limit check before any signing or IPFS work.
    if rate_limiter.check_key(&client_ip).is_err() {
        return Ok(Response::new(441, "Posting rate limit exceeded"));
    }

    let article = read_dot_terminated(&mut state.stream).await?;
    validate_article_structure(&article)?;
    let signed = sign_article(&article, &state.operator_key)?;
    state.ipfs.write_block(&signed).await?;
    state.group_log.append(log_entry_from(&signed)).await?;
    Ok(Response::new(240, "Article received OK"))
}
```

Total new code: approximately 20 lines (rate limiter construction at startup, config
field, and the two-line check above). No existing functions are modified.

---

## Go/No-Go Recommendation

**Recommendation: implement in v1.**

Rationale:
1. The implementation cost is trivial: one config field, one crate, ~20 lines.
2. The protection is real: it prevents naive automation from using the POST endpoint
   to flood the operator's signing key.
3. There is no client compatibility impact: standard newsreaders see only `441` on
   rate exceed, which they already handle.
4. The IHAVE path is unaffected by design (separate binary, separate config).
5. The limitations (distributed spam, slow spam) are acknowledged and are the
   correct concern for a future content-analysis epic, not for this change.

**Acceptance criteria:**
- `post_rate_limit_rpm = 60` is the default; `post_rate_burst = 5` is the default.
- Setting `post_rate_limit_rpm = 0` disables rate limiting (unlimited).
- Clients that exceed the limit receive `441 Posting rate limit exceeded\r\n`.
- The IHAVE/TAKETHIS path in the transit daemon is not affected.
- The rate limiter is keyed per remote IP address; when AUTHINFO is in use, keying
  switches to the authenticated username so IP rotation does not bypass the limit.
- No new `unsafe` code.
