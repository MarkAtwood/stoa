# Spike: Hashcash Proof-of-Work as POST Spam Mitigation

**Status: NO-GO — permanently deferred**
**Date:** 2026-04-20
**Scope:** `stoa-reader` POST path spam mitigation

---

## Conclusion First

Hashcash is **not viable** for this project. The hard blocker is RFC 3977
compatibility: no standard newsreader client (slrn, tin, pan, Thunderbird)
generates `X-Hashcash:` headers. Requiring a stamp that clients cannot produce
breaks the core design invariant that unmodified RFC 3977 clients must work
without modification.

Server-side rate limiting (spike l62.12.6) achieves equivalent spam control
without touching the client at all. There is no scenario where revisiting
Hashcash is worthwhile unless the entire newsreader ecosystem adds stamp support,
which is not on any roadmap.

---

## What Hashcash Is

Hashcash is a proof-of-work scheme originally designed for email anti-spam
(Adam Back, 1997). The IETF documented it informally; it is not an RFC standard
but is widely referenced as "RFC 2289-style" in literature.

### Token format

```
X-Hashcash: 1:<bits>:<date>:<resource>:<ext>:<rand>:<counter>
```

Fields:

| Field      | Description                                              |
|------------|----------------------------------------------------------|
| `1`        | Version number (always 1 in practice)                   |
| `bits`     | Required number of leading zero bits in the SHA-1 hash  |
| `date`     | YYYYMMDD or YYYYMMDDHHMMSS                               |
| `resource` | Protected value (e.g. email address or Message-ID)      |
| `ext`      | Extension data (usually empty)                          |
| `rand`     | Random nonce, base64-encoded                             |
| `counter`  | Incrementing value, base64-encoded                       |

### Proof-of-work mechanism

The client increments `counter` until `SHA-1(<full-token-string>)` has at least
`bits` leading zero bits. The expected number of SHA-1 hashes is `2^bits`.

| Difficulty | Expected hashes | Approx. time (modern laptop) |
|------------|----------------|------------------------------|
| 20 bits    | ~1,048,576      | ~0.1 s                       |
| 24 bits    | ~16,777,216     | ~1.5 s                       |
| 28 bits    | ~268,435,456    | ~25 s                        |

Benchmarks measured on a single core using SHA-1 in software. GPU offload can
reduce these by 2–3 orders of magnitude, which substantially weakens the
anti-spam property against well-resourced senders.

### Server verification

Verification is O(1): compute `SHA-1(<token>)` once, count leading zero bits,
check that `bits` meets the threshold, validate the `date` is within an
acceptance window, and confirm the token has not been seen before (replay check).
Server-side cost is negligible.

### Prior art in email

SpamAssassin awards a negative spam score for a valid Hashcash stamp. Postfix and
Exim can be configured to require stamps. Client support exists in some MUAs
(Thunderbird had an experimental plugin, now unmaintained) and command-line tools
(`hashcash` binary). Adoption never reached critical mass in email; it is now
considered obsolete there as well.

---

## Application to Usenet POST

The conceptual flow would be:

1. Client picks an article Message-ID (e.g., `<unique@example.com>`).
2. Client computes a Hashcash stamp with `resource = <Message-ID>`.
3. Client includes `X-Hashcash: 1:20:20260420:<Message-ID>::<rand>:<counter>` in
   the article headers.
4. Server's `validate_headers` function (during POST processing) checks the stamp.
5. Missing or invalid stamp → `441 Posting failed` response.
6. Valid but already-seen stamp → `441 Posting failed` (replay rejection).

Server-side implementation cost:

- SHA-1 computation: `sha1` crate (~30 lines)
- Stamp parse and validate: ~50 lines
- Replay protection: one SQLite table `(stamp_hash TEXT PRIMARY KEY, seen_at INTEGER)`
  with a GC job to expire entries older than the acceptance window
- Total: roughly 150 lines of production code plus tests

This is low implementation cost. The problem is not on the server side.

---

## Client Support

This is the hard blocker.

| Client      | Generates X-Hashcash | Notes                               |
|-------------|----------------------|-------------------------------------|
| slrn        | No                   | No plugin system for header injection |
| tin         | No                   | No extension mechanism              |
| pan         | No                   | GTK client, no stamp support        |
| Thunderbird | No                   | Historical plugin (Hashcash 0.3.7) removed; not maintained since ~2008 |
| Gnus        | No                   | Emacs NNTP client, no stamp support |
| NNTPgrab    | No                   | Downloader, does not POST           |

No standard newsreader client generates `X-Hashcash:` headers on POST. This is
not an implementation gap that could be closed with a configuration option — the
clients simply do not have this capability.

Workarounds would require:

- A local NNTP proxy that intercepts POST, computes the stamp, and injects the
  header before forwarding to the server. This is a non-trivial piece of custom
  software the user must install, configure, and maintain.
- Custom client forks. Not a realistic path for general deployment.
- A web UI or API that wraps POST and handles stamp generation server-side on
  behalf of the user. This contradicts the design goal of supporting standard
  clients without modification.

Any of these workarounds adds deployment friction that defeats the purpose of
supporting standard RFC 3977 clients.

---

## Design Invariant Conflict

CLAUDE.md hard design invariant 1 states:

> No custom or proprietary extensions. No extensions that expose CIDs, peer
> topology, or IPFS internals to clients.

Requiring `X-Hashcash:` is a custom extension that standard clients do not
generate. Rejecting compliant RFC 3977 POST requests because they lack a
non-standard header violates this invariant. There is no interpretation of the
invariant under which Hashcash requirement is compatible.

---

## GPU and ASIC Resistance

SHA-1 is not memory-hard. GPU clusters can compute SHA-1 at rates that make
20-bit and 24-bit difficulty trivially cheap for a motivated spammer while
remaining painful for legitimate users on older hardware. The difficulty would
need to scale up over time as hardware improves, creating a maintenance burden
and worsening the user experience for low-end clients.

Memory-hard alternatives (Scrypt, Argon2, Equihash) exist but are even further
from any newsreader client implementation and would require specifying a new
wire format. This is not a path worth pursuing.

---

## Comparison with Rate-Limited Signing (l62.12.6)

| Property                       | Hashcash PoW      | Rate-Limited Signing     |
|--------------------------------|-------------------|--------------------------|
| Client changes required        | Yes (hard blocker)| No                       |
| RFC 3977 compatibility         | Broken            | Preserved                |
| Server-side implementation     | ~150 lines        | ~200 lines               |
| GPU offload weakens protection | Yes               | No (signing key required)|
| Per-user rate enforcement      | No                | Yes                      |
| Replay protection needed       | Yes               | No                       |
| Operator control               | Indirect          | Direct                   |

Rate-limited signing achieves the same spam-control goal — making bulk posting
expensive — without requiring any client changes, without the GPU weakness, and
with stronger per-identity enforcement.

---

## Recommendation

**NO-GO for v1 and all subsequent versions unless the newsreader client ecosystem
adds native Hashcash support.**

The client compatibility blocker is architectural, not incidental. No amount of
server-side sophistication resolves the fact that standard clients cannot generate
the required header.

Do not implement Hashcash support. Do not revisit this spike unless a credible
newsreader client (slrn, Thunderbird, or equivalent with significant user base)
ships `X-Hashcash:` generation as a standard feature. File this issue as
permanently deferred.

Pursue rate-limited signing (l62.12.6) instead.
