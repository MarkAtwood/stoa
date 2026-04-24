# ADR-0007: Additive NNTP CID Extensions

**Status:** Accepted
**Date:** 2026-04-20

---

## Context

stoa stores every article as a content-addressed IPLD block in IPFS.
Standard newsreader clients (slrn, tin, pan, Thunderbird) are entirely unaware
of this: they see a normal RFC 3977 NNTP server and never interact with CIDs.

However, CID-aware tooling — archival scripts, the future Corundum indexer,
IPFS pinning automation — can benefit from discovering and verifying article
CIDs over the same NNTP connection without needing a separate API surface.

The original design invariant prohibited all custom extensions that expose IPFS
internals. This ADR documents the relaxation of that invariant to allow a
specific, well-bounded category of additive CID-exposing extensions.

---

## Decision

We add five NNTP extensions to `stoa-reader`, categorised as passive
(article headers) or active (X-commands):

### Passive (injected into responses, no client action required)

1. **`X-Stoa-CID`** header in `ARTICLE` and `HEAD` responses — the
   canonical article CID (RAW codec `0x55`, SHA-256 of the canonical bytes).
   Standard newsreaders ignore unknown headers per RFC 5322 §3.6.8.

2. **`X-Stoa-Root-CID`** header in `ARTICLE` and `HEAD` responses — the
   IPLD DAG root CID (DAG-CBOR `0x71`), present only for multi-block articles.
   Absent for all v1 single-block text articles. Future-proofs the protocol for
   v2 binary support without requiring a protocol change.

### Active (X-commands, opt-in via `CAPABILITIES`)

3. **`XCID [<message-id>]`** — returns `290 <cid>` for the current or named
   article. Clients must confirm `XCID` in `CAPABILITIES` before sending.

4. **`XVERIFY <message-id> <expected-cid> [SIG]`** — verifies stored CID
   matches `expected-cid`; optionally re-verifies the operator ed25519
   signature. Returns `291` (verified), `541` (mismatch/not found), or `542`
   (signature failure).

5. **`ARTICLE cid:<cidv1>`** (and `HEAD cid:...`, `BODY cid:...`) — accepts a
   `cid:` prefixed CIDv1 locator as an alternative to `<message-id>` and
   article number forms. Looks up directly in the IPFS block store.
   Advertised as `X-CID-LOCATOR` in `CAPABILITIES`.

All five are advertised in `CAPABILITIES`. The full wire protocol is in
`docs/wire_format.md §12`.

---

## Rationale

### Why these five, and not others

These extensions expose **only content-addressing metadata**: CIDs and integrity
verification. They do not expose peer topology, DHT state, CRDT log structure,
pin status, GC policy, or any IPFS infrastructure state.

The passive headers require zero client changes and carry no protocol risk:
RFC 5322 §3.6.8 specifies that unknown headers must be ignored. The active
X-commands are explicitly reserved for experimental use by RFC 3977 §7.2; they
are only sent by clients that have confirmed the capability, making them
invisible to standard newsreaders.

### The Corundum integration driver

`X-Stoa-CID` is the highest-value extension. Corundum's future
`rfc822+mime` activity type needs the article root CID to build a content
reference. Exposing it as an article header means the Corundum indexer can
harvest CIDs from normal `ARTICLE` fetches without any custom API.

### `XVERIFY` as an integrity tool

Archival operators need assurance that stored articles are intact. `XVERIFY`
provides a lightweight integrity probe that re-derives the CID from raw block
bytes (independent of the stored CID field), catching local storage corruption.
The `SIG` option catches signing-key misuse without requiring a full article
fetch.

### `ARTICLE cid:` as a content-addressed fetch

CID-aware clients that already hold a CID (from a header, from `XCID`, from
another IPFS node) should be able to fetch by CID directly. This is the most
natural expression of content-addressed storage and enables round-trip
verification: fetch by CID, and you are guaranteed to get exactly the block
that hashes to that CID.

---

## Consequences

### Positive

- CID-aware tools can use standard NNTP connections; no separate API needed.
- Corundum integration path is available without modifying the NNTP protocol.
- `XVERIFY` gives operators a lightweight integrity audit tool.
- All five extensions degrade gracefully: a server without them is
  indistinguishable from a standard NNTP server to newsreader clients.

### Negative / risks

- **Fingerprinting:** advertising `XCID`, `XVERIFY`, and `X-CID-LOCATOR` in
  `CAPABILITIES` reveals that the server is a stoa node. This is
  accepted: the system is not designed for anonymity.
- **Response code collisions:** `290`, `291`, `541`, `542` are unregistered
  experimental codes. If IANA or a future RFC assigns these codes to
  incompatible uses, we will need to renumber. Tracked as a known risk.
- **Maintenance burden:** five additional commands/headers to test and maintain.
  Mitigated by the well-defined scope (CID and signature verification only) and
  the clear invariant about what is prohibited.

---

## Rejected Alternatives

**"Expose everything"** — also advertise peer topology, CRDT log entries, pin
status, GC schedule. Rejected: these expose operational state that is
irrelevant to content-addressed retrieval and would be a privacy and security
risk (topology exposure aids censorship).

**"Separate CID API endpoint"** — provide an HTTP API alongside NNTP for
CID lookups. Rejected: requires a separate connection, separate authentication,
and additional configuration. NNTP extension headers and commands are the
natural extension point for NNTP-connected clients.

**"No extensions at all"** — preserve the original invariant. Rejected: the
Corundum integration requirement and the archival integrity use case are
compelling enough to warrant a carefully scoped relaxation. The invariant is now
more precise, not weaker.
