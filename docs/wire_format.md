# stoa Wire Format Specification

This document specifies every on-wire and on-disk encoding used by stoa.
A conforming implementation in any language must produce and accept bytes that
match these specifications exactly.  Where field names are given, they are the
exact names used in the Rust structs in `crates/core/src/` and
`crates/transit/src/`.

## Table of Contents

1. [Encoding Fundamentals](#1-encoding-fundamentals)
2. [CID Scheme](#2-cid-scheme)
3. [Canonical Article Serialization](#3-canonical-article-serialization)
4. [Article IPLD Block Structure](#4-article-ipld-block-structure)
5. [MIME Node Block Format](#5-mime-node-block-format)
6. [Group Log Entry Format](#6-group-log-entry-format)
7. [HLC Timestamp Encoding](#7-hlc-timestamp-encoding)
8. [Tip Advertisement Message Format](#8-tip-advertisement-message-format)
9. [Message-ID Format and Validation](#9-message-id-format-and-validation)
10. [Gossipsub Topic Naming](#10-gossipsub-topic-naming)
11. [Worked Examples](#11-worked-examples)
12. [NNTP CID Extension Protocol](#12-nntp-cid-extension-protocol)

---

## 1. Encoding Fundamentals

### DAG-CBOR

All IPLD nodes (article root blocks, MIME nodes) are encoded as **DAG-CBOR**,
IPLD codec code `0x71`.  DAG-CBOR is CBOR (RFC 8949) with the following
constraints:

- Map keys must be strings.
- CBOR tag 42 encodes CID links.  A CID link is a CBOR byte string with a
  `0x00` varint prefix prepended to the raw CID bytes, then wrapped in tag 42.
- Integer encoding is minimal (no padding).
- Floating-point is IEEE 754.
- Indefinite-length encodings are forbidden.
- Maps must have no duplicate keys.
- Map key ordering: `serde_ipld_dagcbor` (the implementation library, v0.6)
  serializes struct fields in declaration order.  This is the canonical
  ordering; fields are described in declaration order throughout this document.

Implementation: `serde_ipld_dagcbor` 0.6.  This codec choice is
**irreversible** once articles are written to IPFS and referenced in group logs.

### JSON (Tip Advertisements)

Tip advertisement messages are encoded as plain JSON (`serde_json`).  Field
ordering is the struct declaration order, which is stable.

### Multihash

All hashes use **SHA2-256**, multihash function code `0x12`, 32-byte digest.
The multihash wire encoding is `0x12 0x20` followed by 32 digest bytes.

### CIDv1 String Encoding

CIDs are serialized to strings using multibase **base32upper** with the `b`
prefix (lowercase `b` for base32upper is the libp2p/IPFS convention).  This is
what `Cid::to_string()` produces.

---

## 2. CID Scheme

Two codecs are used, chosen by the block type:

| Block type                   | Codec          | Code   | Input to hash                  |
|------------------------------|----------------|--------|--------------------------------|
| Raw header bytes             | RAW            | `0x55` | verbatim RFC 5536 header bytes |
| Raw body bytes               | RAW            | `0x55` | verbatim NNTP body bytes       |
| Decoded MIME content bytes   | RAW            | `0x55` | decoded (not wire) bytes       |
| Article root node            | DAG-CBOR       | `0x71` | DAG-CBOR serialization of root |
| MIME node                    | DAG-CBOR       | `0x71` | DAG-CBOR serialization of node |
| Canonical article CID        | RAW            | `0x55` | canonical byte string (§3)     |

CID computation procedure for any block:

1. Hash the block bytes with SHA2-256 to obtain a 32-byte digest.
2. Encode as multihash: `0x12 || 0x20 || digest` (34 bytes total).
3. Wrap as CIDv1: `version=1 || codec || multihash`.

The canonical article CID (`cid_for_article`) uses RAW codec over the
canonical byte string defined in §3.  It is used for deduplication and the
`message_id → CID` mapping table.  It is distinct from the IPFS root node CID.

---

## 3. Canonical Article Serialization

Source: `crates/core/src/canonical.rs` and `crates/core/src/cid_util.rs`.

The canonical byte string is the deterministic input used for hashing and
signing.  It is not stored in IPFS; it is recomputed on demand.

### Format

```
From: {from_value}\r\n
Date: {date_value}\r\n
Message-ID: {message_id_value}\r\n
Newsgroups: {newsgroups_sorted_comma_separated}\r\n
Subject: {subject_value}\r\n
Path: {path_value}\r\n
{extra_headers sorted by key (primary) then value (secondary), each as "Key: value\r\n"}
\x00\n
{raw body bytes}
```

Rules:

- The six mandatory headers appear first, in exactly the order listed above.
- `Newsgroups` value: group names sorted lexicographically, joined by `,` with
  no spaces (e.g. `alt.atheism,sci.skeptic,talk.origins`).
- Extra headers: sorted by header name first (ascending byte order), then by
  header value as a secondary sort key.  This makes canonicalization
  independent of insertion order and stable when the same header name appears
  multiple times.
- The header/body separator is `\x00\n` (NUL byte followed by LF).  NUL is
  forbidden in well-formed RFC 5322 header values, making the boundary
  unambiguous.
- Body bytes are appended verbatim after the separator; no transformation is
  applied.
- All header name/value text is UTF-8.  No NFKC normalization is applied to
  headers at this layer.  (NFKC normalization applies to signed log entries and
  Corundum activity payloads, not to raw article headers.)

### Canonical Article CID

CID is RAW (codec `0x55`) SHA2-256 of the canonical bytes described above.

Reference vector (Python `hashlib`):

```python
canonical = (
    b"From: user@example.com\r\n"
    b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
    b"Message-ID: <test@example.com>\r\n"
    b"Newsgroups: comp.lang.rust\r\n"
    b"Subject: Test subject\r\n"
    b"Path: news.example.com!user\r\n"
    b"\x00\n"
    b"Body text.\r\n"
)
# hashlib.sha256(canonical).hexdigest()
# => 1e6a730aeedb59c8be15d0d602e80b56f90786e607b386be542b47665b586a79
```

The resulting CIDv1 RAW base32upper string encodes version=1, codec=0x55,
multihash=0x12||0x20||that digest.

---

## 4. Article IPLD Block Structure

Source: `crates/core/src/ipld/root_node.rs`.

An article stored in IPFS consists of three to four blocks:

```
article root node  (DAG-CBOR, CIDv1 0x71)
├── header_cid     (RAW block, CIDv1 0x55) — verbatim wire header bytes
├── body_cid       (RAW block, CIDv1 0x55) — verbatim NNTP body bytes
└── mime_cid       (DAG-CBOR block, CIDv1 0x71, optional) — MIME node
```

### ArticleRootNode

DAG-CBOR encoding of a map with these fields in declaration order:

| Field                | Type              | Description |
|----------------------|-------------------|-------------|
| `schema_version`     | uint (u32)        | Schema version; currently `1`.  Consumers must reject root nodes with `schema_version` greater than the maximum they know. |
| `header_cid`         | CID link          | CID of the RAW block holding verbatim RFC 5536 wire headers. |
| `header_map_cid`     | CID link or null  | CID of the DAG-CBOR block holding the structured header map (`HeaderMapNode`). Enables `ipfs dag get <root>/header_map_cid/<name>` for per-header IPLD traversal. Null/absent only for legacy articles that predate this field. |
| `body_cid`           | CID link          | CID of the RAW block holding verbatim NNTP body bytes (after dot-unstuffing). |
| `mime_cid`           | CID link or null  | CID of the MIME node block (DAG-CBOR), or null/absent if MIME parsing was skipped (no `Content-Type` header present). |
| `metadata`           | map (inline)      | `ArticleMetadata` struct, encoded as an inline DAG-CBOR map. |

### ArticleMetadata (inline sub-map)

Fields in declaration order within the `metadata` map:

| Field                  | Type         | Description |
|------------------------|--------------|-------------|
| `message_id`           | string       | RFC 5536 Message-ID header value, including angle brackets (e.g. `<abc@example.com>`). |
| `newsgroups`           | array[string]| Destination newsgroup names, in lexicographic order. |
| `hlc_timestamp`        | uint (u64)   | HLC wall-clock component in milliseconds since Unix epoch. See §7 for the full HLC encoding in log entries; in metadata only the `wall_ms` field is stored. |
| `operator_signature`   | bytes        | Ed25519 signature (64 bytes) by the operator key over the root node CID bytes, once signing is implemented (issue l62.2.6).  Empty bytes until then. |
| `byte_count`           | uint (u64)   | Total byte count: `header_bytes.len() + body_bytes.len()`. |
| `line_count`           | uint (u64)   | Number of LF (`\n`) characters in the body bytes. |
| `content_type_summary` | string       | Type/subtype from `Content-Type` header, lowercased, parameters stripped (e.g. `"text/plain"`, `"multipart/mixed"`).  Default is `"text/plain"` if no `Content-Type` header is present. |

### Schema Versioning

Adding new optional fields does not increment `schema_version`.  Consumers must
ignore unknown fields (the standard `serde` deserialization behaviour for
structs with DAG-CBOR).  `schema_version` increments only on breaking changes
(removed fields, changed semantics).

### Header and Body Raw Blocks

Both blocks are written to IPFS as raw bytes under the RAW codec (`0x55`).
Their CIDs are SHA2-256 of the exact bytes stored.

The `header_bytes` block contains the verbatim RFC 5536 header lines including
the trailing CRLF of each line, with no blank line separator and no body.

The `body_bytes` block contains the verbatim NNTP body bytes after
dot-unstuffing (leading `..` lines are collapsed to `.`) but before any MIME
decoding.

---

## 5. MIME Node Block Format

Source: `crates/core/src/ipld/mime.rs`.

A MIME node is a DAG-CBOR block (codec `0x71`) whose content is one of two
enum variants: `SinglePart` or `Multipart`.  The serde enum representation
encodes the variant as a map with one key equal to the variant name.

### SinglePart variant

```
{
  "SinglePart": {
    "content_type":      string,   // full Content-Type value with parameters
    "transfer_encoding": string,   // Content-Transfer-Encoding (e.g. "7bit", "quoted-printable")
    "decoded_cid":       CID link, // RAW CID of the decoded (not wire) content bytes
    "is_binary":         bool      // true if MIME top-type is not "text"
  }
}
```

### Multipart variant

```
{
  "Multipart": {
    "content_type": string,        // full Content-Type value with boundary parameter
    "parts":        array[MimePart]
  }
}
```

Each `MimePart` in the array:

```
{
  "content_type": string,   // Content-Type of this part
  "decoded_cid":  CID link, // RAW CID of the decoded content bytes for this part
  "is_binary":    bool      // true if part MIME top-type is not "text"
}
```

`decoded_cid` in all cases points to a RAW block holding the transfer-decoded
bytes:
- For `7bit`/`8bit`/`binary` CTE: the body bytes as-is.
- For `quoted-printable` CTE: the QP-decoded bytes.
- For `base64` CTE: the base64-decoded bytes.

The `body_cid` in the root node always points to the verbatim wire bytes.
`decoded_cid` always points to the decoded bytes.  These differ when CTE is
`quoted-printable` or `base64`.

---

## 6. Group Log Entry Format

Source: `crates/core/src/group_log/types.rs`.

Each newsgroup maintains a Merkle-CRDT append-only log.  Log entries are
stored as DAG-CBOR blocks (codec `0x71`).

### LogEntry

| Field                | Type          | Description |
|----------------------|---------------|-------------|
| `hlc_timestamp`      | uint (u64)    | Wall-clock milliseconds component of the HLC timestamp at ingress time.  See §7 for full HLC structure. |
| `article_cid`        | CID link      | CID of the article root node block in IPFS (DAG-CBOR, codec `0x71`). |
| `operator_signature` | bytes         | Ed25519 signature (64 bytes) by the operator key over the canonical entry bytes.  Empty until issue l62.3.x implements log-entry signing. |
| `parent_cids`        | array[CID]    | CIDs of parent log entries.  Empty for the genesis (first) entry.  Multiple entries indicate a merge of concurrent branches. |

### LogEntryId

A `LogEntryId` is 32 raw bytes, typically the SHA-256 of the entry's canonical
serialization.  Displayed and serialized as a lowercase 64-character hex string.

### LogHead

`LogHead` is an in-memory/storage type that tracks the current tip of a group's
log for a given node.  It is not stored as a standalone IPFS block.

| Field         | Type    | Description |
|---------------|---------|-------------|
| `group_name`  | string  | Newsgroup name (e.g. `comp.lang.rust`). |
| `tip_cid`     | CID     | CID of the current tip `LogEntry` block. |
| `entry_count` | uint    | Approximate total number of entries at this tip. |

### Canonical Serialization for Log Entries

The canonical byte representation for signing and CID computation of a log
entry is not yet finalized (tracked as issue l62.3.x).  The current stub
returns empty bytes.  This section will be completed when that issue is
resolved.

---

## 7. HLC Timestamp Encoding

Source: `crates/core/src/hlc.rs`.

The Hybrid Logical Clock (Kulkarni & Demirbas 2014) produces timestamps that
are totally ordered across distributed nodes without requiring synchronized
clocks.

### HlcTimestamp struct

| Field       | Type       | Size    | Description |
|-------------|------------|---------|-------------|
| `wall_ms`   | uint (u64) | 8 bytes | Physical wall-clock time in milliseconds since Unix epoch. |
| `logical`   | uint (u32) | 4 bytes | Logical counter, incremented when wall time does not advance. |
| `node_id`   | [u8; 8]    | 8 bytes | 8-byte opaque node identifier, used as tiebreaker. |

Total encoded size: 20 bytes when serialized as a flat struct.

### Ordering

Total order: `wall_ms` is primary, `logical` is secondary, `node_id`
(lexicographic byte comparison) is tiebreaker.  A higher `wall_ms` always
sorts greater regardless of `logical`.

### DAG-CBOR Encoding

As a DAG-CBOR map, fields appear in declaration order:
`wall_ms` → `logical` → `node_id`.

### Send Algorithm

On `send(now_ms)`:
- `new_wall = max(last.wall_ms, now_ms)`
- `new_logical = if new_wall == last.wall_ms { last.logical + 1 } else { 0 }`

### Receive Algorithm

On `receive(now_ms, observed)`:
- `new_wall = max(last.wall_ms, observed.wall_ms, now_ms)`
- `new_logical`:
  - If `new_wall == last.wall_ms == observed.wall_ms`: `max(last.logical, observed.logical) + 1`
  - Else if `new_wall == last.wall_ms`: `last.logical + 1`
  - Else if `new_wall == observed.wall_ms`: `observed.logical + 1`
  - Otherwise: `0`

### Encoding in `ArticleMetadata`

`ArticleMetadata.hlc_timestamp` stores only `wall_ms` (u64).  The full
three-field `HlcTimestamp` struct appears in `TipAdvertisement` (see §8) as
three separate JSON fields.

---

## 8. Tip Advertisement Message Format

Source: `crates/transit/src/gossip/tip_advert.rs`.

`TipAdvertisement` messages are broadcast over libp2p gossipsub whenever a node
learns new Merkle-CRDT tip CIDs for a group.

### Transport Encoding

Serialized to JSON bytes using `serde_json::to_vec`.  Fields are serialized in
struct declaration order.  No canonical JSON transformation (RFC 8785) is
applied; the struct declaration order is sufficient for determinism because
`serde_json` respects it.

### TipAdvertisement JSON fields (in wire order)

| Field            | JSON type    | Description |
|------------------|--------------|-------------|
| `group_name`     | string       | Newsgroup name (e.g. `"comp.lang.rust"`).  Must not be empty. |
| `tip_cids`       | array[string]| Tip CIDs encoded as multibase base32upper strings (`Cid::to_string()`).  Array is sorted lexicographically before serialization to ensure determinism when the same logical set of tips is encoded on different calls.  Must not be empty. |
| `hlc_ms`         | number (u64) | `wall_ms` component of the sender's HLC timestamp. |
| `hlc_logical`    | number (u32) | `logical` component of the sender's HLC timestamp. |
| `hlc_node_id`    | string       | `node_id` component as a lowercase hex string (16 hex characters = 8 bytes). |
| `sender_peer_id` | string       | Sending peer's libp2p PeerId as a string. |

### Topic Routing

The message is published to the gossipsub hierarchy topic for the group (see
§10).  Receiving peers filter by `group_name` inside the topic.

### Validation on Receipt

`handle_tip_advertisement` rejects messages where:
- `group_name` is empty.
- `tip_cids` is empty.

Malformed JSON is silently discarded (warning logged).

### Example JSON

```json
{
  "group_name": "comp.lang.rust",
  "tip_cids": [
    "bafyreihv47lkxiaysp7lcdvimct2bdreounj2jtzgj5pn7yabkfxzanlci"
  ],
  "hlc_ms": 1700000000000,
  "hlc_logical": 0,
  "hlc_node_id": "0102030405060708",
  "sender_peer_id": "12D3KooW..."
}
```

---

## 9. Message-ID Format and Validation

Source: `crates/core/src/validation.rs`.

All Message-IDs received from the NNTP wire are treated as attacker-controlled
and must be validated before use as map keys, log entries, or storage lookups.

### Format (RFC 5536 / RFC 5322)

```
<local-part@domain>
```

- Angle brackets are mandatory and are part of the stored value.
- Exactly one `@` between the angle brackets.

### Validation Rules (in order)

1. Total byte length must be ≤ 998 bytes (RFC 5322 §2.1.1).
2. Must start with `<` and end with `>`.
3. The content between angle brackets must contain exactly one `@`.
4. Local part (before `@`): must be non-empty, no whitespace, no `<` or `>`.
5. Domain part (after `@`): must be non-empty, no whitespace, no `<` or `>`.

These checks are deliberately conservative — they are a security boundary, not
a full RFC 5536 parser.  Valid Message-IDs that fail these checks do not exist
in practice.

### Storage

Message-IDs are stored with angle brackets as part of the string, exactly as
they appear in the `Message-ID` header value (e.g. `<abc@example.com>`).

---

## 10. Gossipsub Topic Naming

Source: `crates/transit/src/gossip/topics.rs`.

Topics are per-hierarchy, not per-group.  This is a hard design invariant.

### Rule

```
topic = "stoa.hier." + hierarchy
hierarchy = first dot-separated component of the group name
```

Examples:
- `comp.lang.rust` → `stoa.hier.comp`
- `comp.os.linux` → `stoa.hier.comp` (same topic as above)
- `sci.math` → `stoa.hier.sci`
- `alt.test` → `stoa.hier.alt`
- `local` (no dots) → `stoa.hier.local`

Peers subscribe to one topic per hierarchy.  In-topic filtering by `group_name`
is the responsibility of the receiving peer.

### Topic Hash

libp2p gossipsub uses identity hashing for `IdentTopic` (the raw topic string
is the hash).  All `stoa.hier.*` topics use `IdentTopic`.

---

## 11. Worked Examples

### Example 1: Minimal Text Article

This example shows the complete pipeline for a minimal `text/plain` article
with no `Content-Type` header.

**Article wire content:**

```
From: alice@news.example.com
Date: Mon, 01 Jan 2024 00:00:00 +0000
Message-ID: <hello-001@news.example.com>
Newsgroups: comp.lang.rust
Subject: Hello, Rust Usenet!
Path: news.example.com!alice

This is the body of the article.
It has two lines.
```

**Step 1: Canonical bytes**

Construct the canonical byte string per §3:

```
From: alice@news.example.com\r\n
Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n
Message-ID: <hello-001@news.example.com>\r\n
Newsgroups: comp.lang.rust\r\n
Subject: Hello, Rust Usenet!\r\n
Path: news.example.com!alice\r\n
\x00\n
This is the body of the article.\r\n
It has two lines.\r\n
```

(No extra headers, so no extra header lines appear.)

**Step 2: Canonical article CID**

`sha256(canonical_bytes)` → 32-byte digest.  Encode as CIDv1 RAW
(`0x01 || 0x55 || 0x12 || 0x20 || digest`).  This CID is stored in the
`message_id → CID` mapping table.

**Step 3: Raw blocks**

- `header_cid`: SHA2-256 of the verbatim header bytes (all lines including
  their CRLFs, no blank line at end), wrapped as CIDv1 RAW.
- `body_cid`: SHA2-256 of the verbatim body bytes, wrapped as CIDv1 RAW.

**Step 4: MIME node**

No `Content-Type` header is present.  `parse_mime` returns `None`.
`mime_cid` in the root node is `null`.

**Step 5: ArticleMetadata values**

```
message_id:           "<hello-001@news.example.com>"
newsgroups:           ["comp.lang.rust"]
hlc_timestamp:        1704067200000   (2024-01-01T00:00:00Z in ms)
operator_signature:   []              (empty until l62.2.6)
byte_count:           (header_bytes.len()) + (body_bytes.len())
line_count:           2               (two \n characters in body)
content_type_summary: "text/plain"    (default; no Content-Type header)
```

**Step 6: ArticleRootNode DAG-CBOR**

The root node is serialized to DAG-CBOR as a map with fields in this order:
`schema_version (1)`, `header_cid`, `header_map_cid`, `body_cid`,
`mime_cid (null)`, `metadata (inline map)`.

**Step 7: Root CID**

`root_cid` = SHA2-256 of the DAG-CBOR bytes, wrapped as CIDv1 DAG-CBOR
(codec `0x71`).  This CID is the stable IPFS address of the article and is
what appears in `LogEntry.article_cid`.

---

### Example 2: Quoted-Printable Article with Multiple Newsgroups

This example shows canonicalization with multiple newsgroups and MIME decoding.

**Article wire content:**

```
From: bob@news.example.com
Date: Tue, 02 Jan 2024 12:00:00 +0000
Message-ID: <qp-002@news.example.com>
Newsgroups: sci.math,comp.lang.rust
Subject: A café article
Path: news.example.com!bob
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

caf=C3=A9
```

**Newsgroups canonicalization:**

The two groups are sorted lexicographically: `comp.lang.rust` < `sci.math`.
The canonical `Newsgroups` line is:

```
Newsgroups: comp.lang.rust,sci.math\r\n
```

(Even though the wire `Newsgroups` header listed `sci.math` first.)

**Canonical bytes excerpt:**

```
From: bob@news.example.com\r\n
Date: Tue, 02 Jan 2024 12:00:00 +0000\r\n
Message-ID: <qp-002@news.example.com>\r\n
Newsgroups: comp.lang.rust,sci.math\r\n
Subject: A café article\r\n
Path: news.example.com!bob\r\n
Content-Type: text/plain; charset=utf-8\r\n
Content-Transfer-Encoding: quoted-printable\r\n
\x00\n
caf=C3=A9\r\n
```

Note: `Content-Type` and `Content-Transfer-Encoding` are extra headers (not
among the six mandatory headers), so they appear after `Path`, sorted
lexicographically by header name: `Content-Transfer-Encoding` < `Content-Type`.

**MIME node:**

The QP-encoded body `caf=C3=A9\r\n` decodes to `caf\xc3\xa9\r\n` (UTF-8 for
"café").

- `body_cid`: SHA2-256 of the wire bytes `caf=C3=A9\r\n` (RAW codec).
- `decoded_cid` in `SinglePartMime`: SHA2-256 of `caf\xc3\xa9\r\n` (RAW codec).
  These are different CIDs because the wire bytes differ from the decoded bytes.

`ArticleMetadata.content_type_summary` = `"text/plain"` (parameters stripped).

**ArticleMetadata.newsgroups:**

Stored in lexicographic order: `["comp.lang.rust", "sci.math"]`.

---

### Example 3: Tip Advertisement

A node that has just ingested an article for `comp.lang.rust` with root CID
`bafyreihv47lkxiaysp7lcdvimct2bdreounj2jtzgj5pn7yabkfxzanlci` broadcasts
the following tip advertisement on topic `stoa.hier.comp`:

```json
{
  "group_name": "comp.lang.rust",
  "tip_cids": [
    "bafyreihv47lkxiaysp7lcdvimct2bdreounj2jtzgj5pn7yabkfxzanlci"
  ],
  "hlc_ms": 1704067200000,
  "hlc_logical": 0,
  "hlc_node_id": "0102030405060708",
  "sender_peer_id": "12D3KooWExamplePeerIdStringHere"
}
```

A peer subscribed to `stoa.hier.comp` receives this message, checks its
local log storage for `comp.lang.rust`, and if the `tip_cids` entry is unknown,
initiates CRDT reconciliation to fetch the missing log entry and its article
block.

---

## Appendix: Encoding Constants

| Constant             | Value  | Meaning |
|----------------------|--------|---------|
| DAG-CBOR codec       | `0x71` | IPLD codec for article root nodes and MIME nodes |
| RAW codec            | `0x55` | IPLD codec for raw byte blocks |
| SHA2-256 fn code     | `0x12` | Multihash function identifier |
| SHA2-256 digest size | `0x20` | 32 bytes |
| Schema version       | `1`    | `ArticleRootNode.schema_version` |
| Max Message-ID bytes | `998`  | RFC 5322 §2.1.1 |
| Max header value     | `998`  | RFC 5322 §2.1.1, per field |
| Default max body     | `1 MiB`| `ValidationConfig::default()` |

---

## 12. NNTP CID Extension Protocol

These extensions are implemented in `stoa-reader`. They are purely
additive: a standard newsreader that never sends an `X` command and never
reads `X-Stoa-*` headers sees zero behaviour change. All five are
advertised in the `CAPABILITIES` response.

All CID values in extension responses and headers use multibase base32upper
(`b`-prefixed) CIDv1 string encoding as defined in §1.

---

### 12.1 `X-Stoa-CID` Header

Injected into `ARTICLE` and `HEAD` responses. Value is the canonical article
CID stored in the `msgid_map` table (RAW codec `0x55`, SHA-256 of the
canonical bytes defined in §3).

**Wire format:**

```
X-Stoa-CID: <cidv1-base32upper-string>
```

Rules:

- Present whenever the article's CID is in the `msgid_map` table.
- Absent for articles ingested via legacy import paths that did not record a CID.
- The header is injected at the reader session layer during response
  serialisation; it is **not** stored in the raw header block in IPFS.
- The value is the canonical article CID (RAW codec `0x55`), not the IPFS DAG
  root CID (DAG-CBOR `0x71`). Use `X-Stoa-Root-CID` (§12.2) for the DAG root.

---

### 12.2 `X-Stoa-Root-CID` Header

Injected into `ARTICLE` and `HEAD` responses for articles stored as multi-block
IPLD DAGs. Absent for all v1 single-block text articles.

**Wire format:**

```
X-Stoa-Root-CID: <cidv1-base32upper-string>
```

Rules:

- **Absent** for all v1 text articles (single-block storage; root CID equals
  canonical CID, so the header would be redundant).
- **Present** in v2+ when the article is a DAG root (DAG-CBOR CIDv1, codec
  `0x71`) that links to multiple content blocks per §4.
- When present, the value is IPLD-traversable to all content blocks via
  `ArticleRootNode` links.

---

### 12.3 `XCID` Command

Returns the CID for the current article or a named article. Per RFC 3977
§7.2, `X`-prefixed commands are experimental; clients must confirm the
`XCID` keyword in `CAPABILITIES` before sending.

**Syntax:**

```
XCID [<message-id>]
```

- **No argument:** returns the CID of the current article (requires a group
  selected and a current article pointer set by a prior `ARTICLE`, `HEAD`,
  `BODY`, or `STAT`).
- **With `<message-id>`** (angle-bracket form): returns the CID for the named
  article regardless of current group context.

**Responses:**

| Code | Meaning |
|------|---------|
| `290 <cid>` | CID found; CIDv1 base32upper string follows the space on the same line. |
| `412` | No newsgroup selected (no-argument form only). |
| `423` | No current article (no-argument form; group selected but no current article pointer). |
| `430` | No article with that message-id (message-id form). |
| `501` | Syntax error (argument present but not a valid angle-bracket message-id). |

Example:

```
C: GROUP comp.lang.rust
S: 211 42 1 42 comp.lang.rust
C: ARTICLE 1
S: 220 1 <hello@example.com> Article follows
S: (headers and body)
S: .
C: XCID
S: 290 bafkreiexamplecidstringhere...
```

**`CAPABILITIES` keyword:** `XCID`

---

### 12.4 `XVERIFY` Command

Verifies that this server holds an article with the given message-id and that
its stored CID matches the supplied expected CID. Optionally re-verifies the
operator ed25519 signature.

**Syntax:**

```
XVERIFY <message-id> <expected-cid> [SIG]
```

- `<message-id>`: angle-bracket form (e.g. `<foo@example.com>`).
- `<expected-cid>`: CIDv1 base32upper string to compare against.
- `SIG` (optional keyword, literal): if present, additionally re-verifies
  the operator ed25519 signature over the article's canonical bytes.

**Verification procedure:**

1. Look up `<message-id>` in `msgid_map`; if not found → `541`.
2. Compare stored CID to `<expected-cid>`; if mismatch → `541`.
3. Fetch block bytes from IPFS, re-derive SHA-256 CIDv1 RAW independently of
   the stored CID; if the re-derived CID does not match the stored CID → `541`
   (local storage corruption indicator).
4. If `SIG` keyword is present: deserialize canonical bytes from the block,
   call `core::signing::verify()` with the operator's public key; if the
   signature fails → `542`.
5. All checks passed → `291`.

Step 3 is an independent recomputation — it reads raw block bytes and hashes
from scratch, making it a genuine integrity check rather than a metadata lookup.

**Responses:**

| Code | Meaning |
|------|---------|
| `291 Verified` | All requested checks passed. |
| `501` | Syntax error (malformed message-id or CID string, or unknown keyword). |
| `541 Not found or CID mismatch` | Article not found in `msgid_map`, stored CID differs from `expected-cid`, or local block re-hash failed. |
| `542 Signature verification failed` | CID verified, but the ed25519 signature is invalid (only possible when `SIG` is specified). |

**`CAPABILITIES` keyword:** `XVERIFY`

---

### 12.5 `ARTICLE cid:` Locator Form

The `ARTICLE`, `HEAD`, and `BODY` commands accept a `cid:` prefixed locator as
an alternative to the `<message-id>` (angle-bracket) form and article number
(integer) form.

**Syntax:**

```
ARTICLE cid:<cidv1-string>
HEAD    cid:<cidv1-string>
BODY    cid:<cidv1-string>
```

The `cid:` prefix (case-insensitive) is unambiguous: message-ids start with
`<`, article numbers are integers, and neither can start with `cid:`.

Lookup procedure:

1. Strip the `cid:` prefix; attempt to parse the remainder as a CIDv1 string.
   If parsing fails → `501`.
2. Look up the CID directly in the IPFS block store (bypasses `msgid_map`).
   If not found → `430`.
3. Reconstruct the article from the block; return `220` / `221` / `222` as
   for the standard command form.

An article returned via `cid:` locator may or may not appear in `msgid_map`
(e.g. an article fetched from a peer but not yet indexed returns successfully
via its CID).

**Response codes:** same as the standard `ARTICLE` (`220`), `HEAD` (`221`),
and `BODY` (`222`) forms on success. `430` for unknown CID. `501` for
malformed CID string.

**`CAPABILITIES` keyword:** `X-CID-LOCATOR`

---

### 12.6 `CAPABILITIES` Advertisement

The reader advertises all five extensions in `CAPABILITIES`. A client SHOULD
check `CAPABILITIES` before sending any `X` command or before relying on
`X-Stoa-*` headers.

```
101 Capability list:
VERSION 2
READER
IHAVE
POST
HDR
LIST ACTIVE NEWSGROUPS OVERVIEW.FMT
OVER
MODE-READER
XCID
XVERIFY
X-CID-LOCATOR
STARTTLS
.
```

Standard newsreaders that do not inspect `CAPABILITIES` for these keywords
and never send `XCID` or `XVERIFY` see no change in behaviour.
