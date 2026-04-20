# Test Writing Guide — usenet-ipfs

This guide documents how tests are written, organised, and validated in this
codebase. Read it before adding a test. The oracle policy in section 1 is the
most important part; everything else is secondary.

---

## 1. Test Oracle Policy

**A test that uses the code under test as its own oracle proves nothing.**

The canonical failure mode: call `build_article`, serialise the result with
`serde_ipld_dagcbor`, compute a CID, then assert that CID equals the CID
returned by `build_article`. If the serialisation has a bug, both sides of the
assertion carry that bug and the test passes anyway. This is not a test; it is
a tautology.

Every assertion about a computed value must be checked against an oracle that
is independent of this codebase.

### Acceptable oracles

**External reference implementation (strongest)**

Compute the expected value with a tool or library that has no code shared with
this repo. Hardcode the result as a literal constant. The test then asserts
that the code under test reproduces that literal.

Examples used in this codebase:

- RAW-codec CIDs (SHA-256 over header or body bytes): computed with Python
  `hashlib.sha256(data).digest()`, then converted to CIDv1 base32 with
  `cid.CIDv1("raw", multihash.encode(digest, "sha2-256")).encode("base32")`.
  The resulting string is pasted in as a `const &str` with a comment naming
  the oracle tool and the exact Python expression used.

- RFC section numbers: response codes for NNTP commands (238, 439, 435, etc.)
  are specified in the RFC. The RFC is the oracle. Comments cite the exact
  section (`RFC 4644 §2.3`).

**Stability oracle (acceptable for compound serialisation)**

When the output is a deterministic but complex composite structure (a DAG-CBOR
root node whose CID depends on the encoding of nested IPLD links), run the
code once with a known-correct implementation, record the output as a
hardcoded constant, and assert it thereafter.

A stability oracle does not validate that the first recorded value was correct
— that must be verified separately (e.g. by checking the constituent RAW CIDs
against the external oracle first, then inspecting the root CID with `ipfs
dag get`). Its purpose is to act as a trip-wire: any future change to the
encoding or schema breaks the assertion, forcing a conscious re-recording. The
comment on a stability constant must say exactly that.

Example from `crates/core/src/ipld/test_vectors.rs`:

```rust
/// Oracle: stability value recorded from `build_article` on first run.
/// Any change here means the DAG-CBOR encoding or ArticleRootNode schema changed.
const TV1_EXPECTED_ROOT_CID: &str =
    "bafyreihv47lkxiaysp7lcdvimct2bdreounj2jtzgj5pn7yabkfxzanlci";
```

**Cross-validation between two independent implementations (acceptable)**

If two independent implementations of the same algorithm produce the same
output for a given input, that is evidence of correctness. The implementations
must share no code. Used in property tests when the invariant is structural
(commutativity, idempotency) rather than value-exact.

### What is not acceptable

- Asserting `encode(x) == encode(x)`: always true by reflexivity.
- Asserting `decode(encode(x)) == x` using the same crate for both directions:
  a roundtrip test with a single implementation.
- Deriving a test vector by running the code under test and capturing the
  output in a first run, without a separate cross-check against an external
  source for at least the leaf values.

### How test vectors are stored

Hardcode as `const` string literals in the test file. Always include a comment
explaining which tool produced the value and the exact invocation or expression.

```rust
/// Oracle: Python `hashlib.sha256(TV1_HEADER).digest()` → CIDv1 RAW base32.
/// sha256 = e89c40254f36229d6392ba53f00202cd8155140753152f20c3da0048ca98b9cc
const TV1_EXPECTED_HEADER_CID: &str =
    "bafkreihitracktzwekowhev2kpyaeawnqfkrib2tcuxsbq62abemvgfzzq";
```

Binary fixtures go in `crates/<crate>/tests/fixtures/` as committed files.
Never generate fixtures at test runtime from the code under test.

---

## 2. Test Types and When to Use Each

### Unit tests (`#[test]` in `mod tests`)

Location: inside the source file, in a `#[cfg(test)] mod tests { ... }` block.

Use for: pure functions with no I/O — validators, parsers, serialisers, CID
computation, header field parsing, group name validation, article size checks.
These tests must be fast and have zero external dependencies (no SQLite, no
IPFS, no network).

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_name_rejects_uppercase() {
        assert!(GroupName::new("Comp.lang.rust").is_err());
    }
}
```

### Integration tests (`tests/` directory)

Location: `crates/<crate>/tests/<name>.rs`.

Use for: storage operations (real SQLite, `tempfile`-backed), NNTP session
lifecycle (full ingestion pipeline), CRDT reconciliation with real storage.
These tests may use a real SQLite connection and an in-memory IPFS store but
must not require a running IPFS daemon or network access.

**SQLite isolation**: each test function creates its own temporary file using
`tempfile::NamedTempFile` and keeps the `TempPath` alive for the duration of
the test. This avoids migration races that occur with named in-memory SQLite
URIs shared across connections. Do not use `:memory:` for tests that run in
parallel.

```rust
async fn make_msgid_map() -> (MsgIdMap, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    let opts = SqliteConnectOptions::from_str(&url)
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    usenet_ipfs_core::migrations::run_migrations(&pool).await.unwrap();
    (MsgIdMap::new(pool), tmp)
}
```

The `TempPath` must be returned and bound in the caller — if it is dropped
early, the file is deleted and the pool's connections fail.

### Property-based tests (`proptest`)

Location: `crates/<crate>/tests/<name>.rs` or inline `mod tests`.

Use for: CRDT invariants (commutativity, idempotency, convergence), parser
no-panic guarantees, boundary conditions that are hard to enumerate manually.

The `proptest!` macro generates random inputs and shrinks failures to minimal
examples. Wrap async logic in `tokio::runtime::Runtime::new().unwrap().block_on(...)` inside the `proptest!` body — proptest strategies are not natively async.

```rust
use proptest::prelude::*;

fn entry_seeds() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0u8..=127u8, 0..=8).prop_map(|mut v| {
        v.sort();
        v.dedup();
        v
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn reconcile_against_self_is_empty(seeds in entry_seeds()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (want, have) = rt.block_on(async {
            // ... set up storage, insert entries, call reconcile ...
        });
        prop_assert!(want.is_empty(), "...");
        prop_assert!(have.is_empty(), "...");
    }
}
```

Tune `with_cases` conservatively: `1000` for fast purely-in-memory paths,
`500` for paths that touch SQLite, `200` for convergence simulations with many
rounds. Cases that are too high slow CI; cases that are too low miss edge cases
in shrinking.

Use `prop_assert!` and `prop_assert_eq!` (not plain `assert!`) inside
`proptest!` blocks so that failures trigger shrinking instead of panicking
immediately.

### Interop tests (live NNTP clients)

Location: `crates/reader/tests/interop/`.

Use for: RFC 3977 conformance, newsreader compatibility (`slrn`, `tin`, `pan`,
Thunderbird). These tests require an actual binary on `$PATH` and a live reader
process. They must be annotated `#[ignore]` so they are excluded from `cargo
test` and `cargo nextest run` by default.

```rust
#[tokio::test]
#[ignore = "requires slrn on PATH and NNTP_INTEROP=1"]
async fn slrn_can_fetch_article() {
    // ...
}
```

Run them explicitly:

```bash
NNTP_INTEROP=1 cargo test --test interop -- --ignored
```

RFC 3977 conformance must not be tested with mocked clients. A mock that
returns the responses you expect does not prove that an unmodified newsreader
will behave correctly.

---

## 3. Test Vector Derivation

### CID computation (RAW codec, SHA-256)

The oracle for RAW-codec CIDs is Python `hashlib` + the `cid` and `multihash`
packages.

```python
import hashlib
import multihash
import cid as cid_lib

data = b"From: user@example.com\r\n..."  # exact bytes as in the test

digest = hashlib.sha256(data).digest()
mh = multihash.encode(digest, "sha2-256")
c = cid_lib.CIDv1("raw", mh)
print(c.encode("base32").decode())
# → bafkrei...
```

Paste the printed string into a `const &str` with a comment showing the Python
expression and the hex digest.

### CID computation (DAG-CBOR codec, root nodes)

DAG-CBOR root CIDs cannot be independently verified from the raw bytes alone
because their value depends on the exact CBOR encoding of the `ArticleRootNode`
struct, which is defined in this codebase. The process is:

1. Verify all constituent RAW-codec CIDs against Python `hashlib` first.
2. Run `build_article` in a one-off binary or `#[test]` that prints the root
   CID.
3. Cross-check the printed CID with `ipfs dag get <cid>` against a local Kubo
   node:
   ```bash
   echo -n '<serialised dag-cbor block>' | \
     ipfs block put --cid-codec dag-cbor --mhtype sha2-256
   ```
4. Hardcode the CID as a stability constant with a comment stating it was
   recorded after this cross-check.

### Canonical JSON

Oracle: Python `canonicaljson` (implements RFC 8785).

```python
import canonicaljson
obj = {"newsgroups": ["comp.lang.rust"], "message_id": "<x@y.com>"}
print(canonicaljson.encode_canonical_json(obj))
# → b'{"message_id":"<x@y.com>","newsgroups":["comp.lang.rust"]}'
```

Use this to verify that the Rust canonical serialisation produces identical
bytes before signing or hashing.

### ed25519 signatures

Oracle: Python `cryptography` library.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import binascii

key_bytes = bytes([0x42] * 32)
key = Ed25519PrivateKey.from_private_bytes(key_bytes)
msg = b"message to sign"
sig = key.sign(msg)
print(binascii.hexlify(sig).decode())
# → <64-byte hex>
```

Hardcode the signature as a `hex!("...")` literal (from the `hex-literal`
crate). Tests that verify signing must use the same fixed key seed and message,
not generate a fresh key at test time.

---

## 4. Writing a New NNTP Conformance Test

Worked example: assert that `GROUP` on an unknown group returns `411`.

RFC 3977 §6.1.1 specifies: "If the group specified is not available on the
server, the response code 411 must be returned."

```rust
//! Integration test: GROUP command returns 411 for unknown groups.
//!
//! Oracle: RFC 3977 §6.1.1 — unknown group → 411.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Spawn the reader server on an ephemeral port and return its address.
/// (Replace with the actual helper once the reader crate exposes one.)
async fn start_reader() -> std::net::SocketAddr {
    // ... bind to 127.0.0.1:0, run server task, return bound address
    todo!("wire up to the real server startup helper")
}

#[tokio::test]
async fn group_unknown_returns_411() {
    let addr = start_reader().await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // Consume the greeting.
    let greeting = lines.next_line().await.unwrap().unwrap();
    assert!(greeting.starts_with("200") || greeting.starts_with("201"),
        "expected 200/201 greeting, got: {greeting:?}");

    // Send GROUP for a group that does not exist.
    writer.write_all(b"GROUP no.such.group\r\n").await.unwrap();

    let response = lines.next_line().await.unwrap().unwrap();
    assert!(
        response.starts_with("411"),
        "GROUP on unknown group must return 411 (RFC 3977 §6.1.1), got: {response:?}"
    );
}
```

Notes:

- Connect with `tokio::net::TcpStream`, not a mock. The point is to exercise
  the full read loop, command dispatch, and response formatter.
- Consume the greeting before issuing commands. Servers may send a multiline
  greeting in some configurations.
- Assert with `starts_with("NNN")`, not `==`. Response lines may carry
  free-text after the code.
- Cite the RFC section in the assertion message.

### Testing CID Extensions

The five NNTP CID extensions each have distinct test concerns:

**`X-Usenet-IPFS-CID` header** — POST an article, then `ARTICLE <msgid>`.
Assert the header is present in the response, parse the CID string, and
cross-validate it against the Python oracle:

```python
# Oracle: recompute CID from canonical bytes independently.
import hashlib, multihash, cid as cid_lib
digest = hashlib.sha256(canonical_bytes).digest()
mh = multihash.encode(digest, "sha2-256")
expected = cid_lib.CIDv1("raw", mh).encode("base32").decode()
assert header_value == expected
```

**`XCID` command** — confirm `XCID` appears in `CAPABILITIES`, then select a
group, `STAT` to an article, send `XCID` with no argument, assert `290`. Send
`XCID <msgid>` without selecting a group, assert `290`. Assert the CID value
matches the one from `X-Usenet-IPFS-CID` header for the same article.

**`XVERIFY` command** — assert `291` when correct CID supplied, `541` when CID
is wrong, `541` when message-id is unknown, and `542` when `SIG` is appended
and the article has a valid CID but the signature test is forced to fail (if
testable via a test signing key). Cite RFC 3977 §7.2 in comments.

**`ARTICLE cid:` locator** — confirm `X-CID-LOCATOR` in `CAPABILITIES`. POST
an article, capture its CID from the `X-Usenet-IPFS-CID` header. Then send
`ARTICLE cid:<that-cid>` and assert `220`. Assert `430` for an unknown CID.
Assert `501` for `ARTICLE cid:notacid`.

**`X-Usenet-IPFS-Root-CID` header** — assert the header is **absent** for all
v1 single-block text articles (its presence for single-block articles would be
a bug). This header is only present for future multi-block DAG articles.

For all extension tests: connect with `tokio::net::TcpStream` against a live
reader process (same as other conformance tests). Do not mock the server.
Assert response codes with `starts_with("NNN")`, not exact equality.

---

## 5. Async Test Patterns

### Basic async test

```rust
#[tokio::test]
async fn example() {
    let result = some_async_fn().await;
    assert!(result.is_ok());
}
```

### Async inside proptest

`proptest!` is synchronous. Use a one-shot runtime:

```rust
proptest! {
    #[test]
    fn my_property(seed in 0u8..=127u8) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            // async work here
        });
        prop_assert!(result);
    }
}
```

Do not share a `Runtime` across proptest cases — create a fresh one per case.
The overhead is acceptable for the case counts used in this codebase.

### SQLite isolation

Each test that touches SQLite must create its own temporary file. Hold the
`TempPath` in a binding for the duration of the test:

```rust
let (store, _tmp) = make_msgid_map().await;
// _tmp must not be dropped until the test is done
```

If you name the binding `_` (not `_tmp`), it is dropped immediately at the
`let` statement. That deletes the file and breaks the pool. Always use a
named binding with a leading underscore.

### Sleeping

Never use `std::thread::sleep` in async tests — it blocks the tokio thread
pool. Use `tokio::time::sleep` when a deliberate delay is needed (rare in unit
and integration tests; avoid if possible).

---

## 6. Running Tests

```bash
# Full test suite
cargo test --workspace

# Parallel runner (faster, better output)
cargo nextest run --workspace

# Verbose logging
RUST_LOG=debug cargo test

# A single integration test file
cargo test --test rfc4644_streaming

# Run proptest with a higher case count (override for local exploration)
PROPTEST_CASES=5000 cargo test --test crdt_properties

# Interop tests (requires live clients and NNTP_INTEROP=1)
NNTP_INTEROP=1 cargo test --test interop -- --include-ignored
```

### Tests that require a running IPFS daemon

Tests that call into a real `rust-ipfs` node must be annotated `#[ignore]` and
gated on an environment variable:

```rust
#[tokio::test]
#[ignore = "requires running IPFS daemon; set IPFS_TEST=1"]
async fn stores_block_in_ipfs() {
    if std::env::var("IPFS_TEST").is_err() {
        return;
    }
    // ...
}
```

Run them with:

```bash
IPFS_TEST=1 cargo nextest run --workspace --include-ignored
```

These tests must never run in CI unless the CI environment explicitly provisions
a daemon. Mark them `#[ignore]` unconditionally; the env var is a secondary
guard against accidental execution.

---

## 7. Checklist Before Committing a New Test

- [ ] Every asserted value has an independent oracle identified in a comment.
- [ ] No roundtrip-only assertions using the code under test on both sides.
- [ ] SQLite tests use `tempfile::NamedTempFile`, not `:memory:`.
- [ ] Async tests use `#[tokio::test]` or a one-shot `Runtime` inside proptest.
- [ ] `std::thread::sleep` does not appear; `tokio::time::sleep` used instead.
- [ ] Tests requiring external processes or daemons are annotated `#[ignore]`.
- [ ] `prop_assert!` / `prop_assert_eq!` used inside `proptest!` blocks, not
  bare `assert!`.
- [ ] No test modifies, skips, or weakens an existing assertion to achieve a
  pass. If the code is wrong, fix the code.
