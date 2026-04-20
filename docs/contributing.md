# Contributing to usenet-ipfs

## Prerequisites

Install these before doing anything else.

**Rust (stable, via rustup)**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

The repository has a `rust-toolchain.toml` that pins the stable channel with `rustfmt` and `clippy` components. `rustup` picks this up automatically — you do not need to set a toolchain manually.

**just** — task runner used for all development commands:

```bash
cargo install just
```

**cargo-nextest** — faster parallel test runner (optional but recommended):

```bash
cargo install cargo-nextest
```

**SQLite3** — for inspecting local state databases during development:

```bash
# Debian/Ubuntu
sudo apt install sqlite3
```

**Kubo (go-ipfs)** — required for integration tests that talk to a live IPFS node:

```bash
# https://docs.ipfs.tech/install/command-line/
# Verify:
ipfs version
```

Unit tests do not require a running IPFS node. Integration tests do; they expect `ipfs` on `PATH` and the daemon reachable at the default API address.

---

## Getting Started

```bash
git clone <repo-url>
cd usenet-ipfs

just build      # cargo build --workspace
just test       # cargo test --workspace
just lint       # cargo fmt --check + cargo clippy -D warnings
```

Other useful commands:

```bash
just nextest    # faster parallel test run via cargo-nextest
just check      # compilation check without linking (quick feedback loop)
just fmt        # auto-fix formatting in place
just doc        # build and open rustdoc
just key        # generate a test Ed25519 operator key in /tmp/
just bench      # run benchmarks (see Benchmarks section below)
just --list     # print all available recipes
```

---

## Project Structure

```
crates/
  core/       usenet-ipfs-core  — shared types and logic (rlib)
  transit/    usenet-ipfs-transit — NNTP peering daemon (binary)
  reader/     usenet-ipfs-reader  — RFC 3977 reader server (binary)
spikes/       library benchmark results (iroh, rust-ipfs, libp2p)
docs/         design and process documents
```

**`usenet-ipfs-core`** owns: article IPLD schema, CID derivation, canonical serialization, group log (Merkle-CRDT), Ed25519 signing, `message_id` validation, and all shared error types. The other crates import error types and domain types from here; they do not define their own.

**`usenet-ipfs-transit`** is the peering daemon. It speaks NNTP to other transit servers, runs the gossipsub peer mesh, manages the pinning policy, and drives GC.

**`usenet-ipfs-reader`** is the RFC 3977 server that newsreader clients connect to (`slrn`, `tin`, Thunderbird, etc.). It synthesizes local article numbers, maintains the overview index, and handles `POST`.

---

## Coding Conventions

**Async runtime:** `tokio` throughout. No blocking I/O on the main task pool — use `tokio::task::spawn_blocking` if you must call a blocking API.

**Local state:** `sqlx` + SQLite. All SQL lives in dedicated `store` modules. Do not scatter queries through business logic.

**Signing:** `ed25519-dalek`. This is a fixed dependency choice; do not swap it.

**IPLD codec:** DAG-CBOR (codec `0x71`), implemented with `serde_ipld_dagcbor` 0.6. This is irreversible once articles are in IPFS and referenced in group logs.

**Gossipsub topic naming:** `usenet.hier.<hierarchy>` — for example, `usenet.hier.comp`. Topics are per-hierarchy, not per-group. Filter by group name inside the topic handler.

**Canonical serialization:** RFC 8785 canonical JSON for any object that is signed or hashed. Rules: sorted keys, NFKC normalization, UTC timestamps with `Z` suffix, no whitespace, no trailing zeros in fractional seconds.

**No `unsafe`** outside FFI boundary crates. If you believe you need `unsafe`, stop and raise it for review before writing it.

**Cargo features must be additive.** Never unconditionally enable an algorithm or capability in `Cargo.toml`.

**Rust edition 2021, resolver v2.** Do not downgrade either.

**Article numbers are local and synthetic.** Never use a local article number as a network-stable identifier or CID pointer.

**NNTP client compatibility is non-negotiable.** The reader server must work with unmodified `slrn`, `tin`, `pan`, `gnus`, and Thunderbird. No custom extensions that expose CIDs or IPFS internals to clients.

---

## Test Requirements

**Never modify, skip, or weaken a failing test to make it pass. Fix the code.**

Tests must have an independent oracle — not the code under test itself:

- For IPLD/CID correctness: cross-validate against a reference implementation (Python `canonicaljson`, `js-dag-json`, or equivalent). Do not assert round-trip through your own encoder/decoder as a proof of correctness.
- For canonical serialization: derive test vectors from an external tool (e.g. Python `canonicaljson` library) once, hardcode them, and compare byte-for-byte.
- For RFC 3977 conformance: use real unmodified newsreader clients against a live reader process. Do not mock the NNTP client.

`just test` (or `cargo test --workspace`) must be green before opening a PR.

---

## Submitting a PR

1. **File a Beads issue first.**

   ```bash
   bd create          # create an issue
   bd update <id> --claim   # claim it before starting work
   ```

   Work one issue at a time. Large features should be broken into a Beads epic with child issues.

2. **Write your code.** Follow the conventions above.

3. **Run the full gate locally** before pushing:

   ```bash
   just fmt           # fix formatting
   just lint          # fmt check + clippy -D warnings
   just test          # full test suite
   ```

4. **Commit message format:** conventional commits, subject line under 50 characters.

   ```
   feat: add ARTICLE command handler
   fix: reject message-id with bare LF
   refactor: extract store module from reader
   ```

   No `Co-Authored-By: Claude` lines. No "Generated with" footers.

5. **Open the PR.** CI runs: build (stable + MSRV 1.80), test, fmt check, clippy, and `cargo deny`. All jobs must pass.

6. **Close the Beads issue** once the PR merges:

   ```bash
   bd close <id>
   ```

---

## Benchmarks

The `spikes/` directory contains the results of the IPFS client library benchmarks that informed the `rust-ipfs` selection. Those are read-only records.

For ongoing performance work:

```bash
just bench    # cargo bench --workspace
```

Benchmark results are not part of CI. Run them locally when working on performance-sensitive code paths.

---

## Releasing

See [docs/release_process.md](release_process.md) for the release workflow.
