# ADR-0001: ed25519-dalek for Operator Signing

## Status
Accepted

## Context

Every article written to IPFS must be signed by an operator key before the IPFS
write commits and before the group log entry is appended. The signature field
travels inside both the `ArticleRootNode` metadata and the `LogEntry`, so the
choice of signing library affects the canonical serialization format and the
dependency surface of `usenet-ipfs-core`.

Three options were evaluated:

- **ed25519-dalek** — pure-Rust Ed25519 implementation maintained under the
  RustCrypto umbrella. Implements the `signature` crate traits. No unsafe
  outside the backend arithmetic (which is behind the `zeroize` feature wall).
  Audited. Stable API since 2.x.

- **ring** — Google's BoringSSL-backed Rust binding. Fast and well-hardened, but
  uses `unsafe` throughout, requires a C toolchain, and does not implement the
  `signature` crate trait abstractions. Cross-compilation to unusual targets is
  harder.

- **RustCrypto/ed25519** — the trait crate only (`ed25519` crate, no
  implementation). Requires pairing with a backend (`ed25519-dalek` or
  `ed25519-compact`). Using this at the call sites adds an indirection layer
  without a benefit when only one backend is needed in v1.

Hardware security module (HSM) or PKCS#11 key storage was considered but
deferred: it requires a separate integration layer that adds significant
operational complexity for a v1 system where the threat model is accidental key
exposure, not targeted hardware extraction.

## Decision

Use `ed25519-dalek` as the sole signing implementation in `usenet-ipfs-core`.
The `SigningKey` and `Signature` types from `ed25519-dalek` are the canonical
types throughout the codebase. The signing key is loaded from disk at startup,
held in memory, and never written to any log statement or error message.

## Consequences

- Pure-Rust, no C toolchain dependency. Cross-compilation and static linking
  are straightforward.
- `ed25519-dalek` is independently audited. The audit covers the arithmetic
  backend (curve25519-dalek) as well as the signing API.
- The `signature` crate trait bound is satisfied, so future key source
  abstractions (e.g. wrapping a PKCS#11 token) can substitute without changing
  call sites.
- No hardware token support in v1. Key rotation is supported via the operator
  CLI (`cli/key_rotate.rs`), which replaces the on-disk key file; old signatures
  remain valid because they are stored in the log.
- Zeroization of key material on drop requires the `zeroize` feature, which must
  be enabled explicitly in `Cargo.toml`.
