# ADR-0010: Native MIT Sieve Evaluator Isolates AGPL Dependency

**Status:** Accepted
**Date:** 2026-04-29

---

## Context

Sieve (RFC 5228) filtering is needed in the SMTP submission path to allow
operators to route, reject, and file inbound mail. The Rust ecosystem has one
production-quality Sieve implementation: `sieve-rs` 0.7, which is licensed
AGPL-3.0-only.

`stoa-smtp` is MIT-licensed. Linking an AGPL library into an MIT binary imposes
AGPL obligations on the combined work. For an operator who embeds stoa in a
proprietary product, this is a hard blocker.

Three options were considered:

1. **Link `sieve-rs` directly into `stoa-smtp`.** Simple; full Sieve coverage
   immediately. Imposes AGPL on `stoa-smtp` and on any binary that links it.
   Rejected: conflicts with the MIT license goal for production binaries.

2. **Subprocess isolation.** Run a separate `stoa-sieve` process (AGPL) and
   communicate over a local socket or stdio. The MIT binary does not link the
   AGPL code. Viable, but adds IPC latency, a separate process lifecycle to
   manage, serialization overhead, and deployment complexity.

3. **Native MIT re-implementation.** Implement the Sieve subset needed by stoa
   (`fileinto`, `reject`, `keep`, `discard`, `address`, `header`, `size`,
   `allof`, `anyof`, `not`) natively in `stoa-sieve-native` (MIT), and use
   `stoa-sieve` (AGPL) only as a cross-validation oracle in tests.

---

## Decision

`stoa-sieve-native` is a native Sieve evaluator (MIT-licensed) that implements
the RFC 5228 subset required by the SMTP submission path. It uses
`fancy-regex` for glob pattern matching and is cross-validated against the
`stoa-sieve` oracle (which wraps `sieve-rs` 0.7, AGPL-3.0-only).

`stoa-sieve` (the AGPL wrapper) remains in the workspace as a test oracle and
for operators who want full Sieve coverage and accept the AGPL obligations, but
it is **never linked by any production binary**. The `stoa-smtp` binary depends
only on `stoa-sieve-native`.

Divergences between `stoa-sieve-native` and the `sieve-rs` oracle are
documented in `evaluator.rs` with RFC section citations. The cross-validation
test suite (`sieve-native/tests/cross_validate.rs`) catches regressions.

---

## Consequences

- `stoa-smtp` is MIT-licensed end-to-end. No AGPL obligations for operators of
  production binaries.
- The native evaluator covers the Sieve subset needed for SMTP routing and
  filtering. Full RFC 5228 edge cases not covered by the subset are documented
  as out of scope.
- `fancy-regex` is pinned in `stoa-sieve-native/Cargo.toml`. Upgrades require
  running the glob test suite and cross-validating against `stoa-sieve`.
- The AGPL boundary is enforced by workspace structure: no production binary's
  dependency graph reaches `stoa-sieve`. Verified by `cargo deny` in CI.
