# ADR-0011: secretx Abstraction for Operator Secrets

**Status:** Accepted
**Date:** 2026-04-29

---

## Context

`stoa-transit`, `stoa-reader`, and `stoa-smtp` each handle at least one secret
value at startup: the operator signing key, TLS private key, SMTP credential
password, or database connection string. These secrets must not be hardcoded in
config files checked into source control.

Operators run stoa in different environments with different secret management
infrastructure: some use environment variables or a secrets file on a locked
filesystem, others use AWS Secrets Manager, Azure Key Vault, or GCP Secret
Manager.

The simplest approach — reading a secret from an environment variable or file
path — satisfies local development and simple deployments. However, hardcoding
the read mechanism forces a recompile to change the backend, and it duplicates
boilerplate across the three daemons.

---

## Decision

All secrets are referenced via `secretx` URI strings (e.g. `env:MY_SECRET`,
`file:/run/secrets/signing_key`, `aws-sm:arn:aws:secretsmanager:...`).

`secretx` 0.3.1 provides:
- `env:` and `file:` backends, always compiled in (zero additional dependencies)
- `aws-sm:` / `aws-ssm:` backends, gated behind the `aws` Cargo feature
- `azure-kv:` backend, gated behind the `azure` Cargo feature
- `gcp-sm:` backend, gated behind the `gcp` Cargo feature

Each binary enables only the cloud features it is built with. A minimal
deployment that uses only env/file secrets has no cloud SDK in its dependency
tree.

Secrets are resolved at daemon startup via `secretx::from_uri(uri)?.get().await`.
If resolution fails, the daemon exits non-zero before accepting any connections
(fail-fast startup). Secrets are never logged.

---

## Consequences

- Operators can change the secret backend without recompiling by updating the
  URI string in the config file and rebuilding with the appropriate Cargo
  feature enabled.
- The `env:` and `file:` backends add no dependencies. Cloud backends are
  opt-in at compile time, keeping binary size small for operators who do not
  need them.
- All three daemons share the same URI syntax. Operators who run all three
  can use a single secret store with a consistent naming scheme.
- A duplicate `resolve_secret_uri` helper exists in `transit/main.rs` and
  `reader/main.rs`; this is tracked as a known maintenance liability in
  usenet-ipfs-u02k.2 and will be consolidated in usenet-ipfs-aubi.
