# Spike: Admin HTTP Endpoint Authentication Options

**Status:** Decision reached — see Recommendation
**Date:** 2026-04-19
**Scope:** `usenet-ipfs-transit` admin HTTP endpoint (`[admin]` in config.toml)

---

## Background

The transit daemon exposes an admin HTTP endpoint (default `127.0.0.1:9090`) serving:

- `GET /metrics` — Prometheus scrape target
- `GET /log-tip` — operator diagnostic endpoint

The current `AdminConfig` in `crates/transit/src/config.rs` has two fields:

```rust
pub struct AdminConfig {
    pub addr: String,           // default "127.0.0.1:9090"
    pub allow_non_loopback: bool,
}
```

`check_admin_addr` emits a startup warning when the bind address is non-loopback and
`allow_non_loopback` is not set. This is a deterrent, not enforcement. There is currently
no authentication.

The loopback default is safe for single-host deployments where the Prometheus scraper
runs on the same machine. The question is what to implement when the endpoint must be
reachable remotely.

---

## Option 1: Bearer Token (static secret in config)

### How it works

A random 32-byte token (hex or base64-encoded) is set in `config.toml`. The server
requires every request to carry `Authorization: Bearer <token>`. Requests without a
valid token get `401 Unauthorized`. Token comparison uses constant-time equality to
avoid timing oracles.

The token can alternatively be a keyed HMAC-SHA256 tag over a fixed message if the
operator wants to derive it from a master secret, but a simple random token is
sufficient and easier to reason about.

### Pros

- No PKI, no certificate management, no external dependencies.
- Works out of the box with `curl -H "Authorization: Bearer <token>"` and with
  Prometheus `bearer_token` in `scrape_configs`.
- Stateless: every request is independently authenticated; no session state.
- Single axum middleware layer; no new crate dependencies beyond what is already
  in the tree.
- Token is at rest in the config file; standard `chmod 0600` on the config protects it.

### Cons

- Token rotation requires updating `config.toml` and reloading the daemon; there is
  no graceful dual-token transition window unless the implementation explicitly supports
  it.
- No per-client identity: every client with the token is indistinguishable.
- Token is a shared secret; if it leaks, all clients are compromised until rotation.
- Config file must have `0600` permissions — operator responsibility, not enforced
  by the daemon (though a startup warning is straightforward to add).

### Implementation complexity

Low. One axum `from_fn` middleware that reads the `Authorization` header, splits off
the `Bearer ` prefix, and does a constant-time comparison against the configured token.
If the token field is empty and the address is loopback, the middleware is a no-op.
If the token is empty and the address is non-loopback, the existing `check_admin_addr`
warning already fires.

### Verdict

Good default for v1. Covers the most common deployment pattern (Prometheus on a
separate host, single operator) with minimal complexity.

---

## Option 2: Mutual TLS (mTLS)

### How it works

The admin endpoint is wrapped in TLS. The server presents a certificate signed by the
operator CA. Each client (Prometheus scraper, operator shell scripts) also presents a
client certificate signed by the same CA. The server validates the client certificate
chain and rejects connections whose client cert cannot be verified.

### Pros

- Strong per-client identity: each scraper or operator tool can have its own
  certificate with a distinct CN/SAN, enabling per-client revocation.
- No shared secret: compromise of one client's private key does not expose other
  clients.
- Revocation via CRL or OCSP (if the operator runs that infrastructure).
- Well-understood security model with a large body of tooling.

### Cons

- Requires the operator to run a CA, even if it is a trivial self-signed one created
  with `openssl` or `step-ca`. This is a non-trivial operational burden for small
  deployments.
- Prometheus `scrape_configs` must be updated with `tls_config.cert_file`,
  `tls_config.key_file`, and `tls_config.ca_file`; easy to misconfigure.
- Certificate expiry adds an operational failure mode that does not exist with a
  static token.
- Implementation requires `rustls` integration (or `native-tls`), client certificate
  extraction from the TLS handshake, and certificate chain verification — materially
  more code than a middleware function.
- rustls does not expose client certificate verification via a simple axum layer;
  it requires a custom `tokio-rustls` acceptor and manual cert chain inspection.

### Implementation complexity

High. Estimated 2–4 days to implement correctly, plus operator CA setup documentation.

### Verdict

Appropriate for multi-operator or multi-tenant deployments where client identity
matters. Overkill for v1 where a single operator controls all clients. Deferred to a
future security hardening epic.

---

## Option 3: Unix Domain Socket

### How it works

The admin endpoint listens on a Unix domain socket path (e.g.,
`/run/usenet-ipfs/admin.sock`) rather than a TCP address. The OS enforces access
control via socket file permissions: `chmod 0600` owned by the operator user means
only processes running as that user (or root) can connect. No cryptographic
authentication is involved.

### Pros

- Access control is enforced by the OS kernel, not application logic.
- No secrets to manage, rotate, or leak.
- No TLS overhead; connections are local IPC.
- Natural fit for single-host deployments where the admin user is well-defined.
- `curl --unix-socket /run/usenet-ipfs/admin.sock http://localhost/metrics` works
  without any authentication headers.

### Cons

- Remote Prometheus scraping is not directly supported. Options are:
  - SSH tunnel: `ssh -L 9090:/run/usenet-ipfs/admin.sock operator@host` and scrape
    `localhost:9090` — works but requires SSH key management.
  - `node_exporter` textfile collector or a local reverse proxy: adds deployment
    complexity.
- Not portable to Windows (not a v1 concern, but worth noting).
- `addr` field in `AdminConfig` is a string formatted as `host:port`; accepting a
  socket path requires either a separate config field or a convention like
  `unix:/run/usenet-ipfs/admin.sock` that the bind logic must detect.
- axum/hyper UnixListener support requires the `tokio` feature `net` and a small
  amount of glue; it is not difficult but adds a branch to the server startup path.

### Implementation complexity

Low-to-medium. The axum routing layer is identical; only the listener differs. A
`unix:` prefix in `addr` (or a separate `socket_path` field) triggers the Unix socket
branch. Estimated half a day of implementation plus testing.

### Verdict

Excellent for local-only use. Complements bearer token well: operators who only need
local access get OS-level protection for free; operators who need remote access use
the bearer token over TCP. The two modes can coexist if desired (bind both). Suitable
for a later iteration rather than v1.

---

## Comparison Summary

| Criterion                  | Bearer Token | mTLS   | Unix Socket    |
|----------------------------|--------------|--------|----------------|
| Remote Prometheus scraping | Yes          | Yes    | Via SSH tunnel |
| Operator setup burden      | Low          | High   | Low            |
| Per-client identity        | No           | Yes    | No (UID-based) |
| Secret rotation required   | Yes          | Yes    | No             |
| New crate dependencies     | None         | rustls | None           |
| Implementation effort      | Low          | High   | Low-medium     |
| v1 recommendation          | Yes          | No     | Later          |

---

## Recommendation

**v1: implement Option 1 (bearer token).**

The vast majority of v1 deployments will have a single operator and a Prometheus
instance on one or two hosts. Bearer token is the lowest-friction path that actually
provides authentication when `addr` is non-loopback.

The implementation rule is:

- If `token` is empty and `addr` is loopback: no authentication, no warning (existing
  safe default).
- If `token` is non-empty: enforce `Authorization: Bearer <token>` on all requests
  regardless of bind address.
- If `token` is empty and `addr` is non-loopback: existing `check_admin_addr` warning
  fires; requests are served unauthenticated (operator opted in via
  `allow_non_loopback`).

Unix socket (Option 3) is a clean follow-on for operators who want OS-level access
control on a single host. It can be added in a later iteration without touching the
bearer token logic.

mTLS (Option 2) is deferred to a future security hardening epic.

---

## Config Schema Change

Minimal addition to `AdminConfig`: one optional `token` field.

```toml
[admin]
addr = "127.0.0.1:9090"
allow_non_loopback = false
token = ""  # empty = no auth required (loopback only); set for remote access
```

Corresponding Rust struct delta:

```rust
pub struct AdminConfig {
    pub addr: String,
    pub allow_non_loopback: bool,
    /// Bearer token for admin endpoint authentication.
    /// Empty string disables authentication (safe only on loopback).
    /// Generate with: openssl rand -hex 32
    #[serde(default)]
    pub token: String,
}
```

The `check_admin_addr` function (or a sibling `check_admin_config`) should be
extended to also warn when `addr` is non-loopback and `token` is empty, even if
`allow_non_loopback` is set — making the intent explicit rather than relying on the
operator to remember the token field.

Config file containing a token must be created with `chmod 0600`. A startup check
that warns if the config file is world-readable is a worthwhile addition alongside
the token implementation, but is out of scope for this spike.
