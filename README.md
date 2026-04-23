# usenet-ipfs

Run your own Usenet server. Articles are stored in IPFS and group state is reconciled peer-to-peer over libp2p gossipsub. Standard newsreader clients — slrn, tin, pan, gnus, Thunderbird — connect over unmodified RFC 3977 NNTP. No client changes required.

## Prerequisites

- **Rust** stable toolchain — [rustup.rs](https://rustup.rs)
- **Kubo** (go-ipfs) — [install guide](https://docs.ipfs.tech/install/command-line/)

Both daemons speak to Kubo's HTTP RPC API (`http://127.0.0.1:5001` by default). Article bytes live in Kubo's block store on disk and survive daemon restarts. Start Kubo before starting either daemon:

```bash
ipfs daemon
```

A local filesystem block cache (`[ipfs] cache_path`) is optional but recommended to avoid re-fetching blocks from Kubo on every read.

## Quick start

```bash
git clone https://github.com/MarkAtwood/usenet-ipfs.git
cd usenet-ipfs
cargo build --release -p usenet-ipfs-transit -p usenet-ipfs-reader
```

Binaries land in `target/release/`.

### Run the transit daemon

Create `transit.toml`:

```toml
[listen]
addr = "0.0.0.0:119"

[groups]
names = ["comp.lang.rust", "alt.test"]

[ipfs]
api_url    = "http://127.0.0.1:5001"
cache_path = "/var/cache/usenet-ipfs/blocks"

[database]
core_path = "/var/lib/usenet-ipfs/transit/core.db"
path      = "/var/lib/usenet-ipfs/transit/transit.db"

[admin]
addr = "127.0.0.1:9090"

[log]
level = "info"
format = "json"
```

```bash
mkdir -p /var/lib/usenet-ipfs/transit
target/release/usenet-ipfs-transit --config transit.toml
```

Verify it's up:

```bash
curl -s http://127.0.0.1:9090/health
# {"status":"ok","uptime_secs":3}
```

### Run the reader daemon

Create `reader.toml`:

```toml
[listen]
addr = "0.0.0.0:119"

[ipfs]
api_url    = "http://127.0.0.1:5001"
cache_path = "/var/cache/usenet-ipfs/blocks"

[auth]
required = false

[admin]
addr = "127.0.0.1:9091"

[log]
level = "info"
format = "json"
```

```bash
target/release/usenet-ipfs-reader --config reader.toml
```

Verify:

```bash
{ echo "CAPABILITIES"; sleep 1; echo "QUIT"; } | nc localhost 119
# 200 usenet-ipfs reader ready
# 101 Capability list follows
# VERSION 2
# READER
# ...
```

### Connect a newsreader

Point any RFC 3977 newsreader at `localhost:119`. No configuration or plugins on the client side. Groups appear after the first articles are posted; use `LIST` or let your client refresh.

---

## Read newsgroups as email (JMAP)

`usenet-ipfs-mail` is a JMAP server (RFC 8620/8621) that exposes the article store to email clients — Thunderbird, Fastmail, iOS Mail.

Create `mail.toml`:

```toml
[listen]
addr = "127.0.0.1:8080"

[database]
path = "/var/lib/usenet-ipfs/mail/mail.db"

[auth]
required = false

[log]
level = "info"
format = "json"
```

```bash
mkdir -p /var/lib/usenet-ipfs/mail
target/release/usenet-ipfs-mail --config mail.toml
```

Configure your JMAP client with session URL `http://127.0.0.1:8080/jmap/session`.

> **Production:** always use HTTPS. Configure `[tls]` cert/key paths before exposing to a non-loopback network.

---

## Peer two transit nodes

Add the other node's address to `[peers]` on both sides and restart:

```toml
[peers]
addresses = ["other-host:119"]
```

Both nodes must list the same groups in `[groups] names`. Articles injected at either node are forwarded via IHAVE/TAKETHIS and tip-advertised over gossipsub.

---

## v1 limitations

| Limitation | Detail |
|-----------|--------|
| Requires Kubo | A running Kubo daemon is required. Both daemons fail to start if Kubo is unreachable. |
| Ephemeral signing key | Transit generates a new Ed25519 key at each startup. A warning is emitted. |
| In-memory reader index | Article numbers and the overview index (SQLite) are in-memory and lost on reader restart. |
| No peer block fetch | Gossip reconciliation finds gaps but cannot yet fetch them from remote peers. |
| TLS not advertised | TLS infrastructure is wired; STARTTLS not yet in CAPABILITIES. |
| Text groups only | Binary groups and yEnc are out of scope for v1. |

---

## Status

730+ tests pass across the workspace (~30K LOC). RFC 3977 conformance verified by a Python nntplib client and a two-process transit+reader integration test.

Implemented: full NNTP command set, article ingestion pipeline, Merkle-CRDT group log, ed25519 signing, rust-ipfs 0.15.0 embedded node, gossipsub swarm, overview index, SQLite article number store, admin HTTP endpoint, AUTHINFO.

Open work tracked via `bd ready`.

---

## Full deployment guide

See [`docs/RUNBOOK.md`](docs/RUNBOOK.md) for the complete operator reference: configuration field descriptions, peering setup, GC policy, troubleshooting, and the mail daemon user-management steps.

---

## Architecture

Two binaries sharing a core library:

| Binary | Role |
|--------|------|
| `usenet-ipfs-transit` | Peering daemon. Accepts articles via IHAVE/TAKETHIS, stores to IPFS, appends to group log, propagates over gossipsub. Admin HTTP endpoint. |
| `usenet-ipfs-reader` | RFC 3977 NNTP server. Serves articles to newsreader clients. Synthesizes local sequential article numbers, maintains overview index, handles POST. |

`usenet-ipfs-core` (rlib) holds shared types: article format, CID scheme, Message-ID↔CID mapping, Merkle-CRDT group log, canonical serialization, and signing.

Articles are stored as DAG-CBOR IPLD blocks (SHA-256, CIDv1 codec 0x71). Group state is a per-group Merkle-CRDT append-only log with HLC timestamps and operator ed25519 signatures, tips advertised over gossipsub topics per hierarchy (`usenet.hier.comp`, `usenet.hier.sci`, …). Article numbers are local and synthetic — never network-stable.

### Design invariants

1. **Reader speaks RFC 3977 verbatim.** No extensions that break standard clients.
2. **v1 is text-only.** Binary groups and yEnc are out of scope.
3. **No moderation in v1.** No cancel messages, no NoCeM.
4. **Gossipsub topics are per-hierarchy.** `comp.*` is one topic; group filtering is inside it.
5. **Article numbers are local.** Never treat them as network-stable identifiers.
6. **Retention is explicit.** Every stored article must be covered by a pin or GC policy.

### Workspace layout

```
usenet-ipfs/
├── Cargo.toml
├── crates/
│   ├── core/               shared types, CID scheme, Merkle-CRDT, signing
│   ├── transit/            peering daemon
│   ├── reader/             RFC 3977 NNTP server
│   └── integration-tests/
├── docs/
│   └── RUNBOOK.md          operator deployment guide
└── spikes/                 IPFS client library evaluation results
```

### Building and testing

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
```

Requirements: Rust stable (edition 2021), tokio, sqlx + SQLite, ed25519-dalek, rust-ipfs 0.15.0.

---

## Contributing

Issue tracker: [Beads](https://github.com/beads-dev/beads). Run `bd ready` for available work. All non-trivial changes must trace to an open issue.

---

## License

MIT, except: `usenet-ipfs-sieve` and the `usenet-ipfs-smtp` binary that links it depend on [`sieve-rs`](https://crates.io/crates/sieve-rs) (AGPL-3.0-only). Operators running `usenet-ipfs-smtp` as a network service must make complete corresponding source available to users of that service.
