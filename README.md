# stoa

Run your own Usenet server. Articles are stored in a content-addressed block store and group state is reconciled peer-to-peer. Standard newsreader clients — slrn, tin, pan, gnus, Thunderbird — connect over unmodified RFC 3977 NNTP. No client changes required.

## Prerequisites

- **Rust** stable toolchain — [rustup.rs](https://rustup.rs)

That's it for the default LMDB backend. Kubo (go-ipfs) is an optional alternative — see [Backend options](#backend-options) below.

## Quick start

```bash
git clone https://github.com/MarkAtwood/stoa.git
cd stoa
cargo build --release -p stoa-transit -p stoa-reader
```

Binaries land in `target/release/`.

### Run the transit daemon

Create `transit.toml`:

```toml
[listen]
addr = "0.0.0.0:119"

[groups]
names = ["comp.lang.rust", "alt.test"]

[backend]
type = "lmdb"

[backend.lmdb]
path = "/var/lib/stoa/transit/blocks"

[database]
core_path = "/var/lib/stoa/transit/core.db"
path      = "/var/lib/stoa/transit/transit.db"

[admin]
addr = "127.0.0.1:9090"

[log]
level = "info"
format = "json"
```

```bash
mkdir -p /var/lib/stoa/transit
target/release/stoa-transit --config transit.toml
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

[backend]
type = "lmdb"

[backend.lmdb]
path = "/var/lib/stoa/reader/blocks"

[auth]
required = false

[admin]
addr = "127.0.0.1:9091"

[log]
level = "info"
format = "json"
```

```bash
target/release/stoa-reader --config reader.toml
```

Verify:

```bash
{ echo "CAPABILITIES"; sleep 1; echo "QUIT"; } | nc localhost 119
# 200 stoa reader ready
# 101 Capability list follows
# VERSION 2
# READER
# ...
```

### Connect a newsreader

Point any RFC 3977 newsreader at `localhost:119`. No configuration or plugins on the client side. Groups appear after the first articles are posted; use `LIST` or let your client refresh.

---

## Read newsgroups as email (JMAP)

`stoa-mail` is a JMAP server (RFC 8620/8621) that exposes the article store to email clients — Thunderbird, Fastmail, iOS Mail.

Create `mail.toml`:

```toml
[listen]
addr = "127.0.0.1:8080"

[database]
path = "/var/lib/stoa/mail/mail.db"

[auth]
required = false

[log]
level = "info"
format = "json"
```

```bash
mkdir -p /var/lib/stoa/mail
target/release/stoa-mail --config mail.toml
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

## Backend options

Block store backends:

| Backend | Config `type` | Status | Notes |
|---------|--------------|--------|-------|
| **LMDB** | `"lmdb"` | Implemented | Default. Memory-mapped, zero external dependencies. Fast concurrent reads. |
| **Kubo** | `"kubo"` | Implemented | Delegates to a running [Kubo](https://docs.ipfs.tech/install/command-line/) (go-ipfs) daemon. |
| **S3** | `"s3"` | Planned | Object storage; AWS S3 or compatible (MinIO, Backblaze B2, Cloudflare R2, etc.). |
| **Azure Blob** | `"azure"` | Planned | Azure Blob Storage native API. |
| **GCS** | `"gcs"` | Planned | Google Cloud Storage native API. |
| **Ceph RADOS** | `"rados"` | Planned | Ceph native RADOS object store. |
| **RocksDB** | `"rocksdb"` | Planned | Embedded LSM-tree KV store; higher write throughput than LMDB. |
| **Filesystem** | `"filesystem"` | Planned | Plain directory of files; useful for debugging and cold import. |

### Kubo backend config

```toml
[backend]
type = "kubo"

[backend.kubo]
api_url    = "http://127.0.0.1:5001"
cache_path = "/var/cache/stoa/blocks"   # optional local read cache
```

Start Kubo before either daemon when using this backend:

```bash
ipfs daemon
```

---

## v1 limitations

| Limitation | Detail |
|-----------|--------|
| Ephemeral signing key | Transit generates a new Ed25519 key at each startup. A warning is emitted. |
| No peer block fetch | Gossip reconciliation finds gaps but cannot yet fetch them from remote peers. |
| TLS not advertised | TLS infrastructure is wired; STARTTLS not yet in CAPABILITIES. |
| Text groups only | Binary groups and yEnc are out of scope for v1. |

---

## Status

730+ tests pass across the workspace (~30K LOC). RFC 3977 conformance verified by a Python nntplib client and a two-process transit+reader integration test.

Implemented: full NNTP command set, article ingestion pipeline, Merkle-CRDT group log, ed25519 signing, LMDB/SQLite/Kubo block store backends, gossipsub swarm, overview index, SQLite article number store, admin HTTP endpoint, AUTHINFO.

Open work tracked via `bd ready`.

---

## Full deployment guide

See [`docs/RUNBOOK.md`](docs/RUNBOOK.md) for the complete operator reference: configuration field descriptions, peering setup, GC policy, troubleshooting, and the mail daemon user-management steps.

---

## Architecture

Two binaries sharing a core library:

| Binary | Role |
|--------|------|
| `stoa-transit` | Peering daemon. Accepts articles via IHAVE/TAKETHIS, writes to the block store, appends to the group log, propagates over gossipsub. Admin HTTP endpoint. |
| `stoa-reader` | RFC 3977 NNTP server. Serves articles to newsreader clients. Synthesizes local sequential article numbers, maintains overview index, handles POST. |

`stoa-core` (rlib) holds shared types: article format, CID scheme, Message-ID↔CID mapping, Merkle-CRDT group log, canonical serialization, and signing.

Articles are stored as DAG-CBOR IPLD blocks (SHA-256, CIDv1). Group state is a per-group Merkle-CRDT append-only log with HLC timestamps and operator ed25519 signatures, tips advertised over gossipsub topics per hierarchy (`stoa.hier.comp`, `stoa.hier.sci`, …). Article numbers are local and synthetic — never network-stable.

### Design invariants

1. **Reader speaks RFC 3977 verbatim.** No extensions that break standard clients.
2. **v1 is text-only.** Binary groups and yEnc are out of scope.
3. **No moderation in v1.** No cancel messages, no NoCeM.
4. **Gossipsub topics are per-hierarchy.** `comp.*` is one topic; group filtering is inside it.
5. **Article numbers are local.** Never treat them as network-stable identifiers.
6. **Retention is explicit.** Every stored article must be covered by a pin or GC policy.

### Workspace layout

```
stoa/
├── Cargo.toml
├── crates/
│   ├── core/               shared types, CID scheme, Merkle-CRDT, signing
│   ├── transit/            peering daemon
│   ├── reader/             RFC 3977 NNTP server
│   ├── lmdb/               LMDB block store (FFI boundary crate)
│   └── integration-tests/
├── docs/
│   └── RUNBOOK.md          operator deployment guide
└── spikes/                 block store backend evaluation results
```

### Building and testing

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
```

Requirements: Rust stable (edition 2021), tokio, sqlx + SQLite, ed25519-dalek.

---

## Contributing

Issue tracker: [Beads](https://github.com/beads-dev/beads). Run `bd ready` for available work. All non-trivial changes must trace to an open issue.

---

## License

MIT.
