# Operator Deployment Runbook

This runbook covers building, configuring, and running both usenet-ipfs daemons
on a single host. It reflects the current codebase state.

---

## v1 Limitations

Before deploying, understand these v1 constraints:

| Limitation | Detail |
|-----------|--------|
| **Ephemeral signing key (transit)** | Transit generates a new Ed25519 key at each startup. Cross-peer signature verification is not reliable across restarts. A warning is emitted at startup. |
| **In-memory storage (reader)** | The reader daemon stores article numbers, the overview index, and the message-ID map in in-memory SQLite. All reader state is lost on restart; articles must be re-ingested. |
| **No peer block fetch** | When gossip reconciliation finds missing entries, the fetch is stubbed out. Remote entries are logged as warnings but not retrieved. |
| **TLS not yet advertised** | TLS infrastructure is wired but STARTTLS is not yet advertised in CAPABILITIES. |

---

## Prerequisites

- Rust stable toolchain (rustup: https://rustup.rs)
- Git

---

## Build

```bash
git clone https://github.com/MarkAtwood/usenet-ipfs.git
cd usenet-ipfs
cargo build --release -p usenet-ipfs-transit -p usenet-ipfs-reader
```

Binaries land in `target/release/`:
- `target/release/usenet-ipfs-transit`
- `target/release/usenet-ipfs-reader`

Run the test suite to verify the build:
```bash
cargo test --workspace
```

All tests must pass (730+ expected) before deploying.

---

## Transit daemon

### Configuration

The transit daemon takes a single flag: `--config <path>`.

Create `transit.toml`:

```toml
[listen]
addr = "0.0.0.0:119"

[peers]
# Other transit peers to exchange articles with.
addresses = []

[groups]
# Groups this node subscribes to and relays.
names = [
    "comp.lang.rust",
    "alt.test",
]

[ipfs]
# rust-ipfs is embedded in the transit daemon. This field is reserved
# for future external-node support; the value is not currently used.
api_url = "http://127.0.0.1:5001"

[pinning]
rules = ["pin-all-ingress"]

[gc]
schedule = "0 3 * * *"
max_age_days = 90

[database]
# SQLite database files. Directories must exist; files are created on first run.
core_path = "/var/lib/usenet-ipfs/transit/core.db"
path       = "/var/lib/usenet-ipfs/transit/transit.db"

[admin]
addr = "127.0.0.1:9090"
# bearer_token = "set-this-for-non-loopback-use"
# rate_limit_rpm = 60

[log]
level = "info"
format = "json"
```

### Start

```bash
mkdir -p /var/lib/usenet-ipfs/transit
usenet-ipfs-transit --config transit.toml
```

The daemon logs structured JSON to stdout. Redirect as needed:
```bash
usenet-ipfs-transit --config transit.toml 2>&1 | tee -a /var/log/usenet-ipfs-transit.log
```

On startup you will see:
```
WARN using ephemeral operator signing key — add key persistence before production
```
This is expected in v1.

### Verify

Check the admin endpoint:

```bash
curl -s http://127.0.0.1:9090/health | python3 -m json.tool
```

Expected response:
```json
{
  "status": "ok",
  "uptime_secs": 12
}
```

Other admin endpoints:
- `GET /stats` — article, group, and peer counts
- `GET /log-tip?group=comp.lang.rust` — current group log tip CID
- `GET /peers` — connected peers
- `GET /metrics` — Prometheus text format

---

## Reader daemon

### Configuration

The reader daemon takes a single flag: `--config <path>`.

> **Note**: the reader currently stores all state in in-memory SQLite. Article
> numbers, the overview index, and the message-ID map are rebuilt from scratch
> on each restart. This is a v1 limitation tracked as a future issue.

Create `reader.toml`:

```toml
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 100
command_timeout_secs = 30

[auth]
required = false   # set true and add [[auth.users]] for production

# [[auth.users]]
# username = "alice"
# password = "changeme"

[tls]
# Uncomment to enable immediate TLS (NNTPS):
# cert_path = "/etc/ssl/certs/nntp.pem"
# key_path  = "/etc/ssl/private/nntp.key"

[admin]
# Use a different port if reader and transit run on the same host.
addr = "127.0.0.1:9091"

[log]
level = "info"
format = "json"
```

### Start

```bash
usenet-ipfs-reader --config reader.toml
```

The reader starts its own embedded rust-ipfs node. On first connection it
backfills the overview index from articles already in IPFS.

### Verify

Connect with netcat:

```bash
{ echo "CAPABILITIES"; sleep 1; echo "QUIT"; } | nc localhost 119
```

Expected output:
```
200 usenet-ipfs reader ready
101 Capability list follows
VERSION 2
READER
POST
IHAVE
OVER
HDR
LIST ACTIVE NEWSGROUPS OVERVIEW.FMT
.
205 Bye
```

---

## Peering two transit instances

1. Set `[listen] addr` on each node to its publicly reachable address.
2. Add the other node's `host:port` to `[peers] addresses` on both sides.
3. List the same groups in `[groups] names` on both nodes (required for gossipsub
   topic subscription to overlap).
4. Restart both daemons.

Articles injected at either node will be forwarded to the other via NNTP
IHAVE/TAKETHIS and tip-advertised over gossipsub. Watch the logs for:
```
INFO gossip: reconcile result  group=comp.lang.rust  want=0  have=1
```

---

## Troubleshooting

| Symptom | Likely cause | Action |
|---------|-------------|--------|
| `error: failed to bind 0.0.0.0:119` | Port 119 requires root or `CAP_NET_BIND_SERVICE` | Use port ≥1024 in config, or `sudo setcap cap_net_bind_service=+ep target/release/usenet-ipfs-transit` |
| `LIST` returns empty | No articles posted yet | POST an article via the reader; groups are discovered from posted articles |
| `GROUP comp.lang.rust` returns `411 No such newsgroup` | No articles in that group | The reader synthesizes groups from posted articles; a group with no articles is not listed |
| Admin endpoint returns 403 | `bearer_token` is configured | Pass `Authorization: Bearer <token>` header |
| Transit logs `v1: peer block fetch not yet implemented` | Gossip reconciliation found missing remote entries | Expected in v1; backfill from peers is a future feature |
| Reader loses all articles after restart | In-memory storage — expected in v1 | Re-post articles; persistent storage is a future feature |

---

## See also

- `docs/ops/configuration_reference.md` — full field-by-field reference
- `docs/ops/peering_guide.md` — detailed peering setup
- `docs/ops/retention_guide.md` — pinning and GC policy configuration
- `docs/threat_model.md` — security considerations
