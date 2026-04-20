# Installation and First-Run Guide

This guide covers building usenet-ipfs from source, generating operator keys, writing
minimal configuration files, and starting both daemons for the first time.

## Prerequisites

### Rust toolchain

Install the stable Rust toolchain via rustup:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install stable
```

Minimum supported Rust version is tracked in each crate's `Cargo.toml`
`rust-version` field. Building on nightly is not required.

### IPFS node

usenet-ipfs communicates with an IPFS node over its HTTP API (default
`http://127.0.0.1:5001`). Two options:

- **Embedded rust-ipfs** (planned feature): the transit daemon can run an
  embedded `rust-ipfs` 0.15 node with no external dependency. No action
  needed.
- **External Kubo node**: install [Kubo](https://docs.ipfs.tech/install/command-line/)
  and start it with `ipfs daemon`. Confirm the API is reachable:
  ```
  curl http://127.0.0.1:5001/api/v0/version
  ```

Both daemons use the same IPFS API endpoint. If the transit daemon is running
an embedded node, point the reader at the same API address.

### Operating system

Linux and macOS are supported. x86-64 and aarch64 are the tested
architectures. A minimum of 1 GB RAM and 10 GB disk is recommended for a
development instance; production sizing depends on group list and retention
policy.

### Network ports

| Port | Protocol | Daemon | Purpose |
|------|----------|--------|---------|
| 119 | TCP | both | NNTP plain-text (or STARTTLS upgrade) |
| 563 | TCP | reader | NNTPS (immediate TLS) — alternative port |
| 9090 | HTTP | both | Admin endpoint (loopback only by default) |
| 5001 | HTTP | — | IPFS API (local; transit connects to this) |
| 4001 | TCP/UDP | — | IPFS swarm (libp2p) |

---

## Building from Source

Clone the repository and build both release binaries:

```
git clone https://github.com/your-org/usenet-ipfs.git
cd usenet-ipfs
cargo build --release -p usenet-ipfs-transit -p usenet-ipfs-reader
```

Binaries are placed in `target/release/`:

```
target/release/usenet-ipfs-transit
target/release/usenet-ipfs-reader
```

Copy them to a system path or run from the build directory.

To build the full workspace (includes `usenet-ipfs-core` library and all
tests):

```
cargo build --workspace
```

---

## Generating Operator Keys

Every article written to IPFS is signed with the operator's Ed25519 key.
Generate the key before starting either daemon:

```
mkdir -p keys
usenet-ipfs-transit keygen --output keys/operator.key
```

This writes a new Ed25519 signing key to `keys/operator.key`. Protect this
file:

```
chmod 600 keys/operator.key
```

The key is never logged or included in error messages. Store a backup in a
secure location. Key rotation is available via `usenet-ipfs-transit key-rotate`
(see `usenet-ipfs-transit help key-rotate`).

---

## Transit Daemon Configuration

Create `transit.toml`. The minimum required sections are `[listen]`, `[peers]`,
`[groups]`, `[ipfs]`, `[pinning]`, and `[gc]`.

```toml
# transit.toml — usenet-ipfs-transit configuration

# ---------------------------------------------------------------------------
# [listen] — NNTP peering listener
# ---------------------------------------------------------------------------
[listen]
# Address and port to accept inbound NNTP peering connections.
# Use 0.0.0.0 to accept from any interface.
addr = "0.0.0.0:119"

# ---------------------------------------------------------------------------
# [peers] — outbound NNTP peering targets
# ---------------------------------------------------------------------------
[peers]
# List of remote transit peers to connect to and exchange articles with.
# Each entry is "host:port" for a usenet-ipfs or INN transit peer.
addresses = [
    "192.0.2.10:119",
    "192.0.2.20:119",
]

# ---------------------------------------------------------------------------
# [groups] — group subscription list
# ---------------------------------------------------------------------------
[groups]
# Groups this node subscribes to. Only articles for listed groups are
# stored and relayed. Group names must be lowercase dot-separated labels.
names = [
    "comp.lang.rust",
    "comp.lang.c",
    "alt.test",
]

# ---------------------------------------------------------------------------
# [ipfs] — IPFS node connection
# ---------------------------------------------------------------------------
[ipfs]
# HTTP API endpoint of the IPFS node.
# Default Kubo address is http://127.0.0.1:5001
api_url = "http://127.0.0.1:5001"

# ---------------------------------------------------------------------------
# [pinning] — article pinning policy
# ---------------------------------------------------------------------------
[pinning]
# List of pinning rules evaluated in order. The first matching rule wins.
# Pinning is explicit opt-in: articles not matched by any rule are not pinned.
#
# Built-in shorthand values:
#   "pin-all"          — pin every incoming article (no GC)
#   "pin-all-ingress"  — same as pin-all; explicit label
#
# For fine-grained rules, use [[pinning.rules]] tables instead (see the
# configuration reference for the full PinRule schema).
rules = [
    "pin-all-ingress",
]

# ---------------------------------------------------------------------------
# [gc] — garbage collection schedule
# ---------------------------------------------------------------------------
[gc]
# Cron expression for GC runs (standard 5-field UTC cron syntax).
# "0 3 * * *" = 03:00 UTC daily.
schedule = "0 3 * * *"
# Remove articles older than this many days that are not pinned.
max_age_days = 90

# ---------------------------------------------------------------------------
# [admin] — admin HTTP endpoint (optional section; defaults shown)
# ---------------------------------------------------------------------------
[admin]
# Loopback-only by default. Non-loopback requires allow_non_loopback = true
# and is warned at startup unless a bearer_token is configured.
addr = "127.0.0.1:9090"
# allow_non_loopback = false
# bearer_token = "change-me-to-a-strong-random-string"
# rate_limit_rpm = 60

# ---------------------------------------------------------------------------
# [log] — logging (optional section; defaults shown)
# ---------------------------------------------------------------------------
[log]
# Log level: "error", "warn", "info", "debug", "trace".
# Can also be a filter string: "usenet_ipfs_transit=debug,info"
# Overridden at runtime by the RUST_LOG environment variable.
level = "info"
# Output format: "json" (structured, recommended for log aggregation)
# or "text" (human-readable, useful in development).
format = "json"
```

---

## Reader Daemon Configuration

Create `reader.toml`. The minimum required sections are `[listen]`, `[limits]`,
`[auth]`, and `[tls]`.

```toml
# reader.toml — usenet-ipfs-reader configuration

# ---------------------------------------------------------------------------
# [listen] — NNTP client listener
# ---------------------------------------------------------------------------
[listen]
# Address and port to accept newsreader client connections (RFC 3977).
# Port 119 is standard plain-text NNTP (with optional STARTTLS upgrade).
# Use port 563 with TLS configured below for immediate NNTPS.
addr = "0.0.0.0:119"

# ---------------------------------------------------------------------------
# [limits] — connection and session limits
# ---------------------------------------------------------------------------
[limits]
# Maximum number of concurrent client connections. Default: 100.
max_connections = 100
# Seconds to wait for the next command before closing an idle connection.
command_timeout_secs = 30

# ---------------------------------------------------------------------------
# [auth] — AUTHINFO USER/PASS authentication (RFC 4643)
# ---------------------------------------------------------------------------
[auth]
# When true, clients must authenticate before accessing any groups.
# When false and users list is empty, all credential attempts succeed
# (development mode — do not use in production without TLS).
required = true

# User credentials. Each entry is a username/password pair.
# Passwords are compared in constant time; store them out of VCS.
[[auth.users]]
username = "alice"
password = "changeme"

# [[auth.users]]
# username = "bob"
# password = "changeme2"

# ---------------------------------------------------------------------------
# [tls] — TLS configuration
# ---------------------------------------------------------------------------
[tls]
# Paths to PEM-encoded TLS certificate and private key.
# Both must be set together or both must be absent.
#   Both set   → immediate TLS on every connection (NNTPS).
#   Both absent → plain-text with STARTTLS offered in CAPABILITIES.
cert_path = "/etc/ssl/certs/nntp-server.pem"
key_path  = "/etc/ssl/private/nntp-server.key"

# To disable TLS entirely (development only), comment out both lines:
# cert_path and key_path absent → STARTTLS available but not required.

# ---------------------------------------------------------------------------
# [admin] — admin HTTP endpoint (optional section; defaults shown)
# ---------------------------------------------------------------------------
[admin]
addr = "127.0.0.1:9090"
# allow_non_loopback = false

# ---------------------------------------------------------------------------
# [log] — logging (optional section; defaults shown)
# ---------------------------------------------------------------------------
[log]
level = "info"
format = "json"
```

---

## Starting Both Daemons

Start the transit daemon, pointing it at its config file and operator key:

```
usenet-ipfs-transit --config transit.toml --key keys/operator.key
```

Start the reader daemon in a separate terminal (or as a separate service):

```
usenet-ipfs-reader --config reader.toml --key keys/operator.key
```

Both daemons log structured JSON to stdout by default. Redirect to a file or
pipe through a log aggregator as appropriate.

To run as systemd services, see the example unit files in `contrib/systemd/`
(not yet committed; copy and adapt from the templates below).

### Minimal systemd unit (transit)

```ini
[Unit]
Description=usenet-ipfs transit daemon
After=network.target ipfs.service

[Service]
ExecStart=/usr/local/bin/usenet-ipfs-transit --config /etc/usenet-ipfs/transit.toml --key /etc/usenet-ipfs/keys/operator.key
Restart=on-failure
User=usenet-ipfs
ProtectSystem=strict
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Minimal systemd unit (reader)

```ini
[Unit]
Description=usenet-ipfs reader daemon
After=network.target usenet-ipfs-transit.service

[Service]
ExecStart=/usr/local/bin/usenet-ipfs-reader --config /etc/usenet-ipfs/reader.toml --key /etc/usenet-ipfs/keys/operator.key
Restart=on-failure
User=usenet-ipfs
ProtectSystem=strict
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## Verifying with the Operator CLI

After both daemons are running, verify the transit daemon with:

```
usenet-ipfs-transit status
```

Expected output (abbreviated):

```
transit: running
  listen:      0.0.0.0:119
  ipfs:        connected (http://127.0.0.1:5001)
  peers:       2 configured, 1 connected
  groups:      3 subscribed
  pinning:     1 rule(s) active
  gc:          schedule "0 3 * * *", next run in 18h
  admin:       http://127.0.0.1:9090
```

If the daemon is not reachable, check that `admin.addr` in `transit.toml`
matches the address you are querying. The admin endpoint is loopback-only by
default.

To check the reader daemon, connect with any standard newsreader client or
use netcat:

```
nc localhost 119
200 usenet-ipfs reader ready
CAPABILITIES
101 Capability list follows
VERSION 2
READER
POST
IHAVE
OVER
HDR
LIST ACTIVE NEWSGROUPS OVERVIEW.FMT
STARTTLS
AUTHINFO USER
.
QUIT
205 Bye
```

The `STARTTLS` capability appears when TLS is not configured for immediate
upgrade. `AUTHINFO USER` appears when `auth.required = true`.
