# Operator Deployment Runbook

This runbook covers building, configuring, and running both stoa daemons
on a single host. It reflects the current codebase state.

---

## v1 Limitations

Before deploying, understand these v1 constraints:

| Limitation | Detail |
|-----------|--------|
| **Requires Kubo** | Both daemons require a running Kubo (go-ipfs) node. They fail at startup if the Kubo API is unreachable. Articles are stored durably in Kubo's block store and survive daemon restarts. |
| **Ephemeral signing key (loopback only)** | Both daemons generate an ephemeral key when `[operator] signing_key_path` is absent. This is only permitted for loopback (`127.0.0.1`/`::1`) bind addresses. Non-loopback deployments must generate and configure a persistent key (see [Operator Signing Key](#operator-signing-key) below). |
| **Reader state requires backfill on schema change** | Reader SQLite databases (`reader.db`, `reader_core.db`, `reader_verify.db`) persist across restarts. If the schema is migrated, article numbers and overview entries survive; the backfill at startup fills any gaps. |
| **No peer block fetch** | When gossip reconciliation finds missing entries, the fetch is stubbed out. Remote entries are logged as warnings but not retrieved. |
| **TLS not yet advertised** | TLS infrastructure is wired but STARTTLS is not yet advertised in CAPABILITIES. |

---

## Prerequisites

- Rust stable toolchain (rustup: https://rustup.rs)
- Git
- Kubo (go-ipfs): https://docs.ipfs.tech/install/command-line/

Start the Kubo daemon before starting either stoa daemon:

```bash
ipfs daemon
```

Kubo must be reachable at `http://127.0.0.1:5001` (the default) or at the `api_url` configured in each daemon's `[ipfs]` section.

---

## Build

```bash
git clone https://github.com/MarkAtwood/stoa.git
cd stoa
cargo build --release -p stoa-transit -p stoa-reader
```

Binaries land in `target/release/`:
- `target/release/stoa-transit`
- `target/release/stoa-reader`

Run the test suite to verify the build:
```bash
cargo test --workspace
```

All tests must pass (730+ expected) before deploying.

---

## Operator Signing Key

Both daemons sign every article they ingest with an Ed25519 key.  The key is
used to:

- Sign articles (adds `X-Stoa-Sig:` header) so peers can verify they
  came from a trusted operator.
- Derive the stable 8-byte HLC node ID embedded in all timestamps.

### Generate a key

Run `keygen` once, **before** the daemon's first start:

```bash
# For the transit daemon:
stoa-transit keygen --output /etc/stoa/transit/operator.key

# For the reader daemon:
stoa-reader keygen --output /etc/stoa/reader/operator.key
```

Output:
```
public_key: <64-hex-char Ed25519 public key>
node_id:    <16-hex-char HLC node ID>
key_file:   /etc/stoa/transit/operator.key
```

The key file is written with mode 0600 (owner-read only).  If the file already
exists, `keygen` exits with an error — use `--force` to regenerate (which
orphans all previous signatures).

### Configure the key path

Add to your config file:

```toml
[operator]
signing_key_path = "/etc/stoa/transit/operator.key"
```

Both daemons **require** this setting when binding to a non-loopback address.
They exit at startup with a clear error if it is absent:

```
error: operator.signing_key_path must be set when listening on a non-loopback
address (0.0.0.0:119). Run `stoa-transit keygen --output <path>` to
generate a key, then set [operator] signing_key_path in your config.
```

### Key file security

- The key file must not be world-readable.  Both daemons exit with an error if
  `o+r` is set: `chmod 0600 /etc/stoa/transit/operator.key`.
- The file must contain exactly 32 raw bytes (the Ed25519 seed).

### Backup and recovery

**Back up the key file.**  Losing it has these consequences:

| Consequence | Detail |
|------------|--------|
| Orphaned signatures | Articles signed with the old key cannot be verified by peers. |
| HLC node ID change | Timestamps from before and after the key change are not comparable. |
| IPNS discontinuity | The IPNS address (if used) changes with the key. |

Back up to a second offline location, encrypted with a passphrase:

```bash
gpg --symmetric --cipher-algo AES256 -o operator.key.gpg /etc/stoa/transit/operator.key
```

To restore, decrypt and copy the file back, then verify the daemon starts cleanly.

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
# Kubo HTTP RPC API URL. Kubo must be running before starting this daemon.
api_url    = "http://127.0.0.1:5001"
# Optional local block cache directory. Created at startup if absent.
# Recommended: avoids re-fetching blocks from Kubo on every read.
cache_path = "/var/cache/stoa/blocks"

[pinning]
rules = ["pin-all-ingress"]

[gc]
schedule = "0 3 * * *"
max_age_days = 90

[database]
# SQLite database files. Directories must exist; files are created on first run.
core_path = "/var/lib/stoa/transit/core.db"
path       = "/var/lib/stoa/transit/transit.db"

[operator]
signing_key_path = "/etc/stoa/transit/operator.key"

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
# Generate operator key (first time only):
stoa-transit keygen --output /etc/stoa/transit/operator.key

mkdir -p /var/lib/stoa/transit
stoa-transit --config transit.toml
```

The daemon logs structured JSON to stdout. Redirect as needed:
```bash
stoa-transit --config transit.toml 2>&1 | tee -a /var/log/stoa-transit.log
```

### Verify

Check the readiness endpoint (verifies SQLite and Kubo are up):

```bash
curl -s http://127.0.0.1:9090/healthz/ready | python3 -m json.tool
```

Expected response when healthy:
```json
{
  "status": "ok",
  "uptime_secs": 12,
  "checks": [
    {"name": "sqlite_transit", "ok": true, "detail": ""},
    {"name": "sqlite_core",    "ok": true, "detail": ""},
    {"name": "kubo_reachable", "ok": true, "detail": "peer ID: QmXxx..."}
  ]
}
```

Returns HTTP 503 with `"status": "degraded"` if any check fails.

`GET /health` is a backward-compatible alias for `/healthz/ready`.

Other admin endpoints:
- `GET /healthz/live` — process-alive probe (always 200; no external deps)
- `GET /stats` — article, group, and peer counts
- `GET /log-tip?group=comp.lang.rust` — current group log tip CID
- `GET /peers` — connected peers
- `GET /metrics` — Prometheus text format

---

## Reader daemon

### Configuration

The reader daemon takes a single flag: `--config <path>`.

> **Note**: the reader stores article numbers, the overview index, and the
> message-ID map in on-disk SQLite with WAL mode. State survives restarts.
> A startup backfill re-populates the overview for any article that has a
> number assigned but no overview record (e.g. after a crash mid-write).

Create `reader.toml`:

```toml
[listen]
addr = "0.0.0.0:119"

[limits]
max_connections = 100
command_timeout_secs = 30

[ipfs]
api_url    = "http://127.0.0.1:5001"
cache_path = "/var/cache/stoa/blocks"

[database]
# On-disk SQLite files. Parent directories are created at startup if absent.
# Three files are required — mixing schemas in one file causes migration errors.
reader_path = "/var/lib/stoa/reader/reader.db"
core_path   = "/var/lib/stoa/reader/reader_core.db"
verify_path = "/var/lib/stoa/reader/reader_verify.db"

[auth]
required = false   # set true and add [[auth.users]] for production

# [[auth.users]]
# username = "alice"
# password = "changeme"

[tls]
# Uncomment to enable immediate TLS (NNTPS):
# cert_path = "/etc/ssl/certs/nntp.pem"
# key_path  = "/etc/ssl/private/nntp.key"

[operator]
signing_key_path = "/etc/stoa/reader/operator.key"

[admin]
# Use a different port if reader and transit run on the same host.
addr = "127.0.0.1:9091"

[log]
level = "info"
format = "json"
```

### Start

```bash
# Generate operator key (first time only):
stoa-reader keygen --output /etc/stoa/reader/operator.key

stoa-reader --config reader.toml
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
200 stoa reader ready
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

## Graceful shutdown

Both daemons handle SIGTERM and CTRL-C by draining in-flight connections before
exiting.  The sequence is:

1. Signal received — accept loops stop; new TCP connections get ECONNREFUSED.
2. In-flight NNTP sessions continue until they complete their current command.
3. Transit drains the ingestion queue (pending `block_put` / group log appends).
4. Process exits with code `0` on clean drain, `1` if the drain timeout fired.

### What is drained

| Daemon | What is drained | Notes |
|--------|----------------|-------|
| Reader | All active NNTP/NNTPS sessions (shared semaphore) | Plain and TLS connections share one limit |
| Transit | Staging drain task (flushes queued staging rows) | Stopped first, before ingestion drain |
| Transit | Ingestion queue (pending `block_put` / group log appends) | Dropped sender closes channel; task finishes queue |

### Drain timeout

The default drain timeout is **30 seconds**.  Override in config:

```toml
# reader: crates/reader/src/config.rs → LimitsConfig
[limits]
drain_timeout_secs = 60   # wait up to 60 s before forcing exit

# transit: crates/transit/src/config.rs → PeeringConfig
[peering]
drain_timeout_secs = 60
```

### systemd unit file

Set `TimeoutStopSec` larger than `drain_timeout_secs` to give the process a
chance to exit cleanly before systemd sends SIGKILL:

```ini
[Unit]
Description=stoa transit daemon
After=network.target ipfs.service
Requires=ipfs.service

[Service]
ExecStart=/usr/local/bin/stoa-transit --config /etc/stoa/transit.toml
Restart=on-failure
RestartSec=5s
User=stoa

# Graceful shutdown: send SIGTERM, wait up to 90 s, then SIGKILL.
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
```

Use `TimeoutStopSec=90` (larger than the 30–60 s `drain_timeout_secs`) so the
process has a full drain window before systemd escalates to SIGKILL.

### AWS ECS

Set `stopTimeout` to the maximum allowed value (120 s on ECS/EC2 and Fargate):

```json
{
  "containerDefinitions": [{
    "name": "transit",
    "stopTimeout": 120
  }]
}
```

ECS sends SIGTERM to PID 1, then SIGKILL after `stopTimeout` seconds.
Enable `"initProcessEnabled": true` in the task definition so the init process
relays SIGTERM to the daemon and reaps zombie processes cleanly.

### Drain log messages

Watch for these INFO/WARN log lines during a shutdown:

| Log message | Meaning |
|-------------|---------|
| `draining active connections active_connections=N` | Drain started with N sessions in flight |
| `all connections drained cleanly` | Reader: all sessions finished before timeout |
| `shutting down, draining ingestion queue` | Transit: dropping ingestion channel |
| `ingestion task drained cleanly` | Transit: all queued articles flushed to IPFS |
| `drain timeout exceeded, forcing exit remaining_connections=N` | Timeout fired; N sessions were killed |
| `ingestion drain timeout, forcing exit` | Transit ingestion drain timed out |

Exit code `1` after any of the timeout messages indicates articles may have been
lost.  Check the group log to determine whether the in-flight articles need to
be re-ingested.

---

## Troubleshooting

| Symptom | Likely cause | Action |
|---------|-------------|--------|
| `error: failed to bind 0.0.0.0:119` | Port 119 requires root or `CAP_NET_BIND_SERVICE` | Use port ≥1024 in config, or `sudo setcap cap_net_bind_service=+ep target/release/stoa-transit` |
| `LIST` returns empty | No articles posted yet | POST an article via the reader; groups are discovered from posted articles |
| `GROUP comp.lang.rust` returns `411 No such newsgroup` | No articles in that group | The reader synthesizes groups from posted articles; a group with no articles is not listed |
| Admin endpoint returns 403 | `bearer_token` is configured | Pass `Authorization: Bearer <token>` header |
| Transit logs `v1: peer block fetch not yet implemented` | Gossip reconciliation found missing remote entries | Expected in v1; backfill from peers is a future feature |
| Reader loses articles after restart | `[database]` paths not configured or pointing to a new directory | Set `reader_path`, `core_path`, `verify_path` in `[database]` to persistent paths |

---

## Mail daemon (stoa-mail)

`stoa-mail` is a JMAP (RFC 8620/8621) server that exposes the stoa
article store to email clients such as Fastmail, Thunderbird, and iOS Mail.

> **v1 Limitations**
>
> | Limitation | Detail |
> |-----------|--------|
> | **No EventSource push** | `eventSourceUrl` is advertised but not implemented. Clients must poll. |
> | **cannotCalculateChanges** | `Mailbox/changes` and `Email/changes` always return `cannotCalculateChanges`. Clients perform full re-sync on every session. |
> | **In-memory user_flags** | `\Seen`/`\Flagged` state uses the mail SQLite database and persists, but is per-instance only — not shared across mail server restarts if the database is in-memory. |
> | **Depends on reader stores** | The mail server reads articles from the same SQLite and IPFS as a co-located `stoa-reader`. They must share the same reader database file. |

### Prerequisites

`stoa-mail` must run on the same host as `stoa-reader` and share its
SQLite database file. The reader daemon must be started first.

### Configuration

Create `mail.toml`:

```toml
[listen]
addr = "127.0.0.1:8080"

[tls]
# Uncomment for HTTPS (JMAP requires TLS in production):
# cert_path = "/etc/ssl/certs/jmap.pem"
# key_path  = "/etc/ssl/private/jmap.key"

[database]
# Mail-specific state (per-user flags, subscriptions).
path = "/var/lib/stoa/mail/mail.db"

[auth]
required = false   # set true and add [[auth.users]] for production

# [[auth.users]]
# username = "alice"
# password = "changeme"

[log]
level = "info"
format = "json"
```

### Start

```bash
mkdir -p /var/lib/stoa/mail
stoa-mail --config mail.toml
```

### Create users (manual)

User records live in the mail SQLite database. To add a user, generate a bcrypt hash
and insert directly:

```bash
# Generate bcrypt hash (cost factor 12):
python3 -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt(12)).decode())"

# Insert into database:
sqlite3 /var/lib/stoa/mail/mail.db \
  "INSERT INTO users (username, password_hash) VALUES ('alice', '\$2b\$12\$...');"
```

### Connect a JMAP client

JMAP clients discover the server via the well-known URL:

```
http://127.0.0.1:8080/.well-known/jmap
```

This redirects to `/jmap/session`. Configure your client with:

| Field | Value |
|-------|-------|
| **Server** | `http://127.0.0.1:8080` (or your hostname) |
| **Username** | as configured in `[[auth.users]]` |
| **Password** | as configured |
| **Session URL** | `http://127.0.0.1:8080/jmap/session` |

For Fastmail app, Thunderbird, or iOS Mail — use "Other JMAP server" and enter
the session URL above.

> **Production:** always use HTTPS. JMAP transmits credentials and message content
> in HTTP request bodies. Configure `[tls]` cert/key paths before exposing to any
> non-loopback network.

### Verify

```bash
curl -s http://127.0.0.1:8080/health | python3 -m json.tool
```

Expected:
```json
{"status": "ok", "uptime_secs": 5}
```

Check the JMAP session resource:
```bash
curl -s http://127.0.0.1:8080/jmap/session | python3 -m json.tool
```

---

## OIDC / SSO authentication

`stoa-mail` (JMAP) and `stoa-reader` (NNTP `AUTHINFO SASL OAUTHBEARER`) both
support JWT Bearer token authentication via OpenID Connect (OIDC).  Configure
one `[[auth.oidc_providers]]` entry per identity provider.  Multiple providers
are tried in order; the first that accepts the JWT wins.

The provider is discovered via its `/.well-known/openid-configuration` endpoint.
JWKS keys are fetched lazily on first use and cached for one hour.  On key
rotation (unknown `kid`), the cache is force-refreshed once.

Only RSA algorithms (RS256, RS384, RS512, PS256, PS384, PS512) are accepted.
The `none` algorithm is always rejected.

### AWS Cognito

1. Create a User Pool and an App Client with the grant type `client_credentials`
   (for machine-to-machine) or `authorization_code` (for user-facing flows).
2. Note the **User Pool ID** and **AWS region** — the issuer URL is:
   `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>`
3. The **audience** (`aud` claim) is the App Client ID.
4. Default token signing: RS256.

```toml
[[auth.oidc_providers]]
issuer   = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX"
audience = "your-cognito-app-client-id"
# username_claim defaults to "email"; change to "cognito:username" if preferred:
username_claim = "cognito:username"
```

> If your Cognito pool enforces a custom domain, use that as the issuer URL
> (e.g. `https://auth.example.com/`).

### Microsoft Entra ID (Azure AD)

1. Register an application in the Azure portal.
2. Note the **Tenant ID** and **Client ID** (Application ID).
3. Issuer URL: `https://login.microsoftonline.com/<tenant-id>/v2.0`
4. Audience is the Client ID.
5. Default token signing: RS256.

```toml
[[auth.oidc_providers]]
issuer   = "https://login.microsoftonline.com/your-tenant-id/v2.0"
audience = "your-application-client-id"
username_claim = "preferred_username"
```

> For multi-tenant apps, replace the tenant ID with `common` or `organizations`.

### Okta

1. Create an Authorization Server (or use the default `https://<domain>/oauth2/default`).
2. Create an Application (Web or Service) and note the **Client ID**.
3. Issuer URL: `https://<okta-domain>/oauth2/default` (or your custom AS URL).
4. Audience is the `aud` value from the authorization server settings (often `api://default`).

```toml
[[auth.oidc_providers]]
issuer   = "https://dev-XXXXXXXX.okta.com/oauth2/default"
audience = "api://default"
username_claim = "sub"
```

### Multiple providers

Stacking multiple `[[auth.oidc_providers]]` entries is supported — each request
is tried against each provider in order until one succeeds:

```toml
[[auth.oidc_providers]]
issuer   = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AAAAAAAAA"
audience = "client-id-for-internal-apps"
username_claim = "cognito:username"

[[auth.oidc_providers]]
issuer   = "https://login.microsoftonline.com/tenant-id/v2.0"
audience = "azure-app-client-id"
username_claim = "preferred_username"
```

### NNTP SASL OAUTHBEARER

When `[[auth.oidc_providers]]` is configured, `stoa-reader` advertises
`SASL OAUTHBEARER` in `CAPABILITIES`.  NNTP clients send:

```
AUTHINFO SASL OAUTHBEARER <base64(n,,\x01auth=Bearer <jwt>\x01\x01)>
```

Only NNTPS (implicit TLS, port 563) connections are required when
`[auth] required = true`; plaintext connections receive `483 Encryption
required` for any `AUTHINFO` command.

### Coexistence with password auth

OIDC and bcrypt password auth coexist.  For JMAP Bearer tokens that look like
JWTs (exactly two dots), OIDC validation is attempted first.  Self-issued tokens
(opaque strings from `/jmap/session`) always fall through to the token store.

---

## Migrating to `[backend]` block store configuration

The `[ipfs]` config section is still supported and is not being removed, but
new deployments should use the `[backend]` section instead. Future backends
(S3, filesystem) will only be configurable via `[backend]`.

### Transit daemon

Before (legacy — still works):
```toml
[ipfs]
api_url = "http://127.0.0.1:5001"
```

After (new style):
```toml
[backend]
type = "kubo"

[backend.kubo]
api_url = "http://127.0.0.1:5001"
```

When `[backend]` is present it takes precedence over `[ipfs]`. You may keep
`[ipfs]` in the file during a rolling upgrade — it will be ignored.

### Reader daemon

Before (legacy — still works):
```toml
[ipfs]
api_url = "http://127.0.0.1:5001"
cache_path = "/var/cache/reader-blocks"
```

After (new style):
```toml
[backend]
type = "kubo"

[backend.kubo]
api_url = "http://127.0.0.1:5001"
cache_path = "/var/cache/reader-blocks"
```

### Unimplemented backends

`type = "s3"` and `type = "filesystem"` are accepted by the parser but will
cause a hard startup error ("not yet implemented"). They are placeholders for
future epics.

---

## Kubernetes and ECS health probes

### Liveness vs readiness

| Probe | Endpoint | When 200 | When to use |
|-------|----------|----------|-------------|
| **Liveness** | `GET /healthz/live` | Always (process is running) | Kubernetes `livenessProbe` — restart the pod if the process hangs |
| **Readiness** | `GET /healthz/ready` | SQLite and Kubo are reachable | Kubernetes `readinessProbe` / ALB target group — remove from rotation while starting up or degraded |

A daemon that is alive but not yet connected to Kubo should fail readiness without failing liveness.  Kubernetes will stop sending traffic but will not restart the pod.

### Kubernetes probe configuration

```yaml
livenessProbe:
  httpGet:
    path: /healthz/live
    port: 9090          # [admin] port in transit.toml
  initialDelaySeconds: 5
  periodSeconds: 15
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /healthz/ready
    port: 9090
  initialDelaySeconds: 10   # allow time for Kubo to connect
  periodSeconds: 10
  failureThreshold: 3
```

If the admin endpoint requires a bearer token, inject it as an HTTP header:

```yaml
readinessProbe:
  httpGet:
    path: /healthz/ready
    port: 9090
    httpHeaders:
      - name: Authorization
        value: Bearer $(ADMIN_TOKEN)
```

### ECS health check configuration

```json
{
  "healthCheck": {
    "command": [
      "CMD-SHELL",
      "curl -sf -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:9090/healthz/ready || exit 1"
    ],
    "interval": 15,
    "timeout": 5,
    "retries": 3,
    "startPeriod": 30
  }
}
```

### ALB target group health check

- **Path**: `/healthz/ready`
- **Port**: admin port (e.g. 9090)
- **Protocol**: HTTP
- **Healthy threshold**: 2
- **Unhealthy threshold**: 3
- **Timeout**: 5 s
- **Interval**: 15 s

> The admin endpoint should be bound to loopback (`127.0.0.1`) for security.
> Route ALB health checks through a sidecar or NLB that forwards only to the admin port.

---

## See also

- `docs/ops/configuration_reference.md` — full field-by-field reference
- `docs/ops/peering_guide.md` — detailed peering setup
- `docs/ops/retention_guide.md` — pinning and GC policy configuration
- `docs/threat_model.md` — security considerations
