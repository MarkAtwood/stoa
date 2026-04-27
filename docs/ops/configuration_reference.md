# Configuration Reference

This document describes every configuration field for both `stoa-transit`
and `stoa-reader`. Configuration is TOML; each daemon reads its file at
startup via `Config::from_file`. Unknown keys are rejected with a parse error.

Required sections must be present in the file. Optional sections may be omitted;
their defaults are noted per-field.

---

## stoa-transit

Config struct: `crates/transit/src/config.rs::Config`

Required sections: `[listen]`, `[peers]`, `[groups]`, `[ipfs]`, `[pinning]`, `[gc]`

Optional sections: `[admin]`, `[log]`

### `[listen]`

Controls the inbound NNTP peering listener.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | — (required) | `"host:port"` to bind the NNTP listener. Use `"0.0.0.0:119"` to accept on all interfaces. Must not be empty. |

Example:

```toml
[listen]
addr = "0.0.0.0:119"
```

---

### `[peers]`

Configures outbound NNTP peering targets.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addresses` | array of strings | — (required) | List of `"host:port"` addresses of remote NNTP peering peers. May be empty if the node operates as a sink only. Each address is a stoa or INN transit peer. |

Example:

```toml
[peers]
addresses = [
    "192.0.2.10:119",
    "peer2.example.com:119",
]
```

---

### `[groups]`

Defines the set of groups this node subscribes to.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `names` | array of strings | — (required) | List of group names to subscribe to. Each name must be a lowercase dot-separated identifier. Components must match `[a-z0-9+\-_]+`. Uppercase letters and empty components are rejected at startup. |

Example:

```toml
[groups]
names = [
    "comp.lang.rust",
    "comp.lang.c",
    "alt.test",
]
```

---

### `[ipfs]`

Configures the connection to the IPFS node.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_url` | string | — (required) | HTTP URL of the IPFS node API endpoint. Must not be empty. Default Kubo address is `"http://127.0.0.1:5001"`. All article writes and fetches go through this endpoint. |

Example:

```toml
[ipfs]
api_url = "http://127.0.0.1:5001"
```

---

### `[pinning]`

Controls which articles are pinned in IPFS. Pinning is explicit opt-in;
articles not matched by any rule are not pinned and become eligible for GC.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rules` | array of strings | — (required, must be non-empty) | Ordered list of pinning rule identifiers or `[[pinning.rules]]` table entries (see below). Must contain at least one entry. The first matching rule determines the outcome. |

#### Shorthand rule strings

The following string values are recognized in the `rules` array:

| Value | Meaning |
|-------|---------|
| `"pin-all"` | Pin every article, regardless of group, age, or size. |
| `"pin-all-ingress"` | Alias for `"pin-all"`. Explicit label for intent. |

#### Fine-grained pinning rules (`[[pinning.rules]]`)

For per-group or age/size-bounded pinning, declare one or more
`[[pinning.rules]]` tables. Rules are evaluated in declaration order; the
first rule whose conditions all match determines the outcome.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `groups` | string | — (required) | Group pattern. `"all"` matches every group. `"comp.*"` or `"comp.**"` matches any group whose name begins with `"comp."`. An exact name such as `"comp.lang.rust"` matches only that group. Pattern components must be valid dotted-label syntax. |
| `max_age_days` | integer | none (no age limit) | If set, the rule only matches articles whose age (from the `Date:` header) is at most this many days. A value of `0` with `groups = "all"` is rejected as a useless rule. |
| `max_article_bytes` | integer | none (no size limit) | If set, the rule only matches articles whose wire size is at most this many bytes. |
| `action` | string | — (required) | `"pin"` to pin matching articles; `"skip"` to leave them unpinned and eligible for GC. |

Example with fine-grained rules:

```toml
[pinning]
# The rules array must still be present; it names the [[pinning.rules]] tables.
# Use the table form for fine-grained control.
rules = []

[[pinning.rules]]
groups = "comp.*"
max_age_days = 180
action = "pin"

[[pinning.rules]]
groups = "alt.*"
max_age_days = 30
max_article_bytes = 102400
action = "pin"

[[pinning.rules]]
groups = "all"
action = "skip"
```

Startup validation rejects:

- An empty `pinning.rules` list with no `[[pinning.rules]]` tables.
- A rule with an invalid `groups` pattern (e.g. uppercase, empty component).
- A rule with `max_age_days = 0` and `groups = "all"` (matches nothing; useless).
- Duplicate `groups` patterns across rules emit a startup warning (not an error).

---

### `[gc]`

Controls the garbage collection schedule. GC removes articles from IPFS that
are not pinned and whose age exceeds `max_age_days`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schedule` | string | — (required) | Standard 5-field UTC cron expression for when GC runs. Example: `"0 3 * * *"` runs at 03:00 UTC daily. |
| `max_age_days` | integer | — (required) | Articles older than this many days that are not pinned are eligible for GC. Must be a positive integer. |

Example:

```toml
[gc]
schedule = "0 3 * * *"
max_age_days = 90
```

---

### `[admin]`

Controls the HTTP admin endpoint used by the operator CLI (`stoa-transit status`
and related subcommands). This section is optional; all fields have defaults.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | `"127.0.0.1:9090"` | `"host:port"` to bind the admin HTTP endpoint. Default is loopback-only. |
| `bearer_token` | string | none | If set, all admin HTTP requests must include `Authorization: Bearer <token>`. In production, always set this when `addr` is non-loopback. When unset and `addr` is non-loopback, a warning is logged at startup. |
| `rate_limit_rpm` | integer | `60` | Maximum admin HTTP requests per minute per source IP. Set to `0` to disable rate limiting (not recommended on non-loopback addresses). |

Example:

```toml
[admin]
addr = "127.0.0.1:9090"
bearer_token = "replace-with-a-strong-random-token"
rate_limit_rpm = 60
```

---

### `[log]`

Controls log output. This section is optional; all fields have defaults.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | string | `"info"` | Log level or filter string. Simple values: `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`. Filter syntax: `"stoa_transit=debug,info"` (per-crate directives). Overridden at runtime by the `RUST_LOG` environment variable. |
| `format` | string | `"json"` | Output format. `"json"` emits structured JSON (recommended for log aggregation). `"text"` emits human-readable lines (useful in development). |

Example:

```toml
[log]
level = "info"
format = "json"
```

---

## stoa-reader

Config struct: `crates/reader/src/config.rs::Config`

Required sections: `[listen]`, `[limits]`, `[auth]`, `[tls]`

Optional sections: `[admin]`, `[log]`

**Note on CID extensions:** The five NNTP CID extensions (`X-Stoa-CID`
header, `X-Stoa-Root-CID` header, `XCID` command, `XVERIFY` command,
`ARTICLE cid:` locator) are always enabled and require no configuration.
They are advertised in `CAPABILITIES` automatically. See `docs/wire_format.md`
§12 for the full protocol specification.

### `[listen]`

Controls the NNTP client-facing listener.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | — (required) | `"host:port"` to bind the NNTP listener. Port 119 is standard plain-text NNTP (with optional STARTTLS upgrade). Port 563 is conventional for immediate NNTPS when TLS is configured. Must not be empty. |

Example:

```toml
[listen]
addr = "0.0.0.0:119"
```

---

### `[limits]`

Controls connection and session limits.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_connections` | integer | `100` | Maximum number of concurrent client connections. Must be greater than 0. The daemon rejects new connections when this limit is reached. |
| `command_timeout_secs` | integer | — (required) | Seconds to wait for a client command before closing an idle connection. |

Example:

```toml
[limits]
max_connections = 100
command_timeout_secs = 30
```

---

### `[auth]`

Controls AUTHINFO USER/PASS authentication per RFC 4643. Authentication state
is recorded in the append-only audit log on every attempt.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `required` | boolean | — (required) | When `true`, clients must successfully authenticate before accessing any group or article commands. When `false`, unauthenticated access is permitted. |
| `users` | array of `[[auth.users]]` tables | `[]` | User credentials for AUTHINFO USER/PASS. See the sub-table fields below. If `required = false` and this list is empty, all credential attempts succeed without validation (development mode; never use in production). |

#### `[[auth.users]]`

Each entry in the users array has the following fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `username` | string | — (required) | The AUTHINFO username string. Case-sensitive. |
| `password` | string | — (required) | The AUTHINFO password. Compared in constant time. Store securely; do not commit credentials to VCS. |

Example:

```toml
[auth]
required = true

[[auth.users]]
username = "alice"
password = "correct-horse-battery-staple"

[[auth.users]]
username = "bob"
password = "hunter2"
```

Development mode (no authentication):

```toml
[auth]
required = false
# users list absent or empty: all credential attempts succeed
```

---

### `[tls]`

Controls TLS for client connections. Both fields must be set together or both
must be absent; a partial configuration is rejected at startup.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cert_path` | string or absent | none | Filesystem path to a PEM-encoded TLS certificate (including any intermediate chain). When set together with `key_path`, every connection is immediately upgraded to TLS before the NNTP greeting (NNTPS mode). |
| `key_path` | string or absent | none | Filesystem path to the PEM-encoded private key corresponding to `cert_path`. |

When both fields are absent, the daemon starts in plain-text mode and
advertises `STARTTLS` in the `CAPABILITIES` response. Clients that send
`STARTTLS` receive an in-session TLS upgrade via tokio-rustls.

When both fields are set, the daemon binds in immediate-TLS mode. Consider
using port 563 when operating in NNTPS mode.

Example (immediate TLS):

```toml
[tls]
cert_path = "/etc/ssl/certs/nntp-server.pem"
key_path  = "/etc/ssl/private/nntp-server.key"
```

Example (STARTTLS / plain-text with upgrade):

```toml
[tls]
# Both fields absent: plain-text listener, STARTTLS offered in CAPABILITIES.
```

---

### `[admin]`

Controls the HTTP admin endpoint. This section is optional; all fields have
defaults.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | `"127.0.0.1:9090"` | `"host:port"` to bind the admin HTTP endpoint. Default is loopback-only. |

Note: the reader's `[admin]` section does not include `bearer_token` or
`rate_limit_rpm` fields (those exist only in the transit config struct).

Example:

```toml
[admin]
addr = "127.0.0.1:9090"
```

---

### `[log]`

Controls log output. This section is optional; all fields have defaults.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | string | `"info"` | Log level or filter string. Simple values: `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`. Filter syntax: `"stoa_reader=debug,info"`. Overridden at runtime by the `RUST_LOG` environment variable. |
| `format` | string | `"json"` | Output format. `"json"` emits structured JSON. `"text"` emits human-readable lines. |

Example:

```toml
[log]
level = "info"
format = "json"
```

---

## Startup Validation Summary

Both daemons validate their config at startup and exit with a non-zero status
if any constraint is violated. The following table summarises validation rules
enforced by the config layer (additional semantic checks occur at runtime):

### Transit

| Constraint | Error type |
|------------|-----------|
| `listen.addr` is empty | Validation |
| `ipfs.api_url` is empty | Validation |
| `pinning.rules` is empty (and no `[[pinning.rules]]` tables) | Validation |
| Any name in `groups.names` contains an uppercase letter, empty component, or invalid character | Validation |
| A `[[pinning.rules]]` entry has an invalid `groups` pattern | Validation |
| A `[[pinning.rules]]` entry has `max_age_days = 0` and `groups = "all"` | Validation |
| `[listen]` section absent | Parse |
| Any required section absent | Parse |

### Reader

| Constraint | Error type |
|------------|-----------|
| `listen.addr` is empty | Validation |
| `limits.max_connections` is 0 | Validation |
| Exactly one of `tls.cert_path` or `tls.key_path` is set (partial TLS config) | Validation |
| `[listen]` section absent | Parse |
| Any required section absent | Parse |

---

## Environment Variable Overrides

| Variable | Effect |
|----------|--------|
| `RUST_LOG` | Overrides `log.level` in both daemons. Accepts the same filter syntax as the `level` field. |

No other configuration fields are overridable via environment variables.
Secrets (operator key path, bearer token) are set in the config file, not via
environment variables, to avoid leakage through `/proc/*/environ`.
