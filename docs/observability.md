# Observability

This document describes the observability surface of the stoa system:
Prometheus metrics exported by both daemons, the admin HTTP API served by the
transit daemon, structured log fields emitted via `tracing`, and practical
PromQL queries for dashboards and alerts.

## Table of contents

1. [Prometheus metrics](#prometheus-metrics)
   - [Transit daemon metrics](#transit-daemon-metrics)
   - [GC runner metrics](#gc-runner-metrics)
   - [Reader daemon metrics](#reader-daemon-metrics)
   - [Histogram bucket reference](#histogram-bucket-reference)
2. [Admin HTTP endpoints (transit)](#admin-http-endpoints-transit)
   - [Authentication](#authentication)
   - [GET /health](#get-health)
   - [GET /stats](#get-stats)
   - [GET /log-tip](#get-log-tip)
   - [GET /peers](#get-peers)
   - [GET /metrics](#get-metrics)
3. [Structured log fields](#structured-log-fields)
   - [NNTP session lifecycle (reader)](#nntp-session-lifecycle-reader)
   - [GC runner (transit)](#gc-runner-transit)
   - [Admin and metrics servers (transit)](#admin-and-metrics-servers-transit)
4. [Example PromQL queries](#example-promql-queries)

---

## Prometheus metrics

Both daemons export metrics in Prometheus text format 0.0.4. The transit daemon
serves them via its standalone metrics server and also via the admin server's
`/metrics` endpoint. The reader daemon serves them via its own metrics server.

### Transit daemon metrics

Registered in `crates/transit/src/metrics.rs`.

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `articles_ingested_total` | counter | — | Total articles accepted and ingested by the transit daemon across all groups and peers. |
| `articles_ingested_group_total` | counter | `group` | Articles ingested, partitioned by newsgroup name (e.g. `comp.lang.rust`). |
| `articles_rejected_total` | counter | `reason` | Articles rejected during ingestion. See reason values below. |
| `articles_served_total` | counter | — | Total articles served by the reader daemon (registered in the transit metrics module for shared access). |
| `ipfs_write_latency_seconds` | histogram | — | End-to-end latency of IPFS block write operations in seconds. |
| `gc_articles_unpinned_total` | counter | — | Total number of articles unpinned by the garbage collector across all GC runs. |
| `gossip_messages_published_total` | counter | — | Total gossipsub messages published to any topic. |
| `gossip_messages_dropped_total` | counter | — | Total gossipsub messages dropped (queue full, validation failure, etc.). |
| `peer_connections_active` | gauge | — | Number of currently active libp2p peer connections. |
| `groups_served` | gauge | — | Number of newsgroups currently served by this node. |
| `pinned_articles_total` | gauge | — | Current count of articles pinned in IPFS. |
| `nntp_command_duration_seconds` | histogram | `command` | Duration of NNTP command handling in the transit daemon, labeled by uppercase command name. |

**`articles_rejected_total` — known `reason` label values**

| Value | Meaning |
|---|---|
| `duplicate` | Message-ID already present in the `msgid_map` store. |
| `malformed` | Invalid Message-ID format, or one or more mandatory headers (`From`, `Date`, `Message-ID`, `Newsgroups`, `Subject`) missing. |
| `size_exceeded` | Article byte count exceeds the 1 MiB ingest limit. |

**`nntp_command_duration_seconds` — known `command` label values**

The label is the uppercase first token of the NNTP command line as received
from the peer. Any RFC 3977 or RFC 4644 command name may appear. Examples
observed in tests: `ARTICLE`, `CAPABILITIES`, `GROUP`, `HEAD`, `OVER`, `POST`.

### GC runner metrics

The GC runner in `crates/transit/src/retention/gc.rs` maintains its own atomic
counters and exposes them via a separate `GcRunner::prometheus_text()` method.
These metrics are not registered in the global Prometheus registry used by
`gather_metrics()`; they must be included in the metrics response by the caller
that owns the `GcRunner` instance.

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `gc_articles_unpinned_total` | counter | — | Total articles unpinned by GC across all runs (also tracked in the global registry; the GC runner copy is the authoritative in-process counter). |
| `gc_last_run_duration_ms` | gauge | — | Duration of the most recent GC run in milliseconds. Resets to 0 until the first run completes. |

### Reader daemon metrics

Registered in `crates/reader/src/metrics.rs`.

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `nntp_command_duration_seconds` | histogram | `command` | Duration of NNTP command handling in the reader daemon, labeled by uppercase command name. Shares the same metric name and bucket widths as the transit copy; because both daemons run in separate processes they do not conflict. |

**`nntp_command_duration_seconds` — known `command` label values (reader)**

Examples observed in tests: `ARTICLE`, `CAPABILITIES`, `GROUP`, `HEAD`, `OVER`, `POST`.

### Histogram bucket reference

Both `ipfs_write_latency_seconds` and `nntp_command_duration_seconds` use the
same bucket boundaries:

| Upper bound (seconds) | Typical scope |
|---|---|
| 0.001 | Sub-millisecond (cache hit, trivial command) |
| 0.005 | Fast local operation |
| 0.010 | Typical SQLite read |
| 0.050 | Light IPFS block fetch |
| 0.100 | Moderate IPFS or network operation |
| 0.500 | Slow IPFS write or multi-hop network |
| 1.000 | Very slow; warrants investigation |
| 5.000 | Timeout territory |
| +Inf | Catch-all |

---

## Admin HTTP endpoints (transit)

The transit daemon starts an HTTP server on a configurable address (bind to
loopback in production). It serves a small set of JSON endpoints for operator
inspection, plus the Prometheus metrics endpoint.

### Authentication

If a bearer token is configured, every request must include:

```
Authorization: Bearer <token>
```

Requests without the header, or with the wrong token, receive `401 Unauthorized`:

```json
{"error": "unauthorized"}
```

If no token is configured, all requests are accepted without authentication.

The string comparison is not constant-time. This endpoint is intended for
loopback/ops use only. Do not expose it to the public internet without a
reverse proxy that enforces mTLS or equivalent.

### GET /health

Liveness check. Returns immediately without touching the database.

**Response** `200 OK`, `Content-Type: application/json`

```json
{
  "status": "ok",
  "uptime_secs": 3742
}
```

| Field | Type | Description |
|---|---|---|
| `status` | string | Always `"ok"` when the process is running. |
| `uptime_secs` | integer (u64) | Seconds elapsed since the daemon started. |

**Example**

```bash
curl -s http://127.0.0.1:8081/health
curl -s -H "Authorization: Bearer mysecret" http://127.0.0.1:8081/health
```

### GET /stats

Live counts from SQLite. Queries four tables: `msgid_map`, `pinned_cids`,
`articles` (distinct group names), and `peers` (non-blacklisted).

**Response** `200 OK`, `Content-Type: application/json`

```json
{
  "articles": 142857,
  "pinned_cids": 98304,
  "groups": 47,
  "peers": 12
}
```

| Field | Type | Description |
|---|---|---|
| `articles` | integer (i64) | Rows in `msgid_map` — total known articles. |
| `pinned_cids` | integer (i64) | Rows in `pinned_cids` — articles currently pinned in IPFS. |
| `groups` | integer (i64) | Distinct `group_name` values in the `articles` table. |
| `peers` | integer (i64) | Peers where `blacklisted_until` is NULL or 0. |

On database error: `500 Internal Server Error`, `{"error":"internal server error"}`.

**Example**

```bash
curl -s http://127.0.0.1:8081/stats | jq .
```

### GET /log-tip

Returns the tip CID and entry count for a single group's Merkle-CRDT log.
Used to compare state between peers and diagnose replication lag.

**Query parameter**

| Parameter | Required | Description |
|---|---|---|
| `group` | yes | Full newsgroup name, e.g. `comp.lang.rust`. |

**Response** `200 OK`, `Content-Type: application/json`

```json
{
  "group": "comp.lang.rust",
  "tip_cid": "bafyreig...",
  "entry_count": 8192
}
```

| Field | Type | Description |
|---|---|---|
| `group` | string | The group name echoed from the query parameter. |
| `tip_cid` | string | CIDv1 string of the most recent log entry. |
| `entry_count` | integer (i64) | Maximum `sequence_number` in `group_log` for this group. |

- `400 Bad Request` if `group` parameter is absent: `{"error":"missing group parameter"}`
- `404 Not Found` if the group has no log entries: `{"error":"group not found"}`

**Example**

```bash
curl -s "http://127.0.0.1:8081/log-tip?group=comp.lang.rust" | jq .
```

### GET /peers

Returns the list of active (non-blacklisted) peers from the `peers` table.

**Response** `200 OK`, `Content-Type: application/json`

```json
[
  {"peer_id": "12D3KooW...", "addr": "/ip4/203.0.113.5/tcp/4001"},
  {"peer_id": "12D3KooW...", "addr": "/ip4/198.51.100.2/tcp/4001"}
]
```

| Field | Type | Description |
|---|---|---|
| `peer_id` | string | libp2p `PeerId` in base58 encoding. |
| `addr` | string | Multiaddr of the peer. |

Returns `[]` if no active peers are known.

On database error: `500 Internal Server Error`, `{"error":"internal server error"}`.

**Example**

```bash
curl -s http://127.0.0.1:8081/peers | jq 'length'
```

### GET /metrics

Prometheus text format 0.0.4. Delegates to `crates/transit/src/metrics::gather_metrics()`.

**Response** `200 OK`, `Content-Type: text/plain; version=0.0.4`

```
# HELP articles_ingested_total Total number of articles ingested by the transit daemon
# TYPE articles_ingested_total counter
articles_ingested_total 142857
...
```

This endpoint is also available on the standalone metrics server port (if
configured separately from the admin server).

**Example**

```bash
curl -s http://127.0.0.1:9090/metrics
# or via the admin port:
curl -s http://127.0.0.1:8081/metrics
```

---

## Structured log fields

Both daemons use the `tracing` crate with structured key-value fields. The
fields below are the ones actually emitted in the codebase; this is not an
exhaustive list of all possible span fields.

### NNTP session lifecycle (reader)

Source: `crates/reader/src/session/lifecycle.rs`

**Span / event: session start**

Emitted at `INFO` level when a new connection begins its protocol loop.

| Field | Type | Example | Description |
|---|---|---|---|
| `peer` | socket address | `203.0.113.5:49152` | Remote address of the connecting client. |

Log message: `"plain session started"` or `"session started"` (TLS path).

**Span / event: session end**

Emitted at `INFO` level when the session loop exits (client QUIT, disconnect,
or error).

| Field | Type | Example | Description |
|---|---|---|---|
| `peer` | socket address | `203.0.113.5:49152` | Remote address of the connecting client. |
| `elapsed_ms` | integer (u128) | `4821` | Total session duration in milliseconds. |

Log message: `"plain session ended"` or `"session ended"` (TLS path).

**Event: command received**

Emitted at `DEBUG` level for every NNTP command line received.

| Field | Type | Example | Description |
|---|---|---|---|
| `peer` | socket address | `203.0.113.5:49152` | Remote address. |
| `cmd` | string | `GROUP comp.lang.rust` | Raw command line as received (may include arguments). |

Log message: `"received"`.

**Event: client disconnected**

Emitted at `DEBUG` level on EOF (zero-byte read).

| Field | Type | Example | Description |
|---|---|---|---|
| `peer` | socket address | `203.0.113.5:49152` | Remote address. |

Log message: `"client disconnected"`.

### GC runner (transit)

Source: `crates/transit/src/retention/gc.rs`

**Event: article unpinned**

Emitted at `INFO` level for each article successfully unpinned in a GC pass.

| Field | Type | Example | Description |
|---|---|---|---|
| `cid` | string | `bafyreig...` | CIDv1 of the unpinned article. |
| `group` | string | `comp.lang.rust` | Newsgroup the article belongs to. |

Log message: `"GC: unpinned article"`.

**Event: unpin failed**

Emitted at `WARN` level when an unpin call returns an error.

| Field | Type | Example | Description |
|---|---|---|---|
| `cid` | string | `bafyreig...` | CIDv1 of the article that could not be unpinned. |

Log message: `"GC: unpin failed: <error>"`.

**Event: GC run complete**

Emitted at `INFO` level at the end of each GC pass.

| Field | Type | Example | Description |
|---|---|---|---|
| `unpinned` | integer (u64) | `42` | Number of articles unpinned in this pass. |
| `elapsed_ms` | integer (u64) | `318` | Wall-clock duration of this GC pass in milliseconds. |

Log message: `"GC run complete"`.

### Admin and metrics servers (transit)

Source: `crates/transit/src/admin.rs`, `crates/transit/src/metrics.rs`

These servers emit unstructured `WARN` events for bind failures, accept errors,
and per-connection errors. No structured key-value fields beyond the error
message string. Example messages:

- `"admin server failed to bind <addr>: <error>"` — `WARN`
- `"admin server listening on <addr>"` — `INFO`
- `"admin connection error from <peer>: <error>"` — `WARN`
- `"metrics server failed to bind <addr>: <error>"` — `WARN`
- `"metrics server listening on <addr>"` — `INFO`
- `"metrics connection error from <peer>: <error>"` — `WARN`

---

## Example PromQL queries

### Article ingest rate per minute

Total articles ingested across all groups, as a per-minute rate:

```promql
rate(articles_ingested_total[1m]) * 60
```

### GC unpin rate (articles per hour)

```promql
rate(gc_articles_unpinned_total[5m]) * 3600
```

### NNTP p99 command latency — overall

Across all command types, 99th percentile latency:

```promql
histogram_quantile(0.99, sum(rate(nntp_command_duration_seconds_bucket[5m])) by (le))
```

### NNTP p99 command latency — per command

99th percentile latency broken out by command name:

```promql
histogram_quantile(0.99,
  sum(rate(nntp_command_duration_seconds_bucket[5m])) by (le, command)
)
```

### Per-group ingestion rate (top 10 groups)

Articles ingested per minute for the ten most active groups:

```promql
topk(10, rate(articles_ingested_group_total[1m]) * 60)
```

### Article rejection rate by reason

Rate of rejections per minute, split by rejection reason:

```promql
rate(articles_rejected_total[1m]) * 60
```

To see only a specific reason (e.g. duplicate articles):

```promql
rate(articles_rejected_total{reason="duplicate"}[1m]) * 60
```

### Gossipsub drop ratio

Fraction of gossip messages dropped versus published, as a ratio:

```promql
rate(gossip_messages_dropped_total[5m])
  /
(rate(gossip_messages_published_total[5m]) + rate(gossip_messages_dropped_total[5m]))
```

### IPFS write latency p95

95th percentile IPFS block write latency:

```promql
histogram_quantile(0.95, rate(ipfs_write_latency_seconds_bucket[5m]))
```
