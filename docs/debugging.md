# Debugging and Operations Guide

This guide covers the tools available for diagnosing a running stoa
deployment: log levels, the admin HTTP endpoint, the operator CLI subcommands,
and direct SQLite queries.

---

## 1. Verbose Logging

Both `stoa-transit` and `stoa-reader` use the `tracing` crate
with `RUST_LOG`-controlled filtering. The default level when `RUST_LOG` is
unset is `info`.

### Syntax

`RUST_LOG` accepts a comma-separated list of `target=level` directives, or a
bare level name to set the global default.

```
# Only the transit daemon at debug, everything else at info
RUST_LOG=stoa_transit=debug stoa-transit --config /etc/transit.toml

# Only the reader at debug
RUST_LOG=stoa_reader=debug stoa-reader --config /etc/reader.toml

# Everything at debug (very verbose — includes libp2p internals)
RUST_LOG=debug stoa-transit --config /etc/transit.toml

# Per-module precision
RUST_LOG=stoa_transit::peering=debug,stoa_transit::gossip=debug \
    stoa-transit --config /etc/transit.toml
```

### Log levels

| Level   | Use                                                        |
|---------|------------------------------------------------------------|
| `error` | Unrecoverable errors that prevent normal operation         |
| `warn`  | Degraded operation: peer blacklisted, log append failed, audit buffer full |
| `info`  | Normal lifecycle events (startup, shutdown, session open/close) |
| `debug` | Per-connection and per-message events; high volume in production |

### Key log events to look for

**Daemon startup (transit)**
```
INFO stoa_transit: stoa-transit starting
  listen_addr=0.0.0.0:119 peer_count=2 group_count=3
```

**Daemon startup (reader)**
```
INFO stoa-reader: stoa-reader starting
  listen_addr=0.0.0.0:119 max_connections=100
```

**Reader session lifecycle**
```
INFO stoa_reader::session::lifecycle: session started peer=192.0.2.42:54321
INFO stoa_reader::session::lifecycle: session ended
  peer=192.0.2.42:54321 elapsed_ms=1243
```

**Reader command trace (debug level)**
```
DEBUG stoa_reader::session::lifecycle: received
  peer=192.0.2.42:54321 cmd="GROUP comp.lang.rust"
```

**Gossipsub swarm (debug level)**
```
INFO  stoa_transit::gossip::swarm: gossipsub swarm listening
  address=/ip4/0.0.0.0/tcp/4001
DEBUG stoa_transit::gossip::swarm: subscribed to topic
  topic=stoa.hier.comp
DEBUG stoa_transit::gossip::swarm: peer subscribed
  peer_id=12D3KooWExample topic=stoa.hier.comp
DEBUG stoa_transit::gossip::swarm: connection established
  peer_id=12D3KooWExample
DEBUG stoa_transit::gossip::swarm: connection closed
  peer_id=12D3KooWExample
```

**Article ingestion (warn on problems)**
```
WARN  stoa_transit::peering::pipeline: invalid group name in Newsgroups: "Comp.Lang.Rust"
WARN  stoa_transit::peering::pipeline: log append failed for group comp.lang.rust: ...
```

**Peer blacklisting**
```
WARN  stoa_transit::peering::blacklist: peer blacklisted after exceeding failure threshold
  peer_id=12D3KooWExample consecutive_failures=10 blacklisted_until_ms=1700003600000
```

**Audit logger problems**
```
WARN  stoa_core::audit: audit log buffer full; event dropped
WARN  stoa_core::audit: audit logger shut down; event dropped
```

### Systemd integration

When running under systemd, `RUST_LOG` can be set in the unit's `[Service]`
section:

```ini
[Service]
Environment=RUST_LOG=stoa_transit=debug
ExecStart=/usr/local/bin/stoa-transit --config /etc/stoa/transit.toml
```

Log output goes to the journal. View it with:

```
journalctl -u stoa-transit -f
```

---

## 2. Admin HTTP Endpoint

Both daemons expose an admin HTTP endpoint for runtime inspection.

### Configuration

In `transit.toml` or `reader.toml`:

```toml
[admin]
addr = "127.0.0.1:9090"
# allow_non_loopback = false
```

The default is `127.0.0.1:9090`. If you bind to a non-loopback address without
setting `allow_non_loopback = true`, the daemon will log a warning at startup:

```
WARN stoa-transit: WARNING: admin endpoint bound to non-loopback
address '0.0.0.0:9090' without authentication. Set admin.allow_non_loopback
= true in config to suppress this warning, or bind to 127.0.0.1.
```

The admin endpoint carries no authentication. Keep it on loopback, or
restrict it with a firewall rule.

### `/metrics` — Prometheus metrics

Returns Prometheus text-format metrics for the transit daemon.

```
curl -s http://127.0.0.1:9090/metrics
```

Example output:

```
# HELP articles_ingested_total Total number of articles ingested by the transit daemon
# TYPE articles_ingested_total counter
articles_ingested_total 4721

# HELP ipfs_write_latency_seconds Latency of IPFS block write operations in seconds
# TYPE ipfs_write_latency_seconds histogram
ipfs_write_latency_seconds_bucket{le="0.001"} 312
ipfs_write_latency_seconds_bucket{le="0.005"} 4105
ipfs_write_latency_seconds_bucket{le="0.01"} 4620
ipfs_write_latency_seconds_bucket{le="0.05"} 4718
ipfs_write_latency_seconds_bucket{le="0.1"} 4721
ipfs_write_latency_seconds_bucket{le="+Inf"} 4721
ipfs_write_latency_seconds_sum 12.843
ipfs_write_latency_seconds_count 4721

# HELP gc_articles_unpinned_total Total number of articles unpinned by the garbage collector
# TYPE gc_articles_unpinned_total counter
gc_articles_unpinned_total 89

# HELP gossip_messages_published_total Total number of gossipsub messages published
# TYPE gossip_messages_published_total counter
gossip_messages_published_total 4721

# HELP gossip_messages_dropped_total Total number of gossipsub messages dropped
# TYPE gossip_messages_dropped_total counter
gossip_messages_dropped_total 3

# HELP peer_connections_active Number of currently active peer connections
# TYPE peer_connections_active gauge
peer_connections_active 2
```

Key metrics to watch:

| Metric | What to check |
|--------|---------------|
| `articles_ingested_total` | Increasing steadily? If flat, peering may be stalled. |
| `ipfs_write_latency_seconds` | p99 latency spike indicates IPFS node pressure. |
| `gossip_messages_dropped_total` | Any non-zero value warrants investigation (backpressure). |
| `peer_connections_active` | Should match the number of configured peers when healthy. |
| `gc_articles_unpinned_total` | Cross-check against retention policy expectations. |

### `/log-tip` — Group log tip CIDs

Returns the current tip CID set per group. A "tip" is the most recent entry in
the Merkle-CRDT group log for that group — the set of CIDs that no other entry
currently points to as a parent.

```
curl -s http://127.0.0.1:9090/log-tip
```

Example output (JSON):

```json
{
  "comp.lang.rust": [
    "bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm"
  ],
  "comp.lang.c": [
    "bafyreid3p7ok4n3s3nyinncqkqvqq2y7noxhkxhbjxnbqzpqhfzxfqbxqu",
    "bafyreib5x4p3z2t7qzwyjljkq5jf3xgkexamplecidgoeshere12345678"
  ],
  "alt.test": []
}
```

Multiple CIDs for a group means concurrent tip divergence — this is normal
during a gossipsub partition and will resolve when peers reconcile.

An empty array means no articles have been ingested for that group yet.

> Note: The admin HTTP server (both `/metrics` and `/log-tip`) is implemented
> at the configuration and metrics-collection layer. The HTTP listener itself
> is pending integration work.

---

## 3. Operator CLI

The `transit` binary provides subcommands for querying and managing the local
SQLite state. These commands operate directly on the database file and do not
require the daemon to be running.

> Note: The CLI business logic is fully implemented in the `cli/` module.
> The argument-parsing layer (clap wiring) that exposes these as subcommands
> is pending integration work.

### `transit status`

Print summary counts: active peers, total articles, pinned CIDs.

```
transit status --config /etc/transit.toml
```

Example output:

```
peers (active):  2
articles:        4721
pinned CIDs:     4721
```

With `--json`:

```json
{
  "peers_active": 2,
  "articles": 4721,
  "pinned_cids": 4721
}
```

### `transit peer-list`

Show all known peers with their reputation score and blacklist status.

```
transit peer-list --config /etc/transit.toml
transit peer-list --config /etc/transit.toml --json
```

Example table output:

```
PEER_ID                                              ADDRESS              SCORE STATUS       LAST_SEEN_MS
----------------------------------------------------------------------------------------------------------
12D3KooWExamplePeerId1abc123def456ghi789jkl012mno34 192.0.2.10:119        0.952 active       1700001234567
12D3KooWExamplePeerId2pqr567stu890vwx123yz456abc789 192.0.2.20:119        0.200 blacklisted  1700000012345
```

The score is a float in [0, 1]. Higher is better. A score near 1.0 means the
peer has accepted many articles and no failures. A score near 0 indicates
repeated rejections or consecutive failures.

### `transit peer-score <peer-id>`

Show detailed metrics for a single peer.

```
transit peer-score 12D3KooWExamplePeerId1abc123def456ghi789jkl012mno34 \
    --config /etc/transit.toml
```

Example output:

```
peer_id:              12D3KooWExamplePeerId1abc123def456ghi789jkl012mno34
address:              192.0.2.10:119
score:                0.9524
status:               active
articles_accepted:    4601
articles_rejected:    12
consecutive_failures: 0
last_seen_ms:         1700001234567
configured:           true
```

### `transit peer-blacklist <peer-id> [duration-secs]`

Manually blacklist a peer for a given duration (default: 3600 seconds).

```
transit peer-blacklist 12D3KooWExamplePeerId2pqr567stu890vwx123yz456abc789 \
    --config /etc/transit.toml

transit peer-blacklist 12D3KooWExamplePeerId2pqr567stu890vwx123yz456abc789 \
    7200 --config /etc/transit.toml
```

### `transit peer-unblacklist <peer-id>`

Clear a peer's blacklist entry and reset consecutive_failures to zero.

```
transit peer-unblacklist 12D3KooWExamplePeerId2pqr567stu890vwx123yz456abc789 \
    --config /etc/transit.toml
```

### `transit gc-run`

Run the garbage collector immediately, using the policy from the config file.

```
transit gc-run --config /etc/transit.toml
```

Example output:

```
gc-run: 4721 scanned, 89 unpinned
```

This removes articles from the `pinned_cids` table that the configured policy
no longer wants to retain. The policy is governed by `[pinning]` in config.

### `transit pin <cid>` / `transit unpin <cid>`

Manually add or remove an operator pin for a specific CID.

```
transit pin bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm \
    --config /etc/transit.toml

transit unpin bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm \
    --config /etc/transit.toml
```

### `transit audit-export`

Export the audit log as newline-delimited JSON. Supports filtering by time
range or event type.

```
# All events
transit audit-export --config /etc/transit.toml

# Auth failures in the last hour
transit audit-export --event-type auth_attempt \
    --since-ms $(date -d '1 hour ago' +%s)000 \
    --config /etc/transit.toml

# GC events
transit audit-export --event-type gc_run --config /etc/transit.toml
```

Audit event types: `article_signed`, `auth_attempt`, `peer_blacklisted`,
`gc_run`, `admin_access`.

### `transit keygen`

Generate an operator Ed25519 keypair. Run this once on a fresh node.

```
transit keygen --output-dir /etc/stoa/keys
```

Writes:
- `/etc/stoa/keys/operator_key.pem` (mode 0600)
- `/etc/stoa/keys/operator_key.pub.pem` (mode 0644)

Prints the public key fingerprint (SHA-256 of SubjectPublicKeyInfo DER, hex).
Keep the private key file secret; the fingerprint appears in `audit_log` rows
for `article_signed` events.

---

## 4. SQLite Databases

There are three SQLite database files. The database path configuration field
is not yet wired into the config files; when it is, it will appear as a
`[database]` section in each daemon's config. In the meantime, the path is
set in the binary at startup.

### transit database

Contains peer state, pinning records, and the audit log.

**File**: configured at runtime (e.g. `/var/lib/stoa/transit.db`)

#### `peers` — peer registry

```sql
-- All active peers (not blacklisted)
SELECT peer_id, address, articles_accepted, articles_rejected,
       consecutive_failures, last_seen
FROM peers
WHERE blacklisted_until IS NULL OR blacklisted_until = 0
ORDER BY last_seen DESC;

-- Currently blacklisted peers
SELECT peer_id, address, blacklisted_until,
       datetime(blacklisted_until / 1000, 'unixepoch') AS blacklisted_until_utc
FROM peers
WHERE blacklisted_until > (strftime('%s', 'now') * 1000);

-- Peer details by peer_id
SELECT * FROM peers WHERE peer_id = '12D3KooWExamplePeerId1abc123def456ghi789jkl012mno34';
```

```
sqlite3 /var/lib/stoa/transit.db \
  "SELECT peer_id, address, articles_accepted FROM peers ORDER BY last_seen DESC LIMIT 20;"
```

#### `peer_groups` — groups served per peer

```sql
-- Which groups does a given peer serve?
SELECT group_name, updated_at
FROM peer_groups
WHERE peer_id = '12D3KooWExamplePeerId1abc123def456ghi789jkl012mno34'
ORDER BY group_name;

-- Which peers serve comp.lang.rust?
SELECT peer_id, updated_at FROM peer_groups WHERE group_name = 'comp.lang.rust';
```

#### `pinned_cids` — operator-pinned articles

```sql
-- How many CIDs are currently pinned?
SELECT COUNT(*) FROM pinned_cids;

-- Is a specific CID pinned?
SELECT pinned_at_ms,
       datetime(pinned_at_ms / 1000, 'unixepoch') AS pinned_at_utc
FROM pinned_cids
WHERE cid = 'bafyreigdmqpykrgxyaxtlafqpqhzrfegdmqivsfeq7clzqya3oqpjzxnkm';

-- Oldest 10 pins (candidates for manual review before next GC)
SELECT cid, datetime(pinned_at_ms / 1000, 'unixepoch') AS pinned_at_utc
FROM pinned_cids ORDER BY pinned_at_ms ASC LIMIT 10;
```

#### `audit_log` — security events

The audit log is append-only. No rows are ever updated or deleted.

```sql
-- 20 most recent events
SELECT datetime(timestamp_ms / 1000, 'unixepoch') AS ts,
       event_type, event_json
FROM audit_log
ORDER BY id DESC LIMIT 20;

-- All authentication failures
SELECT datetime(timestamp_ms / 1000, 'unixepoch') AS ts, event_json
FROM audit_log
WHERE event_type = 'auth_attempt'
  AND json_extract(event_json, '$.success') = 0
ORDER BY id DESC LIMIT 50;

-- Recent peer blacklist events
SELECT datetime(timestamp_ms / 1000, 'unixepoch') AS ts, event_json
FROM audit_log
WHERE event_type = 'peer_blacklisted'
ORDER BY id DESC LIMIT 10;

-- GC runs in the last 24 hours
SELECT datetime(timestamp_ms / 1000, 'unixepoch') AS ts, event_json
FROM audit_log
WHERE event_type = 'gc_run'
  AND timestamp_ms > (strftime('%s', 'now') - 86400) * 1000
ORDER BY id DESC;
```

```
sqlite3 /var/lib/stoa/transit.db \
  "SELECT datetime(timestamp_ms/1000,'unixepoch'), event_type, event_json \
   FROM audit_log ORDER BY id DESC LIMIT 20;"
```

### core database

Contains the Message-ID map and the Merkle-CRDT group log. Shared by both
daemons.

**File**: configured at runtime (e.g. `/var/lib/stoa/core.db`)

#### `msgid_map` — Message-ID to CID mapping

Note: CIDs are stored as raw bytes (BLOB). To display them as strings, use
the `transit status` or `transit peer-score` commands, or read them via the
application rather than directly querying the BLOB column.

```sql
-- Count total articles known
SELECT COUNT(*) FROM msgid_map;

-- Check if a specific Message-ID has been ingested
SELECT COUNT(*) FROM msgid_map WHERE message_id = '<12345@example.com>';
```

```
sqlite3 /var/lib/stoa/core.db \
  "SELECT COUNT(*) FROM msgid_map;"
```

#### `log_entries` / `log_entry_parents` / `group_tips` — group CRDT log

```sql
-- How many log entries exist?
SELECT COUNT(*) FROM log_entries;

-- Current tip IDs for all groups
SELECT group_name, COUNT(*) AS tip_count
FROM group_tips GROUP BY group_name;

-- Tip count > 1 indicates unreconciled concurrent appends (normal during partition)
SELECT group_name, COUNT(*) AS tip_count
FROM group_tips
GROUP BY group_name
HAVING tip_count > 1;
```

### reader database

Contains the synthesized per-reader article numbers and the overview index.

**File**: configured at runtime (e.g. `/var/lib/stoa/reader.db`)

#### `article_numbers` — local article number assignments

```sql
-- How many articles are numbered for a group?
SELECT group_name, COUNT(*) AS count, MIN(article_number), MAX(article_number)
FROM article_numbers
GROUP BY group_name;

-- Look up the CID for a specific article number in a group
-- (CID is stored as BLOB; this confirms the row exists)
SELECT article_number FROM article_numbers
WHERE group_name = 'comp.lang.rust' AND article_number = 42;
```

---

## 5. Diagnosing Common Problems

### Article not propagating to peers

1. Check that gossipsub is connected to the expected peers:
   ```
   transit peer-list --config /etc/transit.toml
   ```
   Look for `peer_connections_active` in metrics and confirm peers show
   `status: active`.

2. Check `gossip_messages_dropped_total` in metrics. Any non-zero value means
   the gossipsub publish channel is experiencing backpressure.

3. Check whether the sending peer is blacklisted:
   ```
   transit peer-score <peer-id> --config /etc/transit.toml
   ```
   If `status: blacklisted`, unblacklist manually:
   ```
   transit peer-unblacklist <peer-id> --config /etc/transit.toml
   ```

4. Enable debug logging for the gossip and peering subsystems:
   ```
   RUST_LOG=stoa_transit::gossip=debug,stoa_transit::peering=debug \
       stoa-transit --config /etc/transit.toml
   ```
   Look for `gossipsub publish error` warnings and `log append failed` warnings.

5. Check `group_tips` for the affected group. An empty tip set means no
   articles have been appended to the CRDT log for that group:
   ```
   sqlite3 /var/lib/stoa/core.db \
     "SELECT group_name, COUNT(*) FROM group_tips GROUP BY group_name;"
   ```

### IPFS write failures

The pipeline aborts immediately if the IPFS write fails. Look for:

```
# At error level
ERROR stoa_transit::peering::pipeline: IPFS write failed: ...
```

1. Confirm the IPFS node is reachable at the configured `ipfs.api_url`:
   ```
   curl -s http://127.0.0.1:5001/api/v0/id
   ```

2. Check `ipfs_write_latency_seconds` in metrics. If the p99 bucket is in
   the 5-second range, the IPFS node may be overloaded.

3. Check available disk space on the IPFS datastore volume.

### SQLite errors

SQLite errors surface as `StorageError::Database(...)` strings in log output.
Common causes:

- **Disk full**: the BLOB writes to `msgid_map` or `log_entries` will fail.
  Check `df -h` on the volume containing the database files.
- **Permissions**: the daemon process must have read-write access to both the
  `.db` file and its directory (SQLite writes a `-wal` and `-shm` file
  alongside the database).
- **Migration not run**: if tables are missing, the binary may have been
  deployed without running migrations. Migrations run automatically at startup
  via `sqlx::migrate!`; if they fail the daemon will exit with an error.

### Authentication failures

Check the audit log for `auth_attempt` events where `success` is false:

```
sqlite3 /var/lib/stoa/transit.db \
  "SELECT datetime(timestamp_ms/1000,'unixepoch'), \
          json_extract(event_json,'$.peer_addr'), \
          json_extract(event_json,'$.user') \
   FROM audit_log \
   WHERE event_type='auth_attempt' \
     AND json_extract(event_json,'$.success')=0 \
   ORDER BY id DESC LIMIT 20;"
```

Or use the CLI:

```
transit audit-export --event-type auth_attempt --config /etc/transit.toml \
  | jq 'select(.success == false)'
```

Repeated failures from the same IP may indicate a credential misconfiguration
on the client side, or a brute-force attempt. If the latter, add a firewall
rule against the source address.
