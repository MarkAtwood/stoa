# Operator Retention and GC Guide

## Retention Concepts

stoa does not retain articles automatically. Writing an article to IPFS does not preserve it — IPFS garbage-collects unpinned blocks. Every article that should survive must be either operator-pinned or matched by a `pin` rule in the pinning policy.

**Design invariant:** Retention is explicit opt-in. "It's in IPFS" is not a retention strategy.

The transit daemon evaluates each article against the pinning policy at ingestion time. If the policy says `pin`, the article's CID is added to the `pinned_cids` table and the IPFS node is instructed to pin the block. If the policy says `skip`, or if no rule matches, the block is stored in IPFS but not pinned and will be eligible for GC.

The GC runner periodically re-evaluates all entries in `pinned_cids` against the policy. Articles whose policy outcome has changed to `skip` (for example, because they have aged past a `max_age_days` threshold) are unpinned and removed from `pinned_cids`.

---

## PinRule Format

Pinning policy rules are declared in `transit.toml` under `[[retention.rules]]`. Each rule is a TOML table:

```toml
[[retention.rules]]
groups           = "<pattern>"      # required
max_age_days     = <integer>        # optional
max_article_bytes = <integer>       # optional
action           = "pin" | "skip"   # required
```

### Fields

**`groups`** (required) — Which groups this rule applies to. Three forms are accepted:

| Pattern | Matches |
|---|---|
| `"all"` | Every group |
| `"comp.*"` or `"comp.**"` | Any group whose name starts with `comp.` |
| `"comp.lang.rust"` | Exactly that group, nothing else |

Each component of a dotted group name must start with an ASCII letter and contain only ASCII letters and digits. Uppercase is not valid in group names.

**`max_age_days`** (optional) — If present, the rule only matches articles whose `Date:` header is no more than this many days old. Articles older than `max_age_days` do not match this rule and fall through to the next rule. Omit to match articles of any age.

**`max_article_bytes`** (optional) — If present, the rule only matches articles whose byte count is no more than this value. Articles larger than `max_article_bytes` do not match this rule and fall through. Omit to match articles of any size.

**`action`** (required) — `"pin"` to pin matching articles; `"skip"` to leave them unpinned.

### Validation

The policy is validated at startup:

- An empty rule list is rejected — at least one rule is required.
- Invalid group patterns (malformed dotted names, empty components, leading digits) are rejected.
- `max_age_days = 0` combined with `groups = "all"` is rejected as a useless rule that can never match any article.
- Duplicate group patterns across multiple rules emit a startup warning (not an error). Only the first matching rule takes effect; the later rule is unreachable.

---

## Policy Evaluation Order

Rules are evaluated in declaration order. **The first matching rule wins.** If no rule matches an article, `should_pin` returns `false` — the article is not pinned.

Example evaluation for an article in `comp.lang.rust`, 5 days old, 2048 bytes:

```
Rule 1: groups="sci.math",  action="pin"   → groups do not match → skip
Rule 2: groups="comp.*",    max_age_days=30, action="pin" → groups match, age 5 ≤ 30 → PIN
(Rule 3 is never reached)
```

---

## Example Policies

### Pin everything indefinitely

```toml
[[retention.rules]]
groups = "all"
action = "pin"
```

All articles in all groups are pinned. No GC will unpin any article. Storage grows without bound.

### Pin comp.* for 30 days, skip everything else

```toml
[[retention.rules]]
groups      = "comp.*"
max_age_days = 30
action      = "pin"

[[retention.rules]]
groups = "all"
action = "skip"
```

Articles in any `comp.*` group that are 30 days old or newer are pinned. Articles older than 30 days fall through the first rule (age exceeds `max_age_days`) and match the second rule (`skip`). Articles in any other hierarchy (`sci.*`, `alt.*`, etc.) skip the first rule on the group pattern and match the second rule (`skip`).

### Pin sci.math forever, pin everything else for 7 days

```toml
[[retention.rules]]
groups = "sci.math"
action = "pin"

[[retention.rules]]
groups      = "all"
max_age_days = 7
action      = "pin"

[[retention.rules]]
groups = "all"
action = "skip"
```

`sci.math` articles match the first rule immediately and are pinned indefinitely. All other articles match the second rule while they are 7 days old or newer and are pinned; once they age past 7 days they fall through to the third rule (`skip`).

Note that a trailing `skip` catch-all is optional but recommended for clarity. Without it, articles that match no `pin` rule are implicitly not pinned — the behavior is the same. The explicit `skip` makes the intent unambiguous.

---

## GC Operation: `transit gc-run`

```bash
transit gc-run
```

Runs one GC pass immediately against the current policy. The command:

1. Reads all CIDs from `pinned_cids`.
2. Evaluates each against the policy using the article's actual group, age, and size metadata.
3. For each CID whose policy outcome is `skip`, calls the IPFS unpin API and removes the row from `pinned_cids`.
4. Emits a summary line and records a `GcRun` event in the audit log.

**Output:**

```
gc-run: 1024 scanned, 37 unpinned
```

- `scanned` — total CIDs evaluated.
- `unpinned` — CIDs removed from the pin set in this run.

GC errors (IPFS unpin failures) are logged as warnings and do not abort the run. The CID is left in `pinned_cids` and will be retried on the next GC run.

### Scheduled GC

The GC scheduler runs automatically on the interval configured in `[gc]`:

```toml
[gc]
schedule    = "0 3 * * *"   # cron expression: 03:00 UTC daily
max_age_days = 30
```

`schedule` is a standard five-field cron expression (minute, hour, day-of-month, month, day-of-week). `max_age_days` is a fallback upper bound applied when no more specific rule matches. The scheduled run produces the same output as `transit gc-run` and records the same audit events.

---

## Pin and Unpin Manually

### Pin a CID

```bash
transit pin <cid>
```

Inserts the CID into `pinned_cids` and instructs the IPFS node to pin the block. The CID must be a valid base32 or base58 CIDv0/CIDv1 string; an invalid CID is rejected with an error before any database write.

Output:
```
pinned: bafyreib...
```

Pinning is idempotent. Calling `transit pin` on an already-pinned CID succeeds without error.

### Unpin a CID

```bash
transit unpin <cid>
```

Removes the CID from `pinned_cids`. If the CID was not pinned, the command reports that and exits without error.

Output (found):
```
unpinned: bafyreib...
```

Output (not found):
```
not pinned: bafyreib...
```

Manual unpins are not recorded in the GC audit log — only GC-driven unpins are. If you need an audit trail for manual unpins, record the action in your operational runbook.

---

## Audit Log

### Where GC actions are recorded

Every GC-driven unpin is recorded in the `gc_audit_log` SQLite table in the transit daemon's database. The table is append-only — no UPDATE or DELETE is ever run against it.

Schema:

```sql
gc_audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    cid            TEXT    NOT NULL,
    group_name     TEXT    NOT NULL,
    ingested_at_ms INTEGER NOT NULL,   -- Unix ms from article Date: header
    gc_at_ms       INTEGER NOT NULL,   -- Unix ms when the unpin occurred
    reason         TEXT    NOT NULL    -- human-readable policy reason
)
```

### Querying the audit log

Direct SQLite queries against the transit database file:

```bash
# All unpins in the last 24 hours:
sqlite3 transit.db \
  "SELECT cid, group_name, reason FROM gc_audit_log
   WHERE gc_at_ms > (strftime('%s','now') - 86400) * 1000
   ORDER BY gc_at_ms DESC"

# Count of unpins per group:
sqlite3 transit.db \
  "SELECT group_name, COUNT(*) AS unpins
   FROM gc_audit_log
   GROUP BY group_name
   ORDER BY unpins DESC"

# Full history for a specific CID:
sqlite3 transit.db \
  "SELECT * FROM gc_audit_log WHERE cid = 'bafyreib...'"
```

The `transit audit` subcommand provides a higher-level interface to the same table without requiring direct SQL access:

```bash
transit audit --since 24h
transit audit --group comp.lang.rust
```

---

## Monitoring: `transit status`

```bash
transit status
transit status --format json
```

**Table output:**

```
peers (active):  4
articles:        12847
pinned CIDs:     9203
```

**JSON output:**

```json
{
  "peers_active": 4,
  "articles": 12847,
  "pinned_cids": 9203
}
```

Fields:
- `peers_active` — peers in the registry whose `blacklisted_until` is NULL or in the past.
- `articles` — total rows in `msgid_map` (all articles ever ingested, including unpinned ones).
- `pinned_cids` — rows currently in `pinned_cids` (articles the IPFS node is holding by operator request).

The difference between `articles` and `pinned_cids` is the count of articles that have been ingested but are not currently pinned. These blocks exist in IPFS only as long as IPFS has not yet run its own block GC. Once IPFS sweeps them, they are gone permanently unless a peer still holds a copy.

### Prometheus metrics

The GC runner exposes two Prometheus metrics at the admin endpoint (`GET /metrics`):

```
gc_articles_unpinned_total   counter   Total articles unpinned across all GC runs since startup
gc_last_run_duration_ms      gauge     Duration of the most recent GC run in milliseconds
```

A `gc_articles_unpinned_total` value that grows rapidly indicates your policy thresholds are removing articles faster than expected. A `gc_last_run_duration_ms` value that grows over time indicates the `pinned_cids` table is large and the GC scan is taking longer.
