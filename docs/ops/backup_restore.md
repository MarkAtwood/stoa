# SQLite Backup and Restore

stoa stores article index state in SQLite databases.  Loss of these databases
means articles can no longer be located by group, number, or message-ID — the
articles themselves remain in Kubo/IPFS/S3, but they become unreachable until
the index is rebuilt.  This guide documents how to back up and restore all
stoa SQLite databases.

## Databases

### stoa-transit

| Config key | Default filename | Schema |
|---|---|---|
| `database.path` | `transit.db` | peers, peer groups, staged articles |
| `database.core_path` | `transit_core.db` | message-ID map, group log |
| `database.verify_path` | `transit_verify.db` | article verifications, seen keys |

### stoa-reader

| Config key | Default filename | Schema |
|---|---|---|
| `database.reader_path` | `reader.db` | article numbers, overview index |
| `database.core_path` | `reader_core.db` | message-ID map |
| `database.verify_path` | `reader_verify.db` | article verifications, seen keys |

---

## Manual backup via `POST /admin/backup`

The admin HTTP endpoint triggers an online SQLite backup using SQLite's
`VACUUM INTO` statement, which is safe to run while the database is live.

### Configuration

Add a `[backup]` section to `transit.toml`:

```toml
[backup]
dest_dir = "/var/backups/stoa"
```

The directory is created automatically if it does not exist.

### Triggering a backup

```bash
curl -s -X POST http://127.0.0.1:9090/backup \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

On success the response is HTTP 200 with a JSON body listing the backup files:

```json
{"backups":["/var/backups/stoa/transit-20260427T030000Z.db","/var/backups/stoa/core-20260427T030000Z.db"]}
```

If `backup.dest_dir` is not configured, the endpoint returns HTTP 503.

### Backup filename format

Files are named `<schema>-<timestamp>.db` where `<timestamp>` is UTC in
`YYYYMMDDTHHmmSSZ` format, for example:

```
transit-20260427T030000Z.db
core-20260427T030000Z.db
```

---

## Scheduled automatic backup

> **Not yet implemented.**  Scheduled backup is tracked in issue usenet-ipfs-l79h.2.
> When implemented, the `[backup] schedule` field will accept a cron expression.

Planned configuration:

```toml
[backup]
dest_dir = "/var/backups/stoa"
schedule = "0 3 * * *"   # 03:00 UTC daily
```

---

## S3 upload

> **Not yet implemented.**  S3 upload is tracked in issue usenet-ipfs-l79h.2.
> When implemented, backup files will be uploaded to S3 after the local write.

Planned configuration:

```toml
[backup]
dest_dir = "/var/backups/stoa"
s3_bucket = "my-stoa-backups"
schedule = "0 3 * * *"
```

For now, operators can upload backup files using the AWS CLI after triggering
a manual backup:

```bash
# Trigger backup and capture output
BACKUP_JSON=$(curl -s -X POST http://127.0.0.1:9090/backup \
  -H "Authorization: Bearer $ADMIN_TOKEN")

# Upload each file to S3
echo "$BACKUP_JSON" | jq -r '.backups[]' | while read f; do
  aws s3 cp "$f" "s3://my-stoa-backups/$(basename "$f")"
done
```

---

## Restore procedure

### Prerequisites

- stoa daemon is **stopped** (restore must run before the daemon opens the databases)
- Backup files are present locally (copy from S3 if needed)

### Step-by-step restore

1. **Stop the daemon:**

   ```bash
   systemctl stop stoa-transit    # or stoa-reader
   ```

2. **Copy backup files from S3 (if applicable):**

   ```bash
   aws s3 cp s3://my-stoa-backups/transit-20260427T030000Z.db /tmp/
   aws s3 cp s3://my-stoa-backups/core-20260427T030000Z.db /tmp/
   ```

3. **Restore using the `--restore` flag:**

   ```bash
   stoa-transit --config /etc/stoa/transit.toml \
     --restore \
       /tmp/transit-20260427T030000Z.db \
       /tmp/core-20260427T030000Z.db
   ```

   The `--restore` flag:
   - Reads the config to determine where each database lives
   - Verifies that each backup file is a valid SQLite database
   - Copies each file to the configured database path
   - Prints a confirmation line for each file restored
   - Exits 0 on success, 1 on any error

   **File mapping by filename prefix:**

   | Prefix | Transit destination | Reader destination |
   |---|---|---|
   | `transit-*` | `database.path` | *(not applicable)* |
   | `core-*` | `database.core_path` | `database.core_path` |
   | `verify-*` | `database.verify_path` | `database.verify_path` |
   | `reader-*` | *(not applicable)* | `database.reader_path` |

4. **Restart the daemon:**

   ```bash
   systemctl start stoa-transit
   ```

5. **Verify:**

   ```bash
   curl -s http://127.0.0.1:9090/health
   curl -s http://127.0.0.1:9090/stats
   ```

---

## Disaster scenario: Kubo is intact but SQLite is lost

This is the most common data loss scenario: the SQLite files are deleted or
corrupted (e.g. disk failure, accidental `rm`, filesystem corruption), but the
IPFS block store (Kubo, S3, or LMDB) is still intact.

**What is lost:**

- Article numbers assigned to clients (local, synthetic — clients will see
  renumbered articles after rebuild)
- Overview index (subject, author, date — rebuilt from article headers)
- Message-ID → CID mapping (rebuildable by scanning IPFS pins)
- Group log state (rebuildable from IPFS)

**Recovery path:**

1. Restore the most recent backup using the `--restore` procedure above.

2. If no backup is available, the databases can be rebuilt from scratch by
   starting the daemon with empty databases.  Articles already pinned in IPFS
   will be re-ingested on the next peering sync.  Locally synthesised article
   numbers will be reassigned from 1; clients that cached old numbers will
   re-sync automatically (NNTP clients are tolerant of number gaps and resets).

3. To accelerate rebuild, run the overview backfill:

   ```bash
   # stoa-reader performs overview backfill automatically at startup
   # when it detects that article_numbers or overview rows are missing.
   systemctl start stoa-reader
   ```

**What is NOT lost:**

- Article content (stored in IPFS, addressed by CID)
- Operator signing key (stored separately, not in SQLite)
- Articles replicated to peer transit servers

---

## Cross-host restore

To migrate stoa to a new host or restore to a different machine:

1. Copy backup files to the new host:

   ```bash
   rsync -av /var/backups/stoa/ newhost:/tmp/stoa-restore/
   ```

2. Install stoa on the new host and write a config file with the desired
   database paths.

3. Run `--restore` with the config and backup files:

   ```bash
   stoa-transit --config /etc/stoa/transit.toml \
     --restore \
       /tmp/stoa-restore/transit-20260427T030000Z.db \
       /tmp/stoa-restore/core-20260427T030000Z.db
   ```

4. Copy the operator signing key (`database.signing_key_path`) to the new host.
   Without the same key, articles previously signed by this operator will not
   verify against the new operator key.

5. Update peering configuration (`[peers]`) if the new host has a different
   address, then start the daemon.

---

## Backup retention policy

stoa does not automatically prune old backup files.  Operators should implement
their own retention policy.  A simple cron job using `find`:

```bash
# Keep backups for 30 days, delete older files
find /var/backups/stoa -name "*.db" -mtime +30 -delete
```

Or use S3 lifecycle rules:

```json
{
  "Rules": [{
    "ID": "stoa-backup-30d",
    "Status": "Enabled",
    "Filter": {"Prefix": ""},
    "Expiration": {"Days": 30}
  }]
}
```
