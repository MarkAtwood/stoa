# Git Object Database Backend

The `git_sha256` backend stores article blocks as git blob objects in a bare git
repository.  A SQLite index maps each IPFS CID to its git object ID (OID) so
blocks can be retrieved by CID.

This backend is **reader-only** (`stoa-reader` only).  It is not supported by
`stoa-transit`.

## Configuration

```toml
[backend]
type = "git_sha256"

[backend.git_sha256]
# Path to the bare git repository.  Created automatically if absent.
repo_path = "/var/lib/stoa/articles.git"

# Path to the SQLite CID-to-OID index.  Created automatically if absent.
index_db  = "/var/lib/stoa/git_index.db"
```

## Repository initialisation

`stoa-reader` initialises the bare repository on first start if `repo_path` does
not exist.  No manual `git init` is required.

To pre-create the repository:

```sh
git init --bare /var/lib/stoa/articles.git
```

## SHA-1 vs SHA-256 note

The git repository uses **SHA-1** object IDs internally.  `libgit2` (the
underlying C library) does not yet expose the SHA-256 object format
(`extensions.objectFormat = sha256`) in its public API.  CIDs (the external
keys used throughout stoa) are SHA-256 based; the git OID is an implementation
detail stored only in the SQLite index.  When upstream `libgit2` enables
SHA-256 this limitation will be lifted.

## Garbage collection

`delete()` removes the CID from the SQLite index but leaves the git blob object
in the ODB.  The orphaned object is invisible to stoa but occupies disk space
until git runs garbage collection.

Schedule periodic GC via cron or systemd:

```sh
# Daily GC, pruning objects orphaned for more than 7 days
0 3 * * * git -C /var/lib/stoa/articles.git gc --prune=7.days.ago --quiet
```

After GC completes, `get_raw()` on a deleted CID returns `NotFound`.

## Replication via git push

The bare repository is a standard git repository and can be replicated with
`git push`:

```sh
# Mirror to a remote bare repository (e.g. on a backup server)
git -C /var/lib/stoa/articles.git remote add backup user@backup-host:/data/stoa/articles.git
git -C /var/lib/stoa/articles.git push --mirror backup
```

Automate with a post-commit hook or a systemd timer.

> **Note:** The SQLite index is not replicated by `git push`.  Replicas that
> serve reads must either rebuild the index from the ODB or maintain their own
> index via the same ingestion path.

## Backup

Back up both the git repository and the SQLite index together so they remain
consistent:

```sh
# Consistent snapshot with rsync (run on idle or with reader paused)
rsync -a --delete /var/lib/stoa/articles.git/ /backup/articles.git/
rsync -a /var/lib/stoa/git_index.db /backup/git_index.db
```

For online backups, SQLite WAL mode (used by stoa) supports `BACKUP` API or
`sqlite3 git_index.db ".backup /backup/git_index.db"` without pausing writes.
