# ADR-0003: SQLite + sqlx for Local Mutable State

## Status
Accepted

## Context

Both binaries need durable, queryable local state that must survive process
restart. The state is owned by a single process (one reader instance, one
transit instance) and is never shared across nodes at the database level —
cross-node state reconciliation is handled by the Merkle-CRDT gossip layer, not
by a shared database.

State categories:

- **`msgid_map`** — bidirectional `message_id ↔ CID` mapping. High insert and
  point-lookup rate. Duplicate-rejection semantics (insert must fail if a
  conflicting CID exists for the same message-id).
- **`log_entries` / `log_entry_parents` / `group_tips`** — Merkle-CRDT group
  log. Append-only with transactional tip updates.
- **`article_numbers` / `overview`** — reader-only. Sequential number assignment
  per group with MAX+1 logic; must serialize concurrent assignments.
- **`peers` / `articles`** — transit-only. Peer registry with mutable stats and
  blacklist state; GC-candidate tracking.
- **`audit_log`** — append-only security event log. No UPDATE or DELETE ever
  runs against this table.

Options considered:

- **SQLite + sqlx** — embedded, zero-operational-overhead, ACID with
  WAL mode, full SQL expressiveness (transactions, indices, AUTOINCREMENT).
  `sqlx` provides compile-time query checking and async support on top of
  tokio. Migrations are managed per-crate (core migrations shared by both
  binaries; reader and transit have their own migration sets).

- **PostgreSQL / MySQL** — requires a separate database process, network
  connection, credentials management, and deployment co-ordination. The
  multi-writer concurrency benefits do not apply here because all writes come
  from a single process. Operational overhead is not justified.

- **sled / redb** — embedded key-value stores. Sufficient for the msgid_map
  point-lookup case, but GROUP BY and range queries over article_numbers and
  overview would require application-layer index maintenance. The SQL schema is
  more expressive and auditable.

- **In-memory only** — state would not survive restart. Unacceptable for
  msgid_map (duplicate rejection) and article_numbers (stable numbering across
  client reconnects).

## Decision

Use SQLite (via `sqlx` with the SQLite feature) for all local mutable state.
SQL lives in dedicated store modules (`core/msgid_map.rs`,
`core/group_log/append.rs`, `reader/store/article_numbers.rs`, etc.). No SQL
is scattered through application logic. All schema changes go through
`sqlx::migrate!` migration files. WAL mode is enabled at startup for concurrent
readers.

## Consequences

- No separate database process. Both binaries embed SQLite and manage their own
  database file. Deployment is simpler and the operational surface is smaller.
- ACID transactions handle the sequential article number assignment (MAX+1 in a
  transaction, no separate coordination needed).
- `sqlx` compile-time query checking catches SQL errors at build time rather
  than at runtime.
- SQLite is not suitable for multi-writer or cross-node shared state. That is by
  design: cross-node state is handled by the CRDT gossip layer, and each process
  owns its local database exclusively.
- WAL mode allows concurrent reads from the reader session handlers while a
  single write transaction is in progress.
- Database file paths are configured at startup. Tests use in-memory (`:memory:`)
  or temporary-file databases.
