# ADR-0006: Merkle-CRDT Append-Only Log for Group State

## Status
Accepted

## Context

Each newsgroup needs a shared, replicated, ordered view of which articles have
been posted to it. Nodes must be able to reconcile their local group state with
peers after a partition, after a new peer joins, and after concurrent posts on
different nodes. The reconciliation mechanism must work without a coordinator.

Four approaches were evaluated:

- **Raft/Paxos consensus** — provides strict total order and linearizable reads.
  Requires a stable quorum of nodes; minority partitions become read-only.
  Leader election adds latency on every write. For a store-and-forward system
  where partitions are normal operating conditions (nodes come and go, peers
  peer on opportunistic schedules), blocking writes during partition is
  unacceptable.

- **Centralized coordinator** — a designated leader per group sequences article
  numbers globally. Simple to implement. Single point of failure; the group
  becomes unavailable if the coordinator is unreachable. Reintroduces the
  server-dependency model that usenet-ipfs is designed to eliminate.

- **Operational Transform (OT)** — designed for concurrent document edits.
  Requires a central sequencer for correctness guarantees in the general case.
  The group log is append-only (no edits, no deletes), which means OT's
  per-character conflict resolution is irrelevant overhead. Not a natural fit.

- **Merkle-CRDT append-only log** — each node maintains a local DAG of log
  entries. Each entry carries a Hybrid Logical Clock (HLC) timestamp and a set
  of parent CIDs (the current frontier). Concurrent appends on different nodes
  produce a DAG with multiple tips. Reconciliation is set-union: merge any two
  nodes' entry sets. The merged state is a superset of both. This is a
  grow-only set CRDT (2P-set without the tombstone half, since we have no
  deletes in v1). Content-addressing via SHA-256 ensures idempotency: re-merging
  an already-known entry is a no-op.

The Merkle-CRDT approach is used in IPFS itself (IPFS Cluster's collaborative
pinning log), OrbitDB, and Ceramic Network, all of which have the same
requirements: distributed, partition-tolerant, coordinator-free, append-only.

## Decision

Each group has an independent Merkle-CRDT append-only log stored in three
SQLite tables in `usenet-ipfs-core`:

- `log_entries (id BLOB PK, hlc_timestamp, article_cid, operator_signature)`
- `log_entry_parents (entry_id, parent_id)` — DAG parent links
- `group_tips (group_name, tip_id)` — current frontier tip set per group

A `LogEntryId` is the SHA-256 of the entry's canonical serialization (RFC 8785
JSON). HLC timestamps provide a causal clock that is monotonic on each node and
advances forward on merge. The `parent_cids` field of each entry points at the
entries it was appended on top of, forming the DAG.

Reconciliation (`core/group_log/reconcile.rs`) computes the symmetric difference
between local and remote tip sets and exchanges missing entries. After backfill,
the local tip set is updated to include all merged tips. Tip advertisements are
broadcast via gossipsub (`usenet.hier.<hierarchy>` topics, see ADR-0004).

## Consequences

- The system is partition-tolerant: nodes continue to accept and store new
  articles during a partition. On reconnect, the two partition halves merge by
  exchanging their respective DAG entries. No entries are lost.
- Set-union merge is commutative, associative, and idempotent. Merge order and
  merge frequency do not affect the final state.
- Ordering within the merged log is causal/HLC, not strict total order. Two
  concurrent articles posted to the same group on different nodes have no defined
  relative ordering beyond their HLC timestamps. This is acceptable for a Usenet
  group (articles are not dependent on each other by default; threading is by
  `References:` header, not by log position).
- No deletes. Cancel messages (retract an article) are out of scope for v1.
  The append-only property is what makes the set-union merge correct; supporting
  deletes would require a more complex CRDT (2P-set or observed-remove set) and
  is deferred to a future epic.
- The `LogEntryId` being the hash of canonical bytes means the same article
  appended to two independent nodes produces the same `LogEntryId`. Re-merging
  a known entry is a SQLite unique-key no-op, providing idempotency for free.
- Article numbers (RFC 3977) are synthesized locally from the merged log state
  and are not part of the CRDT log. See ADR-0005.
