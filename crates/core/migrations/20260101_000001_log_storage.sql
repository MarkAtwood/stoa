-- Log entries in the per-group Merkle-CRDT append-only log.
-- Entries have no group_name column; group association is tracked via group_tips.
CREATE TABLE IF NOT EXISTS log_entries (
    id                 BLOB    PRIMARY KEY NOT NULL,
    hlc_timestamp      INTEGER NOT NULL,
    article_cid        BLOB    NOT NULL,
    operator_signature BLOB    NOT NULL
);

-- Parent links for the DAG (zero or more parents per entry).
CREATE TABLE IF NOT EXISTS log_entry_parents (
    entry_id  BLOB NOT NULL,
    parent_id BLOB NOT NULL,
    PRIMARY KEY (entry_id, parent_id)
);

-- Current tip set per group (replaced atomically on merge).
CREATE TABLE IF NOT EXISTS group_tips (
    group_name TEXT NOT NULL,
    tip_id     BLOB NOT NULL,
    PRIMARY KEY (group_name, tip_id)
);
