-- Log entries in the per-group Merkle-CRDT append-only log.
-- Entries have no group_name column; group association is tracked via group_tips.
CREATE TABLE IF NOT EXISTS log_entries (
    id                 BYTEA   PRIMARY KEY NOT NULL,
    hlc_timestamp      BIGINT  NOT NULL,
    article_cid        BYTEA   NOT NULL,
    operator_signature BYTEA   NOT NULL
);

-- Parent links for the DAG (zero or more parents per entry).
CREATE TABLE IF NOT EXISTS log_entry_parents (
    entry_id  BYTEA NOT NULL,
    parent_id BYTEA NOT NULL,
    PRIMARY KEY (entry_id, parent_id)
);

-- Current tip set per group (replaced atomically on merge).
CREATE TABLE IF NOT EXISTS group_tips (
    group_name TEXT  NOT NULL,
    tip_id     BYTEA NOT NULL,
    PRIMARY KEY (group_name, tip_id)
);
