-- Per-peer group serving list.
-- Tracks which newsgroups each peer has indicated it serves.
-- Populated by feed negotiation at connection time; refreshed periodically.

CREATE TABLE IF NOT EXISTS peer_groups (
    peer_id    TEXT   NOT NULL REFERENCES peers(peer_id) ON DELETE CASCADE,
    group_name TEXT   NOT NULL,
    updated_at BIGINT NOT NULL DEFAULT 0,  -- Unix timestamp ms
    PRIMARY KEY (peer_id, group_name)
);

CREATE INDEX IF NOT EXISTS idx_peer_groups_group ON peer_groups (group_name);
