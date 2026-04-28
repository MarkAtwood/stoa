CREATE TABLE IF NOT EXISTS msgid_map (
    message_id TEXT  PRIMARY KEY,
    cid        BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS msgid_map_cid_idx ON msgid_map (cid);
