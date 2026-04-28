-- JMAP change log for incremental sync (/changes methods).
CREATE TABLE IF NOT EXISTS jmap_change_log (
    seq     BIGINT NOT NULL,
    scope   TEXT   NOT NULL,
    item_id TEXT   NOT NULL,
    change  TEXT   NOT NULL,
    PRIMARY KEY (seq, scope, item_id)
);
