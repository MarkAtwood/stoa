CREATE TABLE IF NOT EXISTS gc_audit_log (
    id             BIGSERIAL PRIMARY KEY,
    cid            TEXT   NOT NULL,
    group_name     TEXT   NOT NULL,
    ingested_at_ms BIGINT NOT NULL,
    gc_at_ms       BIGINT NOT NULL,
    reason         TEXT   NOT NULL
);
