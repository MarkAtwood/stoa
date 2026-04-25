CREATE TABLE IF NOT EXISTS gc_audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cid             TEXT    NOT NULL,
    group_name      TEXT    NOT NULL,
    ingested_at_ms  INTEGER NOT NULL,
    gc_at_ms        INTEGER NOT NULL,
    reason          TEXT    NOT NULL
);
