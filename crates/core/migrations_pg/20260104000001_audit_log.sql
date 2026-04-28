-- Audit log: append-only record of security-relevant events.
-- No UPDATE or DELETE ever runs against this table.
CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGSERIAL PRIMARY KEY,
    timestamp_ms BIGINT NOT NULL,
    event_type   TEXT   NOT NULL,
    event_json   TEXT   NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_log_timestamp_ms ON audit_log (timestamp_ms);
CREATE INDEX IF NOT EXISTS audit_log_event_type ON audit_log (event_type);
