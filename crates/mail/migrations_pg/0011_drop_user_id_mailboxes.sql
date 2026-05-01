-- Migration 0011 (Postgres): replace user_mailboxes with mailboxes (shared).
-- Old rows are intentionally NOT copied: their mailbox_id values used
-- SHA-256(user_id || role); new code uses SHA-256(role).  Copying stale
-- IDs would silently break JMAP mailbox lookups on upgraded deployments.
-- provision_mailboxes() at server startup repopulates the table.
CREATE TABLE mailboxes (
    mailbox_id TEXT    PRIMARY KEY,
    role       TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    sort_order BIGINT  NOT NULL DEFAULT 10
);
DROP TABLE user_mailboxes;
