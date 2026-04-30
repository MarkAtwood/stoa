-- Migration 0012 (Postgres): replace mailbox_messages with messages (shared).
-- mailboxes must exist before messages (foreign key).
CREATE TABLE messages (
    id            BIGSERIAL PRIMARY KEY,
    mailbox_id    TEXT      NOT NULL,
    envelope_from TEXT      NOT NULL,
    envelope_to   TEXT      NOT NULL,
    raw_message   BYTEA     NOT NULL,
    received_at   TEXT      NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(mailbox_id)
);
CREATE INDEX idx_messages_mailbox ON messages (mailbox_id);
INSERT INTO messages (id, mailbox_id, envelope_from, envelope_to, raw_message, received_at)
    SELECT id, mailbox_id, envelope_from, envelope_to, raw_message, received_at
    FROM   mailbox_messages;
DROP TABLE mailbox_messages;
