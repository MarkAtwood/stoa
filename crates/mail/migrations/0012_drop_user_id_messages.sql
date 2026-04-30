-- Migration 0012: replace mailbox_messages (user-partitioned) with messages (shared).
-- mailboxes must exist before messages (foreign key).
CREATE TABLE messages_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id    TEXT    NOT NULL,
    envelope_from TEXT    NOT NULL,
    envelope_to   TEXT    NOT NULL,
    raw_message   BLOB    NOT NULL,
    received_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(mailbox_id)
);
CREATE INDEX idx_messages_mailbox ON messages_new (mailbox_id);
INSERT INTO messages_new (id, mailbox_id, envelope_from, envelope_to, raw_message, received_at)
    SELECT id, mailbox_id, envelope_from, envelope_to, raw_message, received_at
    FROM   mailbox_messages;
DROP TABLE mailbox_messages;
ALTER TABLE messages_new RENAME TO messages;
