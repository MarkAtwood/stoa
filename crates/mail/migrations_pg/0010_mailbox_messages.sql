CREATE TABLE IF NOT EXISTS mailbox_messages (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT  NOT NULL,
    mailbox_id    TEXT    NOT NULL,
    envelope_from TEXT    NOT NULL,
    envelope_to   TEXT    NOT NULL,
    raw_message   BYTEA   NOT NULL,
    received_at   TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_mailbox_messages_user_mailbox
    ON mailbox_messages (user_id, mailbox_id);
