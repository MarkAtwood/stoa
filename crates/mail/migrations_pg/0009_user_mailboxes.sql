CREATE TABLE IF NOT EXISTS user_mailboxes (
    user_id    BIGINT NOT NULL,
    role       TEXT   NOT NULL,
    mailbox_id TEXT   NOT NULL,
    name       TEXT   NOT NULL,
    sort_order BIGINT NOT NULL DEFAULT 10,
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE (user_id, mailbox_id)
);
