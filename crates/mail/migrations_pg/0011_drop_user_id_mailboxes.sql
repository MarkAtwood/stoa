-- Migration 0011 (Postgres): replace user_mailboxes with mailboxes (shared).
CREATE TABLE mailboxes (
    mailbox_id TEXT    PRIMARY KEY,
    role       TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    sort_order BIGINT  NOT NULL DEFAULT 10
);
INSERT INTO mailboxes (mailbox_id, role, name, sort_order)
    SELECT mailbox_id, role, name, sort_order
    FROM   user_mailboxes
    WHERE  user_id = (SELECT MIN(user_id) FROM user_mailboxes)
       OR  user_id IS NULL;
DROP TABLE user_mailboxes;
