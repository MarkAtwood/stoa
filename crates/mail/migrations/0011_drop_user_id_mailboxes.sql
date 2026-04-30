-- Migration 0011: replace user_mailboxes (user-partitioned) with mailboxes (shared).
-- SQLite <3.35 does not support DROP COLUMN so we use CREATE/INSERT/DROP/RENAME.
CREATE TABLE mailboxes_new (
    mailbox_id TEXT    PRIMARY KEY,
    role       TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 10
);
INSERT INTO mailboxes_new (mailbox_id, role, name, sort_order)
    SELECT mailbox_id, role, name, sort_order
    FROM   user_mailboxes
    WHERE  user_id = (SELECT MIN(user_id) FROM user_mailboxes)
       OR  user_id IS NULL;
DROP TABLE user_mailboxes;
ALTER TABLE mailboxes_new RENAME TO mailboxes;
