-- JMAP change log for incremental sync (/changes methods).
--
-- Populated when articles are created via Email/set (SMTP relay path).
-- Each row records a state-version at which a specific item was created,
-- updated, or destroyed.
--
-- seq: the Email or Mailbox state version when the change occurred.
-- scope: 'Email' or 'Mailbox'
-- item_id: CID string (Email) or mailbox-id string (Mailbox)
-- change: one of 'created', 'updated', 'destroyed'

CREATE TABLE IF NOT EXISTS jmap_change_log (
    seq     INTEGER NOT NULL,
    scope   TEXT    NOT NULL,
    item_id TEXT    NOT NULL,
    change  TEXT    NOT NULL,
    PRIMARY KEY (seq, scope, item_id)
);
