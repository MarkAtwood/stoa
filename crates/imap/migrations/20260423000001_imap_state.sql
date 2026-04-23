-- IMAP server persistent state.
--
-- uid_validity: one row per mailbox (newsgroup mapped to an IMAP folder).
--   uidvalidity is a 32-bit unsigned integer that MUST NOT change for the
--   lifetime of the mailbox; we generate it once at first SELECT and persist
--   it here (RFC 3501 §2.3.1.1).
--
-- imap_flags: per-user, per-UID flag storage.
--   Flags set via STORE (\Seen, \Answered, \Flagged, \Deleted) are durable.
--   \Recent is session-only and is never written to this table.

CREATE TABLE IF NOT EXISTS imap_uid_validity (
    mailbox      TEXT    NOT NULL PRIMARY KEY,  -- newsgroup name used as IMAP mailbox
    uidvalidity  INTEGER NOT NULL,              -- UIDVALIDITY value (u32, positive)
    next_uid     INTEGER NOT NULL DEFAULT 1     -- next UID to assign on APPEND
);

-- Per-user flag storage.
-- uid is the IMAP UID assigned at article ingestion for this mailbox.
-- flags is a space-separated list of system flags (\Seen \Answered \Flagged \Deleted).
CREATE TABLE IF NOT EXISTS imap_flags (
    username   TEXT    NOT NULL,
    mailbox    TEXT    NOT NULL,
    uid        INTEGER NOT NULL,
    flags      TEXT    NOT NULL DEFAULT '',   -- space-separated system flags
    PRIMARY KEY (username, mailbox, uid)
);

CREATE INDEX IF NOT EXISTS idx_imap_flags_mailbox ON imap_flags (username, mailbox);
