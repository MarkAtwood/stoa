-- IMAP server persistent state.
--
-- uid_validity: one row per mailbox (newsgroup mapped to an IMAP folder).
--   uidvalidity is a 32-bit unsigned integer that MUST NOT change for the
--   lifetime of the mailbox; we generate it once at first SELECT and persist
--   it here (RFC 3501 §2.3.1.1).

CREATE TABLE IF NOT EXISTS imap_uid_validity (
    mailbox      TEXT    NOT NULL PRIMARY KEY,  -- newsgroup name used as IMAP mailbox
    uidvalidity  INTEGER NOT NULL,              -- UIDVALIDITY value (u32, positive)
    next_uid     INTEGER NOT NULL DEFAULT 1     -- next UID to assign on APPEND
);
