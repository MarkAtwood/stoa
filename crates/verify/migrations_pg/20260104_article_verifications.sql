-- Stores per-article signature verification results.
-- One row per (cid, sig_type, identity) triple.
-- An article may have multiple rows if it carries multiple signatures.
CREATE TABLE IF NOT EXISTS article_verifications (
    cid         BYTEA   NOT NULL,
    sig_type    TEXT    NOT NULL,  -- 'x-usenet-ipfs-sig' | 'dkim'
    result      TEXT    NOT NULL,  -- 'pass' | 'fail' | 'dns-error' | 'no-key' | 'parse-error'
    identity    TEXT    NOT NULL DEFAULT '',  -- pubkey hex for x-sig; signing domain for dkim; '' if unknown
    reason      TEXT,              -- failure reason; NULL on pass
    verified_at BIGINT  NOT NULL,  -- Unix epoch milliseconds
    PRIMARY KEY (cid, sig_type, identity)
);

CREATE INDEX IF NOT EXISTS article_verifications_cid_idx ON article_verifications (cid);
