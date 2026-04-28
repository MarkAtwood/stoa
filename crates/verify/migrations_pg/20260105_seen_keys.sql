-- Accumulates signing keys observed in verified articles.
-- Populated when a Pass result is recorded for x-usenet-ipfs-sig or dkim.
-- cert_der column is reserved for S/MIME X.509 certs (v2, unused in v1).
CREATE TABLE IF NOT EXISTS seen_keys (
    key_type        TEXT    NOT NULL,  -- 'ed25519' | 'rsa'
    key_id          TEXT    NOT NULL,  -- SHA-256 hex fingerprint of key_data
    key_data        BYTEA   NOT NULL,  -- 32 raw bytes (ed25519) or DER (rsa)
    cert_der        BYTEA,             -- reserved: X.509 DER for S/MIME (v2)
    first_seen_cid  BYTEA   NOT NULL,  -- CID of first article this key signed
    first_seen_at   BIGINT  NOT NULL,  -- Unix epoch milliseconds
    PRIMARY KEY (key_type, key_id)
);
