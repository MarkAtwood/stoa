CREATE TABLE IF NOT EXISTS bearer_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    username TEXT NOT NULL,
    label TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT
);
