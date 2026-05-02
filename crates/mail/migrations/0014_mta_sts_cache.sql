CREATE TABLE IF NOT EXISTS mta_sts_cache (
    domain       TEXT NOT NULL PRIMARY KEY,
    policy_id    TEXT NOT NULL,
    mode         TEXT NOT NULL,
    mx_patterns  TEXT NOT NULL,
    max_age_secs INTEGER NOT NULL,
    fetched_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);
