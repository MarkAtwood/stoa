-- Remote pinning jobs for external IPFS pinning services (Pinata, web3.storage, etc.).
--
-- Each row represents one (cid, service) pair tracking the submission and polling
-- state for the IPFS Remote Pinning API (https://ipfs.github.io/pinning-services-api-spec/).
--
-- Status values mirror the Remote Pinning API:
--   pending   : not yet submitted (initial state)
--   queued    : accepted by service, waiting to be processed
--   pinning   : service is actively retrieving/pinning the CID
--   pinned    : successfully pinned
--   failed    : service returned failed status or max_attempts exhausted

CREATE TABLE IF NOT EXISTS remote_pin_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cid             TEXT NOT NULL,
    service_name    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    request_id      TEXT,
    submitted_at_ms INTEGER,
    last_attempt_ms INTEGER,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    error           TEXT,

    UNIQUE (cid, service_name)
);

CREATE INDEX IF NOT EXISTS idx_remote_pin_jobs_status
    ON remote_pin_jobs (status);
