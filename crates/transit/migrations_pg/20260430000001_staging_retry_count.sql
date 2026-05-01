-- Add retry_count column to transit_staging for transient-failure tracking
-- (usenet-ipfs-zmn9.42).
--
-- On a transient pipeline failure (IPFS unavailable, DB lock) the drain worker
-- increments retry_count and leaves the row for the next drain pass.  Once
-- retry_count reaches the operator-configured limit (default 10) the article
-- is treated as permanently failed and the row is purged, preventing unbounded
-- queue growth.  On a permanent failure (invalid article format, signing error)
-- the row is purged immediately without incrementing the counter.
ALTER TABLE transit_staging ADD COLUMN retry_count BIGINT NOT NULL DEFAULT 0;
