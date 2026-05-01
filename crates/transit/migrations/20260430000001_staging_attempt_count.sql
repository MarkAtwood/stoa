-- Add attempt_count column to transit_staging for dead-letter after max retries
-- (usenet-ipfs-ed079dd8).
--
-- On each failed pipeline attempt the drain task increments attempt_count.
-- When attempt_count reaches MAX_PIPELINE_ATTEMPTS the row is deleted and
-- the article is dead-lettered with a warning log, preventing infinite retry.
ALTER TABLE transit_staging ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;
