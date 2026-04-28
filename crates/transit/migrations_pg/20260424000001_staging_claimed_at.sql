-- Add claimed_at column to transit_staging for exclusive drain-worker claims
-- (usenet-ipfs-cl86).
--
-- drain_one() atomically sets claimed_at on the oldest unclaimed row so that
-- multiple concurrent drain workers never process the same article twice.
-- On daemon restart, reset_claims() clears any stale claims left by a previous
-- run that crashed after claiming but before completing.
ALTER TABLE transit_staging ADD COLUMN claimed_at BIGINT;
