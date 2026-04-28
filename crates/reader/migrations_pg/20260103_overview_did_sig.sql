-- Add DID signature verification status column to overview table.
-- NULL = no X-Usenet-IPFS-DID-Sig header was present.
-- 0    = signature verification failed.
-- 1    = signature verified successfully.
ALTER TABLE overview ADD COLUMN IF NOT EXISTS did_sig_valid INTEGER;
