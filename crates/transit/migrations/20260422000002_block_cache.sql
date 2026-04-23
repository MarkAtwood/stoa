-- Local LRU block cache for IPFS content (usenet-ipfs-31v).
--
-- Each row represents one block that is available on local disk without an
-- IPFS network round-trip.  Rows are evicted (file + row deleted) by the
-- LRU policy when either the byte-size or entry-count limit is exceeded.
-- CID immutability guarantees that cached bytes are always correct: same CID
-- always means the same bytes, forever.
CREATE TABLE IF NOT EXISTS transit_block_cache (
    cid         TEXT    NOT NULL PRIMARY KEY,   -- CID string (multibase, e.g. base32upper)
    file_path   TEXT    NOT NULL,               -- absolute path to the cache file
    byte_size   INTEGER NOT NULL,               -- cached block size in bytes
    last_access INTEGER NOT NULL                -- Unix epoch seconds (LRU key)
);

-- Used by eviction queries: delete the oldest entries first.
CREATE INDEX IF NOT EXISTS idx_block_cache_lru
    ON transit_block_cache (last_access ASC);
