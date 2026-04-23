-- Transit write-ahead staging table (usenet-ipfs-9mf).
--
-- Articles written by peering sessions land here before the IPFS pipeline
-- processes them.  Each row corresponds to a staging file on disk.
-- Rows are removed once run_pipeline succeeds.  Any rows that survive a
-- crash or unclean shutdown are re-drained on the next daemon startup.
CREATE TABLE IF NOT EXISTS transit_staging (
    id          TEXT    NOT NULL PRIMARY KEY,   -- random hex ID; also the staging filename
    message_id  TEXT    NOT NULL UNIQUE,        -- NNTP Message-ID
    file_path   TEXT    NOT NULL,               -- absolute path to the staging file
    received_at INTEGER NOT NULL,               -- Unix epoch seconds (drain order)
    byte_size   INTEGER NOT NULL                -- bytes on disk (for max_bytes limit check)
);
