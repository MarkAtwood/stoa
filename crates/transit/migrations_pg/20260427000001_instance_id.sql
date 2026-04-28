-- Per-instance identity table (usenet-ipfs-ky62.5).
--
-- Each transit daemon inserts one row on startup keyed by hostname.
-- INSERT ... ON CONFLICT (key) DO NOTHING ensures the value is stable
-- across restarts: the first startup claims the UUID and every subsequent
-- restart reads back the same stored bytes.
--
-- Used to derive the HLC node_id for each instance so that multiple transit
-- daemons sharing a signing key still generate distinct HLC timestamps.
CREATE TABLE IF NOT EXISTS transit_instance_id (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
