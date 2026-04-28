-- Peer registry for usenet-ipfs-transit.
--
-- Each row represents a known peer (configured or discovered).
-- `peer_id` is the libp2p PeerId encoded as its multibase string form.
-- `configured` = TRUE if the peer comes from the config file; FALSE if discovered via gossipsub/DHT.
-- `blacklisted_until` is NULL when the peer is in good standing.

CREATE TABLE IF NOT EXISTS peers (
    peer_id              TEXT   NOT NULL PRIMARY KEY,
    address              TEXT   NOT NULL,
    last_seen            BIGINT NOT NULL DEFAULT 0,   -- Unix timestamp ms
    articles_accepted    BIGINT NOT NULL DEFAULT 0,
    articles_rejected    BIGINT NOT NULL DEFAULT 0,
    consecutive_failures BIGINT NOT NULL DEFAULT 0,
    blacklisted_until    BIGINT,                      -- Unix timestamp ms, NULL = not blacklisted
    configured           BIGINT NOT NULL DEFAULT 0    -- 0=discovered, 1=from config
);

CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers (last_seen);
CREATE INDEX IF NOT EXISTS idx_peers_blacklisted_until ON peers (blacklisted_until)
    WHERE blacklisted_until IS NOT NULL;
