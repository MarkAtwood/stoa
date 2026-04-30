-- Deduplication table for received ActivityPub activities.
-- activity_id is the JSON-LD "@id" / "id" field of the received activity.
CREATE TABLE IF NOT EXISTS activitypub_received (
    activity_id  TEXT PRIMARY KEY,
    received_at  BIGINT NOT NULL
);
