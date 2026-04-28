-- Article metadata store for usenet-ipfs-transit.
--
-- Tracks every article that has been stored locally.
-- `cid` is the DAG-CBOR CIDv1 of the article root block, encoded as a string.
-- `group_name` is the primary newsgroup from the article's Newsgroups header.
-- `ingested_at_ms` is the Unix timestamp in milliseconds when the article arrived.
-- `byte_count` is the total byte size of the article's raw wire form.

CREATE TABLE IF NOT EXISTS articles (
    cid            TEXT   NOT NULL PRIMARY KEY,
    group_name     TEXT   NOT NULL DEFAULT '',
    ingested_at_ms BIGINT NOT NULL,
    byte_count     BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_articles_ingested_at ON articles (ingested_at_ms);
CREATE INDEX IF NOT EXISTS idx_articles_group ON articles (group_name);
