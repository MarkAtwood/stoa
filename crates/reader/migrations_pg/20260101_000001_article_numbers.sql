CREATE TABLE IF NOT EXISTS article_numbers (
    group_name TEXT NOT NULL,
    article_number BIGINT NOT NULL,
    cid BYTEA NOT NULL,
    PRIMARY KEY (group_name, article_number)
);

CREATE UNIQUE INDEX IF NOT EXISTS article_numbers_cid_idx ON article_numbers (group_name, cid);
