CREATE TABLE IF NOT EXISTS overview (
    group_name TEXT NOT NULL,
    article_number BIGINT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    from_header TEXT NOT NULL DEFAULT '',
    date_header TEXT NOT NULL DEFAULT '',
    message_id TEXT NOT NULL DEFAULT '',
    references_header TEXT NOT NULL DEFAULT '',
    byte_count BIGINT NOT NULL DEFAULT 0,
    line_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (group_name, article_number)
);
