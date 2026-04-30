CREATE TABLE IF NOT EXISTS activitypub_followers (
    group_name TEXT NOT NULL,
    actor_url  TEXT NOT NULL,
    inbox_url  TEXT NOT NULL,
    followed_at BIGINT NOT NULL,
    PRIMARY KEY (group_name, actor_url)
);
