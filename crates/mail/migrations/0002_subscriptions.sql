CREATE TABLE IF NOT EXISTS subscriptions (
    user_id INTEGER NOT NULL,
    group_name TEXT NOT NULL,
    subscribed_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, group_name),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
