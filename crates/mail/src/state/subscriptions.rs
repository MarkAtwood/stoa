use sqlx::SqlitePool;

/// Manages per-user newsgroup subscriptions.
pub struct SubscriptionStore {
    pool: SqlitePool,
}

impl SubscriptionStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Subscribe a user to a group (idempotent).
    pub async fn subscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        sqlx::query(
            "INSERT INTO subscriptions (user_id, group_name, subscribed_at) VALUES (?, ?, ?)
             ON CONFLICT(user_id, group_name) DO NOTHING",
        )
        .bind(user_id)
        .bind(group_name)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Unsubscribe a user from a group (idempotent).
    pub async fn unsubscribe(&self, user_id: i64, group_name: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "DELETE FROM subscriptions WHERE user_id = ? AND group_name = ?",
        )
        .bind(user_id)
        .bind(group_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return all group names a user is subscribed to.
    pub async fn list_subscribed(&self, user_id: i64) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT group_name FROM subscriptions WHERE user_id = ? ORDER BY group_name")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
    }

    /// Check whether a user is subscribed to a specific group.
    pub async fn is_subscribed(&self, user_id: i64, group_name: &str) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subscriptions WHERE user_id = ? AND group_name = ?",
        )
        .bind(user_id)
        .bind(group_name)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::str::FromStr as _;

    static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

    async fn make_store() -> SubscriptionStore {
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:sub_test_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("pool");
        crate::migrations::run_migrations(&pool).await.expect("migrations");
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .expect("insert user");
        SubscriptionStore::new(pool)
    }

    #[tokio::test]
    async fn subscribe_and_list() {
        let store = make_store().await;
        store.subscribe(1, "comp.lang.rust").await.unwrap();
        store.subscribe(1, "alt.test").await.unwrap();
        let subs = store.list_subscribed(1).await.unwrap();
        assert_eq!(subs.len(), 2);
        assert!(subs.contains(&"comp.lang.rust".to_string()));
        assert!(subs.contains(&"alt.test".to_string()));
    }

    #[tokio::test]
    async fn subscribe_idempotent() {
        let store = make_store().await;
        store.subscribe(1, "comp.lang.rust").await.unwrap();
        store.subscribe(1, "comp.lang.rust").await.unwrap(); // must not error
        let subs = store.list_subscribed(1).await.unwrap();
        assert_eq!(subs.len(), 1);
    }

    #[tokio::test]
    async fn unsubscribe_removes() {
        let store = make_store().await;
        store.subscribe(1, "comp.lang.rust").await.unwrap();
        store.unsubscribe(1, "comp.lang.rust").await.unwrap();
        let subs = store.list_subscribed(1).await.unwrap();
        assert!(subs.is_empty());
    }

    #[tokio::test]
    async fn is_subscribed_check() {
        let store = make_store().await;
        assert!(!store.is_subscribed(1, "comp.lang.rust").await.unwrap());
        store.subscribe(1, "comp.lang.rust").await.unwrap();
        assert!(store.is_subscribed(1, "comp.lang.rust").await.unwrap());
    }
}
