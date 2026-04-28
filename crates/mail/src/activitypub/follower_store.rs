//! SQLite store for ActivityPub group followers.

use sqlx::AnyPool;
use std::time::{SystemTime, UNIX_EPOCH};

/// A remote actor that follows a newsgroup.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Follower {
    pub group_name: String,
    pub actor_url: String,
    pub inbox_url: String,
    pub followed_at: i64,
}

/// Persistent store for group followers.
pub struct FollowerStore {
    pool: AnyPool,
}

impl FollowerStore {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Add or update a follower for a group.
    pub async fn add(
        &self,
        group_name: &str,
        actor_url: &str,
        inbox_url: &str,
    ) -> Result<(), sqlx::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        sqlx::query(
            "INSERT INTO activitypub_followers (group_name, actor_url, inbox_url, followed_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(group_name, actor_url) DO UPDATE SET inbox_url = excluded.inbox_url",
        )
        .bind(group_name)
        .bind(actor_url)
        .bind(inbox_url)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove a follower from a group.
    pub async fn remove(&self, group_name: &str, actor_url: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM activitypub_followers WHERE group_name = ? AND actor_url = ?")
            .bind(group_name)
            .bind(actor_url)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List all followers for a group, returning their inbox URLs.
    pub async fn list(&self, group_name: &str) -> Result<Vec<Follower>, sqlx::Error> {
        let rows = sqlx::query_as::<_, Follower>(
            "SELECT group_name, actor_url, inbox_url, followed_at
             FROM activitypub_followers WHERE group_name = ?
             ORDER BY followed_at ASC",
        )
        .bind(group_name)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Return true if the given actor is following the group.
    pub async fn is_follower(
        &self,
        group_name: &str,
        actor_url: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM activitypub_followers WHERE group_name = ? AND actor_url = ?",
        )
        .bind(group_name)
        .bind(actor_url)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> (FollowerStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (FollowerStore::new(pool), tmp)
    }

    #[tokio::test]
    async fn add_and_list_follower() {
        let (store, _tmp) = make_store().await;
        store
            .add(
                "comp.lang.rust",
                "https://mastodon.social/users/alice",
                "https://mastodon.social/users/alice/inbox",
            )
            .await
            .unwrap();
        let followers = store.list("comp.lang.rust").await.unwrap();
        assert_eq!(followers.len(), 1);
        assert_eq!(
            followers[0].actor_url,
            "https://mastodon.social/users/alice"
        );
    }

    #[tokio::test]
    async fn remove_follower() {
        let (store, _tmp) = make_store().await;
        store
            .add(
                "comp.lang.rust",
                "https://mastodon.social/users/alice",
                "https://mastodon.social/users/alice/inbox",
            )
            .await
            .unwrap();
        store
            .remove("comp.lang.rust", "https://mastodon.social/users/alice")
            .await
            .unwrap();
        let followers = store.list("comp.lang.rust").await.unwrap();
        assert!(followers.is_empty());
    }

    #[tokio::test]
    async fn is_follower_returns_correct_result() {
        let (store, _tmp) = make_store().await;
        assert!(!store
            .is_follower("comp.lang.rust", "https://mastodon.social/users/alice")
            .await
            .unwrap());
        store
            .add(
                "comp.lang.rust",
                "https://mastodon.social/users/alice",
                "https://mastodon.social/users/alice/inbox",
            )
            .await
            .unwrap();
        assert!(store
            .is_follower("comp.lang.rust", "https://mastodon.social/users/alice")
            .await
            .unwrap());
    }
}
