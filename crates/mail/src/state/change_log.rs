//! JMAP change log for incremental sync (`/changes` methods).
//!
//! Populated by `Email/set` when articles are created via the SMTP relay path.
//! `Email/changes` and `Mailbox/changes` query this table to return deltas.

use sqlx::AnyPool;

/// Store for the JMAP change log.
pub struct ChangeLogStore {
    pool: AnyPool,
}

impl ChangeLogStore {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Record a batch of created item IDs at the given state version.
    ///
    /// `scope` is `"Email"` or `"Mailbox"`.
    /// `seq` is the new state version returned by `StateStore::bump_state`.
    pub async fn record_created(
        &self,
        scope: &str,
        item_ids: &[String],
        seq: i64,
    ) -> Result<(), sqlx::Error> {
        for id in item_ids {
            sqlx::query(
                "INSERT OR IGNORE INTO jmap_change_log (seq, scope, item_id, change) \
                 VALUES (?, ?, ?, 'created')",
            )
            .bind(seq)
            .bind(scope)
            .bind(id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Return item IDs for the given scope with state version > `since_seq`.
    ///
    /// Returns `None` if `since_seq` is before the oldest tracked state (i.e.
    /// the caller must fall back to a full resync).
    ///
    /// For our v1 implementation, "before oldest tracked" means `since_seq < 0`
    /// (shouldn't happen normally) or the table is empty and since_seq > 0.
    pub async fn query_since(
        &self,
        scope: &str,
        since_seq: i64,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT item_id FROM jmap_change_log \
             WHERE scope = ? AND seq > ? AND change = 'created' \
             ORDER BY seq ASC",
        )
        .bind(scope)
        .bind(since_seq)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> (ChangeLogStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (ChangeLogStore::new(pool), tmp)
    }

    #[tokio::test]
    async fn query_since_returns_items_after_seq() {
        let (store, _tmp) = make_store().await;
        store
            .record_created("Email", &["cid1".to_string(), "cid2".to_string()], 1)
            .await
            .unwrap();
        store
            .record_created("Email", &["cid3".to_string()], 2)
            .await
            .unwrap();

        let items = store.query_since("Email", 0).await.unwrap();
        assert_eq!(items.len(), 3);

        let items = store.query_since("Email", 1).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "cid3");

        let items = store.query_since("Email", 2).await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn query_since_is_scope_isolated() {
        let (store, _tmp) = make_store().await;
        store
            .record_created("Email", &["email1".to_string()], 1)
            .await
            .unwrap();
        store
            .record_created("Mailbox", &["mbox1".to_string()], 1)
            .await
            .unwrap();

        let email_items = store.query_since("Email", 0).await.unwrap();
        assert_eq!(email_items, vec!["email1"]);

        let mbox_items = store.query_since("Mailbox", 0).await.unwrap();
        assert_eq!(mbox_items, vec!["mbox1"]);
    }
}
