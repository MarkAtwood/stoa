use cid::Cid;
use sqlx::SqlitePool;

/// Per-user article flags: \Seen and \Flagged (JMAP keywords).
pub struct Flags {
    pub seen: bool,
    pub flagged: bool,
}

pub struct UserFlagsStore {
    pool: SqlitePool,
}

impl UserFlagsStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Set \Seen and \Flagged for (user_id, cid). Creates the row if absent.
    pub async fn set_flags(
        &self,
        user_id: i64,
        cid: &Cid,
        seen: bool,
        flagged: bool,
    ) -> Result<(), sqlx::Error> {
        let cid_bytes = cid.to_bytes();
        sqlx::query(
            "INSERT INTO user_flags (user_id, article_cid, seen, flagged)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(user_id, article_cid) DO UPDATE SET seen = ?, flagged = ?",
        )
        .bind(user_id)
        .bind(&cid_bytes)
        .bind(seen as i64)
        .bind(flagged as i64)
        .bind(seen as i64)
        .bind(flagged as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get flags for (user_id, cid). Returns None if no row exists (all flags default to false).
    pub async fn get_flags(&self, user_id: i64, cid: &Cid) -> Result<Option<Flags>, sqlx::Error> {
        let cid_bytes = cid.to_bytes();
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT seen, flagged FROM user_flags WHERE user_id = ? AND article_cid = ?",
        )
        .bind(user_id)
        .bind(&cid_bytes)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(seen, flagged)| Flags {
            seen: seen != 0,
            flagged: flagged != 0,
        }))
    }

    /// Return all CIDs that match a given flag for a user.
    /// Used for listing unseen/flagged articles.
    pub async fn list_cids_with_flag(
        &self,
        user_id: i64,
        seen: Option<bool>,
        flagged: Option<bool>,
    ) -> Result<Vec<Cid>, sqlx::Error> {
        let rows: Vec<Vec<u8>> = match (seen, flagged) {
            (None, None) => sqlx::query_scalar(
                "SELECT article_cid FROM user_flags WHERE user_id = ?",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?,
            (Some(s), None) => sqlx::query_scalar(
                "SELECT article_cid FROM user_flags WHERE user_id = ? AND seen = ?",
            )
            .bind(user_id)
            .bind(s as i64)
            .fetch_all(&self.pool)
            .await?,
            (None, Some(f)) => sqlx::query_scalar(
                "SELECT article_cid FROM user_flags WHERE user_id = ? AND flagged = ?",
            )
            .bind(user_id)
            .bind(f as i64)
            .fetch_all(&self.pool)
            .await?,
            (Some(s), Some(f)) => sqlx::query_scalar(
                "SELECT article_cid FROM user_flags WHERE user_id = ? AND seen = ? AND flagged = ?",
            )
            .bind(user_id)
            .bind(s as i64)
            .bind(f as i64)
            .fetch_all(&self.pool)
            .await?,
        };
        rows.into_iter()
            .map(|bytes| {
                Cid::try_from(bytes.as_slice()).map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

    fn test_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    async fn make_store() -> UserFlagsStore {
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:flags_test_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("pool");
        crate::migrations::run_migrations(&pool)
            .await
            .expect("migrations");
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .expect("insert user");
        UserFlagsStore::new(pool)
    }

    #[tokio::test]
    async fn get_flags_returns_none_for_unset() {
        let store = make_store().await;
        let cid = test_cid(b"article-1");
        let flags = store.get_flags(1, &cid).await.unwrap();
        assert!(flags.is_none());
    }

    #[tokio::test]
    async fn set_and_get_flags() {
        let store = make_store().await;
        let cid = test_cid(b"article-2");
        store.set_flags(1, &cid, true, false).await.unwrap();
        let flags = store.get_flags(1, &cid).await.unwrap().expect("must exist");
        assert!(flags.seen);
        assert!(!flags.flagged);
    }

    #[tokio::test]
    async fn toggle_seen_does_not_affect_flagged() {
        let store = make_store().await;
        let cid = test_cid(b"article-3");
        store.set_flags(1, &cid, false, true).await.unwrap();
        store.set_flags(1, &cid, true, true).await.unwrap();
        let flags = store.get_flags(1, &cid).await.unwrap().expect("must exist");
        assert!(flags.seen);
        assert!(flags.flagged, "flagged must still be true");
    }

    #[tokio::test]
    async fn list_cids_with_seen_flag() {
        let store = make_store().await;
        let c1 = test_cid(b"seen-article");
        let c2 = test_cid(b"unseen-article");
        store.set_flags(1, &c1, true, false).await.unwrap();
        store.set_flags(1, &c2, false, false).await.unwrap();
        let seen_cids = store
            .list_cids_with_flag(1, Some(true), None)
            .await
            .unwrap();
        assert_eq!(seen_cids.len(), 1);
        assert_eq!(seen_cids[0], c1);
    }
}
