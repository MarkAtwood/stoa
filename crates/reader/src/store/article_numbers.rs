//! SQLite-backed local article number store.
//!
//! Assigns and records sequential article numbers per group. Numbers are
//! local to this reader instance and are never treated as network-stable
//! identifiers (see design invariant #5).

use cid::Cid;
use sqlx::SqlitePool;

/// Assigns and records local sequential article numbers per group.
///
/// CIDs are stored as raw bytes (`cid.to_bytes()`).
pub struct ArticleNumberStore {
    pool: SqlitePool,
}

impl ArticleNumberStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Assign a sequential article number to a CID within a group.
    ///
    /// Idempotent: if `(group, cid)` already has a number, return it.
    /// Numbers start at 1 and increment by 1.
    pub async fn assign_number(&self, group: &str, cid: &Cid) -> Result<u64, sqlx::Error> {
        let cid_bytes = cid.to_bytes();

        let mut tx = self.pool.begin().await?;

        // Check if this (group, cid) pair already has a number.
        let existing: Option<i64> = sqlx::query_scalar(
            "SELECT article_number FROM article_numbers WHERE group_name = ? AND cid = ?",
        )
        .bind(group)
        .bind(&cid_bytes)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(n) = existing {
            tx.commit().await?;
            return Ok(n as u64);
        }

        // Compute the next number: MAX + 1, or 1 if the group is empty.
        let next: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(article_number), 0) + 1 FROM article_numbers WHERE group_name = ?",
        )
        .bind(group)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO article_numbers (group_name, article_number, cid) VALUES (?, ?, ?)",
        )
        .bind(group)
        .bind(next)
        .bind(&cid_bytes)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(next as u64)
    }

    /// Look up the CID for a given `(group, number)` pair.
    ///
    /// Returns `None` if no article with that number exists in the group.
    pub async fn lookup_cid(&self, group: &str, number: u64) -> Result<Option<Cid>, sqlx::Error> {
        let number = number as i64;

        let row: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT cid FROM article_numbers WHERE group_name = ? AND article_number = ?",
        )
        .bind(group)
        .bind(number)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some(bytes) => {
                let cid = Cid::try_from(bytes.as_slice())
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
                Ok(Some(cid))
            }
        }
    }

    /// Return all `(group_name, article_number, cid)` rows across all groups.
    ///
    /// Used for startup backfill of the overview index.
    pub async fn list_all_articles(&self) -> Result<Vec<(String, u64, Cid)>, sqlx::Error> {
        #[derive(sqlx::FromRow)]
        struct Row {
            group_name: String,
            article_number: i64,
            cid: Vec<u8>,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT group_name, article_number, cid FROM article_numbers ORDER BY group_name, article_number",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let cid = Cid::try_from(row.cid.as_slice())
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
                Ok((row.group_name, row.article_number as u64, cid))
            })
            .collect()
    }

    /// Return the `(low, high)` article number range for a group.
    ///
    /// Returns `(1, 0)` for an empty group (RFC 3977 convention: `low > high`
    /// means empty).
    pub async fn group_range(&self, group: &str) -> Result<(u64, u64), sqlx::Error> {
        let row: (Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT MIN(article_number), MAX(article_number) FROM article_numbers WHERE group_name = ?",
        )
        .bind(group)
        .fetch_one(&self.pool)
        .await?;

        match row {
            (Some(lo), Some(hi)) => Ok((lo as u64, hi as u64)),
            // No rows for this group — return the RFC 3977 empty sentinel.
            _ => Ok((1, 0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;

    async fn make_store() -> (ArticleNumberStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        (ArticleNumberStore::new(pool), tmp)
    }

    fn test_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x55, Code::Sha2_256.digest(data))
    }

    #[tokio::test]
    async fn assign_sequential() {
        let (store, _tmp) = make_store().await;

        let n1 = store
            .assign_number("comp.lang.rust", &test_cid(b"article-1"))
            .await
            .unwrap();
        let n2 = store
            .assign_number("comp.lang.rust", &test_cid(b"article-2"))
            .await
            .unwrap();
        let n3 = store
            .assign_number("comp.lang.rust", &test_cid(b"article-3"))
            .await
            .unwrap();

        assert_eq!(n1, 1);
        assert_eq!(n2, 2);
        assert_eq!(n3, 3);
    }

    #[tokio::test]
    async fn assign_idempotent() {
        let (store, _tmp) = make_store().await;
        let cid = test_cid(b"idempotent-article");

        let first = store.assign_number("comp.lang.rust", &cid).await.unwrap();
        let second = store.assign_number("comp.lang.rust", &cid).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(first, 1);
    }

    #[tokio::test]
    async fn lookup_cid() {
        let (store, _tmp) = make_store().await;
        let cid = test_cid(b"lookup-article");

        let number = store.assign_number("comp.lang.rust", &cid).await.unwrap();
        let found = store.lookup_cid("comp.lang.rust", number).await.unwrap();

        assert_eq!(found, Some(cid));
    }

    #[tokio::test]
    async fn lookup_missing() {
        let (store, _tmp) = make_store().await;

        let found = store.lookup_cid("comp.lang.rust", 9999).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn group_range_empty() {
        let (store, _tmp) = make_store().await;

        let (lo, hi) = store.group_range("comp.lang.rust").await.unwrap();
        assert_eq!((lo, hi), (1, 0));
    }

    #[tokio::test]
    async fn group_range_after_inserts() {
        let (store, _tmp) = make_store().await;

        store
            .assign_number("comp.lang.rust", &test_cid(b"r1"))
            .await
            .unwrap();
        store
            .assign_number("comp.lang.rust", &test_cid(b"r2"))
            .await
            .unwrap();
        store
            .assign_number("comp.lang.rust", &test_cid(b"r3"))
            .await
            .unwrap();

        let (lo, hi) = store.group_range("comp.lang.rust").await.unwrap();
        assert_eq!((lo, hi), (1, 3));
    }

    #[tokio::test]
    async fn multi_group_isolation() {
        let (store, _tmp) = make_store().await;

        let a1 = store
            .assign_number("comp.lang.rust", &test_cid(b"rust-1"))
            .await
            .unwrap();
        let b1 = store
            .assign_number("alt.test", &test_cid(b"test-1"))
            .await
            .unwrap();
        let a2 = store
            .assign_number("comp.lang.rust", &test_cid(b"rust-2"))
            .await
            .unwrap();
        let b2 = store
            .assign_number("alt.test", &test_cid(b"test-2"))
            .await
            .unwrap();

        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(b1, 1);
        assert_eq!(b2, 2);
    }
}
