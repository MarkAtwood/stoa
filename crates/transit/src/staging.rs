//! Write-ahead staging area for inbound articles (usenet-ipfs-9mf).
//!
//! When `[staging]` is configured, articles accepted from peers are written to
//! a local directory (one file per article) and recorded in the
//! `transit_staging` SQLite table before the daemon returns success to the
//! sending peer.  A separate drain task reads from the table in arrival order
//! and processes each article through the normal IPFS pipeline.  On pipeline
//! success the file is deleted and the row is removed.
//!
//! Any rows that survive a crash or unclean shutdown are automatically
//! re-drained on the next daemon startup — the staging area serves as a
//! durable write-ahead log that bridges peer acceptance from IPFS write
//! throughput.
//!
//! # Serving staged articles
//!
//! When an article is staged but has not yet been written to IPFS, any reader
//! request for that Message-ID must be served directly from the staging file.
//! That integration point lives in the reader server's ARTICLE/HEAD/BODY
//! handler and is wired in when those handlers are implemented.

use std::path::PathBuf;
use std::sync::Arc;

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sqlx::SqlitePool;
use tokio::fs;
use tracing::warn;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Write-ahead staging configuration (`[staging]` in transit.toml).
///
/// Omit the entire section to use the in-memory ingestion queue only.
#[derive(Debug, Deserialize)]
pub struct StagingConfig {
    /// Directory for staging files.  Created at startup if it does not exist.
    pub path: String,
    /// Maximum total staging area size in bytes.  Default: 5 GiB.
    ///
    /// When this limit would be exceeded by a new article, the article is
    /// rejected with a transient 436/439 so the peer retries later.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Maximum number of staged articles.  Default: 500 000.
    ///
    /// Serves as a per-entry guard independent of byte size.
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,
    /// Number of parallel drain worker tasks.  Default: 1.
    ///
    /// Increasing this allows multiple articles to be written to IPFS
    /// concurrently but consumes more IPFS write bandwidth.
    #[serde(default = "default_drain_workers")]
    pub drain_workers: u32,
}

fn default_max_bytes() -> u64 {
    5 * 1024 * 1024 * 1024
}
fn default_max_entries() -> u64 {
    500_000
}
fn default_drain_workers() -> u32 {
    1
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors from staging operations.
#[derive(Debug)]
pub enum StagingError {
    Db(sqlx::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StagingError::Db(e) => write!(f, "staging DB error: {e}"),
            StagingError::Io(e) => write!(f, "staging I/O error: {e}"),
        }
    }
}

impl std::error::Error for StagingError {}

impl From<sqlx::Error> for StagingError {
    fn from(e: sqlx::Error) -> Self {
        StagingError::Db(e)
    }
}

impl From<std::io::Error> for StagingError {
    fn from(e: std::io::Error) -> Self {
        StagingError::Io(e)
    }
}

// ── Article record ────────────────────────────────────────────────────────────

/// An article that has been staged to disk and is ready for pipeline
/// processing.
pub struct StagedArticle {
    /// Opaque staging ID — the primary key in `transit_staging` and also the
    /// leaf filename of [`file_path`].
    pub id: String,
    /// NNTP Message-ID.
    pub message_id: String,
    /// Raw article bytes read from the staging file.
    pub bytes: Vec<u8>,
    /// Absolute path to the staging file (used by [`StagingStore::complete`]).
    pub file_path: String,
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Handle to the staging area, shared across sessions and the drain task.
pub struct StagingStore {
    pub config: StagingConfig,
    pool: Arc<SqlitePool>,
}

impl StagingStore {
    /// Create a new handle.  Does NOT create the staging directory — the caller
    /// must call [`tokio::fs::create_dir_all`] on `config.path` first.
    pub fn new(config: StagingConfig, pool: Arc<SqlitePool>) -> Self {
        Self { config, pool }
    }

    /// Write an article to the staging area.
    ///
    /// Returns `Ok(true)` if the article was staged, `Ok(false)` if either
    /// capacity limit is already reached (caller should return 436/439 to the
    /// peer).  Returns `Err` only on I/O or DB failures.
    pub async fn try_stage(
        &self,
        message_id: &str,
        bytes: &[u8],
    ) -> Result<bool, StagingError> {
        // Check entry limit.
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
                .fetch_one(&*self.pool)
                .await?;
        if count as u64 >= self.config.max_entries {
            return Ok(false);
        }

        // Check byte limit.
        let (total_bytes,): (i64,) =
            sqlx::query_as("SELECT COALESCE(SUM(byte_size), 0) FROM transit_staging")
                .fetch_one(&*self.pool)
                .await?;
        if total_bytes as u64 + bytes.len() as u64 > self.config.max_bytes {
            return Ok(false);
        }

        let id = new_staging_id();
        let file_path = PathBuf::from(&self.config.path)
            .join(&id)
            .to_string_lossy()
            .into_owned();

        // Write to disk first; if this fails the DB stays clean.
        fs::write(&file_path, bytes).await?;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let db_result = sqlx::query(
            "INSERT INTO transit_staging \
             (id, message_id, file_path, received_at, byte_size) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(message_id)
        .bind(&file_path)
        .bind(now_secs)
        .bind(bytes.len() as i64)
        .execute(&*self.pool)
        .await;

        if let Err(e) = db_result {
            // Best-effort cleanup of the orphaned file.
            let _ = fs::remove_file(&file_path).await;
            return Err(StagingError::Db(e));
        }

        Ok(true)
    }

    /// Fetch the oldest staged article from the staging directory and return it
    /// with its bytes already read into memory.
    ///
    /// Returns `Ok(None)` when the staging table is empty.
    pub async fn drain_one(&self) -> Result<Option<StagedArticle>, StagingError> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT id, message_id, file_path \
             FROM transit_staging \
             ORDER BY received_at ASC \
             LIMIT 1",
        )
        .fetch_optional(&*self.pool)
        .await?;

        let Some((id, message_id, file_path)) = row else {
            return Ok(None);
        };

        let bytes = fs::read(&file_path).await?;
        Ok(Some(StagedArticle { id, message_id, bytes, file_path }))
    }

    /// Remove the staging file and its DB row after the pipeline has
    /// successfully processed the article.
    pub async fn complete(&self, article: &StagedArticle) -> Result<(), StagingError> {
        if let Err(e) = fs::remove_file(&article.file_path).await {
            warn!(id = %article.id, "could not remove staging file: {e}");
        }
        sqlx::query("DELETE FROM transit_staging WHERE id = ?")
            .bind(&article.id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    /// Return the number of articles currently in the staging table.
    ///
    /// Used at startup to log how many articles survived the previous run and
    /// will be re-drained.
    pub async fn pending_count(&self) -> Result<u64, StagingError> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
                .fetch_one(&*self.pool)
                .await?;
        Ok(count as u64)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generate a random 32-character lowercase-hex staging ID.
fn new_staging_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory SQLite pool with the staging schema applied.
    async fn make_pool() -> Arc<SqlitePool> {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE transit_staging (
                id          TEXT    NOT NULL PRIMARY KEY,
                message_id  TEXT    NOT NULL UNIQUE,
                file_path   TEXT    NOT NULL,
                received_at INTEGER NOT NULL,
                byte_size   INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        Arc::new(pool)
    }

    fn staging_config(dir: &str) -> StagingConfig {
        StagingConfig {
            path: dir.to_owned(),
            max_bytes: 10 * 1024 * 1024,
            max_entries: 100,
            drain_workers: 1,
        }
    }

    #[tokio::test]
    async fn try_stage_writes_file_and_row() {
        let dir = tempfile::tempdir().unwrap();
        let pool = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        let bytes = b"From: test@example.com\r\nSubject: test\r\n\r\nbody\r\n";
        let ok = store.try_stage("<a@b>", bytes).await.unwrap();
        assert!(ok, "should have staged the article");

        // Row in DB.
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
                .fetch_one(&*pool)
                .await
                .unwrap();
        assert_eq!(count, 1);

        // File on disk.
        let row: (String,) =
            sqlx::query_as("SELECT file_path FROM transit_staging")
                .fetch_one(&*pool)
                .await
                .unwrap();
        assert!(
            std::path::Path::new(&row.0).exists(),
            "staging file must exist"
        );
    }

    #[tokio::test]
    async fn drain_one_returns_correct_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let pool = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        let body = b"From: x@y\r\n\r\nhello\r\n";
        store.try_stage("<x@y>", body).await.unwrap();

        let article = store.drain_one().await.unwrap().expect("should have one article");
        assert_eq!(article.message_id, "<x@y>");
        assert_eq!(article.bytes, body);
    }

    #[tokio::test]
    async fn drain_one_empty_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let pool = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool);

        assert!(store.drain_one().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn complete_removes_file_and_row() {
        let dir = tempfile::tempdir().unwrap();
        let pool = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        store.try_stage("<del@test>", b"bytes").await.unwrap();
        let article = store.drain_one().await.unwrap().unwrap();
        let path = article.file_path.clone();

        store.complete(&article).await.unwrap();

        assert!(!std::path::Path::new(&path).exists(), "file must be deleted");
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
                .fetch_one(&*pool)
                .await
                .unwrap();
        assert_eq!(count, 0, "row must be deleted");
    }

    #[tokio::test]
    async fn try_stage_rejects_when_max_entries_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let pool = make_pool().await;
        let config = StagingConfig {
            path: dir.path().to_str().unwrap().to_owned(),
            max_bytes: 100 * 1024 * 1024,
            max_entries: 1,
            drain_workers: 1,
        };
        let store = StagingStore::new(config, pool);

        assert!(store.try_stage("<one@a>", b"x").await.unwrap(), "first should succeed");
        let second = store.try_stage("<two@a>", b"y").await.unwrap();
        assert!(!second, "second must fail: max_entries=1 already reached");
    }

    #[tokio::test]
    async fn try_stage_rejects_when_max_bytes_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let pool = make_pool().await;
        let config = StagingConfig {
            path: dir.path().to_str().unwrap().to_owned(),
            max_bytes: 5,
            max_entries: 100,
            drain_workers: 1,
        };
        let store = StagingStore::new(config, pool);

        let big = b"123456";
        let ok = store.try_stage("<big@a>", big).await.unwrap();
        assert!(!ok, "should reject: 6 bytes > max_bytes=5");
    }

    #[tokio::test]
    async fn pending_count_reflects_staged_articles() {
        let dir = tempfile::tempdir().unwrap();
        let pool = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool);

        assert_eq!(store.pending_count().await.unwrap(), 0);
        store.try_stage("<c1@t>", b"a").await.unwrap();
        store.try_stage("<c2@t>", b"b").await.unwrap();
        assert_eq!(store.pending_count().await.unwrap(), 2);
    }
}
