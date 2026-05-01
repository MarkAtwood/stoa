//! Write-ahead staging area for inbound articles (stoa-9mf).
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
use sqlx::AnyPool;
use tokio::fs;
use tracing::warn;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Write-ahead staging configuration (`[staging]` in transit.toml).
///
/// Omit the entire section to use the in-memory ingestion queue only.
#[derive(Debug, Clone, Deserialize)]
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
    pool: Arc<AnyPool>,
}

impl StagingStore {
    /// Create a new handle.  Does NOT create the staging directory — the caller
    /// must call [`tokio::fs::create_dir_all`] on `config.path` first.
    pub fn new(config: StagingConfig, pool: Arc<AnyPool>) -> Self {
        Self { config, pool }
    }

    /// Write an article to the staging area.
    ///
    /// Returns `Ok(true)` if the article was staged, `Ok(false)` if either
    /// capacity limit is already reached (caller should return 436/439 to the
    /// peer).  Returns `Err` only on I/O or DB failures.
    ///
    /// The capacity check and the INSERT are performed inside a single
    /// `BEGIN IMMEDIATE` transaction so that concurrent callers cannot both
    /// pass the checks and collectively exceed the configured limits.
    pub async fn try_stage(&self, message_id: &str, bytes: &[u8]) -> Result<bool, StagingError> {
        let id = new_staging_id();
        let path_buf = PathBuf::from(&self.config.path).join(&id);
        let file_path = path_buf.to_str().ok_or_else(|| {
            StagingError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "staging path contains non-UTF-8 bytes: {}",
                    path_buf.display()
                ),
            ))
        })?;

        // Write to disk before taking the DB lock.  If the DB checks reject
        // the article we delete the file; if the DB write fails we also
        // delete it.  In the pathological case where this future is cancelled
        // after fs::write but before COMMIT, the file is left as an orphan;
        // cleanup_orphaned_files() removes these at drain-task startup.
        fs::write(&file_path, bytes).await?;

        // BEGIN IMMEDIATE: takes a write lock before the capacity checks so
        // no concurrent caller can insert between our checks and our INSERT.
        // We use a raw connection and manual BEGIN IMMEDIATE / COMMIT because
        // sqlx's pool.begin() issues `BEGIN` (deferred), which only upgrades
        // to a write lock on the first write — too late for our read-check.
        let mut conn = match self.pool.acquire().await {
            Ok(c) => c,
            Err(e) => {
                let _ = fs::remove_file(&file_path).await;
                return Err(StagingError::Db(e));
            }
        };

        if let Err(e) = sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await {
            let _ = fs::remove_file(&file_path).await;
            return Err(StagingError::Db(e));
        }

        let result: Result<bool, StagingError> = async {
            let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
                .fetch_one(&mut *conn)
                .await?;
            if count as u64 >= self.config.max_entries {
                return Ok(false);
            }

            let (total_bytes,): (i64,) =
                sqlx::query_as("SELECT COALESCE(SUM(byte_size), 0) FROM transit_staging")
                    .fetch_one(&mut *conn)
                    .await?;
            if total_bytes as u64 + bytes.len() as u64 > self.config.max_bytes {
                return Ok(false);
            }

            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            sqlx::query(
                "INSERT INTO transit_staging \
                 (id, message_id, file_path, received_at, byte_size) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(message_id)
            .bind(file_path)
            .bind(now_secs)
            .bind(bytes.len() as i64)
            .execute(&mut *conn)
            .await?;

            Ok(true)
        }
        .await;

        match &result {
            Ok(true) => {
                if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
                    let _ = fs::remove_file(&file_path).await;
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(StagingError::Db(e));
                }
            }
            Ok(false) => {
                let _ = fs::remove_file(&file_path).await;
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            }
            Err(_) => {
                let _ = fs::remove_file(&file_path).await;
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            }
        }

        result
    }

    /// Fetch the oldest unclaimed staged article and atomically mark it as
    /// claimed so that concurrent drain workers never process the same article.
    ///
    /// Returns `Ok(None)` when the staging table has no unclaimed rows.
    pub async fn drain_one(&self) -> Result<Option<StagedArticle>, StagingError> {
        // BEGIN IMMEDIATE prevents any other writer from inserting or updating
        // between the SELECT and the UPDATE, making the claim exclusive even
        // with multiple concurrent drain workers.
        //
        // pool.begin() issues DEFERRED which only upgrades to a write lock on
        // the first write — too late; another worker could SELECT the same
        // unclaimed row between our SELECT and our UPDATE.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut conn = match self.pool.acquire().await {
            Ok(c) => c,
            Err(e) => return Err(StagingError::Db(e)),
        };

        if let Err(e) = sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await {
            return Err(StagingError::Db(e));
        }

        let result: Result<Option<(String, String, String)>, StagingError> = async {
            let row: Option<(String, String, String)> = sqlx::query_as(
                "SELECT id, message_id, file_path \
                 FROM transit_staging \
                 WHERE claimed_at IS NULL \
                 ORDER BY received_at ASC \
                 LIMIT 1",
            )
            .fetch_optional(&mut *conn)
            .await?;

            if let Some((ref id, _, _)) = row {
                sqlx::query("UPDATE transit_staging SET claimed_at = ? WHERE id = ?")
                    .bind(now_secs)
                    .bind(id)
                    .execute(&mut *conn)
                    .await?;
            }

            Ok(row)
        }
        .await;

        match result {
            Ok(None) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Ok(None)
            }
            Ok(Some((id, message_id, file_path))) => {
                if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(StagingError::Db(e));
                }
                let bytes = fs::read(&file_path).await?;
                Ok(Some(StagedArticle {
                    id,
                    message_id,
                    bytes,
                    file_path,
                }))
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    /// Clear stale claims left by a previous run that crashed after claiming
    /// but before completing an article.  Call once at drain-task startup.
    pub async fn reset_claims(&self) -> Result<(), StagingError> {
        sqlx::query("UPDATE transit_staging SET claimed_at = NULL")
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    /// Delete staging files that have no corresponding row in `transit_staging`.
    ///
    /// Orphans are produced when `try_stage` writes the file but is cancelled
    /// (e.g. peer disconnects) before the `COMMIT`.  Call once at drain-task
    /// startup alongside [`reset_claims`](Self::reset_claims).
    ///
    /// Non-fatal: logs warnings for any file that cannot be removed; returns
    /// `Ok(count)` where count is the number of orphan files deleted.
    pub async fn cleanup_orphaned_files(&self) -> Result<u32, StagingError> {
        // Collect IDs that currently have a DB row.
        let rows: Vec<(String,)> = sqlx::query_as("SELECT id FROM transit_staging")
            .fetch_all(&*self.pool)
            .await?;
        let known_ids: std::collections::HashSet<String> =
            rows.into_iter().map(|(id,)| id).collect();

        let dir = std::path::Path::new(&self.config.path);
        let mut read_dir = match fs::read_dir(dir).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(StagingError::Io(e)),
        };

        let mut deleted = 0u32;
        loop {
            let entry = match read_dir.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(e) => {
                    warn!("staging cleanup: error reading directory entry: {e}");
                    continue;
                }
            };
            let name = entry.file_name();
            let id = name.to_string_lossy();
            if !known_ids.contains(id.as_ref()) {
                let path = entry.path();
                match fs::remove_file(&path).await {
                    Ok(()) => {
                        tracing::info!(path = %path.display(), "staging: removed orphaned file");
                        deleted += 1;
                    }
                    Err(e) => {
                        warn!(path = %path.display(), "staging: could not remove orphaned file: {e}");
                    }
                }
            }
        }
        Ok(deleted)
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

    /// Remove the staging file and its DB row after a permanent pipeline
    /// failure.  Called when the article can never be processed successfully
    /// (e.g. missing Message-ID, signing self-check failure).
    ///
    /// Identical cleanup logic to [`complete`](Self::complete) but named
    /// separately to make the failure path explicit at call sites.
    pub async fn purge(&self, article: &StagedArticle) -> Result<(), StagingError> {
        if let Err(e) = fs::remove_file(&article.file_path).await {
            warn!(id = %article.id, "could not remove staging file on purge: {e}");
        }
        sqlx::query("DELETE FROM transit_staging WHERE id = ?")
            .bind(&article.id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    /// Increment the `retry_count` for a transiently-failed article and reset
    /// `claimed_at` to `NULL` so the row becomes eligible for the next drain
    /// pass.
    ///
    /// Returns the new `retry_count` so the caller can compare it against the
    /// configured maximum and call [`purge`](Self::purge) when the limit is
    /// reached.
    pub async fn increment_retry_count(&self, article: &StagedArticle) -> Result<i64, StagingError> {
        let row: (i64,) = sqlx::query_as(
            "UPDATE transit_staging \
             SET retry_count = retry_count + 1, claimed_at = NULL \
             WHERE id = ? \
             RETURNING retry_count",
        )
        .bind(&article.id)
        .fetch_one(&*self.pool)
        .await?;
        Ok(row.0)
    }

    /// Return the number of articles currently in the staging table.
    ///
    /// Used at startup to log how many articles survived the previous run and
    /// will be re-drained.
    pub async fn pending_count(&self) -> Result<u64, StagingError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
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

    /// Temp-file SQLite pool with the staging schema applied via migrations.
    ///
    /// Returns `(pool, tmp)` — keep `tmp` alive for the test duration so the
    /// temp file is not deleted before the pool is dropped.
    async fn make_pool() -> (Arc<AnyPool>, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (Arc::new(pool), tmp)
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
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        let bytes = b"From: test@example.com\r\nSubject: test\r\n\r\nbody\r\n";
        let ok = store.try_stage("<a@b>", bytes).await.unwrap();
        assert!(ok, "should have staged the article");

        // Row in DB.
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(count, 1);

        // File on disk.
        let row: (String,) = sqlx::query_as("SELECT file_path FROM transit_staging")
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
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        let body = b"From: x@y\r\n\r\nhello\r\n";
        store.try_stage("<x@y>", body).await.unwrap();

        let article = store
            .drain_one()
            .await
            .unwrap()
            .expect("should have one article");
        assert_eq!(article.message_id, "<x@y>");
        assert_eq!(article.bytes, body);
    }

    #[tokio::test]
    async fn drain_one_empty_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool);

        assert!(store.drain_one().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn complete_removes_file_and_row() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        store.try_stage("<del@test>", b"bytes").await.unwrap();
        let article = store.drain_one().await.unwrap().unwrap();
        let path = article.file_path.clone();

        store.complete(&article).await.unwrap();

        assert!(
            !std::path::Path::new(&path).exists(),
            "file must be deleted"
        );
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "row must be deleted");
    }

    #[tokio::test]
    async fn try_stage_rejects_when_max_entries_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let config = StagingConfig {
            path: dir.path().to_str().unwrap().to_owned(),
            max_bytes: 100 * 1024 * 1024,
            max_entries: 1,
            drain_workers: 1,
        };
        let store = StagingStore::new(config, pool);

        assert!(
            store.try_stage("<one@a>", b"x").await.unwrap(),
            "first should succeed"
        );
        let second = store.try_stage("<two@a>", b"y").await.unwrap();
        assert!(!second, "second must fail: max_entries=1 already reached");
    }

    #[tokio::test]
    async fn try_stage_rejects_when_max_bytes_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
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

    /// Two sequential drain_one() calls on a store with one article: the second
    /// call must return None because the first has claimed the only row.
    #[tokio::test]
    async fn drain_one_claims_exclusively() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        let body = b"From: x@y\r\n\r\nclaim test\r\n";
        store.try_stage("<claim@test>", body).await.unwrap();

        let first = store.drain_one().await.unwrap();
        assert!(first.is_some(), "first drain_one must return the article");

        let second = store.drain_one().await.unwrap();
        assert!(
            second.is_none(),
            "second drain_one must return None: article already claimed"
        );
    }

    /// reset_claims clears claimed_at so the article can be re-drained.
    #[tokio::test]
    async fn reset_claims_allows_redrain() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        store.try_stage("<reset@test>", b"bytes").await.unwrap();
        let _ = store.drain_one().await.unwrap(); // claim it

        store.reset_claims().await.unwrap();

        let re = store.drain_one().await.unwrap();
        assert!(
            re.is_some(),
            "after reset_claims the article must be re-drainable"
        );
    }

    #[tokio::test]
    async fn pending_count_reflects_staged_articles() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool);

        assert_eq!(store.pending_count().await.unwrap(), 0);
        store.try_stage("<c1@t>", b"a").await.unwrap();
        store.try_stage("<c2@t>", b"b").await.unwrap();
        assert_eq!(store.pending_count().await.unwrap(), 2);
    }

    /// cleanup_orphaned_files removes files in the staging dir that have no DB row.
    /// Simulates a try_stage cancellation after fs::write but before COMMIT.
    #[tokio::test]
    async fn cleanup_orphaned_files_removes_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        // Stage a legitimate article so there is a known ID in the DB.
        store.try_stage("<legit@t>", b"hello").await.unwrap();

        // Manually write an orphaned file (no DB row).
        let orphan_path = dir.path().join("deadbeef00000000000000000000dead");
        fs::write(&orphan_path, b"orphan").await.unwrap();

        let deleted = store.cleanup_orphaned_files().await.unwrap();
        assert_eq!(deleted, 1, "exactly one orphan must be deleted");
        assert!(!orphan_path.exists(), "orphan file must be gone");

        // The legitimate file must still exist.
        let row: (String,) = sqlx::query_as("SELECT file_path FROM transit_staging")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert!(
            std::path::Path::new(&row.0).exists(),
            "legitimate staging file must survive cleanup"
        );
    }

    /// cleanup_orphaned_files on a non-existent directory returns Ok(0).
    #[tokio::test]
    async fn cleanup_orphaned_files_missing_dir_returns_zero() {
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(
            staging_config("/tmp/stoa-staging-does-not-exist-xyzzy"),
            pool,
        );
        let deleted = store.cleanup_orphaned_files().await.unwrap();
        assert_eq!(deleted, 0);
    }

    /// purge removes the staging file and DB row on permanent failure.
    #[tokio::test]
    async fn purge_removes_file_and_row() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        store.try_stage("<purge@test>", b"bytes").await.unwrap();
        let article = store.drain_one().await.unwrap().unwrap();
        let path = article.file_path.clone();

        store.purge(&article).await.unwrap();

        assert!(
            !std::path::Path::new(&path).exists(),
            "staging file must be deleted after purge"
        );
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transit_staging")
            .fetch_one(&*pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "DB row must be deleted after purge");
    }

    /// increment_retry_count increments the counter and resets claimed_at so
    /// the article can be re-drained.
    #[tokio::test]
    async fn increment_retry_count_resets_claim_and_increments() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, _tmp) = make_pool().await;
        let store = StagingStore::new(staging_config(dir.path().to_str().unwrap()), pool.clone());

        store.try_stage("<retry@test>", b"bytes").await.unwrap();
        let article = store.drain_one().await.unwrap().unwrap();

        // Article is now claimed; second drain_one must return None.
        assert!(store.drain_one().await.unwrap().is_none());

        let new_count = store.increment_retry_count(&article).await.unwrap();
        assert_eq!(new_count, 1, "retry_count must be 1 after first increment");

        // claimed_at has been cleared; article is drainable again.
        let re = store.drain_one().await.unwrap();
        assert!(
            re.is_some(),
            "article must be re-drainable after increment_retry_count"
        );

        // Second increment gives 2.
        let article2 = re.unwrap();
        let new_count2 = store.increment_retry_count(&article2).await.unwrap();
        assert_eq!(new_count2, 2, "retry_count must be 2 after second increment");
    }
}
