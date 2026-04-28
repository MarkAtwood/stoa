//! Database pool helpers for multi-backend support (SQLite + PostgreSQL).
//!
//! All metadata stores (msgid_map, group_log, peers, articles, overview, mail)
//! use [`sqlx::AnyPool`] so that operators can point stoa at either a local
//! SQLite file or a managed PostgreSQL / Aurora instance.
//!
//! SQLite-specific IPFS block stores (`sqlite_store`) are **not** affected;
//! they continue to use [`sqlx::SqlitePool`] directly.
//!
//! ## Database URL format
//!
//! - SQLite: `sqlite:///absolute/path/to/file.db` or `sqlite::memory:`
//! - PostgreSQL: `postgres://user:pass@host/dbname` or `postgresql://...`

use sqlx::any::AnyPoolOptions;

/// Returns `true` if `url` is a PostgreSQL URL.
pub fn is_postgres_url(url: &str) -> bool {
    url.starts_with("postgres://") || url.starts_with("postgresql://")
}

/// Open an [`sqlx::AnyPool`] from a database URL.
///
/// - `sqlite://` URLs: creates the file if absent (`mode=rwc`), enables WAL mode.
/// - `postgres://` / `postgresql://` URLs: connects directly.
///
/// Panics and calls `process::exit(1)` on connection failure.
/// Suitable for use in binary `main`; prefer [`try_open_any_pool`] in tests.
pub async fn open_any_pool(url: &str, pool_size: u32) -> sqlx::AnyPool {
    match try_open_any_pool(url, pool_size).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to open database '{url}': {e}");
            std::process::exit(1);
        }
    }
}

/// Open an [`sqlx::AnyPool`] from a database URL, returning an error on failure.
pub async fn try_open_any_pool(url: &str, pool_size: u32) -> Result<sqlx::AnyPool, String> {
    sqlx::any::install_default_drivers();

    if is_postgres_url(url) {
        AnyPoolOptions::new()
            .max_connections(pool_size)
            .connect(url)
            .await
            .map_err(|e| e.to_string())
    } else {
        // SQLite path.
        // Append ?mode=rwc to the URL so SQLite creates the file if absent
        // (the default `mode=rw` refuses to create a new file).
        // Skip for in-memory databases which never need file creation.
        let effective_url = if !url.contains(":memory:") && !url.contains("mode=") {
            if url.contains('?') {
                format!("{url}&mode=rwc")
            } else {
                format!("{url}?mode=rwc")
            }
        } else {
            url.to_string()
        };

        let pool: sqlx::AnyPool = AnyPoolOptions::new()
            .max_connections(pool_size)
            .connect(&effective_url)
            .await
            .map_err(|e| e.to_string())?;

        // Enable WAL journal mode for better concurrent read performance.
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await
            .map_err(|e| e.to_string())?;

        Ok(pool)
    }
}
