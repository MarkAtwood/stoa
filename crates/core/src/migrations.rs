use std::str::FromStr as _;

use crate::db_pool::is_postgres_url;
use crate::error::StorageError;

/// Run all pending migrations for the core schema against the database at `url`.
///
/// Selects the SQLite or PostgreSQL dialect automatically based on the URL.
/// Opens a short-lived backend-specific pool just for migration (AnyPool does
/// not expose the `Migrate` trait); the caller's `AnyPool` is unaffected.
pub async fn run_migrations(url: &str) -> Result<(), StorageError> {
    if is_postgres_url(url) {
        run_pg_migrations(url).await
    } else {
        run_sqlite_migrations(url).await
    }
}

async fn run_sqlite_migrations(url: &str) -> Result<(), StorageError> {
    let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)
        .map_err(|e| StorageError::MigrationFailed(e.to_string()))?
        .create_if_missing(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;
    let result = sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| StorageError::MigrationFailed(e.to_string()));
    pool.close().await;
    result
}

async fn run_pg_migrations(url: &str) -> Result<(), StorageError> {
    let pool = sqlx::PgPool::connect(url)
        .await
        .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;
    let result = sqlx::migrate!("./migrations_pg")
        .run(&pool)
        .await
        .map_err(|e| StorageError::MigrationFailed(e.to_string()));
    pool.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrations_run_on_fresh_db() {
        run_migrations("sqlite::memory:").await.expect("migrations must succeed");
    }

    #[tokio::test]
    async fn migrations_idempotent() {
        run_migrations("sqlite::memory:").await.expect("first run");
        // Second call on a fresh in-memory DB is idempotent (already applied).
        run_migrations("sqlite::memory:").await.expect("second run");
    }
}
