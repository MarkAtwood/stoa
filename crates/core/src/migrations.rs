use sqlx::SqlitePool;

use crate::error::StorageError;

/// Run all pending SQLite migrations against `pool`.
///
/// The migration files live in `crates/core/migrations/` relative to the
/// crate root. `sqlx::migrate!` embeds them at compile time.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), StorageError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| StorageError::MigrationFailed(e.to_string()))
}
