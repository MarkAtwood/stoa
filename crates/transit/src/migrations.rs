//! SQLite migration runner for usenet-ipfs-transit.

use sqlx::SqlitePool;

/// Run all pending migrations for the transit database.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
