use sqlx::SqlitePool;

/// Run all pending SQLite migrations against `pool`.
///
/// The migration files live in `crates/reader/migrations/` relative to the
/// crate root. `sqlx::migrate!` embeds them at compile time.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
