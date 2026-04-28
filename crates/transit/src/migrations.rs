//! Migration runner for stoa-transit.
//!
//! Detects sqlite vs postgres from the URL and runs the appropriate migration set.

/// Run all pending migrations for the transit database.
///
/// Accepts a database URL (e.g. `sqlite:///transit.db` or
/// `postgres://user:pass@host/db`).  Opens a short-lived backend-specific
/// pool, runs migrations, then closes it.
pub async fn run_migrations(url: &str) -> Result<(), sqlx::migrate::MigrateError> {
    if stoa_core::db_pool::is_postgres_url(url) {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .map_err(|e| sqlx::migrate::MigrateError::Execute(e))?;
        let result = sqlx::migrate!("./migrations_pg").run(&pool).await;
        pool.close().await;
        result
    } else {
        let opts = match <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str(url) {
            Ok(o) => o.create_if_missing(true),
            Err(e) => {
                return Err(sqlx::migrate::MigrateError::Execute(
                    sqlx::Error::Configuration(e.to_string().into()),
                ));
            }
        };
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .map_err(|e| sqlx::migrate::MigrateError::Execute(e))?;
        let result = sqlx::migrate!("./migrations").run(&pool).await;
        pool.close().await;
        result
    }
}
