/// Run all pending mail-crate migrations against the database at `url`.
///
/// Selects the SQLite or PostgreSQL dialect automatically based on the URL.
/// The migration files live in `crates/mail/migrations/` (SQLite) or
/// `crates/mail/migrations_pg/` (PostgreSQL). `sqlx::migrate!` embeds them
/// at compile time.
pub async fn run_migrations(url: &str) -> Result<(), sqlx::Error> {
    use std::str::FromStr as _;

    if stoa_core::db_pool::is_postgres_url(url) {
        let pool = sqlx::PgPool::connect(url).await?;
        let result = sqlx::migrate!("./migrations_pg").run(&pool).await;
        pool.close().await;
        result.map_err(Into::into)
    } else {
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)?.create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        let result = sqlx::migrate!("./migrations").run(&pool).await;
        pool.close().await;
        result.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_url() -> (String, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        (url, tmp)
    }

    #[tokio::test]
    async fn migrations_run_on_fresh_db() {
        let (url, _tmp) = make_url().await;
        run_migrations(&url).await.expect("migrations must succeed");
    }

    #[tokio::test]
    async fn migrations_idempotent() {
        let (url, _tmp) = make_url().await;
        run_migrations(&url).await.expect("first run");
        run_migrations(&url)
            .await
            .expect("second run must also succeed");
    }
}
