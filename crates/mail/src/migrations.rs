use sqlx::SqlitePool;

/// Run all pending SQLite migrations against `pool`.
///
/// The migration files live in `crates/mail/migrations/` relative to the
/// crate root. `sqlx::migrate!` embeds them at compile time.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

    async fn make_pool() -> sqlx::SqlitePool {
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:mail_test_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("pool")
    }

    #[tokio::test]
    async fn migrations_run_on_fresh_db() {
        let pool = make_pool().await;
        run_migrations(&pool)
            .await
            .expect("migrations must succeed");
    }

    #[tokio::test]
    async fn migrations_idempotent() {
        let pool = make_pool().await;
        run_migrations(&pool).await.expect("first run");
        run_migrations(&pool)
            .await
            .expect("second run must also succeed");
    }
}
