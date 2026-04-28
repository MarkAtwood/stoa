//! Article signature verification for stoa.
//!
//! Verifies two signature types:
//! - `X-Stoa-Sig`: operator Ed25519 signature over article content.
//! - `DKIM-Signature`: standard DKIM signature, verified via DNS TXT lookup.
//!
//! Results are persisted to SQLite via `VerificationStore` and surfaced
//! through NNTP (`X-Stoa-Verified` header) and JMAP.

pub mod dkim;
pub mod store;
pub mod types;
pub mod x_sig;

pub use store::VerificationStore;
pub use types::{ArticleVerification, SigType, VerifResult};

/// Run all pending verify-crate migrations against the database at `url`.
///
/// Selects the SQLite or PostgreSQL dialect automatically based on the URL.
/// Call this once at startup before opening the `AnyPool` for `VerificationStore`.
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

/// Aggregate verification status across a slice of results.
///
/// Returns `Some(true)` if any result passed, `Some(false)` if all results
/// are non-pass, `None` if the slice is empty.
pub fn aggregate_status(verifications: &[ArticleVerification]) -> Option<bool> {
    if verifications.is_empty() {
        return None;
    }
    Some(verifications.iter().any(|v| v.result.is_pass()))
}
