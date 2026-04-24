//! Article signature verification for usenet-ipfs.
//!
//! Verifies two signature types:
//! - `X-Usenet-IPFS-Sig`: operator Ed25519 signature over article content.
//! - `DKIM-Signature`: standard DKIM signature, verified via DNS TXT lookup.
//!
//! Results are persisted to SQLite via `VerificationStore` and surfaced
//! through NNTP (`X-Usenet-IPFS-Verified` header) and JMAP.

pub mod dkim;
pub mod store;
pub mod types;
pub mod x_sig;

pub use store::VerificationStore;
pub use types::{ArticleVerification, SigType, VerifResult};

use sqlx::SqlitePool;

/// Run all pending verify-crate migrations against `pool`.
///
/// Call this once at startup on whichever pool will back the `VerificationStore`.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
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
