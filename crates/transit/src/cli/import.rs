//! CLI handler for the `transit import` subcommand.

use usenet_ipfs_core::error::StorageError;

use crate::import::ihave_push::{IhaveImportConfig, run_ihave_import};

/// Run an IHAVE bulk import from `article_dir`, sending to `addr`.
///
/// Returns a one-line summary string on success.
pub async fn cmd_import(
    article_dir: &std::path::Path,
    addr: &str,
    parallel: usize,
) -> Result<String, StorageError> {
    let config = IhaveImportConfig {
        addr: addr.to_string(),
        parallel,
    };
    let summary = run_ihave_import(article_dir, config)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(format!("{summary}\n"))
}
