//! Shared `secretx:` URI resolution used by all stoa daemons.
//!
//! Both `stoa-transit` and `stoa-reader` call [`resolve_secret_uri`] at
//! startup to fetch credentials (bearer tokens, TLS keys, etc.) from the
//! configured secret backend.

/// Errors returned by [`resolve_secret_uri`].
#[derive(Debug)]
pub enum SecretError {
    InvalidUri(String),
    Retrieval(String),
    Encoding(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUri(s) | Self::Retrieval(s) | Self::Encoding(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for SecretError {}

/// Resolve a `secretx:` URI to its plaintext value.
///
/// - `None` → `Ok(None)` (field was not set in config).
/// - A plain string (no `secretx:` prefix) → returned as-is.
/// - A `secretx:`-prefixed URI → the secret is fetched from the backend.
///
/// Returns `Err(SecretError)` on failure; the error message is pre-formatted
/// with `label` and is suitable for printing to stderr before exiting.
pub async fn resolve_secret_uri(
    value: Option<String>,
    label: &str,
) -> Result<Option<String>, SecretError> {
    let s = match value {
        None => return Ok(None),
        Some(s) => s,
    };
    if !s.starts_with("secretx:") {
        return Ok(Some(s));
    }
    let store = secretx::from_uri(&s).map_err(|e| {
        SecretError::InvalidUri(format!("error: {label}: invalid secretx URI: {e}"))
    })?;
    let secret = store.get().await.map_err(|e| {
        SecretError::Retrieval(format!("error: {label}: secretx retrieval failed: {e}"))
    })?;
    let text = secret.as_str().map_err(|e| {
        SecretError::Encoding(format!(
            "error: {label}: secretx value not valid UTF-8: {e}"
        ))
    })?;
    Ok(Some(text.trim().to_string()))
}
