//! Shared `secretx:` URI resolution used by all stoa daemons.
//!
//! Both `stoa-transit` and `stoa-reader` call [`resolve_secret_uri`] at
//! startup to fetch credentials (bearer tokens, TLS keys, etc.) from the
//! configured secret backend.

/// Resolve a `secretx:` URI to its plaintext value.
///
/// - `None` → `Ok(None)` (field was not set in config).
/// - A plain string (no `secretx:` prefix) → returned as-is.
/// - A `secretx:`-prefixed URI → the secret is fetched from the backend.
///
/// Returns `Err(String)` on failure; the error string is pre-formatted with
/// `label` and is suitable for printing to stderr before exiting.  Library
/// callers should propagate or display it; binary callers should exit after
/// printing.
pub async fn resolve_secret_uri(
    value: Option<String>,
    label: &str,
) -> Result<Option<String>, String> {
    let s = match value {
        None => return Ok(None),
        Some(s) => s,
    };
    if !s.starts_with("secretx:") {
        return Ok(Some(s));
    }
    let store =
        secretx::from_uri(&s).map_err(|e| format!("error: {label}: invalid secretx URI: {e}"))?;
    let secret = store
        .get()
        .await
        .map_err(|e| format!("error: {label}: secretx retrieval failed: {e}"))?;
    let text = secret
        .as_str()
        .map_err(|e| format!("error: {label}: secretx value not valid UTF-8: {e}"))?;
    Ok(Some(text.trim().to_string()))
}
