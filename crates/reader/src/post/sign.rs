//! Operator Ed25519 signing for POST articles.
//!
//! Articles are signed over their raw bytes (headers + blank line + body)
//! before the signature header is inserted. The signature is appended as
//! `X-Stoa-Sig: <base64url-no-pad>` immediately before the blank line
//! separating headers from body.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use stoa_core::signing::{self, Signature, SigningKey, VerifyingKey};

pub use stoa_core::signing::load_signing_key;

use crate::post::find_header_boundary;

/// The header name for the operator signature.
pub const OPERATOR_SIG_HEADER: &str = "X-Stoa-Sig";

/// Sign article bytes and return `(signed_article, sig_bytes)`.
///
/// `signed_article` is the article with `X-Stoa-Sig` inserted immediately
/// before the header/body separator. `sig_bytes` is the raw 64-byte Ed25519
/// signature over `article_bytes`, used for the `X-Stoa-Sig` header value.
///
/// The signature is computed over the full `article_bytes` as supplied (before
/// the signature header exists). `article_bytes` must contain a header/body
/// separator (`\r\n\r\n` or `\n\n`); if none is found the bytes are returned
/// unchanged and sig_bytes is still the valid signature over the input.
///
/// Ed25519 via ed25519-dalek uses RFC 8032 deterministic signing: same key +
/// same bytes → same signature → same CID in IPFS.  Do NOT add a nonce or
/// timestamp to the signature; that would break CID idempotency and cause
/// duplicate articles in IPFS.
pub fn sign_article(key: &SigningKey, article_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sig: Signature = signing::sign(key, article_bytes);
    let sig_bytes = sig.to_bytes().to_vec();
    let sig_value = URL_SAFE_NO_PAD.encode(&sig_bytes);
    let sig_line = format!("{OPERATOR_SIG_HEADER}: {sig_value}\r\n");

    // Locate the end-of-headers boundary and insert the sig header immediately
    // before the blank line.  `find_header_boundary` returns the first body byte;
    // the blank line starts 2 bytes earlier for \r\n\r\n and 1 byte earlier for \n\n.
    let out = if let Some(body_start) = find_header_boundary(article_bytes) {
        let sep_len: usize =
            if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                2 // blank line = second \r\n; insert before it
            } else {
                1 // blank line = second \n; insert before it
            };
        let insert_at = body_start - sep_len;
        let mut out = Vec::with_capacity(article_bytes.len() + sig_line.len());
        out.extend_from_slice(&article_bytes[..insert_at]);
        out.extend_from_slice(sig_line.as_bytes());
        out.extend_from_slice(&article_bytes[insert_at..]);
        out
    } else {
        article_bytes.to_vec()
    };
    (out, sig_bytes)
}

/// Verify that the `X-Stoa-Sig` header in `article_bytes` is valid.
///
/// Returns `Ok(())` if the signature is present and valid.
/// Returns `Err` with a description if the header is missing, malformed, or
/// the signature does not verify.
pub fn verify_article_sig(pubkey: &VerifyingKey, article_bytes: &[u8]) -> Result<(), String> {
    // Find and extract the sig header line.
    let (sig_bytes, article_without_sig) = extract_sig_header(article_bytes)?;

    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("{OPERATOR_SIG_HEADER} contains an invalid signature: {e}"))?;

    signing::verify(pubkey, &article_without_sig, &sig)
        .map_err(|_| "signature verification failed".to_string())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Find the `X-Stoa-Sig` header in `article_bytes`, decode its value,
/// and return `(signature_bytes, article_bytes_without_sig_header)`.
fn extract_sig_header(article_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Work line by line in the header section only.
    let body_start = find_header_boundary(article_bytes)
        .ok_or_else(|| "article has no header/body separator".to_string())?;

    // Include the blank line in the slice so split_inclusive('\n') naturally
    // stops iterating before body bytes while still covering all header lines.
    let header_section = &article_bytes[..body_start];

    // Split on \r\n or \n.
    let header_str = std::str::from_utf8(header_section)
        .map_err(|e| format!("article headers contain non-UTF-8 bytes: {e}"))?;

    let prefix = format!("{OPERATOR_SIG_HEADER}:");

    let mut sig_value: Option<&str> = None;
    let mut sig_line_start: Option<usize> = None;
    let mut sig_line_end: Option<usize> = None;

    let mut cursor = 0usize;
    for raw_line in header_str.split_inclusive('\n') {
        let line = raw_line.trim_end_matches(['\r', '\n']);
        if line.starts_with(&prefix) {
            let value = line[prefix.len()..].trim();
            sig_value = Some(value);
            sig_line_start = Some(cursor);
            sig_line_end = Some(cursor + raw_line.len());
            break;
        }
        cursor += raw_line.len();
    }

    let value = sig_value.ok_or_else(|| format!("{OPERATOR_SIG_HEADER} header not found"))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| format!("{OPERATOR_SIG_HEADER} value is not valid base64url: {e}"))?;

    // Reconstruct the article without the sig header line.
    let start = sig_line_start.unwrap();
    let end = sig_line_end.unwrap();
    let mut without = Vec::with_capacity(article_bytes.len() - (end - start));
    without.extend_from_slice(&article_bytes[..start]);
    without.extend_from_slice(&article_bytes[end..]);

    Ok((sig_bytes, without))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoa_core::signing::SigningKey;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn test_article() -> Vec<u8> {
        b"From: user@example.com\r\nSubject: Hello\r\nNewsgroups: comp.test\r\n\r\nBody text.\r\n"
            .to_vec()
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = test_key();
        let pubkey = key.verifying_key();
        let article = test_article();

        let (signed, _) = sign_article(&key, &article);
        assert!(
            verify_article_sig(&pubkey, &signed).is_ok(),
            "verification with the correct key must succeed"
        );
    }

    #[test]
    fn sign_appends_header() {
        let key = test_key();
        let article = test_article();

        let (signed, _) = sign_article(&key, &article);
        let signed_str = std::str::from_utf8(&signed).expect("signed article must be UTF-8");

        assert!(
            signed_str.contains(&format!("{OPERATOR_SIG_HEADER}:")),
            "signed article must contain the signature header"
        );
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let key_a = test_key();
        let key_b = SigningKey::from_bytes(&[0x13u8; 32]);
        let article = test_article();

        let (signed, _) = sign_article(&key_a, &article);
        let result = verify_article_sig(&key_b.verifying_key(), &signed);

        assert!(
            result.is_err(),
            "verification with a different key must fail"
        );
    }

    #[test]
    fn verify_with_tampered_body_fails() {
        let key = test_key();
        let pubkey = key.verifying_key();
        let article = test_article();

        let (mut signed, _) = sign_article(&key, &article);

        // Flip the last byte of the body.
        let last = signed.len() - 1;
        signed[last] ^= 0xff;

        let result = verify_article_sig(&pubkey, &signed);
        assert!(result.is_err(), "verification over tampered body must fail");
    }
}
