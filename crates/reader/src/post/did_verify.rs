//! DID author signature verification for `X-Usenet-IPFS-DID-Sig` headers.

/// Error returned when DID signature verification cannot be completed.
#[derive(Debug)]
pub enum DidSigError {
    /// The header value was not in the expected `<did-url> <base64url-sig>` format.
    InvalidFormat(String),
    /// The DID method is not supported (only `did:key` is supported in v1).
    UnsupportedMethod(String),
    /// The key material could not be decoded (invalid multicodec, wrong length, etc.).
    InvalidKeyEncoding(String),
    /// The signature bytes could not be decoded from base64url.
    InvalidSignatureEncoding(String),
    /// The signature was syntactically valid but did not verify against the key and article.
    VerificationFailed,
}

impl std::fmt::Display for DidSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DidSigError::InvalidFormat(msg) => write!(f, "invalid DID sig header format: {msg}"),
            DidSigError::UnsupportedMethod(method) => {
                write!(f, "unsupported DID method: {method}")
            }
            DidSigError::InvalidKeyEncoding(msg) => write!(f, "invalid DID key encoding: {msg}"),
            DidSigError::InvalidSignatureEncoding(msg) => {
                write!(f, "invalid signature encoding: {msg}")
            }
            DidSigError::VerificationFailed => write!(f, "DID signature verification failed"),
        }
    }
}

impl std::error::Error for DidSigError {}

/// Multicodec prefix bytes for an Ed25519 verification key (varint 0xed01).
const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// Decode a `did:key` URI into an Ed25519 verifying key.
///
/// Only `did:key` with the Ed25519 multicodec (`0xed01`) is supported.
/// `did:web` and other methods return [`DidSigError::UnsupportedMethod`].
///
/// # Format
/// ```text
/// did:key:z<base58btc-encoded( 0xed 0x01 || 32-byte-pubkey )>
/// ```
/// The `z` prefix is the multibase indicator for base58btc.
pub fn parse_did_key(did_url: &str) -> Result<ed25519_dalek::VerifyingKey, DidSigError> {
    // 1. Must start with "did:key:"
    let multibase_id = did_url
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            let method = did_url.split(':').nth(1).unwrap_or("unknown");
            DidSigError::UnsupportedMethod(method.to_owned())
        })?;

    // 2. Multibase 'z' prefix = base58btc.
    let b58_str = multibase_id.strip_prefix('z').ok_or_else(|| {
        DidSigError::InvalidKeyEncoding("not base58btc multibase (expected 'z' prefix)".into())
    })?;

    // 3. Decode base58btc.
    let decoded = bs58::decode(b58_str)
        .into_vec()
        .map_err(|e| DidSigError::InvalidKeyEncoding(e.to_string()))?;

    // 4. Check multicodec prefix.
    if decoded.len() < 2 || decoded[..2] != MULTICODEC_ED25519_PUB {
        return Err(DidSigError::UnsupportedMethod(
            "not an Ed25519 did:key (multicodec prefix mismatch)".into(),
        ));
    }

    // 5. Extract 32-byte key material.
    let key_bytes = &decoded[2..];
    if key_bytes.len() != 32 {
        return Err(DidSigError::InvalidKeyEncoding(format!(
            "expected 32-byte Ed25519 key, got {} bytes",
            key_bytes.len()
        )));
    }
    let arr: [u8; 32] = key_bytes.try_into().unwrap(); // infallible: len checked above

    // 6. Validate the curve point via ed25519-dalek.
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| DidSigError::InvalidKeyEncoding(e.to_string()))
}

/// Verify the Ed25519 DID author signature over article bytes.
///
/// `article_bytes` is the full raw article (headers + blank line + body),
/// which may include the `X-Usenet-IPFS-DID-Sig` header line itself.
///
/// `header_value` is the value of the `X-Usenet-IPFS-DID-Sig` header:
/// `"<did-url> <base64url-no-pad-signature>"`.
///
/// The signature covers the article bytes **with the DID sig header line
/// stripped**, matching the bytes the author signed before adding the header.
///
/// Returns `Ok(true)` if the signature verifies, `Ok(false)` if verification
/// fails (wrong key, tampered content, etc.), or `Err` if the header value
/// cannot be parsed.
pub fn verify_did_sig(
    article_bytes: &[u8],
    header_value: &str,
) -> Result<bool, DidSigError> {
    // 1. Split header_value into (did_url, sig_b64).
    //    Split on the LAST space so did-urls with embedded spaces (unusual) still work.
    let last_space = header_value.rfind(' ').ok_or_else(|| {
        DidSigError::InvalidFormat("expected '<did-url> <base64url-sig>'".into())
    })?;
    let did_url = header_value[..last_space].trim();
    let sig_b64 = header_value[last_space + 1..].trim();

    if did_url.is_empty() || sig_b64.is_empty() {
        return Err(DidSigError::InvalidFormat(
            "did-url or signature is empty".into(),
        ));
    }

    // 2. Decode base64url-no-pad signature.
    use base64::Engine as _;
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| DidSigError::InvalidSignatureEncoding(e.to_string()))?;

    if sig_bytes.len() != 64 {
        return Err(DidSigError::InvalidSignatureEncoding(format!(
            "expected 64-byte Ed25519 signature, got {} bytes",
            sig_bytes.len()
        )));
    }
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap(); // infallible: len checked above
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // 3. Resolve the DID to a verifying key.
    let verifying_key = parse_did_key(did_url)?;

    // 4. Strip the X-Usenet-IPFS-DID-Sig header from article_bytes to get
    //    the bytes the author originally signed.
    let unsigned_bytes = strip_did_sig_header(article_bytes);

    // 5. Verify.
    match verifying_key.verify_strict(&unsigned_bytes, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test vectors generated by Python `cryptography` library ───────────────
    // Oracle: pyca/cryptography 41.0.7 (pip install cryptography==41.0.7)
    //
    // Generation script (seed = bytes(range(32)), i.e. 0x00..0x1f):
    //
    //   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    //   import base64
    //   seed = bytes(range(32))
    //   key = Ed25519PrivateKey.from_private_bytes(seed)
    //   pub_bytes = key.public_key().public_bytes_raw()
    //   # ... base58btc-encode [0xed, 0x01] + pub_bytes with 'z' multibase prefix
    //   article = b'From: alice@example.com\r\nSubject: DID test\r\n\r\nBody text.\r\n'
    //   sig = key.sign(article)
    //   sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    //
    // All values below are hardcoded from that single Python run.

    const TEST_DID_KEY: &str = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
    const TEST_PUB_HEX: &str =
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    const TEST_SIG_B64: &str =
        "P-hOa6ZB6pbFXp9kjpWXZSpADgh45PfFfviTPJbatZu3Dz5caID0Sp22jBbxiXfJn7AkmjTnUkiMpA6NnT2rBA";
    const WRONG_SIG_B64: &str =
        "P-hOa6ZB6pbFXp9kjpWXZSpADgh45PfFfviTPJbatZu3Dz5caID0Sp22jBbxiXfJn7AkmjTnUkiMpA6NnT2r-w";
    // Article bytes WITHOUT the DID-Sig header; this is what was signed.
    const ARTICLE_BYTES: &[u8] =
        b"From: alice@example.com\r\nSubject: DID test\r\n\r\nBody text.\r\n";

    // ── parse_did_key tests ───────────────────────────────────────────────────

    #[test]
    fn parse_did_key_valid_ed25519() {
        let result = parse_did_key(TEST_DID_KEY);
        assert!(result.is_ok(), "parse_did_key failed: {result:?}");
        let expected_pub = hex::decode(TEST_PUB_HEX).unwrap();
        assert_eq!(
            result.unwrap().as_bytes(),
            expected_pub.as_slice(),
            "public key bytes do not match Python reference"
        );
    }

    #[test]
    fn parse_did_key_unsupported_method_web() {
        let result = parse_did_key("did:web:example.com");
        assert!(
            matches!(result, Err(DidSigError::UnsupportedMethod(_))),
            "expected UnsupportedMethod for did:web, got: {result:?}"
        );
    }

    #[test]
    fn parse_did_key_unsupported_method_example() {
        let result = parse_did_key("did:example:123");
        assert!(
            matches!(result, Err(DidSigError::UnsupportedMethod(_))),
            "expected UnsupportedMethod for did:example, got: {result:?}"
        );
    }

    #[test]
    fn parse_did_key_wrong_multicodec() {
        // Encode [0x12, 0x00] + 32 zero bytes with base58btc and 'z' multibase
        // prefix to produce a syntactically valid did:key whose multicodec is
        // SHA-256 (0x1200) rather than Ed25519 (0xed01).
        let mut payload = vec![0x12u8, 0x00];
        payload.extend_from_slice(&[0u8; 32]);
        let b58 = bs58::encode(&payload).into_string();
        let did_url = format!("did:key:z{b58}");
        let result = parse_did_key(&did_url);
        assert!(
            matches!(result, Err(DidSigError::UnsupportedMethod(_))),
            "expected UnsupportedMethod for wrong multicodec, got: {result:?}"
        );
    }

    #[test]
    fn parse_did_key_truncated_key() {
        // Valid Ed25519 multicodec prefix but only 16 bytes of key material
        // instead of the required 32.
        let mut payload = vec![0xed, 0x01];
        payload.extend_from_slice(&[0xabu8; 16]);
        let b58 = bs58::encode(&payload).into_string();
        let did_url = format!("did:key:z{b58}");
        let result = parse_did_key(&did_url);
        assert!(
            matches!(result, Err(DidSigError::InvalidKeyEncoding(_))),
            "expected InvalidKeyEncoding for truncated key, got: {result:?}"
        );
    }

    // ── verify_did_sig tests ──────────────────────────────────────────────────

    #[test]
    fn verify_did_sig_valid() {
        let header_value = format!("{TEST_DID_KEY} {TEST_SIG_B64}");
        let result = verify_did_sig(ARTICLE_BYTES, &header_value);
        assert_eq!(
            result.unwrap(),
            true,
            "expected valid signature to verify"
        );
    }

    #[test]
    fn verify_did_sig_wrong_sig() {
        let header_value = format!("{TEST_DID_KEY} {WRONG_SIG_B64}");
        let result = verify_did_sig(ARTICLE_BYTES, &header_value);
        assert_eq!(
            result.unwrap(),
            false,
            "expected wrong signature to return false"
        );
    }

    #[test]
    fn verify_did_sig_tampered_article() {
        let mut tampered = ARTICLE_BYTES.to_vec();
        tampered[5] ^= 0xff; // flip a byte in the From header
        let header_value = format!("{TEST_DID_KEY} {TEST_SIG_B64}");
        let result = verify_did_sig(&tampered, &header_value);
        assert_eq!(
            result.unwrap(),
            false,
            "expected tampered article to fail verification"
        );
    }

    #[test]
    fn verify_did_sig_format_error_no_space() {
        let result = verify_did_sig(ARTICLE_BYTES, "did:key:z6Mk...");
        assert!(
            matches!(result, Err(DidSigError::InvalidFormat(_))),
            "expected InvalidFormat when header has no space, got: {result:?}"
        );
    }

    #[test]
    fn verify_did_sig_strips_header_before_verifying() {
        // Build an article that includes the DID-Sig header.  The signature
        // was computed over ARTICLE_BYTES (without the header), so
        // verify_did_sig must strip the header before verifying.
        //
        // ARTICLE_BYTES = "From: ...\r\nSubject: ...\r\n\r\nBody text.\r\n"
        // Insert the DID-Sig header line immediately before the blank line.
        let header_line =
            format!("X-Usenet-IPFS-DID-Sig: {TEST_DID_KEY} {TEST_SIG_B64}\r\n");
        // Find the position of the blank line (\r\n\r\n); insert after the
        // second \r\n (i.e. right at the start of \r\n that forms the blank line).
        let insert_pos = ARTICLE_BYTES
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("ARTICLE_BYTES must contain a blank line")
            + 2; // after the last real header's \r\n
        let mut article_with_header = ARTICLE_BYTES[..insert_pos].to_vec();
        article_with_header.extend_from_slice(header_line.as_bytes());
        article_with_header.extend_from_slice(&ARTICLE_BYTES[insert_pos..]);

        let header_value = format!("{TEST_DID_KEY} {TEST_SIG_B64}");
        let result = verify_did_sig(&article_with_header, &header_value);
        assert_eq!(
            result.unwrap(),
            true,
            "should strip DID-Sig header and verify against original article bytes"
        );
    }
}

/// Strip the `X-Usenet-IPFS-DID-Sig` header (including any RFC 5322 folded
/// continuation lines) from raw article bytes.
///
/// Handles both `\r\n` and bare `\n` line endings.  All other headers and
/// the body are returned unchanged.
fn strip_did_sig_header(article_bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(article_bytes);
    let prefix = format!(
        "{}:",
        crate::post::did_passthrough::DID_SIG_HEADER.to_ascii_lowercase()
    );

    // Split on bare \n; preserve \r\n by keeping the \r at end of each chunk.
    let mut out_lines: Vec<&str> = Vec::new();
    let mut skip_continuations = false;

    for line in text.split('\n') {
        let stripped = line.trim_end_matches('\r');
        if stripped.starts_with(' ') || stripped.starts_with('\t') {
            // Continuation line: skip if we are inside the DID-Sig header.
            if skip_continuations {
                continue;
            }
            skip_continuations = false;
        } else {
            // Non-continuation: check whether this is the DID-Sig header.
            skip_continuations = stripped.to_ascii_lowercase().starts_with(&prefix);
            if skip_continuations {
                continue;
            }
        }
        out_lines.push(line);
    }
    out_lines.join("\n").into_bytes()
}
