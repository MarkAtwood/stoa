/// The name of the DID signature passthrough header.
pub const DID_SIG_HEADER: &str = "X-Usenet-IPFS-DID-Sig";

/// Extract the value of the `X-Usenet-IPFS-DID-Sig` header from raw article
/// bytes, if present.  Returns `None` if the header is absent.
///
/// `header_bytes` are the raw headers section (before the blank line).
/// Header name matching is case-insensitive per RFC 5322 §2.2.
pub fn extract_did_sig(header_bytes: &[u8]) -> Option<String> {
    let prefix = format!("{}:", DID_SIG_HEADER.to_ascii_lowercase());

    // Split on CRLF first; fall back to bare LF for lenient clients.
    let text = String::from_utf8_lossy(header_bytes);
    for line in text.split('\n') {
        // Strip any trailing CR so both \r\n and \n work uniformly.
        let line = line.trim_end_matches('\r');
        if line.to_ascii_lowercase().starts_with(&prefix) {
            let value = &line[prefix.len()..];
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// Return `true` if `header_bytes` contain an `X-Usenet-IPFS-DID-Sig` header.
pub fn has_did_sig(header_bytes: &[u8]) -> bool {
    extract_did_sig(header_bytes).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_present_returns_value() {
        let headers =
            b"From: user@example.com\r\nX-Usenet-IPFS-DID-Sig: did:key:z6Mk...\r\nSubject: hi\r\n";
        let result = extract_did_sig(headers);
        assert_eq!(result, Some("did:key:z6Mk...".to_owned()));
    }

    #[test]
    fn header_absent_returns_none() {
        let headers = b"From: user@example.com\r\nSubject: hi\r\n";
        assert_eq!(extract_did_sig(headers), None);
    }

    #[test]
    fn has_did_sig_true() {
        let headers = b"X-Usenet-IPFS-DID-Sig: did:key:z6Mk...\r\nFrom: a@b\r\n";
        assert!(has_did_sig(headers));
    }

    #[test]
    fn has_did_sig_false() {
        let headers = b"From: a@b\r\nSubject: test\r\n";
        assert!(!has_did_sig(headers));
    }

    #[test]
    fn case_insensitive_header_name() {
        let headers = b"x-usenet-ipfs-did-sig: did:key:z6Mk...\r\nFrom: a@b\r\n";
        let result = extract_did_sig(headers);
        assert_eq!(result, Some("did:key:z6Mk...".to_owned()));
    }
}
