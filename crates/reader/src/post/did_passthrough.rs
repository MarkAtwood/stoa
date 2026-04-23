/// The name of the DID signature passthrough header.
pub const DID_SIG_HEADER: &str = "X-Usenet-IPFS-DID-Sig";

/// Return the header section of a raw article (bytes before the blank line).
///
/// Uses [`crate::post::find_header_boundary`] to locate the separator.
/// Returns the full slice if no blank line is found (malformed article).
pub(crate) fn header_section(article_bytes: &[u8]) -> &[u8] {
    match crate::post::find_header_boundary(article_bytes) {
        // find_header_boundary returns the first body byte (after separator).
        // The separator is \r\n\r\n (4 bytes) or \n\n (2 bytes).  We want the
        // slice up to but not including the blank line itself.  Walk back past
        // the trailing \r\n (or \n) of the last real header.
        Some(body_start) => {
            // Determine separator length by inspecting the bytes at the
            // separator position.  If the article uses \r\n\r\n the separator
            // is 4 bytes; for bare \n\n it is 2 bytes.
            let sep_len =
                if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                    4usize
                } else {
                    2usize
                };
            // Return headers including the final \r\n (or \n) of the last
            // header line (i.e. exclude only the blank line).
            &article_bytes[..body_start - sep_len + if sep_len == 4 { 2 } else { 1 }]
        }
        None => article_bytes,
    }
}

/// Extract the value of the `X-Usenet-IPFS-DID-Sig` header from raw article
/// bytes, if present.  Returns `None` if the header is absent.
///
/// Only the **header section** (before the blank line) is searched; body
/// lines are never considered, preventing body-injection attacks.
///
/// RFC 5322 §2.2.3 header folding is handled: continuation lines starting
/// with SP or HTAB are joined to the preceding logical line.
///
/// Header name matching is case-insensitive per RFC 5322 §2.2.
pub fn extract_did_sig(article_bytes: &[u8]) -> Option<String> {
    let prefix = format!("{}:", DID_SIG_HEADER.to_ascii_lowercase());

    // Only search the header section.
    let header_bytes = header_section(article_bytes);
    let text = String::from_utf8_lossy(header_bytes);

    // Collect logical header lines by unfolding RFC 5322 continuations.
    let mut logical_lines: Vec<String> = Vec::new();
    for physical_line in text.split('\n') {
        let line = physical_line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation: append to the previous logical line.
            if let Some(last) = logical_lines.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        } else {
            logical_lines.push(line.to_owned());
        }
    }

    for logical in &logical_lines {
        if logical.to_ascii_lowercase().starts_with(&prefix) {
            let value = &logical[prefix.len()..];
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// Return `true` if `article_bytes` contain an `X-Usenet-IPFS-DID-Sig` header.
///
/// Only the header section is searched; body injection is not possible.
pub fn has_did_sig(article_bytes: &[u8]) -> bool {
    extract_did_sig(article_bytes).is_some()
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

    #[test]
    fn folded_header_value_is_joined() {
        // RFC 5322 §2.2.3: a long header may be folded across multiple lines
        // by inserting a CRLF followed by at least one SP or HTAB.
        let headers =
            b"From: a@b\r\nX-Usenet-IPFS-DID-Sig: did:key:z6Mk\r\n abc123\r\nSubject: hi\r\n";
        let result = extract_did_sig(headers);
        assert_eq!(result, Some("did:key:z6Mk abc123".to_owned()));
    }

    #[test]
    fn body_injection_is_ignored() {
        // An attacker plants the header in the body; it must not be extracted.
        let article =
            b"From: a@b\r\nSubject: test\r\n\r\nX-Usenet-IPFS-DID-Sig: did:key:z6Mk...\r\n";
        assert_eq!(extract_did_sig(article), None);
    }

    #[test]
    fn header_present_in_full_article_is_extracted() {
        // extract_did_sig accepts full article bytes and finds the header.
        let article = b"From: a@b\r\nX-Usenet-IPFS-DID-Sig: did:key:z6Mk...\r\n\r\nBody.\r\n";
        let result = extract_did_sig(article);
        assert_eq!(result, Some("did:key:z6Mk...".to_owned()));
    }
}
