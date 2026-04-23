/// Compute byte_count for OVER/XOVER output from verbatim body bytes.
///
/// Per RFC 3977 §8.5.2, the `:bytes` field counts the total number of
/// octets in the article (header + body). For our purposes we compute
/// this from body_bytes.len() (the header byte count is accounted for
/// by the caller).
pub fn compute_byte_count(body_bytes: &[u8]) -> u64 {
    body_bytes.len() as u64
}

/// Compute line_count for OVER/XOVER output from verbatim body bytes.
///
/// Per RFC 3977 §8.5.2, the `:lines` field counts the number of lines
/// in the article body. A line ends with \n (LF). Matches what NNTP
/// servers report in OVER/XOVER output.
pub fn compute_line_count(body_bytes: &[u8]) -> u64 {
    body_bytes.iter().filter(|&&b| b == b'\n').count() as u64
}

/// Extract content_type_summary from raw article header bytes.
///
/// Returns the type/subtype portion of the Content-Type header value
/// without parameters (e.g. "text/plain" from "text/plain; charset=utf-8").
/// Returns "text/plain" if no Content-Type header is present (RFC 2045
/// §5.2: default content type is text/plain; charset=us-ascii).
/// Returns the value as-is (lowercased) if it cannot be parsed further.
pub fn extract_content_type_summary(header_bytes: &[u8]) -> String {
    // Convert to str lossy so we can work with lines. Header bytes are
    // expected to be ASCII/UTF-8; invalid bytes are replaced with U+FFFD
    // and will not match any Content-Type header name.
    let header_str = String::from_utf8_lossy(header_bytes);

    // Collect header lines, handling CRLF and bare LF.
    let raw_lines: Vec<&str> = header_str.split('\n').collect();

    // Unfold the Content-Type header: find the line starting with
    // "content-type:" (case-insensitive), then collect any continuation
    // lines (lines starting with whitespace).
    let mut ct_value: Option<String> = None;
    let mut in_ct = false;

    for line in &raw_lines {
        // Strip trailing CR if present (CRLF line endings).
        let line = line.trim_end_matches('\r');

        if in_ct {
            // A continuation line begins with whitespace.
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some(ref mut v) = ct_value {
                    v.push(' ');
                    v.push_str(line.trim());
                }
                continue;
            } else {
                // Next header field; stop collecting.
                break;
            }
        }

        // Check if this line starts the Content-Type field.
        if line.len() >= 13 && line[..13].eq_ignore_ascii_case("content-type:") {
            let value = line[13..].trim().to_string();
            ct_value = Some(value);
            in_ct = true;
        }
    }

    match ct_value {
        None => "text/plain".to_string(),
        Some(value) => {
            // Take the part before the first ';' (strips parameters).
            let type_subtype = value.split(';').next().unwrap_or("").trim();
            if type_subtype.is_empty() {
                "text/plain".to_string()
            } else {
                type_subtype.to_lowercase()
            }
        }
    }
}

/// Compute the fields of ArticleMetadata that are derived from article bytes.
///
/// The caller must provide:
/// - `header_bytes`: verbatim RFC 5536 wire headers
/// - `body_bytes`: verbatim NNTP body bytes (after dot-unstuffing)
/// - `message_id`: the Message-ID header value (already parsed)
/// - `newsgroups`: the Newsgroups list (already parsed, sorted)
/// - `hlc_timestamp`: the HLC timestamp for this entry (caller-provided)
///
/// Returns a partially-filled ArticleMetadata; `operator_signature` is
/// set to empty bytes because the signing pipeline is not yet wired up.
/// Callers that need a signed article must populate the field after this
/// function returns.
pub fn compute_metadata(
    header_bytes: &[u8],
    body_bytes: &[u8],
    message_id: String,
    newsgroups: Vec<String>,
    hlc_timestamp: u64,
) -> crate::ipld::root_node::ArticleMetadata {
    crate::ipld::root_node::ArticleMetadata {
        message_id,
        newsgroups,
        hlc_timestamp,
        operator_signature: Vec::new(),
        byte_count: header_bytes.len() as u64 + compute_byte_count(body_bytes),
        line_count: compute_line_count(body_bytes),
        content_type_summary: extract_content_type_summary(header_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_count_empty_body() {
        assert_eq!(compute_byte_count(b""), 0);
    }

    #[test]
    fn byte_count_known_bytes() {
        assert_eq!(compute_byte_count(b"Hello\r\n"), 7);
    }

    #[test]
    fn line_count_empty_body() {
        assert_eq!(compute_line_count(b""), 0);
    }

    #[test]
    fn line_count_single_line() {
        assert_eq!(compute_line_count(b"Hello\r\n"), 1);
    }

    #[test]
    fn line_count_multi_line() {
        assert_eq!(compute_line_count(b"line1\r\nline2\r\nline3\r\n"), 3);
    }

    #[test]
    fn line_count_no_trailing_newline() {
        assert_eq!(compute_line_count(b"noeol"), 0);
    }

    #[test]
    fn content_type_plain_text() {
        let headers = b"From: user@example.com\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "text/plain");
    }

    #[test]
    fn content_type_with_params() {
        let headers = b"From: user@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "text/plain");
    }

    #[test]
    fn content_type_multipart() {
        let headers =
            b"From: user@example.com\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "multipart/mixed");
    }

    #[test]
    fn content_type_missing_returns_default() {
        let headers = b"From: user@example.com\r\nSubject: no content-type here\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "text/plain");
    }

    #[test]
    fn content_type_case_insensitive() {
        let headers = b"From: user@example.com\r\ncontent-type: TEXT/HTML\r\n\r\n";
        assert_eq!(extract_content_type_summary(headers), "text/html");
    }

    #[test]
    fn compute_metadata_fields() {
        // header_bytes is 47 bytes, body_bytes is 21 bytes → byte_count = 68
        // body has 3 LF characters → line_count = 3
        // Content-Type header is "text/plain; charset=utf-8" → summary "text/plain"
        let header_bytes = b"Content-Type: text/plain; charset=utf-8\r\n\r\n";
        let body_bytes = b"line1\r\nline2\r\nline3\r\n";

        assert_eq!(header_bytes.len(), 43);
        assert_eq!(body_bytes.len(), 21);

        let metadata = compute_metadata(
            header_bytes,
            body_bytes,
            "<test-001@example.com>".to_string(),
            vec!["comp.lang.rust".to_string(), "comp.test".to_string()],
            1_700_000_000_000,
        );

        assert_eq!(metadata.byte_count, 64); // 43 + 21
        assert_eq!(metadata.line_count, 3);
        assert_eq!(metadata.content_type_summary, "text/plain");
        assert_eq!(metadata.message_id, "<test-001@example.com>");
        assert_eq!(
            metadata.newsgroups,
            vec!["comp.lang.rust".to_string(), "comp.test".to_string()]
        );
        assert_eq!(metadata.hlc_timestamp, 1_700_000_000_000);
        assert!(metadata.operator_signature.is_empty());
    }
}
