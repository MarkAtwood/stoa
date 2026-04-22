use mail_parser::{HeaderName, MessageParser};

/// Parse the List-ID value from an RFC 2919 header value string.
///
/// Input is the full header value, e.g. `<rust-users.lists.rust-lang.org>`.
/// Returns the value between `<` and `>`, or `None` if not present or unparseable.
pub fn parse_list_id(header_value: &str) -> Option<String> {
    let trimmed = header_value.trim();
    let start = trimmed.find('<')?;
    let end = trimmed.rfind('>')?;
    if end <= start {
        return None;
    }
    let inner = trimmed[start + 1..end].trim();
    if inner.is_empty() {
        return None;
    }
    Some(inner.to_string())
}

/// Extract the List-ID header value from raw RFC 5322 message bytes.
///
/// Only the header section (bytes before the first blank line) is parsed,
/// avoiding a full body parse for what may be a multi-megabyte message.
pub fn extract_list_id(raw_message: &[u8]) -> Option<String> {
    // Locate the blank line that separates headers from body.
    let header_end = raw_message
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2) // include the trailing \r\n so the parser sees a complete header block
        .or_else(|| {
            raw_message
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|p| p + 1)
        })
        .unwrap_or(raw_message.len());

    let msg = MessageParser::default().parse(&raw_message[..header_end])?;
    let raw = msg.header_raw(HeaderName::ListId)?;
    parse_list_id(raw)
}

/// Return `true` if the message already contains a `Newsgroups:` header.
///
/// Only the header section (up to the first blank line) is scanned.
/// The check is case-insensitive per RFC 2822 §2.2.
pub fn has_newsgroups_header(raw_message: &[u8]) -> bool {
    let header_end = raw_message
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2)
        .or_else(|| {
            raw_message
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|p| p + 1)
        })
        .unwrap_or(raw_message.len());

    let headers = &raw_message[..header_end];
    // Header at start of message or after a newline (handles both \r\n and \n).
    headers
        .windows(12)
        .any(|w| w.eq_ignore_ascii_case(b"\nNewsgroups:"))
        || headers.len() >= 11 && headers[..11].eq_ignore_ascii_case(b"Newsgroups:")
}

/// Synthesize a `Newsgroups:` header into raw article bytes.
///
/// Prepends `"Newsgroups: <newsgroup>\r\n"` at the front of the message.
/// Callers must ensure the message does not already have a `Newsgroups:`
/// header; use [`has_newsgroups_header`] to check first.
///
/// Returns `None` if `newsgroup` contains characters outside the set of valid
/// RFC 3977 newsgroup name characters (ASCII alphanumeric, `.`, `-`, `+`,
/// `_`). This prevents CRLF injection and null-byte injection into the
/// synthesized header line.
pub fn add_newsgroups_header(raw_message: &[u8], newsgroup: &str) -> Option<Vec<u8>> {
    if newsgroup.is_empty()
        || !newsgroup
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
    {
        return None;
    }
    let header = format!("Newsgroups: {newsgroup}\r\n");
    let mut result = Vec::with_capacity(header.len() + raw_message.len());
    result.extend_from_slice(header.as_bytes());
    result.extend_from_slice(raw_message);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_list_id ---

    #[test]
    fn parse_list_id_standard() {
        assert_eq!(
            parse_list_id("<rust-users.lists.rust-lang.org>"),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    #[test]
    fn parse_list_id_with_display_name() {
        // RFC 2919 allows: "Display Name <list-id>"
        assert_eq!(
            parse_list_id("Rust Users <rust-users.lists.rust-lang.org>"),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    #[test]
    fn parse_list_id_with_whitespace() {
        assert_eq!(
            parse_list_id("  <rust-users.lists.rust-lang.org>  "),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    #[test]
    fn parse_list_id_no_angle_brackets() {
        assert_eq!(parse_list_id("rust-users.lists.rust-lang.org"), None);
    }

    #[test]
    fn parse_list_id_empty_angle_brackets() {
        assert_eq!(parse_list_id("<>"), None);
    }

    #[test]
    fn parse_list_id_reversed_brackets() {
        assert_eq!(parse_list_id(">rust-users.lists.rust-lang.org<"), None);
    }

    // --- has_newsgroups_header ---

    #[test]
    fn has_newsgroups_header_present() {
        let msg = b"Newsgroups: comp.test\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert!(has_newsgroups_header(msg));
    }

    #[test]
    fn has_newsgroups_header_mid_headers() {
        let msg = b"From: a@b.com\r\nNewsgroups: comp.test\r\nSubject: hi\r\n\r\nbody\r\n";
        assert!(has_newsgroups_header(msg));
    }

    #[test]
    fn has_newsgroups_header_absent() {
        let msg = b"From: a@b.com\r\nSubject: hi\r\n\r\nbody\r\n";
        assert!(!has_newsgroups_header(msg));
    }

    #[test]
    fn has_newsgroups_header_case_insensitive() {
        let msg = b"from: a@b.com\r\nnewsgroups: comp.test\r\n\r\nbody\r\n";
        assert!(has_newsgroups_header(msg));
    }

    #[test]
    fn has_newsgroups_header_in_body_not_counted() {
        // "Newsgroups:" appearing only in the body must not count.
        let msg = b"From: a@b.com\r\n\r\nNewsgroups: comp.test\r\n";
        assert!(!has_newsgroups_header(msg));
    }

    // --- extract_list_id ---

    #[test]
    fn extract_list_id_present() {
        let msg = b"From: sender@example.com\r\nList-Id: <rust-users.lists.rust-lang.org>\r\nSubject: test\r\n\r\nbody\r\n";
        assert_eq!(
            extract_list_id(msg),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    #[test]
    fn extract_list_id_absent() {
        let msg = b"From: sender@example.com\r\nSubject: no list here\r\n\r\nbody\r\n";
        assert_eq!(extract_list_id(msg), None);
    }

    #[test]
    fn extract_list_id_with_display_name() {
        let msg = b"From: sender@example.com\r\nList-Id: Rust Users <rust-users.lists.rust-lang.org>\r\nSubject: test\r\n\r\nbody\r\n";
        assert_eq!(
            extract_list_id(msg),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    // --- add_newsgroups_header ---

    #[test]
    fn add_newsgroups_header_prepends() {
        let msg = b"From: a@b.com\r\n\r\nbody\r\n";
        let result = add_newsgroups_header(msg, "comp.lang.rust").unwrap();
        assert!(result.starts_with(b"Newsgroups: comp.lang.rust\r\n"));
        assert!(result.ends_with(b"From: a@b.com\r\n\r\nbody\r\n"));
    }

    #[test]
    fn add_newsgroups_header_correct_length() {
        let msg = b"Subject: test\r\n\r\nbody";
        let header = b"Newsgroups: misc.test\r\n";
        let result = add_newsgroups_header(msg, "misc.test").unwrap();
        assert_eq!(result.len(), header.len() + msg.len());
    }

    #[test]
    fn add_newsgroups_header_rejects_crlf_injection() {
        assert!(add_newsgroups_header(b"body", "comp.test\r\nX-Evil: hdr").is_none());
        assert!(add_newsgroups_header(b"body", "comp.test\nX-Evil: hdr").is_none());
        assert!(add_newsgroups_header(b"body", "comp.test\0evil").is_none());
    }

    #[test]
    fn add_newsgroups_header_rejects_empty() {
        assert!(add_newsgroups_header(b"body", "").is_none());
    }
}
