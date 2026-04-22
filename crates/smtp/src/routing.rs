use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
    headers.windows(12).any(|w| w.eq_ignore_ascii_case(b"\nNewsgroups:"))
        || headers.len() >= 11 && headers[..11].eq_ignore_ascii_case(b"Newsgroups:")
}

/// Return `true` if the message already contains a `Message-ID:` header.
///
/// Only the header section (up to the first blank line) is scanned.
/// The check is case-insensitive per RFC 2822 §2.2.
pub fn has_message_id_header(raw_message: &[u8]) -> bool {
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
    // Check at start of message or after a newline (covers both \r\n and \n line endings).
    // "\nMessage-ID:" is 12 bytes (\n + 10 name chars + colon).
    headers
        .windows(12)
        .any(|w| w.eq_ignore_ascii_case(b"\nMessage-ID:"))
        || headers.len() >= 11 && headers[..11].eq_ignore_ascii_case(b"Message-ID:")
}

/// Synthesize a unique `Message-ID` value suitable for use as a header.
///
/// Format: `<{timestamp_ms}.{pid_hex}{counter_hex}@{hostname}>`
///
/// Uniqueness is guaranteed within a process (monotonic counter) and across
/// process restarts on the same host (millisecond-resolution timestamp).  The
/// PID disambiguates concurrent processes sharing the same hostname.
///
/// No entropy source is required; Message-IDs are not security identifiers.
pub fn synthesize_message_id(hostname: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let pid = std::process::id();
    format!("<{timestamp_ms}.{pid:x}{seq:016x}@{hostname}>")
}

/// Synthesize a `Newsgroups:` header into raw article bytes.
///
/// Prepends `"Newsgroups: <newsgroup>\r\n"` at the front of the message.
/// Callers must ensure the message does not already have a `Newsgroups:`
/// header; use [`has_newsgroups_header`] to check first.
pub fn add_newsgroups_header(raw_message: &[u8], newsgroup: &str) -> Vec<u8> {
    let header = format!("Newsgroups: {newsgroup}\r\n");
    let mut result = Vec::with_capacity(header.len() + raw_message.len());
    result.extend_from_slice(header.as_bytes());
    result.extend_from_slice(raw_message);
    result
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
        let result = add_newsgroups_header(msg, "comp.lang.rust");
        assert!(result.starts_with(b"Newsgroups: comp.lang.rust\r\n"));
        assert!(result.ends_with(b"From: a@b.com\r\n\r\nbody\r\n"));
    }

    #[test]
    fn add_newsgroups_header_correct_length() {
        let msg = b"Subject: test\r\n\r\nbody";
        let header = b"Newsgroups: misc.test\r\n";
        let result = add_newsgroups_header(msg, "misc.test");
        assert_eq!(result.len(), header.len() + msg.len());
    }

    // --- has_message_id_header ---

    #[test]
    fn has_message_id_header_present_at_start() {
        let msg = b"Message-ID: <foo@bar.com>\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert!(has_message_id_header(msg));
    }

    #[test]
    fn has_message_id_header_present_mid_headers() {
        let msg = b"From: a@b.com\r\nMessage-ID: <foo@bar.com>\r\nSubject: hi\r\n\r\nbody\r\n";
        assert!(has_message_id_header(msg));
    }

    #[test]
    fn has_message_id_header_absent() {
        let msg = b"From: a@b.com\r\nSubject: hi\r\n\r\nbody\r\n";
        assert!(!has_message_id_header(msg));
    }

    #[test]
    fn has_message_id_header_case_insensitive() {
        let msg = b"from: a@b.com\r\nmessage-id: <foo@bar.com>\r\n\r\nbody\r\n";
        assert!(has_message_id_header(msg));
    }

    #[test]
    fn has_message_id_header_in_body_not_counted() {
        // "Message-ID:" appearing only in the body must not count.
        let msg = b"From: a@b.com\r\n\r\nMessage-ID: <foo@bar.com>\r\n";
        assert!(!has_message_id_header(msg));
    }

    // --- synthesize_message_id ---

    #[test]
    fn synthesize_message_id_format() {
        let mid = synthesize_message_id("test.example.com");
        assert!(mid.starts_with('<'), "must start with '<': {mid}");
        assert!(mid.ends_with('>'), "must end with '>': {mid}");
        assert!(
            mid.contains("@test.example.com>"),
            "must contain @hostname>: {mid}"
        );
    }

    #[test]
    fn synthesize_message_id_unique() {
        let a = synthesize_message_id("test.example.com");
        let b = synthesize_message_id("test.example.com");
        assert_ne!(a, b, "successive calls must produce different IDs");
    }
}
