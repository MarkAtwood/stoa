use chrono::{DateTime, TimeZone, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use stoa_core::InjectionSource;

/// Process-global counter for Message-ID uniqueness.  Starts at 1; incremented
/// by `fetch_add` on every call to `inject_message_id`.  Using a counter rather
/// than sub-second time avoids collisions when two POST requests arrive within
/// the same microsecond (which `subsec_micros()` cannot distinguish).
static MSG_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// The header name prepended by the SMTP queue drain.
const INJECTION_SOURCE_HEADER: &[u8] = b"X-Stoa-Injection-Source:";

/// Strip all server-synthesized `X-Stoa-*` headers that clients must never be
/// able to forge by including them in a POST.
///
/// These headers are injected dynamically at read time and must not be stored
/// in IPFS.  If a client includes them in a POST, they would be returned
/// verbatim before the server's injected value, allowing a client to forge
/// the integrity signal seen by readers.
///
/// Stripped headers:
/// - `X-Stoa-DID-Verified` — DID author signature result (dynamic, per-reader)
/// - `X-Stoa-Verified`     — operator X-Stoa-Sig result (dynamic, per-reader)
/// - `X-Stoa-CID`          — article root CID (derived from IPFS write)
///
/// All occurrences are stripped (not just the first) so a client cannot hide
/// one forged value behind another.
pub fn strip_server_synthesized_headers(article_bytes: &mut Vec<u8>) {
    strip_all_occurrences(article_bytes, b"x-stoa-did-verified:");
    strip_all_occurrences(article_bytes, b"x-stoa-verified:");
    strip_all_occurrences(article_bytes, b"x-stoa-cid:");
}

/// Remove every header line whose name (lowercase, with colon) matches
/// `header_name_lower`.  Single-pass copy excluding matched lines to avoid
/// O(k·n) from repeated drain + rescan.  Only the header section is scanned.
fn strip_all_occurrences(article_bytes: &mut Vec<u8>, header_name_lower: &[u8]) {
    let header_end = find_header_end(article_bytes);
    let mut out: Vec<u8> = Vec::with_capacity(article_bytes.len());
    let mut i = 0;
    while i < header_end {
        let line_end = find_line_end(article_bytes, i, header_end);
        let line = &article_bytes[i..line_end];
        let end = skip_line_terminator(article_bytes, line_end);
        if line.len() < header_name_lower.len()
            || !line[..header_name_lower.len()].eq_ignore_ascii_case(header_name_lower)
        {
            out.extend_from_slice(&article_bytes[i..end]);
        }
        i = end;
    }
    out.extend_from_slice(&article_bytes[header_end..]);
    *article_bytes = out;
}

/// Extract and remove the `X-Stoa-Injection-Source:` header from
/// `article_bytes`, returning the parsed `InjectionSource`.
///
/// The SMTP queue drain prepends this header before posting via NNTP so the
/// reader pipeline can distinguish peerable articles from local-only ones.
/// After extraction the header is removed from the bytes so it is not stored
/// in IPFS or forwarded to peers.
///
/// Returns `InjectionSource::NntpPost` (the default) if the header is absent
/// or its value cannot be parsed.
pub fn extract_injection_source(article_bytes: &mut Vec<u8>) -> InjectionSource {
    // Scan only the header section (up to the first blank line).
    // We look for the header at line boundaries within the first portion of
    // the buffer.  The SMTP drain always prepends it as the very first line,
    // but we search the whole header section for robustness.

    let header_end = find_header_end(article_bytes);

    let header_name_lower = b"x-stoa-injection-source:";
    let mut found_line_start: Option<usize> = None;
    let mut found_line_end: Option<usize> = None;
    let mut value: Option<InjectionSource> = None;

    let mut i = 0;
    while i < header_end {
        // Find the end of the current line (CRLF or LF).
        let line_end = find_line_end(article_bytes, i, header_end);
        let line = &article_bytes[i..line_end];

        // Case-insensitive prefix match for the header name.
        if line.len() >= header_name_lower.len()
            && line[..header_name_lower.len()].eq_ignore_ascii_case(header_name_lower)
        {
            let raw_val = &line[INJECTION_SOURCE_HEADER.len()..];
            let val_str = std::str::from_utf8(raw_val)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            value = Some(match val_str.as_str() {
                "nntppost" => InjectionSource::NntpPost,
                "smtpnewsgroups" => InjectionSource::SmtpNewsgroups,
                "smtpsieve" => InjectionSource::SmtpSieve,
                "smtplistid" => InjectionSource::SmtpListId,
                _ => InjectionSource::NntpPost,
            });
            found_line_start = Some(i);
            // Include the line terminator in the range to remove.
            found_line_end = Some(skip_line_terminator(article_bytes, line_end));
            break;
        }

        i = skip_line_terminator(article_bytes, line_end);
    }

    if let (Some(src), Some(start), Some(end)) = (value, found_line_start, found_line_end) {
        let mut new_bytes = Vec::with_capacity(article_bytes.len() - (end - start));
        new_bytes.extend_from_slice(&article_bytes[..start]);
        new_bytes.extend_from_slice(&article_bytes[end..]);
        *article_bytes = new_bytes;
        src
    } else {
        InjectionSource::NntpPost
    }
}

/// Add or prepend-to the `Path:` header required by RFC 5536 §3.1.
///
/// POST articles from newsreader clients MUST NOT include a `Path:` header
/// (RFC 5536 §3.1).  This function handles both cases:
/// - No existing `Path:` header → inserts `Path: hostname\r\n` before the
///   blank line separating headers from body.
/// - Existing `Path:` header → prepends `hostname!` to the existing value.
///
/// Returns the new article bytes.
pub fn prepend_path_header(article_bytes: &[u8], hostname: &str) -> Vec<u8> {
    let header_end = find_header_end(article_bytes);
    let mut out = Vec::with_capacity(article_bytes.len() + 64);
    let mut path_found = false;
    let mut i = 0;
    while i < header_end {
        let line_end = find_line_end(article_bytes, i, header_end);
        let line = &article_bytes[i..line_end];
        let end = skip_line_terminator(article_bytes, line_end);
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"path:") {
            let old_val = String::from_utf8_lossy(&line[5..]);
            let old_val = old_val.trim();
            let new_line = format!("Path: {hostname}!{old_val}\r\n");
            out.extend_from_slice(new_line.as_bytes());
            path_found = true;
        } else {
            out.extend_from_slice(&article_bytes[i..end]);
        }
        i = end;
    }
    if !path_found {
        let path_line = format!("Path: {hostname}\r\n");
        out.extend_from_slice(path_line.as_bytes());
    }
    out.extend_from_slice(&article_bytes[header_end..]);
    out
}

/// Synthesize a `Message-ID:` header if none is present (RFC 5536 §3.1).
///
/// If the article already has a `Message-ID:` header, the article is returned
/// unchanged.  Otherwise a header of the form
/// `Message-ID: <YYYYMMDDHHMMSS.NNNNN.PID@hostname>\r\n`
/// is inserted before the blank line separating headers from body.
///
/// `hostname` is the configured server hostname (same as used for `Path:`).
pub fn inject_message_id(article_bytes: &[u8], hostname: &str) -> Vec<u8> {
    let header_end = find_header_end(article_bytes);
    // Check whether a Message-ID header already exists.
    let mut i = 0;
    while i < header_end {
        let line_end = find_line_end(article_bytes, i, header_end);
        let line = &article_bytes[i..line_end];
        if line.len() >= 11 && line[..11].eq_ignore_ascii_case(b"message-id:") {
            return article_bytes.to_vec();
        }
        i = skip_line_terminator(article_bytes, line_end);
    }

    // Synthesize a Message-ID from current time + process ID + monotonic counter.
    // The counter is the source of uniqueness: PID is constant within a process
    // and subsec_micros() wraps every second, so two POSTs in the same microsecond
    // would collide without it.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let pid = std::process::id();
    let seq = MSG_ID_COUNTER.fetch_add(1, Ordering::Relaxed);

    // Format: YYYYMMDDHHMMSS.SEQNUM.PID
    let dt = format_utc_datetime(secs);
    let local_part = format!("{dt}.{seq}.{pid}");
    let msgid_line = format!("Message-ID: <{local_part}@{hostname}>\r\n");

    let mut out = Vec::with_capacity(article_bytes.len() + msgid_line.len());
    out.extend_from_slice(&article_bytes[..header_end]);
    out.extend_from_slice(msgid_line.as_bytes());
    out.extend_from_slice(&article_bytes[header_end..]);
    out
}

/// Add an `Injection-Info:` header (RFC 5536 §3.2.9).
///
/// Always inserts a fresh header before the blank line; any existing
/// `Injection-Info:` left by the client is preserved (clients are not
/// expected to include this header, but RFC 5536 does not prohibit it).
///
/// Format:
/// ```text
/// Injection-Info: posting-host="<client_ip>"[; posting-account="<username>"][; mail-complaints-to="<addr>"]
/// ```
///
/// `username` is `Some` only when the session is authenticated.
/// `mail_complaints_to` comes from `[operator] mail_complaints_to` in config.
pub fn inject_injection_info(
    article_bytes: &[u8],
    client_ip: &str,
    username: Option<&str>,
    mail_complaints_to: Option<&str>,
) -> Vec<u8> {
    let mut value = format!("posting-host=\"{client_ip}\"");
    if let Some(u) = username {
        value.push_str(&format!("; posting-account=\"{u}\""));
    }
    if let Some(addr) = mail_complaints_to {
        value.push_str(&format!("; mail-complaints-to=\"{addr}\""));
    }
    let header_line = format!("Injection-Info: {value}\r\n");

    let header_end = find_header_end(article_bytes);
    let mut out = Vec::with_capacity(article_bytes.len() + header_line.len());
    out.extend_from_slice(&article_bytes[..header_end]);
    out.extend_from_slice(header_line.as_bytes());
    out.extend_from_slice(&article_bytes[header_end..]);
    out
}

/// Add an `Injection-Date:` header (RFC 5536 §3.2.3) when needed.
///
/// When `max_clock_skew_secs` is `None`, this is a no-op.
///
/// When `max_clock_skew_secs` is `Some(limit)`:
/// - If the article has no `Date:` header, `Injection-Date:` is added with
///   the server's current UTC time.
/// - If the article has a `Date:` header whose value deviates from server
///   time by more than `limit` seconds, `Injection-Date:` is added with the
///   server's current UTC time.
/// - Otherwise the article is returned unchanged.
///
/// The `Date:` header is never removed or modified; `Injection-Date:` is
/// purely additive.
pub fn inject_injection_date(article_bytes: &[u8], max_clock_skew_secs: Option<u64>) -> Vec<u8> {
    let limit = match max_clock_skew_secs {
        Some(l) => l as i64,
        None => return article_bytes.to_vec(),
    };

    let header_end = find_header_end(article_bytes);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Locate the Date: header value.
    let mut date_parsed: Option<i64> = None;
    let mut i = 0;
    while i < header_end {
        let line_end = find_line_end(article_bytes, i, header_end);
        let line = &article_bytes[i..line_end];
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"date:") {
            if let Ok(s) = std::str::from_utf8(&line[5..]) {
                date_parsed = mailparse::dateparse(s.trim()).ok();
            }
            break;
        }
        i = skip_line_terminator(article_bytes, line_end);
    }

    let needs_injection = match date_parsed {
        None => true,
        Some(ts) => (ts - now_secs).abs() > limit,
    };

    if !needs_injection {
        return article_bytes.to_vec();
    }

    let injection_date = format_utc_rfc2822(now_secs);
    let header_line = format!("Injection-Date: {injection_date}\r\n");

    let mut out = Vec::with_capacity(article_bytes.len() + header_line.len());
    out.extend_from_slice(&article_bytes[..header_end]);
    out.extend_from_slice(header_line.as_bytes());
    out.extend_from_slice(&article_bytes[header_end..]);
    out
}

/// Format a Unix timestamp as `YYYYMMDDHHMMSS` (UTC, no separators).
fn format_utc_datetime(secs: u64) -> String {
    let dt: DateTime<Utc> = Utc
        .timestamp_opt(secs as i64, 0)
        .single()
        .unwrap_or_else(Utc::now);
    dt.format("%Y%m%d%H%M%S").to_string()
}

/// Format a Unix timestamp as RFC 2822 (e.g. `Mon, 20 Apr 2026 12:00:00 +0000`).
fn format_utc_rfc2822(secs: i64) -> String {
    stoa_core::util::epoch_to_rfc2822(secs)
}

/// Return the byte offset of the first blank line separator (`\r\n\r\n` or
/// `\n\n`), pointing to the start of the blank line itself.  Returns
/// `article_bytes.len()` if no separator is found (treat entire buffer as
/// headers).
fn find_header_end(article_bytes: &[u8]) -> usize {
    match crate::post::find_header_boundary(article_bytes) {
        Some(body_start) => {
            // Return position after the last header's line terminator but before
            // the blank separator line: body_start - sep_len + sep_len/2.
            // CRLF (sep_len=4): body_start - 2; bare-LF (sep_len=2): body_start - 1.
            let sep_len =
                if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                    4usize
                } else {
                    2usize
                };
            body_start - sep_len / 2
        }
        None => article_bytes.len(),
    }
}

/// Find the end of the line starting at `start`, not crossing `limit`.
/// Returns the index of the `\r` (for CRLF) or `\n` (for LF), or `limit`
/// if no newline is found before `limit`.
fn find_line_end(buf: &[u8], start: usize, limit: usize) -> usize {
    buf[start..limit]
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .map_or(limit, |pos| start + pos)
}

/// Advance past the line terminator (`\r\n` or `\n`) at `pos`.
fn skip_line_terminator(buf: &[u8], pos: usize) -> usize {
    if pos < buf.len() && buf[pos] == b'\r' {
        if pos + 1 < buf.len() && buf[pos + 1] == b'\n' {
            return pos + 2;
        }
        return pos + 1;
    }
    if pos < buf.len() && buf[pos] == b'\n' {
        return pos + 1;
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_article(extra_header: Option<&str>, body: &str) -> Vec<u8> {
        let mut s = String::new();
        if let Some(h) = extra_header {
            s.push_str(h);
            s.push_str("\r\n");
        }
        s.push_str("Newsgroups: comp.test\r\n");
        s.push_str("From: test@example.com\r\n");
        s.push_str("Subject: test\r\n");
        s.push_str("Message-ID: <test@example.com>\r\n");
        s.push_str("\r\n");
        s.push_str(body);
        s.into_bytes()
    }

    #[test]
    fn no_header_returns_nntp_post() {
        let mut article = make_article(None, "body\r\n");
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::NntpPost);
        // Article bytes unchanged.
        let expected = make_article(None, "body\r\n");
        assert_eq!(article, expected);
    }

    #[test]
    fn smtp_list_id_is_extracted_and_removed() {
        let mut article = make_article(Some("X-Stoa-Injection-Source: SmtpListId"), "body\r\n");
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::SmtpListId);
        // Header line must be gone.
        let s = String::from_utf8(article.clone()).unwrap();
        assert!(
            !s.contains("X-Stoa-Injection-Source"),
            "header must be removed; got: {s:?}"
        );
        // Remaining headers must still be present.
        assert!(s.contains("Newsgroups: comp.test"));
    }

    #[test]
    fn smtp_newsgroups_is_extracted_and_removed() {
        let mut article = make_article(Some("X-Stoa-Injection-Source: SmtpNewsgroups"), "body\r\n");
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::SmtpNewsgroups);
        let s = String::from_utf8(article).unwrap();
        assert!(!s.contains("X-Stoa-Injection-Source"));
    }

    #[test]
    fn smtp_sieve_is_extracted_and_removed() {
        let mut article = make_article(Some("X-Stoa-Injection-Source: SmtpSieve"), "body\r\n");
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::SmtpSieve);
        let s = String::from_utf8(article).unwrap();
        assert!(!s.contains("X-Stoa-Injection-Source"));
    }

    #[test]
    fn nntp_post_is_extracted_and_removed() {
        let mut article = make_article(Some("X-Stoa-Injection-Source: NntpPost"), "body\r\n");
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::NntpPost);
        let s = String::from_utf8(article).unwrap();
        assert!(!s.contains("X-Stoa-Injection-Source"));
    }

    #[test]
    fn unknown_value_defaults_to_nntp_post() {
        let mut article = make_article(Some("X-Stoa-Injection-Source: Bogus"), "body\r\n");
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::NntpPost);
        // Header is still removed even when the value is unrecognised.
        let s = String::from_utf8(article).unwrap();
        assert!(!s.contains("X-Stoa-Injection-Source"));
    }

    #[test]
    fn header_removal_leaves_valid_structure() {
        // After removal the blank-line separator must still be present so
        // downstream header parsing succeeds.
        let mut article = make_article(Some("X-Stoa-Injection-Source: SmtpListId"), "body\r\n");
        extract_injection_source(&mut article);
        let s = String::from_utf8(article).unwrap();
        assert!(
            s.contains("\r\n\r\n"),
            "blank-line separator must remain after header removal"
        );
    }

    // ── strip_server_synthesized_headers tests ────────────────────────────────

    #[test]
    fn strip_did_verified_removed() {
        let mut article = make_article(Some("X-Stoa-DID-Verified: true"), "body\r\n");
        strip_server_synthesized_headers(&mut article);
        let s = String::from_utf8(article).unwrap();
        assert!(
            !s.contains("X-Stoa-DID-Verified"),
            "X-Stoa-DID-Verified must be stripped: {s:?}"
        );
        assert!(s.contains("Newsgroups:"), "other headers must remain");
    }

    #[test]
    fn strip_x_stoa_verified_removed() {
        let mut article = make_article(Some("X-Stoa-Verified: pass"), "body\r\n");
        strip_server_synthesized_headers(&mut article);
        let s = String::from_utf8(article).unwrap();
        assert!(
            !s.contains("X-Stoa-Verified"),
            "X-Stoa-Verified must be stripped: {s:?}"
        );
    }

    #[test]
    fn strip_cid_header_removed() {
        let mut article = make_article(Some("X-Stoa-CID: bafyreiabc"), "body\r\n");
        strip_server_synthesized_headers(&mut article);
        let s = String::from_utf8(article).unwrap();
        assert!(
            !s.contains("X-Stoa-CID"),
            "X-Stoa-CID must be stripped: {s:?}"
        );
    }

    #[test]
    fn strip_multiple_occurrences_all_removed() {
        // Two forged X-Stoa-DID-Verified headers must both be stripped.
        let mut article = format!(
            "X-Stoa-DID-Verified: true\r\n\
             X-Stoa-DID-Verified: false\r\n\
             Newsgroups: comp.test\r\n\
             From: a@b\r\n\
             Subject: test\r\n\
             Message-ID: <x@y>\r\n\
             \r\n\
             body\r\n"
        )
        .into_bytes();
        strip_server_synthesized_headers(&mut article);
        let s = String::from_utf8(article).unwrap();
        assert!(
            !s.contains("X-Stoa-DID-Verified"),
            "all occurrences must be stripped: {s:?}"
        );
        assert!(s.contains("\r\n\r\n"), "blank-line separator must remain");
    }

    #[test]
    fn strip_no_matching_headers_unchanged() {
        let mut article = make_article(None, "body\r\n");
        let before = article.clone();
        strip_server_synthesized_headers(&mut article);
        assert_eq!(
            article, before,
            "article with no synthesized headers must be unchanged"
        );
    }

    #[test]
    fn strip_case_insensitive() {
        let mut article = make_article(Some("x-stoa-did-verified: true"), "body\r\n");
        strip_server_synthesized_headers(&mut article);
        let s = String::from_utf8(article).unwrap();
        assert!(
            !s.to_ascii_lowercase().contains("x-stoa-did-verified"),
            "stripping must be case-insensitive: {s:?}"
        );
    }

    // ── prepend_path_header tests ─────────────────────────────────────────────

    #[test]
    fn path_header_added_when_absent() {
        let article = make_article(None, "body\r\n");
        let result = prepend_path_header(&article, "news.example.com");
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.contains("Path: news.example.com\r\n"),
            "Path header must be added: {s:?}"
        );
        assert!(s.contains("Newsgroups:"), "other headers must remain");
        assert!(s.contains("\r\n\r\n"), "blank-line separator must remain");
        assert!(s.ends_with("body\r\n"), "body must be unchanged");
    }

    #[test]
    fn path_header_prepended_when_existing() {
        let article = make_article(Some("Path: upstream.example.com"), "body\r\n");
        let result = prepend_path_header(&article, "news.example.com");
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.contains("Path: news.example.com!upstream.example.com\r\n"),
            "Path must be prepended: {s:?}"
        );
        // Original Path header value must not appear standalone.
        assert!(
            !s.contains("Path: upstream.example.com\r\n"),
            "old Path header must be replaced: {s:?}"
        );
    }

    #[test]
    fn path_header_injection_case_insensitive() {
        let article = make_article(Some("path: old.example.com"), "body\r\n");
        let result = prepend_path_header(&article, "new.example.com");
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.contains("Path: new.example.com!old.example.com\r\n"),
            "Path must be prepended case-insensitively: {s:?}"
        );
    }

    // ── inject_message_id tests ───────────────────────────────────────────────

    #[test]
    fn message_id_synthesized_when_absent() {
        // Article has no Message-ID header.
        let article = format!(
            "Newsgroups: comp.test\r\n\
             From: user@example.com\r\n\
             Subject: test\r\n\
             \r\n\
             body\r\n"
        )
        .into_bytes();
        let result = inject_message_id(&article, "news.example.com");
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.to_ascii_lowercase().contains("message-id:"),
            "Message-ID must be synthesized: {s:?}"
        );
        assert!(
            s.contains("@news.example.com>"),
            "Message-ID must use configured hostname: {s:?}"
        );
        assert!(s.contains("\r\n\r\n"), "blank-line separator must remain");
        assert!(s.ends_with("body\r\n"), "body must be unchanged");
    }

    #[test]
    fn message_id_unchanged_when_present() {
        let article = make_article(None, "body\r\n");
        // make_article adds Message-ID: <test@example.com>
        let before = article.clone();
        let result = inject_message_id(&article, "news.example.com");
        assert_eq!(
            result, before,
            "article with existing Message-ID must be unchanged"
        );
    }

    #[test]
    fn message_id_case_insensitive_detection() {
        // Lower-case header name must also be detected.
        let article = format!(
            "Newsgroups: comp.test\r\n\
             message-id: <existing@old.example.com>\r\n\
             From: user@example.com\r\n\
             Subject: test\r\n\
             \r\n\
             body\r\n"
        )
        .into_bytes();
        let before = article.clone();
        let result = inject_message_id(&article, "news.example.com");
        assert_eq!(
            result, before,
            "lower-case Message-ID must be detected and left unchanged"
        );
    }

    // ── inject_injection_info tests ───────────────────────────────────────────

    #[test]
    fn injection_info_unauthenticated() {
        let article = make_article(None, "body\r\n");
        let result = inject_injection_info(&article, "192.0.2.1", None, None);
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.contains("Injection-Info: posting-host=\"192.0.2.1\"\r\n"),
            "Injection-Info must contain posting-host: {s:?}"
        );
        assert!(
            !s.contains("posting-account"),
            "posting-account must not appear when unauthenticated: {s:?}"
        );
        assert!(
            !s.contains("mail-complaints-to"),
            "mail-complaints-to must not appear when unconfigured: {s:?}"
        );
    }

    #[test]
    fn injection_info_authenticated() {
        let article = make_article(None, "body\r\n");
        let result = inject_injection_info(&article, "192.0.2.1", Some("alice"), None);
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.contains("posting-account=\"alice\""),
            "posting-account must appear when authenticated: {s:?}"
        );
    }

    #[test]
    fn injection_info_with_mail_complaints_to() {
        let article = make_article(None, "body\r\n");
        let result = inject_injection_info(&article, "192.0.2.1", None, Some("abuse@example.com"));
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.contains("mail-complaints-to=\"abuse@example.com\""),
            "mail-complaints-to must appear when configured: {s:?}"
        );
    }

    #[test]
    fn injection_info_all_fields() {
        let article = make_article(None, "body\r\n");
        let result = inject_injection_info(
            &article,
            "10.0.0.1",
            Some("bob"),
            Some("abuse@news.example.com"),
        );
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.contains("posting-host=\"10.0.0.1\""),
            "posting-host present: {s:?}"
        );
        assert!(
            s.contains("posting-account=\"bob\""),
            "posting-account present: {s:?}"
        );
        assert!(
            s.contains("mail-complaints-to=\"abuse@news.example.com\""),
            "mail-complaints-to present: {s:?}"
        );
        assert!(s.contains("\r\n\r\n"), "blank-line separator must remain");
    }

    // ── inject_injection_date tests ───────────────────────────────────────────

    #[test]
    fn injection_date_noop_when_no_skew_limit() {
        // Without a max_clock_skew_secs config, no Injection-Date is ever added.
        let article = format!(
            "Newsgroups: comp.test\r\n\
             From: user@example.com\r\n\
             Subject: test\r\n\
             \r\n\
             body\r\n"
        )
        .into_bytes();
        let before = article.clone();
        let result = inject_injection_date(&article, None);
        assert_eq!(
            result, before,
            "no Injection-Date must be added when max_clock_skew_secs is None"
        );
    }

    #[test]
    fn injection_date_added_when_date_absent() {
        // Article has no Date: header; with a skew limit, Injection-Date must be added.
        let article = format!(
            "Newsgroups: comp.test\r\n\
             From: user@example.com\r\n\
             Subject: test\r\n\
             \r\n\
             body\r\n"
        )
        .into_bytes();
        let result = inject_injection_date(&article, Some(86400));
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.to_ascii_lowercase().contains("injection-date:"),
            "Injection-Date must be added when Date is absent: {s:?}"
        );
        assert!(s.contains("\r\n\r\n"), "blank-line separator must remain");
    }

    #[test]
    fn injection_date_not_added_when_date_within_skew() {
        // Article Date is current-ish (within 1 hour); no Injection-Date needed.
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let date_str = stoa_core::util::epoch_to_rfc2822(now);
        let article = format!(
            "Newsgroups: comp.test\r\n\
             From: user@example.com\r\n\
             Subject: test\r\n\
             Date: {date_str}\r\n\
             \r\n\
             body\r\n"
        )
        .into_bytes();
        let before = article.clone();
        let result = inject_injection_date(&article, Some(86400));
        assert_eq!(
            result, before,
            "Injection-Date must not be added when Date is within skew limit"
        );
    }

    #[test]
    fn injection_date_added_when_date_outside_skew() {
        // Article Date is far in the past (year 2000); must trigger Injection-Date.
        let article = format!(
            "Newsgroups: comp.test\r\n\
             From: user@example.com\r\n\
             Subject: test\r\n\
             Date: Sat, 01 Jan 2000 00:00:00 +0000\r\n\
             \r\n\
             body\r\n"
        )
        .into_bytes();
        let result = inject_injection_date(&article, Some(86400));
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.to_ascii_lowercase().contains("injection-date:"),
            "Injection-Date must be added when Date is outside skew limit: {s:?}"
        );
        // Original Date: must still be present (Injection-Date is additive).
        assert!(
            s.contains("Date: Sat, 01 Jan 2000 00:00:00 +0000"),
            "original Date: header must be preserved: {s:?}"
        );
    }
}
