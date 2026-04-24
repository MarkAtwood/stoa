use usenet_ipfs_core::InjectionSource;

/// The header name prepended by the SMTP queue drain.
const INJECTION_SOURCE_HEADER: &[u8] = b"X-Usenet-IPFS-Injection-Source:";

/// Extract and remove the `X-Usenet-IPFS-Injection-Source:` header from
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

    let header_name_lower = b"x-usenet-ipfs-injection-source:";
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
            && line[..header_name_lower.len()]
                .iter()
                .zip(header_name_lower.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
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
        article_bytes.drain(start..end);
        src
    } else {
        InjectionSource::NntpPost
    }
}

/// Return the byte offset of the first blank line separator (`\r\n\r\n` or
/// `\n\n`), pointing to the start of the blank line itself.  Returns
/// `article_bytes.len()` if no separator is found (treat entire buffer as
/// headers).
fn find_header_end(article_bytes: &[u8]) -> usize {
    for i in 0..article_bytes.len().saturating_sub(3) {
        if article_bytes[i..].starts_with(b"\r\n\r\n") {
            return i + 2; // include the first CRLF, stop before blank line
        }
    }
    for i in 0..article_bytes.len().saturating_sub(1) {
        if article_bytes[i..].starts_with(b"\n\n") {
            return i + 1;
        }
    }
    article_bytes.len()
}

/// Find the end of the line starting at `start`, not crossing `limit`.
/// Returns the index of the `\r` (for CRLF) or `\n` (for LF), or `limit`
/// if no newline is found before `limit`.
fn find_line_end(buf: &[u8], start: usize, limit: usize) -> usize {
    for i in start..limit {
        if buf[i] == b'\r' || buf[i] == b'\n' {
            return i;
        }
    }
    limit
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
        let mut article = make_article(
            Some("X-Usenet-IPFS-Injection-Source: SmtpListId"),
            "body\r\n",
        );
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::SmtpListId);
        // Header line must be gone.
        let s = String::from_utf8(article.clone()).unwrap();
        assert!(
            !s.contains("X-Usenet-IPFS-Injection-Source"),
            "header must be removed; got: {s:?}"
        );
        // Remaining headers must still be present.
        assert!(s.contains("Newsgroups: comp.test"));
    }

    #[test]
    fn smtp_newsgroups_is_extracted_and_removed() {
        let mut article = make_article(
            Some("X-Usenet-IPFS-Injection-Source: SmtpNewsgroups"),
            "body\r\n",
        );
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::SmtpNewsgroups);
        let s = String::from_utf8(article).unwrap();
        assert!(!s.contains("X-Usenet-IPFS-Injection-Source"));
    }

    #[test]
    fn smtp_sieve_is_extracted_and_removed() {
        let mut article = make_article(
            Some("X-Usenet-IPFS-Injection-Source: SmtpSieve"),
            "body\r\n",
        );
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::SmtpSieve);
        let s = String::from_utf8(article).unwrap();
        assert!(!s.contains("X-Usenet-IPFS-Injection-Source"));
    }

    #[test]
    fn nntp_post_is_extracted_and_removed() {
        let mut article =
            make_article(Some("X-Usenet-IPFS-Injection-Source: NntpPost"), "body\r\n");
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::NntpPost);
        let s = String::from_utf8(article).unwrap();
        assert!(!s.contains("X-Usenet-IPFS-Injection-Source"));
    }

    #[test]
    fn unknown_value_defaults_to_nntp_post() {
        let mut article = make_article(Some("X-Usenet-IPFS-Injection-Source: Bogus"), "body\r\n");
        let src = extract_injection_source(&mut article);
        assert_eq!(src, InjectionSource::NntpPost);
        // Header is still removed even when the value is unrecognised.
        let s = String::from_utf8(article).unwrap();
        assert!(!s.contains("X-Usenet-IPFS-Injection-Source"));
    }

    #[test]
    fn header_removal_leaves_valid_structure() {
        // After removal the blank-line separator must still be present so
        // downstream header parsing succeeds.
        let mut article = make_article(
            Some("X-Usenet-IPFS-Injection-Source: SmtpListId"),
            "body\r\n",
        );
        extract_injection_source(&mut article);
        let s = String::from_utf8(article).unwrap();
        assert!(
            s.contains("\r\n\r\n"),
            "blank-line separator must remain after header removal"
        );
    }
}
