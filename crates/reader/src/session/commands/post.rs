use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::session::response::Response;

/// Default maximum article size (1 MiB) used when no config value is available.
pub const DEFAULT_MAX_ARTICLE_BYTES: usize = 1_048_576;

/// Apply RFC 5536 §3.1.1 dot-unstuffing to a single line (without line ending).
///
/// Lines that begin with `..` have one leading dot removed. All other lines
/// are returned unchanged.
pub fn dot_unstuff(line: &str) -> &str {
    if line.starts_with("..") {
        &line[1..]
    } else {
        line
    }
}

/// Read a dot-terminated NNTP article stream from `reader`.
///
/// Reads lines until the dot-terminator `.\r\n` (or `.\n`) is encountered.
/// Applies dot-unstuffing per RFC 5536 §3.1.1.
/// Returns the reassembled article bytes (with `\r\n` line endings, terminator
/// removed).
///
/// Generic over `AsyncBufRead` so that unit tests can supply a `BufReader<&[u8]>`
/// instead of a live TCP stream.
pub async fn read_dot_terminated<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let mut article = Vec::new();
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        let n = reader.read_line(&mut line_buf).await?;
        if n == 0 {
            // EOF before terminator — return what we have.
            break;
        }

        // Normalize to bare content (strip trailing \r\n or \n for comparison).
        let bare = line_buf.trim_end_matches(['\r', '\n']);

        // Dot-terminator: a line consisting of exactly a single dot.
        if bare == "." {
            break;
        }

        // Dot-unstuff and write canonical CRLF line into output.
        let content = dot_unstuff(bare);
        article.extend_from_slice(content.as_bytes());
        article.extend_from_slice(b"\r\n");
    }

    Ok(article)
}

/// Validate an article received via POST and return the appropriate response.
///
/// Called after the dot-terminated stream has been read and reassembled into
/// `article_bytes`.  This function is pure (no I/O) so it can be tested
/// directly without a network connection.
///
/// Returns:
/// - `240 Article received OK` on success
/// - `441 Article too large` if the article exceeds `max_article_bytes`
/// - `441 Missing Newsgroups header` if the `Newsgroups:` header is absent
/// - `441 Missing From header` if the `From:` header is absent
pub fn complete_post(article_bytes: &[u8], max_article_bytes: usize) -> Response {
    if article_bytes.len() > max_article_bytes {
        return Response::new(441, "Article too large");
    }

    // Split at the first blank line to separate headers from body.
    // Accept both \r\n\r\n and \n\n as the separator.
    let header_bytes = if let Some(pos) = find_header_end(article_bytes) {
        &article_bytes[..pos]
    } else {
        // No blank line found — treat the whole thing as headers.
        article_bytes
    };

    let headers = String::from_utf8_lossy(header_bytes);

    if !has_header(&headers, "Newsgroups") {
        return Response::new(441, "Missing Newsgroups header");
    }

    if !has_header(&headers, "From") {
        return Response::new(441, "Missing From header");
    }

    Response::new(240, "Article received OK")
}

/// Find the byte offset of the start of the blank line that separates
/// headers from body.  Returns the offset of the last byte of the header
/// block (i.e. just before the blank line), or `None` if not found.
///
/// Recognises both `\r\n\r\n` and `\n\n`.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    // Search for \r\n\r\n first (canonical), then \n\n.
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return Some(i);
        }
        if bytes[i..].starts_with(b"\n\n") {
            return Some(i);
        }
    }
    None
}

/// Check whether `headers` contains a header field named `name`.
///
/// Matches case-insensitively and accepts both `Name:` (no space) and
/// `Name: value` forms.  Folded headers (RFC 5322 §2.2.3) are not unfolded
/// here because we only check for presence, not value.
fn has_header(headers: &str, name: &str) -> bool {
    let prefix_colon = format!("{}:", name.to_ascii_lowercase());
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with(&prefix_colon) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- dot_unstuff -----

    #[test]
    fn dot_unstuff_double_dot_removes_one() {
        assert_eq!(dot_unstuff("..foo"), ".foo");
    }

    #[test]
    fn dot_unstuff_plain_line_unchanged() {
        assert_eq!(dot_unstuff("foo bar"), "foo bar");
    }

    #[test]
    fn dot_unstuff_single_dot_unchanged() {
        // A bare "." is the terminator — caller handles it before unstuffing.
        // dot_unstuff itself should leave it alone.
        assert_eq!(dot_unstuff("."), ".");
    }

    #[test]
    fn dot_unstuff_triple_dot_removes_one() {
        assert_eq!(dot_unstuff("..."), "..");
    }

    #[test]
    fn dot_unstuff_empty_line_unchanged() {
        assert_eq!(dot_unstuff(""), "");
    }

    // ----- complete_post -----

    fn minimal_article(newsgroups: Option<&str>, from: Option<&str>) -> Vec<u8> {
        let mut headers = String::new();
        if let Some(ng) = newsgroups {
            headers.push_str(&format!("Newsgroups: {ng}\r\n"));
        }
        if let Some(f) = from {
            headers.push_str(&format!("From: {f}\r\n"));
        }
        headers.push_str("Subject: test\r\n");
        headers.push_str("\r\n");
        headers.push_str("Body text.\r\n");
        headers.into_bytes()
    }

    #[test]
    fn complete_post_valid_article_returns_240() {
        let article = minimal_article(Some("comp.lang.rust"), Some("user@example.com"));
        let resp = complete_post(&article, DEFAULT_MAX_ARTICLE_BYTES);
        assert_eq!(resp.code, 240);
    }

    #[test]
    fn complete_post_oversized_returns_441_too_large() {
        let article = minimal_article(Some("comp.lang.rust"), Some("user@example.com"));
        let resp = complete_post(&article, 1); // limit of 1 byte
        assert_eq!(resp.code, 441);
        assert!(resp.text.contains("too large"));
    }

    #[test]
    fn complete_post_missing_newsgroups_returns_441() {
        let article = minimal_article(None, Some("user@example.com"));
        let resp = complete_post(&article, DEFAULT_MAX_ARTICLE_BYTES);
        assert_eq!(resp.code, 441);
        assert!(resp.text.contains("Newsgroups"));
    }

    #[test]
    fn complete_post_missing_from_returns_441() {
        let article = minimal_article(Some("comp.lang.rust"), None);
        let resp = complete_post(&article, DEFAULT_MAX_ARTICLE_BYTES);
        assert_eq!(resp.code, 441);
        assert!(resp.text.contains("From"));
    }

    #[test]
    fn complete_post_missing_both_headers_reports_newsgroups_first() {
        let article = minimal_article(None, None);
        let resp = complete_post(&article, DEFAULT_MAX_ARTICLE_BYTES);
        assert_eq!(resp.code, 441);
        assert!(resp.text.contains("Newsgroups"));
    }

    // ----- read_dot_terminated -----

    async fn read_article(input: &[u8]) -> Vec<u8> {
        let mut reader = tokio::io::BufReader::new(input);
        read_dot_terminated(&mut reader).await.unwrap()
    }

    #[tokio::test]
    async fn read_dot_terminated_basic() {
        let input = b"Subject: hi\r\nFrom: a@b\r\n\r\nBody\r\n.\r\n";
        let result = read_article(input).await;
        assert_eq!(result, b"Subject: hi\r\nFrom: a@b\r\n\r\nBody\r\n");
    }

    #[tokio::test]
    async fn read_dot_terminated_dot_stuffing_removed() {
        let input = b"..leading dot\r\n.\r\n";
        let result = read_article(input).await;
        assert_eq!(result, b".leading dot\r\n");
    }

    #[tokio::test]
    async fn read_dot_terminated_lf_only_client() {
        // Lenient: accept \n line endings from the client.
        let input = b"Subject: hi\nFrom: a@b\n\nBody\n.\n";
        let result = read_article(input).await;
        // Output is normalized to CRLF.
        assert_eq!(result, b"Subject: hi\r\nFrom: a@b\r\n\r\nBody\r\n");
    }

    #[tokio::test]
    async fn read_dot_terminated_eof_before_terminator() {
        // Stream ends without "."; return what was read so far.
        let input = b"partial line\r\n";
        let result = read_article(input).await;
        assert_eq!(result, b"partial line\r\n");
    }
}
