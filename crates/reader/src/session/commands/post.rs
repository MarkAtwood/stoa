use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::post::{find_header_boundary, validate_headers::validate_post_headers};
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
/// If accumulating the article would exceed `max_bytes`, this function switches
/// to drain mode: it continues reading until the dot-terminator (keeping the
/// NNTP connection valid) but discards all content, then returns
/// `Err(ErrorKind::InvalidData)`.  The caller should send a 441 response and
/// continue accepting commands — the connection is still usable.
///
/// Generic over `AsyncBufRead` so that unit tests can supply a `BufReader<&[u8]>`
/// instead of a live TCP stream.
pub async fn read_dot_terminated<R>(reader: &mut R, max_bytes: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let mut article = Vec::new();
    let mut line_buf = String::new();
    // Once true, we stop accumulating but keep reading until the terminator.
    let mut too_large = false;

    loop {
        line_buf.clear();
        let n = reader.read_line(&mut line_buf).await?;
        if n == 0 {
            // EOF before terminator — return what we have (or the error).
            break;
        }

        // Normalize to bare content (strip trailing \r\n or \n for comparison).
        let bare = line_buf.trim_end_matches(['\r', '\n']);

        // Dot-terminator: a line consisting of exactly a single dot.
        if bare == "." {
            break;
        }

        if too_large {
            // Drain mode: discard content, keep reading for the terminator.
            continue;
        }

        // Dot-unstuff and write canonical CRLF line into output.
        let content = dot_unstuff(bare);
        // +2 accounts for the CRLF we are about to append.
        if article.len() + content.len() + 2 > max_bytes {
            // Switch to drain mode.  Do not accumulate this line.
            too_large = true;
            continue;
        }
        article.extend_from_slice(content.as_bytes());
        article.extend_from_slice(b"\r\n");
    }

    if too_large {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "article too large",
        ));
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
/// - `441` with RFC 5536 error detail if any mandatory header is missing or invalid
pub fn complete_post(article_bytes: &[u8], max_article_bytes: usize) -> Result<(), Response> {
    if article_bytes.len() > max_article_bytes {
        return Err(Response::new(441, "Article too large"));
    }

    // Split at the first blank line to separate headers from body.
    // Accept both \r\n\r\n and \n\n as the separator.
    let header_bytes = if let Some(body_start) = find_header_boundary(article_bytes) {
        // Exclude the separator itself: 4 bytes for \r\n\r\n, 2 for \n\n.
        let sep_len =
            if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                4
            } else {
                2
            };
        &article_bytes[..body_start - sep_len]
    } else {
        // No blank line found — treat the whole thing as headers.
        article_bytes
    };

    validate_post_headers(header_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use stoa_core::util::epoch_to_rfc2822;

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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            // infallible: system clock is always after UNIX_EPOCH on any supported platform
            .unwrap()
            .as_secs() as i64;
        let date_str = epoch_to_rfc2822(now);
        let mut headers = String::new();
        if let Some(ng) = newsgroups {
            headers.push_str(&format!("Newsgroups: {ng}\r\n"));
        }
        if let Some(f) = from {
            headers.push_str(&format!("From: {f}\r\n"));
        }
        headers.push_str("Subject: test\r\n");
        headers.push_str(&format!("Date: {date_str}\r\n"));
        headers.push_str("Message-ID: <test@example.com>\r\n");
        headers.push_str("\r\n");
        headers.push_str("Body text.\r\n");
        headers.into_bytes()
    }

    #[test]
    fn complete_post_valid_article_returns_240() {
        let article = minimal_article(Some("comp.lang.rust"), Some("user@example.com"));
        assert!(complete_post(&article, DEFAULT_MAX_ARTICLE_BYTES).is_ok());
    }

    #[test]
    fn complete_post_oversized_returns_441_too_large() {
        let article = minimal_article(Some("comp.lang.rust"), Some("user@example.com"));
        let err = complete_post(&article, 1).unwrap_err(); // limit of 1 byte
        assert_eq!(err.code, 441);
        assert!(err.text.contains("too large"));
    }

    #[test]
    fn complete_post_missing_newsgroups_returns_441() {
        let article = minimal_article(None, Some("user@example.com"));
        let err = complete_post(&article, DEFAULT_MAX_ARTICLE_BYTES).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("Newsgroups"),
            "expected 'Newsgroups' in: {}",
            err.text
        );
    }

    #[test]
    fn complete_post_missing_from_returns_441() {
        let article = minimal_article(Some("comp.lang.rust"), None);
        let err = complete_post(&article, DEFAULT_MAX_ARTICLE_BYTES).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("From"),
            "expected 'From' in: {}",
            err.text
        );
    }

    #[test]
    fn complete_post_missing_both_headers_reports_from_first() {
        // validate_post_headers checks mandatory headers in order:
        // From, Date, Message-ID, Newsgroups, Subject — so From is reported first.
        let article = minimal_article(None, None);
        let err = complete_post(&article, DEFAULT_MAX_ARTICLE_BYTES).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("From"),
            "expected 'From' in: {}",
            err.text
        );
    }

    // ----- read_dot_terminated -----

    async fn read_article(input: &[u8]) -> Vec<u8> {
        let mut reader = tokio::io::BufReader::new(input);
        read_dot_terminated(&mut reader, DEFAULT_MAX_ARTICLE_BYTES)
            .await
            .unwrap()
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

    #[tokio::test]
    async fn read_dot_terminated_too_large_returns_invalid_data() {
        // Content is 22 bytes ("0123456789abcdefghij\r\n"), limit is 10.
        // Expects Err(InvalidData) after draining to the terminator.
        let input = b"0123456789abcdefghij\r\n.\r\n";
        let mut reader = tokio::io::BufReader::new(input.as_ref());
        let result = read_dot_terminated(&mut reader, 10).await;
        assert!(result.is_err(), "expected Err for oversized article");
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData,
            "must be InvalidData so caller can send 441 and keep connection"
        );
    }

    #[tokio::test]
    async fn read_dot_terminated_exactly_at_limit_succeeds() {
        // 5-byte content ("hi\r\n" = 4 bytes + planned CRLF → effectively "hi\r\n").
        // Limit is 4 — exactly fits.
        let input = b"hi\r\n.\r\n";
        let mut reader = tokio::io::BufReader::new(input.as_ref());
        let result = read_dot_terminated(&mut reader, 4).await;
        assert!(result.is_ok(), "exactly at limit must succeed");
        assert_eq!(result.unwrap(), b"hi\r\n");
    }
}
