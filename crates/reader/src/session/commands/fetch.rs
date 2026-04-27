use cid::Cid;
use stoa_verify::ArticleVerification;
use tracing::debug;

use crate::session::response::Response;

/// Represents a stored article's content (resolved from storage).
pub struct ArticleContent {
    pub article_number: u64,
    pub message_id: String,
    /// Raw header bytes (without trailing blank line)
    pub header_bytes: Vec<u8>,
    /// Raw body bytes
    pub body_bytes: Vec<u8>,
    /// The article CID from the msgid→CID map, if available.
    /// Used to inject X-Stoa-CID into ARTICLE and HEAD responses.
    pub cid: Option<Cid>,
    /// DID signature verification result from the overview index.
    ///
    /// `None`  — no `X-Stoa-DID-Sig` header was present (header omitted).
    /// `Some(false)` — signature verification failed.
    /// `Some(true)`  — signature verified successfully.
    pub did_sig_valid: Option<bool>,
    /// Cryptographic signature verification results from the verify store.
    ///
    /// Empty when no verifications have been recorded for this article (e.g.
    /// legacy articles written before verification was enabled).  The
    /// `X-Stoa-Verified` header is omitted in that case.
    pub verifications: Vec<ArticleVerification>,
}

/// Apply dot-stuffing to article output: prepend '.' to any line starting with '.'.
///
/// Input is raw bytes split on CRLF boundaries. Each line that begins with '.'
/// has an additional '.' prepended, per RFC 3977 §3.1.1. The output preserves
/// CRLF line endings.
pub fn dot_stuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut pos = 0;
    while pos < data.len() {
        // Find end of line (CRLF or end of data).
        let (line, advance) = if let Some(rel) = find_crlf(&data[pos..]) {
            (&data[pos..pos + rel], rel + 2)
        } else {
            (&data[pos..], data.len() - pos)
        };

        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        // Restore CRLF if it was present.
        if pos + advance <= data.len() && advance > line.len() {
            out.extend_from_slice(b"\r\n");
        }
        pos += advance;
    }
    out
}

/// Find the position of `\r\n` in `data`, returning the byte offset of `\r`.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

/// Split raw bytes on CRLF into a Vec of Strings (without the CRLF).
///
/// Used to populate `Response.body` lines.
fn bytes_to_lines(data: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let (line, advance) = if let Some(rel) = find_crlf(&data[pos..]) {
            (&data[pos..pos + rel], rel + 2)
        } else {
            (&data[pos..], data.len() - pos)
        };
        lines.push(String::from_utf8_lossy(line).into_owned());
        pos += advance;
    }
    lines
}

/// Dot-stuff `data` and split into body lines for a `Response`.
fn dot_stuffed_lines(data: &[u8]) -> Vec<String> {
    bytes_to_lines(&dot_stuff(data))
}

/// Build the X-Stoa-CID header line string for injection into responses.
///
/// Returns `None` when no CID is available (legacy articles or failed lookups).
fn cid_header_line(content: &ArticleContent) -> Option<String> {
    content.cid.as_ref().map(|c| format!("X-Stoa-CID: {c}"))
}

/// Build the X-Stoa-DID-Verified header line string for injection into responses.
///
/// Returns `None` when no DID signature was present on the article (i.e.
/// `did_sig_valid` is `None`).  Returns `Some("X-Stoa-DID-Verified: true")`
/// or `Some("X-Stoa-DID-Verified: false")` when a verification result is known.
fn did_verified_header_line(content: &ArticleContent) -> Option<String> {
    content
        .did_sig_valid
        .map(|v| format!("X-Stoa-DID-Verified: {v}"))
}

/// Build the `X-Stoa-Verified` header line for injection into responses.
///
/// Returns `None` when no verification results have been recorded (empty slice).
/// Returns `Some("X-Stoa-Verified: pass")` if any method passed,
/// `Some("X-Stoa-Verified: fail")` if all methods tried and none passed.
fn verified_header_line(content: &ArticleContent) -> Option<String> {
    stoa_verify::aggregate_status(&content.verifications)
        .map(|pass| format!("X-Stoa-Verified: {}", if pass { "pass" } else { "fail" }))
}

/// ARTICLE response: 220 + article_number + message_id, followed by headers,
/// a blank line, and the dot-stuffed body. Terminated by ".".
pub fn article_response(content: &ArticleContent) -> Response {
    let mut body = bytes_to_lines(&content.header_bytes);
    if let Some(cid_line) = cid_header_line(content) {
        body.push(cid_line);
    }
    if let Some(did_line) = did_verified_header_line(content) {
        debug!(
            message_id = %content.message_id,
            did_sig_valid = ?content.did_sig_valid,
            "injecting X-Stoa-DID-Verified header"
        );
        body.push(did_line);
    }
    if let Some(verified_line) = verified_header_line(content) {
        body.push(verified_line);
    }
    body.push(String::new()); // blank line separating headers from body
    body.extend(dot_stuffed_lines(&content.body_bytes));
    Response {
        code: 220,
        text: format!(
            "{} {} Article follows",
            content.article_number, content.message_id
        ),
        body,
        multiline: true,
    }
}

/// HEAD response: 221 + article_number + message_id, followed by headers only.
/// Terminated by ".".
pub fn head_response(content: &ArticleContent) -> Response {
    let mut body = bytes_to_lines(&content.header_bytes);
    if let Some(cid_line) = cid_header_line(content) {
        body.push(cid_line);
    }
    if let Some(did_line) = did_verified_header_line(content) {
        debug!(
            message_id = %content.message_id,
            did_sig_valid = ?content.did_sig_valid,
            "injecting X-Stoa-DID-Verified header"
        );
        body.push(did_line);
    }
    if let Some(verified_line) = verified_header_line(content) {
        body.push(verified_line);
    }
    Response {
        code: 221,
        text: format!(
            "{} {} Headers follow",
            content.article_number, content.message_id
        ),
        body,
        multiline: true,
    }
}

/// 290 response for XCID: returns the CID of the current or named article.
pub fn xcid_response(cid: &Cid) -> Response {
    Response::new(290, cid.to_string())
}

/// BODY response: 222 + article_number + message_id, followed by dot-stuffed body.
/// Terminated by ".".
pub fn body_response(content: &ArticleContent) -> Response {
    Response {
        code: 222,
        text: format!(
            "{} {} Body follows",
            content.article_number, content.message_id
        ),
        body: dot_stuffed_lines(&content.body_bytes),
        multiline: true,
    }
}

/// 430 No article with that message-ID.
pub fn no_such_msgid() -> Response {
    Response::new(430, "No article with that message-id")
}

/// 423 No article with that number (when group is selected).
pub fn no_such_number() -> Response {
    Response::new(423, "No article with that number")
}

/// 412 No newsgroup selected (when number form used without GROUP).
pub fn no_group_selected() -> Response {
    Response::new(412, "No newsgroup selected")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_content() -> ArticleContent {
        ArticleContent {
            article_number: 42,
            message_id: "<test@example.com>".into(),
            header_bytes: b"Subject: Test\r\nFrom: foo@bar.com".to_vec(),
            body_bytes: b"Hello\r\n.dotted line\r\n".to_vec(),
            cid: None,
            did_sig_valid: None,
            verifications: vec![],
        }
    }

    #[test]
    fn dot_stuff_no_leading_dot() {
        let input = b"hello\r\nworld\r\n";
        assert_eq!(dot_stuff(input), input.to_vec());
    }

    #[test]
    fn dot_stuff_leading_dot() {
        let input = b"..foo\r\n";
        let expected = b"...foo\r\n";
        assert_eq!(dot_stuff(input), expected.to_vec());
    }

    #[test]
    fn dot_stuff_multiple_lines() {
        let input = b"normal\r\n.dotted\r\nnormal again\r\n";
        let expected = b"normal\r\n..dotted\r\nnormal again\r\n";
        assert_eq!(dot_stuff(input), expected.to_vec());
    }

    #[test]
    fn article_response_code() {
        let resp = article_response(&test_content());
        assert_eq!(resp.code, 220);
    }

    #[test]
    fn head_response_code() {
        let resp = head_response(&test_content());
        assert_eq!(resp.code, 221);
    }

    #[test]
    fn body_response_code() {
        let resp = body_response(&test_content());
        assert_eq!(resp.code, 222);
    }

    #[test]
    fn article_response_contains_dot_stuffed_body() {
        let content = ArticleContent {
            article_number: 1,
            message_id: "<x@y>".into(),
            header_bytes: b"Subject: X".to_vec(),
            body_bytes: b".starts with dot\r\n".to_vec(),
            cid: None,
            did_sig_valid: None,
            verifications: vec![],
        };
        let resp = article_response(&content);
        // The dot-stuffed line should appear as "..starts with dot" in the body lines.
        assert!(resp.body.iter().any(|l| l == "..starts with dot"));
    }

    #[test]
    fn head_response_does_not_include_body() {
        let content = test_content();
        let resp = head_response(&content);
        // Body text ("Hello") must not appear in a HEAD response.
        assert!(!resp.body.iter().any(|l| l.contains("Hello")));
        // Header text must be present.
        assert!(resp.body.iter().any(|l| l.contains("Subject: Test")));
    }

    #[test]
    fn body_response_does_not_include_headers() {
        let content = test_content();
        let resp = body_response(&content);
        // Header text must not appear in a BODY response.
        assert!(!resp.body.iter().any(|l| l.contains("Subject: Test")));
        // Body text must be present.
        assert!(resp.body.iter().any(|l| l.contains("Hello")));
    }

    #[test]
    fn article_response_injects_did_verified_true() {
        let content = ArticleContent {
            article_number: 1,
            message_id: "<did@example.com>".into(),
            header_bytes: b"Subject: DID test".to_vec(),
            body_bytes: b"body\r\n".to_vec(),
            cid: None,
            did_sig_valid: Some(true),
            verifications: vec![],
        };
        let resp = article_response(&content);
        assert!(
            resp.body.iter().any(|l| l == "X-Stoa-DID-Verified: true"),
            "expected X-Stoa-DID-Verified: true in article response"
        );
    }

    #[test]
    fn article_response_injects_did_verified_false() {
        let content = ArticleContent {
            article_number: 2,
            message_id: "<did-bad@example.com>".into(),
            header_bytes: b"Subject: DID bad".to_vec(),
            body_bytes: b"body\r\n".to_vec(),
            cid: None,
            did_sig_valid: Some(false),
            verifications: vec![],
        };
        let resp = article_response(&content);
        assert!(
            resp.body.iter().any(|l| l == "X-Stoa-DID-Verified: false"),
            "expected X-Stoa-DID-Verified: false in article response"
        );
    }

    #[test]
    fn article_response_omits_did_verified_when_none() {
        let content = test_content(); // did_sig_valid: None
        let resp = article_response(&content);
        assert!(
            !resp
                .body
                .iter()
                .any(|l| l.starts_with("X-Stoa-DID-Verified:")),
            "X-Stoa-DID-Verified must be absent when did_sig_valid is None"
        );
    }

    #[test]
    fn head_response_injects_did_verified_true() {
        let content = ArticleContent {
            article_number: 3,
            message_id: "<head-did@example.com>".into(),
            header_bytes: b"Subject: HEAD DID test".to_vec(),
            body_bytes: b"body\r\n".to_vec(),
            cid: None,
            did_sig_valid: Some(true),
            verifications: vec![],
        };
        let resp = head_response(&content);
        assert!(
            resp.body.iter().any(|l| l == "X-Stoa-DID-Verified: true"),
            "expected X-Stoa-DID-Verified: true in head response"
        );
    }

    #[test]
    fn head_response_omits_did_verified_when_none() {
        let content = test_content(); // did_sig_valid: None
        let resp = head_response(&content);
        assert!(
            !resp
                .body
                .iter()
                .any(|l| l.starts_with("X-Stoa-DID-Verified:")),
            "X-Stoa-DID-Verified must be absent when did_sig_valid is None"
        );
    }
}
