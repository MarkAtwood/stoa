use crate::peering::mode_stream::PeeringMode;
use stoa_core::msgid_map::MsgIdMap;
use stoa_core::validation::validate_message_id;

/// Maximum article size for v1 text-only mode: 1 MiB.
pub const MAX_ARTICLE_BYTES: usize = 1_048_576;

/// Result of attempting to ingest an article.
#[derive(Debug, PartialEq)]
pub enum IngestResult {
    /// Article accepted and stored: respond 235 (IHAVE) or 239 (TAKETHIS).
    Accepted,
    /// Already known by Message-ID: respond 435 (IHAVE) or 438 (TAKETHIS).
    Duplicate,
    /// Article rejected (malformed/invalid): respond 437 (IHAVE) or 439 (TAKETHIS).
    Rejected(String),
    /// Transient failure: respond 436 (IHAVE) or 431 (TAKETHIS).
    TransientError(String),
}

/// Validate and process an incoming article from a peer.
///
/// Checks (in order):
/// 1. Message-ID format valid (angle brackets, single `@`, non-empty parts)
/// 2. Article size ≤ [`MAX_ARTICLE_BYTES`]  — cheap array-len check before any I/O
/// 3. Duplicate check via `msgid_map`       — DB round-trip only for plausible articles
/// 4. Mandatory headers present (`From`, `Date`, `Message-ID`, `Newsgroups`, `Subject`)
///
/// Returns [`IngestResult`] without storing anything — the caller is
/// responsible for actually writing to IPFS and the group log.
pub async fn check_ingest(
    message_id: &str,
    article_bytes: &[u8],
    msgid_map: &MsgIdMap,
) -> IngestResult {
    // 1. Message-ID format.
    if let Err(e) = validate_message_id(message_id) {
        crate::metrics::ARTICLES_REJECTED_TOTAL
            .with_label_values(&["malformed"])
            .inc();
        return IngestResult::Rejected(format!("invalid Message-ID format: {e}"));
    }

    // 2. Size limit — O(1) check before the DB round-trip below.
    // A peer sending oversized articles should be rejected immediately without
    // paying the cost of a duplicate lookup.
    if article_bytes.len() > MAX_ARTICLE_BYTES {
        crate::metrics::ARTICLES_REJECTED_TOTAL
            .with_label_values(&["size_exceeded"])
            .inc();
        return IngestResult::Rejected(format!(
            "article too large: {} bytes (limit {})",
            article_bytes.len(),
            MAX_ARTICLE_BYTES
        ));
    }

    // 3. Duplicate check.
    match msgid_map.lookup_by_msgid(message_id).await {
        Err(e) => {
            return IngestResult::TransientError(format!(
                "storage error during duplicate check: {e}"
            ));
        }
        Ok(Some(_)) => {
            crate::metrics::ARTICLES_REJECTED_TOTAL
                .with_label_values(&["duplicate"])
                .inc();
            return IngestResult::Duplicate;
        }
        Ok(None) => {}
    }

    // 4. Mandatory headers.
    const MANDATORY: &[&str] = &["From", "Date", "Message-ID", "Newsgroups", "Subject"];
    for name in MANDATORY {
        if !has_header(article_bytes, name) {
            crate::metrics::ARTICLES_REJECTED_TOTAL
                .with_label_values(&["malformed"])
                .inc();
            return IngestResult::Rejected(format!("missing mandatory header: {name}"));
        }
    }

    IngestResult::Accepted
}

/// Format the NNTP response line for an IHAVE result.
///
/// | Result          | Code |
/// |-----------------|------|
/// | Accepted        | 235  |
/// | Duplicate       | 435  |
/// | Rejected        | 437  |
/// | TransientError  | 436  |
pub fn ihave_response(result: &IngestResult) -> &'static str {
    match result {
        IngestResult::Accepted => "235 Article transferred OK\r\n",
        IngestResult::Duplicate => "435 Duplicate\r\n",
        IngestResult::Rejected(_) => "437 Article rejected\r\n",
        IngestResult::TransientError(_) => "436 Transfer failed, try again later\r\n",
    }
}

/// Format the NNTP response line for a TAKETHIS result.
///
/// | Result          | Code |
/// |-----------------|------|
/// | Accepted        | 239  |
/// | Duplicate       | 438  |
/// | Rejected        | 439  |
/// | TransientError  | 431  |
pub fn takethis_response(result: &IngestResult) -> &'static str {
    match result {
        IngestResult::Accepted => "239 Article transferred OK\r\n",
        IngestResult::Duplicate => "438 Already have it\r\n",
        IngestResult::Rejected(_) => "439 Article not wanted\r\n",
        IngestResult::TransientError(_) => "431 Try sending it again later\r\n",
    }
}

/// Format the NNTP response line for a CHECK result (RFC 4644).
///
/// | Result          | Code |
/// |-----------------|------|
/// | Accepted        | 238  |
/// | Duplicate       | 438  |
/// | Rejected        | 438  |
/// | TransientError  | 431  |
pub fn check_response(result: &IngestResult) -> &'static str {
    match result {
        IngestResult::Accepted => "238 Send it\r\n",
        IngestResult::Duplicate => "438 Already have it\r\n",
        IngestResult::Rejected(_) => "438 Article not wanted\r\n",
        IngestResult::TransientError(_) => "431 Try sending it again later\r\n",
    }
}

/// Guard for the CHECK command: CHECK is only valid in streaming mode.
///
/// Returns `None` if `mode` is [`PeeringMode::Streaming`] (CHECK allowed),
/// or `Some(response)` with a 401 error line if the mode is
/// [`PeeringMode::Ihave`] (CHECK not permitted).
pub fn check_mode_guard(mode: PeeringMode) -> Option<&'static str> {
    match mode {
        PeeringMode::Streaming => None,
        PeeringMode::Ihave => Some("401 This command is only allowed in streaming mode\r\n"),
    }
}

/// Guard for the TAKETHIS command: TAKETHIS is only valid after MODE STREAM.
///
/// RFC 4644 §2.5: the server MUST NOT accept TAKETHIS unless MODE STREAM was
/// successfully negotiated.  Returns `None` if `mode` is
/// [`PeeringMode::Streaming`] (TAKETHIS allowed), or `Some(response)` with a
/// 500 error line if the mode is [`PeeringMode::Ihave`] (TAKETHIS not
/// permitted — 500 because the command is not available in this mode, not
/// merely disallowed by policy).
pub fn takethis_mode_guard(mode: PeeringMode) -> Option<&'static str> {
    match mode {
        PeeringMode::Streaming => None,
        PeeringMode::Ihave => Some("500 Command not available in current mode\r\n"),
    }
}

// ── Path: header mutation ─────────────────────────────────────────────────────

/// Prepend `<hostname>!` to the `Path:` header, creating the header if absent.
///
/// Son-of-RFC-1036 §3.3: every transit hop MUST prepend its FQDN to the
/// `Path:` header before storing or forwarding an article.
///
/// * If `Path:` is present: the new value is `<hostname>!<old-value>`.
/// * If `Path:` is absent: `Path: <hostname>\r\n` is inserted just before
///   the blank line that separates headers from body.
pub fn prepend_path_header(article_bytes: Vec<u8>, hostname: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(article_bytes.len() + hostname.len() + 10);
    let mut path_found = false;
    let mut in_body = false;

    // Pre-collect lines split on LF.  Remove the trailing empty slice that
    // `split` produces when input ends with '\n'; we must NOT skip empty slices
    // inside the body because they represent genuine blank lines.
    let raw_lines: Vec<&[u8]> = article_bytes.split(|&b| b == b'\n').collect();
    let lines = if raw_lines.last().is_some_and(|l| l.is_empty()) {
        &raw_lines[..raw_lines.len() - 1]
    } else {
        &raw_lines[..]
    };

    for line in lines {
        if in_body {
            out.extend_from_slice(line);
            out.push(b'\n');
            continue;
        }

        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };

        if trimmed.is_empty() {
            if !path_found {
                let new_path = format!("Path: {hostname}\r\n");
                out.extend_from_slice(new_path.as_bytes());
            }
            in_body = true;
            out.extend_from_slice(b"\r\n");
            continue;
        }

        let lower = String::from_utf8_lossy(trimmed).to_ascii_lowercase();
        if lower.starts_with("path:") {
            let old_val = String::from_utf8_lossy(&trimmed["path:".len()..]);
            let old_val = old_val.trim();
            let new_line = format!("Path: {hostname}!{old_val}\r\n");
            out.extend_from_slice(new_line.as_bytes());
            path_found = true;
        } else {
            out.extend_from_slice(trimmed);
            out.extend_from_slice(b"\r\n");
        }
    }

    out
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns `true` if the raw article bytes contain a header named `name`.
///
/// Scans the header section (up to the first blank line) for a line that
/// starts with `name:` (case-insensitive ASCII comparison).
fn has_header(article_bytes: &[u8], name: &str) -> bool {
    let name_lower = name.to_ascii_lowercase();
    let needle = format!("{name_lower}:");

    for line in article_bytes.split(|&b| b == b'\n') {
        // Stop at the blank line separating headers from body.
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.is_empty() {
            break;
        }
        let line_lower = String::from_utf8_lossy(line).to_ascii_lowercase();
        if line_lower.starts_with(&needle) {
            return true;
        }
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;

    async fn make_msgid_map() -> (MsgIdMap, tempfile::TempPath) {
        // Use a unique temp file per test to avoid shared-memory migration races.
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        stoa_core::migrations::run_migrations(&pool).await.unwrap();
        (MsgIdMap::new(pool), tmp)
    }

    fn valid_article(msgid: &str) -> Vec<u8> {
        format!(
            "From: sender@example.com\r\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
             Message-ID: {msgid}\r\n\
             Newsgroups: alt.test\r\n\
             Subject: Test\r\n\
             \r\n\
             Body.\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn valid_article_accepted() {
        let (map, _tmp) = make_msgid_map().await;
        let msgid = "<valid@example.com>";
        let bytes = valid_article(msgid);
        let result = check_ingest(msgid, &bytes, &map).await;
        assert_eq!(result, IngestResult::Accepted);
    }

    #[tokio::test]
    async fn duplicate_msgid_rejected() {
        use cid::Cid;
        use multihash_codetable::{Code, MultihashDigest};

        let (map, _tmp) = make_msgid_map().await;
        let msgid = "<dup@example.com>";

        // Pre-insert a CID for this Message-ID to simulate a known article.
        let cid = Cid::new_v1(0x71, Code::Sha2_256.digest(b"some-article"));
        map.insert(msgid, &cid).await.unwrap();

        let bytes = valid_article(msgid);
        let result = check_ingest(msgid, &bytes, &map).await;
        assert_eq!(result, IngestResult::Duplicate);
    }

    #[tokio::test]
    async fn oversized_article_rejected() {
        let (map, _tmp) = make_msgid_map().await;
        let msgid = "<big@example.com>";
        let big: Vec<u8> = vec![b'x'; MAX_ARTICLE_BYTES + 1];
        let result = check_ingest(msgid, &big, &map).await;
        assert!(
            matches!(result, IngestResult::Rejected(_)),
            "expected Rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn invalid_msgid_format() {
        let (map, _tmp) = make_msgid_map().await;
        let msgid = "no-angle-brackets@example.com";
        let bytes = valid_article(msgid);
        let result = check_ingest(msgid, &bytes, &map).await;
        assert!(
            matches!(result, IngestResult::Rejected(_)),
            "expected Rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn missing_from_header() {
        let (map, _tmp) = make_msgid_map().await;
        let msgid = "<nofrom@example.com>";
        let bytes = format!(
            "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
             Message-ID: {msgid}\r\n\
             Newsgroups: alt.test\r\n\
             Subject: Test\r\n\
             \r\n\
             Body.\r\n"
        )
        .into_bytes();
        let result = check_ingest(msgid, &bytes, &map).await;
        assert!(
            matches!(result, IngestResult::Rejected(ref msg) if msg.contains("From")),
            "expected Rejected with 'From', got {result:?}"
        );
    }

    #[test]
    fn ihave_response_codes() {
        assert!(ihave_response(&IngestResult::Accepted).starts_with("235"));
        assert!(ihave_response(&IngestResult::Duplicate).starts_with("435"));
        assert!(ihave_response(&IngestResult::Rejected("x".into())).starts_with("437"));
        assert!(ihave_response(&IngestResult::TransientError("x".into())).starts_with("436"));
    }

    #[test]
    fn takethis_response_codes() {
        assert!(takethis_response(&IngestResult::Accepted).starts_with("239"));
        assert!(takethis_response(&IngestResult::Duplicate).starts_with("438"));
        assert!(takethis_response(&IngestResult::Rejected("x".into())).starts_with("439"));
        assert!(takethis_response(&IngestResult::TransientError("x".into())).starts_with("431"));
    }

    #[test]
    fn check_response_codes() {
        assert!(check_response(&IngestResult::Accepted).starts_with("238"));
        assert!(check_response(&IngestResult::Duplicate).starts_with("438"));
        assert!(check_response(&IngestResult::Rejected("x".into())).starts_with("438"));
        assert!(check_response(&IngestResult::TransientError("x".into())).starts_with("431"));
    }

    #[test]
    fn check_mode_guard_streaming_allows() {
        assert!(check_mode_guard(PeeringMode::Streaming).is_none());
    }

    #[test]
    fn check_mode_guard_ihave_blocks() {
        let resp = check_mode_guard(PeeringMode::Ihave).expect("should return Some");
        assert!(resp.starts_with("401"));
    }

    #[test]
    fn takethis_mode_guard_streaming_allows() {
        assert!(takethis_mode_guard(PeeringMode::Streaming).is_none());
    }

    #[test]
    fn takethis_mode_guard_ihave_blocks_with_500() {
        let resp = takethis_mode_guard(PeeringMode::Ihave).expect("should return Some");
        assert!(
            resp.starts_with("500"),
            "RFC 4644 §2.5: TAKETHIS in IHAVE mode must return 500, got: {resp:?}"
        );
    }

    // ── prepend_path_header tests ─────────────────────────────────────────────

    #[test]
    fn path_header_existing_gets_prepended() {
        let article =
            b"From: sender@example.com\r\nPath: peer.example.com\r\nMessage-ID: <x@y>\r\n\r\nBody.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Path: local.hostname!peer.example.com\r\n"),
            "Path: must be prepended: {text:?}"
        );
        assert!(
            !text.contains("Path: peer.example.com\r\n"),
            "old standalone Path: must not remain: {text:?}"
        );
    }

    #[test]
    fn path_header_absent_gets_inserted() {
        let article = b"From: sender@example.com\r\nMessage-ID: <x@y>\r\n\r\nBody.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Path: local.hostname\r\n"),
            "Path: must be inserted: {text:?}"
        );
    }

    #[test]
    fn path_header_body_preserved() {
        let article =
            b"From: sender@example.com\r\nPath: peer.example.com\r\n\r\nHello, world!\r\nSecond line.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.ends_with("Hello, world!\r\nSecond line.\r\n"),
            "body must be unchanged: {text:?}"
        );
    }

    #[test]
    fn path_header_multi_hop_chain() {
        let article =
            b"From: sender@example.com\r\nPath: hop2.example.com!hop1.example.com\r\n\r\nBody.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Path: local.hostname!hop2.example.com!hop1.example.com\r\n"),
            "multi-hop chain must be built correctly: {text:?}"
        );
    }

    #[test]
    fn path_header_blank_body_lines_preserved_lf_only() {
        // LF-only article (non-CRLF): blank lines within the body must not be dropped.
        let article = b"From: sender@example.com\nMessage-ID: <x@y>\n\nPara one.\n\nPara two.\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Para one.\nPara two.") || text.contains("Para one.\n\nPara two."),
            "blank line between paragraphs must be preserved: {text:?}"
        );
        // Specifically: the blank line separating the two paragraphs must be present.
        assert!(
            text.contains("Para one.\n\n"),
            "blank line after Para one must be preserved: {text:?}"
        );
    }

    #[test]
    fn path_header_blank_body_lines_preserved_crlf() {
        // CRLF article: blank lines within the body must not be dropped.
        let article =
            b"From: sender@example.com\r\nMessage-ID: <x@y>\r\n\r\nPara one.\r\n\r\nPara two.\r\n";
        let result = prepend_path_header(article.to_vec(), "local.hostname");
        let text = String::from_utf8(result).unwrap();
        assert!(
            text.contains("Para one.\r\n\r\nPara two."),
            "blank line between paragraphs must be preserved in CRLF article: {text:?}"
        );
    }
}
