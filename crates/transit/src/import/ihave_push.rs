//! IHAVE bulk import: push articles to a transit daemon via NNTP IHAVE.

use std::path::Path;
use std::time::Instant;

/// Summary of a completed import run.
#[derive(Debug, Default)]
pub struct ImportSummary {
    pub total: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub duplicates: usize,
    pub malformed: usize,
    pub elapsed_ms: u64,
}

impl std::fmt::Display for ImportSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "total: {}, accepted: {}, rejected: {}, duplicates: {}, malformed: {}, elapsed: {}ms",
            self.total,
            self.accepted,
            self.rejected,
            self.duplicates,
            self.malformed,
            self.elapsed_ms
        )
    }
}

/// Configuration for the IHAVE bulk import.
#[derive(Debug, Clone)]
pub struct IhaveImportConfig {
    /// Address of the transit daemon NNTP port (e.g., "127.0.0.1:1190").
    pub addr: String,
    /// Number of concurrent connections (each sends articles serially).
    pub parallel: usize,
}

use crate::import::{connect_nntp, send_ihave_on_conn, SendResult};

/// Run the IHAVE bulk import from `article_dir`.
///
/// Reads all files in `article_dir`, sends each via IHAVE to the daemon at
/// `config.addr`. Uses `config.parallel` concurrent TCP connections.
pub async fn run_ihave_import(
    article_dir: &Path,
    config: IhaveImportConfig,
) -> Result<ImportSummary, std::io::Error> {
    let start = Instant::now();

    // Collect all file paths from the directory.
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    let mut rd = tokio::fs::read_dir(article_dir).await?;
    while let Some(entry) = rd.next_entry().await? {
        let ft = entry.file_type().await?;
        if ft.is_file() {
            paths.push(entry.path());
        }
    }

    if paths.is_empty() {
        return Ok(ImportSummary {
            elapsed_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        });
    }

    let total = paths.len();
    let parallel = config.parallel.max(1);

    // Chunk the file list into `parallel` slices; each chunk runs in one task.
    let chunk_size = total.div_ceil(parallel);
    let mut tasks = tokio::task::JoinSet::new();

    for chunk in paths.chunks(chunk_size) {
        let chunk: Vec<std::path::PathBuf> = chunk.to_vec();
        let addr = config.addr.clone();
        tasks.spawn(async move { process_chunk(chunk, addr).await });
    }

    let mut summary = ImportSummary {
        total,
        ..Default::default()
    };

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((accepted, rejected, duplicates, malformed)) => {
                summary.accepted += accepted;
                summary.rejected += rejected;
                summary.duplicates += duplicates;
                summary.malformed += malformed;
            }
            Err(e) => {
                tracing::warn!("import task panicked: {e}");
            }
        }
    }

    summary.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(summary)
}

/// Process a slice of article files over a single TCP connection.
///
/// Opens one connection to `addr` at the start of the chunk and reuses it
/// for every article.  On any I/O error the connection is re-established
/// once; if reconnection also fails the remaining articles are counted as
/// rejected.
///
/// Returns `(accepted, rejected, duplicates, malformed)`.
async fn process_chunk(
    paths: Vec<std::path::PathBuf>,
    addr: String,
) -> (usize, usize, usize, usize) {
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut duplicates = 0usize;
    let mut malformed = 0usize;

    // Establish the shared connection for this chunk.
    let mut conn = connect_nntp(&addr).await;

    for path in &paths {
        let content = match tokio::fs::read(path).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("failed to read {:?}: {e}", path);
                malformed += 1;
                continue;
            }
        };

        let content_str = match std::str::from_utf8(&content) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("non-UTF-8 article {:?}, counting as malformed", path);
                malformed += 1;
                continue;
            }
        };

        let msgid = match extract_message_id(content_str) {
            Some(id) => id,
            None => {
                tracing::warn!("no Message-ID in {:?}, counting as malformed", path);
                malformed += 1;
                continue;
            }
        };

        // If there is no live connection, try to reconnect once.
        if conn.is_none() {
            conn = connect_nntp(&addr).await;
        }

        let result = match conn.as_mut() {
            Some((reader, writer)) => send_ihave_on_conn(reader, writer, &msgid, &content).await,
            None => {
                tracing::warn!("no connection to {addr}, counting {msgid} as rejected");
                rejected += 1;
                continue;
            }
        };

        match result {
            Ok(SendResult::Accepted) => {
                tracing::debug!("accepted: {msgid}");
                accepted += 1;
            }
            Ok(SendResult::Duplicate) => {
                tracing::debug!("duplicate: {msgid}");
                duplicates += 1;
            }
            Ok(SendResult::Rejected) => {
                tracing::info!("rejected: {msgid}");
                rejected += 1;
            }
            Err(e) => {
                // I/O error on the connection; drop it so the next article
                // triggers a reconnect.
                tracing::warn!("connection error sending {msgid}: {e}; will reconnect");
                conn = None;
                rejected += 1;
            }
        }
    }

    (accepted, rejected, duplicates, malformed)
}

/// Extract the `Message-ID` header value (including angle brackets) from article text.
///
/// Searches the header section (up to the first blank line) for a
/// `Message-ID:` line and returns the `<...>` value, or `None` if absent.
pub(crate) fn extract_message_id(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.is_empty() {
            // Blank line = end of headers.
            break;
        }
        if line.get(..11).is_some_and(|h| h.eq_ignore_ascii_case("message-id:")) {
            let rest = line[11..].trim();
            if rest.starts_with('<') && rest.contains('>') {
                let end = rest.find('>').unwrap();
                return Some(rest[..=end].to_string());
            }
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_article(dir: &TempDir, name: &str, content: &str) {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn malformed_article_no_message_id_counted() {
        let dir = TempDir::new().unwrap();
        write_article(&dir, "art1.txt", "From: test@example.com\r\n\r\nBody\r\n");
        // Connect to a port that nothing is listening on (should fail per-article)
        // The import should not panic, and should count 1 malformed.
        // Use a deliberate malformed article that fails validation before TCP connect.
        let config = IhaveImportConfig {
            addr: "127.0.0.1:19999".to_string(),
            parallel: 1,
        };
        let summary = run_ihave_import(dir.path(), config).await.unwrap();
        assert_eq!(summary.malformed, 1, "malformed: {summary}");
        assert_eq!(summary.accepted, 0);
    }

    #[tokio::test]
    async fn empty_directory_returns_zero_total() {
        let dir = TempDir::new().unwrap();
        let config = IhaveImportConfig {
            addr: "127.0.0.1:19999".to_string(),
            parallel: 1,
        };
        let summary = run_ihave_import(dir.path(), config).await.unwrap();
        assert_eq!(summary.total, 0);
    }

    #[tokio::test]
    async fn message_id_extraction() {
        // Test the Message-ID extraction helper directly
        let article =
            "From: a@b.com\r\nMessage-ID: <abc123@example.com>\r\nSubject: Test\r\n\r\nBody\r\n";
        let msgid = extract_message_id(article);
        assert_eq!(msgid, Some("<abc123@example.com>".to_string()));
    }

    #[test]
    fn extract_message_id_missing() {
        let article = "From: a@b.com\r\nSubject: No ID\r\n\r\nBody\r\n";
        assert_eq!(extract_message_id(article), None);
    }

    #[test]
    fn extract_message_id_stops_at_blank_line() {
        // Message-ID in body should not be found.
        let article = "From: a@b.com\r\n\r\nMessage-ID: <in-body@example.com>\r\n";
        assert_eq!(extract_message_id(article), None);
    }

    #[test]
    fn dot_stuff_prefixes_dot_lines() {
        let input = b"Normal line\r\n.dotted line\r\nAnother\r\n";
        let output = stoa_core::util::nntp_dot_stuff(input);
        let s = std::str::from_utf8(&output).unwrap();
        assert!(
            s.contains("..dotted line"),
            "expected dot-stuffed line in: {s}"
        );
        assert!(s.contains("Normal line"), "normal line should be unchanged");
    }

    #[test]
    fn dot_stuff_no_dot_lines_unchanged_content() {
        let input = b"Line one\r\nLine two\r\n";
        let output = stoa_core::util::nntp_dot_stuff(input);
        // Content should be present; length same or +1 per dot-start line (none here).
        let s = std::str::from_utf8(&output).unwrap();
        assert!(s.contains("Line one"));
        assert!(s.contains("Line two"));
    }

    /// Regression test for 3vye.7: CRLF input must produce exactly CRLF output
    /// with no extra bare `\n` at the end.  The old implementation split on
    /// `\n` and appended `\n` to each segment, leaving the `\r` attached.
    /// For input ending with `\r\n` this produced a trailing bare `\n` via
    /// the final empty split element.
    #[test]
    fn dot_stuff_crlf_input_no_extra_newline() {
        let input = b"Line one\r\nLine two\r\n";
        let output = stoa_core::util::nntp_dot_stuff(input);
        assert_eq!(
            output,
            b"Line one\r\nLine two\r\n",
            "CRLF input must not produce a trailing bare \\n; got: {:?}",
            std::str::from_utf8(&output).unwrap_or("<non-utf8>")
        );
    }

    /// Dot-stuffing with CRLF preserves CRLF in output and stuffs correctly.
    #[test]
    fn dot_stuff_crlf_dot_line_stuffed() {
        let input = b".top\r\nregular\r\n..already-double\r\n";
        let output = stoa_core::util::nntp_dot_stuff(input);
        let s = std::str::from_utf8(&output).unwrap();
        assert!(
            s.contains("..top\r\n"),
            "first dot-line must be stuffed: {s:?}"
        );
        assert!(s.contains("regular\r\n"), "regular line unchanged: {s:?}");
        assert!(
            s.contains("...already-double\r\n"),
            "double-dot line must get one more dot: {s:?}"
        );
        assert_eq!(output.last(), Some(&b'\n'), "output must end with \\n");
        // Must not have bare \n (every \n must be preceded by \r).
        for i in 1..output.len() {
            if output[i] == b'\n' {
                assert_eq!(
                    output[i - 1],
                    b'\r',
                    "bare \\n at position {i}; output: {s:?}"
                );
            }
        }
    }

    #[test]
    fn response_code_parses_correctly() {
        assert_eq!(
            crate::import::parse_nntp_response_code("235 Article transferred OK\r\n"),
            235
        );
        assert_eq!(
            crate::import::parse_nntp_response_code("435 Duplicate\r\n"),
            435
        );
        assert_eq!(
            crate::import::parse_nntp_response_code("335 Send article\r\n"),
            335
        );
        assert_eq!(crate::import::parse_nntp_response_code(""), 0);
        assert_eq!(crate::import::parse_nntp_response_code("xy"), 0);
    }
}
