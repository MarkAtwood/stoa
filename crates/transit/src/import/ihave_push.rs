//! IHAVE bulk import: push articles to a transit daemon via NNTP IHAVE.

use std::path::Path;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

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

/// Result of sending a single article via IHAVE.
#[derive(Debug)]
enum SendResult {
    Accepted,
    Duplicate,
    Rejected,
}

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

/// Process a slice of article files, sending each via IHAVE.
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

        match send_ihave(&addr, &msgid, &content).await {
            SendResult::Accepted => {
                tracing::debug!("accepted: {msgid}");
                accepted += 1;
            }
            SendResult::Duplicate => {
                tracing::debug!("duplicate: {msgid}");
                duplicates += 1;
            }
            SendResult::Rejected => {
                tracing::info!("rejected: {msgid}");
                rejected += 1;
            }
        }
    }

    (accepted, rejected, duplicates, malformed)
}

/// Open a TCP connection to `addr`, read the greeting, and send one article via IHAVE.
async fn send_ihave(addr: &str, msgid: &str, article_bytes: &[u8]) -> SendResult {
    let stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("TCP connect to {addr} failed: {e}");
            return SendResult::Rejected;
        }
    };

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read greeting (200 or 201).
    line.clear();
    if reader.read_line(&mut line).await.is_err() {
        return SendResult::Rejected;
    }
    let code = response_code(&line);
    if code != 200 && code != 201 {
        tracing::warn!("unexpected greeting from {addr}: {}", line.trim());
        return SendResult::Rejected;
    }

    // Send IHAVE <msgid>.
    let ihave_cmd = format!("IHAVE {msgid}\r\n");
    if writer.write_all(ihave_cmd.as_bytes()).await.is_err() {
        return SendResult::Rejected;
    }

    // Read IHAVE response.
    line.clear();
    if reader.read_line(&mut line).await.is_err() {
        return SendResult::Rejected;
    }
    let code = response_code(&line);

    match code {
        435 => return SendResult::Duplicate,
        335 => {} // proceed to send article
        _ => {
            tracing::info!("IHAVE {msgid} got code {code}: {}", line.trim());
            return SendResult::Rejected;
        }
    }

    // Send article with dot-stuffing, terminated by ".\r\n".
    let stuffed = dot_stuff(article_bytes);
    if writer.write_all(&stuffed).await.is_err() {
        return SendResult::Rejected;
    }
    if writer.write_all(b".\r\n").await.is_err() {
        return SendResult::Rejected;
    }

    // Read final transfer response.
    line.clear();
    if reader.read_line(&mut line).await.is_err() {
        return SendResult::Rejected;
    }
    let code = response_code(&line);

    match code {
        235 => SendResult::Accepted,
        436 | 437 => {
            tracing::info!("transfer of {msgid} failed with code {code}");
            SendResult::Rejected
        }
        _ => {
            tracing::info!("unexpected final code {code} for {msgid}");
            SendResult::Rejected
        }
    }
}

/// Apply NNTP dot-stuffing: prefix any line starting with `.` with an extra `.`.
fn dot_stuff(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 16);
    for line in bytes.split(|&b| b == b'\n') {
        // Restore the newline (split removes it).
        if line.starts_with(b".") {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    // Remove the trailing extra newline added for the final (empty) split element.
    if out.last() == Some(&b'\n') && !bytes.ends_with(b"\n") {
        out.pop();
    }
    out
}

/// Parse the 3-digit NNTP response code from the start of a response line.
///
/// Returns 0 if the line is too short or the first three characters are not digits.
fn response_code(line: &str) -> u16 {
    line.get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
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
        if line.to_ascii_lowercase().starts_with("message-id:") {
            let rest = line["message-id:".len()..].trim();
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
        let article = "From: a@b.com\r\nMessage-ID: <abc123@example.com>\r\nSubject: Test\r\n\r\nBody\r\n";
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
        let output = dot_stuff(input);
        let s = std::str::from_utf8(&output).unwrap();
        assert!(s.contains("..dotted line"), "expected dot-stuffed line in: {s}");
        assert!(s.contains("Normal line"), "normal line should be unchanged");
    }

    #[test]
    fn dot_stuff_no_dot_lines_unchanged_content() {
        let input = b"Line one\r\nLine two\r\n";
        let output = dot_stuff(input);
        // Content should be present; length same or +1 per dot-start line (none here).
        let s = std::str::from_utf8(&output).unwrap();
        assert!(s.contains("Line one"));
        assert!(s.contains("Line two"));
    }

    #[test]
    fn response_code_parses_correctly() {
        assert_eq!(response_code("235 Article transferred OK\r\n"), 235);
        assert_eq!(response_code("435 Duplicate\r\n"), 435);
        assert_eq!(response_code("335 Send article\r\n"), 335);
        assert_eq!(response_code(""), 0);
        assert_eq!(response_code("xy"), 0);
    }
}
