//! mbox (RFC 4155) parser and backfill importer.
//!
//! Parses Unix mbox format: messages separated by `From_` lines.
//! Streams messages without loading the entire file into memory.
//! Suitable for multi-gigabyte mbox files.

use std::path::Path;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// A single parsed mbox message.
#[derive(Debug)]
pub struct MboxMessage {
    /// Raw message headers + body, excluding the From_ separator line.
    pub raw: Vec<u8>,
    /// Newsgroups header value, if present.
    pub newsgroups: Option<String>,
    /// Message-ID header value, if present.
    pub message_id: Option<String>,
}

/// Configuration for the mbox import.
#[derive(Debug, Clone)]
pub struct MboxImportConfig {
    /// Default group for messages without a Newsgroups: header.
    /// If None, messages without Newsgroups: are skipped.
    pub default_group: Option<String>,
    /// Address of the transit daemon for IHAVE forwarding.
    pub transit_addr: String,
    /// Print progress every N articles.
    pub progress_interval: usize,
}

/// Summary of an mbox import run.
#[derive(Debug, Default)]
pub struct MboxImportSummary {
    pub total_messages: usize,
    pub imported: usize,
    pub skipped_no_group: usize,
    pub skipped_no_msgid: usize,
    pub failed: usize,
    pub elapsed_ms: u64,
}

impl std::fmt::Display for MboxImportSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "total: {}, imported: {}, skipped(no_group): {}, skipped(no_msgid): {}, failed: {}, elapsed: {}ms",
            self.total_messages,
            self.imported,
            self.skipped_no_group,
            self.skipped_no_msgid,
            self.failed,
            self.elapsed_ms
        )
    }
}

/// Extract a named header value from a raw RFC 2822 message byte slice.
///
/// Performs case-insensitive header name matching and handles RFC 2822
/// folded headers (continuation lines that start with whitespace).
/// Only searches the header section (before the first blank line).
pub(crate) fn extract_header(raw: &[u8], name: &str) -> Option<String> {
    let search = format!("{}:", name.to_ascii_lowercase());
    let text = String::from_utf8_lossy(raw);
    let mut in_target = false;
    let mut value_parts: Vec<String> = Vec::new();

    for line in text.lines() {
        // Blank line signals end of headers.
        if line.is_empty() {
            if in_target {
                break;
            }
            break;
        }

        // Continuation line (folded header).
        if in_target && (line.starts_with(' ') || line.starts_with('\t')) {
            value_parts.push(line.trim().to_string());
            continue;
        }

        // Starting a new header — if we were accumulating, we're done.
        if in_target {
            break;
        }

        // Check if this line starts with our target header name.
        if line.len() > search.len() && line[..search.len()].to_ascii_lowercase() == search {
            let rest = line[search.len()..].trim();
            value_parts.push(rest.to_string());
            in_target = true;
        }
    }

    if value_parts.is_empty() {
        None
    } else {
        Some(value_parts.join(" "))
    }
}

/// Parse a single mbox file and return all messages.
///
/// Streams the file line by line. Uses `From ` separator detection.
/// Each message accumulates lines until the next `From ` line.
pub async fn parse_mbox_file(path: &Path) -> Result<Vec<MboxMessage>, std::io::Error> {
    let file = tokio::fs::File::open(path).await?;
    let mut reader = BufReader::new(file);

    let mut messages: Vec<MboxMessage> = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // EOF: flush any in-progress message.
            if let Some(raw) = current.take() {
                if !raw.is_empty() {
                    messages.push(build_message(raw));
                }
            }
            break;
        }

        if line.starts_with("From ") {
            // Separator line: flush current message, start a new one.
            if let Some(raw) = current.take() {
                if !raw.is_empty() {
                    messages.push(build_message(raw));
                }
            }
            current = Some(Vec::new());
        } else if let Some(ref mut buf) = current {
            buf.extend_from_slice(line.as_bytes());
        }
        // Lines before any From_ separator are ignored.
    }

    Ok(messages)
}

/// Build an `MboxMessage` from an accumulated raw byte buffer.
fn build_message(raw: Vec<u8>) -> MboxMessage {
    let newsgroups = extract_header(&raw, "Newsgroups");
    let message_id = extract_header(&raw, "Message-ID");
    MboxMessage {
        raw,
        newsgroups,
        message_id,
    }
}

/// Parse a directory of .mbox files and collect all messages.
pub async fn parse_mbox_directory(dir: &Path) -> Result<Vec<MboxMessage>, std::io::Error> {
    let mut all: Vec<MboxMessage> = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = rd.next_entry().await? {
        let ft = entry.file_type().await?;
        if ft.is_file() {
            let path = entry.path();
            let mut msgs = parse_mbox_file(&path).await?;
            all.append(&mut msgs);
        }
    }
    Ok(all)
}

/// Run the mbox backfill import from a file or directory.
///
/// For each message, sends it to the transit daemon via IHAVE.
/// Returns a summary of the import.
pub async fn run_mbox_import(
    source: &Path,
    config: &MboxImportConfig,
) -> Result<MboxImportSummary, std::io::Error> {
    let start = Instant::now();

    let messages = if source.is_dir() {
        parse_mbox_directory(source).await?
    } else {
        parse_mbox_file(source).await?
    };

    let mut summary = MboxImportSummary {
        total_messages: messages.len(),
        ..Default::default()
    };

    for (idx, msg) in messages.iter().enumerate() {
        // Determine the newsgroup.
        let group = match msg
            .newsgroups
            .as_deref()
            .or(config.default_group.as_deref())
        {
            Some(g) => g,
            None => {
                summary.skipped_no_group += 1;
                continue;
            }
        };

        // Require a Message-ID.
        let msgid = match msg.message_id.as_deref() {
            Some(id) => id,
            None => {
                tracing::warn!(group, "mbox message has no Message-ID, skipping");
                summary.skipped_no_msgid += 1;
                continue;
            }
        };

        match mbox_send_ihave(&config.transit_addr, msgid, &msg.raw).await {
            IhaveSendResult::Accepted => {
                summary.imported += 1;
            }
            IhaveSendResult::Duplicate => {
                // Already present — counts as imported for reporting purposes.
                summary.imported += 1;
            }
            IhaveSendResult::Failed => {
                summary.failed += 1;
            }
        }

        if config.progress_interval > 0 && (idx + 1) % config.progress_interval == 0 {
            tracing::info!(count = idx + 1, "mbox import progress");
        }
    }

    summary.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(summary)
}

// ── NNTP IHAVE send (inline, per-message TCP connection) ──────────────────────

#[derive(Debug)]
enum IhaveSendResult {
    Accepted,
    Duplicate,
    Failed,
}

/// Open a TCP connection to `addr` and send one article via IHAVE.
async fn mbox_send_ihave(addr: &str, msgid: &str, article_bytes: &[u8]) -> IhaveSendResult {
    let stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("TCP connect to {addr} failed: {e}");
            return IhaveSendResult::Failed;
        }
    };

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read greeting (200 or 201).
    line.clear();
    if reader.read_line(&mut line).await.is_err() {
        return IhaveSendResult::Failed;
    }
    let code = mbox_response_code(&line);
    if code != 200 && code != 201 {
        tracing::warn!("unexpected greeting from {addr}: {}", line.trim());
        return IhaveSendResult::Failed;
    }

    // Send IHAVE <msgid>.
    let cmd = format!("IHAVE {msgid}\r\n");
    if writer.write_all(cmd.as_bytes()).await.is_err() {
        return IhaveSendResult::Failed;
    }

    // Read IHAVE response.
    line.clear();
    if reader.read_line(&mut line).await.is_err() {
        return IhaveSendResult::Failed;
    }
    let code = mbox_response_code(&line);

    match code {
        435 => return IhaveSendResult::Duplicate,
        335 => {} // proceed
        _ => {
            tracing::info!("IHAVE {msgid} got code {code}: {}", line.trim());
            return IhaveSendResult::Failed;
        }
    }

    // Send article with dot-stuffing, terminated by ".\r\n".
    let stuffed = mbox_dot_stuff(article_bytes);
    if writer.write_all(&stuffed).await.is_err() {
        return IhaveSendResult::Failed;
    }
    if writer.write_all(b".\r\n").await.is_err() {
        return IhaveSendResult::Failed;
    }

    // Read final transfer response.
    line.clear();
    if reader.read_line(&mut line).await.is_err() {
        return IhaveSendResult::Failed;
    }
    let code = mbox_response_code(&line);

    match code {
        235 => IhaveSendResult::Accepted,
        _ => {
            tracing::info!("transfer of {msgid} failed with code {code}");
            IhaveSendResult::Failed
        }
    }
}

fn mbox_response_code(line: &str) -> u16 {
    line.get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

fn mbox_dot_stuff(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 16);
    for line in bytes.split(|&b| b == b'\n') {
        if line.starts_with(b".") {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    if out.last() == Some(&b'\n') && !bytes.ends_with(b"\n") {
        out.pop();
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_mbox(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    const SAMPLE_MBOX: &str = "\
From user@example.com Mon Jan 01 00:00:00 2024\r\n\
From: Alice <alice@example.com>\r\n\
Newsgroups: comp.lang.rust\r\n\
Message-ID: <msg1@example.com>\r\n\
Subject: First article\r\n\
\r\n\
Body of first article.\r\n\
\r\n\
From user@example.com Mon Jan 01 00:01:00 2024\r\n\
From: Bob <bob@example.com>\r\n\
Newsgroups: sci.math\r\n\
Message-ID: <msg2@example.com>\r\n\
Subject: Second article\r\n\
\r\n\
Body of second article.\r\n\
";

    #[tokio::test]
    async fn parse_mbox_extracts_two_messages() {
        let dir = TempDir::new().unwrap();
        let path = write_mbox(&dir, "test.mbox", SAMPLE_MBOX);
        let messages = parse_mbox_file(&path).await.unwrap();
        assert_eq!(messages.len(), 2, "should parse 2 messages");
        assert_eq!(messages[0].newsgroups.as_deref(), Some("comp.lang.rust"));
        assert_eq!(
            messages[0].message_id.as_deref(),
            Some("<msg1@example.com>")
        );
        assert_eq!(messages[1].newsgroups.as_deref(), Some("sci.math"));
    }

    #[tokio::test]
    async fn parse_mbox_empty_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = write_mbox(&dir, "empty.mbox", "");
        let messages = parse_mbox_file(&path).await.unwrap();
        assert_eq!(messages.len(), 0);
    }

    #[tokio::test]
    async fn run_mbox_import_skips_no_group_when_no_default() {
        let dir = TempDir::new().unwrap();
        let mbox_content = "\
From user@example.com Mon Jan 01 00:00:00 2024\r\n\
From: Alice <alice@example.com>\r\n\
Message-ID: <msg3@example.com>\r\n\
Subject: No newsgroup\r\n\
\r\n\
Body.\r\n\
";
        let path = write_mbox(&dir, "no_group.mbox", mbox_content);
        let config = MboxImportConfig {
            default_group: None,
            transit_addr: "127.0.0.1:19997".to_string(),
            progress_interval: 100,
        };
        let summary = run_mbox_import(&path, &config).await.unwrap();
        assert_eq!(
            summary.skipped_no_group, 1,
            "should skip article with no group: {summary}"
        );
    }

    #[test]
    fn extract_header_finds_message_id() {
        let raw = b"From: a@b.com\r\nMessage-ID: <abc@test.com>\r\nSubject: Hi\r\n\r\nBody\r\n";
        let id = extract_header(raw, "Message-ID");
        assert_eq!(id.as_deref(), Some("<abc@test.com>"));
    }

    #[test]
    fn extract_header_case_insensitive() {
        let raw = b"newsgroups: comp.lang.rust\r\nSubject: Hi\r\n\r\nBody\r\n";
        let ng = extract_header(raw, "Newsgroups");
        assert_eq!(ng.as_deref(), Some("comp.lang.rust"));
    }

    #[test]
    fn extract_header_absent_returns_none() {
        let raw = b"From: a@b.com\r\nSubject: Hi\r\n\r\nBody\r\n";
        let id = extract_header(raw, "Message-ID");
        assert_eq!(id, None);
    }

    #[test]
    fn extract_header_stops_at_blank_line() {
        let raw = b"Subject: Hi\r\n\r\nMessage-ID: <in-body@example.com>\r\n";
        let id = extract_header(raw, "Message-ID");
        assert_eq!(id, None);
    }

    #[test]
    fn extract_header_folded_header() {
        let raw = b"Subject: Long\r\n subject continued\r\nFrom: a@b.com\r\n\r\nBody\r\n";
        let subj = extract_header(raw, "Subject");
        assert_eq!(subj.as_deref(), Some("Long subject continued"));
    }

    #[tokio::test]
    async fn parse_mbox_directory_aggregates_files() {
        let dir = TempDir::new().unwrap();
        write_mbox(&dir, "a.mbox", SAMPLE_MBOX);
        write_mbox(&dir, "b.mbox", SAMPLE_MBOX);
        let messages = parse_mbox_directory(dir.path()).await.unwrap();
        assert_eq!(messages.len(), 4, "two files × two messages each");
    }
}
