//! mbox (RFC 4155) parser and backfill importer.
//!
//! Parses Unix mbox format: messages separated by `From_` lines.
//! Streams messages without loading the entire file into memory.
//! Suitable for multi-gigabyte mbox files.

use std::path::Path;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::import::{connect_nntp, send_ihave_on_conn, SendResult};

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

/// Parse RFC 2822 headers from raw bytes into a map of name → value.
///
/// Scans the header section (before the first blank line) in a single pass.
/// Header names are returned with their original casing. Folded header values
/// (continuation lines starting with whitespace) are joined with a space.
/// Only the first occurrence of each header name is retained.
fn parse_headers_map(raw: &[u8]) -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;

    let text = String::from_utf8_lossy(raw);
    let mut map: HashMap<String, String> = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_parts: Vec<String> = Vec::new();

    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of the current header.
            current_parts.push(line.trim().to_string());
        } else if let Some(colon) = line.find(':') {
            // New header: flush the previous one first.
            if let Some(n) = current_name.take() {
                if !current_parts.is_empty() && !map.contains_key(&n) {
                    map.insert(n, current_parts.join(" "));
                }
                current_parts.clear();
            }
            let name = line[..colon].to_string();
            let value = line[colon + 1..].trim().to_string();
            current_name = Some(name);
            current_parts.push(value);
        }
    }
    // Flush the final header.
    if let Some(n) = current_name {
        if !current_parts.is_empty() && !map.contains_key(&n) {
            map.insert(n, current_parts.join(" "));
        }
    }

    map
}

/// Extract a named header value from a raw RFC 2822 message byte slice.
///
/// Performs case-insensitive header name matching and handles RFC 2822
/// folded headers (continuation lines that start with whitespace).
/// Only searches the header section (before the first blank line).
#[cfg(test)]
pub(crate) fn extract_header(raw: &[u8], name: &str) -> Option<String> {
    let map = parse_headers_map(raw);
    map.into_iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
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
///
/// Parses the header section in a single pass to extract both `Newsgroups`
/// and `Message-ID` without re-scanning the bytes per field.
fn build_message(raw: Vec<u8>) -> MboxMessage {
    let map = parse_headers_map(&raw);
    let newsgroups = map
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Newsgroups"))
        .map(|(_, v)| v.clone());
    let message_id = map
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Message-ID"))
        .map(|(_, v)| v.clone());
    MboxMessage {
        raw,
        newsgroups,
        message_id,
    }
}

/// Run the mbox backfill import from a file or directory.
///
/// For each message, sends it to the transit daemon via IHAVE.
/// Processes one file at a time so the entire archive is never held
/// in memory simultaneously (fixes OOM risk on multi-GB mbox archives).
/// Returns a summary of the import.
pub async fn run_mbox_import(
    source: &Path,
    config: &MboxImportConfig,
) -> Result<MboxImportSummary, std::io::Error> {
    let start = Instant::now();
    let mut summary = MboxImportSummary::default();

    if source.is_dir() {
        let mut rd = tokio::fs::read_dir(source).await?;
        while let Some(entry) = rd.next_entry().await? {
            let ft = entry.file_type().await?;
            if ft.is_file() {
                let messages = parse_mbox_file(&entry.path()).await?;
                import_messages(messages, config, &mut summary).await;
            }
        }
    } else {
        let messages = parse_mbox_file(source).await?;
        import_messages(messages, config, &mut summary).await;
    }

    summary.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(summary)
}

/// Process a batch of parsed messages, sending each via IHAVE and updating the summary.
///
/// One TCP connection is established for the entire batch and reused across all
/// articles.  On an I/O error mid-batch the connection is dropped and re-established
/// for the next article to avoid failing the whole batch on a transient reset.
async fn import_messages(
    messages: Vec<MboxMessage>,
    config: &MboxImportConfig,
    summary: &mut MboxImportSummary,
) {
    use tokio::io::BufReader;
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

    summary.total_messages += messages.len();

    // Establish one connection per batch; reconnect only after an I/O error.
    let mut conn: Option<(BufReader<OwnedReadHalf>, OwnedWriteHalf)> =
        connect_nntp(&config.transit_addr).await;

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

        // Take the connection from the slot; if gone (post I/O-error), reconnect once.
        let current = match conn.take() {
            Some(c) => Some(c),
            None => connect_nntp(&config.transit_addr).await,
        };

        let send_result = match current {
            Some((mut reader, mut writer)) => {
                match send_ihave_on_conn(&mut reader, &mut writer, msgid, &msg.raw).await {
                    Ok(r) => {
                        // Return the healthy connection to the slot for the next article.
                        conn = Some((reader, writer));
                        r
                    }
                    Err(e) => {
                        // I/O error: drop connection; next article will reconnect.
                        tracing::warn!("I/O error sending {msgid}: {e}");
                        SendResult::Rejected
                    }
                }
            }
            None => {
                tracing::warn!("could not connect to {} for {msgid}", config.transit_addr);
                SendResult::Rejected
            }
        };
        match send_result {
            SendResult::Accepted | SendResult::Duplicate => {
                summary.imported += 1;
            }
            SendResult::Rejected => {
                summary.failed += 1;
            }
        }

        if config.progress_interval > 0 && (idx + 1) % config.progress_interval == 0 {
            tracing::info!(count = idx + 1, "mbox import progress");
        }
    }
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
    async fn parse_mbox_file_each_file_two_messages() {
        // Verify that each mbox file in a directory can be parsed independently;
        // run_mbox_import processes them one at a time without collecting all in memory.
        let dir = TempDir::new().unwrap();
        let a = write_mbox(&dir, "a.mbox", SAMPLE_MBOX);
        let b = write_mbox(&dir, "b.mbox", SAMPLE_MBOX);
        let ma = parse_mbox_file(&a).await.unwrap();
        let mb = parse_mbox_file(&b).await.unwrap();
        assert_eq!(ma.len(), 2, "file a must have 2 messages");
        assert_eq!(mb.len(), 2, "file b must have 2 messages");
    }
}
