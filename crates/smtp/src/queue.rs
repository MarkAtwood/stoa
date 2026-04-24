use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use usenet_ipfs_core::InjectionSource;

use crate::nntp_client::{self, NntpClientConfig};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Return a unique file stem (without extension) for a new queue entry.
///
/// Format: `{nanoseconds_since_epoch}_{sequence:016x}`
fn unique_stem() -> String {
    let ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{ns}_{seq:016x}")
}

/// Metadata sidecar for a queued NNTP article.
///
/// Written as `<stem>.env` (JSON) alongside `<stem>.msg` (raw article bytes).
/// When the drain processes a `.msg` file, it reads the corresponding `.env`
/// to learn the injection source.  If no `.env` exists (e.g. queue files
/// written before this feature), the source defaults to `SmtpSieve`.
#[derive(Debug, Serialize, Deserialize)]
struct NntpEnvelope {
    #[serde(default = "usenet_ipfs_core::default_injection_source")]
    pub injection_source: InjectionSource,
}

/// Extract the value of the `Message-Id:` header from RFC 822 article bytes.
///
/// Scans the header section (up to the blank line) for a line whose field name
/// is `message-id` (case-insensitive).  Returns the bare message-id token
/// (stripped of surrounding `<>` and whitespace) if found, or an empty string
/// if not present.
fn extract_message_id(bytes: &[u8]) -> String {
    let header_end = find_header_end(bytes);
    let headers = &bytes[..header_end];

    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(rest) = strip_field_name(line, b"message-id") {
            let value = std::str::from_utf8(rest).unwrap_or("").trim();
            // Strip enclosing angle brackets if present.
            return value
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string();
        }
    }
    String::new()
}

/// Return the byte offset of the end of the header section (the blank line
/// separator), or the full length of `bytes` if no blank line is found.
fn find_header_end(bytes: &[u8]) -> usize {
    let mut i = 0;
    while i < bytes.len() {
        // Look for \r\n\r\n or \n\n
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return i + 4;
        }
        if bytes[i..].starts_with(b"\n\n") {
            return i + 2;
        }
        // Advance to next line
        while i < bytes.len() && bytes[i] != b'\n' {
            i += 1;
        }
        i += 1; // skip the '\n'
    }
    bytes.len()
}

/// If `line` starts with `field_name:` (case-insensitive), return the bytes
/// after the colon.  The field name must be followed immediately by `:`.
fn strip_field_name<'a>(line: &'a [u8], field_name: &[u8]) -> Option<&'a [u8]> {
    if line.len() <= field_name.len() {
        return None;
    }
    let prefix = &line[..field_name.len()];
    let after = &line[field_name.len()..];
    if prefix.eq_ignore_ascii_case(field_name) && after.first() == Some(&b':') {
        Some(&after[1..])
    } else {
        None
    }
}

/// Prepend an `X-Usenet-IPFS-Injection-Source:` header to `article_bytes`.
///
/// The header is prepended at the very start of the article (before all other
/// headers).  NNTP articles begin directly with headers, so this is safe.
/// The reader strips this header unconditionally and uses it for routing
/// decisions.
fn inject_source_header(article_bytes: &[u8], source: InjectionSource) -> Vec<u8> {
    let header = format!("X-Usenet-IPFS-Injection-Source: {source:?}\r\n");
    let mut result = Vec::with_capacity(header.len() + article_bytes.len());
    result.extend_from_slice(header.as_bytes());
    result.extend_from_slice(article_bytes);
    result
}

/// Durable filesystem-backed queue for outbound NNTP article delivery.
///
/// Articles are written atomically to `queue_dir` (write-to-tmp, then rename).
/// A background drain task picks them up and posts to the NNTP reader.
/// Files that fail delivery are left in place and retried on the next cycle.
/// On startup the drain task scans the directory for files left over from
/// a previous crash — no messages are lost across restarts.
pub struct NntpQueue {
    queue_dir: PathBuf,
    notify: tokio::sync::Notify,
}

impl NntpQueue {
    /// Create a new queue rooted at `queue_dir`, creating the directory if absent.
    pub fn new(queue_dir: impl Into<PathBuf>) -> std::io::Result<Arc<Self>> {
        let queue_dir = queue_dir.into();
        std::fs::create_dir_all(&queue_dir)?;
        Ok(Arc::new(Self {
            queue_dir,
            notify: tokio::sync::Notify::new(),
        }))
    }

    /// Enqueue article bytes for NNTP delivery.
    ///
    /// Writes atomically: first to a `.tmp` file, then renames to `.msg`.
    /// Also writes a `<stem>.env` JSON sidecar recording the injection source.
    /// Returns `Err` if the write fails; callers should respond with a 452
    /// transient error so the sending MTA will retry.
    pub async fn enqueue(
        &self,
        article_bytes: &[u8],
        injection_source: InjectionSource,
    ) -> std::io::Result<()> {
        let stem = unique_stem();
        let tmp_path = self.queue_dir.join(format!("{stem}.msg.tmp"));
        let dst_path = self.queue_dir.join(format!("{stem}.msg"));
        let env_path = self.queue_dir.join(format!("{stem}.env"));
        tokio::fs::write(&tmp_path, article_bytes).await?;
        tokio::fs::rename(&tmp_path, &dst_path).await?;
        let env = NntpEnvelope { injection_source };
        let env_json = serde_json::to_vec(&env).map_err(std::io::Error::other)?;
        tokio::fs::write(&env_path, &env_json).await?;
        self.notify.notify_one();
        Ok(())
    }

    /// Start the background drain task.
    ///
    /// Scans the queue directory immediately on startup (crash recovery), then
    /// wakes again on each new enqueue notification or after `retry_interval`,
    /// whichever comes first.
    pub fn start_drain(self: Arc<Self>, nntp_config: NntpClientConfig, retry_interval: Duration) {
        tokio::spawn(async move {
            loop {
                self.drain_once(&nntp_config).await;
                tokio::select! {
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(retry_interval) => {}
                }
            }
        });
    }

    async fn drain_once(&self, nntp_config: &NntpClientConfig) {
        let mut dir = match tokio::fs::read_dir(&self.queue_dir).await {
            Ok(d) => d,
            Err(e) => {
                warn!(dir = %self.queue_dir.display(), "nntp queue: read_dir failed: {e}");
                return;
            }
        };
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "msg") {
                let env_path = path.with_extension("env");
                let injection_source = match tokio::fs::read(&env_path).await {
                    Ok(env_bytes) => serde_json::from_slice::<NntpEnvelope>(&env_bytes)
                        .map(|e| e.injection_source)
                        .unwrap_or_else(|_| usenet_ipfs_core::default_injection_source()),
                    Err(_) => usenet_ipfs_core::default_injection_source(),
                };
                match tokio::fs::read(&path).await {
                    Ok(bytes) => {
                        let article = inject_source_header(&bytes, injection_source);
                        let message_id = extract_message_id(&article);
                        match nntp_client::post_article(nntp_config, &article, &message_id).await {
                            Ok(()) => {
                                if let Err(e) = tokio::fs::remove_file(&path).await {
                                    warn!(
                                        path = %path.display(),
                                        "nntp queue: failed to remove delivered file: {e}"
                                    );
                                } else {
                                    let _ = tokio::fs::remove_file(&env_path).await;
                                    info!("nntp queue: article delivered");
                                }
                            }
                            Err(e) => {
                                warn!(
                                    path = %path.display(),
                                    "nntp queue: delivery failed, will retry: {e}"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(path = %path.display(), "nntp queue: failed to read file: {e}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use usenet_ipfs_core::InjectionSource;

    #[tokio::test]
    async fn enqueue_creates_msg_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path()).expect("NntpQueue::new");
        queue
            .enqueue(b"article bytes", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue");

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .collect();
        assert_eq!(files.len(), 1, "expected exactly one .msg file");
        let contents = std::fs::read(files[0].path()).expect("read file");
        assert_eq!(contents, b"article bytes");
    }

    #[tokio::test]
    async fn enqueue_multiple_creates_distinct_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path()).expect("NntpQueue::new");
        queue
            .enqueue(b"article one", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue 1");
        queue
            .enqueue(b"article two", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue 2");

        let count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .count();
        assert_eq!(count, 2, "expected two distinct .msg files");
    }

    #[tokio::test]
    async fn no_tmp_files_after_enqueue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path()).expect("NntpQueue::new");
        queue
            .enqueue(b"data", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue");

        let tmp_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "tmp"))
            .count();
        assert_eq!(tmp_count, 0, "no .tmp files should remain after enqueue");
    }

    #[tokio::test]
    async fn new_creates_queue_dir() {
        let parent = tempfile::tempdir().expect("tempdir");
        let queue_dir = parent.path().join("sub").join("queue");
        NntpQueue::new(&queue_dir).expect("NntpQueue::new should create dir");
        assert!(
            queue_dir.is_dir(),
            "queue_dir should exist after NntpQueue::new"
        );
    }

    // --- extract_message_id ---

    #[test]
    fn extract_message_id_present() {
        let article =
            b"From: a@b.com\r\nMessage-Id: <foo@bar.example>\r\nSubject: test\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(article), "foo@bar.example");
    }

    #[test]
    fn extract_message_id_case_insensitive() {
        let article = b"message-id: <lower@case.test>\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(article), "lower@case.test");
    }

    #[test]
    fn extract_message_id_missing() {
        let article = b"From: a@b.com\r\nSubject: no mid\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(article), "");
    }

    #[test]
    fn extract_message_id_no_angle_brackets() {
        let article = b"Message-Id: plain@id.test\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(article), "plain@id.test");
    }
}
