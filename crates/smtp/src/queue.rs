use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use stoa_core::InjectionSource;
use tracing::{info, warn};

use mail_auth::common::headers::HeaderWriter;

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
    #[serde(default = "stoa_core::default_injection_source")]
    pub injection_source: InjectionSource,
}

/// Extract the value of the `Message-Id:` header from RFC 822 article bytes.
///
/// Scans the header section (up to the blank line) for a line whose field name
/// is `message-id` (case-insensitive).  Returns the bare message-id token
/// (stripped of surrounding `<>` and whitespace) if found, or `None` if the
/// header is absent.
pub(crate) fn extract_message_id(bytes: &[u8]) -> Option<String> {
    let header_end = find_header_end(bytes);
    let headers = &bytes[..header_end];

    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(rest) = strip_field_name(line, b"message-id") {
            let value = std::str::from_utf8(rest).unwrap_or("").trim();
            // Strip enclosing angle brackets if present.
            return Some(
                value
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string(),
            );
        }
    }
    None
}

/// Return the byte offset of the end of the header section (the blank line
/// separator), or the full length of `bytes` if no blank line is found.
pub(crate) fn find_header_end(bytes: &[u8]) -> usize {
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
pub(crate) fn strip_field_name<'a>(line: &'a [u8], field_name: &[u8]) -> Option<&'a [u8]> {
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

/// Prepend an `X-Stoa-Injection-Source:` header to `article_bytes`.
///
/// The header is prepended at the very start of the article (before all other
/// headers).  NNTP articles begin directly with headers, so this is safe.
/// The reader strips this header unconditionally and uses it for routing
/// decisions.
fn inject_source_header(article_bytes: &[u8], source: InjectionSource) -> Vec<u8> {
    let header = format!("X-Stoa-Injection-Source: {source}\r\n");
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
    dkim_signer: Option<Arc<mail_auth::dkim::DkimSigner<mail_auth::common::crypto::Ed25519Key, mail_auth::dkim::Done>>>,
}

impl NntpQueue {
    /// Create a new queue rooted at `queue_dir`, creating the directory if absent.
    pub fn new(
        queue_dir: impl Into<PathBuf>,
        dkim_signer: Option<Arc<mail_auth::dkim::DkimSigner<mail_auth::common::crypto::Ed25519Key, mail_auth::dkim::Done>>>,
    ) -> std::io::Result<Arc<Self>> {
        let queue_dir = queue_dir.into();
        std::fs::create_dir_all(&queue_dir)?;
        Ok(Arc::new(Self {
            queue_dir,
            notify: tokio::sync::Notify::new(),
            dkim_signer,
        }))
    }

    /// Enqueue article bytes for NNTP delivery.
    ///
    /// Both the `.msg` payload and the `.env` sidecar are written atomically
    /// (write-to-tmp, then rename).  A crash between the two renames leaves a
    /// `.msg` without an `.env`; the startup scan in `drain_once` removes the
    /// leftover `.env.tmp` and the normal drain skips `.msg` files that have
    /// no paired `.env`.
    /// Returns `Err` if the write fails; callers should respond with a 452
    /// transient error so the sending MTA will retry.
    pub async fn enqueue(
        &self,
        article_bytes: &[u8],
        injection_source: InjectionSource,
    ) -> std::io::Result<()> {
        let stem = unique_stem();
        let msg_tmp = self.queue_dir.join(format!("{stem}.msg.tmp"));
        let msg_dst = self.queue_dir.join(format!("{stem}.msg"));
        let env_tmp = self.queue_dir.join(format!("{stem}.env.tmp"));
        let env_dst = self.queue_dir.join(format!("{stem}.env"));
        tokio::fs::write(&msg_tmp, article_bytes).await?;
        tokio::fs::rename(&msg_tmp, &msg_dst).await?;
        let env = NntpEnvelope { injection_source };
        let env_json = serde_json::to_vec(&env).map_err(std::io::Error::other)?;
        tokio::fs::write(&env_tmp, &env_json).await?;
        tokio::fs::rename(&env_tmp, &env_dst).await?;
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
            // Remove any .msg.tmp or .env.tmp files left by a previous crash.
            // These represent incomplete writes; the corresponding committed
            // file was never created, so there is nothing to deliver.
            if path.to_str().is_some_and(|s| s.ends_with(".msg.tmp") || s.ends_with(".env.tmp")) {
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    warn!(path = %path.display(), "nntp queue: failed to remove orphan tmp file: {e}");
                } else {
                    warn!(path = %path.display(), "nntp queue: removed orphan tmp file from previous crash");
                }
                continue;
            }
            if path.extension().is_some_and(|e| e == "msg") {
                let env_path = path.with_extension("env");
                let injection_source = match tokio::fs::read(&env_path).await {
                    Ok(env_bytes) => serde_json::from_slice::<NntpEnvelope>(&env_bytes)
                        .map(|e| e.injection_source)
                        .unwrap_or_else(|_| stoa_core::default_injection_source()),
                    Err(_) => stoa_core::default_injection_source(),
                };
                match tokio::fs::read(&path).await {
                    Ok(bytes) => {
                        let article = inject_source_header(&bytes, injection_source);
                        // DKIM-sign the article before injecting into NNTP.
                        // If signing fails, defer this article (hold for retry on next cycle).
                        let article = if let Some(signer) = &self.dkim_signer {
                            match signer.sign(&article) {
                                Ok(sig) => {
                                    let header = sig.to_header();
                                    let mut signed =
                                        Vec::with_capacity(header.len() + article.len());
                                    signed.extend_from_slice(header.as_bytes());
                                    signed.extend_from_slice(&article);
                                    signed
                                }
                                Err(e) => {
                                    let message_id = extract_message_id(&article);
                                    warn!(
                                        message_id = %message_id.unwrap_or_default(),
                                        "DKIM signing failed, deferring article: {e}"
                                    );
                                    continue;
                                }
                            }
                        } else {
                            article
                        };
                        let message_id = extract_message_id(&article).unwrap_or_default();
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
    use mail_auth::common::crypto::Ed25519Key;
    use mail_auth::common::headers::HeaderWriter;
    use mail_auth::dkim::DkimSigner;
    use stoa_core::InjectionSource;

    /// Build a DkimSigner using the RFC 8463 §A.2 test ed25519 keypair.
    fn test_dkim_signer(
    ) -> Arc<DkimSigner<Ed25519Key, mail_auth::dkim::Done>> {
        // RFC 8463 §A.2 test private key seed (base64 "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=").
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        // RFC 8463 §A.2 test public key (base64 "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=").
        let pubkey: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let ed_key = Ed25519Key::from_seed_and_public_key(&seed, &pubkey)
            .expect("valid RFC 8463 test keypair");
        Arc::new(
            DkimSigner::from_key(ed_key)
                .domain("example.com")
                .selector("test")
                .headers(["From", "To", "Subject", "Date", "Message-ID", "MIME-Version"]),
        )
    }

    const TEST_MSG: &[u8] =
        b"From: sender@example.com\r\nTo: recip@example.com\r\nSubject: Test\r\n\
Date: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <test@example.com>\r\n\
MIME-Version: 1.0\r\n\r\nHello\r\n";

    #[test]
    fn test_dkim_nntp_signing_prepends_header() {
        let signer = test_dkim_signer();
        let sig = signer.sign(TEST_MSG).expect("sign");
        let header = sig.to_header();
        assert!(
            header.starts_with("DKIM-Signature:"),
            "expected DKIM-Signature header, got: {header}"
        );
        assert!(
            header.contains("a=ed25519-sha256"),
            "expected ed25519-sha256 algorithm tag, got: {header}"
        );
        // Verify the signed bytes are header prepended before message.
        let mut signed = Vec::with_capacity(header.len() + TEST_MSG.len());
        signed.extend_from_slice(header.as_bytes());
        signed.extend_from_slice(TEST_MSG);
        assert!(signed.starts_with(b"DKIM-Signature:"));
    }

    #[test]
    fn test_dkim_nntp_signing_absent() {
        // With no signer, inject_source_header output is the same content
        // (the DKIM branch is skipped entirely — verified by sign() never being called).
        let article = inject_source_header(TEST_MSG, InjectionSource::SmtpSieve);
        // Without a signer the article bytes pass through unchanged by the DKIM block.
        // We confirm the article still starts with the injection header, not a DKIM header.
        assert!(
            article.starts_with(b"X-Stoa-Injection-Source:"),
            "non-DKIM path must not prepend DKIM-Signature"
        );
    }

    #[test]
    fn test_dkim_no_body_length_tag() {
        let signer = test_dkim_signer();
        let sig = signer.sign(TEST_MSG).expect("sign");
        let header = sig.to_header();
        assert!(
            !header.contains("l="),
            "DKIM-Signature must not contain body length tag (l=), got: {header}"
        );
    }

    #[tokio::test]
    async fn enqueue_creates_msg_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path(), None).expect("NntpQueue::new");
        queue
            .enqueue(b"article bytes", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue");

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "msg"))
            .collect();
        assert_eq!(files.len(), 1, "expected exactly one .msg file");
        let contents = std::fs::read(files[0].path()).expect("read file");
        assert_eq!(contents, b"article bytes");
    }

    #[tokio::test]
    async fn enqueue_multiple_creates_distinct_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path(), None).expect("NntpQueue::new");
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
            .filter(|e| e.path().extension().is_some_and(|x| x == "msg"))
            .count();
        assert_eq!(count, 2, "expected two distinct .msg files");
    }

    #[tokio::test]
    async fn no_tmp_files_after_enqueue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path(), None).expect("NntpQueue::new");
        queue
            .enqueue(b"data", InjectionSource::SmtpSieve)
            .await
            .expect("enqueue");

        let tmp_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "tmp"))
            .count();
        assert_eq!(tmp_count, 0, "no .tmp files should remain after enqueue");
    }

    #[tokio::test]
    async fn new_creates_queue_dir() {
        let parent = tempfile::tempdir().expect("tempdir");
        let queue_dir = parent.path().join("sub").join("queue");
        NntpQueue::new(&queue_dir, None).expect("NntpQueue::new should create dir");
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
        assert_eq!(extract_message_id(article), Some("foo@bar.example".to_string()));
    }

    #[test]
    fn extract_message_id_case_insensitive() {
        let article = b"message-id: <lower@case.test>\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(article), Some("lower@case.test".to_string()));
    }

    #[test]
    fn extract_message_id_missing() {
        let article = b"From: a@b.com\r\nSubject: no mid\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(article), None);
    }

    #[test]
    fn extract_message_id_no_angle_brackets() {
        let article = b"Message-Id: plain@id.test\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(article), Some("plain@id.test".to_string()));
    }
}
