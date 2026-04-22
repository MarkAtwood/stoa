use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use tracing::{info, warn};

use crate::nntp_client;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_name() -> String {
    let ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{ns}_{seq:016x}.msg")
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
    /// Returns `Err` if the write fails; callers should respond with a 452
    /// transient error so the sending MTA will retry.
    pub async fn enqueue(&self, article_bytes: &[u8]) -> std::io::Result<()> {
        let name = unique_name();
        let tmp_path = self.queue_dir.join(format!("{name}.tmp"));
        let dst_path = self.queue_dir.join(&name);
        tokio::fs::write(&tmp_path, article_bytes).await?;
        tokio::fs::rename(&tmp_path, &dst_path).await?;
        self.notify.notify_one();
        Ok(())
    }

    /// Start the background drain task.
    ///
    /// Scans the queue directory immediately on startup (crash recovery), then
    /// wakes again on each new enqueue notification or after `retry_interval`,
    /// whichever comes first.
    pub fn start_drain(self: Arc<Self>, nntp_addr: String, retry_interval: Duration) {
        tokio::spawn(async move {
            loop {
                self.drain_once(&nntp_addr).await;
                tokio::select! {
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(retry_interval) => {}
                }
            }
        });
    }

    async fn drain_once(&self, nntp_addr: &str) {
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
                match tokio::fs::read(&path).await {
                    Ok(bytes) => {
                        match nntp_client::post_article(nntp_addr, &bytes).await {
                            Ok(()) => {
                                if let Err(e) = tokio::fs::remove_file(&path).await {
                                    warn!(
                                        path = %path.display(),
                                        "nntp queue: failed to remove delivered file: {e}"
                                    );
                                } else {
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

    #[tokio::test]
    async fn enqueue_creates_msg_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = NntpQueue::new(dir.path()).expect("NntpQueue::new");
        queue.enqueue(b"article bytes").await.expect("enqueue");

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
        queue.enqueue(b"article one").await.expect("enqueue 1");
        queue.enqueue(b"article two").await.expect("enqueue 2");

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
        queue.enqueue(b"data").await.expect("enqueue");

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
        assert!(queue_dir.is_dir(), "queue_dir should exist after NntpQueue::new");
    }
}
