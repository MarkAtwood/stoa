use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime};

use tracing::{info, warn};

use crate::config::SmtpRelayPeerConfig;
use crate::relay_client::{deliver_via_relay, RelayEnvelope};
use crate::relay_health::PeerHealthState;

// Seeded once at startup with the current time in nanoseconds so IDs sort
// chronologically across restarts. After startup the counter only advances;
// NTP clock regressions during operation have no effect on uniqueness.
static SEQ: LazyLock<AtomicU64> = LazyLock::new(|| {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    AtomicU64::new(seed)
});

fn unique_id() -> String {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{seq:020}")
}

/// JSON envelope stored alongside each queued article.
#[derive(serde::Serialize, serde::Deserialize)]
struct EnvelopeFile {
    mail_from: String,
    rcpt_to: Vec<String>,
}

/// Durable filesystem-backed queue for outbound SMTP relay delivery.
///
/// Each queued message is stored as two files written atomically (write-to-tmp,
/// then rename):
/// - `{id}.msg`  — raw article bytes
/// - `{id}.env`  — JSON envelope `{ "mail_from": "...", "rcpt_to": [...] }`
///
/// The drain loop picks `.env` files in FIFO order, selects a healthy peer
/// via [`PeerHealthState`], and calls [`deliver_via_relay`].
///
/// - Transient failure: files remain for retry; peer is marked down.
/// - Permanent failure: files are moved to `dead/` subdirectory; peer is marked down.
/// - No eligible peers: log warning and leave files for the next cycle.
///
/// On startup the drain loop scans the queue directory for files left from a
/// previous crash — no messages are lost across restarts.
pub struct SmtpRelayQueue {
    queue_dir: PathBuf,
    notify: tokio::sync::Notify,
    health: Arc<Mutex<PeerHealthState>>,
    peers: Vec<SmtpRelayPeerConfig>,
}

impl SmtpRelayQueue {
    /// Create a new queue rooted at `queue_dir`, creating the directory and the
    /// `dead/` subdirectory if they are absent.
    ///
    /// `down_backoff` controls how long a peer stays in the down state before
    /// being retried by [`PeerHealthState::select_peer`].
    pub fn new(
        queue_dir: impl Into<PathBuf>,
        peers: Vec<SmtpRelayPeerConfig>,
        down_backoff: Duration,
    ) -> std::io::Result<Arc<Self>> {
        let queue_dir = queue_dir.into();
        std::fs::create_dir_all(&queue_dir)?;
        std::fs::create_dir_all(queue_dir.join("dead"))?;

        // Validate that both directories are writable at startup.
        let sentinel = queue_dir.join(".write_test");
        std::fs::write(&sentinel, b"").map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("relay queue dir {:?} is not writable: {e}", queue_dir),
            )
        })?;
        let _ = std::fs::remove_file(&sentinel);

        let dead_sentinel = queue_dir.join("dead").join(".write_test");
        std::fs::write(&dead_sentinel, b"").map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "relay queue dead-letter dir {:?} is not writable: {e}",
                    queue_dir.join("dead")
                ),
            )
        })?;
        let _ = std::fs::remove_file(&dead_sentinel);

        let health = Arc::new(Mutex::new(PeerHealthState::new(
            peers.clone(),
            down_backoff,
        )));
        Ok(Arc::new(Self {
            queue_dir,
            notify: tokio::sync::Notify::new(),
            health,
            peers,
        }))
    }

    /// Enqueue article bytes for SMTP relay delivery.
    ///
    /// If no peers are configured, or if `rcpt_to` is empty, returns `Ok(())`
    /// immediately without writing any files.
    ///
    /// Write order is load-bearing for crash safety: `.msg` is renamed before
    /// `.env`.  The drain scans for `.env` files and reads the paired `.msg`;
    /// if `.env` is absent, the drain skips the entry.
    ///
    /// Crash between the two renames: `.msg` exists, `.env` does not.  The
    /// drain skips this `.msg` (no `.env` partner) and the file is retried on
    /// the next startup scan.  No orphaned data accumulates indefinitely.
    ///
    /// If the order were reversed (`.env` first), a crash would leave a `.env`
    /// without its `.msg`, causing the drain to read a non-existent payload.
    ///
    /// Returns `Err` only if the filesystem write fails.
    pub async fn enqueue(
        &self,
        article_bytes: &[u8],
        mail_from: &str,
        rcpt_to: &[&str],
    ) -> std::io::Result<()> {
        if self.peers.is_empty() || rcpt_to.is_empty() {
            return Ok(());
        }

        let id = unique_id();

        // Write article bytes atomically.
        let msg_tmp = self.queue_dir.join(format!("{id}.msg.tmp"));
        let msg_dst = self.queue_dir.join(format!("{id}.msg"));
        tokio::fs::write(&msg_tmp, article_bytes).await?;
        tokio::fs::rename(&msg_tmp, &msg_dst).await?;

        // Write envelope atomically.
        let env = EnvelopeFile {
            mail_from: mail_from.to_string(),
            rcpt_to: rcpt_to.iter().map(|s| s.to_string()).collect(),
        };
        let env_bytes = serde_json::to_vec(&env)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let env_tmp = self.queue_dir.join(format!("{id}.env.tmp"));
        let env_dst = self.queue_dir.join(format!("{id}.env"));
        tokio::fs::write(&env_tmp, &env_bytes).await?;
        tokio::fs::rename(&env_tmp, &env_dst).await?;

        self.notify.notify_one();
        Ok(())
    }

    /// Start the background drain task.
    ///
    /// Scans the queue directory immediately on startup (crash recovery), then
    /// wakes again on each new enqueue notification or after `retry_interval`,
    /// whichever comes first.
    pub fn start_drain(self: Arc<Self>, retry_interval: Duration) {
        tokio::spawn(async move {
            loop {
                self.drain_once().await;
                tokio::select! {
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(retry_interval) => {}
                }
            }
        });
    }

    /// Expose the peer health state for metrics collection.
    pub fn health(&self) -> &Arc<Mutex<PeerHealthState>> {
        &self.health
    }

    /// Trigger one drain pass synchronously.
    ///
    /// This exists solely for integration tests that need to drive the queue
    /// without the background task. Not intended for production use.
    #[doc(hidden)]
    pub async fn drain_once_for_test(&self) {
        self.drain_once().await;
    }

    async fn drain_once(&self) {
        let mut env_files: Vec<PathBuf> = Vec::new();

        let mut dir = match tokio::fs::read_dir(&self.queue_dir).await {
            Ok(d) => d,
            Err(e) => {
                warn!(dir = %self.queue_dir.display(), "relay queue: read_dir failed: {e}");
                return;
            }
        };

        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "env") {
                env_files.push(path);
            }
        }

        // Sort by filename for FIFO order (timestamp-prefixed names sort chronologically).
        env_files.sort();

        crate::metrics::set_relay_queue_depth(env_files.len() as f64);

        let dead_dir = self.queue_dir.join("dead");
        if let Ok(mut rd) = tokio::fs::read_dir(&dead_dir).await {
            let mut dead_count: f64 = 0.0;
            while let Ok(Some(entry)) = rd.next_entry().await {
                if entry.path().extension().is_some_and(|e| e == "env") {
                    dead_count += 1.0;
                }
            }
            crate::metrics::set_relay_dead_letter_depth(dead_count);
        }

        for env_path in env_files {
            let stem = match env_path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let msg_path = self.queue_dir.join(format!("{stem}.msg"));

            let env_bytes = match tokio::fs::read(&env_path).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(path = %env_path.display(), "relay queue: failed to read .env file: {e}");
                    continue;
                }
            };
            let envelope: EnvelopeFile = match serde_json::from_slice(&env_bytes) {
                Ok(e) => e,
                Err(e) => {
                    warn!(path = %env_path.display(), "relay queue: failed to parse .env JSON: {e}");
                    continue;
                }
            };

            let article_bytes = match tokio::fs::read(&msg_path).await {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // .msg is missing; .env may be a leftover — skip both.
                    warn!(path = %msg_path.display(), "relay queue: .msg file missing, skipping");
                    continue;
                }
                Err(e) => {
                    warn!(path = %msg_path.display(), "relay queue: failed to read .msg file: {e}");
                    continue;
                }
            };

            self.try_deliver_one(&env_path, &msg_path, &envelope, &article_bytes)
                .await;
        }
    }

    async fn try_deliver_one(
        &self,
        env_path: &std::path::Path,
        msg_path: &std::path::Path,
        envelope: &EnvelopeFile,
        article_bytes: &[u8],
    ) {
        // Select peer and record attempt atomically — hold lock briefly, drop before async call.
        let (idx, peer_cfg) = {
            let mut health = self.health.lock().expect("health lock");
            match health.select_peer() {
                Some((idx, cfg)) => {
                    let cfg = cfg.clone();
                    (idx, cfg)
                }
                None => {
                    warn!("relay queue: no eligible relay peers, deferring delivery");
                    return;
                }
            }
        };

        let relay_envelope = RelayEnvelope {
            mail_from: envelope.mail_from.clone(),
            rcpt_to: envelope.rcpt_to.clone(),
        };

        crate::metrics::inc_relay_attempt(&peer_cfg.host);

        match deliver_via_relay(&peer_cfg, &relay_envelope, article_bytes).await {
            Ok(()) => {
                self.health.lock().expect("health lock").mark_up(idx);
                crate::metrics::inc_relay_success(&peer_cfg.host);
                crate::metrics::set_relay_peer_up(&peer_cfg.host, true);
                // Remove both files; log warnings on failure but do not abort.
                for path in [env_path, msg_path] {
                    if let Err(e) = tokio::fs::remove_file(path).await {
                        warn!(
                            path = %path.display(),
                            "relay queue: failed to remove delivered file: {e}"
                        );
                    }
                }
                info!(peer = %peer_cfg.host_port(), "relay queue: article delivered");
            }
            Err(e) if e.is_transient() => {
                self.health.lock().expect("health lock").mark_down(idx);
                crate::metrics::inc_relay_failure(&peer_cfg.host, "transient");
                crate::metrics::set_relay_peer_up(&peer_cfg.host, false);
                warn!(
                    peer = %peer_cfg.host_port(),
                    "relay queue: transient delivery failure, will retry: {e}"
                );
            }
            Err(e) => {
                // Permanent failure: move to dead/ to prevent infinite retry.
                self.health.lock().expect("health lock").mark_down(idx);
                crate::metrics::inc_relay_failure(&peer_cfg.host, "permanent");
                crate::metrics::set_relay_peer_up(&peer_cfg.host, false);
                warn!(
                    peer = %peer_cfg.host_port(),
                    "relay queue: permanent delivery failure, moving to dead/: {e}"
                );
                let dead_dir = self.queue_dir.join("dead");
                for path in [env_path, msg_path] {
                    if let Some(name) = path.file_name() {
                        let dead_path = dead_dir.join(name);
                        if let Err(mv_err) = tokio::fs::rename(path, &dead_path).await {
                            warn!(
                                path = %path.display(),
                                dead = %dead_path.display(),
                                "relay queue: failed to move file to dead/: {mv_err}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SmtpRelayPeerConfig;
    use std::time::Duration;

    fn make_peer(host: &str) -> SmtpRelayPeerConfig {
        SmtpRelayPeerConfig {
            host: host.to_string(),
            port: 587,
            tls: false,
            username: None,
            password: None,
        }
    }

    #[tokio::test]
    async fn enqueue_no_peers_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(dir.path().to_path_buf(), vec![], Duration::from_secs(300))
            .expect("new");

        queue
            .enqueue(b"article", "from@example.com", &["to@example.com"])
            .await
            .expect("enqueue");

        // Only the dead/ subdirectory should exist; no .env or .msg files.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries.len() <= 1,
            "expected at most dead/ dir, got {} entries",
            entries.len()
        );
    }

    #[tokio::test]
    async fn enqueue_creates_env_and_msg_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![make_peer("smtp.example.com")],
            Duration::from_secs(300),
        )
        .expect("new");

        queue
            .enqueue(b"article bytes", "from@example.com", &["to@example.com"])
            .await
            .expect("enqueue");

        let mut env_count = 0usize;
        let mut msg_count = 0usize;
        for entry in std::fs::read_dir(dir.path()).expect("read_dir") {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".env") {
                env_count += 1;
            }
            if name.ends_with(".msg") {
                msg_count += 1;
            }
        }
        assert_eq!(env_count, 1, "expected 1 .env file");
        assert_eq!(msg_count, 1, "expected 1 .msg file");
    }

    #[tokio::test]
    async fn no_tmp_files_after_enqueue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![make_peer("smtp.example.com")],
            Duration::from_secs(300),
        )
        .expect("new");

        queue
            .enqueue(b"data", "from@example.com", &["to@example.com"])
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
    async fn new_creates_queue_dir_and_dead_subdir() {
        let parent = tempfile::tempdir().expect("tempdir");
        let queue_dir = parent.path().join("sub").join("relay-queue");
        SmtpRelayQueue::new(queue_dir.clone(), vec![], Duration::from_secs(300))
            .expect("new should create dirs");
        assert!(queue_dir.is_dir(), "queue_dir should exist");
        assert!(queue_dir.join("dead").is_dir(), "dead/ subdir should exist");
    }

    #[tokio::test]
    async fn env_file_contains_correct_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![make_peer("smtp.example.com")],
            Duration::from_secs(300),
        )
        .expect("new");

        queue
            .enqueue(
                b"article bytes",
                "sender@example.com",
                &["rcpt1@example.com", "rcpt2@example.com"],
            )
            .await
            .expect("enqueue");

        let env_file = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .find(|e| e.path().extension().map_or(false, |x| x == "env"))
            .expect("env file should exist");

        let contents = std::fs::read(env_file.path()).expect("read env file");
        let parsed: EnvelopeFile = serde_json::from_slice(&contents).expect("parse JSON");
        assert_eq!(parsed.mail_from, "sender@example.com");
        assert_eq!(
            parsed.rcpt_to,
            vec!["rcpt1@example.com", "rcpt2@example.com"]
        );
    }

    #[tokio::test]
    async fn enqueue_multiple_creates_distinct_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![make_peer("smtp.example.com")],
            Duration::from_secs(300),
        )
        .expect("new");

        queue
            .enqueue(b"article one", "from@example.com", &["to@example.com"])
            .await
            .expect("enqueue 1");
        queue
            .enqueue(b"article two", "from@example.com", &["to@example.com"])
            .await
            .expect("enqueue 2");

        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "env"))
            .count();
        let msg_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .count();
        assert_eq!(env_count, 2, "expected 2 .env files");
        assert_eq!(msg_count, 2, "expected 2 .msg files");
    }

    // Oracle: filesystem permission semantics — creating a queue rooted in a
    // read-only directory must produce an Err, not silently succeed.
    #[cfg(unix)]
    #[test]
    fn new_fails_when_queue_dir_is_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().expect("tempdir");
        let queue_dir = parent.path().join("readonly-queue");
        std::fs::create_dir_all(&queue_dir).expect("create queue dir");
        // Remove write permission from the queue dir so we cannot create files inside it.
        std::fs::set_permissions(&queue_dir, std::fs::Permissions::from_mode(0o555))
            .expect("set permissions");

        let result = SmtpRelayQueue::new(queue_dir.clone(), vec![], Duration::from_secs(300));

        // Restore write permission so tempdir cleanup can remove the directory.
        let _ = std::fs::set_permissions(&queue_dir, std::fs::Permissions::from_mode(0o755));

        assert!(
            result.is_err(),
            "new() should fail on a read-only queue dir"
        );
    }

    // Oracle: RFC 5321 §3.3 — enqueue with empty rcpt_to must be a no-op;
    // the caller has already filtered to only valid email recipients.
    #[tokio::test]
    async fn enqueue_empty_rcpt_to_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![make_peer("smtp.example.com")],
            Duration::from_secs(300),
        )
        .expect("new");

        queue
            .enqueue(b"article", "from@example.com", &[])
            .await
            .expect("enqueue with empty rcpt_to should not fail");

        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "env"))
            .count();
        assert_eq!(
            env_count, 0,
            "empty rcpt_to should be a no-op: no .env files expected"
        );
    }
}
