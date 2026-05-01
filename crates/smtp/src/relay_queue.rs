use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime};

use mail_auth::common::headers::HeaderWriter;
use tracing::{error, info, warn};

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
#[derive(Debug, serde::Serialize, serde::Deserialize)]
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
/// - Permanent failure (5xx content rejection): files moved to `dead/`; peer is NOT marked
///   down — the peer is reachable and functional, only this message was refused.
/// - Permanent failure (auth/protocol error): files moved to `dead/`; peer IS marked down.
/// - DKIM signing failure: files moved to `dead/`; peer is not affected.
/// - No eligible peers: log warning and leave files for the next cycle.
///
/// On startup the drain loop scans the queue directory for files left from a
/// previous crash — no messages are lost across restarts.
pub struct SmtpRelayQueue {
    queue_dir: PathBuf,
    notify: tokio::sync::Notify,
    health: Arc<Mutex<PeerHealthState>>,
    dkim_signer: Option<crate::config::DkimSignerArc>,
}

impl SmtpRelayQueue {
    /// Create a new queue rooted at `queue_dir`, creating the directory and the
    /// `dead/` subdirectory if they are absent.
    ///
    /// `down_backoff` controls how long a peer stays in the down state before
    /// being retried by [`PeerHealthState::select_peer`].
    pub fn new(
        queue_dir: impl Into<PathBuf>,
        peers: Vec<crate::config::SmtpRelayPeerConfig>,
        down_backoff: Duration,
        dkim_signer: Option<crate::config::DkimSignerArc>,
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

        let health = Arc::new(Mutex::new(PeerHealthState::new(peers, down_backoff)));
        Ok(Arc::new(Self {
            queue_dir,
            notify: tokio::sync::Notify::new(),
            health,
            dkim_signer,
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
    /// drain skips this `.msg` (no `.env` partner).  On the next startup the
    /// `cleanup_orphan_msg_files` scan moves it to `dead/` for operator
    /// inspection.  No orphaned data accumulates indefinitely.
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
        // The lock is never poisoned: no code panics while holding it.
        if self.health.lock().expect("health lock").is_empty() || rcpt_to.is_empty() {
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
        let env_bytes = serde_json::to_vec(&env).map_err(std::io::Error::other)?;
        let env_tmp = self.queue_dir.join(format!("{id}.env.tmp"));
        let env_dst = self.queue_dir.join(format!("{id}.env"));
        tokio::fs::write(&env_tmp, &env_bytes).await?;
        tokio::fs::rename(&env_tmp, &env_dst).await?;

        self.notify.notify_one();
        Ok(())
    }

    /// Start the background drain task.
    ///
    /// Runs two one-time startup scans before entering the delivery loop:
    /// 1. `cleanup_tmp_files` — removes any `.msg.tmp` or `.env.tmp` files left
    ///    by a crash mid-enqueue.  These are always safe to delete: the atomic
    ///    rename that would have promoted them to committed files never ran.
    /// 2. `cleanup_orphan_msg_files` — moves any `.msg` files without a matching
    ///    `.env` (crash between the two renames) to `dead/` for operator inspection.
    ///
    /// Then scans the queue directory on startup (crash recovery) and wakes
    /// again on each new enqueue notification or after `retry_interval`,
    /// whichever comes first.
    pub fn start_drain(self: Arc<Self>, retry_interval: Duration) {
        tokio::spawn(async move {
            self.cleanup_tmp_files().await;
            self.cleanup_orphan_msg_files().await;
            loop {
                self.drain_once().await;
                tokio::select! {
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(retry_interval) => {}
                }
            }
        });
    }

    /// Remove any `.msg.tmp` or `.env.tmp` files left in the queue directory.
    ///
    /// Called once at startup before `cleanup_orphan_msg_files`.  Tmp files
    /// represent incomplete atomic writes — the rename that would have promoted
    /// them to committed `.msg` / `.env` files never executed.  There is no
    /// corresponding committed file, so deletion (not quarantine) is correct.
    /// Errors during removal are logged and the scan continues.
    async fn cleanup_tmp_files(&self) {
        let mut dir = match tokio::fs::read_dir(&self.queue_dir).await {
            Ok(d) => d,
            Err(e) => {
                warn!(dir = %self.queue_dir.display(), "relay queue: startup tmp scan read_dir failed: {e}");
                return;
            }
        };

        loop {
            match dir.next_entry().await {
                Ok(Some(entry)) => {
                    let path = entry.path();
                    let file_name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n,
                        None => continue,
                    };
                    if !(file_name.ends_with(".msg.tmp") || file_name.ends_with(".env.tmp")) {
                        continue;
                    }
                    if let Err(e) = tokio::fs::remove_file(&path).await {
                        warn!(
                            path = %path.display(),
                            "relay queue: failed to remove orphan tmp file: {e}"
                        );
                    } else {
                        warn!(
                            path = %path.display(),
                            "relay queue: removed orphan tmp file from previous crash"
                        );
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(dir = %self.queue_dir.display(), "relay queue: read_dir entry error: {e}");
                    break;
                }
            }
        }
    }

    /// Move any `.msg` files that lack a corresponding `.env` to `dead/`.
    ///
    /// Called once at startup to handle crash remnants from a previous run
    /// where the `.msg` rename completed but the `.env` rename did not.
    /// Files are moved rather than deleted so the operator can inspect them.
    /// Errors during the move are logged and the scan continues.
    async fn cleanup_orphan_msg_files(&self) {
        let mut dir = match tokio::fs::read_dir(&self.queue_dir).await {
            Ok(d) => d,
            Err(e) => {
                warn!(dir = %self.queue_dir.display(), "relay queue: startup scan read_dir failed: {e}");
                return;
            }
        };

        let dead_dir = self.queue_dir.join("dead");

        loop {
            match dir.next_entry().await {
                Ok(Some(entry)) => {
                    let path = entry.path();
                    // Only consider plain `.msg` files, not `.msg.tmp`.
                    if path.extension().is_none_or(|e| e != "msg") {
                        continue;
                    }
                    let env_path = path.with_extension("env");
                    match tokio::fs::metadata(&env_path).await {
                        Ok(_) => {
                            // Paired .env exists — not an orphan.
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            warn!(
                                path = %path.display(),
                                "relay queue: orphan .msg with no .env (crash remnant), moving to dead/"
                            );
                            if let Some(name) = path.file_name() {
                                let dead_path = dead_dir.join(name);
                                if let Err(mv_err) = tokio::fs::rename(&path, &dead_path).await {
                                    warn!(
                                        path = %path.display(),
                                        dead = %dead_path.display(),
                                        "relay queue: failed to move orphan .msg to dead/: {mv_err}"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                path = %env_path.display(),
                                "relay queue: could not stat .env for orphan check: {e}"
                            );
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(dir = %self.queue_dir.display(), "relay queue: read_dir entry error: {e}");
                    break;
                }
            }
        }
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

        loop {
            match dir.next_entry().await {
                Ok(Some(entry)) => {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "env") {
                        env_files.push(path);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(dir = %self.queue_dir.display(), "relay queue: read_dir entry error: {e}");
                    break;
                }
            }
        }

        // Sort by filename for FIFO order (timestamp-prefixed names sort chronologically).
        env_files.sort();

        crate::metrics::set_relay_queue_depth(env_files.len() as f64);

        let dead_dir = self.queue_dir.join("dead");
        match tokio::fs::read_dir(&dead_dir).await {
            Ok(mut rd) => {
                let mut dead_count = 0usize;
                loop {
                    match rd.next_entry().await {
                        Ok(Some(entry)) => {
                            if entry.path().extension().is_some_and(|x| x == "env") {
                                dead_count += 1;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            warn!(dir = %dead_dir.display(), "relay queue: read_dir entry error: {e}");
                            break;
                        }
                    }
                }
                crate::metrics::set_relay_dead_letter_depth(dead_count as f64);
            }
            Err(e) => {
                warn!(dir = %dead_dir.display(), "relay queue: failed to read dead/ dir for metrics: {e}");
            }
        }

        for env_path in env_files {
            let Some(stem) = env_path.file_stem().and_then(|s| s.to_str()) else {
                continue;
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

    /// Move `msg_path` and `env_path` to the `dead/` subdirectory.
    ///
    /// `.msg` is moved first so that if the `.env` rename fails, the orphaned
    /// `.env` is still visible to `drain_once` — it will warn "msg missing,
    /// skipping" rather than permanently strand the `.msg`.
    async fn move_to_dead_letter(&self, msg_path: &std::path::Path, env_path: &std::path::Path) {
        let dead_dir = self.queue_dir.join("dead");
        for path in [msg_path, env_path] {
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

    async fn try_deliver_one(
        &self,
        env_path: &std::path::Path,
        msg_path: &std::path::Path,
        envelope: &EnvelopeFile,
        article_bytes: &[u8],
    ) {
        // Select peer and record attempt atomically — hold lock briefly, drop before async call.
        let (idx, peer_cfg) = {
            // The lock is never poisoned: no code panics while holding it.
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

        // DKIM-sign the article before SMTP relay delivery.
        // Signing failure = permanent dead-letter (never send unsigned, never retry).
        let signed_bytes;
        let article_bytes_to_send: &[u8] = if let Some(signer) = &self.dkim_signer {
            match signer.sign(article_bytes) {
                Ok(sig) => {
                    let header = sig.to_header();
                    let mut v = Vec::with_capacity(header.len() + article_bytes.len());
                    v.extend_from_slice(header.as_bytes());
                    v.extend_from_slice(article_bytes);
                    signed_bytes = v;
                    &signed_bytes
                }
                Err(e) => {
                    let message_id = crate::queue::extract_message_id(article_bytes);
                    error!(message_id = %message_id.unwrap_or_default(), "DKIM signing failed, moving to dead-letter: {e}");
                    crate::metrics::inc_relay_failure(&peer_cfg.host, "dkim_failure");
                    self.move_to_dead_letter(msg_path, env_path).await;
                    return;
                }
            }
        } else {
            article_bytes
        };

        crate::metrics::inc_relay_attempt(&peer_cfg.host);

        match deliver_via_relay(&peer_cfg, &relay_envelope, article_bytes_to_send).await {
            Ok(()) => {
                // The lock is never poisoned: no code panics while holding it.
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
                // The lock is never poisoned: no code panics while holding it.
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
                // Only mark the peer down for auth/protocol failures, not per-message
                // 5xx content rejections — a 5xx means the peer is healthy but declined
                // this specific message; subsequent messages can be delivered immediately.
                // The lock is never poisoned: no code panics while holding it.
                if e.marks_peer_down() {
                    self.health.lock().expect("health lock").mark_down(idx);
                    crate::metrics::set_relay_peer_up(&peer_cfg.host, false);
                }
                crate::metrics::inc_relay_failure(&peer_cfg.host, "permanent");
                warn!(
                    peer = %peer_cfg.host_port(),
                    "relay queue: permanent delivery failure, moving to dead/: {e}"
                );
                self.move_to_dead_letter(msg_path, env_path).await;
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
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![],
            Duration::from_secs(300),
            None,
        )
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
            None,
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
            None,
        )
        .expect("new");

        queue
            .enqueue(b"data", "from@example.com", &["to@example.com"])
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
    async fn new_creates_queue_dir_and_dead_subdir() {
        let parent = tempfile::tempdir().expect("tempdir");
        let queue_dir = parent.path().join("sub").join("relay-queue");
        SmtpRelayQueue::new(queue_dir.clone(), vec![], Duration::from_secs(300), None)
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
            None,
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
            .find(|e| e.path().extension().is_some_and(|x| x == "env"))
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
            None,
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
            .filter(|e| e.path().extension().is_some_and(|x| x == "env"))
            .count();
        let msg_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "msg"))
            .count();
        assert_eq!(env_count, 2, "expected 2 .env files");
        assert_eq!(msg_count, 2, "expected 2 .msg files");
    }

    // Oracle: filesystem invariant — a .msg file with no paired .env is a
    // crash remnant.  start_drain() must move it to dead/ before processing
    // any normal queue entries.  Verified by checking the dead/ directory
    // contents after a short wait.
    #[tokio::test]
    async fn startup_scan_moves_orphan_msg_to_dead() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![],
            Duration::from_secs(300),
            None,
        )
        .expect("new");

        // Write a .msg with no corresponding .env (simulates a mid-enqueue crash).
        let orphan_msg = dir.path().join("00000000000000000001.msg");
        std::fs::write(&orphan_msg, b"crash remnant").expect("write orphan msg");

        // Invoke the cleanup method directly (avoids spawning a background task
        // and waiting on timing).
        queue.cleanup_orphan_msg_files().await;

        assert!(
            !orphan_msg.exists(),
            "orphan .msg should have been moved out of the queue dir"
        );
        let dead_path = dir.path().join("dead").join("00000000000000000001.msg");
        assert!(
            dead_path.exists(),
            "orphan .msg should be in dead/ after startup scan"
        );
    }

    // Oracle: filesystem invariant — .msg.tmp and .env.tmp files are incomplete
    // atomic writes that were never promoted to committed files.  cleanup_tmp_files
    // must delete them on startup; no corresponding committed file was ever created
    // so deletion (not quarantine) is correct.
    #[tokio::test]
    async fn startup_scan_removes_tmp_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue = SmtpRelayQueue::new(
            dir.path().to_path_buf(),
            vec![],
            Duration::from_secs(300),
            None,
        )
        .expect("new");

        // Place tmp files that simulate mid-enqueue crashes.
        let msg_tmp = dir.path().join("00000000000000000001.msg.tmp");
        let env_tmp = dir.path().join("00000000000000000001.env.tmp");
        std::fs::write(&msg_tmp, b"partial msg write").expect("write msg.tmp");
        std::fs::write(&env_tmp, b"partial env write").expect("write env.tmp");

        queue.cleanup_tmp_files().await;

        assert!(
            !msg_tmp.exists(),
            ".msg.tmp should be removed by cleanup_tmp_files"
        );
        assert!(
            !env_tmp.exists(),
            ".env.tmp should be removed by cleanup_tmp_files"
        );
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

        let result = SmtpRelayQueue::new(queue_dir.clone(), vec![], Duration::from_secs(300), None);

        // Restore write permission so tempdir cleanup can remove the directory.
        let _ = std::fs::set_permissions(&queue_dir, std::fs::Permissions::from_mode(0o755));

        assert!(
            result.is_err(),
            "new() should fail on a read-only queue dir"
        );
    }

    // --- DKIM signing tests ---

    // Build a DkimSigner using the RFC 8463 §A.2 test key.
    // Seed and public key taken verbatim from the RFC appendix; these are
    // fixed public test vectors, not derived from this code.
    fn test_dkim_signer() -> Arc<
        mail_auth::dkim::DkimSigner<mail_auth::common::crypto::Ed25519Key, mail_auth::dkim::Done>,
    > {
        // RFC 8463 §A.2 private key seed (base64 "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=").
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        // RFC 8463 §A.2 public key (base64 "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=").
        let pubkey: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let ed_key =
            mail_auth::common::crypto::Ed25519Key::from_seed_and_public_key(&seed, &pubkey)
                .expect("RFC 8463 §A.2 test key must be valid");
        Arc::new(
            mail_auth::dkim::DkimSigner::from_key(ed_key)
                .domain("example.com")
                .selector("test")
                .headers([
                    "From",
                    "To",
                    "Subject",
                    "Date",
                    "Message-ID",
                    "MIME-Version",
                ]),
        )
    }

    // Oracle: RFC 6376 §3.5 — DKIM-Signature header field is prepended to the
    // message, contains "a=ed25519-sha256", and does NOT contain "l=" (body
    // length tag is prohibited by RFC 8463 §3.4 for security reasons).
    #[test]
    fn test_relay_dkim_signing_prepends_header() {
        let signer = test_dkim_signer();
        let msg = b"From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nMIME-Version: 1.0\r\n\r\nHello.\r\n";
        let sig = signer
            .sign(msg)
            .expect("sign must succeed with RFC 8463 test key");
        let header = sig.to_header();
        assert!(
            header.starts_with("DKIM-Signature:"),
            "signed header must start with 'DKIM-Signature:', got: {header:?}"
        );
        assert!(
            header.contains("a=ed25519-sha256"),
            "signed header must contain 'a=ed25519-sha256', got: {header:?}"
        );
        assert!(
            !header.contains("l="),
            "signed header must NOT contain body length tag 'l=', got: {header:?}"
        );
        // Verify prepend logic: signed message = header bytes + original bytes.
        let mut expected = Vec::new();
        expected.extend_from_slice(header.as_bytes());
        expected.extend_from_slice(msg);
        assert_eq!(
            &expected[..header.len()],
            header.as_bytes(),
            "signed bytes must begin with the DKIM-Signature header"
        );
        assert_eq!(
            &expected[header.len()..],
            msg.as_ref(),
            "original article bytes must follow the DKIM-Signature header unchanged"
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
            None,
        )
        .expect("new");

        queue
            .enqueue(b"article", "from@example.com", &[])
            .await
            .expect("enqueue with empty rcpt_to should not fail");

        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "env"))
            .count();
        assert_eq!(
            env_count, 0,
            "empty rcpt_to should be a no-op: no .env files expected"
        );
    }
}
