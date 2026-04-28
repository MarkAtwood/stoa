//! Inbound peering session handler.
//!
//! Each accepted TCP connection gets its own `run_peering_session` task.
//! The session speaks the NNTP transit subset: CAPABILITIES, MODE STREAM,
//! IHAVE, CHECK, TAKETHIS, QUIT.  Accepted articles are enqueued into the
//! shared [`IngestionSender`]; the pipeline drain task in `main.rs` processes
//! them asynchronously.

use mail_auth::MessageAuthenticator;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tokio_rustls;

use stoa_core::{msgid_map::MsgIdMap, validation::validate_message_id};
use stoa_verify::VerificationStore;

use crate::peering::{
    auth::run_auth_handshake,
    blacklist::{check_and_blacklist, is_blacklisted, BlacklistConfig},
    ingestion::{
        check_ingest, check_mode_guard, check_response, ihave_response, takethis_mode_guard,
        takethis_response, IngestResult,
    },
    ingestion_queue::{IngestionSender, QueuedArticle},
    mode_stream::{capabilities_response, handle_mode_stream, PeeringMode},
    peer_registry::PeerRegistry,
    pipeline::IpfsStore,
    rate_limit::PeerRateLimiter,
};
use crate::staging::StagingStore;

/// State shared across all peering sessions (and the pipeline drain task).
pub struct PeeringShared {
    /// IPFS block store (write-only at the transit layer).
    pub ipfs: Arc<dyn IpfsStore>,
    /// Message-ID → CID mapping.
    pub msgid_map: Arc<MsgIdMap>,
    /// Operator signing key (articles are signed before log-append).
    pub signing_key: Arc<ed25519_dalek::SigningKey>,
    /// HLC clock shared across sessions (mutex for exclusive send() access).
    pub hlc: Arc<Mutex<stoa_core::hlc::HlcClock>>,
    /// Ingestion queue sender; sessions enqueue articles here.
    pub ingestion_sender: Arc<IngestionSender>,
    /// Local FQDN prepended to `Path:` on every ingested article (Son-of-RFC-1036 §3.3).
    pub local_hostname: String,
    /// Per-IP rate limiter shared across all sessions.
    ///
    /// Keyed by peer IP (not IP:port) so that multiple simultaneous connections
    /// from one host share a single budget — preventing N-connection burst
    /// multiplication.
    pub peer_rate_limiter: Arc<std::sync::Mutex<PeerRateLimiter>>,
    /// Transit SQLite pool for peer registry and blacklist lookups.
    pub transit_pool: Arc<sqlx::AnyPool>,
    /// Blacklist policy configuration.
    pub blacklist_config: BlacklistConfig,
    /// Write-ahead staging store.  When `Some`, accepted articles are written
    /// to disk before this function returns to the peer; a separate drain task
    /// processes them through the IPFS pipeline.  When `None`, articles are
    /// enqueued to the in-memory [`IngestionSender`] instead.
    pub staging: Option<Arc<StagingStore>>,
    /// Trusted peer public keys for ed25519 challenge-response auth.
    ///
    /// Non-empty → every inbound connection must complete the mutual handshake
    /// before any NNTP bytes are exchanged.  Empty → auth is skipped (port
    /// must be firewalled in that case).
    pub trusted_keys: Arc<tokio::sync::RwLock<Vec<ed25519_dalek::VerifyingKey>>>,
    /// Optional rustls acceptor for TLS-wrapped inbound connections.
    ///
    /// `Some` → every accepted connection is TLS-upgraded before any NNTP
    /// bytes.  `None` → plain TCP is used (suitable for LAN / loopback or
    /// when a TLS terminator sits in front of the daemon).
    pub tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    /// Article verification store. `None` disables signature recording.
    pub verification_store: Option<Arc<VerificationStore>>,
    /// DKIM authenticator. `None` disables DKIM checks.
    pub dkim_authenticator: Option<Arc<MessageAuthenticator>>,
}

/// Handle one inbound NNTP peering connection.
///
/// `stream` may be a plain `TcpStream` or a TLS-wrapped stream — the generic
/// bound keeps this zero-cost while supporting both without boxing.
/// `peer_addr` and `peer_ip` are extracted by the caller (from the TCP
/// `accept()` return value) and passed in so this function can operate on any
/// stream type.
///
/// Returns when the peer disconnects or sends QUIT.
pub async fn run_peering_session<S>(
    stream: S,
    peer_addr: String,
    peer_ip: String,
    shared: Arc<PeeringShared>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tracing::debug!(%peer_addr, "peering connection accepted");

    // Register peer if not yet known; then check blacklist.
    // Silently drop the connection with no NNTP greeting on blacklist hit —
    // do not leak the reason to the peer.
    let registry = PeerRegistry::new((*shared.transit_pool).clone());
    let now_ms = wall_ms();
    if let Err(e) = registry
        .ensure_registered(&peer_ip, &peer_addr, now_ms)
        .await
    {
        tracing::warn!(%peer_ip, "peer registry update failed: {e}");
    }
    match is_blacklisted(&shared.transit_pool, &peer_ip, now_ms).await {
        Ok(true) => {
            tracing::debug!(%peer_ip, "rejecting blacklisted peer");
            return;
        }
        Err(e) => {
            tracing::warn!(%peer_ip, "blacklist check failed: {e}");
        }
        Ok(false) => {}
    }

    let (mut reader_half, mut writer) = tokio::io::split(stream);

    // Mutual ed25519 challenge-response handshake before any NNTP bytes.
    // Runs only when the operator has configured trusted peer keys.
    // On failure the connection is dropped silently — do not leak the reason.
    let trusted_keys_snap = shared.trusted_keys.read().await.clone();
    if !trusted_keys_snap.is_empty() {
        match run_auth_handshake(
            &mut reader_half,
            &mut writer,
            &shared.signing_key,
            &trusted_keys_snap,
        )
        .await
        {
            Ok(_remote_pubkey) => {
                tracing::debug!(%peer_addr, "peering auth handshake succeeded");
            }
            Err(e) => {
                tracing::warn!(%peer_addr, error = %e, "peering auth handshake failed");
                return;
            }
        }
    }

    let mut reader = BufReader::new(reader_half);
    let mut mode = PeeringMode::Ihave;

    if writer
        .write_all(b"200 stoa-transit NNTP service ready\r\n")
        .await
        .is_err()
    {
        return;
    }

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let cmd_str = line.trim_end_matches(['\r', '\n']);
        if cmd_str.is_empty() {
            continue;
        }

        let mut parts = cmd_str.splitn(2, ' ');
        let verb = parts.next().unwrap_or("").to_ascii_uppercase();
        let arg = parts.next().unwrap_or("").trim();

        let response: Option<String> = match verb.as_str() {
            "CAPABILITIES" => Some(capabilities_response()),
            "MODE" if arg.eq_ignore_ascii_case("STREAM") => {
                let (resp, new_mode) = handle_mode_stream(mode);
                mode = new_mode;
                Some(resp)
            }
            "QUIT" => {
                let _ = writer.write_all(b"205 Closing connection\r\n").await;
                break;
            }
            "CHECK" => {
                let msgid = arg;
                if let Some(guard_resp) = check_mode_guard(mode) {
                    Some(guard_resp.to_owned())
                } else {
                    let result = check_msgid_only(msgid, &shared.msgid_map).await;
                    // RFC 4644 §2.3: response format is "NNN <message-id> [comment]".
                    // Extract just the code from check_response() and put msgid next.
                    let code = check_response(&result)
                        .split_ascii_whitespace()
                        .next()
                        .unwrap_or("438");
                    Some(format!("{code} {msgid}\r\n"))
                }
            }
            "TAKETHIS" => {
                let msgid = arg.to_owned();
                if let Some(guard_resp) = takethis_mode_guard(mode) {
                    Some(guard_resp.to_owned())
                } else {
                    match read_dot_stuffed(&mut reader).await {
                        DotStuffedResult::Eof => break,
                        DotStuffedResult::TooLarge => {
                            // Stream was drained to the terminator; connection is still valid.
                            // RFC 4644 §2.4: "NNN <message-id> [comment]".
                            Some(format!("439 {msgid} Article too large\r\n"))
                        }
                        DotStuffedResult::Data(article_bytes) => {
                            let result =
                                check_ingest(&msgid, &article_bytes, &shared.msgid_map).await;
                            let resp = if result == IngestResult::Accepted {
                                if shared
                                    .peer_rate_limiter
                                    .lock()
                                    .unwrap()
                                    .check(&peer_ip)
                                    .is_none()
                                {
                                    if enqueue_article(&shared, &msgid, article_bytes)
                                        .await
                                        .is_ok()
                                    {
                                        record_accepted(&registry, &peer_ip).await;
                                        takethis_response(&result)
                                    } else {
                                        "436 Transfer not possible; try again later"
                                    }
                                } else {
                                    tracing::warn!(
                                        %peer_addr, %msgid,
                                        "TAKETHIS rate limit exceeded"
                                    );
                                    record_and_maybe_blacklist(&registry, &shared, &peer_ip).await;
                                    "436 Transfer not possible; try again later"
                                }
                            } else {
                                if matches!(result, IngestResult::Rejected(_)) {
                                    record_and_maybe_blacklist(&registry, &shared, &peer_ip).await;
                                }
                                takethis_response(&result)
                            };
                            // RFC 4644 §2.4: response format is "NNN <message-id> [comment]".
                            // Extract just the code from the resp string and put msgid next.
                            let code = resp.split_ascii_whitespace().next().unwrap_or("431");
                            Some(format!("{code} {msgid}\r\n"))
                        }
                    }
                }
            }
            "IHAVE" => {
                let msgid = arg.to_owned();
                // Pre-check: do we want it?
                let pre = check_msgid_only(&msgid, &shared.msgid_map).await;
                match pre {
                    IngestResult::Accepted => {
                        // Tell the peer to send it.
                        if writer.write_all(b"335 Send it\r\n").await.is_err() {
                            break;
                        }
                        match read_dot_stuffed(&mut reader).await {
                            DotStuffedResult::Eof => break,
                            DotStuffedResult::TooLarge => {
                                // Stream was drained; connection is still valid.
                                Some("437 Article too large\r\n".to_owned())
                            }
                            DotStuffedResult::Data(article_bytes) => {
                                let result =
                                    check_ingest(&msgid, &article_bytes, &shared.msgid_map).await;
                                if result == IngestResult::Accepted {
                                    if shared
                                        .peer_rate_limiter
                                        .lock()
                                        .unwrap()
                                        .check(&peer_ip)
                                        .is_none()
                                    {
                                        if enqueue_article(&shared, &msgid, article_bytes)
                                            .await
                                            .is_ok()
                                        {
                                            record_accepted(&registry, &peer_ip).await;
                                            Some(ihave_response(&result).to_owned())
                                        } else {
                                            Some(
                                                "436 Transfer failed, try again later\r\n"
                                                    .to_owned(),
                                            )
                                        }
                                    } else {
                                        tracing::warn!(
                                            %peer_addr, %msgid,
                                            "IHAVE rate limit exceeded"
                                        );
                                        record_and_maybe_blacklist(&registry, &shared, &peer_ip)
                                            .await;
                                        Some("436 Transfer failed, try again later\r\n".to_owned())
                                    }
                                } else {
                                    if matches!(result, IngestResult::Rejected(_)) {
                                        record_and_maybe_blacklist(&registry, &shared, &peer_ip)
                                            .await;
                                    }
                                    Some(ihave_response(&result).to_owned())
                                }
                            }
                        }
                    }
                    IngestResult::Duplicate => Some("435 Duplicate\r\n".to_owned()),
                    IngestResult::TransientError(_) => {
                        Some("436 Transfer failed, try again later\r\n".to_owned())
                    }
                    IngestResult::Rejected(_) => Some("437 Article rejected\r\n".to_owned()),
                }
            }
            // XCID is not advertised in CAPABILITIES (Hard Design Invariant 1: CRDT log
            // internals must not be exposed via protocol extensions).
            "XCID" => Some("502 Command unavailable\r\n".to_owned()),
            _ => Some(format!("500 Unknown command: {verb}\r\n")),
        };

        if let Some(resp) = response {
            if writer.write_all(resp.as_bytes()).await.is_err() {
                break;
            }
        }
    }

    tracing::debug!(%peer_addr, "peering connection closed");
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Current wall-clock time in Unix milliseconds.
fn wall_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Record an accepted article in the peer registry; log on failure.
async fn record_accepted(registry: &PeerRegistry, peer_ip: &str) {
    if let Err(e) = registry.record_accepted(peer_ip, wall_ms()).await {
        tracing::warn!(%peer_ip, "record_accepted failed: {e}");
    }
}

/// Record a rejected article and check whether to blacklist the peer.
///
/// Called after any Rejected (not Duplicate or TransientError) outcome
/// so that a peer sending repeated invalid articles accumulates failures.
async fn record_and_maybe_blacklist(
    registry: &PeerRegistry,
    shared: &PeeringShared,
    peer_ip: &str,
) {
    let now_ms = wall_ms();
    if let Err(e) = registry.record_rejected(peer_ip, now_ms).await {
        tracing::warn!(%peer_ip, "record_rejected failed: {e}");
    }
    match check_and_blacklist(
        &shared.transit_pool,
        peer_ip,
        now_ms,
        &shared.blacklist_config,
    )
    .await
    {
        Ok(true) => {
            tracing::warn!(%peer_ip, "peer blacklisted after repeated article rejections");
        }
        Err(e) => {
            tracing::warn!(%peer_ip, "check_and_blacklist failed: {e}");
        }
        Ok(false) => {}
    }
}

/// Check only msgid format and duplicate status (no article bytes needed).
async fn check_msgid_only(msgid: &str, msgid_map: &MsgIdMap) -> IngestResult {
    if validate_message_id(msgid).is_err() {
        return IngestResult::Rejected("invalid Message-ID".to_owned());
    }
    match msgid_map.lookup_by_msgid(msgid).await {
        Err(e) => IngestResult::TransientError(e.to_string()),
        Ok(Some(_)) => IngestResult::Duplicate,
        Ok(None) => IngestResult::Accepted,
    }
}

/// Enqueue an accepted article for pipeline processing.
///
/// When [`PeeringShared::staging`] is `Some`, the article is written to the
/// on-disk staging area and `Ok(())` is returned immediately — the drain task
/// will process it asynchronously.  Returns `Err` if the staging area is at
/// capacity (caller should respond 436/439 so the peer retries later).
///
/// When staging is `None`, the article is enqueued into the shared in-memory
/// [`IngestionSender`].  Returns `Err` if the queue is full.
async fn enqueue_article(
    shared: &PeeringShared,
    message_id: &str,
    bytes: Vec<u8>,
) -> Result<(), &'static str> {
    if let Some(ref staging) = shared.staging {
        return match staging.try_stage(message_id, &bytes).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                tracing::warn!(message_id, "staging area full, article rejected");
                Err("staging full")
            }
            Err(e) => {
                tracing::warn!(message_id, "staging error: {e}");
                Err("staging error")
            }
        };
    }
    let article = QueuedArticle {
        bytes,
        message_id: message_id.to_owned(),
    };
    shared
        .ingestion_sender
        .try_enqueue(article)
        .await
        .map_err(|e| {
            tracing::warn!(message_id, "ingestion queue full, article dropped: {e}");
            "queue full"
        })
}


/// Result of reading a dot-stuffed article from a peer.
enum DotStuffedResult {
    /// Article read successfully; contains the unstuffed bytes.
    Data(Vec<u8>),
    /// Article exceeded the size limit; stream was drained to the terminator.
    TooLarge,
    /// Connection closed before the dot-terminator.
    Eof,
}

/// Read a dot-stuffed NNTP article terminated by `.\r\n` (or `.\n`).
///
/// Applies dot-unstuffing (leading `..` → `.`) and enforces
/// `crate::peering::ingestion::MAX_ARTICLE_BYTES`.  If the accumulated
/// content exceeds the limit, switches to drain mode (reads until the
/// terminator without accumulating) and returns [`DotStuffedResult::TooLarge`].
/// This keeps the NNTP connection valid so a 437/439 rejection can be sent.
async fn read_dot_stuffed<R>(reader: &mut BufReader<R>) -> DotStuffedResult
where
    R: AsyncRead + Unpin,
{
    use crate::peering::ingestion::MAX_ARTICLE_BYTES;

    let mut buf = Vec::new();
    let mut line = String::new();
    let mut too_large = false;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return DotStuffedResult::Eof,
            Ok(_) => {}
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "." {
            return if too_large {
                DotStuffedResult::TooLarge
            } else {
                DotStuffedResult::Data(buf)
            };
        }

        if too_large {
            // Drain mode: keep reading for the terminator without accumulating.
            continue;
        }

        let output_line = if let Some(rest) = trimmed.strip_prefix("..") {
            format!(".{rest}\r\n")
        } else {
            format!("{trimmed}\r\n")
        };
        if buf.len() + output_line.len() > MAX_ARTICLE_BYTES {
            too_large = true;
            continue;
        }
        buf.extend_from_slice(output_line.as_bytes());
    }
}
