//! Inbound peering session handler.
//!
//! Each accepted TCP connection gets its own `run_peering_session` task.
//! The session speaks the NNTP transit subset: CAPABILITIES, MODE STREAM,
//! IHAVE, CHECK, TAKETHIS, QUIT.  Accepted articles are enqueued into the
//! shared [`IngestionSender`]; the pipeline drain task in `main.rs` processes
//! them asynchronously.

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use usenet_ipfs_core::group_log::SqliteLogStorage;
use usenet_ipfs_core::{msgid_map::MsgIdMap, validation::validate_message_id};

use crate::peering::{
    ingestion::{
        check_ingest, check_mode_guard, check_response, ihave_response, takethis_response,
        IngestResult,
    },
    ingestion_queue::{IngestionSender, QueuedArticle},
    mode_stream::{capabilities_response, handle_mode_stream, PeeringMode},
    pipeline::IpfsStore,
};

/// State shared across all peering sessions (and the pipeline drain task).
pub struct PeeringShared {
    /// IPFS block store (write-only at the transit layer).
    pub ipfs: Arc<dyn IpfsStore>,
    /// Message-ID → CID mapping.
    pub msgid_map: Arc<MsgIdMap>,
    /// Group-log storage.
    pub log_storage: Arc<SqliteLogStorage>,
    /// Gossipsub send channel; `None` if gossipsub is not running.
    pub gossip_tx: Option<mpsc::Sender<(String, Vec<u8>)>>,
    /// Operator signing key (articles are signed before log-append).
    pub signing_key: Arc<ed25519_dalek::SigningKey>,
    /// HLC clock shared across sessions (mutex for exclusive send() access).
    pub hlc: Arc<Mutex<usenet_ipfs_core::hlc::HlcClock>>,
    /// Ingestion queue sender; sessions enqueue articles here.
    pub ingestion_sender: Arc<IngestionSender>,
    /// Libp2p peer identity string (used in tip advertisements).
    pub local_peer_id: String,
}

/// Handle one inbound NNTP peering TCP connection.
///
/// Returns when the peer disconnects or sends QUIT.
pub async fn run_peering_session(stream: TcpStream, shared: Arc<PeeringShared>) {
    let peer_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut mode = PeeringMode::Ihave;
    let mut rate_limiter = TokenBucket::new(RATE_BURST, RATE_PER_SEC);

    tracing::debug!(%peer_addr, "peering connection accepted");

    if writer
        .write_all(b"200 usenet-ipfs-transit NNTP service ready\r\n")
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
                    Some(format!(
                        "{} {}\r\n",
                        check_response(&result).trim_end(),
                        msgid
                    ))
                }
            }
            "TAKETHIS" => {
                let msgid = arg.to_owned();
                if let Some(guard_resp) = check_mode_guard(mode) {
                    Some(guard_resp.to_owned())
                } else {
                    match read_dot_stuffed(&mut reader).await {
                        DotStuffedResult::Eof => break,
                        DotStuffedResult::TooLarge => {
                            // Stream was drained to the terminator; connection is still valid.
                            Some(format!("439 Article too large {msgid}\r\n"))
                        }
                        DotStuffedResult::Data(article_bytes) => {
                            let result =
                                check_ingest(&msgid, &article_bytes, &shared.msgid_map).await;
                            let resp = if result == IngestResult::Accepted {
                                if rate_limiter.try_consume() {
                                    enqueue_article(&shared, &msgid, article_bytes).await;
                                    takethis_response(&result)
                                } else {
                                    tracing::warn!(
                                        %peer_addr, %msgid,
                                        "TAKETHIS rate limit exceeded"
                                    );
                                    "431 Article too soon, try again later"
                                }
                            } else {
                                takethis_response(&result)
                            };
                            Some(format!("{} {}\r\n", resp.trim_end(), msgid))
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
                                    if rate_limiter.try_consume() {
                                        enqueue_article(&shared, &msgid, article_bytes).await;
                                        Some(ihave_response(&result).to_owned())
                                    } else {
                                        tracing::warn!(
                                            %peer_addr, %msgid,
                                            "IHAVE rate limit exceeded"
                                        );
                                        Some("436 Transfer failed, try again later\r\n".to_owned())
                                    }
                                } else {
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

// ── Per-session rate limiter ──────────────────────────────────────────────────

/// Burst capacity: number of accepted articles allowed in a sudden burst
/// before the per-second rate limit kicks in.
const RATE_BURST: f64 = 200.0;

/// Sustained rate: articles accepted per second per connection in steady state.
const RATE_PER_SEC: f64 = 100.0;

/// Token-bucket rate limiter for per-connection article acceptance.
///
/// Prevents a single peer from flooding the ingestion queue and starving
/// legitimate peers.  Calls to `try_consume` return `true` (allowed) or
/// `false` (rate limit exceeded; caller should respond with 431/436).
pub(crate) struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    pub(crate) fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Attempt to consume one token.  Returns `true` if the token was granted,
    /// `false` if the bucket was empty (rate limit exceeded).
    pub(crate) fn try_consume(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

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

/// Enqueue an accepted article into the ingestion queue.
///
/// Logs a warning if the queue is full; the article is dropped in that case.
async fn enqueue_article(shared: &PeeringShared, message_id: &str, bytes: Vec<u8>) {
    let article = QueuedArticle {
        bytes,
        message_id: message_id.to_owned(),
    };
    if let Err(e) = shared.ingestion_sender.try_enqueue(article).await {
        tracing::warn!(message_id, "ingestion queue full, article dropped: {e}");
    }
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
async fn read_dot_stuffed(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> DotStuffedResult {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_up_to_capacity() {
        let mut tb = TokenBucket::new(5.0, 0.0); // no refill
        for _ in 0..5 {
            assert!(tb.try_consume(), "should allow up to capacity");
        }
        assert!(!tb.try_consume(), "should deny when exhausted");
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let mut tb = TokenBucket::new(1.0, 1_000_000.0); // very fast refill
        assert!(tb.try_consume(), "first consume succeeds");
        // drain
        while tb.try_consume() {}
        // Sleep not needed: the refill formula uses elapsed time; with 1M tokens/sec
        // even a nanosecond of elapsed time will refill at least one token.
        // Force a small artificial delay via setting last_refill in the past.
        tb.last_refill -= std::time::Duration::from_secs(1);
        assert!(tb.try_consume(), "should refill after time passes");
    }

    #[test]
    fn token_bucket_does_not_exceed_capacity() {
        let cap = 10.0;
        let mut tb = TokenBucket::new(cap, 1_000_000.0);
        // Wait a long time (via time manipulation)
        tb.last_refill -= std::time::Duration::from_secs(9999);
        // Consume once to trigger refill
        tb.try_consume();
        // tokens should be capped at capacity - 1
        assert!(
            tb.tokens <= cap,
            "tokens {:.1} must not exceed capacity {cap}",
            tb.tokens
        );
    }

    #[test]
    fn token_bucket_zero_refill_stays_empty_after_drain() {
        let mut tb = TokenBucket::new(3.0, 0.0);
        for _ in 0..3 {
            assert!(tb.try_consume());
        }
        tb.last_refill -= std::time::Duration::from_secs(100);
        assert!(!tb.try_consume(), "zero refill rate must not replenish");
    }
}
