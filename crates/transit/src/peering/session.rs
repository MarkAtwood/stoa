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
                    let article_bytes = match read_dot_stuffed(&mut reader).await {
                        Some(b) => b,
                        None => break,
                    };
                    let result = check_ingest(&msgid, &article_bytes, &shared.msgid_map).await;
                    let resp = takethis_response(&result);
                    if result == IngestResult::Accepted {
                        enqueue_article(&shared, &msgid, article_bytes).await;
                    }
                    Some(format!("{} {}\r\n", resp.trim_end(), msgid))
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
                        let article_bytes = match read_dot_stuffed(&mut reader).await {
                            Some(b) => b,
                            None => break,
                        };
                        let result = check_ingest(&msgid, &article_bytes, &shared.msgid_map).await;
                        if result == IngestResult::Accepted {
                            enqueue_article(&shared, &msgid, article_bytes).await;
                        }
                        Some(ihave_response(&result).to_owned())
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

/// Read a dot-stuffed NNTP article terminated by `.\r\n` (or `.\n`).
///
/// Returns the accumulated raw bytes (with dot-unstuffing applied), or
/// `None` if the connection closed before the terminator.
async fn read_dot_stuffed(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "." {
            return Some(buf);
        }
        let output_line = if let Some(rest) = trimmed.strip_prefix("..") {
            format!(".{rest}\r\n")
        } else {
            format!("{trimmed}\r\n")
        };
        buf.extend_from_slice(output_line.as_bytes());
    }
}
