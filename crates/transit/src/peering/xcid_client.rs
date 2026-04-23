//! XCID client: fetches `LogEntry` structs from remote transit peers.
//!
//! The XCID protocol is a usenet-ipfs extension over the existing NNTP peering
//! TCP channel.  A requester sends `XCID <cid>\r\n` and receives either:
//! - `224 Block follows (<cid>)\r\n<base64_lines>\r\n.\r\n` — entry found, or
//! - `430 No such block\r\n` — entry not present on that peer.
//!
//! The CID encodes a `LogEntryId` as a CIDv1 with codec 0x71 (DAG-CBOR) and a
//! SHA-256 multihash whose digest is the raw 32-byte `LogEntryId`.
//!
//! This client opens ephemeral TCP connections per fetch attempt; it does not
//! reuse the inbound peering session because the session handler runs in a
//! separate task with its own ownership of the stream.

use std::sync::Arc;

use base64::Engine as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use usenet_ipfs_core::group_log::{
    types::{LogEntry, LogEntryId},
    verify::{verify_signature, VerifiedEntry},
};

/// Client for fetching log entries from remote transit peers via the XCID command.
pub struct XcidClient {
    peer_addresses: Arc<Vec<String>>,
    trusted_keys: Arc<Vec<ed25519_dalek::VerifyingKey>>,
}

impl XcidClient {
    /// Create a new client that will try `peer_addresses` in order.
    ///
    /// `trusted_keys` is the set of operator public keys whose signatures are
    /// accepted.  A fetched entry must be signed by at least one of these keys.
    pub fn new(
        peer_addresses: Vec<String>,
        trusted_keys: Vec<ed25519_dalek::VerifyingKey>,
    ) -> Self {
        Self {
            peer_addresses: Arc::new(peer_addresses),
            trusted_keys: Arc::new(trusted_keys),
        }
    }

    /// Fetch and verify a log entry by its ID, trying each configured peer in turn.
    ///
    /// Returns the first successfully fetched and signature-verified entry.
    /// Returns `Err` if all peers are exhausted or no trusted key validates the
    /// fetched entry.
    pub async fn fetch_entry(&self, entry_id: &LogEntryId) -> Result<VerifiedEntry, String> {
        if self.peer_addresses.is_empty() {
            return Err("no peer addresses configured for XCID fetch".to_string());
        }

        let cid_str = entry_id.to_cid().to_string();

        for addr in self.peer_addresses.iter() {
            match self.try_fetch_from_peer(addr, &cid_str, entry_id).await {
                Ok(verified) => return Ok(verified),
                Err(e) => {
                    tracing::debug!(peer = %addr, cid = %cid_str, "xcid: peer fetch failed: {e}");
                }
            }
        }

        Err(format!("xcid: all peers exhausted for {cid_str}"))
    }

    async fn try_fetch_from_peer(
        &self,
        addr: &str,
        cid_str: &str,
        expected_id: &LogEntryId,
    ) -> Result<VerifiedEntry, String> {
        // Open an ephemeral TCP connection to the peer.
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect to {addr}: {e}"))?;
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();

        // Read the server greeting (200 or 201).
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read greeting: {e}"))?;
        if !line.starts_with("200 ") && !line.starts_with("201 ") {
            return Err(format!("unexpected greeting: {}", line.trim()));
        }

        // Send the XCID command.
        write_half
            .write_all(format!("XCID {cid_str}\r\n").as_bytes())
            .await
            .map_err(|e| format!("write XCID: {e}"))?;

        // Read the first response line.
        line.clear();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        let response_line = line.trim().to_owned();

        if response_line.starts_with("430 ") || response_line.starts_with("500 ") {
            return Err(format!("peer responded: {response_line}"));
        }
        if !response_line.starts_with("224 ") {
            return Err(format!("unexpected response: {response_line}"));
        }

        // Read base64 body lines until a standalone ".".
        let mut b64_accumulator = String::new();
        loop {
            line.clear();
            reader
                .read_line(&mut line)
                .await
                .map_err(|e| format!("read body: {e}"))?;
            let t = line.trim();
            if t == "." {
                break;
            }
            if line.is_empty() {
                return Err("unexpected EOF in XCID response body".to_string());
            }
            b64_accumulator.push_str(t);
        }

        // Best-effort QUIT before closing the connection.
        let _ = write_half.write_all(b"QUIT\r\n").await;

        // Decode base64 → DAG-CBOR bytes.
        let cbor_bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64_accumulator)
            .map_err(|e| format!("base64 decode: {e}"))?;

        // Deserialize LogEntry from DAG-CBOR.
        let entry: LogEntry = serde_ipld_dagcbor::from_slice(&cbor_bytes)
            .map_err(|e| format!("dagcbor deserialize: {e}"))?;

        // Verify integrity: recompute the LogEntryId from the entry fields and
        // compare to what was requested.  This guards against a peer serving a
        // different entry under the same CID.
        let computed_id = LogEntryId::from_entry(&entry);
        if computed_id != *expected_id {
            return Err(format!(
                "entry ID mismatch: expected {expected_id}, computed {computed_id}"
            ));
        }

        // Verify the operator signature with any trusted key.
        for key in self.trusted_keys.iter() {
            if let Ok(verified) = verify_signature(entry.clone(), key) {
                return Ok(verified);
            }
        }

        Err(format!(
            "no trusted key (tried {}) could verify entry {expected_id} from {addr}",
            self.trusted_keys.len()
        ))
    }
}
