//! Tip advertisement message format for gossipsub.
//!
//! `TipAdvertisement` is broadcast over the hierarchy topic whenever a node
//! learns new Merkle-CRDT tip CIDs for a group. Peers receiving it use
//! `handle_tip_advertisement` to trigger reconciliation if they see unknown tips.

use cid::Cid;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use usenet_ipfs_core::hlc::HlcTimestamp;

/// A tip advertisement broadcast over gossipsub.
///
/// Serialized to JSON bytes for transport. Field order in the struct is fixed
/// so serde_json produces deterministic output for the same logical content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TipAdvertisement {
    /// The newsgroup this advertisement is for.
    pub group_name: String,
    /// Tip CIDs encoded as multibase base32upper strings (CID::to_string()).
    pub tip_cids: Vec<String>,
    /// Wall-clock ms component of the sender's HLC timestamp.
    pub hlc_ms: u64,
    /// Logical clock component.
    pub hlc_logical: u32,
    /// Node ID component as hex string.
    pub hlc_node_id: String,
    /// Sending peer's identity as a string.
    pub sender_peer_id: String,
}

impl TipAdvertisement {
    /// Build a TipAdvertisement from structured types.
    pub fn build(
        group_name: &str,
        tip_cids: &[Cid],
        timestamp: &HlcTimestamp,
        sender: &PeerId,
    ) -> Self {
        let mut tip_strings: Vec<String> = tip_cids.iter().map(|c| c.to_string()).collect();
        // Sort CIDs for determinism — same logical content must produce identical bytes.
        tip_strings.sort();
        Self {
            group_name: group_name.to_owned(),
            tip_cids: tip_strings,
            hlc_ms: timestamp.wall_ms,
            hlc_logical: timestamp.logical,
            hlc_node_id: hex::encode(timestamp.node_id),
            sender_peer_id: sender.to_string(),
        }
    }

    /// Serialize to canonical JSON bytes for transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("TipAdvertisement serialization must not fail")
    }

    /// Deserialize from transport bytes.
    ///
    /// Returns `None` and logs a warning if the bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match serde_json::from_slice(bytes) {
            Ok(advert) => Some(advert),
            Err(e) => {
                tracing::warn!("malformed TipAdvertisement received: {e}");
                None
            }
        }
    }
}

/// Publish a tip advertisement for `group_name` to the hierarchy gossipsub topic.
///
/// Sends the serialized advertisement to the gossipsub swarm via `tx`.
/// Returns an error if the swarm channel is closed.
pub async fn publish_tip(
    tx: &tokio::sync::mpsc::Sender<(String, Vec<u8>)>,
    group_name: &str,
    tip_cids: &[Cid],
    timestamp: &HlcTimestamp,
    sender: &PeerId,
) -> Result<(), tokio::sync::mpsc::error::SendError<(String, Vec<u8>)>> {
    use crate::gossip::topics::topic_for_group;
    let advert = TipAdvertisement::build(group_name, tip_cids, timestamp, sender);
    let topic = topic_for_group(group_name).to_string();
    let bytes = advert.to_bytes();
    tx.send((topic, bytes)).await
}

/// Parse and validate an incoming tip advertisement message.
///
/// Returns `None` if the bytes cannot be parsed or the group name is empty.
/// Logs a warning on any rejection.
pub fn handle_tip_advertisement(bytes: &[u8]) -> Option<TipAdvertisement> {
    let advert = TipAdvertisement::from_bytes(bytes)?;
    if advert.group_name.is_empty() {
        tracing::warn!("TipAdvertisement with empty group_name rejected");
        return None;
    }
    if advert.tip_cids.is_empty() {
        tracing::warn!("TipAdvertisement with no tip_cids rejected");
        return None;
    }
    Some(advert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use libp2p::PeerId;
    use multihash_codetable::{Code, MultihashDigest};
    use usenet_ipfs_core::hlc::HlcTimestamp;

    fn make_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x71, digest)
    }

    fn make_timestamp() -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: 1700000000000,
            logical: 0,
            node_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        }
    }

    fn make_peer_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn build_and_roundtrip() {
        let cid1 = make_cid(b"article-1");
        let cid2 = make_cid(b"article-2");
        let ts = make_timestamp();
        let peer = make_peer_id();

        let advert = TipAdvertisement::build("comp.lang.rust", &[cid1, cid2], &ts, &peer);
        let bytes = advert.to_bytes();
        let parsed = TipAdvertisement::from_bytes(&bytes).expect("must parse");

        assert_eq!(advert, parsed);
        assert_eq!(parsed.group_name, "comp.lang.rust");
        assert_eq!(parsed.tip_cids.len(), 2);
        assert_eq!(parsed.hlc_ms, 1700000000000);
        assert_eq!(parsed.sender_peer_id, peer.to_string());
    }

    #[test]
    fn serialization_is_deterministic() {
        // Same inputs must produce identical bytes on repeated calls.
        let cid1 = make_cid(b"article-1");
        let ts = make_timestamp();
        let peer = make_peer_id();

        let bytes_a = TipAdvertisement::build("comp.lang.rust", &[cid1], &ts, &peer).to_bytes();
        let bytes_b = TipAdvertisement::build("comp.lang.rust", &[cid1], &ts, &peer).to_bytes();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn tip_cids_sorted_for_determinism() {
        // Same CIDs in different order must produce same bytes.
        let cid1 = make_cid(b"article-1");
        let cid2 = make_cid(b"article-2");
        let ts = make_timestamp();
        let peer = make_peer_id();

        let bytes_ab =
            TipAdvertisement::build("comp.lang.rust", &[cid1, cid2], &ts, &peer).to_bytes();
        let bytes_ba =
            TipAdvertisement::build("comp.lang.rust", &[cid2, cid1], &ts, &peer).to_bytes();
        assert_eq!(
            bytes_ab, bytes_ba,
            "tip_cid ordering must not affect output"
        );
    }

    #[test]
    fn malformed_bytes_return_none() {
        let bytes = b"not valid json";
        assert!(TipAdvertisement::from_bytes(bytes).is_none());
    }

    #[test]
    fn handle_tip_empty_group_rejected() {
        let cid1 = make_cid(b"x");
        let ts = make_timestamp();
        let peer = make_peer_id();
        let mut advert = TipAdvertisement::build("comp.lang.rust", &[cid1], &ts, &peer);
        advert.group_name = String::new();
        let bytes = advert.to_bytes();
        assert!(handle_tip_advertisement(&bytes).is_none());
    }

    #[test]
    fn handle_tip_empty_tips_rejected() {
        let cid1 = make_cid(b"x");
        let ts = make_timestamp();
        let peer = make_peer_id();
        let mut advert = TipAdvertisement::build("comp.lang.rust", &[cid1], &ts, &peer);
        advert.tip_cids.clear();
        let bytes = advert.to_bytes();
        assert!(handle_tip_advertisement(&bytes).is_none());
    }

    #[test]
    fn handle_tip_valid_returns_some() {
        let cid1 = make_cid(b"article-valid");
        let ts = make_timestamp();
        let peer = make_peer_id();
        let advert = TipAdvertisement::build("comp.lang.rust", &[cid1], &ts, &peer);
        let bytes = advert.to_bytes();
        assert!(handle_tip_advertisement(&bytes).is_some());
    }
}
