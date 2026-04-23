//! Background task: publish a signed IPNS record after each article ingestion.
//!
//! The record points to a JSON index block that maps every active newsgroup to
//! its most-recently-ingested article CID.  The stable IPNS address is the
//! node's libp2p peer identity key (one address per node).
//!
//! Resolvers: IPNS → index CID → fetch JSON block → look up group by name.
//!
//! Rate limiting: a minimum interval between consecutive publishes prevents
//! excessive DHT traffic on high-volume ingestion nodes.

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use rust_ipfs::path::IpfsPath;

/// Event sent by the drain task each time an article is successfully ingested.
pub struct IpnsEvent {
    /// Primary newsgroup the article was appended to.
    pub group: String,
    /// Article block CID (the most-recently-ingested CID for this group).
    pub cid: Cid,
}

/// Background worker that maintains a per-group CID index and publishes it via IPNS.
pub struct IpnsPublisher {
    ipfs: rust_ipfs::Ipfs,
    /// Most-recently-seen CID per group, in alphabetical order.
    groups: BTreeMap<String, Cid>,
    /// Minimum milliseconds between consecutive IPNS publishes.
    republish_interval_ms: u64,
    /// Wall-clock time of the last successful publish (ms since UNIX epoch).
    last_publish_ms: u64,
}

impl IpnsPublisher {
    pub fn new(ipfs: rust_ipfs::Ipfs, republish_interval_secs: u64) -> Self {
        Self {
            ipfs,
            groups: BTreeMap::new(),
            republish_interval_ms: republish_interval_secs.saturating_mul(1000),
            last_publish_ms: 0,
        }
    }

    /// Receive ingestion events and publish the IPNS index on each one,
    /// subject to the configured rate limit.
    pub async fn run(mut self, mut rx: mpsc::Receiver<IpnsEvent>) {
        info!("IPNS publisher started");
        while let Some(event) = rx.recv().await {
            self.groups.insert(event.group.clone(), event.cid);
            let now_ms = now_ms();
            if now_ms.saturating_sub(self.last_publish_ms) >= self.republish_interval_ms {
                self.update_and_publish().await;
                self.last_publish_ms = now_ms;
            } else {
                debug!(group = %event.group, "IPNS publish skipped (rate limit)");
            }
        }
        info!("IPNS publisher stopped");
    }

    /// Build the JSON index, store it as an IPFS block, then publish IPNS.
    async fn update_and_publish(&self) {
        let json_bytes = build_index_json(&self.groups);
        let digest = Code::Sha2_256.digest(&json_bytes);
        let index_cid = Cid::new_v1(0x55, digest);

        let block = match rust_ipfs::Block::new(index_cid, json_bytes) {
            Ok(b) => b,
            Err(e) => {
                warn!("IPNS publisher: failed to construct index block: {e}");
                return;
            }
        };

        if let Err(e) = self.ipfs.put_block(&block).await {
            warn!("IPNS publisher: failed to store index block: {e}");
            return;
        }

        let path = IpfsPath::from(index_cid);
        match self.ipfs.publish_ipns(&path).await {
            Ok(ipns_path) => {
                info!(
                    groups = self.groups.len(),
                    ipns = %ipns_path,
                    index_cid = %index_cid,
                    "IPNS index published"
                );
            }
            Err(e) => {
                warn!("IPNS publisher: publish_ipns failed: {e}");
            }
        }
    }
}

/// Build the JSON group index as UTF-8 bytes.
///
/// Format: `{"version":1,"groups":{"comp.lang.rust":"<cid>",...}}`
///
/// Keys are sorted because `BTreeMap` iterates in alphabetical order, which
/// produces a deterministic byte sequence for the same group/CID set.
/// Determinism matters because the CID of the index block is content-addressed.
pub fn build_index_json(groups: &BTreeMap<String, Cid>) -> Vec<u8> {
    let mut out = String::from(r#"{"version":1,"groups":{"#);
    let mut first = true;
    for (group, cid) in groups {
        if !first {
            out.push(',');
        }
        first = false;
        // JSON-encode group name (may contain dots; no special chars in newsgroup names)
        out.push('"');
        out.push_str(group);
        out.push_str(r#"":""#);
        out.push_str(&cid.to_string());
        out.push('"');
    }
    out.push_str("}}");
    out.into_bytes()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn make_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x55, digest)
    }

    /// Empty group map produces a fixed known byte sequence.
    ///
    /// Oracle: hand-constructed JSON string.
    #[test]
    fn build_index_json_empty_groups() {
        let groups = BTreeMap::new();
        let json = build_index_json(&groups);
        assert_eq!(
            json,
            br#"{"version":1,"groups":{}}"#.to_vec(),
            "empty groups must produce exactly the expected JSON bytes"
        );
    }

    /// Single group produces correct JSON with version and groups keys.
    ///
    /// Oracle: hand-constructed expected string.
    #[test]
    fn build_index_json_single_group() {
        let mut groups = BTreeMap::new();
        // Use a known CID by constructing it from known data.
        let cid = make_cid(b"test block");
        groups.insert("comp.lang.rust".to_string(), cid);

        let json = build_index_json(&groups);
        let s = std::str::from_utf8(&json).unwrap();

        assert!(s.starts_with(r#"{"version":1,"groups":{"#), "JSON must start with correct prefix");
        assert!(s.ends_with("}}"), "JSON must end with double closing brace");
        assert!(
            s.contains(r#""comp.lang.rust":""#),
            "JSON must contain the group name as key"
        );
        assert!(
            s.contains(&cid.to_string()),
            "JSON must contain the CID string"
        );
    }

    /// Two groups produce alphabetically-ordered keys (BTreeMap ordering).
    ///
    /// Oracle: hand-constructed expected JSON; "alt.test" < "comp.lang.rust" alphabetically.
    #[test]
    fn build_index_json_key_order_is_alphabetical() {
        let mut groups = BTreeMap::new();
        let cid_comp = make_cid(b"comp block");
        let cid_alt = make_cid(b"alt block");
        // Insert in reverse alphabetical order to test BTreeMap sorting.
        groups.insert("comp.lang.rust".to_string(), cid_comp);
        groups.insert("alt.test".to_string(), cid_alt);

        let json = build_index_json(&groups);
        let s = std::str::from_utf8(&json).unwrap();

        let alt_pos = s.find("alt.test").expect("alt.test must appear in output");
        let comp_pos = s.find("comp.lang.rust").expect("comp.lang.rust must appear in output");
        assert!(
            alt_pos < comp_pos,
            "alt.test must appear before comp.lang.rust (alphabetical ordering)"
        );
    }

    /// JSON output is valid UTF-8 and can be parsed by serde_json.
    ///
    /// Oracle: serde_json parse of the known structure.
    #[test]
    fn build_index_json_is_valid_json() {
        let mut groups = BTreeMap::new();
        groups.insert("sci.math".to_string(), make_cid(b"sci block"));
        groups.insert("comp.test".to_string(), make_cid(b"comp block"));

        let json = build_index_json(&groups);
        let v: serde_json::Value = serde_json::from_slice(&json)
            .expect("build_index_json must produce valid JSON");

        assert_eq!(v["version"], 1, "version must be 1");
        assert!(v["groups"].is_object(), "groups must be a JSON object");
        assert_eq!(
            v["groups"].as_object().unwrap().len(),
            2,
            "groups must have 2 entries"
        );
    }
}
