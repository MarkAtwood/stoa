//! POST pipeline building blocks.
//!
//! Each function is a single stage. Stages run in order; an `Err` short-circuits
//! the rest of the pipeline and the response is sent back to the client.

use cid::Cid;
use serde::Serialize;
use tokio::sync::mpsc;
use usenet_ipfs_core::article::GroupName;
use usenet_ipfs_core::hlc::HlcTimestamp;
use usenet_ipfs_core::msgid_map::MsgIdMap;

use crate::session::response::Response;

/// Wire-format tip advertisement, compatible with transit's TipAdvertisement.
/// Field names must match exactly for interoperability.
#[derive(Serialize)]
struct TipAdvert<'a> {
    group_name: &'a str,
    tip_cids: Vec<String>,
    hlc_ms: u64,
    hlc_logical: u32,
    hlc_node_id: String,
    sender_peer_id: &'a str,
}

/// Publish tip advertisements for each group after a successful POST.
///
/// Sends one TipAdvertisement per group to the gossipsub channel.
/// If the channel is `None` or send fails, logs a warning and continues —
/// gossipsub propagation is best-effort and must not cause POST failure.
///
/// Topic naming: `usenet.hier.<hierarchy>` where hierarchy is the first
/// component of the group name (e.g. `comp.lang.rust` → `usenet.hier.comp`).
pub async fn publish_tips_after_post(
    gossip_tx: &Option<mpsc::Sender<(String, Vec<u8>)>>,
    newsgroups: &[GroupName],
    tip_cid: &Cid,
    timestamp: &HlcTimestamp,
    sender_peer_id: &str,
) {
    let tx = match gossip_tx {
        Some(tx) => tx,
        None => return,
    };

    let tip_str = tip_cid.to_string();
    let node_id_hex = hex::encode(timestamp.node_id);

    for group in newsgroups {
        let group_str = group.as_str();
        let hierarchy = group_str.split('.').next().unwrap_or(group_str);
        let topic = format!("usenet.hier.{hierarchy}");

        let advert = TipAdvert {
            group_name: group_str,
            tip_cids: vec![tip_str.clone()],
            hlc_ms: timestamp.wall_ms,
            hlc_logical: timestamp.logical,
            hlc_node_id: node_id_hex.clone(),
            sender_peer_id,
        };

        match serde_json::to_vec(&advert) {
            Err(e) => {
                tracing::warn!(group = %group_str, "failed to serialize tip advertisement: {e}");
            }
            Ok(bytes) => {
                if let Err(e) = tx.send((topic, bytes)).await {
                    tracing::warn!(group = %group_str, "gossipsub send failed: {e}");
                }
            }
        }
    }
}

/// Configuration for the POST pipeline.
pub struct PostPipelineConfig {
    pub max_article_bytes: usize,
}

impl Default for PostPipelineConfig {
    fn default() -> Self {
        Self { max_article_bytes: 1_048_576 }
    }
}

/// Check whether `message_id` is already in the map.
///
/// Returns `Err(441 response)` if the message-id is already known (duplicate),
/// `Ok(())` if the message-id has not been seen before.
///
/// This check MUST happen before any signing or IPFS write.
pub async fn check_duplicate_msgid(
    msgid_map: &MsgIdMap,
    message_id: &str,
) -> Result<(), Response> {
    match msgid_map.lookup_by_msgid(message_id).await {
        Ok(Some(_)) => Err(Response::new(441, "441 Duplicate article: Message-ID already known")),
        Ok(None) => Ok(()),
        Err(_) => Err(Response::new(500, "500 Internal error: storage lookup failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    async fn make_msgid_map() -> MsgIdMap {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        usenet_ipfs_core::migrations::run_migrations(&pool).await.unwrap();
        MsgIdMap::new(pool)
    }

    fn test_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x55, Code::Sha2_256.digest(data))
    }

    #[tokio::test]
    async fn unknown_msgid_returns_ok() {
        let map = make_msgid_map().await;
        let result = check_duplicate_msgid(&map, "<unknown@example.com>").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn known_msgid_returns_441() {
        let map = make_msgid_map().await;
        let cid = test_cid(b"some-article-content");
        map.insert("<known@example.com>", &cid).await.unwrap();

        let result = check_duplicate_msgid(&map, "<known@example.com>").await;
        let err = result.unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("Duplicate"),
            "expected 'Duplicate' in text, got: {:?}",
            err.text
        );
    }

    #[tokio::test]
    async fn duplicate_response_code_is_441() {
        let map = make_msgid_map().await;
        let cid = test_cid(b"another-article-content");
        map.insert("<dup@example.com>", &cid).await.unwrap();

        let result = check_duplicate_msgid(&map, "<dup@example.com>").await;
        let err = result.unwrap_err();
        assert_eq!(err.code, 441);
    }

    // ── publish_tips_after_post ───────────────────────────────────────────────

    use usenet_ipfs_core::article::GroupName;
    use usenet_ipfs_core::hlc::HlcTimestamp;

    fn test_cid_dag(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    fn make_timestamp() -> HlcTimestamp {
        HlcTimestamp { wall_ms: 1700000000000, logical: 0, node_id: [1, 2, 3, 4, 5, 6, 7, 8] }
    }

    #[tokio::test]
    async fn no_gossip_tx_is_noop() {
        let groups = vec![GroupName::new("comp.lang.rust").unwrap()];
        let cid = test_cid_dag(b"article");
        let ts = make_timestamp();
        publish_tips_after_post(&None, &groups, &cid, &ts, "12D3abc").await;
    }

    #[tokio::test]
    async fn publishes_one_message_per_group() {
        let (tx, mut rx) = mpsc::channel(10);
        let groups = vec![
            GroupName::new("comp.lang.rust").unwrap(),
            GroupName::new("sci.math").unwrap(),
        ];
        let cid = test_cid_dag(b"article");
        let ts = make_timestamp();
        publish_tips_after_post(&Some(tx), &groups, &cid, &ts, "12D3abc").await;

        let msg1 = rx.try_recv().expect("should have message for comp.lang.rust");
        let msg2 = rx.try_recv().expect("should have message for sci.math");
        assert!(rx.try_recv().is_err(), "should have exactly 2 messages");

        assert_eq!(msg1.0, "usenet.hier.comp");
        assert_eq!(msg2.0, "usenet.hier.sci");

        let v1: serde_json::Value = serde_json::from_slice(&msg1.1).expect("must be valid JSON");
        assert_eq!(v1["group_name"], "comp.lang.rust");
        assert!(!v1["tip_cids"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn topic_uses_first_component_as_hierarchy() {
        let (tx, mut rx) = mpsc::channel(10);
        let groups = vec![GroupName::new("alt.binaries.test").unwrap()];
        let cid = test_cid_dag(b"article");
        let ts = make_timestamp();
        publish_tips_after_post(&Some(tx), &groups, &cid, &ts, "12D3abc").await;
        let (topic, _) = rx.try_recv().expect("should have a message");
        assert_eq!(topic, "usenet.hier.alt");
    }
}
