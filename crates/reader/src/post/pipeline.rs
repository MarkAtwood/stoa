//! POST pipeline building blocks.
//!
//! Each function is a single stage. Stages run in order; an `Err` short-circuits
//! the rest of the pipeline and the response is sent back to the client.

use stoa_core::msgid_map::MsgIdMap;

use crate::session::response::Response;

/// Configuration for the POST pipeline.
pub struct PostPipelineConfig {
    pub max_article_bytes: usize,
}

impl Default for PostPipelineConfig {
    fn default() -> Self {
        Self {
            max_article_bytes: 1_048_576,
        }
    }
}

/// Check whether `message_id` is already in the map.
///
/// Returns `Err(441 response)` if the message-id is already known (duplicate),
/// `Ok(())` if the message-id has not been seen before.
///
/// # Dedup architecture
///
/// This is the **authoritative** dedup gate and MUST be called before any
/// signing or IPFS write.  `ipfs_write::write_article_to_ipfs` contains a
/// second identical lookup that acts as a **defensive backstop** against a
/// concurrent-request race (two POST requests that both pass this gate before
/// either commits).  Both checks must be kept: removing this one leaves no
/// early rejection for non-concurrent duplicates; removing the one in
/// `ipfs_write` opens a small race window for concurrent requests.
pub async fn check_duplicate_msgid(msgid_map: &MsgIdMap, message_id: &str) -> Result<(), Response> {
    match msgid_map.lookup_by_msgid(message_id).await {
        Ok(Some(_)) => Err(Response::new(
            441,
            "Duplicate article: Message-ID already known",
        )),
        Ok(None) => Ok(()),
        Err(_) => Err(Response::new(500, "Internal error: storage lookup failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    async fn make_msgid_map() -> MsgIdMap {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        std::mem::forget(tmp);
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
}
