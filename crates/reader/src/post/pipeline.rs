//! POST pipeline building blocks.
//!
//! Each function is a single stage. Stages run in order; an `Err` short-circuits
//! the rest of the pipeline and the response is sent back to the client.

use crate::session::response::Response;
use usenet_ipfs_core::msgid_map::MsgIdMap;

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
}
