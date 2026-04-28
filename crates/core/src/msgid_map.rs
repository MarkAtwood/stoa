//! Multi-backend bidirectional Message-ID ↔ CID mapping store.

use cid::Cid;
use sqlx::AnyPool;

use crate::error::StorageError;

/// Bidirectional mapping between Usenet Message-IDs and IPFS CIDs.
///
/// CIDs are stored as raw bytes (`cid.to_bytes()`).
pub struct MsgIdMap {
    pool: AnyPool,
}

impl MsgIdMap {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Insert a Message-ID → CID mapping.
    ///
    /// - If the `message_id` does not exist: insert and return `Ok(())`.
    /// - If it exists with the same CID: return `Ok(())` (idempotent).
    /// - If it exists with a different CID: return `Err(StorageError::Database(...))`.
    ///
    /// Uses `ON CONFLICT DO NOTHING` so concurrent callers with the same
    /// `(message_id, cid)` pair (e.g. two IHAVE sessions for the same article)
    /// are both handled without a UNIQUE constraint error.
    pub async fn insert(&self, message_id: &str, cid: &Cid) -> Result<(), StorageError> {
        let cid_bytes = cid.to_bytes();

        // Atomic insert: if message_id already exists the row is left unchanged
        // and rows_affected() returns 0.  This avoids the SELECT→INSERT TOCTOU
        // where two concurrent callers both see no row, then one fails with a
        // UNIQUE constraint violation.
        let result = sqlx::query(
            "INSERT INTO msgid_map (message_id, cid) VALUES (?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(message_id)
        .bind(&cid_bytes)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        if result.rows_affected() == 1 {
            // We inserted the row — no collision possible.
            return Ok(());
        }

        // Row already existed (INSERT was a no-op).  Fetch the stored CID to
        // decide between idempotent same-CID and a genuine collision.
        let stored_bytes: Vec<u8> =
            sqlx::query_scalar("SELECT cid FROM msgid_map WHERE message_id = ?")
                .bind(message_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| StorageError::Database(e.to_string()))?;

        if stored_bytes == cid_bytes {
            Ok(())
        } else {
            // Two distinct articles share a Message-ID.  This is either a
            // bug in the sender, a deliberate replay/injection attempt, or
            // a hash collision (negligible probability).  Log it so operators
            // can detect and investigate duplicate-ID injection.
            tracing::warn!(
                message_id,
                "Message-ID collision: already mapped to a different CID"
            );
            Err(StorageError::Database(format!(
                "message-id {message_id:?} already mapped to a different CID"
            )))
        }
    }

    /// Look up a CID by Message-ID. Returns `None` if not found.
    pub async fn lookup_by_msgid(&self, message_id: &str) -> Result<Option<Cid>, StorageError> {
        let row: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT cid FROM msgid_map WHERE message_id = ?")
                .bind(message_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::Database(e.to_string()))?;

        match row {
            None => Ok(None),
            Some(bytes) => {
                let cid = Cid::try_from(bytes.as_slice())
                    .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(Some(cid))
            }
        }
    }

    /// Look up a Message-ID by CID. Returns `None` if not found.
    pub async fn lookup_by_cid(&self, cid: &Cid) -> Result<Option<String>, StorageError> {
        let cid_bytes = cid.to_bytes();

        let row: Option<String> =
            sqlx::query_scalar("SELECT message_id FROM msgid_map WHERE cid = ?")
                .bind(&cid_bytes)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row)
    }

    /// Remove all `msgid_map` entries whose CID matches `cid`.
    ///
    /// Idempotent: deleting a CID that has no mapping returns `Ok(())`.
    /// Used by the GC pipeline after a successful IPFS unpin to prevent
    /// the message-id from blocking re-ingestion of the same article from
    /// another peer.
    pub async fn delete_by_cid(&self, cid: &Cid) -> Result<(), StorageError> {
        let cid_bytes = cid.to_bytes();
        sqlx::query("DELETE FROM msgid_map WHERE cid = ?")
            .bind(&cid_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_pool::try_open_any_pool;
    use multihash_codetable::{Code, MultihashDigest};

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        // Each test needs an isolated database.  Using a unique temp file
        // per test gives true isolation across concurrent test runs.
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = try_open_any_pool(&url, 1).await.unwrap();
        (pool, tmp)
    }

    fn test_cid(data: &[u8]) -> Cid {
        Cid::new_v1(crate::ipld::codec::CODEC_RAW, Code::Sha2_256.digest(data))
    }

    #[tokio::test]
    async fn insert_and_lookup_by_msgid() {
        let (pool, _tmp) = make_pool().await;
        let store = MsgIdMap::new(pool);
        let cid = test_cid(b"test-article-data");
        let msgid = "<test@example.com>";

        store.insert(msgid, &cid).await.unwrap();

        let found = store.lookup_by_msgid(msgid).await.unwrap();
        assert_eq!(found, Some(cid));
    }

    #[tokio::test]
    async fn lookup_by_cid() {
        let (pool, _tmp) = make_pool().await;
        let store = MsgIdMap::new(pool);
        let cid = test_cid(b"lookup-by-cid-data");
        let msgid = "<lookup@example.com>";

        store.insert(msgid, &cid).await.unwrap();

        let found = store.lookup_by_cid(&cid).await.unwrap();
        assert_eq!(found.as_deref(), Some(msgid));
    }

    #[tokio::test]
    async fn lookup_missing_returns_none() {
        let (pool, _tmp) = make_pool().await;
        let store = MsgIdMap::new(pool);

        let by_msgid = store
            .lookup_by_msgid("<notfound@example.com>")
            .await
            .unwrap();
        assert!(by_msgid.is_none());

        let phantom_cid = test_cid(b"phantom");
        let by_cid = store.lookup_by_cid(&phantom_cid).await.unwrap();
        assert!(by_cid.is_none());
    }

    #[tokio::test]
    async fn duplicate_same_cid_is_idempotent() {
        let (pool, _tmp) = make_pool().await;
        let store = MsgIdMap::new(pool);
        let cid = test_cid(b"idempotent-data");
        let msgid = "<idem@example.com>";

        store.insert(msgid, &cid).await.unwrap();
        store.insert(msgid, &cid).await.unwrap();

        let found = store.lookup_by_msgid(msgid).await.unwrap();
        assert_eq!(found, Some(cid));
    }

    #[tokio::test]
    async fn delete_by_cid_removes_mapping() {
        let (pool, _tmp) = make_pool().await;
        let store = MsgIdMap::new(pool);
        let cid = test_cid(b"delete-test");
        let msgid = "<delete@example.com>";

        store.insert(msgid, &cid).await.unwrap();
        assert!(store.lookup_by_msgid(msgid).await.unwrap().is_some());

        store.delete_by_cid(&cid).await.unwrap();

        assert!(store.lookup_by_msgid(msgid).await.unwrap().is_none());
        assert!(store.lookup_by_cid(&cid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_by_cid_is_idempotent() {
        let (pool, _tmp) = make_pool().await;
        let store = MsgIdMap::new(pool);
        let cid = test_cid(b"idempotent-delete");
        // Delete a CID that was never inserted — must not error.
        store.delete_by_cid(&cid).await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_different_cid_returns_error() {
        let (pool, _tmp) = make_pool().await;
        let store = MsgIdMap::new(pool);
        let cid1 = test_cid(b"first-article");
        let cid2 = test_cid(b"second-article");
        let msgid = "<conflict@example.com>";

        store.insert(msgid, &cid1).await.unwrap();

        let result = store.insert(msgid, &cid2).await;
        assert!(
            matches!(result, Err(StorageError::Database(ref msg)) if msg.contains("already mapped to a different CID")),
            "expected Database error, got: {result:?}"
        );
    }
}
