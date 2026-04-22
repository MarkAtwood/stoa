use rand::RngCore as _;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::sync::Arc;

/// Metadata returned when listing tokens for a user.
/// The raw token and its hash are never exposed here.
pub struct TokenInfo {
    pub id: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// Persistent store for bearer tokens.
///
/// Raw tokens are never stored.  Only the SHA-256 hash of the 32-byte
/// random token is written to the database.  The raw token (base64url
/// encoded) is returned only at issuance time and can never be recovered.
pub struct TokenStore {
    pool: Arc<SqlitePool>,
}

impl TokenStore {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }

    /// Issue a new bearer token for `username`.
    ///
    /// Returns `(raw_token_base64url, id, expires_at_unix_secs)`.
    /// The caller must surface `raw_token_base64url` to the user once;
    /// it cannot be retrieved again.
    pub async fn issue(
        &self,
        username: &str,
        label: Option<String>,
        expires_in_days: Option<i64>,
    ) -> Result<(String, String, Option<i64>), sqlx::Error> {
        // Generate 32 cryptographically random bytes.
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);

        // base64url-encode (no padding) for the token value returned to the caller.
        let raw_b64url = data_encoding::BASE64URL_NOPAD.encode(&raw);

        // SHA-256 hash for storage.
        let hash: Vec<u8> = Sha256::digest(raw).to_vec();

        let id = uuid::Uuid::new_v4().to_string();

        let now_secs: i64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs() as i64;

        let expires_at: Option<i64> =
            expires_in_days.map(|days| now_secs + days * 86_400);

        sqlx::query(
            "INSERT INTO bearer_tokens (id, token_hash, username, label, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&hash)
        .bind(username)
        .bind(&label)
        .bind(now_secs)
        .bind(expires_at)
        .execute(self.pool.as_ref())
        .await?;

        Ok((raw_b64url, id, expires_at))
    }

    /// Verify a raw base64url-encoded token.
    ///
    /// Returns `Some(username)` if the token exists and has not expired.
    /// Returns `Ok(None)` for any invalid, unknown, or expired token —
    /// never leaks *why* verification failed.
    pub async fn verify(&self, raw_token_b64url: &str) -> Result<Option<String>, sqlx::Error> {
        let raw = match data_encoding::BASE64URL_NOPAD.decode(raw_token_b64url.as_bytes()) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };

        let hash: Vec<u8> = Sha256::digest(raw).to_vec();

        let now_secs: i64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs() as i64;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT username FROM bearer_tokens
             WHERE token_hash = ?
               AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(&hash)
        .bind(now_secs)
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(row.map(|(username,)| username))
    }

    /// List all tokens for a user.  The raw token and hash are not included.
    pub async fn list(&self, username: &str) -> Result<Vec<TokenInfo>, sqlx::Error> {
        let rows: Vec<(String, Option<String>, i64, Option<i64>)> = sqlx::query_as(
            "SELECT id, label, created_at, expires_at
             FROM bearer_tokens
             WHERE username = ?
             ORDER BY created_at ASC",
        )
        .bind(username)
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, label, created_at, expires_at)| TokenInfo {
                id,
                label,
                created_at,
                expires_at,
            })
            .collect())
    }

    /// Revoke the token with `token_id` if it is owned by `username`.
    ///
    /// Returns `true` if a row was deleted, `false` if not found or not owned
    /// by `username`.
    pub async fn revoke(&self, username: &str, token_id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM bearer_tokens WHERE id = ? AND username = ?",
        )
        .bind(token_id)
        .bind(username)
        .execute(self.pool.as_ref())
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

    async fn make_store() -> TokenStore {
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:token_store_test_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("pool");
        crate::migrations::run_migrations(&pool).await.expect("migrations");
        TokenStore::new(Arc::new(pool))
    }

    #[tokio::test]
    async fn issue_and_verify_token() {
        let store = make_store().await;
        let (raw, _id, _expires) = store.issue("alice", None, None).await.unwrap();
        let username = store.verify(&raw).await.unwrap();
        assert_eq!(username, Some("alice".to_string()));
    }

    #[tokio::test]
    async fn verify_unknown_token_returns_none() {
        let store = make_store().await;
        // Issue one token so the table is non-empty, then verify a different one.
        store.issue("alice", None, None).await.unwrap();
        // Generate a fresh random token that was never issued.
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let unknown = data_encoding::BASE64URL_NOPAD.encode(&raw);
        let result = store.verify(&unknown).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn verify_invalid_base64_returns_none() {
        let store = make_store().await;
        let result = store.verify("not!!valid base64url").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn expired_token_returns_none() {
        let store = make_store().await;
        let (raw, _id, _expires) = store.issue("alice", None, Some(-1)).await.unwrap();
        let result = store.verify(&raw).await.unwrap();
        assert_eq!(result, None, "expired token must not authenticate");
    }

    #[tokio::test]
    async fn list_tokens_excludes_hash() {
        let store = make_store().await;
        let (_raw1, id1, _) = store.issue("alice", Some("cli".to_string()), None).await.unwrap();
        let (_raw2, id2, _) = store.issue("alice", None, None).await.unwrap();
        let tokens = store.list("alice").await.unwrap();
        assert_eq!(tokens.len(), 2);
        let ids: Vec<&str> = tokens.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&id1.as_str()));
        assert!(ids.contains(&id2.as_str()));
        let labeled = tokens.iter().find(|t| t.id == id1).unwrap();
        assert_eq!(labeled.label.as_deref(), Some("cli"));
    }

    #[tokio::test]
    async fn revoke_own_token() {
        let store = make_store().await;
        let (raw, id, _) = store.issue("alice", None, None).await.unwrap();
        let deleted = store.revoke("alice", &id).await.unwrap();
        assert!(deleted);
        let result = store.verify(&raw).await.unwrap();
        assert_eq!(result, None, "revoked token must not authenticate");
    }

    #[tokio::test]
    async fn revoke_other_users_token_returns_false() {
        let store = make_store().await;
        let (_raw, id, _) = store.issue("alice", None, None).await.unwrap();
        let deleted = store.revoke("bob", &id).await.unwrap();
        assert!(!deleted, "bob must not revoke alice's token");
    }

    #[tokio::test]
    async fn revoke_nonexistent_token_returns_false() {
        let store = make_store().await;
        let deleted = store.revoke("alice", "no-such-id").await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn list_returns_only_own_tokens() {
        let store = make_store().await;
        store.issue("alice", None, None).await.unwrap();
        store.issue("bob", None, None).await.unwrap();
        let alice_tokens = store.list("alice").await.unwrap();
        assert_eq!(alice_tokens.len(), 1);
        let bob_tokens = store.list("bob").await.unwrap();
        assert_eq!(bob_tokens.len(), 1);
    }
}
