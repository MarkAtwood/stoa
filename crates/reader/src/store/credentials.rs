//! Bcrypt-hashed credential store for AUTHINFO USER/PASS.
//!
//! Password fields in `UserCredential` must be bcrypt hashes (not plaintext).
//! A dummy hash is always verified even when the requested username is not
//! found, to prevent a timing oracle on username existence.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::config::UserCredential;

/// Pre-computed dummy bcrypt hash for timing-attack prevention.
///
/// Lazily initialised on first `check()` call. A real bcrypt hash at the same
/// cost as production hashes ensures `bcrypt::verify` performs a full
/// computation even when the username is unknown.
static DUMMY_HASH: OnceLock<String> = OnceLock::new();

fn dummy_hash() -> &'static str {
    DUMMY_HASH.get_or_init(|| {
        bcrypt::hash("__dummy__never_matches__", bcrypt::DEFAULT_COST)
            .expect("bcrypt::hash must not fail with a valid cost")
    })
}

/// Bcrypt-hashed credential store.
///
/// Usernames are normalised to ASCII-lowercase for case-insensitive matching.
pub struct CredentialStore {
    /// Lowercase username → bcrypt hash.
    entries: HashMap<String, String>,
}

impl CredentialStore {
    /// Build a `CredentialStore` from the operator-configured user list.
    ///
    /// The `password` field in each `UserCredential` must already be a valid
    /// bcrypt hash (not a plaintext password). Usernames are normalised to
    /// ASCII-lowercase.
    pub fn from_credentials(users: &[UserCredential]) -> Self {
        let entries = users
            .iter()
            .map(|u| (u.username.to_ascii_lowercase(), u.password.clone()))
            .collect();
        Self { entries }
    }

    /// Return an empty `CredentialStore` (no users configured; all checks fail).
    pub fn empty() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Verify `username`/`password` against the stored bcrypt hashes.
    ///
    /// Always calls `bcrypt::verify` — even when the username is not found —
    /// to prevent a timing oracle on username existence. The bcrypt computation
    /// is offloaded to a blocking thread pool via `tokio::task::spawn_blocking`.
    ///
    /// Returns `false` on any error (unknown user, wrong password, malformed hash).
    pub async fn check(&self, username: &str, password: &str) -> bool {
        let hash = self
            .entries
            .get(&username.to_ascii_lowercase())
            .cloned()
            .unwrap_or_else(|| dummy_hash().to_string());
        let password = password.to_string();
        tokio::task::spawn_blocking(move || {
            bcrypt::verify(&password, &hash).unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_alice() -> CredentialStore {
        // Cost 4 for fast tests (minimum valid bcrypt cost).
        let hash = bcrypt::hash("correct-horse", 4).expect("bcrypt::hash must not fail");
        CredentialStore {
            entries: HashMap::from([("alice".to_string(), hash)]),
        }
    }

    #[tokio::test]
    async fn test_correct_password_accepted() {
        let store = store_with_alice();
        assert!(store.check("alice", "correct-horse").await, "correct password must be accepted");
    }

    #[tokio::test]
    async fn test_wrong_password_rejected() {
        let store = store_with_alice();
        assert!(!store.check("alice", "wrong-password").await, "wrong password must be rejected");
    }

    #[tokio::test]
    async fn test_unknown_user_rejected() {
        let store = store_with_alice();
        assert!(!store.check("bob", "any-password").await, "unknown user must be rejected");
    }

    #[tokio::test]
    async fn test_empty_store_rejects_all() {
        let store = CredentialStore::empty();
        assert!(!store.check("alice", "any-password").await, "empty store must reject all");
    }

    #[tokio::test]
    async fn test_username_case_insensitive() {
        let store = store_with_alice();
        assert!(
            store.check("ALICE", "correct-horse").await,
            "uppercase username must be accepted"
        );
        assert!(
            store.check("Alice", "correct-horse").await,
            "mixed-case username must be accepted"
        );
    }
}
