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
        Self {
            entries: HashMap::new(),
        }
    }

    /// Return `true` if no credentials are configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build a `CredentialStore` from a credential file at `path`.
    ///
    /// File format: one `username:bcrypt_hash` per line. Blank lines and lines
    /// starting with `#` are ignored. Duplicate usernames: last wins.
    ///
    /// Returns `Err(String)` if the file cannot be read or a line is malformed.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let mut entries = HashMap::new();
        for (lineno, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (user, hash) = line
                .split_once(':')
                .ok_or_else(|| format!("{path}:{}: missing ':' separator", lineno + 1))?;
            let user = user.trim().to_ascii_lowercase();
            let hash = hash.trim().to_string();
            if user.is_empty() {
                return Err(format!("{path}:{}: empty username", lineno + 1));
            }
            entries.insert(user, hash);
        }
        Ok(Self { entries })
    }

    /// Merge credentials from a file into an existing store, overwriting
    /// any duplicate usernames with the file's version.
    pub fn merge_from_file(&mut self, path: &str) -> Result<(), String> {
        let other = Self::from_file(path)?;
        self.entries.extend(other.entries);
        Ok(())
    }

    /// Verify `username`/`password` against the stored bcrypt hashes.
    ///
    /// Always calls `bcrypt::verify` — even when the username is not found —
    /// to prevent a timing oracle on username existence. The bcrypt computation
    /// is offloaded to a blocking thread pool via `tokio::task::spawn_blocking`.
    ///
    /// Returns `false` on any error (unknown user, wrong password, malformed hash).
    pub async fn check(&self, username: &str, password: &str) -> bool {
        // Always run bcrypt::verify even for unknown usernames.  Without this,
        // a user-not-found path completes in microseconds while a known-username
        // path takes ~100ms (bcrypt work factor), leaking the username set via
        // timing measurement.  dummy_hash() returns a precomputed hash at the
        // same cost factor so verify() always performs a full computation.
        let hash = self
            .entries
            .get(&username.to_ascii_lowercase())
            .cloned()
            .unwrap_or_else(|| dummy_hash().to_string());
        let password = password.to_string();
        tokio::task::spawn_blocking(move || bcrypt::verify(&password, &hash).unwrap_or(false))
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
        assert!(
            store.check("alice", "correct-horse").await,
            "correct password must be accepted"
        );
    }

    #[tokio::test]
    async fn test_wrong_password_rejected() {
        let store = store_with_alice();
        assert!(
            !store.check("alice", "wrong-password").await,
            "wrong password must be rejected"
        );
    }

    #[tokio::test]
    async fn test_unknown_user_rejected() {
        let store = store_with_alice();
        assert!(
            !store.check("bob", "any-password").await,
            "unknown user must be rejected"
        );
    }

    #[tokio::test]
    async fn test_empty_store_rejects_all() {
        let store = CredentialStore::empty();
        assert!(
            !store.check("alice", "any-password").await,
            "empty store must reject all"
        );
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

    #[test]
    fn from_file_loads_valid_credentials() {
        let hash = bcrypt::hash("filepass", 4).expect("bcrypt::hash must not fail");
        let contents = format!("# comment\nbob:{hash}\n\nalice:dummyhash\n");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &contents).unwrap();

        let store = CredentialStore::from_file(tmp.path().to_str().unwrap())
            .expect("from_file must succeed");
        assert!(store.entries.contains_key("bob"), "bob must be loaded");
        assert!(store.entries.contains_key("alice"), "alice must be loaded");
    }

    #[test]
    fn from_file_returns_err_for_missing_file() {
        let result = CredentialStore::from_file("/nonexistent/path/creds.txt");
        assert!(
            result.is_err(),
            "from_file must return Err for missing file"
        );
    }

    #[test]
    fn from_file_returns_err_for_malformed_line() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "nocolon\n").unwrap();
        let result = CredentialStore::from_file(tmp.path().to_str().unwrap());
        assert!(
            result.is_err(),
            "from_file must return Err for line missing ':'"
        );
    }

    #[tokio::test]
    async fn merge_from_file_overrides_inline() {
        let inline_hash = bcrypt::hash("inline-pass", 4).unwrap();
        let file_hash = bcrypt::hash("file-pass", 4).unwrap();
        // Alice in inline store with inline-pass.
        let mut store = CredentialStore {
            entries: HashMap::from([("alice".to_string(), inline_hash)]),
        };
        // File has alice with file-pass (overrides) + bob.
        let contents = format!("alice:{file_hash}\nbob:{}\n", bcrypt::hash("b", 4).unwrap());
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &contents).unwrap();
        store.merge_from_file(tmp.path().to_str().unwrap()).unwrap();

        assert!(
            store.check("alice", "file-pass").await,
            "alice must use file-pass after merge"
        );
        assert!(
            store.entries.contains_key("bob"),
            "bob must be added by merge"
        );
    }
}
