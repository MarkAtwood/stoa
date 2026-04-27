//! Bcrypt-hashed credential store for AUTHINFO USER/PASS.
//!
//! Password fields in `UserCredential` must be bcrypt hashes (not plaintext).
//! A dummy hash is always verified even when the requested username is not
//! found, to prevent a timing oracle on username existence.

use std::collections::HashMap;

use crate::config::UserCredential;

/// Extract the cost factor from a bcrypt hash string.
///
/// bcrypt hashes have the form `$2b$COST$SALTANDHASH` where COST is a
/// 2-digit decimal number. Returns `None` if the format is unrecognised.
fn parse_bcrypt_cost(hash: &str) -> Option<u32> {
    // Split on '$': ["", "2b", "12", "SALTANDHASH"]
    let mut parts = hash.splitn(4, '$');
    parts.next(); // empty prefix
    let version = parts.next()?;
    if !matches!(version, "2a" | "2b" | "2x" | "2y") {
        return None;
    }
    let cost: u32 = parts.next()?.parse().ok()?;
    // bcrypt cost must be in range 4–31; reject out-of-range values early so
    // make_dummy_hash() never calls bcrypt::hash with an invalid cost.
    if !(4..=31).contains(&cost) {
        return None;
    }
    Some(cost)
}

/// Compute a dummy bcrypt hash at the same cost as the configured hashes.
///
/// Inspects the entries map and extracts the cost from the first valid bcrypt
/// hash it finds.  Falls back to `DEFAULT_COST` when no hashes are configured
/// or none can be parsed, which is safe because there is no oracle risk when
/// the store is empty (every user is "unknown").
fn make_dummy_hash(entries: &HashMap<String, String>) -> String {
    let cost = entries
        .values()
        .find_map(|h| parse_bcrypt_cost(h))
        .unwrap_or(bcrypt::DEFAULT_COST);
    bcrypt::hash("__dummy__never_matches__", cost)
        .expect("bcrypt::hash must not fail with a valid cost")
}

/// Bcrypt-hashed credential store.
///
/// Usernames are normalised to ASCII-lowercase for case-insensitive matching.
pub struct CredentialStore {
    /// Lowercase username → bcrypt hash.
    entries: HashMap<String, String>,
    /// Dummy hash used for timing-safe verification of unknown usernames.
    ///
    /// Pre-computed at the same cost as the configured production hashes so
    /// `bcrypt::verify` always runs for the same wall-clock time regardless
    /// of whether the username exists, preventing a timing oracle.
    dummy_hash: String,
}

impl CredentialStore {
    /// Build a `CredentialStore` from the operator-configured user list.
    ///
    /// The `password` field in each `UserCredential` must already be a valid
    /// bcrypt hash (not a plaintext password). Usernames are normalised to
    /// ASCII-lowercase.
    ///
    /// # Panics
    ///
    /// Panics if any `password` is not a recognised bcrypt hash (i.e. does not
    /// start with `$2a$`, `$2b$`, `$2x$`, or `$2y$` with a cost of 4–31).
    /// This is a fatal configuration error: a plaintext password would cause
    /// `bcrypt::verify` to always return `false`, making authentication silently
    /// fail for that user with no error at request time.
    pub fn from_credentials(users: &[UserCredential]) -> Self {
        for u in users {
            if parse_bcrypt_cost(&u.password).is_none() {
                panic!(
                    "stoa-auth: password for user '{}' is not a valid bcrypt hash \
                     (must start with $2a$, $2b$, $2x$, or $2y$ with a cost of 4–31); \
                     use `htpasswd -B -n {}` or `bcrypt::hash()` to generate a valid hash",
                    u.username, u.username,
                );
            }
        }
        let entries: HashMap<String, String> = users
            .iter()
            .map(|u| (u.username.to_ascii_lowercase(), u.password.clone()))
            .collect();
        let dummy_hash = make_dummy_hash(&entries);
        Self {
            entries,
            dummy_hash,
        }
    }

    /// Return an empty `CredentialStore` (no users configured; all checks fail).
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
            dummy_hash: make_dummy_hash(&HashMap::new()),
        }
    }

    /// Return `true` if no credentials are configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build a `CredentialStore` from credential file content.
    ///
    /// File format: one `username:bcrypt_hash` per line. Blank lines and lines
    /// starting with `#` are ignored. Duplicate usernames: last wins.
    ///
    /// `label` is used in error messages (typically the file path or URI).
    ///
    /// Returns `Err(String)` if a line is malformed.
    pub fn from_content(label: &str, content: &str) -> Result<Self, String> {
        let mut entries = HashMap::new();
        for (lineno, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (user, hash) = line
                .split_once(':')
                .ok_or_else(|| format!("{label}:{}: missing ':' separator", lineno + 1))?;
            let user = user.trim().to_ascii_lowercase();
            let hash = hash.trim().to_string();
            if user.is_empty() {
                return Err(format!("{label}:{}: empty username", lineno + 1));
            }
            if parse_bcrypt_cost(&hash).is_none() {
                return Err(format!(
                    "{label}:{}: password for user '{user}' is not a valid bcrypt hash \
                     (must start with $2a$, $2b$, $2x$, or $2y$ with a cost of 4–31)",
                    lineno + 1
                ));
            }
            entries.insert(user, hash);
        }
        let dummy_hash = make_dummy_hash(&entries);
        Ok(Self {
            entries,
            dummy_hash,
        })
    }

    /// Build a `CredentialStore` from a credential file at `path`.
    ///
    /// Reads the file and delegates to [`from_content`](Self::from_content).
    ///
    /// Returns `Err(String)` if the file cannot be read or a line is malformed.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        Self::from_content(path, &content)
    }

    /// Merge credentials from raw content into an existing store, overwriting
    /// any duplicate usernames with the content's version.  The dummy hash is
    /// recomputed from the merged entry set.
    ///
    /// `label` is used in error messages (typically the source path or URI).
    pub fn merge_from_content(&mut self, label: &str, content: &str) -> Result<(), String> {
        let other = Self::from_content(label, content)?;
        self.entries.extend(other.entries);
        self.dummy_hash = make_dummy_hash(&self.entries);
        Ok(())
    }

    /// Merge credentials from a file into an existing store, overwriting
    /// any duplicate usernames with the file's version.  The dummy hash is
    /// recomputed from the merged entry set.
    pub fn merge_from_file(&mut self, path: &str) -> Result<(), String> {
        let other = Self::from_file(path)?;
        self.entries.extend(other.entries);
        self.dummy_hash = make_dummy_hash(&self.entries);
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
            .unwrap_or_else(|| self.dummy_hash.clone());
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
        let entries = HashMap::from([("alice".to_string(), hash)]);
        let dummy_hash = make_dummy_hash(&entries);
        CredentialStore {
            entries,
            dummy_hash,
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
    #[should_panic(expected = "not a valid bcrypt hash")]
    fn from_credentials_panics_on_plaintext_password() {
        CredentialStore::from_credentials(&[UserCredential {
            username: "alice".to_string(),
            password: "plaintextpassword".to_string(),
        }]);
    }

    #[test]
    fn from_credentials_accepts_valid_bcrypt_hash() {
        let hash = bcrypt::hash("valid-password", 4).expect("bcrypt::hash");
        let store = CredentialStore::from_credentials(&[UserCredential {
            username: "alice".to_string(),
            password: hash,
        }]);
        assert!(store.entries.contains_key("alice"));
    }

    #[test]
    fn from_file_loads_valid_credentials() {
        let hash_bob = bcrypt::hash("filepass", 4).expect("bcrypt::hash must not fail");
        let hash_alice = bcrypt::hash("alicepass", 4).expect("bcrypt::hash must not fail");
        let contents = format!("# comment\nbob:{hash_bob}\n\nalice:{hash_alice}\n");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &contents).unwrap();

        let store = CredentialStore::from_file(tmp.path().to_str().unwrap())
            .expect("from_file must succeed");
        assert!(store.entries.contains_key("bob"), "bob must be loaded");
        assert!(store.entries.contains_key("alice"), "alice must be loaded");
    }

    #[test]
    fn from_file_returns_err_for_plaintext_password() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "alice:plaintextpassword\n").unwrap();
        let result = CredentialStore::from_file(tmp.path().to_str().unwrap());
        assert!(result.is_err(), "from_file must return Err for plaintext password");
        let msg = result.err().unwrap();
        assert!(msg.contains("not a valid bcrypt hash"), "got: {msg}");
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

    #[test]
    fn from_content_parses_valid_credential_lines() {
        let hash = bcrypt::hash("pass", 4).unwrap();
        let content = format!("alice:{hash}\n# comment\n\nbob:{hash}\n");
        let store = CredentialStore::from_content("<test>", &content).unwrap();
        assert!(store.entries.contains_key("alice"));
        assert!(store.entries.contains_key("bob"));
    }

    #[test]
    fn from_content_returns_err_for_malformed_line() {
        let result = CredentialStore::from_content("<test>", "nocolon\n");
        assert!(result.is_err(), "must fail on malformed line");
        let msg = result.err().unwrap();
        assert!(msg.contains("missing ':' separator"), "got: {msg}");
    }

    #[tokio::test]
    async fn merge_from_content_overrides_inline() {
        let inline_hash = bcrypt::hash("inline-pass", 4).unwrap();
        let file_hash = bcrypt::hash("file-pass", 4).unwrap();
        let entries = HashMap::from([("alice".to_string(), inline_hash)]);
        let dummy_hash = make_dummy_hash(&entries);
        let mut store = CredentialStore {
            entries,
            dummy_hash,
        };
        let content = format!("alice:{file_hash}\n");
        store.merge_from_content("<test>", &content).unwrap();
        // The file version should now authenticate, not the inline one.
        assert!(
            store.check("alice", "file-pass").await,
            "alice must authenticate with file-pass after merge_from_content"
        );
        assert!(
            !store.check("alice", "inline-pass").await,
            "alice must not authenticate with old inline-pass after override"
        );
    }

    #[tokio::test]
    async fn merge_from_file_overrides_inline() {
        let inline_hash = bcrypt::hash("inline-pass", 4).unwrap();
        let file_hash = bcrypt::hash("file-pass", 4).unwrap();
        // Alice in inline store with inline-pass.
        let entries = HashMap::from([("alice".to_string(), inline_hash)]);
        let dummy_hash = make_dummy_hash(&entries);
        let mut store = CredentialStore {
            entries,
            dummy_hash,
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
