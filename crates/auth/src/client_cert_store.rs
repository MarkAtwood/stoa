//! Certificate-fingerprint-based authentication store.
//!
//! Maps SHA-256 fingerprints of TLS client certificate DER bytes to usernames.
//! Fingerprint matching happens at the application layer after the TLS handshake;
//! the TLS layer accepts (but does not require) any client certificate.

use std::collections::HashMap;

use crate::config::ClientCertEntry;

/// Maps normalised SHA-256 certificate fingerprints to usernames.
///
/// Fingerprints are stored and matched in canonical form:
/// `"sha256:<64-lowercase-hex-chars>"`.
pub struct ClientCertStore {
    /// Normalised fingerprint → lowercase username.
    entries: HashMap<String, String>,
}

/// Normalise a fingerprint to canonical form `"sha256:<lowercase-hex>"`.
///
/// Accepts input with or without the `"sha256:"` prefix, and any case.
fn normalise(fp: &str) -> String {
    let lower = fp.to_ascii_lowercase();
    let hex_part = lower
        .strip_prefix("sha256:")
        .unwrap_or(&lower);
    format!("sha256:{hex_part}")
}

impl ClientCertStore {
    /// Build a `ClientCertStore` from the operator-configured certificate list.
    pub fn from_config(entries: &[ClientCertEntry]) -> Self {
        let map = entries
            .iter()
            .map(|e| {
                (
                    normalise(&e.sha256_fingerprint),
                    e.username.to_ascii_lowercase(),
                )
            })
            .collect();
        Self { entries: map }
    }

    /// Return an empty store (no certificates configured).
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Look up the username for a given fingerprint.
    ///
    /// `fingerprint` must be in the form `"sha256:<64-lowercase-hex-chars>"`,
    /// as produced by the TLS layer after computing SHA-256 of the leaf
    /// certificate DER bytes.
    ///
    /// Returns `None` when no matching entry is configured.
    pub fn lookup(&self, fingerprint: &str) -> Option<&str> {
        self.entries
            .get(&normalise(fingerprint))
            .map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fp: &str, user: &str) -> ClientCertEntry {
        ClientCertEntry {
            sha256_fingerprint: fp.to_string(),
            username: user.to_string(),
        }
    }

    #[test]
    fn lookup_exact_fingerprint() {
        let fp = "sha256:aabbccdd".repeat(1); // short for test
        let store = ClientCertStore::from_config(&[entry(&fp, "alice")]);
        assert_eq!(store.lookup(&fp), Some("alice"));
    }

    #[test]
    fn lookup_fingerprint_without_prefix() {
        let store = ClientCertStore::from_config(&[entry("sha256:aabbcc", "alice")]);
        assert_eq!(store.lookup("aabbcc"), Some("alice"));
    }

    #[test]
    fn lookup_fingerprint_case_insensitive() {
        let store = ClientCertStore::from_config(&[entry("sha256:AABBCC", "alice")]);
        assert_eq!(store.lookup("sha256:aabbcc"), Some("alice"));
    }

    #[test]
    fn lookup_unknown_fingerprint_returns_none() {
        let store = ClientCertStore::from_config(&[entry("sha256:aabbcc", "alice")]);
        assert_eq!(store.lookup("sha256:deadbeef"), None);
    }

    #[test]
    fn empty_store_returns_none() {
        let store = ClientCertStore::empty();
        assert_eq!(store.lookup("sha256:aabbcc"), None);
    }

    #[test]
    fn username_is_lowercased() {
        let store = ClientCertStore::from_config(&[entry("sha256:aabbcc", "ALICE")]);
        assert_eq!(store.lookup("sha256:aabbcc"), Some("alice"));
    }
}
