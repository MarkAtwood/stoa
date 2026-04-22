//! Shared authentication configuration types.

use serde::Deserialize;

/// A single operator-configured user account.
///
/// The `password` field must be a **bcrypt hash**, never plaintext.
#[derive(Debug, Deserialize)]
pub struct UserCredential {
    pub username: String,
    /// bcrypt hash, never plaintext.
    pub password: String,
}

/// A TLS client certificate pinned to a username.
///
/// When a client presents a certificate whose SHA-256 fingerprint matches
/// `sha256_fingerprint`, the session is authenticated as `username` without
/// requiring a password. Only valid on NNTPS (port 563) connections.
#[derive(Debug, Deserialize, Clone)]
pub struct ClientCertEntry {
    /// SHA-256 fingerprint of the leaf certificate DER, formatted as
    /// `"sha256:<64-hex-chars>"`.  Case-insensitive on input; stored
    /// in normalised lowercase form.
    pub sha256_fingerprint: String,
    /// Username to authenticate when this certificate is presented.
    pub username: String,
}

/// A trusted CA issuer for client certificate authentication.
///
/// When a client presents a certificate signed by this CA, the leaf
/// certificate's Common Name (CN) is used as the authenticated username.
/// Only valid on NNTPS (port 563) connections.
#[derive(Debug, Deserialize, Clone)]
pub struct TrustedIssuerEntry {
    /// Path to a PEM-encoded CA certificate.  The CA's SubjectPublicKeyInfo
    /// (SPKI) is extracted at startup and used for Ed25519 signature
    /// verification.
    pub cert_path: String,
}

/// Authentication configuration shared across NNTP, JMAP, and SMTP services.
#[derive(Debug, Default, Deserialize)]
pub struct AuthConfig {
    pub required: bool,
    /// User accounts for authentication.
    ///
    /// If empty and `required = false` and `credential_file` is unset, all
    /// credential attempts succeed (development mode).
    #[serde(default)]
    pub users: Vec<UserCredential>,
    /// Path to a file of `username:bcrypt_hash` credential pairs.
    ///
    /// Each non-blank, non-comment line must be `username:$2b$...`. Lines
    /// starting with `#` are ignored. Loaded at startup and merged with the
    /// inline `users` list.
    #[serde(default)]
    pub credential_file: Option<String>,
    /// TLS client certificate pins.
    ///
    /// Each entry maps a certificate SHA-256 fingerprint to a username.
    /// When a client presents a matching certificate over TLS, the session
    /// is authenticated without a password exchange.
    #[serde(default)]
    pub client_certs: Vec<ClientCertEntry>,
    /// Trusted CA issuers for client certificate chain authentication.
    ///
    /// When a client presents a certificate signed by one of these CAs, the
    /// leaf certificate's CN is used as the username — no password required.
    /// Takes effect only after fingerprint-based auth has been attempted first.
    #[serde(default)]
    pub trusted_issuers: Vec<TrustedIssuerEntry>,
}

impl AuthConfig {
    /// Returns `true` when no credentials are configured and auth is not
    /// required — the development / open-access mode.
    pub fn is_dev_mode(&self) -> bool {
        !self.required && self.users.is_empty() && self.credential_file.is_none()
    }
}
