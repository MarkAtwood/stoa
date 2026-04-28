//! Shared authentication types and credential store for stoa services.
//!
//! This crate is used by the reader (NNTP AUTHINFO), mail (JMAP), and SMTP
//! services. It is a pure library crate with no binary.

pub mod client_cert_store;
pub mod config;
pub mod oidc;
pub mod store;
pub mod trusted_issuer_store;

pub use client_cert_store::ClientCertStore;
pub use config::{AuthConfig, ClientCertEntry, OidcProviderConfig, TrustedIssuerEntry, UserCredential};
pub use oidc::{OidcError, OidcStore};
pub use store::CredentialStore;
pub use trusted_issuer_store::TrustedIssuerStore;

/// Compute the SHA-256 fingerprint of a certificate DER encoding.
///
/// Returns `"sha256:<64-lowercase-hex-chars>"`, the same format used as keys
/// in `ClientCertStore` and as the wire format in the session context.
pub fn compute_fingerprint(der: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(der);
    format!("sha256:{}", hex::encode(digest))
}
