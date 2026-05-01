//! HTTP Signatures (draft-cavage-http-signatures) for ActivityPub outbound delivery.
//!
//! Implements RSA-SHA256 signatures for Mastodon-compatible federation.
//!
//! # Signing
//!
//! `sign_headers` produces a `Signature:` header value suitable for outbound
//! POST requests to remote ActivityPub inboxes.  The signed components are:
//! `(request-target)`, `host`, `date`, and `digest` (SHA-256 of body).
//!
//! # Keys
//!
//! `RsaActorKey` wraps an RSA-2048 key pair.  Call `generate()` for a new key
//! or `from_pem(pem)` to load an existing one.  `public_key_pem()` returns the
//! PEM-encoded public key for inclusion in the Actor document.

use data_encoding::BASE64;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding},
    pkcs1v15::SigningKey,
    RsaPrivateKey,
};
use sha2::{Digest, Sha256};
use std::fmt;

/// RSA key pair used for HTTP Signatures on outbound ActivityPub requests.
#[derive(Clone)]
pub struct RsaActorKey {
    /// Key identifier URL, e.g. `https://example.com/ap/groups/comp.lang.rust#main-key`.
    pub key_id: String,
    private_key: RsaPrivateKey,
    /// Pre-computed signing key — avoids cloning `RsaPrivateKey` on every sign call.
    signing_key: SigningKey<Sha256>,
}

impl fmt::Debug for RsaActorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaActorKey")
            .field("key_id", &self.key_id)
            .field("private_key", &"<redacted>")
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl RsaActorKey {
    /// Generate a new RSA-2048 key pair.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, rsa::Error> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let signing_key = SigningKey::new(private_key.clone());
        Ok(Self {
            key_id: key_id.into(),
            private_key,
            signing_key,
        })
    }

    /// Load an RSA key from PKCS#1 PEM.
    pub fn from_pem(key_id: impl Into<String>, pem: &str) -> Result<Self, rsa::pkcs1::Error> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem)?;
        let signing_key = SigningKey::new(private_key.clone());
        Ok(Self {
            key_id: key_id.into(),
            private_key,
            signing_key,
        })
    }

    /// Serialize the private key to PKCS#1 PEM (for persistence).
    pub fn to_pem(&self) -> Result<String, rsa::pkcs1::Error> {
        self.private_key
            .to_pkcs1_pem(LineEnding::LF)
            .map(|s| s.to_string())
    }

    /// Return the PEM-encoded RSA public key for the Actor `publicKey.publicKeyPem` field.
    pub fn public_key_pem(&self) -> Result<String, rsa::pkcs1::Error> {
        self.private_key
            .to_public_key()
            .to_pkcs1_pem(LineEnding::LF)
    }

    /// Sign an outbound HTTP POST request and return the `Signature:` header value.
    ///
    /// # Arguments
    ///
    /// - `host` — the target server's host (e.g. `mastodon.social`)
    /// - `path` — the request path (e.g. `/users/alice/inbox`)
    /// - `date` — RFC 2822 date string (e.g. `Thu, 27 Apr 2026 12:00:00 GMT`)
    /// - `body` — the raw request body bytes
    ///
    /// # Returns
    ///
    /// The full value for the `Signature:` header, ready to set directly.
    pub fn sign_post(&self, host: &str, path: &str, date: &str, body: &[u8]) -> String {
        let digest = {
            let hash = Sha256::digest(body);
            format!("SHA-256={}", BASE64.encode(&hash))
        };
        let signed_string =
            format!("(request-target): post {path}\nhost: {host}\ndate: {date}\ndigest: {digest}");
        let sig_bytes = self.signing_key.sign(signed_string.as_bytes()).to_bytes();
        let sig_b64 = BASE64.encode(&sig_bytes);
        format!(
            r#"keyId="{}",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="{}""#,
            self.key_id, sig_b64
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_pem_roundtrip() {
        let key = RsaActorKey::generate("https://example.com/ap/groups/test#main-key").unwrap();
        let pem = key.to_pem().unwrap();
        assert!(pem.contains("RSA PRIVATE KEY"), "pem: {pem}");
        let key2 = RsaActorKey::from_pem(key.key_id.clone(), &pem).unwrap();
        assert_eq!(key2.key_id, key.key_id);
    }

    #[test]
    fn public_key_pem_is_public() {
        let key = RsaActorKey::generate("https://example.com/ap/groups/test#main-key").unwrap();
        let pub_pem = key.public_key_pem().unwrap();
        assert!(pub_pem.contains("RSA PUBLIC KEY"), "pub_pem: {pub_pem}");
        assert!(!pub_pem.contains("PRIVATE"), "must not leak private key");
    }

    #[test]
    fn sign_post_produces_signature_header() {
        let key = RsaActorKey::generate("https://example.com/ap/groups/test#main-key").unwrap();
        let sig = key.sign_post(
            "mastodon.social",
            "/users/alice/inbox",
            "Thu, 27 Apr 2026 12:00:00 GMT",
            b"{\"type\":\"Create\"}",
        );
        assert!(sig.contains("keyId="), "sig: {sig}");
        assert!(sig.contains("algorithm=\"rsa-sha256\""), "sig: {sig}");
        assert!(sig.contains("signature="), "sig: {sig}");
    }
}
