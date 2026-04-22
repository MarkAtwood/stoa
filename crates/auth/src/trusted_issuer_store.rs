//! Trusted CA issuer store for client certificate chain authentication.
//!
//! When a client presents a TLS certificate signed by one of the configured
//! trusted CAs, the leaf certificate's Common Name (CN) is used as the
//! authenticated username without a password exchange.
//!
//! This is distinct from the fingerprint-based `ClientCertStore`: fingerprint
//! auth requires the operator to enumerate every allowed certificate by its
//! SHA-256 hash.  Issuer-based auth lets a self-operated CA issue certificates
//! to users; any leaf signed by the trusted CA is accepted, with the CN as the
//! username.
//!
//! # Verification approach
//!
//! Rather than using x509-parser's `verify_signature` API, this implementation
//! performs explicit TBS extraction and dispatches to ed25519-dalek directly
//! for Ed25519-signed certificates:
//!
//! - **Ed25519** (OID `1.3.101.112`): extracts TBS bytes, parses the 32-byte
//!   public key from the SPKI bit string, and calls
//!   `ed25519_dalek::VerifyingKey::verify_strict`.
//! - **All other algorithms**: returns `Ok(None)` — only Ed25519 CAs are
//!   supported.  For RSA/ECDSA CAs, use fingerprint-based `ClientCertStore`.
//!
//! # Security invariants
//!
//! - Empty issuer list → no issuer-based auth (all fall through to password).
//! - Parse errors on the leaf cert → fall through to password (never `Err`).
//! - Non-Ed25519 signature algorithms → fall through to password.
//! - CN match against the requested username is case-insensitive; the caller
//!   performs the comparison.

use ed25519_dalek::{Signature, VerifyingKey};
use x509_parser::prelude::*;

use crate::config::TrustedIssuerEntry;

/// OID for Ed25519 signatures: id-Ed25519 (RFC 8410 §3).
const OID_ED25519: &[u64] = &[1, 3, 101, 112];

/// An in-memory representation of one trusted CA issuer.
#[derive(Debug)]
struct TrustedIssuer {
    /// Raw SubjectPublicKeyInfo DER bytes extracted from the CA certificate.
    spki_der: Vec<u8>,
}

/// Store of parsed CA public keys for issuer-based client cert auth.
///
/// Constructed once at startup via `from_config`; shared (via `Arc`) across
/// all sessions.  Per-connection work is limited to parsing the leaf cert,
/// extracting TBS bytes, and running `ed25519-dalek` verify.
#[derive(Debug)]
pub struct TrustedIssuerStore {
    issuers: Vec<TrustedIssuer>,
}

impl TrustedIssuerStore {
    /// Construct a `TrustedIssuerStore` from operator configuration.
    ///
    /// Reads each PEM file, extracts the CA's SubjectPublicKeyInfo DER, and
    /// caches it for use in `verify_and_extract_cn`.
    ///
    /// Returns `Err` if any `cert_path` cannot be read or parsed.
    pub fn from_config(entries: &[TrustedIssuerEntry]) -> Result<Self, String> {
        let mut issuers = Vec::with_capacity(entries.len());
        for entry in entries {
            let pem_bytes = std::fs::read(&entry.cert_path)
                .map_err(|e| format!("trusted_issuer: cannot read '{}': {e}", entry.cert_path))?;
            issuers.push(issuer_from_pem(&pem_bytes, &entry.cert_path)?);
        }
        Ok(Self { issuers })
    }

    /// Return an empty store (no trusted issuers configured).
    ///
    /// All `verify_and_extract_cn` calls return `Ok(None)`.
    pub fn empty() -> Self {
        Self { issuers: vec![] }
    }

    /// Attempt to verify `leaf_der` against each trusted CA issuer.
    ///
    /// Performs explicit TBS extraction and calls `ed25519-dalek` directly for
    /// Ed25519-signed certificates.  Other signature algorithms return `Ok(None)`.
    ///
    /// Returns `Ok(Some(cn))` when:
    /// - The leaf cert is Ed25519-signed.
    /// - The signature is verified by a configured issuer's Ed25519 key.
    /// - The leaf cert's Subject has a Common Name (CN).
    ///
    /// Returns `Ok(None)` if:
    /// - The issuer list is empty.
    /// - The leaf cert cannot be parsed.
    /// - The signature algorithm is not Ed25519.
    /// - No configured issuer's key verifies the signature.
    /// - The leaf cert has no CN in its Subject.
    ///
    /// Never returns `Err` — all parse and verification failures are absorbed
    /// so the caller falls through to password authentication transparently.
    pub fn verify_and_extract_cn(&self, leaf_der: &[u8]) -> Result<Option<String>, String> {
        if self.issuers.is_empty() {
            return Ok(None);
        }

        // Parse the leaf certificate.  On parse failure, fall through.
        let (_, leaf) = match X509Certificate::from_der(leaf_der) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };

        // Extract CN from leaf Subject.  Missing CN → fall through.
        let cn = match extract_cn(leaf.subject()) {
            Some(s) => s,
            None => return Ok(None),
        };

        // Check signature algorithm.  Only Ed25519 is supported here.
        let sig_oid_arcs: Vec<u64> = match leaf.signature_algorithm.algorithm.iter() {
            Some(iter) => iter.collect(),
            None => return Ok(None),
        };
        if sig_oid_arcs != OID_ED25519 {
            return Ok(None);
        }

        // Extract TBS bytes — the bytes that the CA actually signed.
        // x509-parser stores these as the raw DER slice of the TBSCertificate.
        let tbs_bytes: &[u8] = leaf.tbs_certificate.as_ref();

        // Extract signature bytes from the outer BIT STRING.
        // RFC 5480: the BIT STRING for Ed25519 is 64 bytes, preceded by a
        // leading 0x00 "unused bits" byte in DER encoding.
        // x509-parser's `signature_value.data` is the bit string content
        // *including* the unused-bits byte.
        let raw_sig: &[u8] = &leaf.signature_value.data;
        let sig_bytes: &[u8] = if raw_sig.len() == 65 && raw_sig[0] == 0 {
            &raw_sig[1..]
        } else if raw_sig.len() == 64 {
            raw_sig
        } else {
            return Ok(None);
        };

        // Try each configured issuer using ed25519-dalek directly.
        for issuer in &self.issuers {
            if ed25519_verify_with_spki(tbs_bytes, sig_bytes, &issuer.spki_der) {
                return Ok(Some(cn));
            }
        }

        Ok(None)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extract a `TrustedIssuer` by parsing PEM-encoded CA certificate bytes.
fn issuer_from_pem(pem_bytes: &[u8], path: &str) -> Result<TrustedIssuer, String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_bytes)
        .map_err(|e| format!("trusted_issuer: cannot parse PEM from '{path}': {e}"))?;
    let der = pem.contents;

    let (_, ca_cert) = X509Certificate::from_der(&der)
        .map_err(|e| format!("trusted_issuer: cannot parse X.509 from '{path}': {e}"))?;

    let spki_der = ca_cert.tbs_certificate.subject_pki.raw.to_vec();

    Ok(TrustedIssuer { spki_der })
}

/// Extract the first Common Name (CN) from an X.509 Subject distinguished name.
fn extract_cn(subject: &X509Name<'_>) -> Option<String> {
    for rdn in subject.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                if let Ok(s) = attr.attr_value().as_str() {
                    return Some(s.to_owned());
                }
            }
        }
    }
    None
}

/// Verify `tbs_bytes` against `sig_bytes` using an Ed25519 public key
/// extracted directly from the SubjectPublicKeyInfo DER `spki_der`.
///
/// Uses ed25519-dalek's `VerifyingKey::from_bytes` and `verify_strict`
/// exclusively — no x509-parser signature verification API is invoked here.
///
/// Returns `true` on successful verification; `false` on any parse or
/// cryptographic failure.
fn ed25519_verify_with_spki(tbs_bytes: &[u8], sig_bytes: &[u8], spki_der: &[u8]) -> bool {
    // Parse the SPKI to extract algorithm OID and raw key bytes.
    let (_, spki) = match SubjectPublicKeyInfo::from_der(spki_der) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Confirm the SPKI carries an Ed25519 key.
    let alg_arcs: Vec<u64> = match spki.algorithm.algorithm.iter() {
        Some(iter) => iter.collect(),
        None => return false,
    };
    if alg_arcs != OID_ED25519 {
        return false;
    }

    // Extract the raw 32-byte Ed25519 public key from the SPKI BIT STRING.
    // The DER BIT STRING encoding prepends a 0x00 "unused bits" byte; x509-parser
    // includes this in `subject_public_key.data`.
    let key_data: &[u8] = &spki.subject_public_key.data;
    let key_bytes: &[u8] = if key_data.len() == 33 && key_data[0] == 0 {
        &key_data[1..]
    } else if key_data.len() == 32 {
        key_data
    } else {
        return false;
    };

    let key_arr: &[u8; 32] = match key_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(key_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig_arr: &[u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let signature = Signature::from_bytes(sig_arr);

    // verify_strict rejects non-canonical signatures (small-order points, etc.)
    verifying_key.verify_strict(tbs_bytes, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_always_returns_none() {
        let store = TrustedIssuerStore::empty();
        assert_eq!(store.verify_and_extract_cn(b"not a cert").unwrap(), None);
    }

    #[test]
    fn from_config_with_no_entries_gives_empty_store() {
        let store = TrustedIssuerStore::from_config(&[]).expect("empty config must succeed");
        assert_eq!(store.verify_and_extract_cn(b"garbage").unwrap(), None);
    }

    #[test]
    fn from_config_unreadable_cert_path_returns_err() {
        let entry = TrustedIssuerEntry {
            cert_path: "/nonexistent/ca.pem".to_string(),
        };
        let result = TrustedIssuerStore::from_config(&[entry]);
        assert!(result.is_err(), "unreadable cert must return Err");
    }

    #[test]
    fn unparseable_leaf_cert_returns_none_not_err() {
        let store = TrustedIssuerStore::empty();
        let result = store.verify_and_extract_cn(b"\xff\xfe garbage bytes");
        assert!(result.is_ok(), "parse failure must not propagate as Err");
        assert_eq!(result.unwrap(), None);
    }
}
