//! Ed25519 operator signing for usenet-ipfs-core.
//!
//! Provides sign/verify over canonical bytes (RFC 8785 JSON or DAG-CBOR).
//! The signing key is never logged or exposed in error output.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, Verifier};
use rand_core::OsRng;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::error::SigningError;

/// Load an Ed25519 signing key from a PEM file at the given path.
///
/// Supports two formats (both use the `PRIVATE KEY` PEM label):
/// 1. PKCS#8 DER (48 bytes): 16-byte header + 32-byte seed.
/// 2. Raw 32-byte seed (non-standard, for dev convenience).
///
/// Returns `Err` with a descriptive message if the file is missing, unreadable,
/// or malformed.  The error message never contains key material.
pub fn load_signing_key(path: &std::path::Path) -> Result<SigningKey, String> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read signing key file {}: {e}", path.display()))?;

    let b64_body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let der = STANDARD
        .decode(b64_body.trim())
        .map_err(|e| format!("signing key PEM body is not valid base64: {e}"))?;

    let seed: [u8; 32] = match der.len() {
        48 => {
            // PKCS#8 DER for Ed25519: 16-byte ASN.1 header then 32-byte seed.
            der[16..48]
                .try_into()
                .map_err(|_| "PKCS#8 DER seed extraction failed".to_string())?
        }
        32 => der
            .as_slice()
            .try_into()
            .map_err(|_| "raw seed must be exactly 32 bytes".to_string())?,
        n => {
            return Err(format!(
                "signing key has unexpected DER length {n}; expected 32 (raw) or 48 (PKCS#8)"
            ))
        }
    };

    Ok(SigningKey::from_bytes(&seed))
}

/// Generate a fresh Ed25519 signing key from OS entropy.
///
/// Uses [`OsRng`] so the key is cryptographically random.  The returned key
/// is ephemeral unless the caller persists it (e.g. writes the 32-byte seed to
/// a file owned and readable only by the daemon process).
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Sign `canonical_bytes` with the given Ed25519 signing key.
///
/// The `SigningKey` is never written to any log statement.
pub fn sign(key: &SigningKey, canonical_bytes: &[u8]) -> Signature {
    key.sign(canonical_bytes)
}

/// Verify that `sig` is a valid Ed25519 signature over `canonical_bytes`
/// by the holder of `pubkey`.
///
/// Returns `Err(SigningError::VerificationFailed)` on any mismatch.
pub fn verify(
    pubkey: &VerifyingKey,
    canonical_bytes: &[u8],
    sig: &Signature,
) -> Result<(), SigningError> {
    pubkey
        .verify(canonical_bytes, sig)
        .map_err(|_| SigningError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Sign with key A, verify with key A → must pass.
    #[test]
    fn sign_then_verify_same_key_passes() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let msg = b"canonical article bytes";

        let sig = sign(&key, msg);
        assert!(
            verify(&pubkey, msg, &sig).is_ok(),
            "verification with the correct key must succeed"
        );
    }

    /// Sign with key A, verify with key B (different key) → must fail.
    #[test]
    fn verify_with_wrong_key_returns_err() {
        let signing_key = fresh_key();
        let wrong_key = fresh_key();
        let msg = b"canonical article bytes";

        let sig = sign(&signing_key, msg);
        let result = verify(&wrong_key.verifying_key(), msg, &sig);

        assert_eq!(
            result,
            Err(SigningError::VerificationFailed),
            "verification with a different key must return VerificationFailed"
        );
    }

    /// Sign over `msg`, verify over `msg` with one byte flipped → must fail.
    #[test]
    fn verify_with_tampered_bytes_returns_err() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let msg = b"canonical article bytes";

        let sig = sign(&key, msg);

        let mut tampered = msg.to_vec();
        tampered[0] ^= 0xff;

        let result = verify(&pubkey, &tampered, &sig);

        assert_eq!(
            result,
            Err(SigningError::VerificationFailed),
            "verification over tampered bytes must return VerificationFailed"
        );
    }
}
