//! Ed25519 operator signing for usenet-ipfs-core.
//!
//! Provides sign/verify over canonical bytes (RFC 8785 JSON or DAG-CBOR).
//! The signing key is never logged or exposed in error output.

use ed25519_dalek::{Signer, Verifier};

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::error::SigningError;

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
    use rand::rngs::OsRng;

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
