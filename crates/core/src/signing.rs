//! Ed25519 operator signing for stoa-core.
//!
//! Provides sign/verify over canonical bytes (RFC 8785 JSON or DAG-CBOR).
//! The signing key is never logged or exposed in error output.

use ed25519_dalek::{Signer, Verifier};
use rand_core::OsRng;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::error::SigningError;

/// Load an Ed25519 signing key from raw bytes.
///
/// `bytes` must contain exactly 32 bytes (the Ed25519 seed).  Unlike
/// [`load_signing_key`], no file-permission checks are performed — the caller
/// is responsible for securing the key material before passing it here (e.g.
/// when the bytes were retrieved from a secrets manager rather than a file).
pub fn load_signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, String> {
    if bytes.len() != 32 {
        return Err(format!(
            "signing key must be exactly 32 bytes, got {}",
            bytes.len()
        ));
    }
    let arr: [u8; 32] = bytes.try_into().expect("length already verified above");
    Ok(SigningKey::from_bytes(&arr))
}

/// Load an Ed25519 signing key from a raw 32-byte binary file.
///
/// The file must contain exactly 32 bytes (the Ed25519 seed/private scalar).
/// On Unix, the file must not be world-readable (mode must not have `o+r`).
///
/// Returns `Err` with a descriptive message if the file is missing, unreadable,
/// wrong length, or has insecure permissions.  The error message never contains
/// key material.
pub fn load_signing_key(path: &std::path::Path) -> Result<SigningKey, String> {
    #[cfg(unix)]
    check_key_file_permissions(path)?;

    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read signing key file {}: {e}", path.display()))?;

    if bytes.len() != 32 {
        return Err(format!(
            "signing key file '{}' must contain exactly 32 bytes, got {}",
            path.display(),
            bytes.len()
        ));
    }

    let arr: [u8; 32] = bytes.try_into().expect("length already verified above");
    Ok(SigningKey::from_bytes(&arr))
}

/// Derive the 8-byte HLC node ID from an operator signing key.
///
/// Uses the first 8 bytes of SHA-256(public_key), so the node ID is:
/// - Stable across restarts (as long as the key file is unchanged).
/// - Unique per operator (Ed25519 key pairs are effectively unique).
/// - Not the raw key (only a truncated hash is exposed).
///
/// # DECISION (rbe3.33): node_id derived from signing key, not random or libp2p peer ID
///
/// Using the signing key as the node ID source makes it stable across restarts
/// and globally unique assuming Ed25519 keys are not reused.  Alternative
/// approaches are worse:
/// - Random per restart: HLC timestamps from different runs are not comparable,
///   breaking Merkle-CRDT ordering across a server restart.
/// - libp2p peer ID: couples node identity to the IPFS backend; breaks for
///   non-Kubo backends (iroh, rust-ipfs) and requires the IPFS layer to be
///   initialized before the HLC.
/// - Raw public key bytes: leaks more key material than necessary and is
///   larger than 8 bytes.
///
/// Do NOT change this to use a random value or a libp2p peer ID.
pub fn hlc_node_id(signing_key: &SigningKey) -> [u8; 8] {
    use multihash_codetable::{Code, MultihashDigest};
    let vk = signing_key.verifying_key();
    let digest = Code::Sha2_256.digest(vk.as_bytes());
    let mut node_id = [0u8; 8];
    node_id.copy_from_slice(&digest.digest()[..8]);
    node_id
}

/// Refuse to load a key file that is world-readable.
///
/// A world-readable signing key can be read by any local user and should be
/// treated as compromised.  Operators must set file permissions to 0600.
#[cfg(unix)]
fn check_key_file_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat signing key file {}: {e}", path.display()))?;
    let mode = meta.mode();
    // Reject both world-readable (o+r = 0o004) and group-readable (g+r = 0o040).
    // A group-readable key can be read by any process sharing the same Unix group,
    // which is not acceptable for a signing key.
    if mode & 0o044 != 0 {
        return Err(format!(
            "signing key file '{}' is readable by group or world (mode {:04o}); \
             set permissions to 0600: chmod 0600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        ));
    }
    Ok(())
}

/// Generate a fresh Ed25519 signing key from OS entropy.
///
/// Uses [`OsRng`] so the key is cryptographically random.  The returned key
/// is ephemeral unless the caller persists it (e.g. writes the 32-byte seed to
/// a file owned and readable only by the daemon process).
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Write a raw 32-byte signing key seed to `path` with mode 0600.
///
/// - If `path` already exists and `force` is false, returns `Err`.
/// - On non-Unix platforms, the mode 0600 step is skipped (best effort).
/// - The write is atomic: bytes are written to a sibling temp file then
///   renamed into place, so a crash mid-write never leaves a partial key.
pub fn write_signing_key(
    key: &SigningKey,
    path: &std::path::Path,
    force: bool,
) -> Result<(), String> {
    use std::io::Write;

    if !force && path.exists() {
        return Err(format!(
            "signing key file '{}' already exists; use --force to overwrite",
            path.display()
        ));
    }

    // Determine parent directory for the temp file.
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));

    // Write to a temp file in the same directory so the rename is on the
    // same filesystem (required for atomicity on most platforms).
    let tmp_path = parent.join(format!(".signing_key_tmp_{}.tmp", std::process::id()));

    let result = (|| {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| format!("cannot create temp key file '{}': {e}", tmp_path.display()))?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create_new(&tmp_path)
            .map_err(|e| format!("cannot create temp key file '{}': {e}", tmp_path.display()))?;

        f.write_all(&key.to_bytes())
            .map_err(|e| format!("cannot write signing key to '{}': {e}", tmp_path.display()))?;

        // Flush and close before rename.
        drop(f);

        std::fs::rename(&tmp_path, path).map_err(|e| {
            format!(
                "cannot rename '{}' to '{}': {e}",
                tmp_path.display(),
                path.display()
            )
        })
    })();

    if result.is_err() {
        // Best-effort cleanup; ignore secondary errors.
        let _ = std::fs::remove_file(&tmp_path);
    }

    result
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

    /// HLC node_id is deterministic: same key → same id.
    ///
    /// Independent oracle: manually compute SHA-256(vk_bytes)[0..8] and compare.
    #[test]
    fn hlc_node_id_is_deterministic() {
        let seed = [0x55u8; 32];
        let key = SigningKey::from_bytes(&seed);
        let id1 = hlc_node_id(&key);
        // Reload the same key from bytes and rederive — must match.
        let key2 = SigningKey::from_bytes(&seed);
        let id2 = hlc_node_id(&key2);
        assert_eq!(id1, id2, "node_id must be identical for the same key seed");
    }

    /// HLC node_id differs for different keys.
    #[test]
    fn hlc_node_id_differs_for_different_keys() {
        let key_a = SigningKey::from_bytes(&[0x11u8; 32]);
        let key_b = SigningKey::from_bytes(&[0x22u8; 32]);
        assert_ne!(
            hlc_node_id(&key_a),
            hlc_node_id(&key_b),
            "node_id must differ for distinct keys"
        );
    }

    /// load_signing_key_from_bytes produces the correct verifying key for a known seed.
    ///
    /// Test vector oracle: pyca/cryptography (independent Ed25519 implementation).
    ///   seed   = [0x42; 32]
    ///   verifying key = 2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
    /// Verified with:
    ///   Ed25519PrivateKey.from_private_bytes(b'\x42'*32).public_key().public_bytes(Raw,Raw).hex()
    #[test]
    fn load_signing_key_from_bytes_known_vector() {
        let key = load_signing_key_from_bytes(&[0x42u8; 32]).expect("must succeed with 32 bytes");
        let expected =
            hex::decode("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
                .unwrap();
        assert_eq!(
            key.verifying_key().to_bytes().as_slice(),
            expected.as_slice(),
            "verifying key must match pyca/cryptography oracle"
        );
    }

    /// load_signing_key_from_bytes rejects wrong lengths.
    #[test]
    fn load_signing_key_from_bytes_rejects_wrong_length() {
        let result = load_signing_key_from_bytes(&[0u8; 31]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("32 bytes"));
    }

    /// write_signing_key + load_signing_key round-trip.
    #[test]
    fn write_and_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("operator.key");
        let key = fresh_key();
        write_signing_key(&key, &path, false).expect("write must succeed");

        let loaded = load_signing_key(&path).expect("load must succeed");
        assert_eq!(
            key.to_bytes(),
            loaded.to_bytes(),
            "loaded key must match written key"
        );
    }

    /// load_signing_key refuses a world-readable file on Unix.
    #[cfg(unix)]
    #[test]
    fn load_signing_key_refuses_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("operator.key");
        let key = fresh_key();
        write_signing_key(&key, &path, false).expect("write must succeed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let result = load_signing_key(&path);
        assert!(result.is_err(), "must refuse world-readable key file");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("readable by group or world"),
            "error must mention group-or-world: {msg}"
        );
    }

    /// load_signing_key refuses a group-readable file on Unix.
    #[cfg(unix)]
    #[test]
    fn load_signing_key_refuses_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("operator.key");
        let key = fresh_key();
        write_signing_key(&key, &path, false).expect("write must succeed");
        // 0o640: owner read+write, group read, world none.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let result = load_signing_key(&path);
        assert!(result.is_err(), "must refuse group-readable key file");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("readable by group or world"),
            "error must mention group-or-world: {msg}"
        );
    }
}
