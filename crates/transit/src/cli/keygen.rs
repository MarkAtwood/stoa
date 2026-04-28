//! Operator key generation: generate an Ed25519 signing key and write to disk.
//!
//! The private key is stored as a raw 32-byte binary file (mode 0600).
//! The public key is stored as a SPKI PEM file (mode 0644) for use in key
//! rotation announcements.

use std::fs;
use std::io::Write;

use sha2::Digest;

/// Result of a successful keypair generation.
#[derive(Debug)]
pub struct KeygenOutput {
    /// The hex fingerprint of the public key (SHA-256 of DER-encoded SubjectPublicKeyInfo).
    pub fingerprint: String,
    /// Hex-encoded HLC node ID derived from this key.
    pub node_id_hex: String,
    /// Private key path written (raw 32-byte binary, mode 0600).
    pub private_key_path: std::path::PathBuf,
    /// Public key PEM path written (SPKI PEM, mode 0644).
    pub public_key_path: std::path::PathBuf,
}

/// Generate an ed25519 keypair and write to disk.
///
/// - Private key: `output_path` (raw 32-byte binary seed, mode 0600 on Unix)
/// - Public key: `output_path` + `.pub.pem` (SPKI PEM, mode 0644 on Unix)
/// - Returns fingerprint (SHA-256 of SubjectPublicKeyInfo DER, hex-encoded)
/// - Fails if files already exist and `force` is false
pub fn generate_keypair(
    output_path: &std::path::Path,
    force: bool,
) -> Result<KeygenOutput, String> {
    let public_key_path = {
        let mut p = output_path.as_os_str().to_owned();
        p.push(".pub.pem");
        std::path::PathBuf::from(p)
    };

    if !force {
        if output_path.exists() {
            return Err(format!(
                "private key already exists: {}. Use --force to overwrite.",
                output_path.display()
            ));
        }
        if public_key_path.exists() {
            return Err(format!(
                "public key already exists: {}. Use --force to overwrite.",
                public_key_path.display()
            ));
        }
    }

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut public_der = Vec::with_capacity(44);
    public_der.extend_from_slice(&crate::cli::key_support::SPKI_ED25519_HEADER);
    public_der.extend_from_slice(verifying_key.as_bytes());

    // Fingerprint: SHA-256 of the SPKI DER bytes, hex-encoded
    let digest = sha2::Sha256::digest(&public_der);
    let fingerprint = hex::encode(digest);

    // HLC node ID: first 8 bytes of SHA-256(public_key)
    let node_id = stoa_core::signing::hlc_node_id(&signing_key);
    let node_id_hex = hex::encode(node_id);

    let public_pem = to_pem("PUBLIC KEY", &public_der);

    // Write private key as raw 32-byte binary.
    // On Unix, pass mode 0o600 to open(2) so the file is never world-readable,
    // not even for the instant between creation and a subsequent chmod.
    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(output_path)
                .map_err(|e| e.to_string())?
        };
        #[cfg(not(unix))]
        let mut f = fs::File::create(output_path).map_err(|e| e.to_string())?;
        f.write_all(&signing_key.to_bytes())
            .map_err(|e| e.to_string())?;
    }

    // Write public key PEM: mode 0644
    {
        let mut f = fs::File::create(&public_key_path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o644))
                .map_err(|e| e.to_string())?;
        }
        f.write_all(public_pem.as_bytes())
            .map_err(|e| e.to_string())?;
    }

    Ok(KeygenOutput {
        fingerprint,
        node_id_hex,
        private_key_path: output_path.to_path_buf(),
        public_key_path,
    })
}

fn to_pem(label: &str, der_bytes: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der_bytes);
    let mut lines = String::new();
    for chunk in b64.as_bytes().chunks(64) {
        lines.push_str(std::str::from_utf8(chunk).unwrap());
        lines.push('\n');
    }
    format!("-----BEGIN {label}-----\n{lines}-----END {label}-----\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("operator.key")
    }

    #[test]
    fn generates_key_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        let result = generate_keypair(&path, false).unwrap();

        assert!(
            result.private_key_path.exists(),
            "private key file should exist"
        );
        assert!(
            result.public_key_path.exists(),
            "public key file should exist"
        );
        assert_eq!(
            result.fingerprint.len(),
            64,
            "fingerprint should be 64 hex chars"
        );
        assert_eq!(
            result.node_id_hex.len(),
            16,
            "node_id should be 16 hex chars"
        );
    }

    #[test]
    fn private_key_is_32_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        let result = generate_keypair(&path, false).unwrap();
        let bytes = std::fs::read(&result.private_key_path).unwrap();
        assert_eq!(bytes.len(), 32, "private key must be exactly 32 bytes");
    }

    #[test]
    fn public_key_is_valid_pem() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        let result = generate_keypair(&path, false).unwrap();
        let pem = std::fs::read_to_string(&result.public_key_path).unwrap();
        assert!(
            pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "public key PEM header: {pem}"
        );
        assert!(
            pem.contains("-----END PUBLIC KEY-----"),
            "public key PEM footer"
        );
    }

    #[test]
    fn overwrite_fails_without_force() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        generate_keypair(&path, false).unwrap();
        let result = generate_keypair(&path, false);
        assert!(result.is_err(), "should fail without --force");
        assert!(
            result.unwrap_err().contains("force"),
            "error should mention --force"
        );
    }

    #[test]
    fn overwrite_succeeds_with_force() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        let r1 = generate_keypair(&path, false).unwrap();
        let r2 = generate_keypair(&path, true).unwrap();
        assert_ne!(
            r1.fingerprint, r2.fingerprint,
            "force should generate a new key"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        let result = generate_keypair(&path, false).unwrap();
        let meta = std::fs::metadata(&result.private_key_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "private key must have mode 0600, got {:o}",
            mode
        );
    }

    #[test]
    fn load_signing_key_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = test_key_path(&dir);
        let result = generate_keypair(&path, false).unwrap();

        let key = stoa_core::signing::load_signing_key(&result.private_key_path)
            .expect("should load signing key");

        use ed25519_dalek::Signer;
        let sig = key.sign(b"test message");
        let vk = key.verifying_key();
        use ed25519_dalek::Verifier;
        assert!(
            vk.verify(b"test message", &sig).is_ok(),
            "signature should verify"
        );
    }
}
