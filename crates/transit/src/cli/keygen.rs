//! Operator key generation: generate an ed25519 keypair and write to PEM files.

use std::fs;
use std::io::Write;

use sha2::Digest;

/// Result of a successful keypair generation.
#[derive(Debug)]
pub struct KeygenOutput {
    /// The hex fingerprint of the public key (SHA-256 of DER-encoded SubjectPublicKeyInfo).
    pub fingerprint: String,
    /// Private key PEM path written.
    pub private_key_path: std::path::PathBuf,
    /// Public key PEM path written.
    pub public_key_path: std::path::PathBuf,
}

/// Generate an ed25519 keypair and write to `output_dir`.
///
/// - Private key: `{output_dir}/operator_key.pem` (mode 0600 on Unix)
/// - Public key: `{output_dir}/operator_key.pub.pem` (mode 0644 on Unix)
/// - Returns the public key fingerprint (SHA-256 of SubjectPublicKeyInfo DER, hex)
/// - Fails if files already exist and `force` is false
pub fn generate_keypair(
    output_dir: &std::path::Path,
    force: bool,
) -> Result<KeygenOutput, String> {
    let private_key_path = output_dir.join("operator_key.pem");
    let public_key_path = output_dir.join("operator_key.pub.pem");

    if !force {
        if private_key_path.exists() {
            return Err(format!(
                "private key already exists: {}. Use --force to overwrite.",
                private_key_path.display()
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

    // PKCS#8 v1 DER for ed25519 private key:
    // Fixed 16-byte header + 32-byte seed
    // SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { seed } } }
    const PKCS8_HEADER: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
        0x04, 0x20,
    ];
    let mut private_der = Vec::with_capacity(48);
    private_der.extend_from_slice(&PKCS8_HEADER);
    private_der.extend_from_slice(&signing_key.to_bytes());

    // SubjectPublicKeyInfo DER for ed25519 public key:
    // Fixed 12-byte header + 32-byte public key
    // SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { public key } }
    const SPKI_HEADER: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut public_der = Vec::with_capacity(44);
    public_der.extend_from_slice(&SPKI_HEADER);
    public_der.extend_from_slice(verifying_key.as_bytes());

    // Fingerprint: SHA-256 of the SPKI DER bytes, hex-encoded
    let digest = sha2::Sha256::digest(&public_der);
    let fingerprint = hex::encode(digest);

    let private_pem = to_pem("PRIVATE KEY", &private_der);
    let public_pem = to_pem("PUBLIC KEY", &public_der);

    // Write private key: set mode 0600 before writing content
    {
        let mut f = fs::File::create(&private_key_path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        f.write_all(private_pem.as_bytes()).map_err(|e| e.to_string())?;
    }

    // Write public key: mode 0644
    {
        let mut f = fs::File::create(&public_key_path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o644))
                .map_err(|e| e.to_string())?;
        }
        f.write_all(public_pem.as_bytes()).map_err(|e| e.to_string())?;
    }

    Ok(KeygenOutput {
        fingerprint,
        private_key_path,
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

    #[test]
    fn generates_key_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = generate_keypair(dir.path(), false).unwrap();

        assert!(result.private_key_path.exists(), "private key file should exist");
        assert!(result.public_key_path.exists(), "public key file should exist");
        assert!(!result.fingerprint.is_empty(), "fingerprint should not be empty");
        // Fingerprint is 64 hex chars (SHA-256)
        assert_eq!(result.fingerprint.len(), 64, "fingerprint should be 64 hex chars");
    }

    #[test]
    fn private_key_is_valid_pem() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = generate_keypair(dir.path(), false).unwrap();
        let pem = std::fs::read_to_string(&result.private_key_path).unwrap();
        assert!(
            pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "private key PEM header: {pem}"
        );
        assert!(
            pem.contains("-----END PRIVATE KEY-----"),
            "private key PEM footer: {pem}"
        );
    }

    #[test]
    fn public_key_is_valid_pem() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = generate_keypair(dir.path(), false).unwrap();
        let pem = std::fs::read_to_string(&result.public_key_path).unwrap();
        assert!(
            pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "public key PEM header: {pem}"
        );
        assert!(
            pem.contains("-----END PUBLIC KEY-----"),
            "public key PEM footer: {pem}"
        );
    }

    #[test]
    fn overwrite_fails_without_force() {
        let dir = tempfile::TempDir::new().unwrap();
        generate_keypair(dir.path(), false).unwrap();
        // Second call without force should fail
        let result = generate_keypair(dir.path(), false);
        assert!(result.is_err(), "should fail without --force");
        assert!(result.unwrap_err().contains("force"), "error should mention --force");
    }

    #[test]
    fn overwrite_succeeds_with_force() {
        let dir = tempfile::TempDir::new().unwrap();
        let r1 = generate_keypair(dir.path(), false).unwrap();
        let r2 = generate_keypair(dir.path(), true).unwrap();
        // Both succeed; fingerprints differ (new key generated)
        assert_ne!(r1.fingerprint, r2.fingerprint, "force should generate a new key");
    }

    #[cfg(unix)]
    #[test]
    fn private_key_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let result = generate_keypair(dir.path(), false).unwrap();
        let meta = std::fs::metadata(&result.private_key_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key must have mode 0600, got {:o}", mode);
    }
}
