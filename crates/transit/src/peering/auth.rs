//! Mutual Ed25519 challenge-response authentication for peering connections.
//!
//! The handshake runs as a binary framed protocol *before* any NNTP bytes are
//! exchanged.  Raw binary frames are used — no base64, no text lines — because
//! the handshake occupies a known, fixed byte budget on a fresh TCP connection
//! before the NNTP text mode begins.  This keeps the handshake compact and
//! parse-free on the hot path.
//!
//! # Wire protocol (both sides simultaneously)
//!
//! ```text
//! Round 1 — nonce exchange (32 bytes each direction):
//!   --> my_nonce [u8; 32]
//!   <-- their_nonce [u8; 32]
//!
//! Round 2 — pubkey + signature (96 bytes each direction):
//!   --> my_pubkey [u8; 32] || sig(their_nonce || my_pubkey) [u8; 64]
//!   <-- their_pubkey [u8; 32] || their_sig [u8; 64]
//! ```
//!
//! The signed message is `their_nonce || my_pubkey` (64 bytes).  This binds
//! the signature to both the remote challenge and the sender's own public key,
//! preventing cross-protocol replay of captured frames.
//!
//! After receiving the remote 96-byte frame, the local node:
//! 1. Confirms `their_pubkey` is in the trusted-key list (constant-time).
//! 2. Verifies `their_sig` over `my_nonce || their_pubkey`.
//!
//! On any failure the caller drops the connection silently — no diagnostic
//! information is sent to the peer.
//!
//! # Config key format
//!
//! Trusted peer keys are stored in TOML as `"ed25519:<64-lowercase-hex-digits>"`.
//! Hex is chosen over base64 for operator readability: hex values can be
//! copy-pasted from `xxd` or `openssl pkey` output without worrying about
//! padding variants.

use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Errors that can occur during the peering authentication handshake.
#[non_exhaustive]
#[derive(Debug)]
pub enum PeeringAuthError {
    /// An I/O error occurred on the connection.
    Io(std::io::Error),
    /// A config key string could not be parsed.
    InvalidKeyFormat(String),
    /// A public key or nonce field had the wrong byte length.
    InvalidKeyLength { got: usize },
    /// The remote's signature did not verify against the expected message.
    SignatureVerificationFailed,
    /// The remote's public key was not in the trusted-peers list.
    PeerNotTrusted,
    /// The handshake did not complete within the allowed time.
    Timeout,
}

impl std::fmt::Display for PeeringAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeeringAuthError::Io(e) => write!(f, "I/O error: {e}"),
            PeeringAuthError::InvalidKeyFormat(s) => write!(f, "invalid key format: {s}"),
            PeeringAuthError::InvalidKeyLength { got } => {
                write!(f, "invalid key length: expected 32 bytes, got {got}")
            }
            PeeringAuthError::SignatureVerificationFailed => {
                write!(f, "signature verification failed")
            }
            PeeringAuthError::PeerNotTrusted => write!(f, "peer public key not in trusted list"),
            PeeringAuthError::Timeout => write!(f, "handshake timed out"),
        }
    }
}

impl std::error::Error for PeeringAuthError {}

impl From<std::io::Error> for PeeringAuthError {
    fn from(e: std::io::Error) -> Self {
        PeeringAuthError::Io(e)
    }
}

/// Parse a trusted-peer key string of the form `"ed25519:<64-hex-chars>"`.
///
/// Returns `Err` if the prefix is wrong, the hex is invalid, the decoded bytes
/// are not exactly 32 bytes, or the bytes are not a valid Ed25519 public key.
pub fn parse_trusted_peer_key(s: &str) -> Result<VerifyingKey, PeeringAuthError> {
    let hex_part = s.strip_prefix("ed25519:").ok_or_else(|| {
        PeeringAuthError::InvalidKeyFormat(format!("entry must start with 'ed25519:': {s:?}"))
    })?;

    let bytes = hex::decode(hex_part)
        .map_err(|e| PeeringAuthError::InvalidKeyFormat(format!("invalid hex in {s:?}: {e}")))?;

    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| PeeringAuthError::InvalidKeyLength { got: bytes.len() })?;

    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| PeeringAuthError::InvalidKeyFormat(format!("not a valid Ed25519 key: {e}")))
}

/// Parse all trusted-peer key strings from config, returning the first error.
pub fn parse_trusted_peer_keys(strings: &[String]) -> Result<Vec<VerifyingKey>, PeeringAuthError> {
    strings.iter().map(|s| parse_trusted_peer_key(s)).collect()
}

/// Run the mutual challenge-response authentication handshake with a 15-second
/// timeout.
///
/// Both sides call this function with the same role — there is no distinguished
/// "client" or "server" in the handshake itself.
///
/// Returns `Ok(remote_pubkey_bytes)` on success.  The caller should log the hex
/// of this value for auditing and correlate it with the peer registry.
///
/// Returns `Err` on I/O failure, untrusted key, bad signature, or timeout.
pub async fn run_auth_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    signing_key: &SigningKey,
    trusted_keys: &[VerifyingKey],
) -> Result<[u8; 32], PeeringAuthError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    tokio::time::timeout(
        Duration::from_secs(15),
        handshake_inner(reader, writer, signing_key, trusted_keys),
    )
    .await
    .unwrap_or(Err(PeeringAuthError::Timeout))
}

/// Inner (non-timed) binary handshake logic, wrapped by [`run_auth_handshake`].
async fn handshake_inner<R, W>(
    reader: &mut R,
    writer: &mut W,
    signing_key: &SigningKey,
    trusted_keys: &[VerifyingKey],
) -> Result<[u8; 32], PeeringAuthError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Round 1 — exchange nonces concurrently.
    //
    // Both sides write and read simultaneously via tokio::join! to eliminate
    // the theoretical deadlock that would arise if both sides blocked in
    // write_all() before reading (the two sends can be larger than the kernel
    // TCP send buffer under memory pressure, even though 32 bytes is tiny).
    let mut my_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut my_nonce);

    let mut their_nonce = [0u8; 32];
    let (write_res, read_res) = tokio::join!(
        async {
            writer.write_all(&my_nonce).await?;
            writer.flush().await
        },
        reader.read_exact(&mut their_nonce),
    );
    write_res?;
    read_res?;

    // Round 2 — exchange pubkey+sig frames concurrently (96 bytes each side).
    // Signed message = their_nonce || my_pubkey (64 bytes).
    // DECISION (rbe3.24): signed message is their_nonce || my_pubkey.
    // Including my_pubkey binds the signature to the sender's own identity,
    // preventing cross-protocol replay: a captured signature cannot be reused
    // in another session (nonce differs) or by a different key (pubkey differs).
    // Signing only their_nonce would allow key-substitution replay attacks.
    // Do NOT simplify to sign(their_nonce).
    let my_pubkey_bytes = signing_key.verifying_key().to_bytes();
    let mut signing_msg = [0u8; 64];
    signing_msg[..32].copy_from_slice(&their_nonce);
    signing_msg[32..].copy_from_slice(&my_pubkey_bytes);
    let sig: Signature = signing_key.sign(&signing_msg);

    let mut out_frame = [0u8; 96];
    out_frame[..32].copy_from_slice(&my_pubkey_bytes);
    out_frame[32..].copy_from_slice(&sig.to_bytes());

    let mut in_frame = [0u8; 96];
    let (write_res, read_res) = tokio::join!(
        async {
            writer.write_all(&out_frame).await?;
            writer.flush().await
        },
        reader.read_exact(&mut in_frame),
    );
    write_res?;
    read_res?;
    let their_pubkey_bytes: [u8; 32] = in_frame[..32].try_into().unwrap();
    let their_sig_bytes: [u8; 64] = in_frame[32..].try_into().unwrap();

    // DECISION (rbe3.28): constant-time lookup prevents timing oracle.
    // Using `==` or an early-exit find() would leak the Hamming distance to
    // the nearest trusted key via response latency.  `subtle::ConstantTimeEq`
    // takes the same wall time regardless of where keys differ.  Do NOT
    // replace `ct_eq` with a plain byte comparison, even on loopback.
    // Use fold to scan all keys without short-circuiting, preventing timing oracle.
    let is_trusted = trusted_keys.iter().fold(false, |found, k| {
        found | bool::from(k.to_bytes().ct_eq(&their_pubkey_bytes))
    });
    if !is_trusted {
        return Err(PeeringAuthError::PeerNotTrusted);
    }

    // Reconstruct VerifyingKey and verify their signature over my_nonce || their_pubkey.
    let their_pubkey = VerifyingKey::from_bytes(&their_pubkey_bytes)
        .map_err(|_| PeeringAuthError::SignatureVerificationFailed)?;

    let mut verify_msg = [0u8; 64];
    verify_msg[..32].copy_from_slice(&my_nonce);
    verify_msg[32..].copy_from_slice(&their_pubkey_bytes);

    let their_sig = Signature::from_bytes(&their_sig_bytes);

    use ed25519_dalek::Verifier;
    their_pubkey
        .verify(&verify_msg, &their_sig)
        .map_err(|_| PeeringAuthError::SignatureVerificationFailed)?;

    Ok(their_pubkey_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Run a handshake between two in-memory duplex streams.
    async fn run_pair(
        key_a: &SigningKey,
        trusted_a: &[VerifyingKey],
        key_b: &SigningKey,
        trusted_b: &[VerifyingKey],
    ) -> (Result<[u8; 32], String>, Result<[u8; 32], String>) {
        let (stream_a, stream_b) = tokio::io::duplex(4096);
        let (mut read_a, mut write_a) = tokio::io::split(stream_a);
        let (mut read_b, mut write_b) = tokio::io::split(stream_b);

        let key_a = key_a.clone();
        let key_b = key_b.clone();
        let trusted_a: Vec<VerifyingKey> = trusted_a.to_vec();
        let trusted_b: Vec<VerifyingKey> = trusted_b.to_vec();

        let (res_a, res_b) = tokio::join!(
            async move {
                run_auth_handshake(&mut read_a, &mut write_a, &key_a, &trusted_a)
                    .await
                    .map_err(|e| e.to_string())
            },
            async move {
                run_auth_handshake(&mut read_b, &mut write_b, &key_b, &trusted_b)
                    .await
                    .map_err(|e| e.to_string())
            }
        );
        (res_a, res_b)
    }

    /// Two peers that mutually trust each other must both succeed and return the
    /// other's public key bytes.
    #[tokio::test]
    async fn mutual_auth_succeeds() {
        let key_a = fresh_key();
        let key_b = fresh_key();
        let pub_a = key_a.verifying_key();
        let pub_b = key_b.verifying_key();

        let (res_a, res_b) = run_pair(&key_a, &[pub_b], &key_b, &[pub_a]).await;
        assert_eq!(
            res_a.expect("side A should succeed"),
            pub_b.to_bytes(),
            "side A must see B's pubkey"
        );
        assert_eq!(
            res_b.expect("side B should succeed"),
            pub_a.to_bytes(),
            "side B must see A's pubkey"
        );
    }

    /// A peer whose key is not in the trusted list must be rejected.
    #[tokio::test]
    async fn untrusted_peer_rejected() {
        let key_a = fresh_key();
        let key_b = fresh_key();
        let pub_a = key_a.verifying_key();

        // A trusts nobody; B trusts A.
        let (res_a, _res_b) = run_pair(&key_a, &[], &key_b, &[pub_a]).await;
        let err = res_a.expect_err("A should reject untrusted B");
        assert!(
            err.contains("not in trusted list"),
            "unexpected error message: {err}"
        );
    }

    /// A peer using an untrusted key (not the claimed one) must be rejected.
    #[tokio::test]
    async fn wrong_key_rejected() {
        let key_a = fresh_key();
        let key_b_trusted = fresh_key();
        let key_b_actual = fresh_key(); // different key from what A trusts
        let pub_a = key_a.verifying_key();
        let pub_b_trusted = key_b_trusted.verifying_key();

        // A trusts pub_b_trusted but B authenticates with key_b_actual.
        let trusted_a = vec![pub_b_trusted];
        let trusted_b = vec![pub_a];

        let (res_a, _res_b) = run_pair(&key_a, &trusted_a, &key_b_actual, &trusted_b).await;
        let err = res_a.expect_err("A should reject because key_b_actual's pubkey is not trusted");
        assert!(
            err.contains("not in trusted list"),
            "unexpected error: {err}"
        );
    }

    /// `parse_trusted_peer_key` round-trips through hex encoding.
    #[test]
    fn parse_trusted_peer_key_roundtrip() {
        let key = fresh_key();
        let pub_bytes = key.verifying_key().to_bytes();
        let encoded = format!("ed25519:{}", hex::encode(pub_bytes));
        let parsed = parse_trusted_peer_key(&encoded).expect("valid hex key must parse");
        assert_eq!(parsed.to_bytes(), pub_bytes);
    }

    /// `parse_trusted_peer_key` rejects a bad prefix.
    #[test]
    fn parse_trusted_peer_key_bad_prefix() {
        assert!(parse_trusted_peer_key("rsa:deadbeef").is_err());
    }

    /// `parse_trusted_peer_key` rejects invalid hex.
    #[test]
    fn parse_trusted_peer_key_invalid_hex() {
        assert!(parse_trusted_peer_key("ed25519:notvalidhex!!").is_err());
    }

    /// `parse_trusted_peer_key` rejects a key that is not 32 bytes.
    #[test]
    fn parse_trusted_peer_key_wrong_length() {
        let short = format!("ed25519:{}", hex::encode([0u8; 16]));
        let result = parse_trusted_peer_key(&short);
        assert!(
            matches!(result, Err(PeeringAuthError::InvalidKeyLength { got: 16 })),
            "expected InvalidKeyLength(16), got: {result:?}"
        );
    }
}
