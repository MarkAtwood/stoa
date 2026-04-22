//! Security-invariant tests for the ed25519 challenge-response peer authentication protocol.
//!
//! Protocol definition (from usenet-ipfs-1c8.3):
//!   1. Each side generates 32 random bytes as a nonce and sends it to the other.
//!   2. Each side signs `(remote_nonce || local_pubkey_bytes)` with its ed25519 operator key.
//!   3. Each side verifies the received signature against its `trusted_peers` list.
//!   Peers not in `trusted_peers` are rejected silently.
//!
//! # External oracles used
//!
//! - **RFC 8032 §5.1 Test Vector 1**: used to validate that `ed25519-dalek` is operating
//!   correctly in this test environment before any protocol-level assertions are made.
//!   Source: <https://www.rfc-editor.org/rfc/rfc8032#section-5.1>
//! - **ed25519-dalek 2.x**: the crate's own documented behaviour that `verify()` returns
//!   `Err` on any signature/key/message mismatch.
//! - **usenet_ipfs_core::signing::verify**: the project's thin wrapper, which maps any
//!   dalek error to `SigningError::VerificationFailed` — tested in core's own unit tests.
//!
//! These tests do NOT import or call any code from `crates/transit/src/peering/auth.rs`.
//! They verify the security properties hold at the cryptographic primitive level, proving
//! that the protocol design (not just a particular implementation) is sound.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use usenet_ipfs_core::signing::verify;

// ── RFC 8032 §5.1 Test Vector 1 ──────────────────────────────────────────────
//
// Secret key (seed, 32 bytes):
//   9d61b19deffd5a60ba844af492ec2cc4
//   4449c5697b326919703bac031cae7f60
// Public key (32 bytes):
//   d75a980182b10ab7d54bfed3c964073a
//   0ee172f3daa62325af021a68f707511a
// Message: (empty, 0 bytes)
// Signature (64 bytes):
//   e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
//   5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
//
// Source: RFC 8032, Section 5.1, Test Vector 1 (verified against rfc-editor.org)
// <https://www.rfc-editor.org/rfc/rfc8032#section-5.1>
// Also cross-checked against the ed25519-dalek 2.x crate docstring example.

const RFC8032_TV1_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

const RFC8032_TV1_PUBKEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

const RFC8032_TV1_SIG: [u8; 64] = [
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
];

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Construct the message each side signs during the handshake:
///   `remote_nonce || local_pubkey_bytes`
///
/// This is the canonical message format from the bead spec. Encoding it as a
/// helper ensures tests are testing the same property the implementation must
/// satisfy, not some other concatenation order.
fn auth_message(remote_nonce: &[u8; 32], local_pubkey: &VerifyingKey) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(remote_nonce);
    msg.extend_from_slice(local_pubkey.as_bytes());
    msg
}

/// Generate a fresh random Ed25519 keypair.
fn fresh_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Build a `trusted_peers` list (just the verifying key bytes) from a slice of keys.
fn trusted_set(keys: &[&VerifyingKey]) -> Vec<[u8; 32]> {
    keys.iter().map(|vk| *vk.as_bytes()).collect()
}

/// Returns true if the given verifying key appears in the trusted set.
fn is_trusted(vk: &VerifyingKey, trusted: &[[u8; 32]]) -> bool {
    trusted.iter().any(|k| k == vk.as_bytes())
}

// ── Oracle validation ─────────────────────────────────────────────────────────

/// Verify that ed25519-dalek correctly handles RFC 8032 §5.1 Test Vector 1.
///
/// This is a pre-condition check: if dalek fails this known-good vector the
/// entire test environment is untrustworthy and all other tests below are moot.
///
/// Oracle: RFC 8032, Section 5.1, Test Vector 1.
#[test]
fn rfc8032_tv1_known_good_vector() {
    let signing_key = SigningKey::from_bytes(&RFC8032_TV1_SEED);
    let verifying_key = signing_key.verifying_key();

    // Confirm dalek derives the expected public key from the seed.
    assert_eq!(
        verifying_key.as_bytes(),
        &RFC8032_TV1_PUBKEY,
        "ed25519-dalek must derive the RFC 8032 TV1 public key from the given seed"
    );

    // Reconstruct the Signature from the known bytes.
    let sig = ed25519_dalek::Signature::from_bytes(&RFC8032_TV1_SIG);

    // Message is empty for TV1.
    let result = verify(&verifying_key, b"", &sig);
    assert!(
        result.is_ok(),
        "RFC 8032 §5.1 TV1: verification over empty message with known key and signature must pass"
    );
}

// ── Security Invariant 1: Relay attack prevention ─────────────────────────────
//
// The signed message is (remote_nonce || local_pubkey_bytes), NOT just remote_nonce.
//
// Attack scenario: a relay R intercepts A's nonce, forwards it to C, and asks C
// to sign it. C returns sign(nonce || C_pubkey). R presents C's signature while
// claiming to be A. B's verification constructs (nonce || A_pubkey) and checks
// against A's key — the signature was made over a different message
// (nonce || C_pubkey), so verification fails.

#[test]
fn relay_attack_different_pubkey_in_message_fails() {
    // Peer A is the claimed identity; attacker relays A's nonce to peer C.
    let key_a = fresh_keypair();
    let vk_a = key_a.verifying_key();

    let key_c = fresh_keypair(); // accomplice peer
    let vk_c = key_c.verifying_key();

    let nonce: [u8; 32] = rand_core::RngCore::next_u64(&mut OsRng)
        .to_le_bytes()
        .into_iter()
        .chain(rand_core::RngCore::next_u64(&mut OsRng).to_le_bytes())
        .chain(rand_core::RngCore::next_u64(&mut OsRng).to_le_bytes())
        .chain(rand_core::RngCore::next_u64(&mut OsRng).to_le_bytes())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // C signs (nonce || C_pubkey) — what C would legitimately produce for itself.
    let msg_c = auth_message(&nonce, &vk_c);
    let sig_c = key_c.sign(&msg_c);

    // Attacker presents C's signature while claiming to be A.
    // Verifier constructs (nonce || A_pubkey) and checks with A's key.
    let msg_a = auth_message(&nonce, &vk_a);
    let result = verify(&vk_a, &msg_a, &sig_c);

    assert!(
        result.is_err(),
        "relay attack: C's signature over (nonce || C_pubkey) must not verify as A's signature \
         over (nonce || A_pubkey)"
    );
}

// ── Security Invariant 2: Mutual authentication — both sides must verify ──────
//
// We verify this by construction: run both directions of the handshake and
// confirm each side can independently accept or reject the other.

#[test]
fn mutual_authentication_both_directions_succeed() {
    let key_a = fresh_keypair();
    let vk_a = key_a.verifying_key();

    let key_b = fresh_keypair();
    let vk_b = key_b.verifying_key();

    // Each side's trusted set contains the other.
    let trusted_by_a = trusted_set(&[&vk_b]);
    let trusted_by_b = trusted_set(&[&vk_a]);

    // Simulate nonce exchange (in the real protocol these are sent over the wire).
    let nonce_a: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };
    let nonce_b: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };

    // A signs (B's nonce || A's pubkey) and sends it to B.
    let msg_a_to_b = auth_message(&nonce_b, &vk_a);
    let sig_a = key_a.sign(&msg_a_to_b);

    // B signs (A's nonce || B's pubkey) and sends it to A.
    let msg_b_to_a = auth_message(&nonce_a, &vk_b);
    let sig_b = key_b.sign(&msg_b_to_a);

    // B verifies A's response: reconstruct (nonce_b || A_pubkey), check A is trusted.
    assert!(
        is_trusted(&vk_a, &trusted_by_b),
        "A must be in B's trusted set for this test to be valid"
    );
    assert!(
        verify(&vk_a, &msg_a_to_b, &sig_a).is_ok(),
        "B must successfully verify A's response in the mutual handshake"
    );

    // A verifies B's response: reconstruct (nonce_a || B_pubkey), check B is trusted.
    assert!(
        is_trusted(&vk_b, &trusted_by_a),
        "B must be in A's trusted set for this test to be valid"
    );
    assert!(
        verify(&vk_b, &msg_b_to_a, &sig_b).is_ok(),
        "A must successfully verify B's response in the mutual handshake"
    );
}

// ── Security Invariant 3: Unknown peer rejection ───────────────────────────────
//
// A peer with a valid ed25519 key NOT in trusted_peers must be rejected.
// The trusted_peers check is independent of signature validity.

#[test]
fn unknown_peer_not_in_trusted_list_is_rejected() {
    let key_known = fresh_keypair();
    let vk_known = key_known.verifying_key();

    let key_unknown = fresh_keypair();
    let vk_unknown = key_unknown.verifying_key();

    // trusted_peers contains only the known key.
    let trusted = trusted_set(&[&vk_known]);

    // The unknown peer produces a perfectly valid signature.
    let nonce: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };
    let msg = auth_message(&nonce, &vk_unknown);
    let sig = key_unknown.sign(&msg);

    // Signature itself is valid against the unknown key.
    assert!(
        verify(&vk_unknown, &msg, &sig).is_ok(),
        "pre-condition: the unknown peer's own signature must be valid"
    );

    // But the unknown peer is not trusted — the handshake must be rejected.
    assert!(
        !is_trusted(&vk_unknown, &trusted),
        "unknown peer must not appear in trusted_peers"
    );

    // And the known peer IS trusted.
    assert!(
        is_trusted(&vk_known, &trusted),
        "known peer must appear in trusted_peers"
    );
}

// ── Security Invariant 4: Replay prevention — fresh nonce each time ───────────
//
// Because the nonce is 32 bytes of random input, the signed message
// (remote_nonce || local_pubkey_bytes) is different each handshake.
// A captured signature from a previous session cannot be replayed.

#[test]
fn fresh_nonces_produce_different_signed_messages() {
    let key = fresh_keypair();
    let vk = key.verifying_key();

    let nonce1: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };
    let nonce2: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };

    // Two independently generated nonces must differ (probability of collision is 2^-256).
    assert_ne!(
        nonce1, nonce2,
        "two independently generated 32-byte random nonces must differ"
    );

    let msg1 = auth_message(&nonce1, &vk);
    let msg2 = auth_message(&nonce2, &vk);
    assert_ne!(
        msg1, msg2,
        "different nonces must produce different signed messages"
    );

    // A signature captured from session 1 must not verify against session 2's message.
    let sig1 = key.sign(&msg1);
    let replay_result = verify(&vk, &msg2, &sig1);
    assert!(
        replay_result.is_err(),
        "a signature from a previous session (different nonce) must not verify in a new session"
    );
}

// ── Security Invariant 5: Wrong-key rejection ─────────────────────────────────
//
// A signature produced by a key not matching the claimed verifying key must fail,
// regardless of whether that key is trusted or not.

#[test]
fn signature_by_wrong_key_is_rejected() {
    let key_a = fresh_keypair();
    let vk_a = key_a.verifying_key();

    let key_b = fresh_keypair(); // different key, also trusted

    let nonce: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };

    // A computes the correct message.
    let msg = auth_message(&nonce, &vk_a);

    // But B signs it instead of A (wrong key).
    let sig_by_b = key_b.sign(&msg);

    // Verifying with A's key must fail.
    let result = verify(&vk_a, &msg, &sig_by_b);
    assert!(
        result.is_err(),
        "a signature produced by key B must not verify against key A's verifying key"
    );
}

// ── Security Invariant 5b: Tampered signature bytes ───────────────────────────
//
// Flipping a single bit in the 64-byte signature must cause verification failure.

#[test]
fn tampered_signature_one_bit_flip_is_rejected() {
    let key = fresh_keypair();
    let vk = key.verifying_key();

    let nonce: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };
    let msg = auth_message(&nonce, &vk);
    let sig = key.sign(&msg);

    // Flip one bit in the signature bytes.
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[0] ^= 0x01;
    let tampered_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let result = verify(&vk, &msg, &tampered_sig);
    assert!(
        result.is_err(),
        "a signature with a single flipped bit must not verify"
    );
}

// ── Security Invariant 5c: Wrong nonce in the signed message ──────────────────
//
// The verifier reconstructs the message as (own_nonce || remote_pubkey). If the
// remote signed a different nonce, the reconstructed message won't match and
// verification must fail.

#[test]
fn wrong_nonce_in_signed_message_is_rejected() {
    let key = fresh_keypair();
    let vk = key.verifying_key();

    let correct_nonce: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };
    let wrong_nonce: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };

    // Peer signs over the wrong nonce (not the one the verifier sent).
    let msg_with_wrong_nonce = auth_message(&wrong_nonce, &vk);
    let sig = key.sign(&msg_with_wrong_nonce);

    // Verifier reconstructs using the correct nonce it actually sent.
    let msg_expected = auth_message(&correct_nonce, &vk);

    // The signature was over a different message — must fail.
    let result = verify(&vk, &msg_expected, &sig);
    assert!(
        result.is_err(),
        "a signature over the wrong nonce must not verify against the correct nonce message"
    );
}

// ── Security Invariant 6: Empty trusted_peers rejects everyone ────────────────
//
// An empty trusted_peers list must cause every peer to be rejected, even if
// their signature is cryptographically valid.

#[test]
fn empty_trusted_peers_rejects_all() {
    let key = fresh_keypair();
    let vk = key.verifying_key();

    // Produce a valid signature.
    let nonce: [u8; 32] = {
        let mut n = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
        n
    };
    let msg = auth_message(&nonce, &vk);
    let sig = key.sign(&msg);

    // Signature itself is valid.
    assert!(
        verify(&vk, &msg, &sig).is_ok(),
        "pre-condition: valid signature must verify"
    );

    // Empty trusted set — the lookup must fail regardless.
    let empty_trusted: Vec<[u8; 32]> = vec![];
    assert!(
        !is_trusted(&vk, &empty_trusted),
        "with empty trusted_peers, even a valid-signature peer must be rejected by the trust check"
    );
}

// ── Security Invariant 6b: Non-empty list with one entry rejects others ───────

#[test]
fn trusted_peers_list_does_not_admit_unlisted_keys() {
    let key_trusted = fresh_keypair();
    let vk_trusted = key_trusted.verifying_key();

    let key_other = fresh_keypair();
    let vk_other = key_other.verifying_key();

    let trusted = trusted_set(&[&vk_trusted]);

    // Trusted key is accepted.
    assert!(
        is_trusted(&vk_trusted, &trusted),
        "the listed key must be found in trusted_peers"
    );

    // Other key — even with valid signature — is not admitted.
    assert!(
        !is_trusted(&vk_other, &trusted),
        "an unlisted key must not be found in trusted_peers"
    );
}
