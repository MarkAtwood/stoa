//! Shared test utilities for the smtp crate.
//!
//! Available in both unit tests (via `crate::test_support`) and integration
//! tests (via `stoa_smtp::test_support`) when building with `cfg(test)`.

use std::sync::Arc;

use mail_auth::common::crypto::Ed25519Key;
use mail_auth::dkim::DkimSigner;

/// RFC 8463 §A.2 private key seed.
///
/// base64: "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="
pub const RFC8463_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// RFC 8463 §A.2 public key.
///
/// base64: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
pub const RFC8463_PUBKEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Build a DKIM signer using the RFC 8463 §A.2 test Ed25519 keypair.
///
/// Uses domain `"example.com"`, selector `"test"`, and the standard
/// [`DKIM_SIGNED_HEADERS`](crate::config::DKIM_SIGNED_HEADERS) header list.
/// Panics if the RFC 8463 test vectors are somehow invalid (they are fixed
/// constants, so this cannot happen in practice).
pub fn test_rfc8463_signer() -> Arc<DkimSigner<Ed25519Key, mail_auth::dkim::Done>> {
    let ed_key = Ed25519Key::from_seed_and_public_key(&RFC8463_SEED, &RFC8463_PUBKEY)
        .expect("RFC 8463 §A.2 test keypair must be valid");
    Arc::new(
        DkimSigner::from_key(ed_key)
            .domain("example.com")
            .selector("test")
            .headers(crate::config::DKIM_SIGNED_HEADERS.iter().copied()),
    )
}
