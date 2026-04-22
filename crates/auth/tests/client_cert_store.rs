//! Tests for `ClientCertStore` — SHA-256 fingerprint-based client certificate
//! authentication.
//!
//! # Oracle rationale
//!
//! All fingerprint test vectors are derived from two independent OpenSSL
//! invocations, cross-verified against each other:
//!
//!   openssl req -x509 -newkey ed25519 -keyout /tmp/k.pem -out /tmp/c.pem \
//!     -days 3650 -nodes -subj "/CN=usenet-ipfs-test-cert"
//!   openssl x509 -fingerprint -sha256 -noout -in /tmp/c.pem
//!   → 6E:EC:02:A6:1E:34:81:26:F9:B3:AD:2C:22:37:4E:1F:63:1B:60:5B:55:29:DE:F0:33:29:DB:FD:76:3E:A0:C7
//!   openssl x509 -outform DER -in /tmp/c.pem | openssl dgst -sha256 -hex
//!   → SHA2-256(stdin)= 6eec02a61e348126f9b3ad2c22374e1f631b605b5529def03329dbfd763ea0c7
//!
//! Both commands agree on the same hash value, confirming the oracle.
//!
//! The SHA-256 raw-bytes tests use NIST FIPS 180-4 published test vectors,
//! verified independently by:
//!   printf 'abc' | openssl dgst -sha256 -hex
//!   printf ''    | openssl dgst -sha256 -hex
//!
//! No implementation code is used as its own oracle.

use sha2::{Digest, Sha256};
use usenet_ipfs_auth::{ClientCertEntry, ClientCertStore};

// ---------------------------------------------------------------------------
// Oracle DER test fixture
//
// Self-signed ed25519 cert, CN=usenet-ipfs-test-cert, generated once and
// hardcoded here. Source commands:
//
//   openssl req -x509 -newkey ed25519 -keyout /tmp/k.pem -out /tmp/c.pem \
//     -days 3650 -nodes -subj "/CN=usenet-ipfs-test-cert"
//   openssl x509 -outform DER -in /tmp/c.pem | xxd -p | tr -d '\n'
//
// SHA-256 verified by two independent openssl commands:
//   openssl x509 -fingerprint -sha256 -noout -in /tmp/c.pem
//   → 6E:EC:02:A6:1E:34:81:26:F9:B3:AD:2C:22:37:4E:1F:63:1B:60:5B:55:29:DE:F0:33:29:DB:FD:76:3E:A0:C7
//   openssl x509 -outform DER -in /tmp/c.pem | openssl dgst -sha256 -hex
//   → 6eec02a61e348126f9b3ad2c22374e1f631b605b5529def03329dbfd763ea0c7
// ---------------------------------------------------------------------------

const TEST_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x55, 0x30, 0x82, 0x01, 0x07, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x66,
    0x10, 0xd6, 0x5f, 0x87, 0x67, 0xda, 0x96, 0x50, 0x31, 0xc5, 0xb0, 0x3e, 0x62, 0xcb, 0xd9, 0x8a,
    0x2f, 0x5e, 0xb5, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x20, 0x31, 0x1e, 0x30, 0x1c,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15, 0x75, 0x73, 0x65, 0x6e, 0x65, 0x74, 0x2d, 0x69, 0x70,
    0x66, 0x73, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x63, 0x65, 0x72, 0x74, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x36, 0x30, 0x34, 0x32, 0x32, 0x30, 0x33, 0x35, 0x33, 0x35, 0x36, 0x5a, 0x17, 0x0d, 0x33,
    0x36, 0x30, 0x34, 0x31, 0x39, 0x30, 0x33, 0x35, 0x33, 0x35, 0x36, 0x5a, 0x30, 0x20, 0x31, 0x1e,
    0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15, 0x75, 0x73, 0x65, 0x6e, 0x65, 0x74, 0x2d,
    0x69, 0x70, 0x66, 0x73, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x63, 0x65, 0x72, 0x74, 0x30, 0x2a,
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xee, 0xa1, 0xaa, 0x9d, 0xe7, 0x12,
    0xdf, 0xfc, 0x79, 0x47, 0xba, 0x0d, 0xc6, 0xd0, 0x8e, 0xa7, 0xb2, 0x97, 0x3e, 0x71, 0x52, 0x91,
    0xc4, 0x2f, 0xed, 0xb9, 0xfa, 0xeb, 0xb2, 0xa6, 0x76, 0x66, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xe6, 0xe4, 0x79, 0x75, 0xba, 0x5c, 0xfd,
    0x84, 0x1a, 0x6e, 0x31, 0xab, 0x98, 0xb4, 0xed, 0x65, 0x67, 0x86, 0xf6, 0x38, 0x30, 0x1f, 0x06,
    0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xe6, 0xe4, 0x79, 0x75, 0xba, 0x5c,
    0xfd, 0x84, 0x1a, 0x6e, 0x31, 0xab, 0x98, 0xb4, 0xed, 0x65, 0x67, 0x86, 0xf6, 0x38, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
    0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0xfa, 0x72, 0x0e, 0x96, 0x35, 0x27, 0xa2,
    0x9b, 0x23, 0x50, 0xbd, 0x4f, 0xff, 0x37, 0x5c, 0xd5, 0x38, 0xaf, 0x66, 0xa7, 0xf1, 0x57, 0x7a,
    0xe7, 0x8b, 0x5b, 0x61, 0xb9, 0xd4, 0x17, 0x22, 0x7d, 0xd1, 0xcf, 0xba, 0x27, 0x81, 0x3a, 0x08,
    0x07, 0xb5, 0x6e, 0x12, 0x3e, 0x6a, 0xa7, 0x07, 0xce, 0xe9, 0xe6, 0x05, 0x19, 0xc6, 0xef, 0xd4,
    0xb8, 0x48, 0x09, 0x78, 0x21, 0xa5, 0x64, 0xdb, 0x02,
];

/// SHA-256 of TEST_CERT_DER — verified by two independent openssl commands.
///
/// openssl x509 -fingerprint -sha256 -noout  → colon-separated uppercase hex
/// openssl dgst -sha256 -hex                  → lowercase continuous hex
///
/// Both agree: 6eec02a61e348126f9b3ad2c22374e1f631b605b5529def03329dbfd763ea0c7
const TEST_CERT_FINGERPRINT_HEX: &str =
    "6eec02a61e348126f9b3ad2c22374e1f631b605b5529def03329dbfd763ea0c7";

const TEST_CERT_FINGERPRINT_PREFIXED: &str =
    "sha256:6eec02a61e348126f9b3ad2c22374e1f631b605b5529def03329dbfd763ea0c7";

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn entry(fp: &str, username: &str) -> ClientCertEntry {
    ClientCertEntry {
        sha256_fingerprint: fp.to_string(),
        username: username.to_string(),
    }
}

fn store_with_alice() -> ClientCertStore {
    ClientCertStore::from_config(&[entry(TEST_CERT_FINGERPRINT_PREFIXED, "alice")])
}

// ---------------------------------------------------------------------------
// Section 1: SHA-256 raw computation tests
//
// Oracle: NIST FIPS 180-4 published test vectors, verified by openssl.
// ---------------------------------------------------------------------------

/// FIPS 180-4 example B.1: SHA-256("abc")
/// Verified: printf 'abc' | openssl dgst -sha256 -hex
/// = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
#[test]
fn sha256_of_abc_matches_fips_180_4_vector() {
    let digest = Sha256::digest(b"abc");
    let hex = hex::encode(digest);
    assert_eq!(
        hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256('abc') must match NIST FIPS 180-4 / openssl oracle"
    );
}

/// FIPS 180-4: SHA-256("") (empty input)
/// Verified: printf '' | openssl dgst -sha256 -hex
/// = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
#[test]
fn sha256_of_empty_matches_fips_180_4_vector() {
    let digest = Sha256::digest(b"");
    let hex = hex::encode(digest);
    assert_eq!(
        hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256('') must match NIST FIPS 180-4 / openssl oracle"
    );
}

/// Verify that SHA-256(TEST_CERT_DER) matches the openssl-derived fingerprint.
/// This is the critical oracle cross-check: the DER bytes hardcoded above,
/// hashed by the sha2 crate, must equal what openssl reported.
#[test]
fn sha256_of_test_cert_der_matches_openssl_oracle() {
    let digest = Sha256::digest(TEST_CERT_DER);
    let hex = hex::encode(digest);
    assert_eq!(
        hex, TEST_CERT_FINGERPRINT_HEX,
        "SHA-256 of hardcoded DER must match openssl x509 -fingerprint -sha256 oracle"
    );
}

// ---------------------------------------------------------------------------
// Section 2: compute_fingerprint function
//
// If Agent I exposes a `compute_fingerprint(der: &[u8]) -> String` helper,
// these tests validate it against the openssl oracle. The expected output
// format is "sha256:<lowercase-hex>" — the same format used as map keys.
// ---------------------------------------------------------------------------

#[test]
fn compute_fingerprint_of_test_cert_der_matches_oracle() {
    let fp = usenet_ipfs_auth::compute_fingerprint(TEST_CERT_DER);
    assert_eq!(
        fp, TEST_CERT_FINGERPRINT_PREFIXED,
        "compute_fingerprint must return 'sha256:<hex>' matching openssl oracle"
    );
}

// ---------------------------------------------------------------------------
// Section 3: ClientCertStore unit tests
// ---------------------------------------------------------------------------

/// lookup of a known fingerprint returns the associated username.
#[test]
fn lookup_known_fingerprint_returns_username() {
    let store = store_with_alice();
    let result = store.lookup(TEST_CERT_FINGERPRINT_PREFIXED);
    assert_eq!(
        result,
        Some("alice"),
        "lookup of the configured fingerprint must return 'alice'"
    );
}

/// lookup of an unknown fingerprint returns None.
#[test]
fn lookup_unknown_fingerprint_returns_none() {
    let store = store_with_alice();
    let unknown = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let result = store.lookup(unknown);
    assert!(
        result.is_none(),
        "lookup of an unconfigured fingerprint must return None"
    );
}

/// empty() store returns None for any fingerprint.
#[test]
fn empty_store_returns_none_for_any_fingerprint() {
    let store = ClientCertStore::empty();
    assert!(
        store.lookup(TEST_CERT_FINGERPRINT_PREFIXED).is_none(),
        "empty ClientCertStore must return None for any fingerprint"
    );
    assert!(
        store
            .lookup("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .is_none(),
        "empty ClientCertStore must return None for the SHA-256('abc') fingerprint"
    );
}

/// Fingerprint lookup is case-insensitive: "sha256:ABCD..." == "sha256:abcd..."
#[test]
fn lookup_is_case_insensitive_uppercase_prefix() {
    let store = store_with_alice();
    let upper = TEST_CERT_FINGERPRINT_PREFIXED.to_ascii_uppercase();
    let result = store.lookup(&upper);
    assert_eq!(
        result,
        Some("alice"),
        "lookup must be case-insensitive: 'SHA256:6EEC...' must find 'alice'"
    );
}

#[test]
fn lookup_is_case_insensitive_mixed_case() {
    let store = store_with_alice();
    let mixed = format!(
        "Sha256:{}",
        TEST_CERT_FINGERPRINT_HEX
            .chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            })
            .collect::<String>()
    );
    let result = store.lookup(&mixed);
    assert_eq!(
        result,
        Some("alice"),
        "lookup must be case-insensitive for mixed-case fingerprint input"
    );
}

/// Fingerprint normalisation: entries stored with uppercase are found by lowercase lookup.
#[test]
fn entry_stored_uppercase_found_by_lowercase_lookup() {
    let upper_fp = TEST_CERT_FINGERPRINT_PREFIXED.to_ascii_uppercase();
    let store = ClientCertStore::from_config(&[entry(&upper_fp, "alice")]);
    let result = store.lookup(TEST_CERT_FINGERPRINT_PREFIXED);
    assert_eq!(
        result,
        Some("alice"),
        "entry inserted with uppercase fingerprint must be found by lowercase lookup"
    );
}

/// lookup with colon-separated openssl-style fingerprint (no sha256: prefix)
/// should still match — the normalise() function strips the prefix requirement.
/// This tests the implementation's tolerance for prefix-less input.
#[test]
fn lookup_without_prefix_still_finds_entry() {
    let store = store_with_alice();
    let result = store.lookup(TEST_CERT_FINGERPRINT_HEX);
    assert_eq!(
        result,
        Some("alice"),
        "lookup of fingerprint without 'sha256:' prefix must still match stored entry"
    );
}

/// Multiple users can be registered; each fingerprint maps to its own username.
#[test]
fn multiple_entries_each_maps_to_own_username() {
    let fp_alice = TEST_CERT_FINGERPRINT_PREFIXED;
    // SHA-256("abc") from NIST FIPS 180-4, verified by openssl.
    let fp_bob = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let store = ClientCertStore::from_config(&[entry(fp_alice, "alice"), entry(fp_bob, "bob")]);
    assert_eq!(store.lookup(fp_alice), Some("alice"));
    assert_eq!(store.lookup(fp_bob), Some("bob"));
    assert_ne!(
        store.lookup(fp_alice),
        Some("bob"),
        "alice's cert must not map to bob"
    );
    assert_ne!(
        store.lookup(fp_bob),
        Some("alice"),
        "bob's cert must not map to alice"
    );
}

/// Duplicate fingerprint: last entry wins (same behaviour as CredentialStore file).
#[test]
fn duplicate_fingerprint_last_entry_wins() {
    let fp = TEST_CERT_FINGERPRINT_PREFIXED;
    let store = ClientCertStore::from_config(&[entry(fp, "alice"), entry(fp, "mallory")]);
    let result = store.lookup(fp);
    assert_eq!(
        result,
        Some("mallory"),
        "last entry for a duplicate fingerprint must win"
    );
}

/// Username matching is case-insensitive: cert mapped to "ALICE" is found when
/// the session sends AUTHINFO USER alice (lowercase).
///
/// This test validates only the stored username's case normalisation.
/// The session-level check (that "alice" == stored username for alice's cert)
/// is in the reader dispatch tests.
#[test]
fn stored_username_is_lowercased() {
    let store = ClientCertStore::from_config(&[entry(TEST_CERT_FINGERPRINT_PREFIXED, "ALICE")]);
    assert_eq!(
        store.lookup(TEST_CERT_FINGERPRINT_PREFIXED),
        Some("alice"),
        "stored username must be normalised to lowercase"
    );
}
