//! Shared DER header constants for ed25519 key encoding.
//!
//! Both `keygen` and `key_rotate` construct DER-encoded keys by prepending
//! a fixed ASN.1 header to the raw key bytes.  Centralising the constants
//! here ensures a single point of change if the encoding ever needs updating.

/// PKCS#8 v1 DER header for an ed25519 private key (16 bytes).
///
/// ASN.1 structure:
/// ```text
/// SEQUENCE {
///   INTEGER 0,
///   SEQUENCE { OID 1.3.101.112 },
///   OCTET STRING { OCTET STRING { <32-byte seed> } }
/// }
/// ```
/// Append the 32-byte signing-key seed to obtain a complete 48-byte DER blob.
pub(crate) const PKCS8_ED25519_HEADER: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
    0x20,
];

/// SubjectPublicKeyInfo DER header for an ed25519 public key (12 bytes).
///
/// ASN.1 structure:
/// ```text
/// SEQUENCE {
///   SEQUENCE { OID 1.3.101.112 },
///   BIT STRING { <32-byte public key> }
/// }
/// ```
/// Append the 32-byte verifying-key bytes to obtain a complete 44-byte DER blob.
pub(crate) const SPKI_ED25519_HEADER: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
