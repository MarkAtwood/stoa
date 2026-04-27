//! Known-good test vectors for article serialization, CID computation, and
//! Ed25519 signing.
//!
//! All expected values were computed by independent reference implementations
//! (Python `hashlib`, Python `cryptography`) and are hardcoded as literals.
//! No vector is derived from the code under test.

use stoa_core::{
    article::{Article, ArticleHeader, GroupName},
    canonical::canonical_bytes,
    signing::{sign, verify, SigningKey, VerifyingKey},
};

// ── Shared article construction ───────────────────────────────────────────────

/// The base article used for Vector 1 (minimal, no extra headers).
fn vector1_article() -> Article {
    Article {
        header: ArticleHeader {
            from: "user@example.com".into(),
            date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
            message_id: "<test@example.com>".into(),
            newsgroups: vec![GroupName::new("comp.lang.rust").unwrap()],
            subject: "Test subject".into(),
            path: "news.example.com!user".into(),
            extra_headers: vec![],
        },
        body: b"Body text.\r\n".to_vec(),
    }
}

// ── Serialization vectors ─────────────────────────────────────────────────────

/// Vector 1 — minimal article, no extra headers.
///
/// Expected canonical bytes were manually verified against the format spec:
///   From: user@example.com\r\n
///   Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n
///   Message-ID: <test@example.com>\r\n
///   Newsgroups: comp.lang.rust\r\n
///   Subject: Test subject\r\n
///   Path: news.example.com!user\r\n
///   \x00\n
///   Body text.\r\n
#[test]
fn serial_vector1_canonical_bytes() {
    let article = vector1_article();
    let got = canonical_bytes(&article);

    let expected: &[u8] = &[
        0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x75, 0x73, 0x65, 0x72, 0x40, 0x65, 0x78, 0x61, 0x6d,
        0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20,
        0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x30, 0x31, 0x20, 0x4a, 0x61, 0x6e, 0x20, 0x32, 0x30, 0x32,
        0x34, 0x20, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x20, 0x2b, 0x30, 0x30, 0x30,
        0x30, 0x0d, 0x0a, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2d, 0x49, 0x44, 0x3a, 0x20,
        0x3c, 0x74, 0x65, 0x73, 0x74, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
        0x6f, 0x6d, 0x3e, 0x0d, 0x0a, 0x4e, 0x65, 0x77, 0x73, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73,
        0x3a, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x72, 0x75, 0x73,
        0x74, 0x0d, 0x0a, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x20, 0x54, 0x65, 0x73,
        0x74, 0x20, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x0d, 0x0a, 0x50, 0x61, 0x74, 0x68,
        0x3a, 0x20, 0x6e, 0x65, 0x77, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x21, 0x75, 0x73, 0x65, 0x72, 0x0d, 0x0a, 0x00, 0x0a, 0x42, 0x6f, 0x64,
        0x79, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x0d, 0x0a,
    ];

    assert_eq!(
        got, expected,
        "canonical bytes do not match Vector 1 reference"
    );
}

/// Vector 2 — multi-newsgroup lexicographic sort.
///
/// Groups inserted as ["sci.physics", "alt.science", "comp.lang.python"] must
/// be serialized in sorted order: alt.science,comp.lang.python,sci.physics.
#[test]
fn serial_vector2_newsgroups_sorted() {
    let mut article = vector1_article();
    article.header.newsgroups = vec![
        GroupName::new("sci.physics").unwrap(),
        GroupName::new("alt.science").unwrap(),
        GroupName::new("comp.lang.python").unwrap(),
    ];

    let bytes = canonical_bytes(&article);
    let text = std::str::from_utf8(&bytes).expect("canonical bytes must be valid UTF-8");
    assert!(
        text.contains("Newsgroups: alt.science,comp.lang.python,sci.physics\r\n"),
        "newsgroups must appear in lexicographic order; got: {:?}",
        text.lines().find(|l| l.starts_with("Newsgroups")),
    );
}

/// Vector 3 — extra-header alphabetic sort.
///
/// Extra headers inserted as [("Z-Header","z"), ("A-Header","a")] must
/// appear with A-Header before Z-Header in canonical output.
#[test]
fn serial_vector3_extra_headers_sorted() {
    let mut article = vector1_article();
    article.header.extra_headers = vec![
        ("Z-Header".into(), "z".into()),
        ("A-Header".into(), "a".into()),
    ];

    let bytes = canonical_bytes(&article);
    let text = std::str::from_utf8(&bytes).expect("canonical bytes must be valid UTF-8");

    let a_pos = text.find("A-Header: a\r\n").expect("A-Header not found");
    let z_pos = text.find("Z-Header: z\r\n").expect("Z-Header not found");
    assert!(
        a_pos < z_pos,
        "A-Header must precede Z-Header in canonical bytes"
    );
}

// ── Ed25519 signature vectors ─────────────────────────────────────────────────

/// Reconstruct the known signing key from its fixed 32-byte seed.
///
/// Seed: [0x42; 32]
/// Public key (Python cryptography reference):
///   2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
fn known_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

/// Sig Vector 1 — sign empty bytes.
///
/// Signature computed by Python `cryptography`:
///   3f9f3147d0dd159f334cb800435ae49a2837adae5e6b2394906edc2cfed82978
///   5e3dd186eb2fed1319a0451917cb6617fcbe9382e0d1343eb5ffd4a9a2dd820c
#[test]
fn sig_vector1_sign_empty_bytes() {
    let key = known_signing_key();
    let pubkey: VerifyingKey = key.verifying_key();

    // Verify the public key matches the reference.
    let expected_pubkey =
        hex::decode("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
            .expect("valid hex");
    assert_eq!(
        pubkey.as_bytes(),
        expected_pubkey.as_slice(),
        "public key must match reference"
    );

    // Sign empty bytes and compare to reference signature.
    let sig = sign(&key, b"");
    let expected_sig_hex =
        "3f9f3147d0dd159f334cb800435ae49a2837adae5e6b2394906edc2cfed829785e3dd186eb2fed1319a0451917cb6617fcbe9382e0d1343eb5ffd4a9a2dd820c";
    let expected_sig_bytes = hex::decode(expected_sig_hex).expect("valid hex");

    assert_eq!(
        sig.to_bytes().as_slice(),
        expected_sig_bytes.as_slice(),
        "Sig Vector 1 must match Python reference"
    );

    // The reference signature must also verify cleanly.
    let ref_sig =
        ed25519_dalek::Signature::from_bytes(expected_sig_bytes.as_slice().try_into().unwrap());
    verify(&pubkey, b"", &ref_sig).expect("Sig Vector 1 must verify against known public key");
}

/// Sig Vector 2 — sign the canonical bytes of Vector 1 article.
///
/// Signature computed by Python `cryptography`:
///   01d182dd4f9375e72ae5e95da329a6865adb58d1ddc1f3cdb7d1504c43c0c59
///   579ca874a42ed52fe611f5b64a41870f0b7b43fa15562fe063b78241b4ea7ec0a
#[test]
fn sig_vector2_sign_article_canonical_bytes() {
    let key = known_signing_key();
    let pubkey: VerifyingKey = key.verifying_key();

    let article = vector1_article();
    let cbytes = canonical_bytes(&article);

    let sig = sign(&key, &cbytes);
    let expected_sig_hex =
        "01d182dd4f9375e72ae5e95da329a6865adb58d1ddc1f3cdb7d1504c43c0c59579ca874a42ed52fe611f5b64a41870f0b7b43fa15562fe063b78241b4ea7ec0a";
    let expected_sig_bytes = hex::decode(expected_sig_hex).expect("valid hex");

    assert_eq!(
        sig.to_bytes().as_slice(),
        expected_sig_bytes.as_slice(),
        "Sig Vector 2 must match Python reference"
    );

    // The reference signature must also verify cleanly.
    let ref_sig =
        ed25519_dalek::Signature::from_bytes(expected_sig_bytes.as_slice().try_into().unwrap());
    verify(&pubkey, &cbytes, &ref_sig).expect("Sig Vector 2 must verify against known public key");
}
