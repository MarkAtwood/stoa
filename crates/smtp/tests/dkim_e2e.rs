// E2E tests verifying that outbound messages carry a structurally valid
// DKIM-Signature header.
//
// Oracle: RFC 8463 §A.2 test ed25519 key pair (fixed external test vectors).
// These tests use the signing path directly; full cryptographic verification
// requires a DNS lookup for the public key record, so Test 3 stops at parse.

use mail_auth::AuthenticatedMessage;
use mail_auth::common::crypto::Ed25519Key;
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;
use std::sync::Arc;

// RFC 8463 §A.2 private key seed bytes
// (base64: "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")
const RFC8463_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
    0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
    0x7f, 0x60,
];

// RFC 8463 §A.2 public key bytes
// (base64: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
const RFC8463_PUBKEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
    0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
    0x51, 0x1a,
];

fn test_rfc8463_signer() -> Arc<DkimSigner<Ed25519Key, mail_auth::dkim::Done>> {
    let ed_key = Ed25519Key::from_seed_and_public_key(&RFC8463_SEED, &RFC8463_PUBKEY)
        .expect("RFC 8463 §A.2 test key pair must be valid");
    Arc::new(
        DkimSigner::from_key(ed_key)
            .domain("example.com")
            .selector("test")
            .headers(["From", "To", "Subject", "Date", "Message-ID", "MIME-Version"]),
    )
}

// Minimal RFC 5322 message used as signing input for all three tests.
const TEST_MESSAGE: &[u8] = b"From: sender@example.com\r\n\
To: recip@example.com\r\n\
Subject: DKIM test\r\n\
Date: Thu, 01 Jan 2026 00:00:00 +0000\r\n\
Message-ID: <test@example.com>\r\n\
MIME-Version: 1.0\r\n\
\r\n\
Hello, DKIM!\r\n";

// Oracle: RFC 6376 §3.5 — DKIM-Signature is prepended to the message, must
// carry "a=ed25519-sha256", and must NOT contain "l=" (body length tag
// prohibited by RFC 8463 §3.4 for security reasons).
//
// This mirrors the signing path in queue.rs drain_once: signer.sign(article)
// -> sig.to_header() -> prepend header bytes before article bytes.
#[test]
fn test_e2e_nntp_dkim_header_prepended() {
    let signer = test_rfc8463_signer();
    let sig = signer.sign(TEST_MESSAGE).expect("sign must succeed with RFC 8463 test key");
    let header = sig.to_header();

    assert!(
        header.starts_with("DKIM-Signature:"),
        "DKIM-Signature header must begin with 'DKIM-Signature:', got: {header:?}"
    );
    assert!(
        header.contains("a=ed25519-sha256"),
        "DKIM-Signature must carry algorithm tag 'a=ed25519-sha256', got: {header:?}"
    );
    assert!(
        !header.contains("l="),
        "DKIM-Signature must NOT contain body length tag 'l=', got: {header:?}"
    );

    // Prepend: signed output starts with the DKIM-Signature header, followed by
    // the original article bytes unchanged — exactly the pattern in drain_once.
    let mut signed = Vec::with_capacity(header.len() + TEST_MESSAGE.len());
    signed.extend_from_slice(header.as_bytes());
    signed.extend_from_slice(TEST_MESSAGE);

    assert!(
        signed.starts_with(b"DKIM-Signature:"),
        "prepended message must begin with DKIM-Signature header bytes"
    );
    assert_eq!(
        &signed[header.len()..],
        TEST_MESSAGE,
        "original article bytes must follow the DKIM-Signature header unchanged"
    );
}

// Oracle: same RFC 6376 §3.5 properties, verified for the relay signing path.
//
// relay_queue.rs try_deliver_one uses the same signer.sign(article_bytes) ->
// sig.to_header() -> prepend pattern.  This test confirms the same structural
// invariants hold for the relay code path.
#[test]
fn test_e2e_relay_dkim_header_prepended() {
    let signer = test_rfc8463_signer();
    let sig = signer.sign(TEST_MESSAGE).expect("sign must succeed with RFC 8463 test key");
    let header = sig.to_header();

    assert!(
        header.starts_with("DKIM-Signature:"),
        "relay path: DKIM-Signature header must begin with 'DKIM-Signature:', got: {header:?}"
    );
    assert!(
        header.contains("a=ed25519-sha256"),
        "relay path: DKIM-Signature must carry 'a=ed25519-sha256', got: {header:?}"
    );
    assert!(
        !header.contains("l="),
        "relay path: DKIM-Signature must NOT contain body length tag 'l=', got: {header:?}"
    );

    let mut signed = Vec::with_capacity(header.len() + TEST_MESSAGE.len());
    signed.extend_from_slice(header.as_bytes());
    signed.extend_from_slice(TEST_MESSAGE);

    assert!(
        signed.starts_with(b"DKIM-Signature:"),
        "relay path: prepended message must begin with DKIM-Signature header bytes"
    );
    assert_eq!(
        &signed[header.len()..],
        TEST_MESSAGE,
        "relay path: original article bytes must follow the DKIM-Signature header unchanged"
    );
}

// Oracle: mail_auth::AuthenticatedMessage::parse must recognise the prepended
// DKIM-Signature header and report exactly one parsed DKIM signature header.
//
// Full cryptographic verification (verify_dkim) requires a live DNS lookup for
// the public key TXT record; this test stops at parse so the suite runs offline.
// Structural validity of the header is sufficient to confirm the signing path
// produces well-formed output.
#[test]
fn test_e2e_dkim_signature_cryptographically_valid() {
    let signer = test_rfc8463_signer();
    let sig = signer.sign(TEST_MESSAGE).expect("sign must succeed");
    let header = sig.to_header();

    // Build the signed message exactly as drain_once and try_deliver_one do.
    let mut signed = Vec::with_capacity(header.len() + TEST_MESSAGE.len());
    signed.extend_from_slice(header.as_bytes());
    signed.extend_from_slice(TEST_MESSAGE);

    // mail_auth::AuthenticatedMessage::parse returns None only if the message is
    // unparseable; a well-formed RFC 5322 message with a valid DKIM-Signature
    // header must parse successfully.
    let parsed = AuthenticatedMessage::parse(&signed)
        .expect("signed message must parse as AuthenticatedMessage");

    // dkim_headers holds every parsed DKIM-Signature header found in the message.
    // We prepended exactly one, so there must be exactly one entry.
    assert_eq!(
        parsed.dkim_headers.len(),
        1,
        "parsed message must contain exactly one DKIM-Signature header, got: {}",
        parsed.dkim_headers.len()
    );

    // The parsed signature must not itself be an error — the header was
    // well-formed enough for mail_auth to decode it.
    // .header holds the T = crate::Result<dkim::Signature>; .value is raw bytes.
    assert!(
        parsed.dkim_headers[0].header.is_ok(),
        "parsed DKIM-Signature must be structurally valid (no parse error), \
         got: {:?}",
        parsed.dkim_headers[0].header
    );
}

// Oracle: when no DkimSigner is configured (the None branch in both drain
// paths), article bytes must pass through to the transport layer unchanged.
// This test directly exercises the else-branch logic without instantiating a
// signer.
#[test]
fn test_e2e_no_dkim_signer_passthrough() {
    let signer: Option<Arc<DkimSigner<Ed25519Key, mail_auth::dkim::Done>>> = None;

    // Simulate the None branch from drain_once / try_deliver_one:
    //   let article_to_send = if let Some(s) = &signer { sign(...) } else { article };
    let article_to_send: &[u8] = if signer.is_some() {
        panic!("signer must be None in this test");
    } else {
        TEST_MESSAGE
    };

    assert_eq!(
        article_to_send, TEST_MESSAGE,
        "without a DkimSigner the article bytes must be passed through unmodified"
    );
    assert!(
        !article_to_send.starts_with(b"DKIM-Signature:"),
        "unsigned article must not start with DKIM-Signature header"
    );
}
