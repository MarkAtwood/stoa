//! Session-level tests for client certificate authentication bypass.
//!
//! These tests validate that when a TLS session presents a client certificate
//! whose SHA-256 fingerprint appears in the configured `ClientCertStore`:
//!
//!   AUTHINFO USER <username>  →  281 (authenticated, no AUTHINFO PASS required)
//!
//! And that when the fingerprint is absent or the username does not match:
//!
//!   AUTHINFO USER <username>  →  381 (enter password, proceed to password auth)
//!
//! # Oracle rationale
//!
//! Fingerprint vectors are derived from two independent OpenSSL commands run
//! against a known DER-encoded self-signed ed25519 certificate:
//!
//!   openssl req -x509 -newkey ed25519 -keyout /tmp/k.pem -out /tmp/c.pem \
//!     -days 3650 -nodes -subj "/CN=usenet-ipfs-test-cert"
//!   openssl x509 -fingerprint -sha256 -noout -in /tmp/c.pem
//!   → 6E:EC:02:A6:1E:34:81:26:F9:B3:AD:2C:22:37:4E:1F:63:1B:60:5B:55:29:DE:F0:33:29:DB:FD:76:3E:A0:C7
//!   openssl x509 -outform DER -in /tmp/c.pem | openssl dgst -sha256 -hex
//!   → 6eec02a61e348126f9b3ad2c22374e1f631b605b5529def03329dbfd763ea0c7
//!
//! Session response codes are specified by RFC 4643 §2 and RFC 3977 §3.1:
//!   - 281: Authentication accepted
//!   - 381: Enter passphrase (more authentication information required)
//!   - 483: Encryption required
//!
//! No implementation code is used as its own oracle.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use usenet_ipfs_auth::TrustedIssuerStore;
use usenet_ipfs_reader::{
    config::{AuthConfig, ClientCertEntry},
    session::{
        command::Command,
        context::SessionContext,
        dispatch::dispatch,
        state::SessionState,
    },
    store::client_cert_store::ClientCertStore,
};

// ---------------------------------------------------------------------------
// Shared test vectors (same oracle as auth/tests/client_cert_store.rs)
// ---------------------------------------------------------------------------

/// SHA-256 fingerprint of the hardcoded test cert DER, openssl-verified.
///
/// Derivation:
///   openssl req -x509 -newkey ed25519 ... -subj "/CN=usenet-ipfs-test-cert"
///   openssl x509 -fingerprint -sha256 -noout  → 6E:EC:02:A6:...
///   openssl x509 -outform DER | openssl dgst -sha256 -hex
///   → 6eec02a61e348126f9b3ad2c22374e1f631b605b5529def03329dbfd763ea0c7
const ALICE_CERT_FINGERPRINT: &str =
    "sha256:6eec02a61e348126f9b3ad2c22374e1f631b605b5529def03329dbfd763ea0c7";

/// SHA-256("abc") as a second synthetic fingerprint (NIST FIPS 180-4 vector,
/// verified by openssl: printf 'abc' | openssl dgst -sha256 -hex).
/// Used to represent a second, independent certificate fingerprint.
const BOB_CERT_FINGERPRINT: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn test_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)
}

fn open_auth() -> AuthConfig {
    AuthConfig {
        required: false,
        users: vec![],
        credential_file: None,
        client_certs: vec![],
        trusted_issuers: vec![],
    }
}

fn no_issuers() -> TrustedIssuerStore {
    TrustedIssuerStore::empty()
}

fn entry(fp: &str, username: &str) -> ClientCertEntry {
    ClientCertEntry {
        sha256_fingerprint: fp.to_string(),
        username: username.to_string(),
    }
}

/// Produce a TLS SessionContext where the peer presented a client certificate
/// with the given SHA-256 fingerprint.
fn ctx_tls_with_cert(cert_fingerprint: &str, auth_required: bool) -> SessionContext {
    let mut ctx = SessionContext::new(test_addr(), auth_required, true, true);
    ctx.client_cert_fingerprint = Some(cert_fingerprint.to_string());
    ctx
}

/// Produce a TLS SessionContext with no client certificate presented.
fn ctx_tls_no_cert(auth_required: bool) -> SessionContext {
    SessionContext::new(test_addr(), auth_required, true, true)
}

fn cert_store_with_alice() -> ClientCertStore {
    ClientCertStore::from_entries(&[entry(ALICE_CERT_FINGERPRINT, "alice")])
}

// ---------------------------------------------------------------------------
// Section 1: Cert fingerprint in store, username matches — 281 bypass
// ---------------------------------------------------------------------------

/// Core invariant: when the presented cert fingerprint maps to "alice" and
/// AUTHINFO USER alice is sent, the session returns 281 immediately.
/// No AUTHINFO PASS is required.
#[test]
fn cert_auth_matching_username_returns_281() {
    let mut ctx = ctx_tls_with_cert(ALICE_CERT_FINGERPRINT, true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    let resp = dispatch(
        &mut ctx,
        Command::AuthinfoUser("alice".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_eq!(
        resp.code,
        281,
        "AUTHINFO USER alice with matching cert fingerprint must return 281 (RFC 4643 §2)"
    );
}

/// After cert-bypass 281, the session must be in Active state (not Authenticating).
#[test]
fn cert_auth_bypass_sets_active_state() {
    let mut ctx = ctx_tls_with_cert(ALICE_CERT_FINGERPRINT, true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    dispatch(
        &mut ctx,
        Command::AuthinfoUser("alice".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_eq!(
        ctx.state,
        SessionState::Active,
        "session must be Active after cert-bypass 281, not Authenticating"
    );
}

/// After cert-bypass 281, authenticated_user must be set to the matched username.
#[test]
fn cert_auth_bypass_sets_authenticated_user() {
    let mut ctx = ctx_tls_with_cert(ALICE_CERT_FINGERPRINT, true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    dispatch(
        &mut ctx,
        Command::AuthinfoUser("alice".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_eq!(
        ctx.authenticated_user.as_deref(),
        Some("alice"),
        "authenticated_user must be 'alice' after cert-bypass"
    );
}

/// Fingerprint lookup is case-insensitive: uppercase fingerprint in context
/// matches lowercase-stored entry and returns 281.
#[test]
fn cert_auth_case_insensitive_fingerprint_in_context() {
    let upper_fp = ALICE_CERT_FINGERPRINT.to_ascii_uppercase();
    let mut ctx = ctx_tls_with_cert(&upper_fp, true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    let resp = dispatch(
        &mut ctx,
        Command::AuthinfoUser("alice".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_eq!(
        resp.code,
        281,
        "cert bypass must work when context fingerprint is uppercase"
    );
}

// ---------------------------------------------------------------------------
// Section 2: Security invariant — username mismatch must NOT bypass
// ---------------------------------------------------------------------------

/// CRITICAL SECURITY INVARIANT:
/// Cert fingerprint maps to "alice" in the store, but AUTHINFO USER bob is sent.
/// Must NOT return 281 — bob is not alice.
/// Must return 381 (need password) or 481 (rejected).
#[test]
fn cert_auth_username_mismatch_does_not_bypass() {
    let mut ctx = ctx_tls_with_cert(ALICE_CERT_FINGERPRINT, true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    let resp = dispatch(
        &mut ctx,
        Command::AuthinfoUser("bob".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_ne!(
        resp.code,
        281,
        "AUTHINFO USER bob with alice's cert MUST NOT return 281 — username mismatch"
    );
    assert!(
        resp.code == 381 || resp.code == 481,
        "username mismatch must return 381 (need password) or 481 (rejected), got {}",
        resp.code
    );
}

/// After username mismatch, the session must NOT be in Active state.
#[test]
fn cert_auth_username_mismatch_does_not_set_active_state() {
    let mut ctx = ctx_tls_with_cert(ALICE_CERT_FINGERPRINT, true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    dispatch(
        &mut ctx,
        Command::AuthinfoUser("bob".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_ne!(
        ctx.state,
        SessionState::Active,
        "session must not become Active when cert username does not match"
    );
}

/// After username mismatch, authenticated_user must not be set.
#[test]
fn cert_auth_username_mismatch_does_not_set_authenticated_user() {
    let mut ctx = ctx_tls_with_cert(ALICE_CERT_FINGERPRINT, true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    dispatch(
        &mut ctx,
        Command::AuthinfoUser("bob".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert!(
        ctx.authenticated_user.is_none(),
        "authenticated_user must not be set on username mismatch"
    );
}

// ---------------------------------------------------------------------------
// Section 3: No client cert — falls through to password auth
// ---------------------------------------------------------------------------

/// When no client certificate is presented (no fingerprint in context),
/// AUTHINFO USER must return 381 and require AUTHINFO PASS.
#[test]
fn no_cert_authinfo_user_returns_381() {
    let mut ctx = ctx_tls_no_cert(true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    let resp = dispatch(
        &mut ctx,
        Command::AuthinfoUser("alice".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_eq!(
        resp.code,
        381,
        "AUTHINFO USER without a client cert must return 381 (need password)"
    );
}

/// When no client cert, session stays in Authenticating after AUTHINFO USER.
#[test]
fn no_cert_authinfo_user_stays_authenticating() {
    let mut ctx = ctx_tls_no_cert(true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    dispatch(
        &mut ctx,
        Command::AuthinfoUser("alice".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_eq!(
        ctx.state,
        SessionState::Authenticating,
        "session must remain Authenticating when no client cert presented"
    );
}

// ---------------------------------------------------------------------------
// Section 4: Cert fingerprint not in store — falls through to password auth
// ---------------------------------------------------------------------------

/// When the client presents a cert whose fingerprint is NOT in the store,
/// AUTHINFO USER must return 381 (not bypass to 281).
#[test]
fn cert_fingerprint_not_in_store_returns_381() {
    let mut ctx = ctx_tls_with_cert(BOB_CERT_FINGERPRINT, true);
    let cert_store = cert_store_with_alice();
    let auth = open_auth();

    let resp = dispatch(
        &mut ctx,
        Command::AuthinfoUser("bob".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_ne!(
        resp.code,
        281,
        "AUTHINFO USER with an unconfigured cert fingerprint must not return 281"
    );
}

/// Empty cert store means cert bypass is disabled — AUTHINFO USER returns 381.
#[test]
fn empty_cert_store_disables_cert_bypass() {
    let mut ctx = ctx_tls_with_cert(ALICE_CERT_FINGERPRINT, true);
    let cert_store = ClientCertStore::empty();
    let auth = open_auth();

    let resp = dispatch(
        &mut ctx,
        Command::AuthinfoUser("alice".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_ne!(
        resp.code,
        281,
        "empty ClientCertStore must not bypass auth even when a cert fingerprint is present"
    );
    assert_eq!(
        resp.code,
        381,
        "empty ClientCertStore must return 381 (need password)"
    );
}

// ---------------------------------------------------------------------------
// Section 5: Cert bypass does not apply on plain (non-TLS) connections
// ---------------------------------------------------------------------------

/// Even if a context has a cert fingerprint set, plain connections
/// (tls_active=false) with auth.required=true must return 483 (TLS required),
/// not 281.
#[test]
fn cert_bypass_does_not_apply_on_plain_connection_with_required_auth() {
    let mut ctx = SessionContext::new(test_addr(), true, true, false);
    ctx.client_cert_fingerprint = Some(ALICE_CERT_FINGERPRINT.to_string());
    let cert_store = cert_store_with_alice();
    let auth = AuthConfig {
        required: true,
        users: vec![],
        credential_file: None,
        client_certs: vec![],
        trusted_issuers: vec![],
    };

    let resp = dispatch(
        &mut ctx,
        Command::AuthinfoUser("alice".into()),
        &auth,
        &cert_store,
        &no_issuers(),
        None,
    );
    assert_eq!(
        resp.code,
        483,
        "plain connection with auth.required=true must return 483, not 281"
    );
}
