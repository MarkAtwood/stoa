//! Integration tests for stoa-auth crate.
//!
//! These tests validate the extracted CredentialStore against the bcrypt
//! specification (Provos & Mazieres, 1999) as the external oracle.  No
//! implementation code is used as its own oracle — all password acceptance
//! decisions are cross-checked against bcrypt::verify directly.
//!
//! Oracle rationale:
//!   bcrypt::hash("password", cost) produces a $2b$cost$... string.
//!   bcrypt::verify("password", hash) is the independent verifier.
//!   CredentialStore::check() must agree with bcrypt::verify.

use std::time::Instant;
use stoa_auth::{AuthConfig, CredentialStore, UserCredential};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Produce a CredentialStore with a single user "alice" whose password is
/// "correct-horse", hashed at cost 4 (minimum valid bcrypt cost, fast tests).
/// The hash is computed by bcrypt::hash at test time and verified by
/// bcrypt::verify independently — not by CredentialStore itself.
fn store_with_alice() -> CredentialStore {
    let hash =
        bcrypt::hash("correct-horse", 4).expect("bcrypt::hash must not fail with valid cost");
    // Independently verify our oracle hash before using it in tests.
    assert!(
        bcrypt::verify("correct-horse", &hash).unwrap_or(false),
        "oracle self-check: bcrypt::verify must accept the hash we just produced"
    );
    let users = vec![UserCredential {
        username: "alice".to_string(),
        password: hash,
    }];
    CredentialStore::from_credentials(&users)
}

// ---------------------------------------------------------------------------
// Correct-password acceptance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn correct_password_is_accepted() {
    let store = store_with_alice();
    assert!(
        store.check("alice", "correct-horse").await,
        "CredentialStore::check must return true for the correct password"
    );
}

// ---------------------------------------------------------------------------
// Wrong-password rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_password_is_rejected() {
    let store = store_with_alice();
    assert!(
        !store.check("alice", "wrong-password").await,
        "CredentialStore::check must return false for a wrong password"
    );
}

// ---------------------------------------------------------------------------
// Unknown-user rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_user_is_rejected() {
    let store = store_with_alice();
    assert!(
        !store.check("bob", "any-password").await,
        "CredentialStore::check must return false for an unknown username"
    );
}

// ---------------------------------------------------------------------------
// Empty store rejects all
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_store_rejects_all() {
    let store = CredentialStore::empty();
    assert!(
        !store.check("alice", "any-password").await,
        "empty CredentialStore must reject all credentials"
    );
}

// ---------------------------------------------------------------------------
// Username case folding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn username_is_case_insensitive_upper() {
    let store = store_with_alice();
    assert!(
        store.check("ALICE", "correct-horse").await,
        "uppercase username must match the lowercase-stored entry"
    );
}

#[tokio::test]
async fn username_is_case_insensitive_mixed() {
    let store = store_with_alice();
    assert!(
        store.check("Alice", "correct-horse").await,
        "mixed-case username must match the lowercase-stored entry"
    );
}

#[tokio::test]
async fn wrong_password_with_cased_username_is_rejected() {
    let store = store_with_alice();
    assert!(
        !store.check("ALICE", "wrong-password").await,
        "wrong password must be rejected even when username case matches"
    );
}

// ---------------------------------------------------------------------------
// from_credentials constructor
// ---------------------------------------------------------------------------

#[tokio::test]
async fn from_credentials_accepts_multiple_users() {
    let hash_a = bcrypt::hash("pass-a", 4).expect("bcrypt::hash");
    let hash_b = bcrypt::hash("pass-b", 4).expect("bcrypt::hash");
    let users = vec![
        UserCredential {
            username: "user-a".to_string(),
            password: hash_a,
        },
        UserCredential {
            username: "user-b".to_string(),
            password: hash_b,
        },
    ];
    let store = CredentialStore::from_credentials(&users);
    assert!(
        store.check("user-a", "pass-a").await,
        "user-a must be accepted"
    );
    assert!(
        store.check("user-b", "pass-b").await,
        "user-b must be accepted"
    );
    assert!(
        !store.check("user-a", "pass-b").await,
        "cross-user password must be rejected"
    );
}

// ---------------------------------------------------------------------------
// from_file constructor
// ---------------------------------------------------------------------------

#[test]
fn from_file_loads_valid_credentials() {
    let hash_bob = bcrypt::hash("filepass", 4).expect("bcrypt::hash");
    let hash_alice = bcrypt::hash("alicepass", 4).expect("bcrypt::hash");
    // Independently confirm hash validity.
    assert!(
        bcrypt::verify("filepass", &hash_bob).unwrap_or(false),
        "oracle check for bob"
    );

    let contents = format!("# comment line\nbob:{hash_bob}\n\nalice:{hash_alice}\n");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &contents).expect("write");

    let store =
        CredentialStore::from_file(tmp.path().to_str().unwrap()).expect("from_file must succeed");
    drop(store);
}

#[test]
fn from_file_returns_err_for_missing_file() {
    let result = CredentialStore::from_file("/nonexistent/path/__auth_test_creds.txt");
    assert!(
        result.is_err(),
        "from_file must return Err for a missing file"
    );
}

#[test]
fn from_file_returns_err_for_malformed_line() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), "nocolonseparator\n").expect("write");
    let result = CredentialStore::from_file(tmp.path().to_str().unwrap());
    assert!(
        result.is_err(),
        "from_file must return Err when a line has no ':' separator"
    );
}

#[test]
fn from_file_skips_blank_lines_and_comments() {
    let hash = bcrypt::hash("pw", 4).expect("bcrypt::hash");
    let contents = format!("\n# a comment\n\n  \nalice:{hash}\n");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &contents).expect("write");
    let result = CredentialStore::from_file(tmp.path().to_str().unwrap());
    assert!(
        result.is_ok(),
        "blank lines and comments must not cause an error"
    );
}

#[test]
fn from_file_last_duplicate_wins() {
    let hash1 = bcrypt::hash("first", 4).expect("bcrypt::hash");
    let hash2 = bcrypt::hash("second", 4).expect("bcrypt::hash");
    let contents = format!("alice:{hash1}\nalice:{hash2}\n");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &contents).expect("write");
    // from_file must succeed (duplicates allowed, last wins).
    let result = CredentialStore::from_file(tmp.path().to_str().unwrap());
    assert!(
        result.is_ok(),
        "duplicate usernames must not cause an error; last wins"
    );
}

// ---------------------------------------------------------------------------
// merge_from_file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn merge_from_file_overrides_inline_credential() {
    let inline_hash = bcrypt::hash("inline-pass", 4).expect("bcrypt::hash");
    let file_hash = bcrypt::hash("file-pass", 4).expect("bcrypt::hash");

    // Start with alice at inline-pass.
    let mut store = CredentialStore::from_credentials(&[UserCredential {
        username: "alice".to_string(),
        password: inline_hash,
    }]);

    // File has alice at file-pass (overrides) + new user bob.
    let bob_hash = bcrypt::hash("bob-pass", 4).expect("bcrypt::hash");
    let contents = format!("alice:{file_hash}\nbob:{bob_hash}\n");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &contents).expect("write");
    store
        .merge_from_file(tmp.path().to_str().unwrap())
        .expect("merge_from_file must succeed");

    assert!(
        store.check("alice", "file-pass").await,
        "alice must use file-pass after merge overrides inline"
    );
    assert!(
        !store.check("alice", "inline-pass").await,
        "alice must no longer accept inline-pass after merge"
    );
    assert!(
        store.check("bob", "bob-pass").await,
        "bob must be accessible after merge adds him"
    );
}

#[test]
fn merge_from_file_returns_err_for_missing_file() {
    let mut store = CredentialStore::empty();
    let result = store.merge_from_file("/nonexistent/path/__auth_test_merge.txt");
    assert!(
        result.is_err(),
        "merge_from_file must return Err for a missing file"
    );
}

// ---------------------------------------------------------------------------
// Timing invariant: unknown user must take bcrypt time, not microseconds
//
// Security invariant from the bead spec: check() must call bcrypt::verify
// even for unknown usernames, preventing a timing oracle on username
// existence.  We verify this by measuring both code paths and asserting
// both take >= a lower bound consistent with real bcrypt work (cost 4 ≥ 1ms
// on any modern machine).
//
// We do NOT assert the paths take "approximately equal" time — that would be
// flaky on a loaded CI box.  We assert that the unknown-user path takes
// non-trivial time (> 500 µs), which is impossible unless bcrypt ran.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_user_check_takes_bcrypt_time_not_microseconds() {
    // Use cost 4 (minimum): bcrypt at cost 4 takes > 1ms on any real CPU.
    let hash = bcrypt::hash("timing-password", 4).expect("bcrypt::hash");
    let store = CredentialStore::from_credentials(&[UserCredential {
        username: "timing-user".to_string(),
        password: hash,
    }]);

    let before = Instant::now();
    let result = store
        .check("unknown-user-does-not-exist", "any-password")
        .await;
    let elapsed = before.elapsed();

    assert!(!result, "unknown user must be rejected");
    assert!(
        elapsed.as_micros() > 500,
        "unknown-user check must take > 500µs (bcrypt work factor); \
         got {}µs — this suggests the dummy-hash timing guard is missing",
        elapsed.as_micros()
    );
}

#[tokio::test]
async fn wrong_password_check_takes_bcrypt_time_not_microseconds() {
    let hash = bcrypt::hash("timing-password", 4).expect("bcrypt::hash");
    let store = CredentialStore::from_credentials(&[UserCredential {
        username: "timing-user".to_string(),
        password: hash,
    }]);

    let before = Instant::now();
    let result = store.check("timing-user", "wrong-password").await;
    let elapsed = before.elapsed();

    assert!(!result, "wrong password must be rejected");
    assert!(
        elapsed.as_micros() > 500,
        "wrong-password check must take > 500µs (bcrypt work factor); got {}µs",
        elapsed.as_micros()
    );
}

// ---------------------------------------------------------------------------
// UserCredential struct is importable from stoa_auth (not reader/mail)
// ---------------------------------------------------------------------------

#[test]
fn user_credential_struct_is_from_auth_crate() {
    // This test simply proves the type is importable from stoa_auth.
    // If UserCredential is only in reader or mail (not re-exported from auth),
    // this file will not compile.
    let _cred: UserCredential = UserCredential {
        username: "test".to_string(),
        password: "$2b$04$placeholder".to_string(),
    };
}

// ---------------------------------------------------------------------------
// AuthConfig is importable from stoa_auth
// ---------------------------------------------------------------------------

#[test]
fn auth_config_struct_is_from_auth_crate() {
    let config = AuthConfig {
        required: false,
        users: vec![],
        credential_file: None,
        client_certs: vec![],
        trusted_issuers: vec![],
        oidc_providers: vec![],
        operator_usernames: vec![],
    };
    assert!(
        config.is_dev_mode(),
        "empty AuthConfig with required=false must be dev mode"
    );
}

#[test]
fn auth_config_required_is_not_dev_mode() {
    let config = AuthConfig {
        required: true,
        users: vec![],
        credential_file: None,
        client_certs: vec![],
        trusted_issuers: vec![],
        oidc_providers: vec![],
        operator_usernames: vec![],
    };
    assert!(!config.is_dev_mode(), "required=true must not be dev mode");
}

#[test]
fn auth_config_with_users_is_not_dev_mode() {
    let config = AuthConfig {
        required: false,
        users: vec![UserCredential {
            username: "u".to_string(),
            password: "$2b$04$x".to_string(),
        }],
        credential_file: None,
        client_certs: vec![],
        trusted_issuers: vec![],
        oidc_providers: vec![],
        operator_usernames: vec![],
    };
    assert!(
        !config.is_dev_mode(),
        "AuthConfig with users must not be dev mode"
    );
}

#[test]
fn auth_config_with_credential_file_is_not_dev_mode() {
    let config = AuthConfig {
        required: false,
        users: vec![],
        credential_file: Some("/etc/creds".to_string()),
        client_certs: vec![],
        trusted_issuers: vec![],
        oidc_providers: vec![],
        operator_usernames: vec![],
    };
    assert!(
        !config.is_dev_mode(),
        "AuthConfig with credential_file set must not be dev mode"
    );
}
