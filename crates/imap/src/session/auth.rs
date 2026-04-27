//! IMAP SASL authentication: AUTH=PLAIN and AUTH=LOGIN.
//!
//! Both mechanisms are only advertised and accepted after TLS is established
//! (enforced by the caller — `LOGINDISABLED` is advertised when TLS is absent).
//!
//! # Password storage
//!
//! Passwords in `[auth.users]` must be bcrypt hashes (not plaintext).
//! Use `htpasswd -B -n username` or `python3 -c "import bcrypt; print(bcrypt.hashpw(b'pass', bcrypt.gensalt()).decode())"`.
//!
//! Credential verification is delegated to `stoa_auth::CredentialStore` which
//! handles bcrypt verification, case-insensitive username matching, and
//! timing equalization (via a pre-computed dummy hash) so unknown usernames
//! take the same time as known ones.

use std::borrow::Cow;

use imap_next::{
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        core::Tag,
        response::{CommandContinuationRequest, Status},
        secret::Secret,
    },
    server::Server,
};
use tracing::warn;

/// In-progress multi-step authentication state.
///
/// `CommandAuthenticateReceived` starts a new auth flow.  Subsequent
/// `AuthenticateDataReceived` events advance the flow until it completes or
/// is aborted.
#[derive(Debug, Default)]
pub enum AuthProgress {
    /// No authentication in progress.
    #[default]
    None,
    /// AUTH=PLAIN continuation: waiting for `\0user\0password` payload.
    PlainExpectingPayload { tag: Tag<'static> },
    /// AUTH=LOGIN step 1: username challenge sent; awaiting username response.
    LoginExpectingUsername { tag: Tag<'static> },
    /// AUTH=LOGIN step 2: password challenge sent; awaiting password response.
    LoginExpectingPassword { tag: Tag<'static>, username: String },
}

/// Verify username/password against the credential store.
///
/// Delegates to `stoa_auth::CredentialStore::check` which handles bcrypt
/// verification on a blocking thread, case-insensitive username matching,
/// and timing equalization so unknown usernames take the same time as known
/// ones (dummy hash at the configured cost factor).
pub async fn verify_credentials(
    credential_store: &stoa_auth::CredentialStore,
    username: &str,
    password: &str,
) -> bool {
    credential_store.check(username, password).await
}

/// Handle the initial `CommandAuthenticateReceived` event.
///
/// Returns `Some(username)` if auth succeeds immediately (PLAIN with initial
/// response), `None` if a multi-step flow was started or auth failed.
pub async fn handle_authenticate_start(
    server: &mut Server,
    credential_store: &stoa_auth::CredentialStore,
    auth_progress: &mut AuthProgress,
    tag: Tag<'static>,
    mechanism: AuthMechanism<'static>,
    initial_response: Option<Secret<Cow<'static, [u8]>>>,
) -> Option<String> {
    match mechanism {
        AuthMechanism::Plain => {
            handle_plain_start(server, credential_store, auth_progress, tag, initial_response).await
        }
        AuthMechanism::Login => {
            handle_login_start(server, auth_progress, tag);
            None
        }
        other => {
            warn!("client requested unsupported SASL mechanism: {other}");
            let no = Status::no(Some(tag), None, "Unsupported authentication mechanism")
                .expect("static no is valid");
            server.authenticate_finish(no).ok();
            None
        }
    }
}

/// Handle `AuthenticateDataReceived` events during a multi-step auth flow.
///
/// Returns `Some(username)` when auth succeeds, `None` if the flow continues
/// or failed.
pub async fn handle_authenticate_data(
    server: &mut Server,
    credential_store: &stoa_auth::CredentialStore,
    auth_progress: &mut AuthProgress,
    data: AuthenticateData<'static>,
) -> Option<String> {
    let progress = std::mem::replace(auth_progress, AuthProgress::None);

    match (progress, data) {
        // Client cancelled the auth exchange.
        (_, AuthenticateData::Cancel) => {
            warn!("client cancelled authentication");
            let no =
                Status::no(None, None, "Authentication cancelled").expect("static no is valid");
            server.authenticate_finish(no).ok();
            None
        }

        // AUTH=PLAIN step 2: continuation payload arrives.
        (AuthProgress::PlainExpectingPayload { tag }, AuthenticateData::Continue(payload)) => {
            let bytes = payload.declassify();
            plain_finish(server, credential_store, Some(tag), bytes.as_ref()).await
        }

        // AUTH=LOGIN step 1: username received.
        (AuthProgress::LoginExpectingUsername { tag }, AuthenticateData::Continue(payload)) => {
            let username = match std::str::from_utf8(payload.declassify().as_ref()) {
                Ok(u) => u.to_owned(),
                Err(_) => {
                    let no = Status::no(Some(tag), None, "Invalid UTF-8 in username")
                        .expect("static no is valid");
                    server.authenticate_finish(no).ok();
                    return None;
                }
            };

            // Send password challenge: raw bytes b"Password:" (imap-codec base64-encodes them).
            let ccr = CommandContinuationRequest::base64(b"Password:" as &[u8]);
            match server.authenticate_continue(ccr) {
                Ok(_) => {
                    *auth_progress = AuthProgress::LoginExpectingPassword { tag, username };
                    None
                }
                Err(_) => None,
            }
        }

        // AUTH=LOGIN step 2: password received.
        (
            AuthProgress::LoginExpectingPassword { tag, username },
            AuthenticateData::Continue(payload),
        ) => {
            let password = match std::str::from_utf8(payload.declassify().as_ref()) {
                Ok(p) => p.to_owned(),
                Err(_) => {
                    let no = Status::no(Some(tag), None, "Invalid UTF-8 in password")
                        .expect("static no is valid");
                    server.authenticate_finish(no).ok();
                    return None;
                }
            };

            if verify_credentials(credential_store, &username, &password).await {
                let ok =
                    Status::ok(Some(tag), None, "Authentication successful").expect("static ok");
                server.authenticate_finish(ok).ok();
                Some(username)
            } else {
                let no = Status::no(Some(tag), None, "Invalid credentials").expect("static no");
                server.authenticate_finish(no).ok();
                None
            }
        }

        // Unexpected state.
        (state, _) => {
            warn!("unexpected AuthenticateDataReceived in state {state:?}");
            None
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Start AUTH=PLAIN.  If an initial response is present, verifies immediately.
/// Otherwise sends a continuation request and tracks state.
async fn handle_plain_start(
    server: &mut Server,
    credential_store: &stoa_auth::CredentialStore,
    auth_progress: &mut AuthProgress,
    tag: Tag<'static>,
    initial_response: Option<Secret<Cow<'static, [u8]>>>,
) -> Option<String> {
    match initial_response {
        Some(payload) => {
            let bytes = payload.declassify();
            plain_finish(server, credential_store, Some(tag), bytes.as_ref()).await
        }
        None => {
            // Empty continuation request asks client to send the PLAIN payload.
            let ccr = CommandContinuationRequest::basic(None, "").expect("empty CCR is valid");
            match server.authenticate_continue(ccr) {
                Ok(_) => {
                    *auth_progress = AuthProgress::PlainExpectingPayload { tag };
                    None
                }
                Err(_) => None,
            }
        }
    }
}

/// Parse the PLAIN payload and verify credentials.
///
/// PLAIN format (RFC 4616): `[authzid] NUL authcid NUL passwd`
///
/// `authzid` (authorization identity) must be either empty or equal to
/// `authcid` (authentication identity).  A non-empty `authzid` that differs
/// from `authcid` is an impersonation request that this server does not
/// support; it is rejected with NO to prevent silent privilege escalation.
async fn plain_finish(
    server: &mut Server,
    credential_store: &stoa_auth::CredentialStore,
    tag: Option<Tag<'static>>,
    payload: &[u8],
) -> Option<String> {
    let parts: Vec<&[u8]> = payload.splitn(3, |&b| b == 0).collect();
    if parts.len() != 3 {
        let no = Status::no(tag, None, "Invalid PLAIN payload format").expect("static no is valid");
        server.authenticate_finish(no).ok();
        return None;
    }

    let username = match std::str::from_utf8(parts[1]) {
        Ok(u) => u.to_owned(),
        Err(_) => {
            let no = Status::no(tag, None, "Invalid UTF-8 in PLAIN username")
                .expect("static no is valid");
            server.authenticate_finish(no).ok();
            return None;
        }
    };
    let password = match std::str::from_utf8(parts[2]) {
        Ok(p) => p.to_owned(),
        Err(_) => {
            let no = Status::no(tag, None, "Invalid UTF-8 in PLAIN password")
                .expect("static no is valid");
            server.authenticate_finish(no).ok();
            return None;
        }
    };

    // RFC 4616 §2: if authzid is non-empty it must equal authcid.
    // We do not support proxy/impersonation; reject mismatched authzid.
    let authzid = parts[0];
    if !authzid.is_empty() {
        let authzid_str = match std::str::from_utf8(authzid) {
            Ok(s) => s,
            Err(_) => {
                let no = Status::no(tag, None, "Invalid UTF-8 in PLAIN authzid")
                    .expect("static no is valid");
                server.authenticate_finish(no).ok();
                return None;
            }
        };
        if authzid_str != username {
            let no = Status::no(tag, None, "Authorization identity not supported")
                .expect("static no is valid");
            server.authenticate_finish(no).ok();
            return None;
        }
    }

    if verify_credentials(credential_store, &username, &password).await {
        let ok = Status::ok(tag, None, "Authentication successful").expect("static ok");
        server.authenticate_finish(ok).ok();
        Some(username)
    } else {
        let no = Status::no(tag, None, "Invalid credentials").expect("static no");
        server.authenticate_finish(no).ok();
        None
    }
}

/// Start AUTH=LOGIN: send the username challenge.
fn handle_login_start(server: &mut Server, auth_progress: &mut AuthProgress, tag: Tag<'static>) {
    // Raw bytes b"Username:" — imap-codec encodes them to base64 on the wire.
    let ccr = CommandContinuationRequest::base64(b"Username:" as &[u8]);
    if server.authenticate_continue(ccr).is_ok() {
        *auth_progress = AuthProgress::LoginExpectingUsername { tag };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Passwords in auth config must be bcrypt hashes.  Cost 4 is the minimum
    // valid value and makes tests fast without sacrificing correctness.
    fn hash(pw: &str) -> String {
        bcrypt::hash(pw, 4).expect("bcrypt::hash must not fail")
    }

    fn make_store(users: &[(&str, &str)]) -> stoa_auth::CredentialStore {
        let creds: Vec<stoa_auth::config::UserCredential> = users
            .iter()
            .map(|(u, p)| stoa_auth::config::UserCredential {
                username: u.to_string(),
                password: p.to_string(),
            })
            .collect();
        stoa_auth::CredentialStore::from_credentials(&creds)
    }

    #[tokio::test]
    async fn verify_correct_credentials() {
        let store = make_store(&[("alice", &hash("hunter2"))]);
        assert!(verify_credentials(&store, "alice", "hunter2").await);
    }

    #[tokio::test]
    async fn verify_wrong_password_fails() {
        let store = make_store(&[("alice", &hash("hunter2"))]);
        assert!(!verify_credentials(&store, "alice", "wrongpass").await);
    }

    #[tokio::test]
    async fn verify_unknown_user_fails() {
        let store = make_store(&[("alice", &hash("hunter2"))]);
        assert!(!verify_credentials(&store, "bob", "hunter2").await);
    }

    #[tokio::test]
    async fn verify_empty_user_list_fails() {
        let store = make_store(&[]);
        assert!(!verify_credentials(&store, "alice", "hunter2").await);
    }

    #[tokio::test]
    async fn verify_multiple_users() {
        let store = make_store(&[("alice", &hash("pw1")), ("bob", &hash("pw2"))]);
        assert!(verify_credentials(&store, "alice", "pw1").await);
        assert!(verify_credentials(&store, "bob", "pw2").await);
        assert!(!verify_credentials(&store, "alice", "pw2").await);
    }

    #[test]
    fn plain_payload_parse_three_parts() {
        // Standard PLAIN payload: authzid=empty, authcid=alice, passwd=pw
        let payload = b"\x00alice\x00pw";
        let parts: Vec<&[u8]> = payload.splitn(3, |&b| b == 0).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], b""); // empty authzid
        assert_eq!(parts[1], b"alice");
        assert_eq!(parts[2], b"pw");
    }

    #[test]
    fn plain_payload_authzid_equals_authcid_parses() {
        // authzid == authcid is valid (client naming itself explicitly).
        let payload = b"alice\x00alice\x00hunter2";
        let parts: Vec<&[u8]> = payload.splitn(3, |&b| b == 0).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], b"alice"); // authzid matches authcid — permitted
        assert_eq!(parts[1], b"alice"); // authcid
        assert_eq!(parts[2], b"hunter2");
    }

    #[test]
    fn plain_payload_authzid_differs_from_authcid_parses() {
        // Verifies parsing only; plain_finish rejects this at the logic level.
        let payload = b"bob\x00alice\x00hunter2";
        let parts: Vec<&[u8]> = payload.splitn(3, |&b| b == 0).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], b"bob"); // authzid differs from authcid
        assert_eq!(parts[1], b"alice"); // authcid
        assert_eq!(parts[2], b"hunter2");
    }

    #[test]
    fn plain_payload_malformed_rejected() {
        // Missing second NUL separator
        let payload = b"\x00alice";
        let parts: Vec<&[u8]> = payload.splitn(3, |&b| b == 0).collect();
        assert_ne!(parts.len(), 3, "two-part payload must be rejected");
    }
}
