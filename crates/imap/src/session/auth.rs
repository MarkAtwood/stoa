//! IMAP SASL authentication: AUTH=PLAIN and AUTH=LOGIN.
//!
//! Both mechanisms are only advertised and accepted after TLS is established
//! (enforced by the caller — `LOGINDISABLED` is advertised when TLS is absent).

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
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::config::Config;

/// In-progress multi-step authentication state.
///
/// `CommandAuthenticateReceived` starts a new auth flow.  Subsequent
/// `AuthenticateDataReceived` events advance the flow until it completes or
/// is aborted.
#[derive(Debug)]
pub enum AuthProgress {
    /// No authentication in progress.
    None,
    /// AUTH=PLAIN continuation: waiting for `\0user\0password` payload.
    PlainExpectingPayload { tag: Tag<'static> },
    /// AUTH=LOGIN step 1: username challenge sent; awaiting username response.
    LoginExpectingUsername { tag: Tag<'static> },
    /// AUTH=LOGIN step 2: password challenge sent; awaiting password response.
    LoginExpectingPassword { tag: Tag<'static>, username: String },
}

impl Default for AuthProgress {
    fn default() -> Self {
        Self::None
    }
}

/// Verify username/password against the configured user list.
///
/// Password comparison is constant-time (via `subtle`).
pub fn verify_credentials(config: &Config, username: &str, password: &str) -> bool {
    config.auth.users.iter().any(|cred| {
        cred.username == username
            && bool::from(cred.password.as_bytes().ct_eq(password.as_bytes()))
    })
}

/// Handle the initial `CommandAuthenticateReceived` event.
///
/// Returns `Some(username)` if auth succeeds immediately (PLAIN with initial
/// response), `None` if a multi-step flow was started or auth failed.
pub fn handle_authenticate_start(
    server: &mut Server,
    config: &Config,
    auth_progress: &mut AuthProgress,
    tag: Tag<'static>,
    mechanism: AuthMechanism<'static>,
    initial_response: Option<Secret<Cow<'static, [u8]>>>,
) -> Option<String> {
    match mechanism {
        AuthMechanism::Plain => {
            handle_plain_start(server, config, auth_progress, tag, initial_response)
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
pub fn handle_authenticate_data(
    server: &mut Server,
    config: &Config,
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
            plain_finish(server, config, Some(tag), payload.declassify().as_ref())
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
        (AuthProgress::LoginExpectingPassword { tag, username }, AuthenticateData::Continue(payload)) => {
            let password = match std::str::from_utf8(payload.declassify().as_ref()) {
                Ok(p) => p,
                Err(_) => {
                    let no = Status::no(Some(tag), None, "Invalid UTF-8 in password")
                        .expect("static no is valid");
                    server.authenticate_finish(no).ok();
                    return None;
                }
            };

            if verify_credentials(config, &username, password) {
                let ok = Status::ok(Some(tag), None, "Authentication successful")
                    .expect("static ok");
                server.authenticate_finish(ok).ok();
                Some(username)
            } else {
                let no =
                    Status::no(Some(tag), None, "Invalid credentials").expect("static no");
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
fn handle_plain_start(
    server: &mut Server,
    config: &Config,
    auth_progress: &mut AuthProgress,
    tag: Tag<'static>,
    initial_response: Option<Secret<Cow<'static, [u8]>>>,
) -> Option<String> {
    match initial_response {
        Some(payload) => plain_finish(server, config, Some(tag), payload.declassify().as_ref()),
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
/// We use `authcid` as the username and ignore `authzid`.
fn plain_finish(
    server: &mut Server,
    config: &Config,
    tag: Option<Tag<'static>>,
    payload: &[u8],
) -> Option<String> {
    let parts: Vec<&[u8]> = payload.splitn(3, |&b| b == 0).collect();
    if parts.len() != 3 {
        let no =
            Status::no(tag, None, "Invalid PLAIN payload format").expect("static no is valid");
        server.authenticate_finish(no).ok();
        return None;
    }

    let username = match std::str::from_utf8(parts[1]) {
        Ok(u) => u,
        Err(_) => {
            let no = Status::no(tag, None, "Invalid UTF-8 in PLAIN username")
                .expect("static no is valid");
            server.authenticate_finish(no).ok();
            return None;
        }
    };
    let password = match std::str::from_utf8(parts[2]) {
        Ok(p) => p,
        Err(_) => {
            let no = Status::no(tag, None, "Invalid UTF-8 in PLAIN password")
                .expect("static no is valid");
            server.authenticate_finish(no).ok();
            return None;
        }
    };

    if verify_credentials(config, username, password) {
        let ok = Status::ok(tag, None, "Authentication successful").expect("static ok");
        server.authenticate_finish(ok).ok();
        Some(username.to_owned())
    } else {
        let no = Status::no(tag, None, "Invalid credentials").expect("static no");
        server.authenticate_finish(no).ok();
        None
    }
}

/// Start AUTH=LOGIN: send the username challenge.
fn handle_login_start(
    server: &mut Server,
    auth_progress: &mut AuthProgress,
    tag: Tag<'static>,
) {
    // Raw bytes b"Username:" — imap-codec encodes them to base64 on the wire.
    let ccr = CommandContinuationRequest::base64(b"Username:" as &[u8]);
    match server.authenticate_continue(ccr) {
        Ok(_) => {
            *auth_progress = AuthProgress::LoginExpectingUsername { tag };
        }
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(users: &[(&str, &str)]) -> Config {
        use crate::config::*;
        Config {
            listen: ListenConfig { addr: "127.0.0.1:143".into(), tls_addr: None },
            database: DatabaseConfig { path: "/tmp/test.db".into() },
            limits: LimitsConfig::default(),
            auth: AuthConfig {
                mechanisms: vec!["PLAIN".into(), "LOGIN".into()],
                users: users
                    .iter()
                    .map(|(u, p)| UserCredential {
                        username: u.to_string(),
                        password: p.to_string(),
                    })
                    .collect(),
            },
            tls: TlsConfig { cert_path: None, key_path: None },
            admin: AdminConfig::default(),
            log: LogConfig::default(),
        }
    }

    #[test]
    fn verify_correct_credentials() {
        let cfg = make_config(&[("alice", "hunter2")]);
        assert!(verify_credentials(&cfg, "alice", "hunter2"));
    }

    #[test]
    fn verify_wrong_password_fails() {
        let cfg = make_config(&[("alice", "hunter2")]);
        assert!(!verify_credentials(&cfg, "alice", "wrongpass"));
    }

    #[test]
    fn verify_unknown_user_fails() {
        let cfg = make_config(&[("alice", "hunter2")]);
        assert!(!verify_credentials(&cfg, "bob", "hunter2"));
    }

    #[test]
    fn verify_empty_user_list_fails() {
        let cfg = make_config(&[]);
        assert!(!verify_credentials(&cfg, "alice", "hunter2"));
    }

    #[test]
    fn verify_multiple_users() {
        let cfg = make_config(&[("alice", "pw1"), ("bob", "pw2")]);
        assert!(verify_credentials(&cfg, "alice", "pw1"));
        assert!(verify_credentials(&cfg, "bob", "pw2"));
        assert!(!verify_credentials(&cfg, "alice", "pw2"));
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
    fn plain_payload_with_authzid() {
        let payload = b"alice\x00alice\x00hunter2";
        let parts: Vec<&[u8]> = payload.splitn(3, |&b| b == 0).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], b"alice"); // authzid (ignored)
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
