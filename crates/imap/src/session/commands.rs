//! Handlers for basic IMAP commands: CAPABILITY, NOOP.
//!
//! LOGOUT is handled in `mod.rs` because it needs to break the session loop.

use imap_next::imap_types::{
    auth::AuthMechanism,
    core::{Tag, Vec1},
    response::{Capability, Data},
};

/// Build the server capability list.
///
/// Before TLS: advertise `LOGINDISABLED` (no plaintext auth on insecure channel).
/// After TLS: advertise `AUTH=PLAIN`, `AUTH=LOGIN`, `IDLE`.
///
/// `IMAP4rev1` is always first per RFC 3501 §7.2.1.
pub fn capability_list(tls: bool) -> Vec1<Capability<'static>> {
    let mut caps: Vec<Capability<'static>> = vec![Capability::Imap4Rev1];
    if tls {
        caps.push(Capability::Auth(AuthMechanism::Plain));
        caps.push(Capability::Auth(AuthMechanism::Login));
        caps.push(Capability::Idle);
    } else {
        caps.push(Capability::LoginDisabled);
    }
    // Safety: always at least one element (Imap4Rev1).
    Vec1::unvalidated(caps)
}

/// Build the untagged `* CAPABILITY ...` response data item.
pub fn capability_data(tls: bool) -> Data<'static> {
    Data::capability(capability_list(tls)).expect("capability list is always non-empty")
}

/// Build the tagged `OK` response for CAPABILITY.
pub fn noop_ok(tag: Tag<'static>) -> imap_next::imap_types::response::Status<'static> {
    imap_next::imap_types::response::Status::ok(Some(tag), None, "NOOP completed")
        .expect("static ok is valid")
}

/// Build the tagged `OK` response for the CAPABILITY command.
pub fn capability_ok(tag: Tag<'static>) -> imap_next::imap_types::response::Status<'static> {
    imap_next::imap_types::response::Status::ok(Some(tag), None, "CAPABILITY complete")
        .expect("static ok is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_list_plain_includes_logindisabled() {
        let caps = capability_list(false);
        let has_imap4 = caps.as_ref().contains(&Capability::Imap4Rev1);
        let has_logindisabled = caps.as_ref().contains(&Capability::LoginDisabled);
        let has_auth_plain = caps.as_ref().contains(&Capability::Auth(AuthMechanism::Plain));
        assert!(has_imap4, "IMAP4rev1 must always be present");
        assert!(has_logindisabled, "LOGINDISABLED must be present without TLS");
        assert!(!has_auth_plain, "AUTH=PLAIN must not be advertised without TLS");
    }

    #[test]
    fn capability_list_tls_includes_auth_mechanisms() {
        let caps = capability_list(true);
        let has_imap4 = caps.as_ref().contains(&Capability::Imap4Rev1);
        let has_plain = caps.as_ref().contains(&Capability::Auth(AuthMechanism::Plain));
        let has_login = caps.as_ref().contains(&Capability::Auth(AuthMechanism::Login));
        let has_logindisabled = caps.as_ref().contains(&Capability::LoginDisabled);
        let has_idle = caps.as_ref().contains(&Capability::Idle);
        assert!(has_imap4, "IMAP4rev1 must always be present");
        assert!(has_plain, "AUTH=PLAIN must be present with TLS");
        assert!(has_login, "AUTH=LOGIN must be present with TLS");
        assert!(!has_logindisabled, "LOGINDISABLED must not be present with TLS");
        assert!(has_idle, "IDLE must be advertised with TLS");
    }

    #[test]
    fn capability_list_is_non_empty() {
        // Vec1 invariant: at minimum IMAP4rev1 is present.
        assert!(!capability_list(false).as_ref().is_empty());
        assert!(!capability_list(true).as_ref().is_empty());
    }
}
