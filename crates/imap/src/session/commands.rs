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
/// Before TLS: plain LOGIN is permitted (developer/loopback use-case for v1).
/// After TLS: advertise `AUTH=PLAIN`, `AUTH=LOGIN`, `IDLE`, `UIDPLUS`, `MOVE`.
///
/// `IMAP4rev1` is always first per RFC 3501 §7.2.1.
///
/// Note: LOGINDISABLED is intentionally absent on the plain port because STARTTLS
/// is not yet implemented. RFC 3501 §6.2.1 requires STARTTLS to be offered when
/// LOGINDISABLED is advertised; advertising LOGINDISABLED without STARTTLS leaves
/// plain-port clients unable to authenticate.
/// TODO: re-add LOGINDISABLED and implement STARTTLS (stoa-19f17fab)
pub fn capability_list(tls: bool) -> Vec1<Capability<'static>> {
    let mut caps: Vec<Capability<'static>> = vec![Capability::Imap4Rev1];
    if tls {
        caps.push(Capability::Auth(AuthMechanism::Plain));
        caps.push(Capability::Auth(AuthMechanism::Login));
        caps.push(Capability::Idle);
        caps.push(Capability::UidPlus);
        caps.push(Capability::Move);
        // SASL-IR (RFC 4959): client may include initial response in AUTHENTICATE;
        // we already handle CommandAuthenticateReceived.initial_response.
        caps.push(Capability::SaslIr);
    }
    // These extensions are not TLS-dependent.
    caps.push(Capability::Enable);
    caps.push(Capability::Unselect);
    // WORKAROUND: imap-types 2.0.0-alpha.6 has no Capability::Imap4Rev2 variant.
    // try_from routes this to Capability::Other(CapabilityOther). Replace with
    // Capability::Imap4Rev2 when duesee/imap-codec#702 ships a typed variant.
    caps.push(
        Capability::try_from("IMAP4rev2").expect("IMAP4rev2 is a valid IMAP atom and cannot fail"),
    );
    caps.push(Capability::Namespace);
    Vec1::try_from(caps).expect("capability list always has at least one element")
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
    fn capability_list_plain_omits_logindisabled() {
        // LOGINDISABLED must NOT appear on the plain port while STARTTLS is absent.
        // RFC 3501 §6.2.1: LOGINDISABLED requires STARTTLS to be offered; without
        // it clients can never authenticate. See stoa-19f17fab for the STARTTLS epic.
        let caps = capability_list(false);
        assert!(
            caps.as_ref().contains(&Capability::Imap4Rev1),
            "IMAP4rev1 must always be present"
        );
        assert!(
            !caps.as_ref().contains(&Capability::LoginDisabled),
            "LOGINDISABLED must not be present on plain port until STARTTLS is implemented"
        );
        assert!(
            !caps
                .as_ref()
                .contains(&Capability::Auth(AuthMechanism::Plain)),
            "AUTH=PLAIN must not be advertised without TLS"
        );
        assert!(
            caps.as_ref().contains(&Capability::Enable),
            "ENABLE must always be present"
        );
        assert!(
            caps.as_ref().contains(&Capability::Unselect),
            "UNSELECT must always be present"
        );
        assert!(
            caps.as_ref().contains(
                &Capability::try_from("IMAP4rev2")
                    .expect("IMAP4rev2 is a valid IMAP atom and cannot fail")
            ),
            "IMAP4rev2 must always be present"
        );
        assert!(
            caps.as_ref().contains(&Capability::Namespace),
            "NAMESPACE must always be present"
        );
    }

    #[test]
    fn capability_list_tls_includes_auth_mechanisms() {
        let caps = capability_list(true);
        assert!(
            caps.as_ref().contains(&Capability::Imap4Rev1),
            "IMAP4rev1 must always be present"
        );
        assert!(
            caps.as_ref()
                .contains(&Capability::Auth(AuthMechanism::Plain)),
            "AUTH=PLAIN must be present with TLS"
        );
        assert!(
            caps.as_ref()
                .contains(&Capability::Auth(AuthMechanism::Login)),
            "AUTH=LOGIN must be present with TLS"
        );
        assert!(
            !caps.as_ref().contains(&Capability::LoginDisabled),
            "LOGINDISABLED must not be present with TLS"
        );
        assert!(
            caps.as_ref().contains(&Capability::Idle),
            "IDLE must be advertised with TLS"
        );
        assert!(
            caps.as_ref().contains(&Capability::Enable),
            "ENABLE must always be present"
        );
        assert!(
            caps.as_ref().contains(&Capability::Unselect),
            "UNSELECT must always be present"
        );
        assert!(
            caps.as_ref().contains(&Capability::UidPlus),
            "UIDPLUS must be present with TLS"
        );
        assert!(
            caps.as_ref().contains(&Capability::Move),
            "MOVE must be present with TLS"
        );
        assert!(
            caps.as_ref().contains(
                &Capability::try_from("IMAP4rev2")
                    .expect("IMAP4rev2 is a valid IMAP atom and cannot fail")
            ),
            "IMAP4rev2 must always be present"
        );
        assert!(
            caps.as_ref().contains(&Capability::Namespace),
            "NAMESPACE must always be present"
        );
    }

    #[test]
    fn capability_list_is_non_empty() {
        // Vec1 invariant: at minimum IMAP4rev1 is present.
        assert!(!capability_list(false).as_ref().is_empty());
        assert!(!capability_list(true).as_ref().is_empty());
    }

    // RFC 9051 §6.1.1: capability string for IMAP4rev2 is "IMAP4rev2" (exact case).
    #[test]
    fn capability_list_includes_imap4rev2_no_tls() {
        let caps = capability_list(false);
        assert!(
            caps.as_ref()
                .iter()
                .any(|cap| format!("{}", cap) == "IMAP4rev2"),
            "IMAP4rev2 must be present in capability list (no TLS)"
        );
    }

    #[test]
    fn capability_list_includes_imap4rev2_tls() {
        let caps = capability_list(true);
        assert!(
            caps.as_ref()
                .iter()
                .any(|cap| format!("{}", cap) == "IMAP4rev2"),
            "IMAP4rev2 must be present in capability list (TLS)"
        );
    }

    // RFC 2342 §5: capability string for NAMESPACE is "NAMESPACE".
    #[test]
    fn capability_list_includes_namespace_no_tls() {
        let caps = capability_list(false);
        assert!(
            caps.as_ref().contains(&Capability::Namespace),
            "NAMESPACE must be present in capability list (no TLS)"
        );
    }

    #[test]
    fn capability_list_does_not_include_status_size() {
        for tls in [false, true] {
            let caps = capability_list(tls);
            assert!(
                !caps
                    .as_ref()
                    .iter()
                    .any(|cap| format!("{}", cap) == "STATUS=SIZE"),
                "STATUS=SIZE must not appear in capability list (tls={tls})"
            );
        }
    }

    // RFC 9051 §6.1.1: "IMAP4rev2" must appear as a space-separated atom in the
    // "* CAPABILITY ..." wire response.
    #[test]
    fn capability_data_wire_contains_imap4rev2() {
        use imap_codec::{encode::Encoder, ResponseCodec};
        use imap_next::imap_types::response::Response;

        let data = capability_data(true);
        let response = Response::Data(data);
        let wire = ResponseCodec::default().encode(&response).dump();
        assert!(
            wire.windows(b"IMAP4rev2".len()).any(|w| w == b"IMAP4rev2"),
            "wire encoding of CAPABILITY response must contain b\"IMAP4rev2\"; got: {:?}",
            String::from_utf8_lossy(&wire)
        );
    }
}
