//! AUTHINFO command handler (RFC 4643).

use crate::session::response::Response;
use stoa_core::audit::{AuditEvent, AuditLogger};

/// Process an AUTHINFO USER/PASS attempt and return the appropriate NNTP response.
///
/// The `success` flag comes from the caller (the dispatcher, which currently
/// accepts all credentials as a stub).  When a real credential-store is wired
/// in, the caller will pass the actual outcome here.
///
/// Logs an `AuthAttempt` event to `audit_logger` if one is provided.
/// `service` identifies the protocol (e.g. `"nntp"`); `auth_method` is the
/// mechanism used (e.g. `"password"`, `"client_cert"`).
pub fn authinfo_response(
    username: &str,
    peer_addr: &str,
    success: bool,
    service: &str,
    auth_method: &str,
    audit_logger: Option<&dyn AuditLogger>,
) -> Response {
    if let Some(logger) = audit_logger {
        logger.log(AuditEvent::AuthAttempt {
            peer_addr: peer_addr.to_string(),
            user: username.to_string(),
            success,
            service: service.to_string(),
            auth_method: auth_method.to_string(),
        });
    }
    if success {
        Response::authentication_accepted()
    } else {
        Response::authentication_failed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_success_returns_281() {
        let resp = authinfo_response(
            "testuser",
            "127.0.0.1:50000",
            true,
            "nntp",
            "password",
            None,
        );
        assert_eq!(resp.code, 281, "success should give 281: {:?}", resp);
    }

    #[test]
    fn auth_failure_returns_481() {
        let resp = authinfo_response("baduser", "1.2.3.4:50001", false, "nntp", "password", None);
        assert_eq!(resp.code, 481, "failure should give 481: {:?}", resp);
    }
}
