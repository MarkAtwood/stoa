//! AUTHINFO command handler (RFC 4643).

use usenet_ipfs_core::audit::{AuditEvent, AuditLoggerHandle};

/// Process an AUTHINFO USER/PASS attempt and return the appropriate NNTP response.
///
/// The `success` flag comes from the caller (the dispatcher, which currently
/// accepts all credentials as a stub).  When a real credential-store is wired
/// in, the caller will pass the actual outcome here.
///
/// Logs an `AuthAttempt` event to `audit_logger` if one is provided.
pub fn authinfo_response(
    username: &str,
    peer_addr: &str,
    success: bool,
    audit_logger: Option<&AuditLoggerHandle>,
) -> &'static str {
    if let Some(logger) = audit_logger {
        logger.log(AuditEvent::AuthAttempt {
            peer_addr: peer_addr.to_string(),
            user: username.to_string(),
            success,
        });
    }
    if success {
        "281 Authentication accepted\r\n"
    } else {
        "482 Authentication rejected\r\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_success_returns_281() {
        let resp = authinfo_response("testuser", "127.0.0.1:50000", true, None);
        assert!(resp.starts_with("281"), "success should give 281: {resp}");
    }

    #[test]
    fn auth_failure_returns_482() {
        let resp = authinfo_response("baduser", "1.2.3.4:50001", false, None);
        assert!(resp.starts_with("482"), "failure should give 482: {resp}");
    }
}
