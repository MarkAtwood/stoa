use std::net::SocketAddr;

use usenet_ipfs_core::article::GroupName;

use crate::session::{commands::list::GroupInfo, state::SessionState};

/// All per-connection state for one NNTP session.
///
/// Passed by mutable reference to every command handler.
pub struct SessionContext {
    /// Current session state (auth/group transitions).
    pub state: SessionState,
    /// Authenticated username, if auth was performed.
    pub authenticated_user: Option<String>,
    /// Whether the connection is TLS-protected.
    ///
    /// True for NNTPS connections (implicit TLS, port 563). False for plain
    /// connections (port 119). There is no STARTTLS upgrade: connections are
    /// TLS or not from the first byte.
    pub tls_active: bool,
    /// SHA-256 fingerprint of the client's TLS certificate, if one was
    /// presented during the handshake.
    ///
    /// Format: `"sha256:<64-lowercase-hex-chars>"`.  `None` on plain
    /// connections or when the client did not present a certificate.
    /// Used by the AUTHINFO USER handler for password-free cert-based auth.
    pub client_cert_fingerprint: Option<String>,
    /// Raw DER bytes of the client's TLS leaf certificate.
    ///
    /// Stored alongside `client_cert_fingerprint` so that the AUTHINFO USER
    /// handler can pass the cert to `TrustedIssuerStore::verify_and_extract_cn`
    /// after fingerprint-based auth has been attempted.  `None` on plain
    /// connections or when the client did not present a certificate.
    pub client_cert_der: Option<Vec<u8>>,
    /// Username received from AUTHINFO USER, waiting for AUTHINFO PASS.
    pub pending_auth_user: Option<String>,
    /// Currently selected newsgroup.
    pub current_group: Option<GroupName>,
    /// Article pointer within the current group (1-based, per RFC 3977 §6.1.1).
    pub current_article_number: Option<u64>,
    /// Remote peer address for logging.
    pub peer_addr: SocketAddr,
    /// Whether posting is permitted on this server.
    pub posting_allowed: bool,
    /// Known newsgroups served by this instance.
    ///
    /// Populated at server startup from configuration. Empty until storage
    /// integration is wired in by a later epic.
    pub known_groups: Vec<GroupInfo>,
    /// Count of consecutive AUTHINFO PASS failures this session.
    ///
    /// Incremented on each 481 response. Reset to 0 on a successful 281.
    /// When it reaches `MAX_AUTH_FAILURES` the session is closed with 400
    /// before any further response is sent.
    pub auth_failure_count: u32,
}

/// Maximum consecutive AUTHINFO PASS failures before the connection is dropped.
pub const MAX_AUTH_FAILURES: u32 = 5;

impl SessionContext {
    /// Create a new session context for an incoming connection.
    ///
    /// `auth_required`: if true, start in Authenticating state.
    /// `tls_active`: true for NNTPS (implicit TLS) connections.
    pub fn new(
        peer_addr: SocketAddr,
        auth_required: bool,
        posting_allowed: bool,
        tls_active: bool,
    ) -> Self {
        Self {
            state: if auth_required {
                SessionState::Authenticating
            } else {
                SessionState::Active
            },
            authenticated_user: None,
            tls_active,
            client_cert_fingerprint: None,
            client_cert_der: None,
            pending_auth_user: None,
            current_group: None,
            current_article_number: None,
            peer_addr,
            posting_allowed,
            known_groups: vec![],
            auth_failure_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
    }

    #[test]
    fn test_initial_state_auth_required() {
        let ctx = SessionContext::new(test_addr(), true, true, false);
        assert_eq!(ctx.state, SessionState::Authenticating);
    }

    #[test]
    fn test_initial_state_no_auth() {
        let ctx = SessionContext::new(test_addr(), false, true, false);
        assert_eq!(ctx.state, SessionState::Active);
    }

    #[test]
    fn test_initial_no_group() {
        let ctx = SessionContext::new(test_addr(), false, true, false);
        assert!(ctx.current_group.is_none());
    }

    #[test]
    fn test_posting_allowed_flag() {
        let ctx_allowed = SessionContext::new(test_addr(), false, true, false);
        assert!(ctx_allowed.posting_allowed);
        let ctx_denied = SessionContext::new(test_addr(), false, false, false);
        assert!(!ctx_denied.posting_allowed);
    }

    #[test]
    fn test_tls_active_flag() {
        let ctx_plain = SessionContext::new(test_addr(), false, true, false);
        assert!(!ctx_plain.tls_active);
        let ctx_tls = SessionContext::new(test_addr(), false, true, true);
        assert!(ctx_tls.tls_active);
    }
}
