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
    /// Whether the connection has been upgraded to TLS.
    pub tls_active: bool,
    /// Whether STARTTLS is available on this connection.
    ///
    /// True for plain-text connections when TLS is configured. Set to false
    /// once TLS is active (no double-upgrade) or when TLS is not configured.
    pub starttls_available: bool,
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
}

impl SessionContext {
    /// Create a new session context for an incoming connection.
    ///
    /// `auth_required`: if true, start in Authenticating state.
    /// `starttls_available`: true for plain-text connections when TLS is configured.
    pub fn new(
        peer_addr: SocketAddr,
        auth_required: bool,
        posting_allowed: bool,
        starttls_available: bool,
    ) -> Self {
        Self {
            state: if auth_required {
                SessionState::Authenticating
            } else {
                SessionState::Active
            },
            authenticated_user: None,
            tls_active: false,
            starttls_available,
            pending_auth_user: None,
            current_group: None,
            current_article_number: None,
            peer_addr,
            posting_allowed,
            known_groups: vec![],
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
    fn test_starttls_available_flag() {
        let ctx_plain = SessionContext::new(test_addr(), false, true, true);
        assert!(ctx_plain.starttls_available);
        let ctx_tls = SessionContext::new(test_addr(), false, true, false);
        assert!(!ctx_tls.starttls_available);
    }
}
