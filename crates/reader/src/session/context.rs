use std::net::SocketAddr;

use usenet_ipfs_core::article::GroupName;

use crate::session::state::SessionState;

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
    /// Currently selected newsgroup.
    pub current_group: Option<GroupName>,
    /// Article pointer within the current group (1-based, per RFC 3977 §6.1.1).
    pub current_article_number: Option<u64>,
    /// Remote peer address for logging.
    pub peer_addr: SocketAddr,
    /// Whether posting is permitted on this server.
    pub posting_allowed: bool,
}

impl SessionContext {
    /// Create a new session context for an incoming connection.
    ///
    /// `auth_required`: if true, start in Authenticating state.
    pub fn new(peer_addr: SocketAddr, auth_required: bool, posting_allowed: bool) -> Self {
        Self {
            state: if auth_required {
                SessionState::Authenticating
            } else {
                SessionState::Active
            },
            authenticated_user: None,
            tls_active: false,
            current_group: None,
            current_article_number: None,
            peer_addr,
            posting_allowed,
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
        let ctx = SessionContext::new(test_addr(), true, true);
        assert_eq!(ctx.state, SessionState::Authenticating);
    }

    #[test]
    fn test_initial_state_no_auth() {
        let ctx = SessionContext::new(test_addr(), false, true);
        assert_eq!(ctx.state, SessionState::Active);
    }

    #[test]
    fn test_initial_no_group() {
        let ctx = SessionContext::new(test_addr(), false, true);
        assert!(ctx.current_group.is_none());
    }

    #[test]
    fn test_posting_allowed_flag() {
        let ctx_allowed = SessionContext::new(test_addr(), false, true);
        assert!(ctx_allowed.posting_allowed);
        let ctx_denied = SessionContext::new(test_addr(), false, false);
        assert!(!ctx_denied.posting_allowed);
    }
}
