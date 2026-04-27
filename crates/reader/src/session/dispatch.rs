use stoa_auth::TrustedIssuerStore;

use crate::{
    config::AuthConfig,
    session::{
        command::{ArticleRef, Command, ListSubcommand, OverArg},
        commands::list::{list_active, list_newsgroups, list_overview_fmt, newgroups, newnews},
        context::SessionContext,
        response::Response,
        state::SessionState,
    },
    store::client_cert_store::ClientCertStore,
};

/// Dispatch a parsed command, enforcing state machine preconditions.
///
/// Returns a `Response` to send to the client. Updates `ctx` for state-
/// changing commands (GROUP, AUTHINFO, STARTTLS, QUIT).
///
/// `cert_store`: the client certificate fingerprint store.  When an
/// `AUTHINFO USER` command is received over a TLS connection and the session's
/// `client_cert_fingerprint` matches an entry in this store, the session is
/// authenticated immediately (281) without requiring `AUTHINFO PASS`.
///
/// `trusted_issuer_store`: consulted after fingerprint-based auth fails.
/// If the leaf cert was signed by a configured trusted CA and the cert's CN
/// matches the requested username (case-insensitive), the session is
/// authenticated immediately (281) without requiring `AUTHINFO PASS`.
///
/// # No business logic
/// The dispatcher only routes and checks preconditions. All actual data
/// retrieval (article lookup, group listing, etc.) returns stub responses
/// until the relevant store modules are wired in by later epics.
pub fn dispatch(
    ctx: &mut SessionContext,
    cmd: Command,
    auth_config: &AuthConfig,
    cert_store: &ClientCertStore,
    trusted_issuer_store: &TrustedIssuerStore,
) -> Response {
    // Precondition: Authenticating state — only auth/setup commands allowed.
    if ctx.state == SessionState::Authenticating {
        return match cmd {
            Command::Capabilities => Response::capabilities_with_ctx(
                ctx.posting_allowed,
                true,
                ctx.starttls_available && !ctx.tls_active,
            ),
            Command::Quit => Response::closing_connection(),
            Command::AuthinfoUser(username) => {
                // RFC 3977 §7.1.1: if TLS is required but not active, reject with 483.
                if auth_config.required && !ctx.tls_active {
                    return Response::new(483, "Encryption required for authentication");
                }
                // Cert bypass: if the session carries a pinned client certificate
                // fingerprint that maps to this username, authenticate immediately.
                if let Some(ref fp) = ctx.client_cert_fingerprint {
                    if let Some(cert_user) = cert_store.lookup(fp) {
                        if cert_user.eq_ignore_ascii_case(&username) {
                            ctx.state = SessionState::Active;
                            ctx.authenticated_user = Some(cert_user.to_string());
                            return Response::authentication_accepted();
                        }
                    }
                }
                // Issuer chain bypass: if the leaf cert was signed by a trusted CA
                // and the cert's CN matches the requested username, authenticate.
                if let Some(ref der) = ctx.client_cert_der {
                    if let Ok(Some(cn)) = trusted_issuer_store.verify_and_extract_cn(der) {
                        if cn.eq_ignore_ascii_case(&username) {
                            ctx.state = SessionState::Active;
                            ctx.authenticated_user = Some(cn.to_lowercase());
                            return Response::authentication_accepted();
                        }
                    }
                }
                ctx.pending_auth_user = Some(username);
                Response::enter_password()
            }
            // STARTTLS is not supported: this server uses implicit TLS only (NNTPS port 563).
            Command::StartTls => Response::new(502, "Command unavailable"),
            _ => Response::authentication_required(),
        };
    }

    // Normal dispatch (Active or GroupSelected).
    match cmd {
        Command::Capabilities => Response::capabilities_with_ctx(
            ctx.posting_allowed,
            false,
            ctx.starttls_available && !ctx.tls_active,
        ),
        Command::ModeReader => {
            if ctx.posting_allowed {
                Response::service_available_posting_allowed()
            } else {
                Response::service_available_posting_prohibited()
            }
        }
        Command::Quit => Response::closing_connection(),
        Command::Group(name) => {
            if !ctx.known_groups.iter().any(|g| g.name == name) {
                return Response::no_such_newsgroup();
            }
            match stoa_core::article::GroupName::new(name) {
                Err(_) => Response::no_such_newsgroup(),
                Ok(group) => {
                    let group_str = group.as_str().to_owned();
                    ctx.current_group = Some(group);
                    ctx.current_article_number = Some(0);
                    ctx.state = SessionState::GroupSelected;
                    Response::group_selected(&group_str, 0, 0, 0)
                }
            }
        }
        Command::Next | Command::Last => {
            if !ctx.state.group_selected() {
                Response::no_group_selected()
            } else {
                Response::no_article_with_number()
            }
        }
        Command::Over(ref arg) => match arg {
            Some(OverArg::MessageId(_)) => Response::overview_follows(),
            _ => {
                if !ctx.state.group_selected() {
                    Response::no_group_selected()
                } else {
                    Response::overview_follows()
                }
            }
        },
        Command::Hdr {
            ref range_or_msgid, ..
        } => match range_or_msgid.as_deref() {
            Some(arg) if arg.starts_with('<') => Response::hdr_follows(vec![]),
            _ => {
                if !ctx.state.group_selected() {
                    Response::no_group_selected()
                } else {
                    Response::hdr_follows(vec![])
                }
            }
        },
        Command::Post => {
            if !ctx.posting_allowed {
                Response::posting_not_permitted()
            } else {
                Response::send_article()
            }
        }
        Command::AuthinfoUser(username) => {
            if auth_config.required && !ctx.tls_active {
                return Response::new(483, "Encryption required for authentication");
            }
            // Cert bypass: if the session carries a pinned client certificate
            // fingerprint that maps to this username, authenticate immediately.
            if let Some(ref fp) = ctx.client_cert_fingerprint {
                if let Some(cert_user) = cert_store.lookup(fp) {
                    if cert_user.eq_ignore_ascii_case(&username) {
                        ctx.authenticated_user = Some(cert_user.to_string());
                        return Response::authentication_accepted();
                    }
                }
            }
            // Issuer chain bypass: if the leaf cert was signed by a trusted CA
            // and the cert's CN matches the requested username, authenticate.
            if let Some(ref der) = ctx.client_cert_der {
                if let Ok(Some(cn)) = trusted_issuer_store.verify_and_extract_cn(der) {
                    if cn.eq_ignore_ascii_case(&username) {
                        ctx.authenticated_user = Some(cn.to_lowercase());
                        return Response::authentication_accepted();
                    }
                }
            }
            ctx.pending_auth_user = Some(username);
            Response::enter_password()
        }
        Command::StartTls => Response::new(502, "Command unavailable"),
        Command::List(sub) => match sub {
            ListSubcommand::Active => list_active(&ctx.known_groups, None),
            ListSubcommand::Newsgroups => list_newsgroups(&ctx.known_groups, None),
            ListSubcommand::OverviewFmt => list_overview_fmt(),
        },
        Command::Newgroups { .. } => newgroups(&ctx.known_groups, 0),
        Command::Newnews { wildmat, .. } => newnews(&ctx.known_groups, 0, Some(&wildmat)),
        Command::Article(arg) | Command::Head(arg) | Command::Body(arg) | Command::Stat(arg) => {
            match arg {
                Some(ArticleRef::MessageId(_)) => Response::no_article_with_message_id(),
                _ => {
                    if !ctx.state.group_selected() {
                        Response::no_newsgroup_selected()
                    } else {
                        Response::no_article_with_number()
                    }
                }
            }
        }
        Command::Search { .. } => {
            unreachable!(
                "SEARCH must be intercepted by lifecycle.rs before reaching dispatch; \
                 if this panics, the session lifecycle is missing the interception"
            )
        }
        _ => Response::unknown_command(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{AuthConfig, UserCredential},
        session::{command::Command, context::SessionContext, state::SessionState},
        store::client_cert_store::ClientCertStore,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)
    }

    fn empty_auth() -> AuthConfig {
        AuthConfig {
            required: false,
            users: vec![],
            credential_file: None,
            client_certs: vec![],
            trusted_issuers: vec![],
        }
    }

    fn no_certs() -> ClientCertStore {
        ClientCertStore::empty()
    }

    fn no_issuers() -> TrustedIssuerStore {
        TrustedIssuerStore::empty()
    }

    fn ctx_authenticating() -> SessionContext {
        SessionContext::new(test_addr(), true, true, false)
    }

    fn ctx_active() -> SessionContext {
        SessionContext::new(test_addr(), false, true, false)
    }

    fn ctx_group_selected() -> SessionContext {
        let mut ctx = SessionContext::new(test_addr(), false, true, false);
        ctx.known_groups
            .push(crate::session::commands::list::GroupInfo {
                name: "comp.lang.rust".into(),
                high: 0,
                low: 0,
                posting_allowed: true,
                description: String::new(),
            });
        dispatch(
            &mut ctx,
            Command::Group("comp.lang.rust".into()),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        ctx
    }

    #[test]
    fn test_authenticating_unknown_command_gets_480() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(
            &mut ctx,
            Command::List(crate::session::command::ListSubcommand::Active),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 480);
    }

    #[test]
    fn test_authenticating_quit_allowed() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(
            &mut ctx,
            Command::Quit,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 205);
    }

    #[test]
    fn test_authenticating_authinfo_user_returns_381() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(
            &mut ctx,
            Command::AuthinfoUser("alice".into()),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 381);
        assert_eq!(ctx.state, SessionState::Authenticating);
    }

    #[test]
    fn test_active_next_without_group_gets_412() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Next,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 412);
    }

    #[test]
    fn test_group_selected_next_returns_stub() {
        let mut ctx = ctx_group_selected();
        let resp = dispatch(
            &mut ctx,
            Command::Next,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 423);
    }

    #[test]
    fn test_post_not_permitted() {
        let mut ctx = SessionContext::new(test_addr(), false, false, false);
        let resp = dispatch(
            &mut ctx,
            Command::Post,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 440);
    }

    #[test]
    fn test_post_permitted_stub() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Post,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 340);
    }

    #[test]
    fn test_capabilities_always_works() {
        let mut ctx_a = ctx_authenticating();
        assert_eq!(
            dispatch(
                &mut ctx_a,
                Command::Capabilities,
                &empty_auth(),
                &no_certs(),
                &no_issuers(),
            )
            .code,
            101
        );

        let mut ctx_b = ctx_active();
        assert_eq!(
            dispatch(
                &mut ctx_b,
                Command::Capabilities,
                &empty_auth(),
                &no_certs(),
                &no_issuers(),
            )
            .code,
            101
        );

        let mut ctx_c = ctx_group_selected();
        assert_eq!(
            dispatch(
                &mut ctx_c,
                Command::Capabilities,
                &empty_auth(),
                &no_certs(),
                &no_issuers(),
            )
            .code,
            101
        );
    }

    #[test]
    fn test_capabilities_active_contains_version_2() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Capabilities,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 101);
        assert!(resp.body.iter().any(|l| l == "VERSION 2"));
    }

    #[test]
    fn test_capabilities_posting_allowed_includes_post() {
        let mut ctx = ctx_active(); // posting_allowed = true
        let resp = dispatch(
            &mut ctx,
            Command::Capabilities,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert!(resp.body.iter().any(|l| l == "POST"));
    }

    #[test]
    fn test_capabilities_posting_not_allowed_excludes_post() {
        let mut ctx = SessionContext::new(test_addr(), false, false, false);
        let resp = dispatch(
            &mut ctx,
            Command::Capabilities,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert!(!resp.body.iter().any(|l| l == "POST"));
    }

    #[test]
    fn test_mode_reader_posting_allowed_returns_200() {
        let mut ctx = ctx_active(); // posting_allowed = true
        let resp = dispatch(
            &mut ctx,
            Command::ModeReader,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 200);
    }

    #[test]
    fn test_mode_reader_posting_not_allowed_returns_201() {
        let mut ctx = SessionContext::new(test_addr(), false, false, false);
        let resp = dispatch(
            &mut ctx,
            Command::ModeReader,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 201);
    }

    #[test]
    fn test_quit_returns_205() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Quit,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 205);
    }

    #[test]
    fn starttls_always_returns_502() {
        // STARTTLS is not supported — implicit TLS (NNTPS port 563) is used instead.
        let mut ctx = SessionContext::new(test_addr(), false, true, false);
        let resp = dispatch(
            &mut ctx,
            Command::StartTls,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 502);
    }

    #[test]
    fn authinfo_on_plain_with_required_returns_483() {
        // Plain connection (tls_active=false) with auth.required=true must return 483.
        let hash = bcrypt::hash("secret", 4).expect("bcrypt::hash must not fail");
        let auth = AuthConfig {
            required: true,
            users: vec![UserCredential {
                username: "alice".into(),
                password: hash,
            }],
            credential_file: None,
            client_certs: vec![],
            trusted_issuers: vec![],
        };
        let mut ctx = SessionContext::new(test_addr(), false, true, false);
        let resp = dispatch(
            &mut ctx,
            Command::AuthinfoUser("alice".into()),
            &auth,
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(
            resp.code, 483,
            "AUTHINFO on plain must return 483 when required=true"
        );
    }

    #[test]
    fn capabilities_omits_starttls_when_not_available() {
        // STARTTLS is not advertised when starttls_available=false (no TLS configured).
        for tls_active in [false, true] {
            let mut ctx = SessionContext::new(test_addr(), false, true, tls_active);
            // starttls_available defaults to false
            let resp = dispatch(
                &mut ctx,
                Command::Capabilities,
                &empty_auth(),
                &no_certs(),
                &no_issuers(),
            );
            assert!(
                !resp.body.iter().any(|l| l == "STARTTLS"),
                "STARTTLS must not appear when starttls_available=false (tls_active={tls_active})"
            );
        }
    }

    #[test]
    fn capabilities_includes_starttls_on_plain_when_available() {
        // STARTTLS appears in CAPABILITIES on a plain connection when TLS is configured.
        let mut ctx = SessionContext::new(test_addr(), false, true, false);
        ctx.starttls_available = true;
        let resp = dispatch(
            &mut ctx,
            Command::Capabilities,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert!(
            resp.body.iter().any(|l| l == "STARTTLS"),
            "STARTTLS must appear in CAPABILITIES on plain connection when available"
        );
    }

    #[test]
    fn capabilities_omits_starttls_after_tls_upgrade() {
        // STARTTLS must NOT appear in CAPABILITIES after TLS is active, even if
        // starttls_available is true (RFC 4642: cannot upgrade twice).
        let mut ctx = SessionContext::new(test_addr(), false, true, true);
        ctx.starttls_available = true;
        let resp = dispatch(
            &mut ctx,
            Command::Capabilities,
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert!(
            !resp.body.iter().any(|l| l == "STARTTLS"),
            "STARTTLS must not appear in CAPABILITIES after TLS is active"
        );
    }

    #[test]
    fn group_unknown_returns_411() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Group("no.such.group".into()),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 411);
    }

    #[test]
    fn group_known_returns_211() {
        let mut ctx = ctx_active();
        ctx.known_groups
            .push(crate::session::commands::list::GroupInfo {
                name: "comp.lang.rust".into(),
                high: 0,
                low: 0,
                posting_allowed: true,
                description: String::new(),
            });
        let resp = dispatch(
            &mut ctx,
            Command::Group("comp.lang.rust".into()),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 211);
    }

    /// A group name that passes the `known_groups` membership check but fails
    /// `GroupName::new` validation must return 411, not 211 with a None group.
    #[test]
    fn group_invalid_name_in_known_groups_returns_411() {
        let mut ctx = ctx_active();
        // Push a syntactically-invalid name into known_groups to simulate a
        // misconfigured or adversarial state.
        ctx.known_groups
            .push(crate::session::commands::list::GroupInfo {
                name: "invalid..double.dot".into(),
                high: 0,
                low: 0,
                posting_allowed: true,
                description: String::new(),
            });
        let resp = dispatch(
            &mut ctx,
            Command::Group("invalid..double.dot".into()),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 411, "invalid group name must return 411");
        assert!(
            ctx.current_group.is_none(),
            "current_group must not be set after 411"
        );
    }

    /// RFC 3977 §6.1.1: when GROUP returns 411, the previously selected group
    /// must remain selected (session state is unchanged).
    #[test]
    fn group_invalid_name_preserves_prior_group_selection() {
        // Start with a valid group selected.
        let mut ctx = ctx_group_selected(); // current_group = comp.lang.rust
        let prior_group = ctx.current_group.clone();

        // Push a syntactically-invalid name so the known_groups check passes.
        ctx.known_groups
            .push(crate::session::commands::list::GroupInfo {
                name: "bad..name".into(),
                high: 0,
                low: 0,
                posting_allowed: true,
                description: String::new(),
            });

        let resp = dispatch(
            &mut ctx,
            Command::Group("bad..name".into()),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 411, "invalid group name must return 411");
        assert_eq!(
            ctx.current_group, prior_group,
            "prior group selection must be preserved after 411"
        );
        assert_eq!(
            ctx.state,
            SessionState::GroupSelected,
            "session state must remain GroupSelected after 411"
        );
    }

    #[test]
    fn article_number_without_group_returns_412() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Article(Some(crate::session::command::ArticleRef::Number(1))),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 412);
    }

    #[test]
    fn article_msgid_unknown_returns_430() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Article(Some(crate::session::command::ArticleRef::MessageId(
                "<x@example.com>".into(),
            ))),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 430);
    }

    #[test]
    fn head_msgid_unknown_returns_430() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Head(Some(crate::session::command::ArticleRef::MessageId(
                "<x@example.com>".into(),
            ))),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 430);
    }

    #[test]
    fn body_msgid_unknown_returns_430() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Body(Some(crate::session::command::ArticleRef::MessageId(
                "<x@example.com>".into(),
            ))),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 430);
    }

    #[test]
    fn stat_msgid_unknown_returns_430() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Stat(Some(crate::session::command::ArticleRef::MessageId(
                "<x@example.com>".into(),
            ))),
            &empty_auth(),
            &no_certs(),
            &no_issuers(),
        );
        assert_eq!(resp.code, 430);
    }
}
