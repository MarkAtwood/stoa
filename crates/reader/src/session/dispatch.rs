use usenet_ipfs_core::audit::AuditLoggerHandle;

use crate::{
    config::AuthConfig,
    session::{
        command::{ArticleRef, Command, ListSubcommand, OverArg},
        commands::{
            auth::authinfo_response,
            list::{list_active, list_newsgroups, list_overview_fmt, newgroups, newnews},
        },
        context::SessionContext,
        response::Response,
        state::SessionState,
    },
};

/// Dispatch a parsed command, enforcing state machine preconditions.
///
/// Returns a `Response` to send to the client. Updates `ctx` for state-
/// changing commands (GROUP, AUTHINFO, STARTTLS, QUIT).
///
/// If `audit_logger` is provided, `AuthAttempt` events are emitted for
/// every AUTHINFO command.
///
/// # No business logic
/// The dispatcher only routes and checks preconditions. All actual data
/// retrieval (article lookup, group listing, etc.) returns stub responses
/// until the relevant store modules are wired in by later epics.
pub fn dispatch(
    ctx: &mut SessionContext,
    cmd: Command,
    auth_config: &AuthConfig,
    audit_logger: Option<&AuditLoggerHandle>,
) -> Response {
    let peer_addr = ctx.peer_addr.to_string();

    // Precondition: Authenticating state — only auth/setup commands allowed.
    if ctx.state == SessionState::Authenticating {
        return match cmd {
            Command::Capabilities => {
                Response::capabilities_with_ctx(
                    ctx.posting_allowed,
                    true,
                    ctx.starttls_available,
                )
            }
            Command::Quit => Response::closing_connection(),
            Command::AuthinfoUser(username) => {
                ctx.pending_auth_user = Some(username);
                Response::enter_password()
            }
            Command::AuthinfoPass(password) => {
                let username = match ctx.pending_auth_user.take() {
                    Some(u) => u,
                    None => return Response::authentication_out_of_sequence(),
                };
                let success = check_credentials(auth_config, &username, &password);
                let resp_str = authinfo_response(&username, &peer_addr, success, audit_logger);
                if success {
                    ctx.state = SessionState::Active;
                    ctx.authenticated_user = Some(username);
                }
                Response::from_static_str(resp_str)
            }
            Command::StartTls => dispatch_starttls(ctx),
            _ => Response::authentication_required(),
        };
    }

    // Normal dispatch (Active or GroupSelected).
    match cmd {
        Command::Capabilities => {
            Response::capabilities_with_ctx(
                ctx.posting_allowed,
                false,
                ctx.starttls_available,
            )
        }
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
            ctx.current_group = usenet_ipfs_core::article::GroupName::new(name).ok();
            ctx.current_article_number = Some(0);
            ctx.state = SessionState::GroupSelected;
            let group_str = ctx
                .current_group
                .as_ref()
                .map(|g| g.as_str())
                .unwrap_or("no.such.group");
            Response::group_selected(group_str, 0, 0, 0)
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
        Command::Post => {
            if !ctx.posting_allowed {
                Response::posting_not_permitted()
            } else {
                Response::send_article()
            }
        }
        Command::AuthinfoUser(username) => {
            ctx.pending_auth_user = Some(username);
            Response::enter_password()
        }
        Command::AuthinfoPass(password) => {
            let username = match ctx.pending_auth_user.take() {
                Some(u) => u,
                None => return Response::authentication_out_of_sequence(),
            };
            let success = check_credentials(auth_config, &username, &password);
            let resp_str = authinfo_response(&username, &peer_addr, success, audit_logger);
            if success {
                ctx.authenticated_user = Some(username);
            }
            Response::from_static_str(resp_str)
        }
        Command::StartTls => dispatch_starttls(ctx),
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
        _ => Response::information_follows(),
    }
}

/// Check whether `username`/`password` are valid per `auth_config`.
///
/// If `auth_config.users` is empty and `auth_config.required` is false,
/// all attempts succeed (development mode). Otherwise the credentials
/// must match an entry in `auth_config.users`.
fn check_credentials(auth_config: &AuthConfig, username: &str, password: &str) -> bool {
    if auth_config.users.is_empty() && !auth_config.required {
        return true;
    }
    auth_config
        .users
        .iter()
        .any(|u| u.username == username && u.password == password)
}

/// Return the correct STARTTLS response depending on whether upgrade is available.
fn dispatch_starttls(ctx: &mut SessionContext) -> Response {
    if ctx.starttls_available {
        Response::tls_proceed()
    } else {
        Response::tls_not_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{AuthConfig, UserCredential},
        session::{command::Command, context::SessionContext, state::SessionState},
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)
    }

    fn empty_auth() -> AuthConfig {
        AuthConfig { required: false, users: vec![] }
    }

    fn ctx_authenticating() -> SessionContext {
        SessionContext::new(test_addr(), true, true, false)
    }

    fn ctx_active() -> SessionContext {
        SessionContext::new(test_addr(), false, true, false)
    }

    fn ctx_group_selected() -> SessionContext {
        let mut ctx = SessionContext::new(test_addr(), false, true, false);
        ctx.known_groups.push(crate::session::commands::list::GroupInfo {
            name: "comp.lang.rust".into(),
            high: 0,
            low: 0,
            posting_allowed: true,
            description: String::new(),
        });
        dispatch(&mut ctx, Command::Group("comp.lang.rust".into()), &empty_auth(), None);
        ctx
    }

    #[test]
    fn test_authenticating_unknown_command_gets_480() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(
            &mut ctx,
            Command::List(crate::session::command::ListSubcommand::Active),
            &empty_auth(),
            None,
        );
        assert_eq!(resp.code, 480);
    }

    #[test]
    fn test_authenticating_quit_allowed() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(&mut ctx, Command::Quit, &empty_auth(), None);
        assert_eq!(resp.code, 205);
    }

    #[test]
    fn test_authenticating_authinfo_user_returns_381() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(&mut ctx, Command::AuthinfoUser("alice".into()), &empty_auth(), None);
        assert_eq!(resp.code, 381);
        assert_eq!(ctx.state, SessionState::Authenticating);
    }

    #[test]
    fn test_authenticating_authinfo_pass_after_user_succeeds() {
        let mut ctx = ctx_authenticating();
        dispatch(&mut ctx, Command::AuthinfoUser("alice".into()), &empty_auth(), None);
        let resp = dispatch(&mut ctx, Command::AuthinfoPass("any".into()), &empty_auth(), None);
        assert_eq!(resp.code, 281);
        assert_eq!(ctx.state, SessionState::Active);
    }

    #[test]
    fn test_active_next_without_group_gets_412() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Next, &empty_auth(), None);
        assert_eq!(resp.code, 412);
    }

    #[test]
    fn test_group_selected_next_returns_stub() {
        let mut ctx = ctx_group_selected();
        let resp = dispatch(&mut ctx, Command::Next, &empty_auth(), None);
        assert_eq!(resp.code, 423);
    }

    #[test]
    fn test_post_not_permitted() {
        let mut ctx = SessionContext::new(test_addr(), false, false, false);
        let resp = dispatch(&mut ctx, Command::Post, &empty_auth(), None);
        assert_eq!(resp.code, 440);
    }

    #[test]
    fn test_post_permitted_stub() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Post, &empty_auth(), None);
        assert_eq!(resp.code, 340);
    }

    #[test]
    fn test_capabilities_always_works() {
        let mut ctx_a = ctx_authenticating();
        assert_eq!(dispatch(&mut ctx_a, Command::Capabilities, &empty_auth(), None).code, 101);

        let mut ctx_b = ctx_active();
        assert_eq!(dispatch(&mut ctx_b, Command::Capabilities, &empty_auth(), None).code, 101);

        let mut ctx_c = ctx_group_selected();
        assert_eq!(dispatch(&mut ctx_c, Command::Capabilities, &empty_auth(), None).code, 101);
    }

    #[test]
    fn test_capabilities_active_contains_version_2() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Capabilities, &empty_auth(), None);
        assert_eq!(resp.code, 101);
        assert!(resp.body.iter().any(|l| l == "VERSION 2"));
    }

    #[test]
    fn test_capabilities_posting_allowed_includes_post() {
        let mut ctx = ctx_active(); // posting_allowed = true
        let resp = dispatch(&mut ctx, Command::Capabilities, &empty_auth(), None);
        assert!(resp.body.iter().any(|l| l == "POST"));
    }

    #[test]
    fn test_capabilities_posting_not_allowed_excludes_post() {
        let mut ctx = SessionContext::new(test_addr(), false, false, false);
        let resp = dispatch(&mut ctx, Command::Capabilities, &empty_auth(), None);
        assert!(!resp.body.iter().any(|l| l == "POST"));
    }

    #[test]
    fn test_mode_reader_posting_allowed_returns_200() {
        let mut ctx = ctx_active(); // posting_allowed = true
        let resp = dispatch(&mut ctx, Command::ModeReader, &empty_auth(), None);
        assert_eq!(resp.code, 200);
    }

    #[test]
    fn test_mode_reader_posting_not_allowed_returns_201() {
        let mut ctx = SessionContext::new(test_addr(), false, false, false);
        let resp = dispatch(&mut ctx, Command::ModeReader, &empty_auth(), None);
        assert_eq!(resp.code, 201);
    }

    #[test]
    fn test_quit_returns_205() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Quit, &empty_auth(), None);
        assert_eq!(resp.code, 205);
    }

    #[test]
    fn starttls_not_available_returns_580() {
        let mut ctx = SessionContext::new(test_addr(), false, true, false);
        let resp = dispatch(&mut ctx, Command::StartTls, &empty_auth(), None);
        assert_eq!(resp.code, 580);
    }

    #[test]
    fn starttls_available_returns_382() {
        let mut ctx = SessionContext::new(test_addr(), false, true, true);
        let resp = dispatch(&mut ctx, Command::StartTls, &empty_auth(), None);
        assert_eq!(resp.code, 382);
    }

    #[test]
    fn authinfo_with_credential_match_returns_281() {
        let auth = AuthConfig {
            required: true,
            users: vec![UserCredential {
                username: "alice".into(),
                password: "secret".into(),
            }],
        };
        let mut ctx = SessionContext::new(test_addr(), false, true, false);
        dispatch(&mut ctx, Command::AuthinfoUser("alice".into()), &auth, None);
        let resp = dispatch(&mut ctx, Command::AuthinfoPass("secret".into()), &auth, None);
        assert_eq!(resp.code, 281);
    }

    #[test]
    fn authinfo_with_wrong_password_returns_481() {
        let auth = AuthConfig {
            required: true,
            users: vec![UserCredential {
                username: "alice".into(),
                password: "secret".into(),
            }],
        };
        let mut ctx = SessionContext::new(test_addr(), false, true, false);
        dispatch(&mut ctx, Command::AuthinfoUser("alice".into()), &auth, None);
        let resp = dispatch(&mut ctx, Command::AuthinfoPass("wrong".into()), &auth, None);
        assert_eq!(resp.code, 481);
    }

    #[test]
    fn authinfo_pass_without_user_returns_482() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::AuthinfoPass("secret".into()), &empty_auth(), None);
        assert_eq!(resp.code, 482);
    }

    #[test]
    fn capabilities_includes_starttls_when_available() {
        let mut ctx = SessionContext::new(test_addr(), false, true, true);
        let resp = dispatch(&mut ctx, Command::Capabilities, &empty_auth(), None);
        assert!(resp.body.iter().any(|l| l == "STARTTLS"));
    }

    #[test]
    fn capabilities_excludes_starttls_when_not_available() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Capabilities, &empty_auth(), None);
        assert!(!resp.body.iter().any(|l| l == "STARTTLS"));
    }

    #[test]
    fn group_unknown_returns_411() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Group("no.such.group".into()), &empty_auth(), None);
        assert_eq!(resp.code, 411);
    }

    #[test]
    fn group_known_returns_211() {
        let mut ctx = ctx_active();
        ctx.known_groups.push(crate::session::commands::list::GroupInfo {
            name: "comp.lang.rust".into(),
            high: 0,
            low: 0,
            posting_allowed: true,
            description: String::new(),
        });
        let resp = dispatch(&mut ctx, Command::Group("comp.lang.rust".into()), &empty_auth(), None);
        assert_eq!(resp.code, 211);
    }

    #[test]
    fn article_number_without_group_returns_412() {
        let mut ctx = ctx_active();
        let resp = dispatch(
            &mut ctx,
            Command::Article(Some(crate::session::command::ArticleRef::Number(1))),
            &empty_auth(),
            None,
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
            None,
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
            None,
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
            None,
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
            None,
        );
        assert_eq!(resp.code, 430);
    }
}
