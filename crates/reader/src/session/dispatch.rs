use crate::session::{
    command::{Command, OverArg},
    context::SessionContext,
    response::Response,
    state::SessionState,
};

/// Dispatch a parsed command, enforcing state machine preconditions.
///
/// Returns a `Response` to send to the client. Updates `ctx` for state-
/// changing commands (GROUP, AUTHINFO, STARTTLS, QUIT).
///
/// # No business logic
/// The dispatcher only routes and checks preconditions. All actual data
/// retrieval (article lookup, group listing, etc.) returns stub responses
/// until the relevant store modules are wired in by later epics.
pub fn dispatch(ctx: &mut SessionContext, cmd: Command) -> Response {
    // Precondition: Authenticating state — only auth/setup commands allowed.
    if ctx.state == SessionState::Authenticating {
        return match cmd {
            Command::Capabilities => {
                Response::capabilities_with_ctx(ctx.posting_allowed, true)
            }
            Command::Quit => Response::closing_connection(),
            Command::AuthinfoUser(_) | Command::AuthinfoPass(_) => {
                // Stub: accept any credentials.
                ctx.state = SessionState::Active;
                ctx.authenticated_user = Some("anonymous".into());
                Response::authentication_accepted()
            }
            Command::StartTls => {
                ctx.tls_active = true;
                Response::tls_proceed()
            }
            _ => Response::authentication_required(),
        };
    }

    // Normal dispatch (Active or GroupSelected).
    match cmd {
        Command::Capabilities => {
            Response::capabilities_with_ctx(ctx.posting_allowed, false)
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
        Command::AuthinfoUser(_) | Command::AuthinfoPass(_) => {
            // Already authenticated; re-auth is a no-op stub.
            Response::authentication_accepted()
        }
        Command::StartTls => {
            ctx.tls_active = true;
            Response::tls_proceed()
        }
        _ => Response::information_follows(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{command::Command, context::SessionContext, state::SessionState};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)
    }

    fn ctx_authenticating() -> SessionContext {
        SessionContext::new(test_addr(), true, true)
    }

    fn ctx_active() -> SessionContext {
        SessionContext::new(test_addr(), false, true)
    }

    fn ctx_group_selected() -> SessionContext {
        let mut ctx = SessionContext::new(test_addr(), false, true);
        dispatch(&mut ctx, Command::Group("comp.lang.rust".into()));
        ctx
    }

    #[test]
    fn test_authenticating_unknown_command_gets_480() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(&mut ctx, Command::List(crate::session::command::ListSubcommand::Active));
        assert_eq!(resp.code, 480);
    }

    #[test]
    fn test_authenticating_quit_allowed() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(&mut ctx, Command::Quit);
        assert_eq!(resp.code, 205);
    }

    #[test]
    fn test_authenticating_authinfo_transitions() {
        let mut ctx = ctx_authenticating();
        let resp = dispatch(&mut ctx, Command::AuthinfoUser("alice".into()));
        assert_eq!(resp.code, 281);
        assert_eq!(ctx.state, SessionState::Active);
    }

    #[test]
    fn test_active_next_without_group_gets_412() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Next);
        assert_eq!(resp.code, 412);
    }

    #[test]
    fn test_group_selected_next_returns_stub() {
        let mut ctx = ctx_group_selected();
        let resp = dispatch(&mut ctx, Command::Next);
        assert_eq!(resp.code, 423);
    }

    #[test]
    fn test_post_not_permitted() {
        let mut ctx = SessionContext::new(test_addr(), false, false);
        let resp = dispatch(&mut ctx, Command::Post);
        assert_eq!(resp.code, 440);
    }

    #[test]
    fn test_post_permitted_stub() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Post);
        assert_eq!(resp.code, 340);
    }

    #[test]
    fn test_capabilities_always_works() {
        let mut ctx_a = ctx_authenticating();
        assert_eq!(dispatch(&mut ctx_a, Command::Capabilities).code, 101);

        let mut ctx_b = ctx_active();
        assert_eq!(dispatch(&mut ctx_b, Command::Capabilities).code, 101);

        let mut ctx_c = ctx_group_selected();
        assert_eq!(dispatch(&mut ctx_c, Command::Capabilities).code, 101);
    }

    #[test]
    fn test_capabilities_active_contains_version_2() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Capabilities);
        assert_eq!(resp.code, 101);
        assert!(resp.body.iter().any(|l| l == "VERSION 2"));
    }

    #[test]
    fn test_capabilities_posting_allowed_includes_post() {
        let mut ctx = ctx_active(); // posting_allowed = true
        let resp = dispatch(&mut ctx, Command::Capabilities);
        assert!(resp.body.iter().any(|l| l == "POST"));
    }

    #[test]
    fn test_capabilities_posting_not_allowed_excludes_post() {
        let mut ctx = SessionContext::new(test_addr(), false, false);
        let resp = dispatch(&mut ctx, Command::Capabilities);
        assert!(!resp.body.iter().any(|l| l == "POST"));
    }

    #[test]
    fn test_mode_reader_posting_allowed_returns_200() {
        let mut ctx = ctx_active(); // posting_allowed = true
        let resp = dispatch(&mut ctx, Command::ModeReader);
        assert_eq!(resp.code, 200);
    }

    #[test]
    fn test_mode_reader_posting_not_allowed_returns_201() {
        let mut ctx = SessionContext::new(test_addr(), false, false);
        let resp = dispatch(&mut ctx, Command::ModeReader);
        assert_eq!(resp.code, 201);
    }

    #[test]
    fn test_quit_returns_205() {
        let mut ctx = ctx_active();
        let resp = dispatch(&mut ctx, Command::Quit);
        assert_eq!(resp.code, 205);
    }
}
