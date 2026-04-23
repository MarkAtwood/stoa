//! IMAP session state machine using the `imap-next` sans-I/O library.
//!
//! # Session lifecycle
//!
//! ```text
//! connect
//!   └─> NotAuthenticated  (greeting sent; LOGINDISABLED if no TLS)
//!           └─> [AUTH=PLAIN / AUTH=LOGIN] ──> Authenticated
//!                   └─> [SELECT / EXAMINE]  ──> Selected(mailbox)
//!                           └─> [CLOSE / EXPUNGE] ──> Authenticated
//!   Any state ──> [LOGOUT] ──> Logout  (session ends)
//! ```

pub mod auth;
pub mod commands;
pub mod fetch;
pub mod mailbox;

use std::{net::SocketAddr, sync::Arc};

use imap_next::{
    imap_types::{
        command::CommandBody,
        core::Tag,
        response::{
            CommandContinuationRequest, Data, Greeting, Status, StatusBody, StatusKind, Tagged,
        },
    },
    server::{Event, Options, ResponseHandle, Server},
    stream::Stream,
};
use sqlx::SqlitePool;
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsStream as TlsStreamEnum};
use tracing::{debug, info, warn};

use crate::config::Config;

use auth::AuthProgress;
use fetch::{handle_fetch, handle_search, handle_store};
use mailbox::{
    handle_list, handle_select, handle_status, list_mailbox_to_string, select_status_responses,
    select_untagged_data,
};

/// IMAP session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapState {
    NotAuthenticated,
    Authenticated {
        username: String,
    },
    Selected {
        username: String,
        mailbox: String,
        read_only: bool,
    },
    Logout,
}

/// Session context shared across command handlers.
pub struct SessionContext {
    pub pool: Arc<SqlitePool>,
    pub config: Arc<Config>,
    pub peer: SocketAddr,
    /// Whether the transport is TLS (IMAPS or post-STARTTLS).
    pub tls: bool,
    pub state: ImapState,
    /// In-progress multi-step authentication state.
    pub auth_progress: AuthProgress,
    /// Tag saved when IDLE is accepted; consumed on DONE to send the tagged OK.
    pub idle_tag: Option<Tag<'static>>,
}

/// Entry point for a plain-text IMAP connection.
pub async fn run_session_plain(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
) {
    let imap_stream = Stream::insecure(stream);
    let ctx = SessionContext {
        pool,
        config,
        peer,
        tls: false,
        state: ImapState::NotAuthenticated,
        auth_progress: AuthProgress::None,
        idle_tag: None,
    };
    run_session_inner(imap_stream, ctx).await;
}

/// Entry point for an implicit-TLS IMAPS connection.
pub async fn run_session_tls(
    stream: TlsStream<TcpStream>,
    peer: SocketAddr,
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
) {
    // Wrap server-side TlsStream into the enum variant that imap-next expects.
    let imap_stream = Stream::tls(TlsStreamEnum::Server(stream));
    let ctx = SessionContext {
        pool,
        config,
        peer,
        tls: true,
        state: ImapState::NotAuthenticated,
        auth_progress: AuthProgress::None,
        idle_tag: None,
    };
    run_session_inner(imap_stream, ctx).await;
}

/// Core event loop shared by plain and TLS sessions.
///
/// Drives the `imap-next` state machine until the session ends (LOGOUT or
/// connection error).
async fn run_session_inner(mut stream: Stream, mut ctx: SessionContext) {
    let greeting = match Greeting::ok(None, "IMAP4rev1 usenet-ipfs-imap server ready") {
        Ok(g) => g,
        Err(e) => {
            warn!(peer = %ctx.peer, "failed to construct IMAP greeting: {e}");
            return;
        }
    };
    let mut options = Options::default();
    options.max_literal_size = ctx.config.limits.max_literal_bytes.min(u32::MAX as u64) as u32;
    let mut server = Server::new(options, greeting);

    info!(peer = %ctx.peer, tls = ctx.tls, "IMAP session started");

    loop {
        let event = match stream.next(&mut server).await {
            Ok(ev) => ev,
            Err(e) => {
                debug!(peer = %ctx.peer, "IMAP session ended: {e}");
                break;
            }
        };

        match event {
            Event::GreetingSent { .. } => {
                debug!(peer = %ctx.peer, "IMAP greeting sent");
            }

            Event::ResponseSent { .. } => {
                // Per-handle delivery tracking is added in later waves.
            }

            Event::CommandReceived { command } => {
                let tag = command.tag;
                match command.body {
                    CommandBody::Capability => {
                        server.enqueue_data(commands::capability_data(ctx.tls));
                        server.enqueue_status(commands::capability_ok(tag));
                    }

                    CommandBody::Noop => {
                        server.enqueue_status(commands::noop_ok(tag));
                    }

                    CommandBody::Logout => {
                        // RFC 3501 §6.1.3: send untagged BYE, then tagged OK.
                        server
                            .enqueue_status(Status::bye(None, "Logging out").expect("static bye"));
                        let last = server.enqueue_status(
                            Status::ok(Some(tag), None, "LOGOUT completed").expect("static ok"),
                        );
                        ctx.state = ImapState::Logout;
                        drain_until(&mut stream, &mut server, last).await;
                        break;
                    }

                    CommandBody::Select { mailbox, .. } => match ctx.state {
                        ImapState::Authenticated { ref username }
                        | ImapState::Selected { ref username, .. } => {
                            let username = username.clone();
                            match handle_select(&ctx.pool, tag, mailbox, false).await {
                                Ok(result) => {
                                    let mailbox_name = result.mailbox_name.clone();
                                    for d in select_untagged_data() {
                                        server.enqueue_data(d);
                                    }
                                    for s in select_status_responses(&result) {
                                        server.enqueue_status(s);
                                    }
                                    server.enqueue_status(result.tagged_ok);
                                    ctx.state = ImapState::Selected {
                                        username,
                                        mailbox: mailbox_name,
                                        read_only: false,
                                    };
                                }
                                Err(no) => {
                                    server.enqueue_status(no);
                                }
                            }
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in authenticated state")
                                    .expect("static no"),
                            );
                        }
                    },

                    CommandBody::Examine { mailbox, .. } => match ctx.state {
                        ImapState::Authenticated { ref username }
                        | ImapState::Selected { ref username, .. } => {
                            let username = username.clone();
                            match handle_select(&ctx.pool, tag, mailbox, true).await {
                                Ok(result) => {
                                    let mailbox_name = result.mailbox_name.clone();
                                    for d in select_untagged_data() {
                                        server.enqueue_data(d);
                                    }
                                    for s in select_status_responses(&result) {
                                        server.enqueue_status(s);
                                    }
                                    server.enqueue_status(result.tagged_ok);
                                    ctx.state = ImapState::Selected {
                                        username,
                                        mailbox: mailbox_name,
                                        read_only: true,
                                    };
                                }
                                Err(no) => {
                                    server.enqueue_status(no);
                                }
                            }
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in authenticated state")
                                    .expect("static no"),
                            );
                        }
                    },

                    CommandBody::List {
                        reference,
                        mailbox_wildcard,
                    } => match ctx.state {
                        ImapState::Authenticated { .. } | ImapState::Selected { .. } => {
                            let wildcard = list_mailbox_to_string(&mailbox_wildcard);
                            for d in handle_list(&ctx.pool, &reference, &wildcard).await {
                                server.enqueue_data(d);
                            }
                            server.enqueue_status(
                                Status::ok(Some(tag), None, "LIST complete").expect("static ok"),
                            );
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in authenticated state")
                                    .expect("static no"),
                            );
                        }
                    },

                    CommandBody::Status {
                        mailbox,
                        item_names,
                    } => match ctx.state {
                        ImapState::Authenticated { .. } | ImapState::Selected { .. } => {
                            match handle_status(&ctx.pool, mailbox, item_names.as_ref()).await {
                                Some(data) => {
                                    server.enqueue_data(data);
                                    server.enqueue_status(
                                        Status::ok(Some(tag), None, "STATUS complete")
                                            .expect("static ok"),
                                    );
                                }
                                None => {
                                    server.enqueue_status(
                                        Status::no(Some(tag), None, "No such mailbox")
                                            .expect("static no"),
                                    );
                                }
                            }
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in authenticated state")
                                    .expect("static no"),
                            );
                        }
                    },

                    CommandBody::Fetch { .. } => match ctx.state {
                        ImapState::Selected { .. } => {
                            server.enqueue_status(handle_fetch(tag));
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in selected state")
                                    .expect("static no"),
                            );
                        }
                    },

                    CommandBody::Store {
                        sequence_set,
                        kind,
                        response: store_response,
                        flags,
                        uid,
                        ..
                    } => match ctx.state {
                        ImapState::Selected {
                            ref username,
                            ref mailbox,
                            ..
                        } => {
                            let username = username.clone();
                            let mailbox = mailbox.clone();
                            let status = handle_store(
                                &ctx.pool,
                                &username,
                                &mailbox,
                                tag,
                                &sequence_set,
                                kind,
                                store_response,
                                &flags,
                                uid,
                            )
                            .await;
                            server.enqueue_status(status);
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in selected state")
                                    .expect("static no"),
                            );
                        }
                    },

                    CommandBody::Search { uid, .. } => match ctx.state {
                        ImapState::Selected { .. } => {
                            let (data, status) = handle_search(tag, uid);
                            server.enqueue_data(data);
                            server.enqueue_status(status);
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in selected state")
                                    .expect("static no"),
                            );
                        }
                    },

                    CommandBody::Expunge => {
                        match ctx.state {
                            ImapState::Selected { .. } => {
                                // No messages to expunge (EXISTS=0); tagged OK suffices.
                                server.enqueue_status(
                                    Status::ok(Some(tag), None, "EXPUNGE complete")
                                        .expect("static ok"),
                                );
                            }
                            _ => {
                                server.enqueue_status(
                                    Status::no(Some(tag), None, "Not in selected state")
                                        .expect("static no"),
                                );
                            }
                        }
                    }

                    CommandBody::Close => {
                        match ctx.state {
                            ImapState::Selected { ref username, .. } => {
                                let username = username.clone();
                                // Implicitly expunge deleted messages (no-op, EXISTS=0),
                                // then deselect: transition back to Authenticated.
                                ctx.state = ImapState::Authenticated { username };
                                server.enqueue_status(
                                    Status::ok(Some(tag), None, "CLOSE complete")
                                        .expect("static ok"),
                                );
                            }
                            _ => {
                                server.enqueue_status(
                                    Status::no(Some(tag), None, "Not in selected state")
                                        .expect("static no"),
                                );
                            }
                        }
                    }

                    // UNSELECT (RFC 3691) — deselect without expunging \Deleted.
                    CommandBody::Unselect => match ctx.state {
                        ImapState::Selected { ref username, .. } => {
                            let username = username.clone();
                            ctx.state = ImapState::Authenticated { username };
                            server.enqueue_status(
                                Status::ok(Some(tag), None, "UNSELECT complete")
                                    .expect("static ok"),
                            );
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in selected state")
                                    .expect("static no"),
                            );
                        }
                    },

                    // ENABLE (RFC 5161) — we acknowledge the command but activate no
                    // enableable capabilities in this implementation.
                    CommandBody::Enable { .. } => {
                        match ctx.state {
                            ImapState::Authenticated { .. } | ImapState::Selected { .. } => {
                                // Return empty * ENABLED list: no capabilities activated.
                                server.enqueue_data(Data::Enabled {
                                    capabilities: vec![],
                                });
                                server.enqueue_status(
                                    Status::ok(Some(tag), None, "ENABLE complete")
                                        .expect("static ok"),
                                );
                            }
                            _ => {
                                server.enqueue_status(
                                    Status::no(Some(tag), None, "Not in authenticated state")
                                        .expect("static no"),
                                );
                            }
                        }
                    }

                    // UID EXPUNGE (RFC 4315) — no-op with 0 messages.
                    CommandBody::ExpungeUid { .. } => match ctx.state {
                        ImapState::Selected { .. } => {
                            server.enqueue_status(
                                Status::ok(Some(tag), None, "UID EXPUNGE complete")
                                    .expect("static ok"),
                            );
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in selected state")
                                    .expect("static no"),
                            );
                        }
                    },

                    // MOVE (RFC 6851) — no-op with 0 messages; returns OK.
                    CommandBody::Move { .. } => match ctx.state {
                        ImapState::Selected { .. } => {
                            server.enqueue_status(
                                Status::ok(Some(tag), None, "MOVE complete").expect("static ok"),
                            );
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "Not in selected state")
                                    .expect("static no"),
                            );
                        }
                    },

                    // APPEND — not supported until article storage is wired.
                    CommandBody::Append { .. } => {
                        server.enqueue_status(
                            Status::no(Some(tag), None, "APPEND not yet supported")
                                .expect("static no"),
                        );
                    }

                    // Remaining commands (COPY, RENAME, …) are not yet implemented.
                    _ => {
                        server.enqueue_status(
                            Status::bad(
                                Some(tag),
                                None,
                                "Command not yet implemented in this server version",
                            )
                            .expect("static bad"),
                        );
                    }
                }
            }

            Event::CommandAuthenticateReceived {
                command_authenticate,
            } => {
                let tag = command_authenticate.tag;
                let mechanism = command_authenticate.mechanism;
                let initial_response = command_authenticate.initial_response;

                if !ctx.tls {
                    // RFC 3501: LOGINDISABLED means no authentication before TLS.
                    let no = Status::no(Some(tag), None, "LOGINDISABLED: authenticate over TLS")
                        .expect("static no");
                    server.authenticate_finish(no).ok();
                } else if let Some(username) = auth::handle_authenticate_start(
                    &mut server,
                    &ctx.config,
                    &mut ctx.auth_progress,
                    tag,
                    mechanism,
                    initial_response,
                ) {
                    ctx.state = ImapState::Authenticated { username };
                }
            }

            Event::AuthenticateDataReceived { authenticate_data } => {
                if let Some(username) = auth::handle_authenticate_data(
                    &mut server,
                    &ctx.config,
                    &mut ctx.auth_progress,
                    authenticate_data,
                ) {
                    ctx.state = ImapState::Authenticated { username };
                }
            }

            Event::IdleCommandReceived { tag } => match ctx.state {
                ImapState::Authenticated { .. } | ImapState::Selected { .. } => {
                    let ccr = CommandContinuationRequest::basic(None, "idling")
                        .expect("static CCR is valid");
                    if server.idle_accept(ccr).is_ok() {
                        ctx.idle_tag = Some(tag);
                    }
                }
                _ => {
                    let no = Status::no(Some(tag), None, "Not in authenticated state")
                        .expect("static no");
                    server.idle_reject(no).ok();
                }
            },

            Event::IdleDoneReceived => {
                if let Some(tag) = ctx.idle_tag.take() {
                    let ok = Status::Tagged(Tagged {
                        tag,
                        body: StatusBody {
                            kind: StatusKind::Ok,
                            code: None,
                            text: imap_next::imap_types::core::Text::try_from("IDLE terminated")
                                .expect("static text"),
                        },
                    });
                    server.enqueue_status(ok);
                } else {
                    warn!(peer = %ctx.peer, "unexpected IdleDoneReceived");
                }
            }
        }
    }

    info!(peer = %ctx.peer, "IMAP session ended");
}

/// Drive the event loop until the response identified by `target` has been sent.
///
/// All responses enqueued *before* `target` will be sent first (queue is FIFO),
/// so this flushes everything up to and including the target handle.
async fn drain_until(stream: &mut Stream, server: &mut Server, target: ResponseHandle) {
    loop {
        match stream.next(&mut *server).await {
            Ok(Event::ResponseSent { handle, .. }) if handle == target => break,
            Ok(_) => {}
            Err(e) => {
                debug!("drain error: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imap_state_not_authenticated_is_initial() {
        let state = ImapState::NotAuthenticated;
        assert_eq!(state, ImapState::NotAuthenticated);
    }

    #[test]
    fn imap_state_authenticated_stores_username() {
        let state = ImapState::Authenticated {
            username: "alice".into(),
        };
        assert!(
            matches!(state, ImapState::Authenticated { ref username, .. } if username == "alice")
        );
    }

    #[test]
    fn imap_state_selected_tracks_read_only() {
        let rw = ImapState::Selected {
            username: "alice".into(),
            mailbox: "comp.lang.rust".into(),
            read_only: false,
        };
        assert!(matches!(
            rw,
            ImapState::Selected {
                read_only: false,
                ..
            }
        ));

        let ro = ImapState::Selected {
            username: "alice".into(),
            mailbox: "comp.lang.rust".into(),
            read_only: true,
        };
        assert!(matches!(
            ro,
            ImapState::Selected {
                read_only: true,
                ..
            }
        ));
    }

    #[test]
    fn imap_state_logout() {
        let state = ImapState::Logout;
        assert_eq!(state, ImapState::Logout);
    }
}
