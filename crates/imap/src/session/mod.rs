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
//!
//! Command handlers for AUTH, SELECT, FETCH, etc. are added in later waves
//! (r8u.6 – r8u.17).  The skeleton here handles the event loop, sends the
//! greeting, and returns BAD for any command not yet implemented.

use std::{net::SocketAddr, sync::Arc};

use imap_next::{
    imap_types::{
        command::CommandBody,
        response::{Greeting, Status},
    },
    server::{Event, Options, Server},
    stream::Stream,
};
use sqlx::SqlitePool;
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsStream as TlsStreamEnum};
use tracing::{debug, info, warn};

use crate::config::Config;

/// IMAP session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapState {
    NotAuthenticated,
    Authenticated { username: String },
    Selected { username: String, mailbox: String, read_only: bool },
    Logout,
}

/// Session context shared across command handlers.
pub struct SessionContext {
    pub pool: Arc<SqlitePool>,
    pub config: Arc<Config>,
    pub peer: SocketAddr,
    pub tls: bool,
    pub state: ImapState,
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
    options.max_literal_size =
        ctx.config.limits.max_literal_bytes.min(u32::MAX as u64) as u32;
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
                // Completion tracking per-handle is added in later waves.
            }

            Event::CommandReceived { command } => {
                let tag = command.tag;
                match command.body {
                    CommandBody::Logout => {
                        // RFC 3501 §6.1.3: send untagged BYE, then tagged OK.
                        server.enqueue_status(
                            Status::bye(None, "Logging out").expect("static bye is valid"),
                        );
                        server.enqueue_status(
                            Status::ok(Some(tag), None, "LOGOUT completed")
                                .expect("static ok is valid"),
                        );
                        ctx.state = ImapState::Logout;
                        drain_responses(&mut stream, &mut server).await;
                        break;
                    }

                    // All other commands are handled in later waves (r8u.6 – r8u.17).
                    _ => {
                        server.enqueue_status(
                            Status::bad(
                                Some(tag),
                                None,
                                "Command not yet implemented in this server version",
                            )
                            .expect("static bad is valid"),
                        );
                    }
                }
            }

            Event::CommandAuthenticateReceived { command_authenticate } => {
                // AUTH handling is added in r8u.7 / r8u.8.
                // Must call authenticate_finish to unblock the state machine.
                let no = Status::no(
                    Some(command_authenticate.tag),
                    None,
                    "Authentication not yet implemented",
                )
                .expect("static no is valid");
                server.authenticate_finish(no).ok();
            }

            Event::AuthenticateDataReceived { .. } => {
                // Should not arrive here: we call authenticate_finish without
                // calling authenticate_continue.
                warn!(peer = %ctx.peer, "unexpected AuthenticateDataReceived");
            }

            Event::IdleCommandReceived { tag } => {
                // IDLE handling is added in r8u.16.
                let no = Status::no(Some(tag), None, "IDLE not yet implemented")
                    .expect("static no is valid");
                server.idle_reject(no).ok();
            }

            Event::IdleDoneReceived => {
                warn!(peer = %ctx.peer, "unexpected IdleDoneReceived");
            }
        }
    }

    info!(peer = %ctx.peer, "IMAP session ended");
}

/// Drive the event loop until all queued responses have been sent.
async fn drain_responses(stream: &mut Stream, server: &mut Server) {
    loop {
        match stream.next(&mut *server).await {
            Ok(Event::ResponseSent { .. }) => break,
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
        let state = ImapState::Authenticated { username: "alice".into() };
        assert!(matches!(state, ImapState::Authenticated { ref username, .. } if username == "alice"));
    }

    #[test]
    fn imap_state_selected_tracks_read_only() {
        let rw = ImapState::Selected {
            username: "alice".into(),
            mailbox: "comp.lang.rust".into(),
            read_only: false,
        };
        assert!(matches!(rw, ImapState::Selected { read_only: false, .. }));

        let ro = ImapState::Selected {
            username: "alice".into(),
            mailbox: "comp.lang.rust".into(),
            read_only: true,
        };
        assert!(matches!(ro, ImapState::Selected { read_only: true, .. }));
    }

    #[test]
    fn imap_state_logout() {
        let state = ImapState::Logout;
        assert_eq!(state, ImapState::Logout);
    }
}
