//! IMAP session state machine using the `imap-next` sans-I/O library.
//!
//! # Session lifecycle
//!
//! ```text
//! connect
//!   └─> NotAuthenticated  (greeting sent; STARTTLS advertised if TLS acceptor available)
//!           └─> [STARTTLS] ──> (TLS handshake) ──> NotAuthenticated (no greeting re-sent)
//!           └─> [AUTH=PLAIN / AUTH=LOGIN] ──> Authenticated
//!                   └─> [SELECT / EXAMINE]  ──> Selected(mailbox)
//!                           └─> [CLOSE / EXPUNGE] ──> Authenticated
//!   Any state ──> [LOGOUT] ──> Logout  (session ends)
//! ```

pub mod auth;
pub mod commands;
pub mod fetch;
pub mod mailbox;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use imap_next::{
    imap_types::{
        auth::AuthenticateData,
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
use tokio_rustls::{server::TlsStream, TlsAcceptor, TlsStream as TlsStreamEnum};
use tracing::{debug, info, warn};

use imap_types::extensions::enable::CapabilityEnable;

use crate::config::Config;

use auth::AuthProgress;
use fetch::{handle_fetch, handle_search, handle_store};
use mailbox::{
    handle_list, handle_namespace, handle_select, handle_status, list_mailbox_to_string,
    select_status_responses, select_untagged_data,
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

/// Maximum consecutive authentication failures before the session is closed.
const MAX_AUTH_FAILURES: u32 = 3;

/// Session context shared across command handlers.
pub struct SessionContext {
    pub pool: Arc<SqlitePool>,
    pub config: Arc<Config>,
    /// Credential store built from `config.auth.users` at session start.
    /// Shared via Arc so multiple sessions share the pre-computed dummy hash.
    pub credential_store: Arc<stoa_auth::CredentialStore>,
    pub peer: SocketAddr,
    /// Whether the transport is TLS (IMAPS or post-STARTTLS).
    pub tls: bool,
    /// TLS acceptor for STARTTLS upgrade on plain connections.
    /// `None` when the session is already TLS or when no TLS is configured.
    pub tls_acceptor: Option<Arc<TlsAcceptor>>,
    pub state: ImapState,
    /// In-progress multi-step authentication state.
    pub auth_progress: AuthProgress,
    /// Tag saved when IDLE is accepted; consumed on DONE to send the tagged OK.
    pub idle_tag: Option<Tag<'static>>,
    /// Count of consecutive authentication failures this session.  When this
    /// reaches [`MAX_AUTH_FAILURES`] the server sends BYE and closes the
    /// connection, preventing brute-force credential enumeration.
    pub auth_failures: u32,
    /// Whether the client has ENABLEd IMAP4rev2 semantics for this session.
    /// Set to true by the ENABLE handler; never reset to false.
    pub imap4rev2_enabled: bool,
}

/// Why the command loop exited.
enum LoopExit {
    /// Normal termination: LOGOUT, EOF, error, or idle timeout.
    Done,
    /// Client issued `STARTTLS`; the tagged OK has been flushed.
    ///
    /// The `server` state machine is intact (no greeting pending, all prior
    /// responses flushed).  The caller must perform the TLS handshake using
    /// `acceptor` on the raw TCP stream extracted from `stream`, then wrap the
    /// resulting TLS stream as a new `Stream::tls` and continue the session by
    /// passing the carried `server` and updated `ctx` to `run_command_loop`.
    StartTlsRequested {
        acceptor: Arc<TlsAcceptor>,
        tcp: TcpStream,
        server: Box<Server>,
        ctx: Box<SessionContext>,
    },
}

/// Entry point for a plain-text IMAP connection.
///
/// If `tls_acceptor` is `Some`, `STARTTLS` is advertised in `CAPABILITY`
/// responses and the session upgrades to TLS in-place when the client issues
/// `STARTTLS`.  If `None`, STARTTLS is not offered.
pub async fn run_session_plain(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
    credential_store: Arc<stoa_auth::CredentialStore>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) {
    let ctx = SessionContext {
        pool,
        config,
        credential_store,
        peer,
        tls: false,
        tls_acceptor,
        state: ImapState::NotAuthenticated,
        auth_progress: AuthProgress::None,
        idle_tag: None,
        auth_failures: 0,
        imap4rev2_enabled: false,
    };
    let server = build_server(&ctx);
    let imap_stream = Stream::insecure(stream);
    match run_command_loop(imap_stream, server, ctx).await {
        LoopExit::Done => {}
        LoopExit::StartTlsRequested {
            acceptor,
            tcp,
            server,
            mut ctx,
        } => {
            info!(peer = %peer, "STARTTLS: performing TLS handshake");
            match acceptor.accept(tcp).await {
                Ok(tls_stream) => {
                    // RFC 9051 §6.2.1: reset session state (no re-greeting).
                    ctx.tls = true;
                    ctx.tls_acceptor = None;
                    ctx.state = ImapState::NotAuthenticated;
                    ctx.auth_progress = AuthProgress::None;
                    ctx.idle_tag = None;
                    ctx.auth_failures = 0;
                    ctx.imap4rev2_enabled = false;
                    info!(peer = %peer, "STARTTLS: session resumed over TLS");
                    // Reuse the existing server (no greeting pending) with the
                    // new TLS stream.  Per RFC 9051 §6.2.1, no greeting is sent.
                    let tls_imap_stream = Stream::tls(TlsStreamEnum::Server(tls_stream));
                    match run_command_loop(tls_imap_stream, server, *ctx).await {
                        LoopExit::Done => {}
                        LoopExit::StartTlsRequested { .. } => {
                            warn!(peer = %peer, "unexpected STARTTLS exit after post-STARTTLS session");
                        }
                    }
                }
                Err(e) => {
                    warn!(peer = %peer, "STARTTLS: TLS handshake failed: {e}");
                }
            }
        }
    }
}

/// Entry point for an implicit-TLS IMAPS connection.
pub async fn run_session_tls(
    stream: TlsStream<TcpStream>,
    peer: SocketAddr,
    config: Arc<Config>,
    pool: Arc<SqlitePool>,
    credential_store: Arc<stoa_auth::CredentialStore>,
) {
    let ctx = SessionContext {
        pool,
        config,
        credential_store,
        peer,
        tls: true,
        tls_acceptor: None, // already TLS; STARTTLS is rejected with BAD
        state: ImapState::NotAuthenticated,
        auth_progress: AuthProgress::None,
        idle_tag: None,
        auth_failures: 0,
        imap4rev2_enabled: false,
    };
    let server = build_server(&ctx);
    // Wrap server-side TlsStream into the enum variant that imap-next expects.
    let imap_stream = Stream::tls(TlsStreamEnum::Server(stream));
    match run_command_loop(imap_stream, server, ctx).await {
        LoopExit::Done => {}
        // STARTTLS is always rejected on implicit-TLS sessions (ctx.tls = true),
        // so this arm is unreachable in correct operation.
        LoopExit::StartTlsRequested { .. } => {
            warn!(peer = %peer, "unexpected STARTTLS exit on implicit-TLS session");
        }
    }
}

/// Build a fresh `Server` with a greeting and the appropriate options.
fn build_server(ctx: &SessionContext) -> Box<Server> {
    // Clamp to u32::MAX - 1 so that max_command_size can always be set strictly larger
    // (imap-next requires max_literal_size < max_command_size, strict inequality).
    let max_lit = ctx
        .config
        .limits
        .max_literal_bytes
        .min((u32::MAX - 1) as u64) as u32;
    let cmd_cap = ctx
        .config
        .limits
        .max_command_size_bytes
        .min(u32::MAX as u64) as u32;
    let mut options = Options::default();
    options.max_literal_size = max_lit;
    options.max_command_size = cmd_cap.max(max_lit.saturating_add(1));
    let greeting =
        Greeting::ok(None, "IMAP4rev1 stoa-imap server ready").expect("static greeting is valid");
    Box::new(Server::new(options, greeting))
}

/// Core command dispatch loop.
///
/// Drives the `imap-next` state machine until the session ends (LOGOUT,
/// connection error, idle timeout) or until a STARTTLS upgrade is requested.
///
/// When called for a post-STARTTLS session the `server` carries no pending
/// greeting (the greeting was already sent and acknowledged on the plain leg).
/// The loop handles `GreetingSent` as a no-op for the initial plain/TLS session
/// and simply never sees it on the reused post-STARTTLS server.
async fn run_command_loop(
    mut stream: Stream,
    mut server: Box<Server>,
    mut ctx: SessionContext,
) -> LoopExit {
    info!(peer = %ctx.peer, tls = ctx.tls, "IMAP session started");

    loop {
        let idle_timeout = Duration::from_secs(ctx.config.limits.idle_timeout_secs);
        let event = match tokio::time::timeout(idle_timeout, stream.next(&mut *server)).await {
            Ok(Ok(ev)) => ev,
            Ok(Err(e)) => {
                debug!(peer = %ctx.peer, "IMAP session ended: {e}");
                return LoopExit::Done;
            }
            Err(_elapsed) => {
                // RFC 3501 §5.4: server may close idle connections with BYE.
                warn!(
                    peer = %ctx.peer,
                    idle_secs = ctx.config.limits.idle_timeout_secs,
                    "IMAP idle timeout; sending BYE"
                );
                let bye = server.enqueue_status(
                    Status::bye(None, "Idle timeout — connection closed")
                        .expect("static bye is valid"),
                );
                let _ = tokio::time::timeout(
                    Duration::from_secs(5),
                    drain_until(&mut stream, &mut server, bye),
                )
                .await;
                return LoopExit::Done;
            }
        };

        let mut should_disconnect = false;

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
                        let tls_available = ctx.tls_acceptor.is_some();
                        server.enqueue_data(commands::capability_data(ctx.tls, tls_available));
                        server.enqueue_status(commands::capability_ok(tag));
                    }

                    CommandBody::Noop => {
                        server.enqueue_status(commands::noop_ok(tag));
                    }

                    // RFC 9051 §6.2.1: STARTTLS upgrades the plain connection to TLS.
                    CommandBody::StartTLS => {
                        if ctx.tls {
                            // Already in TLS (IMAPS or post-STARTTLS).
                            server.enqueue_status(
                                Status::bad(Some(tag), None, "Already in TLS").expect("static bad"),
                            );
                        } else if !matches!(ctx.state, ImapState::NotAuthenticated) {
                            // RFC 9051 §6.2.1: STARTTLS only valid in Not-Authenticated.
                            server.enqueue_status(
                                Status::bad(
                                    Some(tag),
                                    None,
                                    "STARTTLS not permitted in authenticated state",
                                )
                                .expect("static bad"),
                            );
                        } else if let Some(acceptor) = ctx.tls_acceptor.take() {
                            // Send tagged OK then flush it before handing off.
                            let ok = server.enqueue_status(
                                Status::ok(Some(tag), None, "Begin TLS negotiation now")
                                    .expect("static ok"),
                            );
                            drain_until(&mut stream, &mut server, ok).await;
                            info!(peer = %ctx.peer, "STARTTLS: OK sent, handing off to TLS");
                            // Extract the raw TcpStream from the imap-next Stream.
                            // The `expose_stream` feature enables `From<Stream> for TcpStream`.
                            let tcp: TcpStream = stream.into();
                            return LoopExit::StartTlsRequested {
                                acceptor,
                                tcp,
                                server,
                                ctx: Box::new(ctx),
                            };
                        } else {
                            // tls_acceptor was None — STARTTLS not available.
                            server.enqueue_status(
                                Status::bad(Some(tag), None, "STARTTLS not available")
                                    .expect("static bad"),
                            );
                        }
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
                        return LoopExit::Done;
                    }

                    CommandBody::Select { mailbox, .. } => match ctx.state {
                        ImapState::Authenticated { ref username }
                        | ImapState::Selected { ref username, .. } => {
                            let username = username.clone();
                            match handle_select(&ctx.pool, tag, mailbox, false).await {
                                Ok(result) => {
                                    let mailbox_name = result.mailbox_name.clone();
                                    for d in select_untagged_data(ctx.imap4rev2_enabled) {
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
                                    for d in select_untagged_data(ctx.imap4rev2_enabled) {
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

                    // ENABLE (RFC 5161) — activate capabilities for this session.
                    // Currently only IMAP4rev2 is recognised; all others are
                    // silently ignored per RFC 5161 §3.2.
                    CommandBody::Enable { capabilities } => {
                        match ctx.state {
                            ImapState::Authenticated { .. } | ImapState::Selected { .. } => {
                                let mut newly_enabled: Vec<CapabilityEnable<'static>> = vec![];
                                for cap in capabilities.as_ref() {
                                    // WORKAROUND: CapabilityEnable has no Imap4Rev2 variant;
                                    // format!("{cap}") delegates to Atom::Display, giving the
                                    // original wire string for case-insensitive matching.
                                    // Replace with a typed match when duesee/imap-codec#702
                                    // ships a typed variant.
                                    let cap_str = format!("{cap}");
                                    if handle_enable(&cap_str, &mut ctx.imap4rev2_enabled) {
                                        // WORKAROUND: same as above — no typed variant yet.
                                        newly_enabled.push(
                                            CapabilityEnable::try_from("IMAP4rev2")
                                                .expect("IMAP4rev2 is a valid IMAP atom"),
                                        );
                                    }
                                }
                                server.enqueue_data(Data::Enabled {
                                    capabilities: newly_enabled,
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

                    // NAMESPACE (RFC 2342) — single personal namespace, no other/shared.
                    CommandBody::Namespace => match ctx.state {
                        ImapState::Authenticated { .. } | ImapState::Selected { .. } => {
                            server.enqueue_data(handle_namespace());
                            server.enqueue_status(
                                Status::ok(Some(tag), None, "NAMESPACE complete")
                                    .expect("static ok status cannot fail"),
                            );
                        }
                        _ => {
                            server.enqueue_status(
                                Status::no(Some(tag), None, "not authenticated")
                                    .expect("static no status cannot fail"),
                            );
                        }
                    },

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
                    ctx.auth_failures += 1;
                    if ctx.auth_failures >= MAX_AUTH_FAILURES {
                        should_disconnect = true;
                    }
                } else if let Some(username) = auth::handle_authenticate_start(
                    &mut server,
                    &ctx.credential_store,
                    &mut ctx.auth_progress,
                    tag,
                    mechanism,
                    initial_response,
                )
                .await
                {
                    ctx.auth_failures = 0;
                    ctx.state = ImapState::Authenticated { username };
                } else if matches!(ctx.auth_progress, AuthProgress::None) {
                    // handle_authenticate_start returned None without setting a
                    // continuation state: auth failed outright (unsupported
                    // mechanism or credential rejection), not a multi-step
                    // exchange in progress.
                    ctx.auth_failures += 1;
                    if ctx.auth_failures >= MAX_AUTH_FAILURES {
                        should_disconnect = true;
                    }
                }
            }

            Event::AuthenticateDataReceived { authenticate_data } => {
                // RFC 9051 §9.1: a client-initiated cancel ('*') must not be
                // counted as a failed authentication attempt.  Distinguish
                // cancel from credential rejection before consuming the value.
                let is_cancel = matches!(authenticate_data, AuthenticateData::Cancel);
                if let Some(username) = auth::handle_authenticate_data(
                    &mut server,
                    &ctx.credential_store,
                    &mut ctx.auth_progress,
                    authenticate_data,
                )
                .await
                {
                    ctx.auth_failures = 0;
                    ctx.state = ImapState::Authenticated { username };
                } else if !is_cancel {
                    // Bad credentials — count toward the lockout threshold.
                    ctx.auth_failures += 1;
                    if ctx.auth_failures >= MAX_AUTH_FAILURES {
                        should_disconnect = true;
                    }
                }
                // Client-initiated cancel: no failure counted (RFC 9051 §9.1).
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

        if should_disconnect {
            warn!(
                peer = %ctx.peer,
                failures = ctx.auth_failures,
                "IMAP auth failure limit reached; sending BYE"
            );
            let bye = server.enqueue_status(
                Status::bye(None, "Too many authentication failures").expect("static bye is valid"),
            );
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                drain_until(&mut stream, &mut server, bye),
            )
            .await;
            return LoopExit::Done;
        }
    }
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

/// Process a single capability name from an ENABLE command.
///
/// Returns `true` if the capability was newly activated this call.
/// Returns `false` if it was already active or is unrecognised.
///
/// Per RFC 5161 §3: unknown capabilities are silently ignored; already-active
/// capabilities are not re-listed in the `* ENABLED` response.
pub(crate) fn handle_enable(cap: &str, imap4rev2_enabled: &mut bool) -> bool {
    if cap.eq_ignore_ascii_case("IMAP4rev2") && !*imap4rev2_enabled {
        *imap4rev2_enabled = true;
        return true;
    }
    false
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

    // ── max_command_size security tests ──────────────────────────────────────
    //
    // Oracle: imap-next-0.3.4/src/server.rs
    //
    // The library's `Options::max_command_size` is a public `u32`.  When the
    // accumulated bytes for a single command cross that threshold the
    // `Fragmentizer` marks the message as too long; `ReceiveState::next`
    // returns `ReceiveError::MessageTooLong`; `handle_receive_interrupt` maps
    // that to `Interrupt::Error(Error::CommandTooLong { discarded_bytes })`.
    // The library does NOT close the connection — it returns the error to the
    // caller.  Our session loop (`run_command_loop`) treats any `Err` as a
    // terminal condition and breaks, so the connection is dropped.
    //
    // The library's own `Default` for `max_command_size` is
    // `(25 * 1024 * 1024) + (64 * 1024)` (~25 MiB).  That is far too large
    // for a command line (which never legitimately exceeds ~8 KiB).  The fix
    // under test must override this default from the operator config before
    // passing `Options` to `Server::new`.

    /// The library default for `Options::max_command_size` is ~25 MiB.
    /// We document this so Agent I's fix is clearly necessary: a session
    /// constructed with `Options::default()` and NO override would silently
    /// allow ~25 MiB command lines.
    #[test]
    fn library_default_max_command_size_is_dangerously_large() {
        // Oracle: imap-next-0.3.4/src/server.rs lines 59-60
        //   max_command_size: (25 * 1024 * 1024) + (64 * 1024),
        let opts = Options::default();
        // 25 MiB + 64 KiB — confirm the library ships with this value.
        assert_eq!(
            opts.max_command_size,
            (25 * 1024 * 1024) + (64 * 1024),
            "library default must match oracle value; update test if upstream changes"
        );
        // The fix must replace this; any value above 64 KiB for a pure
        // command line (no inline literal) is unreasonably large.
        assert!(
            opts.max_command_size > 65_536,
            "library default ({} bytes) exceeds a safe command-line limit; \
             the session setup MUST override this field",
            opts.max_command_size
        );
    }

    /// The operator config default for `max_command_size_bytes` must be
    /// bounded: the `LimitsConfig` default is 8 KiB, well under 64 KiB.
    #[test]
    fn config_default_max_command_size_is_bounded() {
        let limits = crate::config::LimitsConfig::default();
        // Oracle: config.rs `default_max_command_size_bytes()` returns 8 * 1024.
        assert_eq!(limits.max_command_size_bytes, 8 * 1024);
        // Must be under 64 KiB — that is the ceiling for any sane command line.
        assert!(
            limits.max_command_size_bytes <= 65_536,
            "config default max_command_size_bytes ({} bytes) must be <= 65536",
            limits.max_command_size_bytes
        );
    }

    /// Feeding a command line that exceeds `max_command_size` to the
    /// `imap-next` sans-I/O `Server` must produce
    /// `Interrupt::Error(Error::CommandTooLong { .. })`.
    ///
    /// This exercises the library at the sans-I/O layer — no real socket
    /// needed.  The greeting is emitted first (requires draining one
    /// `Interrupt::Io(Io::Output(...))` cycle), then an oversized command
    /// line is fed and the next `next()` call must return `CommandTooLong`.
    #[test]
    fn oversized_command_line_yields_command_too_long_error() {
        use imap_next::{
            server::{Error, Options},
            Interrupt, Io, State,
        };

        // Build a Server with a deliberately small max_command_size.
        // 256 bytes is small enough that a 300-byte command line will always
        // exceed it while still being easy to construct.
        let mut opts = Options::default();
        opts.max_command_size = 256;
        // max_literal_size must be < max_command_size (library invariant).
        opts.max_literal_size = 128;

        let greeting =
            imap_next::imap_types::response::Greeting::ok(None, "test server ready").unwrap();
        let mut server = imap_next::server::Server::new(opts, greeting);

        // Drain the greeting output event.  The library starts by wanting to
        // send the greeting bytes; we must cycle through
        // `Interrupt::Io(Io::Output(_))` until it emits `GreetingSent`.
        // Because we are sans-I/O we simply keep calling `next()` until we
        // see either GreetingSent or a NeedMoreInput stop.
        loop {
            match server.next() {
                Ok(imap_next::server::Event::GreetingSent { .. }) => break,
                Ok(_) => {}
                Err(Interrupt::Io(Io::Output(_))) => {
                    // Simulated write: pretend bytes are flushed, loop again.
                }
                Err(Interrupt::Io(Io::NeedMoreInput)) => {
                    // Greeting is fully sent; library now waits for input.
                    break;
                }
                Err(Interrupt::Error(e)) => {
                    panic!("unexpected error draining greeting: {e:?}");
                }
            }
        }

        // Construct a command line that exceeds max_command_size (256).
        // Use a syntactically valid-looking IMAP tag + NOOP padded with
        // spaces so the total including CRLF is > 256 bytes.
        // We do NOT need the parser to accept it — the size check fires first.
        let oversized: Vec<u8> = {
            let mut v = Vec::with_capacity(300);
            v.extend_from_slice(b"A001 NOOP ");
            v.extend(std::iter::repeat(b'X').take(280));
            v.extend_from_slice(b"\r\n");
            v
        };
        assert!(
            oversized.len() > 256,
            "test setup: command must exceed max_command_size"
        );

        server.enqueue_input(&oversized);

        // Oracle: imap-next-0.3.4/src/server.rs `handle_receive_interrupt`:
        //   ReceiveError::MessageTooLong => Interrupt::Error(Error::CommandTooLong { .. })
        let mut got_too_long = false;
        for _ in 0..20 {
            match server.next() {
                Err(Interrupt::Error(Error::CommandTooLong { .. })) => {
                    got_too_long = true;
                    break;
                }
                Err(Interrupt::Io(Io::Output(_))) => {
                    // Drain any buffered output (e.g. greeting bytes if not
                    // yet flushed in this environment).
                }
                Err(Interrupt::Io(Io::NeedMoreInput)) => {
                    // Should not happen: we already fed the oversized line.
                    panic!("server requested more input after oversized command was enqueued");
                }
                Ok(ev) => {
                    // Any decoded event before CommandTooLong would mean the
                    // command was accepted — that is the failure case.
                    panic!("server emitted event instead of CommandTooLong: {ev:?}");
                }
                Err(Interrupt::Error(other)) => {
                    panic!("unexpected error (expected CommandTooLong): {other:?}");
                }
            }
        }

        assert!(
            got_too_long,
            "server must return CommandTooLong for a command line exceeding max_command_size"
        );
    }

    /// A normal-sized command (well under any reasonable max_command_size)
    /// must NOT trigger CommandTooLong.  This guards against accidentally
    /// setting max_command_size so small that legitimate commands are rejected.
    #[test]
    fn normal_command_is_not_rejected_by_size_limit() {
        use imap_next::{server::Options, Interrupt, Io, State};

        // 8 KiB limit — matches the stoa config default.
        let mut opts = Options::default();
        opts.max_command_size = 8 * 1024;
        opts.max_literal_size = 4 * 1024;

        let greeting =
            imap_next::imap_types::response::Greeting::ok(None, "test server ready").unwrap();
        let mut server = imap_next::server::Server::new(opts, greeting);

        // Drain greeting.
        loop {
            match server.next() {
                Ok(imap_next::server::Event::GreetingSent { .. }) => break,
                Ok(_) => {}
                Err(Interrupt::Io(Io::Output(_))) => {}
                Err(Interrupt::Io(Io::NeedMoreInput)) => break,
                Err(Interrupt::Error(e)) => {
                    panic!("unexpected error draining greeting: {e:?}");
                }
            }
        }

        // A minimal, valid NOOP command — 13 bytes including CRLF.
        server.enqueue_input(b"A001 NOOP\r\n");

        let mut got_command = false;
        for _ in 0..20 {
            match server.next() {
                Ok(imap_next::server::Event::CommandReceived { .. }) => {
                    got_command = true;
                    break;
                }
                Ok(_) => {}
                Err(Interrupt::Io(Io::Output(_))) => {}
                Err(Interrupt::Io(Io::NeedMoreInput)) => break,
                Err(Interrupt::Error(e)) => {
                    panic!("normal NOOP must not produce an error: {e:?}");
                }
            }
        }

        assert!(
            got_command,
            "a short, valid NOOP command must be received without error"
        );
    }

    // ── ENABLE (RFC 5161) logic tests ─────────────────────────────────────────
    //
    // Oracle: RFC 5161 §3, RFC 9051 §6.3.2.
    //
    // RFC 5161 §3: "The ENABLED response MUST list only capabilities that were
    // newly enabled as a result of this ENABLE command.  The server MUST NOT
    // list capabilities that were already enabled before this ENABLE was
    // received."
    //
    // RFC 5161 §3: "Unknown capabilities are silently ignored."
    //
    // RFC 9051 §6.3.2: "ENABLE IMAP4rev2" activates IMAP4rev2 semantics as a
    // one-way latch; once set it MUST NOT be unset for the lifetime of the
    // session.
    //
    // Tests 1–3 directly manipulate the `imap4rev2_enabled` field (which
    // already exists on `SessionContext`) and call `handle_enable()`, the
    // function that drrd.9 adds to session/mod.rs.  Until drrd.9 is complete,
    // these tests will not compile — that is expected.
    //
    // Test 4 verifies the state-guard logic using only already-existing types
    // and compiles right now.

    /// RFC 5161 §3 + RFC 9051 §6.3.2: when `imap4rev2_enabled` is false and
    /// the client sends ENABLE IMAP4rev2, the latch must flip to true and
    /// IMAP4rev2 must appear in the newly-enabled list.
    #[test]
    fn enable_imap4rev2_sets_latch() {
        let mut imap4rev2_enabled = false;
        // `handle_enable` is added by drrd.9.  Signature:
        //   pub fn handle_enable(cap: &str, enabled: &mut bool) -> bool
        // Returns true iff the capability was newly activated this call.
        let newly_enabled = handle_enable("IMAP4rev2", &mut imap4rev2_enabled);
        assert!(
            imap4rev2_enabled,
            "imap4rev2_enabled must be true after ENABLE IMAP4rev2 (RFC 9051 §6.3.2)"
        );
        assert!(
            newly_enabled,
            "IMAP4rev2 must be in the newly-enabled list when it was not yet active (RFC 5161 §3)"
        );
    }

    /// RFC 5161 §3: if IMAP4rev2 is already latched, a second ENABLE IMAP4rev2
    /// must NOT include it in the newly-enabled list.  The latch stays true.
    #[test]
    fn enable_imap4rev2_is_idempotent() {
        let mut imap4rev2_enabled = true; // already active
        let newly_enabled = handle_enable("IMAP4rev2", &mut imap4rev2_enabled);
        assert!(
            imap4rev2_enabled,
            "one-way latch must never revert to false (RFC 9051 §6.3.2)"
        );
        assert!(
            !newly_enabled,
            "already-active capability must NOT appear in newly-enabled list (RFC 5161 §3)"
        );
    }

    /// RFC 5161 §3: an unrecognised capability name must be silently ignored;
    /// no state changes, no error, no panic.
    #[test]
    fn enable_unknown_cap_is_ignored() {
        let mut imap4rev2_enabled = false;
        let newly_enabled = handle_enable("UNKNOWNCAP", &mut imap4rev2_enabled);
        assert!(
            !imap4rev2_enabled,
            "imap4rev2_enabled must not be set when an unrecognised capability is named"
        );
        assert!(
            !newly_enabled,
            "unrecognised capability must not appear in newly-enabled list (RFC 5161 §3)"
        );
    }

    /// RFC 5161 §3: ENABLE is only valid in Authenticated or Selected state.
    /// In NotAuthenticated state the dispatch layer sends NO and skips the
    /// latch entirely.  This test documents the state-guard predicate.
    ///
    /// Note: this test uses only already-existing types and compiles before
    /// drrd.9 is complete.
    #[test]
    fn enable_is_refused_in_not_authenticated_state() {
        // The session loop guards the ENABLE handler with:
        //   ImapState::Authenticated { .. } | ImapState::Selected { .. }
        // Anything else must produce a tagged NO without touching the latch.
        let state = ImapState::NotAuthenticated;
        let guard_passes = matches!(
            state,
            ImapState::Authenticated { .. } | ImapState::Selected { .. }
        );
        assert!(
            !guard_passes,
            "ENABLE state guard must reject NotAuthenticated; the latch must not be touched"
        );
    }

    /// `Data::Enabled` with an empty capability list must encode to the
    /// correct wire bytes per RFC 5161 §3 ABNF:
    ///   enable-data = "*" SP "ENABLED" *(SP capability) CRLF
    /// An empty newly-enabled list encodes as "* ENABLED\r\n".
    ///
    /// Oracle: RFC 5161 §3; verified manually against the imap-codec encoder.
    /// This test compiles and runs right now (no drrd.9 code required).
    #[test]
    fn data_enabled_empty_list_wire_encoding() {
        use imap_codec::{encode::Encoder, ResponseCodec};
        use imap_next::imap_types::response::{Data, Response};

        let data: Data<'static> = Data::Enabled {
            capabilities: vec![],
        };
        let response = Response::Data(data);
        let bytes: Vec<u8> = ResponseCodec::default().encode(&response).dump();
        assert!(
            bytes.windows(b"ENABLED".len()).any(|w| w == b"ENABLED"),
            "wire encoding must contain ENABLED keyword; got: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        // Empty list: nothing after "ENABLED" except CRLF.
        assert!(
            bytes.ends_with(b"ENABLED\r\n"),
            "empty ENABLED list must end with b\"ENABLED\\r\\n\"; got: {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
}
