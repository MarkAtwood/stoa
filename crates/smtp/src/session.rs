use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use mail_auth::MessageAuthenticator;
use sqlx::SqlitePool;
use stoa_auth::CredentialStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use stoa_core::util::epoch_to_rfc2822;

use stoa_core::InjectionSource;

use crate::auth::verify_inbound;
use crate::config::Config;
use crate::metrics::{
    SMTP_CONNECTIONS_TOTAL, SMTP_DATA_BYTES_TOTAL, SMTP_MESSAGES_ACCEPTED_TOTAL,
    SMTP_MESSAGES_REJECTED_TOTAL,
};
use crate::queue::NntpQueue;
use crate::{routing, store};

/// Thread-safe cache of compiled Sieve scripts, keyed by username.
///
/// Scripts are compiled on first use and retained until the sieve admin API
/// explicitly invalidates the entry (on script PUT, DELETE, or activate).
/// This avoids recompiling the same script for every inbound message.
pub type SieveCache = Arc<Mutex<HashMap<String, Arc<stoa_sieve_native::CompiledScript>>>>;

/// Create a new, empty [`SieveCache`].
pub fn new_sieve_cache() -> SieveCache {
    Arc::new(Mutex::new(HashMap::new()))
}

const MAX_LINE_BYTES: usize = 4096;

/// Result of reading one SMTP command line.
enum CmdLine {
    /// A complete line, including the trailing `\n`.
    Line(String),
    /// Client closed the connection (EOF) before a full line arrived.
    Eof,
    /// The line exceeded `MAX_LINE_BYTES`.  The remainder has been drained.
    TooLong,
    /// No data was received within the configured command timeout.
    Timeout,
}

/// Read one SMTP command line with length and timeout enforcement.
///
/// Reads byte-by-byte via the `BufReader` internal buffer — no extra syscall
/// per byte because `BufReader` fills its buffer in chunks.  Returns when
/// `\n` is found, the byte limit is exceeded (and drained), the timeout
/// fires, or EOF.
async fn read_command_line<R>(
    reader: &mut BufReader<R>,
    max_bytes: usize,
    timeout_secs: u64,
) -> CmdLine
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        let mut buf: Vec<u8> = Vec::with_capacity(128);
        let mut byte = [0u8; 1];
        loop {
            match reader.read(&mut byte).await {
                Ok(0) | Err(_) => return CmdLine::Eof,
                Ok(_) => {
                    buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        return CmdLine::Line(String::from_utf8_lossy(&buf).into_owned());
                    }
                    if buf.len() > max_bytes {
                        // Line is too long — drain the rest without buffering
                        // so the session can send 500 and remain coherent.
                        loop {
                            match reader.read(&mut byte).await {
                                Ok(0) | Err(_) => return CmdLine::Eof,
                                Ok(_) if byte[0] == b'\n' => return CmdLine::TooLong,
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(CmdLine::Timeout)
}

#[derive(Debug)]
enum SessionState {
    Fresh,
    Greeted {
        ehlo_domain: String,
    },
    Mail {
        ehlo_domain: String,
        from: String,
    },
    Rcpt {
        ehlo_domain: String,
        from: String,
        to: Vec<String>,
    },
}

#[allow(clippy::too_many_arguments)]
/// Run a complete RFC 5321 SMTP session on the given stream.
///
/// `stream` may be a plain `TcpStream` (ports 25 / 587) or a TLS-wrapped
/// stream (port 465 SMTPS).  The generic bound keeps this zero-cost while
/// allowing both stream types without boxing.
///
/// `is_tls` records whether the session was accepted on the implicit-TLS
/// SMTPS listener.  AUTH PLAIN is only advertised and accepted when
/// `is_tls = true` to prevent credentials from being sent in the clear.
///
/// `credential_store` is the pre-built store used to verify AUTH PLAIN
/// credentials.  Built once at startup from `config.auth` and shared across
/// sessions.
///
/// `auth` is optional: when `Some`, every accepted message is passed through
/// the SPF/DKIM/DMARC/ARC pipeline before enqueuing.  When `None` the message
/// is enqueued without authentication (suitable for loopback submission or
/// unit tests).
///
/// `pool` is optional: when `Some` and `config.users` is non-empty, non-list
/// messages are delivered inline via per-user Sieve scripts instead of being
/// forwarded through the message queue.
pub async fn run_session<S>(
    stream: S,
    is_tls: bool,
    peer_addr: String,
    config: Arc<Config>,
    credential_store: Arc<CredentialStore>,
    nntp_queue: Arc<NntpQueue>,
    auth: Option<Arc<MessageAuthenticator>>,
    pool: Option<SqlitePool>,
    sieve_cache: Option<SieveCache>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    SMTP_CONNECTIONS_TOTAL.inc();

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let greeting = format!("220 {} ESMTP stoa-smtp\r\n", config.hostname);
    if write_half.write_all(greeting.as_bytes()).await.is_err() {
        return;
    }

    // Parse the peer IP once; fall back to loopback if unparseable.
    let client_ip: IpAddr = peer_addr
        .parse::<std::net::SocketAddr>()
        .map(|sa| sa.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));

    let mut state = SessionState::Fresh;
    let mut authenticated_user: Option<String> = None;

    loop {
        let line_buf = match read_command_line(
            &mut reader,
            MAX_LINE_BYTES,
            config.limits.command_timeout_secs,
        )
        .await
        {
            CmdLine::Line(s) => s,
            CmdLine::Eof => {
                debug!(peer = %peer_addr, "client disconnected");
                break;
            }
            CmdLine::TooLong => {
                let _ = write_half.write_all(b"500 Line too long\r\n").await;
                break;
            }
            CmdLine::Timeout => {
                // RFC 5321 §4.2: use 421 when closing due to timeout.
                let _ = write_half
                    .write_all(b"421 4.4.2 Timeout - closing connection\r\n")
                    .await;
                break;
            }
        };

        // Strip trailing CRLF or LF.
        let line = line_buf.trim_end_matches(['\r', '\n']);
        debug!(peer = %peer_addr, cmd = %line, "received");

        // Split verb from arguments (verb is the first whitespace-delimited token).
        let (verb, args) = match line.split_once(|c: char| c.is_ascii_whitespace()) {
            Some((v, a)) => (v.to_ascii_uppercase(), a.trim()),
            None => (line.to_ascii_uppercase(), ""),
        };

        match verb.as_str() {
            "EHLO" => {
                // Reject EHLO arguments containing CR, LF, or NUL: these
                // would allow header injection into the Received: trace we
                // prepend at DATA time.  Per RFC 5321 §4.1.1.1 the domain
                // argument must be a valid hostname or address literal.
                if args.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
                    if write_half
                        .write_all(b"501 5.5.2 Syntax error in parameters\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                // STARTTLS is not advertised here because the upgrade path is
                // not yet implemented (stoa-ryw.3).  Advertising an
                // extension we cannot complete causes MTAs that enforce
                // STARTTLS-policy to fail delivery with a confusing error.
                //
                // AUTH PLAIN is advertised only on SMTPS (is_tls=true) to
                // prevent credentials from being sent over a cleartext
                // connection.
                let auth_line = if is_tls && !credential_store.is_empty() {
                    "250-AUTH PLAIN\r\n"
                } else {
                    ""
                };
                let resp = format!(
                    "250-{}\r\n250-SIZE {}\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-PIPELINING\r\n{}250 OK\r\n",
                    config.hostname, config.limits.max_message_bytes, auth_line
                );
                if write_half.write_all(resp.as_bytes()).await.is_err() {
                    break;
                }
                state = SessionState::Greeted {
                    ehlo_domain: args.to_string(),
                };
            }

            "HELO" => {
                if args.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
                    if write_half
                        .write_all(b"501 5.5.2 Syntax error in parameters\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let resp = format!("250 {}\r\n", config.hostname);
                if write_half.write_all(resp.as_bytes()).await.is_err() {
                    break;
                }
                state = SessionState::Greeted {
                    ehlo_domain: args.to_string(),
                };
            }

            "AUTH" => {
                // RFC 4954 §4: AUTH is only accepted on a TLS-protected
                // connection.  On cleartext sessions reject with 534 to
                // prevent credentials from being sent in the clear.
                if !is_tls {
                    if write_half
                        .write_all(
                            b"534 5.7.9 Encryption required for requested authentication mechanism\r\n",
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                if authenticated_user.is_some() {
                    if write_half
                        .write_all(b"503 5.5.1 Already authenticated\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                // Only SASL PLAIN is supported.
                let mechanism_upper = args.to_ascii_uppercase();
                if mechanism_upper == "PLAIN" || mechanism_upper.starts_with("PLAIN ") {
                    let initial_response = if args.len() > 5 { args[5..].trim() } else { "" };
                    let b64 = if initial_response.is_empty() {
                        // Two-step: send empty challenge, read response.
                        if write_half.write_all(b"334 \r\n").await.is_err() {
                            break;
                        }
                        match read_command_line(
                            &mut reader,
                            MAX_LINE_BYTES,
                            config.limits.command_timeout_secs,
                        )
                        .await
                        {
                            CmdLine::Line(s) => s.trim_end_matches(['\r', '\n']).to_string(),
                            _ => {
                                let _ = write_half
                                    .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                                    .await;
                                break;
                            }
                        }
                    } else {
                        initial_response.to_string()
                    };
                    match verify_sasl_plain(&credential_store, &b64).await {
                        Some(username) => {
                            info!(peer = %peer_addr, %username, "AUTH PLAIN succeeded");
                            authenticated_user = Some(username);
                            if write_half
                                .write_all(b"235 2.7.0 Authentication successful\r\n")
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        None => {
                            warn!(peer = %peer_addr, "AUTH PLAIN failed");
                            if write_half
                                .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                } else {
                    if write_half
                        .write_all(b"504 5.5.4 Unrecognized authentication type\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }

            "MAIL" => {
                // Must be in Greeted state.
                let ehlo_domain = match &state {
                    SessionState::Greeted { ehlo_domain } => ehlo_domain.clone(),
                    _ => {
                        if write_half
                            .write_all(b"503 Bad sequence of commands\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                // RFC 4954 §6: when AUTH is configured, require it before
                // accepting MAIL FROM.  Without this check any unauthenticated
                // client can relay mail through the submission port.
                if !credential_store.is_empty() && authenticated_user.is_none() {
                    if write_half
                        .write_all(b"530 5.7.0 Authentication required\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let from = parse_angle_addr(args);
                if write_half.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
                state = SessionState::Mail { ehlo_domain, from };
            }

            "RCPT" => {
                let to_addr = parse_angle_addr(args);

                match state {
                    SessionState::Mail {
                        ref ehlo_domain,
                        ref from,
                    } => {
                        // Always reject unknown recipients; empty users list rejects all.
                        let known = config
                            .users
                            .iter()
                            .any(|u| u.email.eq_ignore_ascii_case(&to_addr));
                        if !known {
                            if write_half
                                .write_all(b"550 5.1.1 User not found\r\n")
                                .await
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                        let ehlo_domain = ehlo_domain.clone();
                        let from_clone = from.clone();
                        if write_half.write_all(b"250 OK\r\n").await.is_err() {
                            break;
                        }
                        state = SessionState::Rcpt {
                            ehlo_domain,
                            from: from_clone,
                            to: vec![to_addr],
                        };
                    }
                    SessionState::Rcpt { ref mut to, .. } => {
                        // Always reject unknown recipients; empty users list rejects all.
                        let known = config
                            .users
                            .iter()
                            .any(|u| u.email.eq_ignore_ascii_case(&to_addr));
                        if !known {
                            if write_half
                                .write_all(b"550 5.1.1 User not found\r\n")
                                .await
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                        if to.len() >= config.limits.max_recipients {
                            if write_half
                                .write_all(b"452 Too many recipients\r\n")
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else {
                            to.push(to_addr);
                            if write_half.write_all(b"250 OK\r\n").await.is_err() {
                                break;
                            }
                        }
                    }
                    _ => {
                        if write_half
                            .write_all(b"503 Bad sequence of commands\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }

            "DATA" => {
                // Must be in Rcpt state with at least one recipient.
                let (ehlo_domain, from, to) = match state {
                    SessionState::Rcpt {
                        ref ehlo_domain,
                        ref from,
                        ref to,
                    } if !to.is_empty() => (ehlo_domain.clone(), from.clone(), to.clone()),
                    _ => {
                        if write_half
                            .write_all(b"503 Bad sequence of commands\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };

                if write_half
                    .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .await
                    .is_err()
                {
                    break;
                }

                // Read dot-terminated message body (with timeout).
                let max_bytes = config.limits.max_message_bytes;
                let data_result = tokio::time::timeout(
                    Duration::from_secs(config.limits.command_timeout_secs),
                    read_data_body(&mut reader, max_bytes),
                )
                .await;
                let (mut raw_bytes, too_large) = match data_result {
                    Ok(result) => result,
                    Err(_) => {
                        let _ = write_half
                            .write_all(b"421 4.4.2 Timeout - closing connection\r\n")
                            .await;
                        break;
                    }
                };

                if too_large {
                    SMTP_MESSAGES_REJECTED_TOTAL
                        .with_label_values(&["size"])
                        .inc();
                    if write_half
                        .write_all(b"552 Message too large\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    state = SessionState::Greeted { ehlo_domain };
                    continue;
                }

                // Run the inbound authentication pipeline if an authenticator
                // is configured.  On DMARC reject the session sends 550 and
                // resets to Greeted (the TCP connection stays open per RFC 5321
                // §6.1 — a 5xx on DATA is not a reason to terminate).
                if let Some(ref authenticator) = auth {
                    let result = verify_inbound(
                        authenticator,
                        &raw_bytes,
                        client_ip,
                        &ehlo_domain,
                        &from,
                        &config.hostname,
                    )
                    .await;

                    if result.dmarc_reject {
                        warn!(
                            peer = %peer_addr,
                            from = %from,
                            "DMARC reject policy applied — rejecting message"
                        );
                        SMTP_MESSAGES_REJECTED_TOTAL
                            .with_label_values(&["policy"])
                            .inc();
                        if write_half
                            .write_all(b"550 5.7.1 Message rejected due to DMARC policy\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                        state = SessionState::Greeted { ehlo_domain };
                        continue;
                    }

                    // Prepend Authentication-Results header to the message.
                    // Rotate in-place to avoid a second full-body allocation.
                    let header_bytes =
                        format!("Authentication-Results: {}\r\n", result.header).into_bytes();
                    let header_len = header_bytes.len();
                    raw_bytes.resize(raw_bytes.len() + header_len, 0);
                    raw_bytes.rotate_right(header_len);
                    raw_bytes[..header_len].copy_from_slice(&header_bytes);
                }

                // ─── Received: header (RFC 5321 §4.4) ────────────────────────
                // Every MTA that accepts a message MUST prepend a Received:
                // trace header.  This must be the outermost (first) header so
                // it is prepended last, after Authentication-Results.
                {
                    let now_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let date_str = epoch_to_rfc2822(now_secs);
                    let received = format!(
                        "Received: from {} ([{}]) by {} with SMTP; {}\r\n",
                        ehlo_domain, client_ip, config.hostname, date_str
                    );
                    let received_bytes = received.into_bytes();
                    let received_len = received_bytes.len();
                    raw_bytes.resize(raw_bytes.len() + received_len, 0);
                    raw_bytes.rotate_right(received_len);
                    raw_bytes[..received_len].copy_from_slice(&received_bytes);
                }
                // ─────────────────────────────────────────────────────────────

                // NOTE: the presence of a Newsgroups: header in the incoming message
                // does NOT auto-route it to an NNTP newsgroup. NNTP posting is handled
                // explicitly via FileInto("newsgroup:...") in Sieve scripts. This is by
                // design — see stoa-euk.

                // ─── Sieve delivery ──────────────────────────────────────────
                // All inbound SMTP email is processed by Sieve.
                //
                // Actions:
                //   Reject   → 550, reset session (no accept)
                //   Discard  → 250 OK, message dropped
                //   Keep     → 250 OK, deliver to INBOX
                //   FileInto("newsgroup:X") → enqueue to durable NNTP queue
                //   FileInto(folder)        → deliver to named folder
                //
                // When no local user matches a recipient the message is
                // accepted (250 OK) but produces no Sieve actions — the
                // sending MTA's responsibility ends at 250.
                match sieve_delivery(
                    &config,
                    pool.as_ref(),
                    &to,
                    &raw_bytes,
                    &from,
                    sieve_cache.as_ref(),
                    &nntp_queue,
                    &peer_addr,
                )
                .await
                {
                    SieveOutcome::Rejected(reason) => {
                        // Log the per-recipient rejection reason for operator
                        // diagnostics, but do NOT echo it back to the sender.
                        // In multi-recipient envelopes, exposing the per-user
                        // reason would reveal which recipient's Sieve policy
                        // triggered the reject, leaking BCC recipient identity.
                        let safe: String = reason
                            .chars()
                            .filter(|c| c.is_ascii_graphic() || *c == ' ')
                            .take(200)
                            .collect();
                        warn!(peer = %peer_addr, from = %from, %safe, "Sieve reject");
                        SMTP_MESSAGES_REJECTED_TOTAL
                            .with_label_values(&["policy"])
                            .inc();
                        if write_half
                            .write_all(b"550 Message rejected by recipient policy\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    SieveOutcome::Accepted { nntp_queue_error } => {
                        let reply: &[u8] = if nntp_queue_error {
                            b"452 4.3.1 Queue write failed - try again later\r\n"
                        } else {
                            SMTP_MESSAGES_ACCEPTED_TOTAL.inc();
                            SMTP_DATA_BYTES_TOTAL.inc_by(raw_bytes.len() as f64);
                            b"250 OK\r\n"
                        };
                        if write_half.write_all(reply).await.is_err() {
                            break;
                        }
                    }
                }
                // ─────────────────────────────────────────────────────────────

                state = SessionState::Greeted { ehlo_domain };
            }

            "RSET" => {
                if write_half.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
                state = match state {
                    SessionState::Fresh => SessionState::Fresh,
                    SessionState::Greeted { ehlo_domain }
                    | SessionState::Mail { ehlo_domain, .. }
                    | SessionState::Rcpt { ehlo_domain, .. } => {
                        SessionState::Greeted { ehlo_domain }
                    }
                };
            }

            "NOOP" => {
                if write_half.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
            }

            "QUIT" => {
                let _ = write_half.write_all(b"221 Bye\r\n").await;
                break;
            }

            "STARTTLS" => {
                // STARTTLS upgrade is not yet implemented. Return 454 rather
                // than 502 (command not implemented) so that MTAs that
                // opportunistically offer STARTTLS but do not require it
                // gracefully fall back to plaintext. Advertising STARTTLS in
                // EHLO would cause STARTTLS-policy enforcers to fail delivery,
                // so it is omitted from EHLO until a full implementation exists.
                if write_half
                    .write_all(b"454 TLS not available\r\n")
                    .await
                    .is_err()
                {
                    break;
                }
            }

            _ => {
                if write_half
                    .write_all(b"500 Command unrecognized\r\n")
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    info!(peer = %peer_addr, "session ended");
}

/// Verify a SASL PLAIN credential string against the credential store.
///
/// The PLAIN mechanism encodes credentials as base64(`authzid\0authcid\0passwd`)
/// per RFC 4616 §2.  `authzid` is usually empty (authorization identity equals
/// authentication identity).  A non-empty `authzid` is rejected — this server
/// does not support proxy authentication.
///
/// Returns `Some(username)` (ASCII-lowercased) on success, `None` on any
/// failure.  The password is never logged.
async fn verify_sasl_plain(store: &CredentialStore, b64_response: &str) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64_response.trim())
        .ok()?;
    // Split on NUL: [authzid, authcid, passwd]
    let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authzid = std::str::from_utf8(parts[0]).ok()?;
    let authcid = std::str::from_utf8(parts[1]).ok()?;
    let passwd = std::str::from_utf8(parts[2]).ok()?;
    // Empty authcid is not permitted by RFC 4616 §2.
    if authcid.is_empty() {
        return None;
    }
    // Non-empty authzid means proxy-auth — not supported, reject.
    if !authzid.is_empty() {
        return None;
    }
    if store.check(authcid, passwd).await {
        Some(authcid.to_ascii_lowercase())
    } else {
        None
    }
}

/// Load and evaluate the active Sieve script for `username`.
/// Defaults to [`Keep`](stoa_sieve_native::SieveAction::Keep) when no script
/// is stored or the script fails to compile.
/// Outcome of [`sieve_delivery`].
enum SieveOutcome {
    /// At least one recipient's Sieve script issued a `Reject` action.
    /// The inner string is the raw (unsanitised) rejection reason for logging;
    /// it must not be forwarded verbatim to the sender (BCC privacy).
    Rejected(String),
    /// No rejection; message was processed for all recipients.
    /// `nntp_queue_error` is `true` if at least one newsgroup enqueue failed.
    Accepted { nntp_queue_error: bool },
}

/// Evaluate Sieve filters for all addressed local users and apply the
/// resulting actions (Keep → INBOX, FileInto → folder or newsgroup, Discard,
/// Reject).
///
/// Returns [`SieveOutcome::Rejected`] if any script issued a reject — the
/// caller is responsible for sending the 550 response and incrementing the
/// reject metric.  Returns [`SieveOutcome::Accepted`] otherwise, with a flag
/// indicating whether any newsgroup enqueue failed (caller sends 452 vs 250).
#[allow(clippy::too_many_arguments)]
async fn sieve_delivery(
    config: &Config,
    pool: Option<&SqlitePool>,
    to: &[String],
    raw_bytes: &[u8],
    from: &str,
    sieve_cache: Option<&SieveCache>,
    nntp_queue: &NntpQueue,
    peer_addr: &str,
) -> SieveOutcome {
    // Collect Sieve actions for every addressed local user.
    let mut deliveries: Vec<(String, String, Vec<stoa_sieve_native::SieveAction>)> = Vec::new();
    for recipient_email in to {
        if let Some(user) = config
            .users
            .iter()
            .find(|u| u.email.eq_ignore_ascii_case(recipient_email))
        {
            let actions = if let Some(db_pool) = pool {
                let sieve_timeout =
                    tokio::time::Duration::from_millis(config.limits.sieve_eval_timeout_ms);
                let username = user.username.clone();
                match tokio::time::timeout(
                    sieve_timeout,
                    sieve_for_user(
                        db_pool,
                        &username,
                        raw_bytes,
                        from,
                        recipient_email,
                        sieve_cache,
                    ),
                )
                .await
                {
                    Ok(actions) => actions,
                    Err(_elapsed) => {
                        tracing::warn!(%username, "Sieve evaluation timed out; defaulting to Keep");
                        crate::metrics::SMTP_SIEVE_EVAL_TIMEOUTS_TOTAL.inc();
                        vec![stoa_sieve_native::SieveAction::Keep]
                    }
                }
            } else {
                vec![stoa_sieve_native::SieveAction::Keep]
            };
            deliveries.push((user.username.clone(), recipient_email.clone(), actions));
        }
    }

    // If any script wants to reject, reject the whole transaction.
    for (_, _, actions) in &deliveries {
        for action in actions {
            if let stoa_sieve_native::SieveAction::Reject(r) = action {
                return SieveOutcome::Rejected(r.clone());
            }
        }
    }

    // No reject — apply Keep / FileInto / Discard per recipient.
    let mut nntp_queue_error = false;
    for (username, email, actions) in deliveries {
        for action in actions {
            match action {
                stoa_sieve_native::SieveAction::Keep => {
                    if let Some(db_pool) = pool {
                        if let Err(e) =
                            store::deliver(db_pool, &username, "INBOX", from, &email, raw_bytes)
                                .await
                        {
                            warn!(peer = %peer_addr, %username, "deliver to INBOX failed: {e}");
                        }
                    } else {
                        warn!(
                            peer = %peer_addr, %username,
                            "Sieve Keep: no database configured, message not stored"
                        );
                    }
                }
                stoa_sieve_native::SieveAction::FileInto(folder) => {
                    if let Some(newsgroup) = folder.strip_prefix("newsgroup:") {
                        let (article, injection_source) =
                            if routing::has_newsgroups_header(raw_bytes) {
                                (raw_bytes.to_vec(), InjectionSource::SmtpNewsgroups)
                            } else {
                                (
                                    routing::add_newsgroups_header(raw_bytes, newsgroup),
                                    InjectionSource::SmtpSieve,
                                )
                            };
                        if let Err(e) = nntp_queue.enqueue(&article, injection_source).await {
                            warn!(peer = %peer_addr, %newsgroup, "NNTP queue write failed: {e}");
                            nntp_queue_error = true;
                        }
                    } else if let Some(db_pool) = pool {
                        if let Err(e) =
                            store::deliver(db_pool, &username, &folder, from, &email, raw_bytes)
                                .await
                        {
                            warn!(peer = %peer_addr, %username, %folder, "deliver to folder failed: {e}");
                        }
                    } else {
                        warn!(
                            peer = %peer_addr, %username, %folder,
                            "Sieve FileInto: no database configured, message not stored"
                        );
                    }
                }
                stoa_sieve_native::SieveAction::Discard => {
                    info!(peer = %peer_addr, %username, "Sieve discard — message dropped");
                }
                stoa_sieve_native::SieveAction::Reject(_) => {}
            }
        }
    }

    SieveOutcome::Accepted { nntp_queue_error }
}

async fn sieve_for_user(
    pool: &SqlitePool,
    username: &str,
    raw_message: &[u8],
    envelope_from: &str,
    envelope_to: &str,
    cache: Option<&SieveCache>,
) -> Vec<stoa_sieve_native::SieveAction> {
    // Check cache before hitting the database.
    if let Some(cache) = cache {
        let lock = cache.lock().await;
        if let Some(compiled) = lock.get(username) {
            let compiled = Arc::clone(compiled);
            drop(lock);
            return stoa_sieve_native::evaluate(&compiled, raw_message, envelope_from, envelope_to);
        }
    }

    let script_bytes = store::load_active_script(pool, username).await;
    match script_bytes {
        Some(bytes) => match stoa_sieve_native::compile(&bytes) {
            Ok(compiled) => {
                let compiled = Arc::new(compiled);
                if let Some(cache) = cache {
                    cache
                        .lock()
                        .await
                        .insert(username.to_owned(), Arc::clone(&compiled));
                }
                stoa_sieve_native::evaluate(&compiled, raw_message, envelope_from, envelope_to)
            }
            Err(e) => {
                tracing::error!(
                    %username,
                    error = %e,
                    sieve.event = "compile_error",
                    "Sieve script compile error — failing open to Keep; \
                     user's filter rules are NOT being applied"
                );
                vec![stoa_sieve_native::SieveAction::Keep]
            }
        },
        None => vec![stoa_sieve_native::SieveAction::Keep],
    }
}

/// Read the RFC 5321 DATA body: accumulate dot-unstuffed lines until a lone
/// `".\r\n"` terminator is received.
///
/// Reads byte-by-byte via the `BufReader` internal buffer so that a single
/// line longer than `max_bytes` cannot exhaust heap — it is detected early
/// and the rest of that line is drained before continuing.
///
/// Returns `(accumulated_bytes, too_large)`.  If the body exceeds
/// `max_bytes`, we continue reading and discarding until the terminator so
/// the session can continue (RFC 5321 §4.5.3.1).
async fn read_data_body<R>(reader: &mut BufReader<R>, max_bytes: u64) -> (Vec<u8>, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut body: Vec<u8> = Vec::new();
    let mut too_large = false;
    let max_bytes_usize = max_bytes as usize;
    let mut byte = [0u8; 1];
    let mut line_buf: Vec<u8> = Vec::new();

    'outer: loop {
        // Read one line byte-by-byte, bounded to max_bytes_usize per line.
        // A single body line longer than max_bytes means the message is
        // already over the limit; drain that line and mark too_large.
        line_buf.clear();
        loop {
            match reader.read(&mut byte).await {
                Ok(0) | Err(_) => break 'outer,
                Ok(_) => {
                    line_buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        break; // Full line read — process below.
                    }
                    if line_buf.len() > max_bytes_usize {
                        too_large = true;
                        body.clear();
                        // Drain rest of the overlong line without buffering.
                        loop {
                            match reader.read(&mut byte).await {
                                Ok(0) | Err(_) => break 'outer,
                                Ok(_) if byte[0] == b'\n' => break,
                                _ => {}
                            }
                        }
                        continue 'outer;
                    }
                }
            }
        }

        // Terminator: a lone dot followed by CRLF.
        if line_buf == b".\r\n" || line_buf == b".\n" {
            break;
        }

        // Dot-unstuffing: RFC 5321 §4.5.2 — a line beginning with ".." has
        // the leading dot removed.
        let unstuffed: &[u8] = if line_buf.starts_with(b"..") {
            &line_buf[1..]
        } else {
            &line_buf
        };

        if !too_large {
            body.extend_from_slice(unstuffed);
            if body.len() as u64 > max_bytes {
                too_large = true;
                // Drop the accumulated body; keep reading until terminator.
                body.clear();
            }
        }
    }

    (body, too_large)
}

/// Extract the address from an SMTP MAIL FROM or RCPT TO argument.
///
/// Handles ESMTP parameters that follow the angle-bracket pair — for example
/// `MAIL FROM:<sender@example.com> SIZE=12345` or
/// `RCPT TO:<user@example.com> ORCPT=rfc822;user@example.com`.
/// Returns only the content between `<` and the first `>` after it.
/// Returns the trimmed argument as-is when no angle brackets are present.
fn parse_angle_addr(args: &str) -> String {
    // Skip the `FROM:` / `TO:` keyword prefix (case-insensitive).
    let after_colon = if let Some(pos) = args.find(':') {
        &args[pos + 1..]
    } else {
        args
    };
    let trimmed = after_colon.trim();
    // Locate the angle-bracket pair and return only what is inside it.
    // Everything after the closing `>` (ESMTP params) is intentionally ignored.
    if let Some(open) = trimmed.find('<') {
        if let Some(rel_close) = trimmed[open + 1..].find('>') {
            return trimmed[open + 1..open + 1 + rel_close].to_string();
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthConfig, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, ReaderConfig,
        SieveAdminConfig, TlsConfig, UserConfig,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 300,
                max_connections: 10,
                sieve_eval_timeout_ms: 5_000,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
            auth: AuthConfig::default(),
        })
    }

    fn test_config_with_users(users: Vec<UserConfig>) -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 300,
                max_connections: 10,
                sieve_eval_timeout_ms: 5_000,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            users,
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
            auth: AuthConfig::default(),
        })
    }

    async fn open_test_db() -> SqlitePool {
        crate::store::open(":memory:")
            .await
            .expect("open in-memory DB")
    }

    /// Drive a session with the given config and optional pool.
    ///
    /// Returns `(server_response_string, nntp_queue_dir)`.
    /// The caller can inspect the tempdir for `.msg` files to verify NNTP injection.
    async fn drive_session_ext(
        client_script: &[u8],
        config: Arc<Config>,
        pool: Option<SqlitePool>,
    ) -> (String, tempfile::TempDir) {
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path()).expect("NntpQueue::new");
        let credential_store = Arc::new(CredentialStore::empty());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let server_task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(
                stream,
                false,
                peer.to_string(),
                config2,
                credential_store,
                queue2,
                None,
                pool,
                None,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client.write_all(client_script).await.expect("write script");
        client.shutdown().await.expect("shutdown");

        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .await
            .expect("read response");
        server_task.await.expect("server task");

        (response, queue_dir)
    }

    /// Convenience wrapper: no-pool session using the default test config.
    async fn drive_session(client_script: &[u8]) -> (String, tempfile::TempDir) {
        drive_session_ext(client_script, test_config(), None).await
    }

    /// Count .msg files in a queue directory.
    fn count_queued(dir: &tempfile::TempDir) -> usize {
        std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .count()
    }

    #[tokio::test]
    async fn test_basic_smtp_session() {
        // Basic end-to-end: full SMTP exchange with a known recipient completes successfully.
        let rcpt_user = UserConfig {
            username: "rcpt".to_string(),
            email: "rcpt@example.com".to_string(),
        };
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            Subject: Hello\r\n\
            \r\n\
            Body text.\r\n\
            .\r\n\
            QUIT\r\n";

        let (response, _queue_dir) =
            drive_session_ext(client, test_config_with_users(vec![rcpt_user]), None).await;

        assert!(
            response.starts_with("220 "),
            "expected greeting, got: {response}"
        );
        assert!(response.contains("250"), "expected 250 after EHLO");
        assert!(response.contains("354"), "expected 354 DATA prompt");
        assert!(response.contains("250 OK"), "expected 250 after DATA");
        assert!(response.contains("221"), "expected 221 QUIT");
    }

    #[tokio::test]
    async fn test_rset_clears_state() {
        // MAIL then RSET then MAIL again — both MAIL commands must succeed.
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<a@example.com>\r\n\
            RSET\r\n\
            MAIL FROM:<b@example.com>\r\n\
            QUIT\r\n";

        let (response, _) = drive_session(client).await;

        // Count "250 OK" occurrences: MAIL, RSET, MAIL = 3
        let count_250_ok = response.matches("250 OK").count();
        assert!(
            count_250_ok >= 2,
            "expected at least 2x '250 OK', got: {response}"
        );
        assert!(response.contains("221"), "expected 221 after QUIT");
    }

    #[tokio::test]
    async fn test_quit_returns_221() {
        let client = b"QUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.starts_with("220 "),
            "expected greeting, got: {response}"
        );
        assert!(
            response.contains("221 Bye"),
            "expected 221 Bye, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_unknown_command_returns_500() {
        let client = b"FROBNICATE arg\r\n\
            QUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.contains("500 Command unrecognized"),
            "expected 500, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_rcpt_before_mail_returns_503() {
        let client = b"EHLO client.example.com\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            QUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.contains("503 Bad sequence"),
            "expected 503, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_rcpt_empty_users_rejects_all() {
        // An empty user list means no local recipients exist — not an open relay.
        // All RCPT TO addresses must be rejected with 550 when users is empty.
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<anyone@example.com>\r\n\
            QUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.contains("550 5.1.1 User not found"),
            "empty users must reject all RCPT TO with 550, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_oversized_line_returns_500_and_closes() {
        // Build a line that exceeds 4096 bytes.
        let mut long_line = vec![b'A'; MAX_LINE_BYTES + 1];
        long_line.extend_from_slice(b"\r\n");

        let (response, _) = drive_session(&long_line).await;
        assert!(
            response.contains("500 Line too long"),
            "expected 500 Line too long, got: {response}"
        );
    }

    /// When `auth` is Some, a message with no DKIM / no DMARC record still
    /// gets accepted (dmarc_reject will be false) and has the
    /// Authentication-Results header prepended into the delivered message.
    #[tokio::test]
    async fn test_auth_pipeline_stamps_header() {
        let auth = Arc::new(
            mail_auth::MessageAuthenticator::new_cloudflare()
                .expect("resolver creation must not fail"),
        );

        // Use a user so the message is stored in INBOX for inspection.
        let pool = open_test_db().await;
        let config = test_config_with_users(vec![UserConfig {
            username: "rcpt".to_string(),
            email: "rcpt@example.com".to_string(),
        }]);
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path()).expect("NntpQueue::new");
        let credential_store = Arc::new(CredentialStore::empty());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let auth2 = auth.clone();
        let pool2 = pool.clone();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            run_session(
                stream,
                false,
                peer.to_string(),
                config2,
                credential_store,
                queue2,
                Some(auth2),
                Some(pool2),
                None,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let script = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            From: sender@example.com\r\n\
            To: rcpt@example.com\r\n\
            Subject: Auth test\r\n\
            Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
            \r\n\
            Body.\r\n\
            .\r\n\
            QUIT\r\n";
        client.write_all(script).await.unwrap();
        client.shutdown().await.unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("250 OK"), "expected 250 after DATA");

        let raw_bytes = crate::store::get_first_message_raw(&pool, "rcpt", "INBOX")
            .await
            .expect("message must be in INBOX");
        let raw = std::str::from_utf8(&raw_bytes).expect("valid UTF-8");
        assert!(
            raw.contains("Authentication-Results:"),
            "expected Authentication-Results header in message:\n{raw}"
        );
    }

    // ── Sieve delivery tests ──────────────────────────────────────────────────

    fn alice() -> UserConfig {
        UserConfig {
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
        }
    }

    const FULL_MSG: &[u8] = b"EHLO client.example.com\r\n\
        MAIL FROM:<sender@example.com>\r\n\
        RCPT TO:<alice@example.com>\r\n\
        DATA\r\n\
        Subject: Test\r\n\
        \r\n\
        Body\r\n\
        .\r\n\
        QUIT\r\n";

    #[tokio::test]
    async fn test_rcpt_unknown_user_rejected() {
        let config = test_config_with_users(vec![alice()]);
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<unknown@example.com>\r\n\
            QUIT\r\n";
        let (response, _) = drive_session_ext(client, config, None).await;
        assert!(
            response.contains("550 5.1.1"),
            "expected 550 5.1.1 for unknown user, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_rcpt_known_user_accepted() {
        let config = test_config_with_users(vec![alice()]);
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<alice@example.com>\r\n\
            QUIT\r\n";
        let (response, _) = drive_session_ext(client, config, None).await;
        assert!(
            !response.contains("550"),
            "expected no 550 for known user, got: {response}"
        );
        assert!(response.contains("250 OK"), "expected 250 OK for RCPT TO");
    }

    #[tokio::test]
    async fn test_sieve_default_delivers_to_inbox() {
        // No script stored → default Keep → message in INBOX.
        let pool = open_test_db().await;
        let config = test_config_with_users(vec![alice()]);

        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );
        let count = crate::store::count_messages(&pool, "alice", "INBOX").await;
        assert_eq!(count, 1, "expected 1 message in INBOX");
    }

    #[tokio::test]
    async fn test_sieve_fileinto_delivers_to_folder() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            "alice",
            "default",
            br#"require ["fileinto"]; fileinto "Work";"#,
            true,
        )
        .await
        .expect("save script");

        let config = test_config_with_users(vec![alice()]);
        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );
        let count_work = crate::store::count_messages(&pool, "alice", "Work").await;
        let count_inbox = crate::store::count_messages(&pool, "alice", "INBOX").await;
        assert_eq!(count_work, 1, "expected 1 message in Work");
        assert_eq!(count_inbox, 0, "expected 0 messages in INBOX");
    }

    #[tokio::test]
    async fn test_sieve_discard_accepts_but_no_db_write() {
        let pool = open_test_db().await;
        crate::store::save_script(&pool, "alice", "default", b"discard;", true)
            .await
            .expect("save script");

        let config = test_config_with_users(vec![alice()]);
        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK (discard still accepts), got: {response}"
        );
        let count = crate::store::count_messages(&pool, "alice", "INBOX").await;
        assert_eq!(count, 0, "expected 0 messages — message was discarded");
    }

    #[tokio::test]
    async fn test_sieve_reject_returns_550() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            "alice",
            "default",
            br#"require ["reject"]; reject "Not wanted";"#,
            true,
        )
        .await
        .expect("save script");

        let config = test_config_with_users(vec![alice()]);
        let pool_clone = pool.clone();
        let (response, _) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(response.contains("550"), "expected 550, got: {response}");
        let count = crate::store::count_messages(&pool, "alice", "INBOX").await;
        assert_eq!(count, 0, "expected 0 messages — message was rejected");
    }

    // ── Sieve fileinto "newsgroup:X" enqueues to NNTP queue ──────────────────

    #[tokio::test]
    async fn test_sieve_fileinto_newsgroup_enqueues_article() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            "alice",
            "default",
            br#"require ["fileinto"]; fileinto "newsgroup:comp.test";"#,
            true,
        )
        .await
        .expect("save script");

        let config = test_config_with_users(vec![alice()]);
        let pool_clone = pool.clone();
        let (response, queue_dir) = drive_session_ext(FULL_MSG, config, Some(pool_clone)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );
        assert_eq!(
            count_queued(&queue_dir),
            1,
            "expected 1 article in NNTP queue"
        );

        // The queued file should contain the Newsgroups: header.
        let files: Vec<_> = std::fs::read_dir(queue_dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .collect();
        let bytes = std::fs::read(files[0].path()).expect("read queue file");
        let text = std::str::from_utf8(&bytes).expect("valid UTF-8");
        assert!(
            text.contains("Newsgroups: comp.test"),
            "queued article must have Newsgroups header"
        );

        // Nothing in INBOX.
        let count = crate::store::count_messages(&pool, "alice", "INBOX").await;
        assert_eq!(count, 0, "newsgroup fileinto must not deliver to INBOX");
    }

    // ── Sieve fileinto "newsgroup:X" with pre-existing Newsgroups: header ────

    #[tokio::test]
    async fn test_sieve_fileinto_newsgroup_no_duplicate_header() {
        let pool = open_test_db().await;
        crate::store::save_script(
            &pool,
            "alice",
            "default",
            br#"require ["fileinto"]; fileinto "newsgroup:comp.test";"#,
            true,
        )
        .await
        .expect("save script");

        // Message already has a Newsgroups: header.
        let msg_with_ng = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<alice@example.com>\r\n\
            DATA\r\n\
            Newsgroups: alt.test\r\n\
            Subject: Cross-posted\r\n\
            \r\n\
            Body\r\n\
            .\r\n\
            QUIT\r\n";

        let config = test_config_with_users(vec![alice()]);
        let (response, queue_dir) = drive_session_ext(msg_with_ng, config, Some(pool)).await;

        assert!(
            response.contains("250 OK"),
            "expected 250 OK, got: {response}"
        );
        assert_eq!(
            count_queued(&queue_dir),
            1,
            "expected 1 article in NNTP queue"
        );

        let files: Vec<_> = std::fs::read_dir(queue_dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "msg"))
            .collect();
        let bytes = std::fs::read(files[0].path()).expect("read queue file");
        let text = std::str::from_utf8(&bytes).expect("valid UTF-8");

        // Original Newsgroups: must be present.
        assert!(
            text.contains("Newsgroups: alt.test"),
            "original Newsgroups header must be preserved"
        );
        // Must not have a duplicate.
        assert_eq!(
            text.matches("Newsgroups:").count(),
            1,
            "must not have duplicate Newsgroups: header, got:\n{text}"
        );
    }

    // ── Received: header (RFC 5321 §4.4) ─────────────────────────────────────

    /// Every accepted message must start with a Received: trace header.
    #[tokio::test]
    async fn test_received_header_prepended() {
        let pool = open_test_db().await;
        let config = test_config_with_users(vec![UserConfig {
            username: "rcpt".to_string(),
            email: "rcpt@example.com".to_string(),
        }]);

        let client = b"EHLO mail.sender.example\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            From: sender@example.com\r\n\
            To: rcpt@example.com\r\n\
            Subject: Received header test\r\n\
            \r\n\
            Body.\r\n\
            .\r\n\
            QUIT\r\n";

        let (response, _queue_dir) = drive_session_ext(client, config, Some(pool.clone())).await;
        assert!(
            response.contains("250 OK"),
            "expected 250 after DATA: {response}"
        );

        let raw_bytes = crate::store::get_first_message_raw(&pool, "rcpt", "INBOX")
            .await
            .expect("message must be in INBOX");
        let raw = std::str::from_utf8(&raw_bytes).expect("valid UTF-8");

        assert!(
            raw.starts_with("Received:"),
            "stored message must start with Received: header, got:\n{raw}"
        );
        assert!(
            raw.contains("mail.sender.example"),
            "Received: header must contain EHLO domain: {raw}"
        );
        assert!(
            raw.contains("test.example.com"),
            "Received: header must contain local hostname: {raw}"
        );
    }

    // ── ryw.2: parse_angle_addr unit tests ───────────────────────────────────

    #[test]
    fn parse_angle_addr_simple() {
        assert_eq!(parse_angle_addr("FROM:<foo@bar.com>"), "foo@bar.com");
    }

    #[test]
    fn parse_angle_addr_with_size_param() {
        // Modern MTAs send SIZE on MAIL FROM; the address must not include it.
        assert_eq!(
            parse_angle_addr("FROM:<foo@bar.com> SIZE=12345"),
            "foo@bar.com"
        );
    }

    #[test]
    fn parse_angle_addr_with_orcpt_param() {
        // RFC 3461 DSN: ORCPT may follow RCPT TO.
        assert_eq!(
            parse_angle_addr("TO:<alice@example.com> ORCPT=rfc822;alice@example.com"),
            "alice@example.com"
        );
    }

    #[test]
    fn parse_angle_addr_null_sender() {
        // Null sender (<>) used for bounce messages.
        assert_eq!(parse_angle_addr("FROM:<>"), "");
    }

    #[test]
    fn parse_angle_addr_no_brackets() {
        assert_eq!(parse_angle_addr("foo@bar.com"), "foo@bar.com");
    }

    // ── ryw.2: integration — MAIL FROM with SIZE must not corrupt envelope ───

    #[tokio::test]
    async fn test_mail_from_with_size_param_accepted() {
        // A real MTA sends MAIL FROM:<addr> SIZE=nnn.  The session must
        // accept it and store the address without the SIZE suffix.
        let pool = open_test_db().await;
        let config = test_config_with_users(vec![UserConfig {
            username: "rcpt".to_string(),
            email: "rcpt@example.com".to_string(),
        }]);
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com> SIZE=1024\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            Subject: Size test\r\n\
            \r\n\
            Body.\r\n\
            .\r\n\
            QUIT\r\n";

        let (response, _queue_dir) = drive_session_ext(client, config, Some(pool.clone())).await;
        assert!(
            response.contains("250 OK"),
            "expected 250 after DATA: {response}"
        );

        let envelope_from = crate::store::get_first_envelope_from(&pool, "rcpt", "INBOX")
            .await
            .expect("message must be in INBOX");
        assert_eq!(
            envelope_from, "sender@example.com",
            "envelope_from must not include SIZE param"
        );
    }

    // ── ryw.3: STARTTLS must not appear in EHLO even when TLS is configured ──

    #[tokio::test]
    async fn test_ehlo_no_starttls_even_when_tls_configured() {
        // STARTTLS upgrade is not yet implemented; advertising it would break
        // MTAs that enforce STARTTLS-policy (they would connect, see STARTTLS
        // in EHLO, send STARTTLS, get 454, and fail delivery).
        let config = Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: Some("/etc/ssl/cert.pem".into()),
                key_path: Some("/etc/ssl/key.pem".into()),
            },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 300,
                max_connections: 10,
                sieve_eval_timeout_ms: 5_000,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
            auth: AuthConfig::default(),
        });

        let client = b"EHLO client.example.com\r\nQUIT\r\n";
        let (response, _) = drive_session_ext(client, config, None).await;

        assert!(
            !response.contains("STARTTLS"),
            "STARTTLS must not appear in EHLO until implemented: {response}"
        );
        assert!(
            response.contains("250"),
            "expected 250 EHLO response: {response}"
        );
    }

    // ── EHLO/HELO injection guard ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_ehlo_with_bare_cr_returns_501() {
        // Injection vector: a bare CR (no LF) causes read_command_line to
        // include the injected text in the EHLO argument.  The injected
        // content would otherwise be interpolated verbatim into Received:.
        // b"EHLO evil\rX-Injected: header\r\n" is read as one command line.
        let client = b"EHLO evil\rX-Injected: header\r\nQUIT\r\n";
        let (response, _) = drive_session(client).await;
        assert!(
            response.contains("501"),
            "EHLO with bare CR in domain must return 501, got: {response}"
        );
    }

    #[tokio::test]
    async fn test_ehlo_with_nul_returns_501() {
        let mut script = b"EHLO evil".to_vec();
        script.push(0); // NUL
        script.extend_from_slice(b"\r\nQUIT\r\n");
        let (response, _) = drive_session(&script).await;
        assert!(
            response.contains("501"),
            "EHLO with NUL must return 501, got: {response}"
        );
    }

    // ── ryw.1 + ryw.4: timeout test ──────────────────────────────────────────

    #[tokio::test]
    async fn test_command_timeout_sends_421() {
        // Use tokio's simulated time so the test does not sleep for real.
        tokio::time::pause();

        let config = Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
                smtps_addr: None,
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 1, // 1-second timeout for this test
                max_connections: 10,
                sieve_eval_timeout_ms: 5_000,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            reader: ReaderConfig::default(),
            delivery: crate::config::DeliveryConfig::default(),
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
            auth: AuthConfig::default(),
        });

        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path()).expect("NntpQueue::new");
        let credential_store = Arc::new(CredentialStore::empty());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let server_task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            run_session(
                stream,
                false,
                peer.to_string(),
                config2,
                credential_store,
                queue2,
                None,
                None,
                None,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Advance simulated time past the 1-second command timeout.
        tokio::time::advance(Duration::from_secs(2)).await;

        // After the timeout fires, the server sends 421 and closes the write half.
        // read_to_string completes once the write half is dropped.
        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut client, &mut response)
            .await
            .unwrap();
        server_task.await.unwrap();

        assert!(
            response.starts_with("220 "),
            "expected greeting before timeout: {response:?}"
        );
        assert!(
            response.contains("421"),
            "expected 421 timeout response, got: {response:?}"
        );
    }

    // ── Sieve script cache tests ──────────────────────────────────────────

    const MINIMAL_MESSAGE: &[u8] = b"From: a@example.com\r\nTo: b@example.com\r\n\r\nHi\r\n";

    #[tokio::test]
    async fn sieve_for_user_populates_cache_on_first_call() {
        let pool = crate::store::open(":memory:").await.unwrap();
        crate::store::save_script(&pool, "alice", "default", b"keep;", true)
            .await
            .unwrap();

        let cache = new_sieve_cache();
        sieve_for_user(
            &pool,
            "alice",
            MINIMAL_MESSAGE,
            "a@example.com",
            "b@example.com",
            Some(&cache),
        )
        .await;

        assert!(
            cache.lock().await.contains_key("alice"),
            "cache should contain alice after first call"
        );
    }

    #[tokio::test]
    async fn sieve_for_user_uses_cached_script_after_db_removal() {
        let pool = crate::store::open(":memory:").await.unwrap();
        crate::store::save_script(&pool, "alice", "default", b"discard;", true)
            .await
            .unwrap();

        let cache = new_sieve_cache();
        // First call: DB load, cache populated, script is Discard.
        let actions = sieve_for_user(
            &pool,
            "alice",
            MINIMAL_MESSAGE,
            "a@example.com",
            "b@example.com",
            Some(&cache),
        )
        .await;
        assert!(
            actions
                .iter()
                .any(|a| *a == stoa_sieve_native::SieveAction::Discard),
            "expected Discard from compiled script"
        );

        // Remove from DB — subsequent call must use the cache, still Discard.
        crate::store::delete_script(&pool, "alice", "default")
            .await
            .unwrap();
        let actions2 = sieve_for_user(
            &pool,
            "alice",
            MINIMAL_MESSAGE,
            "a@example.com",
            "b@example.com",
            Some(&cache),
        )
        .await;
        assert!(
            actions2
                .iter()
                .any(|a| *a == stoa_sieve_native::SieveAction::Discard),
            "expected Discard from cache even after DB removal"
        );
    }

    #[tokio::test]
    async fn sieve_for_user_no_cache_falls_back_to_keep_when_no_script() {
        let pool = crate::store::open(":memory:").await.unwrap();
        let actions = sieve_for_user(
            &pool,
            "nobody",
            MINIMAL_MESSAGE,
            "a@example.com",
            "b@example.com",
            None,
        )
        .await;
        assert_eq!(actions, vec![stoa_sieve_native::SieveAction::Keep]);
    }

    /// When a credential store is non-empty, MAIL FROM without prior AUTH
    /// must be rejected with 530.
    #[tokio::test]
    async fn test_mail_from_requires_auth_when_credentials_configured() {
        use stoa_auth::{CredentialStore, UserCredential};
        use tokio::io::AsyncWriteExt;

        // bcrypt cost 4 is the minimum; fast enough for tests.
        let hash = bcrypt::hash("hunter2", 4).expect("bcrypt::hash");
        let creds = vec![UserCredential {
            username: "alice".to_string(),
            password: hash,
        }];
        let credential_store = Arc::new(CredentialStore::from_credentials(&creds));

        let config = test_config();
        let queue_dir = tempfile::tempdir().expect("tempdir");
        let nntp_queue = NntpQueue::new(queue_dir.path()).expect("NntpQueue::new");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let config2 = config.clone();
        let queue2 = Arc::clone(&nntp_queue);
        let store2 = Arc::clone(&credential_store);
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(
                stream,
                true,
                peer.to_string(),
                config2,
                store2,
                queue2,
                None,
                None,
                None,
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let script = b"EHLO client.example.com\r\nMAIL FROM:<sender@example.com>\r\nQUIT\r\n";
        client.write_all(script).await.expect("write");
        client.shutdown().await.expect("shutdown");

        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");

        assert!(
            response.contains("530 5.7.0 Authentication required"),
            "unauthenticated MAIL FROM must be rejected with 530 when auth is configured, got: {response}"
        );
        // Verify no 354 DATA prompt was sent (i.e., we never accepted MAIL FROM).
        assert!(
            !response.contains("354"),
            "MAIL FROM must not succeed without auth: {response}"
        );
    }
}
