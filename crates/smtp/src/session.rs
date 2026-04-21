use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use mail_auth::MessageAuthenticator;
use sqlx::SqlitePool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::auth::verify_inbound;
use crate::config::Config;
use crate::queue::{IncomingMessage, MessageQueue};
use crate::{routing, store};

const MAX_LINE_BYTES: usize = 4096;

#[derive(Debug)]
enum SessionState {
    Fresh,
    Greeted { ehlo_domain: String },
    Mail { ehlo_domain: String, from: String },
    Rcpt { ehlo_domain: String, from: String, to: Vec<String> },
}

/// Run a complete RFC 5321 SMTP session on the given TCP stream.
///
/// `auth` is optional: when `Some`, every accepted message is passed through
/// the SPF/DKIM/DMARC/ARC pipeline before enqueuing.  When `None` the message
/// is enqueued without authentication (suitable for loopback submission or
/// unit tests).
///
/// `pool` is optional: when `Some` and `config.users` is non-empty, non-list
/// messages are delivered inline via per-user Sieve scripts instead of being
/// forwarded through the message queue.
pub async fn run_session(
    stream: TcpStream,
    peer_addr: String,
    config: Arc<Config>,
    queue: MessageQueue,
    auth: Option<Arc<MessageAuthenticator>>,
    pool: Option<SqlitePool>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = format!(
        "220 {} ESMTP usenet-ipfs-smtp\r\n",
        config.hostname
    );
    if write_half.write_all(greeting.as_bytes()).await.is_err() {
        return;
    }

    // Parse the peer IP once; fall back to loopback if unparseable.
    let client_ip: IpAddr = peer_addr
        .parse::<std::net::SocketAddr>()
        .map(|sa| sa.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));

    let mut state = SessionState::Fresh;

    loop {
        let mut line_buf = String::new();
        let n = match reader.read_line(&mut line_buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!(peer = %peer_addr, "read error: {e}");
                break;
            }
        };

        if n == 0 {
            debug!(peer = %peer_addr, "client disconnected");
            break;
        }

        if line_buf.len() > MAX_LINE_BYTES {
            let _ = write_half
                .write_all(b"500 Line too long\r\n")
                .await;
            break;
        }

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
                let tls_configured =
                    config.tls.cert_path.is_some() && config.tls.key_path.is_some();
                let mut resp = format!(
                    "250-{}\r\n250-SIZE {}\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-PIPELINING\r\n",
                    config.hostname, config.limits.max_message_bytes
                );
                if tls_configured {
                    resp.push_str("250-STARTTLS\r\n");
                }
                resp.push_str("250 OK\r\n");
                if write_half.write_all(resp.as_bytes()).await.is_err() {
                    break;
                }
                state = SessionState::Greeted { ehlo_domain: args.to_string() };
            }

            "HELO" => {
                let resp = format!("250 {}\r\n", config.hostname);
                if write_half.write_all(resp.as_bytes()).await.is_err() {
                    break;
                }
                state = SessionState::Greeted { ehlo_domain: args.to_string() };
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
                let from = parse_angle_addr(args);
                if write_half.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
                state = SessionState::Mail { ehlo_domain, from };
            }

            "RCPT" => {
                let to_addr = parse_angle_addr(args);

                // Reject unknown recipients when a users list is configured.
                if !config.users.is_empty() {
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
                }

                match state {
                    SessionState::Mail { ref ehlo_domain, ref from } => {
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
                    SessionState::Rcpt { ref ehlo_domain, ref from, ref to } if !to.is_empty() => {
                        (ehlo_domain.clone(), from.clone(), to.clone())
                    }
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

                // Read dot-terminated message body.
                let max_bytes = config.limits.max_message_bytes;
                let (mut raw_bytes, too_large) =
                    read_data_body(&mut reader, max_bytes).await;

                if too_large {
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
                        if write_half
                            .write_all(
                                b"550 5.7.1 Message rejected due to DMARC policy\r\n",
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                        state = SessionState::Greeted { ehlo_domain };
                        continue;
                    }

                    // Prepend Authentication-Results header to the message.
                    let header_line =
                        format!("Authentication-Results: {}\r\n", result.header);
                    let mut prefixed = header_line.into_bytes();
                    prefixed.extend_from_slice(&raw_bytes);
                    raw_bytes = prefixed;
                }

                // ─── Inline Sieve delivery for non-list mail ─────────────────
                // When a DB pool is available and users are configured, messages
                // without a List-ID header are delivered inline via Sieve so
                // that a `reject` action can return 550 before we accept.
                let use_sieve = pool.is_some()
                    && !config.users.is_empty()
                    && routing::extract_list_id(&raw_bytes).is_none();

                if use_sieve {
                    let db_pool = pool.as_ref().unwrap();

                    // Collect Sieve actions for every addressed local user.
                    let mut deliveries: Vec<(String, String, Vec<usenet_ipfs_sieve::SieveAction>)> =
                        Vec::new();
                    for recipient_email in &to {
                        if let Some(user) = config
                            .users
                            .iter()
                            .find(|u| u.email.eq_ignore_ascii_case(recipient_email))
                        {
                            let actions = sieve_for_user(
                                db_pool,
                                &user.username,
                                &raw_bytes,
                                &from,
                                recipient_email,
                            )
                            .await;
                            deliveries.push((
                                user.username.clone(),
                                recipient_email.clone(),
                                actions,
                            ));
                        }
                    }

                    // If any script wants to reject, reject the whole transaction.
                    let mut reject_reason: Option<String> = None;
                    'find_reject: for (_, _, actions) in &deliveries {
                        for action in actions {
                            if let usenet_ipfs_sieve::SieveAction::Reject(r) = action {
                                reject_reason = Some(r.clone());
                                break 'find_reject;
                            }
                        }
                    }

                    if let Some(reason) = reject_reason {
                        // Strip control characters and cap length for safety.
                        let safe: String = reason
                            .chars()
                            .filter(|c| c.is_ascii_graphic() || *c == ' ')
                            .take(200)
                            .collect();
                        warn!(peer = %peer_addr, from = %from, %safe, "Sieve reject");
                        if write_half
                            .write_all(format!("550 {}\r\n", safe).as_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        state = SessionState::Greeted { ehlo_domain };
                        continue;
                    }

                    // No reject — apply keep / fileinto / discard per recipient.
                    for (username, email, actions) in deliveries {
                        for action in actions {
                            match action {
                                usenet_ipfs_sieve::SieveAction::Keep => {
                                    if let Err(e) = store::deliver(
                                        db_pool, &username, "INBOX", &from, &email, &raw_bytes,
                                    )
                                    .await
                                    {
                                        warn!(peer = %peer_addr, %username, "deliver to INBOX failed: {e}");
                                    }
                                }
                                usenet_ipfs_sieve::SieveAction::FileInto(folder) => {
                                    if let Err(e) = store::deliver(
                                        db_pool, &username, &folder, &from, &email, &raw_bytes,
                                    )
                                    .await
                                    {
                                        warn!(peer = %peer_addr, %username, %folder, "deliver to folder failed: {e}");
                                    }
                                }
                                usenet_ipfs_sieve::SieveAction::Discard => {
                                    info!(peer = %peer_addr, %username, "Sieve discard — message dropped");
                                }
                                usenet_ipfs_sieve::SieveAction::Reject(_) => {}
                            }
                        }
                    }

                    if write_half.write_all(b"250 OK\r\n").await.is_err() {
                        break;
                    }
                    state = SessionState::Greeted { ehlo_domain };
                    continue; // skip queue-based path below
                }
                // ─────────────────────────────────────────────────────────────

                // Queue-based path: List-ID routing (or no Sieve config).
                let msg = IncomingMessage {
                    envelope_from: from,
                    envelope_to: to,
                    raw_bytes,
                    received_at: SystemTime::now(),
                    peer_addr: peer_addr.clone(),
                };
                queue.enqueue(msg);

                if write_half.write_all(b"250 OK\r\n").await.is_err() {
                    break;
                }
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

/// Load and evaluate the active Sieve script for `username`.
/// Defaults to [`Keep`](usenet_ipfs_sieve::SieveAction::Keep) when no script
/// is stored or the script fails to compile.
async fn sieve_for_user(
    pool: &SqlitePool,
    username: &str,
    raw_message: &[u8],
    envelope_from: &str,
    envelope_to: &str,
) -> Vec<usenet_ipfs_sieve::SieveAction> {
    let script_bytes = store::load_active_script(pool, username).await;
    match script_bytes {
        Some(bytes) => match usenet_ipfs_sieve::compile(&bytes) {
            Ok(compiled) => {
                usenet_ipfs_sieve::evaluate(&compiled, raw_message, envelope_from, envelope_to)
            }
            Err(e) => {
                warn!(%username, "Sieve compile error: {e} — defaulting to Keep");
                vec![usenet_ipfs_sieve::SieveAction::Keep]
            }
        },
        None => vec![usenet_ipfs_sieve::SieveAction::Keep],
    }
}

/// Read the RFC 5321 DATA body: accumulate dot-unstuffed lines until a lone
/// `".\r\n"` terminator is received.
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

    loop {
        let mut line_buf = String::new();
        match reader.read_line(&mut line_buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }

        // Terminator: a lone dot followed by CRLF.
        if line_buf == ".\r\n" || line_buf == ".\n" {
            break;
        }

        // Dot-unstuffing: RFC 5321 §4.5.2 — a line beginning with ".." has
        // the leading dot removed.
        let unstuffed: &str = if line_buf.starts_with("..") {
            &line_buf[1..]
        } else {
            &line_buf
        };

        if !too_large {
            body.extend_from_slice(unstuffed.as_bytes());
            if body.len() as u64 > max_bytes {
                too_large = true;
                // Drop the accumulated body; keep reading until terminator.
                body.clear();
            }
        }
    }

    (body, too_large)
}

/// Extract the address from an angle-addr argument like `FROM:<addr>` or
/// `TO:<addr>`.  Returns the content between `<` and `>`, or the raw
/// argument if no angle brackets are present.
fn parse_angle_addr(args: &str) -> String {
    // Skip the `FROM:` / `TO:` keyword prefix (case-insensitive).
    let after_colon = if let Some(pos) = args.find(':') {
        &args[pos + 1..]
    } else {
        args
    };
    let trimmed = after_colon.trim();
    if let Some(inner) = trimmed.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
        inner.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, ReaderConfig, SieveAdminConfig,
        TlsConfig, UserConfig,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
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
            },
            log: LogConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
        })
    }

    fn test_config_with_users(users: Vec<UserConfig>) -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
            },
            tls: TlsConfig { cert_path: None, key_path: None },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 300,
                max_connections: 10,
            },
            log: LogConfig { level: "info".to_string(), format: "json".to_string() },
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users,
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
        })
    }

    async fn open_test_db() -> SqlitePool {
        crate::store::open(":memory:").await.expect("open in-memory DB")
    }

    /// Drive a session with the given config and optional pool.
    ///
    /// Returns `(server_response_string, first_queued_message)`.
    async fn drive_session_ext(
        client_script: &[u8],
        config: Arc<Config>,
        pool: Option<SqlitePool>,
    ) -> (String, Option<IncomingMessage>) {
        let (queue, mut rx) = MessageQueue::new();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let config2 = config.clone();
        let queue2 = queue.clone();
        let server_task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(stream, peer.to_string(), config2, queue2, None, pool).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client.write_all(client_script).await.expect("write script");
        client.shutdown().await.expect("shutdown");

        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read response");
        server_task.await.expect("server task");

        let msg = rx.try_recv().ok();
        (response, msg)
    }

    /// Convenience wrapper: no-pool session using the default test config.
    async fn drive_session(client_script: &[u8]) -> (String, Option<IncomingMessage>) {
        drive_session_ext(client_script, test_config(), None).await
    }

    #[tokio::test]
    async fn test_greeting_ehlo_mail_rcpt_data_queue() {
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com>\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            Subject: Hello\r\n\
            \r\n\
            Body text.\r\n\
            .\r\n\
            QUIT\r\n";

        let (response, msg) = drive_session(client).await;

        assert!(
            response.starts_with("220 "),
            "expected greeting, got: {response}"
        );
        assert!(response.contains("250"), "expected 250 after EHLO");
        assert!(response.contains("354"), "expected 354 DATA prompt");
        assert!(response.contains("250 OK"), "expected 250 after DATA");
        assert!(response.contains("221"), "expected 221 QUIT");

        let msg = msg.expect("message must be queued");
        assert_eq!(msg.envelope_from, "sender@example.com");
        assert_eq!(msg.envelope_to, vec!["rcpt@example.com"]);
        assert!(!msg.raw_bytes.is_empty(), "raw_bytes must not be empty");
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
        assert!(response.contains("221 Bye"), "expected 221 Bye, got: {response}");
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
    /// Authentication-Results header prepended.
    #[tokio::test]
    async fn test_auth_pipeline_stamps_header() {
        let auth = Arc::new(
            mail_auth::MessageAuthenticator::new_cloudflare()
                .expect("resolver creation must not fail"),
        );

        let config = test_config();
        let (queue, mut rx) = MessageQueue::new();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config2 = config.clone();
        let queue2 = queue.clone();
        let auth2 = auth.clone();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            run_session(stream, peer.to_string(), config2, queue2, Some(auth2), None).await;
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

        let msg = rx.recv().await.expect("message must be queued");
        let raw = std::str::from_utf8(&msg.raw_bytes).expect("valid UTF-8");
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

        assert!(response.contains("250 OK"), "expected 250 OK, got: {response}");
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

        assert!(response.contains("250 OK"), "expected 250 OK, got: {response}");
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

        assert!(response.contains("250 OK"), "expected 250 OK (discard still accepts), got: {response}");
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
}
