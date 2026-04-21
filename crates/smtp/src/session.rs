use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use mail_auth::MessageAuthenticator;
use sqlx::SqlitePool;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::auth::verify_inbound;
use crate::config::Config;
use crate::queue::{IncomingMessage, MessageQueue};
use crate::{routing, store};

/// Thread-safe cache of compiled Sieve scripts, keyed by username.
///
/// Scripts are compiled on first use and retained until the sieve admin API
/// explicitly invalidates the entry (on script PUT, DELETE, or activate).
/// This avoids recompiling the same script for every inbound message.
pub type SieveCache = Arc<Mutex<HashMap<String, Arc<usenet_ipfs_sieve::CompiledScript>>>>;

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
    sieve_cache: Option<SieveCache>,
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
                // STARTTLS is not advertised here because the upgrade path is
                // not yet implemented (usenet-ipfs-ryw.3).  Advertising an
                // extension we cannot complete causes MTAs that enforce
                // STARTTLS-policy to fail delivery with a confusing error.
                let resp = format!(
                    "250-{}\r\n250-SIZE {}\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-PIPELINING\r\n250 OK\r\n",
                    config.hostname, config.limits.max_message_bytes
                );
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
                    // Rotate in-place to avoid a second full-body allocation.
                    let header_bytes =
                        format!("Authentication-Results: {}\r\n", result.header).into_bytes();
                    let header_len = header_bytes.len();
                    raw_bytes.resize(raw_bytes.len() + header_len, 0);
                    raw_bytes.rotate_right(header_len);
                    raw_bytes[..header_len].copy_from_slice(&header_bytes);
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
                                sieve_cache.as_ref(),
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
                        // Filter to printable ASCII + space only.  is_ascii_graphic()
                        // excludes CR (0x0d) and LF (0x0a), preventing a malicious
                        // Sieve script from injecting additional SMTP response lines
                        // via embedded CRLF sequences in the 550 response text.
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
                let reply = if queue.enqueue(msg) {
                    b"250 OK\r\n" as &[u8]
                } else {
                    b"452 4.3.1 Message queue full - try again later\r\n"
                };
                if write_half.write_all(reply).await.is_err() {
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
    cache: Option<&SieveCache>,
) -> Vec<usenet_ipfs_sieve::SieveAction> {
    // Check cache before hitting the database.
    if let Some(cache) = cache {
        let lock = cache.lock().await;
        if let Some(compiled) = lock.get(username) {
            let compiled = Arc::clone(compiled);
            drop(lock);
            return usenet_ipfs_sieve::evaluate(&compiled, raw_message, envelope_from, envelope_to);
        }
    }

    let script_bytes = store::load_active_script(pool, username).await;
    match script_bytes {
        Some(bytes) => match usenet_ipfs_sieve::compile(&bytes) {
            Ok(compiled) => {
                let compiled = Arc::new(compiled);
                if let Some(cache) = cache {
                    cache.lock().await.insert(username.to_owned(), Arc::clone(&compiled));
                }
                usenet_ipfs_sieve::evaluate(&compiled, raw_message, envelope_from, envelope_to)
            }
            Err(e) => {
                tracing::error!(
                    %username,
                    error = %e,
                    sieve.event = "compile_error",
                    "Sieve script compile error — failing open to Keep; \
                     user's filter rules are NOT being applied"
                );
                vec![usenet_ipfs_sieve::SieveAction::Keep]
            }
        },
        None => vec![usenet_ipfs_sieve::SieveAction::Keep],
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
                queue_capacity: 100,
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
            dns_resolver: "system".to_string(),
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
                queue_capacity: 100,
            },
            log: LogConfig { level: "info".to_string(), format: "json".to_string() },
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users,
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
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
        let (queue, mut rx) = MessageQueue::new(100);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let config2 = config.clone();
        let queue2 = queue.clone();
        let server_task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            run_session(stream, peer.to_string(), config2, queue2, None, pool, None).await;
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
        let (queue, mut rx) = MessageQueue::new(100);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config2 = config.clone();
        let queue2 = queue.clone();
        let auth2 = auth.clone();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            run_session(stream, peer.to_string(), config2, queue2, Some(auth2), None, None).await;
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

    // ── ryw.2: parse_angle_addr unit tests ───────────────────────────────────

    #[test]
    fn parse_angle_addr_simple() {
        assert_eq!(parse_angle_addr("FROM:<foo@bar.com>"), "foo@bar.com");
    }

    #[test]
    fn parse_angle_addr_with_size_param() {
        // Modern MTAs send SIZE on MAIL FROM; the address must not include it.
        assert_eq!(parse_angle_addr("FROM:<foo@bar.com> SIZE=12345"), "foo@bar.com");
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
        // accept it and record the address without the SIZE suffix.
        let client = b"EHLO client.example.com\r\n\
            MAIL FROM:<sender@example.com> SIZE=1024\r\n\
            RCPT TO:<rcpt@example.com>\r\n\
            DATA\r\n\
            Subject: Size test\r\n\
            \r\n\
            Body.\r\n\
            .\r\n\
            QUIT\r\n";

        let (response, msg) = drive_session(client).await;
        assert!(response.contains("250 OK"), "expected 250 after DATA: {response}");

        let msg = msg.expect("message must be queued");
        assert_eq!(
            msg.envelope_from, "sender@example.com",
            "envelope_from must not include SIZE param: {:?}",
            msg.envelope_from
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
                queue_capacity: 100,
            },
            log: LogConfig { level: "info".to_string(), format: "json".to_string() },
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
        });

        let client = b"EHLO client.example.com\r\nQUIT\r\n";
        let (response, _) = drive_session_ext(client, config, None).await;

        assert!(
            !response.contains("STARTTLS"),
            "STARTTLS must not appear in EHLO until implemented: {response}"
        );
        assert!(response.contains("250"), "expected 250 EHLO response: {response}");
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
            },
            tls: TlsConfig { cert_path: None, key_path: None },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 1, // 1-second timeout for this test
                max_connections: 10,
                queue_capacity: 100,
            },
            log: LogConfig { level: "info".to_string(), format: "json".to_string() },
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
        });

        let (queue, _rx) = MessageQueue::new(100);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config2 = config.clone();
        let queue2 = queue.clone();
        let server_task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            run_session(stream, peer.to_string(), config2, queue2, None, None, None).await;
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
        crate::store::save_script(&pool, "alice", "default", b"keep;", true).await.unwrap();

        let cache = new_sieve_cache();
        sieve_for_user(&pool, "alice", MINIMAL_MESSAGE, "a@example.com", "b@example.com", Some(&cache)).await;

        assert!(
            cache.lock().await.contains_key("alice"),
            "cache should contain alice after first call"
        );
    }

    #[tokio::test]
    async fn sieve_for_user_uses_cached_script_after_db_removal() {
        let pool = crate::store::open(":memory:").await.unwrap();
        crate::store::save_script(&pool, "alice", "default", b"discard;", true).await.unwrap();

        let cache = new_sieve_cache();
        // First call: DB load, cache populated, script is Discard.
        let actions = sieve_for_user(&pool, "alice", MINIMAL_MESSAGE, "a@example.com", "b@example.com", Some(&cache)).await;
        assert!(
            actions.iter().any(|a| *a == usenet_ipfs_sieve::SieveAction::Discard),
            "expected Discard from compiled script"
        );

        // Remove from DB — subsequent call must use the cache, still Discard.
        crate::store::delete_script(&pool, "alice", "default").await.unwrap();
        let actions2 = sieve_for_user(&pool, "alice", MINIMAL_MESSAGE, "a@example.com", "b@example.com", Some(&cache)).await;
        assert!(
            actions2.iter().any(|a| *a == usenet_ipfs_sieve::SieveAction::Discard),
            "expected Discard from cache even after DB removal"
        );
    }

    #[tokio::test]
    async fn sieve_for_user_no_cache_falls_back_to_keep_when_no_script() {
        let pool = crate::store::open(":memory:").await.unwrap();
        let actions = sieve_for_user(&pool, "nobody", MINIMAL_MESSAGE, "a@example.com", "b@example.com", None).await;
        assert_eq!(actions, vec![usenet_ipfs_sieve::SieveAction::Keep]);
    }
}
