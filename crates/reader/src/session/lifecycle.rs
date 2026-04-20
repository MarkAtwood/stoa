use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    session::{
        command::{parse_command, Command},
        commands::post::{complete_post, read_dot_terminated, DEFAULT_MAX_ARTICLE_BYTES},
        context::SessionContext,
        dispatch::dispatch,
        response::Response,
    },
};

/// Run a complete NNTP session on the given TCP stream.
///
/// If `config.tls` is configured, upgrades immediately to TLS before the
/// greeting. If TLS is not configured, runs a plain-text session that
/// supports STARTTLS in-session upgrade: when the client sends STARTTLS
/// the plain loop exits, the stream is upgraded, and the command loop
/// continues on the TLS stream.
pub async fn run_session(stream: TcpStream, config: &Config) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("failed to get peer addr: {e}");
            return;
        }
    };

    let tls_configured = config.tls.cert_path.is_some() && config.tls.key_path.is_some();

    if tls_configured {
        let cert = config.tls.cert_path.as_deref().unwrap();
        let key = config.tls.key_path.as_deref().unwrap();
        let acceptor = match crate::tls::load_tls_acceptor(cert, key) {
            Ok(a) => a,
            Err(e) => {
                warn!(peer = %peer_addr, "TLS acceptor setup failed: {e}");
                return;
            }
        };
        match crate::tls::accept_tls(&acceptor, stream).await {
            Ok(tls_stream) => {
                // Already TLS; STARTTLS not available.
                run_session_io(tls_stream, peer_addr, config, false).await;
            }
            Err(e) => {
                warn!(peer = %peer_addr, "TLS handshake failed: {e}");
            }
        }
    } else {
        // Plain-text session. STARTTLS not available (no TLS configured).
        // run_plain_session returns Some(stream) if STARTTLS was requested,
        // but that cannot happen here since starttls_available will be false.
        let _ = run_plain_session(stream, peer_addr, config).await;
    }
}

/// Run a plain-text NNTP session.
///
/// Returns the original `TcpStream` if the client sent STARTTLS, so the
/// caller can upgrade it. Returns `None` if the session ended normally.
///
/// Note: STARTTLS requires TLS to be configured; without cert/key this
/// function never returns `Some` because `starttls_available` will be false
/// in the context and dispatch will return 580.
async fn run_plain_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: &Config,
) -> Option<TcpStream> {
    info!(peer = %peer_addr, "plain session started");
    let start = std::time::Instant::now();

    // STARTTLS is available on a plain connection only when TLS is configured.
    let starttls_available =
        config.tls.cert_path.is_some() && config.tls.key_path.is_some();

    let auth_required = config.auth.required;
    let posting_allowed = true;
    let mut ctx =
        SessionContext::new(peer_addr, auth_required, posting_allowed, starttls_available);

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = if posting_allowed {
        Response::service_available_posting_allowed()
    } else {
        Response::service_available_posting_prohibited()
    };
    if write_half.write_all(greeting.to_string().as_bytes()).await.is_err() {
        let elapsed = start.elapsed();
        info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "plain session ended");
        return None;
    }

    let mut line_buf = String::new();
    let mut do_starttls = false;

    loop {
        line_buf.clear();
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

        let line = line_buf.trim_end_matches(['\r', '\n']);
        debug!(peer = %peer_addr, cmd = %line, "received");

        let cmd = match parse_command(line) {
            Ok(c) => c,
            Err(_) => {
                let resp = Response::unknown_command();
                if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
                    break;
                }
                continue;
            }
        };

        let is_quit = matches!(cmd, Command::Quit);
        let is_post = matches!(cmd, Command::Post);
        let is_starttls = matches!(cmd, Command::StartTls);
        let cmd_label = line.split_whitespace().next().unwrap_or("UNKNOWN").to_uppercase();
        let cmd_start = std::time::Instant::now();
        let resp = dispatch(&mut ctx, cmd, &config.auth, None);
        crate::metrics::NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&[cmd_label.as_str()])
            .observe(cmd_start.elapsed().as_secs_f64());
        let resp_code = resp.code;

        if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
            break;
        }

        if is_quit {
            break;
        }

        // 382 means TLS upgrade was accepted; exit the plain loop.
        if is_starttls && resp_code == 382 {
            do_starttls = true;
            break;
        }

        if is_post && resp_code == 340 {
            let article_bytes = match read_dot_terminated(&mut reader).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(peer = %peer_addr, "post read error: {e}");
                    break;
                }
            };
            let final_resp = complete_post(&article_bytes, DEFAULT_MAX_ARTICLE_BYTES, None);
            if write_half.write_all(final_resp.to_string().as_bytes()).await.is_err() {
                break;
            }
        }
    }

    let elapsed = start.elapsed();
    info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "plain session ended");

    if do_starttls {
        let read_half = reader.into_inner();
        match write_half.reunite(read_half) {
            Ok(stream) => Some(stream),
            Err(e) => {
                warn!(peer = %peer_addr, "stream reunite failed: {e}");
                None
            }
        }
    } else {
        None
    }
}

/// Run the NNTP protocol loop on a generic async I/O stream.
///
/// `starttls_available`: false for TLS streams (no double-upgrade) and for
/// plain streams where STARTTLS was already handled by `run_plain_session`.
async fn run_session_io<S>(
    stream: S,
    peer_addr: SocketAddr,
    config: &Config,
    starttls_available: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    info!(peer = %peer_addr, "session started");
    let start = std::time::Instant::now();

    let auth_required = config.auth.required;
    let posting_allowed = true;
    let mut ctx =
        SessionContext::new(peer_addr, auth_required, posting_allowed, starttls_available);

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let greeting = if posting_allowed {
        Response::service_available_posting_allowed()
    } else {
        Response::service_available_posting_prohibited()
    };
    if writer.write_all(greeting.to_string().as_bytes()).await.is_err() {
        return;
    }

    let mut line_buf = String::new();

    loop {
        line_buf.clear();
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

        let line = line_buf.trim_end_matches(['\r', '\n']);
        debug!(peer = %peer_addr, cmd = %line, "received");

        let cmd = match parse_command(line) {
            Ok(c) => c,
            Err(_) => {
                let resp = Response::unknown_command();
                if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                    break;
                }
                continue;
            }
        };

        let is_quit = matches!(cmd, Command::Quit);
        let is_post = matches!(cmd, Command::Post);
        let cmd_label = line.split_whitespace().next().unwrap_or("UNKNOWN").to_uppercase();
        let cmd_start = std::time::Instant::now();
        let resp = dispatch(&mut ctx, cmd, &config.auth, None);
        crate::metrics::NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&[cmd_label.as_str()])
            .observe(cmd_start.elapsed().as_secs_f64());
        let resp_code = resp.code;

        if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
            break;
        }

        if is_quit {
            break;
        }

        // POST two-phase completion: if dispatch returned 340, read the article.
        if is_post && resp_code == 340 {
            let article_bytes = match read_dot_terminated(&mut reader).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(peer = %peer_addr, "post read error: {e}");
                    break;
                }
            };

            let final_resp = complete_post(&article_bytes, DEFAULT_MAX_ARTICLE_BYTES, None);
            if writer.write_all(final_resp.to_string().as_bytes()).await.is_err() {
                break;
            }
        }
    }

    let elapsed = start.elapsed();
    info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "session ended");
}
