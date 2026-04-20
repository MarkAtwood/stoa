use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    session::{
        command::parse_command,
        commands::post::{complete_post, read_dot_terminated, DEFAULT_MAX_ARTICLE_BYTES},
        context::SessionContext,
        dispatch::dispatch,
        response::Response,
    },
};

/// Run a complete NNTP session on the given TCP stream.
///
/// Accepts a `TcpStream` and upgrades it to TLS if `config.tls` is configured.
/// Delegates to `run_session_io` for the protocol loop.
///
/// STARTTLS in-session upgrade would be integrated here (see issue l62.6.2.4):
/// after the session is running plain-text, a STARTTLS command would trigger
/// a mid-session TLS upgrade of the underlying stream before continuing the
/// command loop.
pub async fn run_session(stream: TcpStream, config: &Config) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("failed to get peer addr: {e}");
            return;
        }
    };

    match (&config.tls.cert_path, &config.tls.key_path) {
        (Some(cert), Some(key)) => {
            let acceptor = match crate::tls::load_tls_acceptor(cert, key) {
                Ok(a) => a,
                Err(e) => {
                    warn!(peer = %peer_addr, "TLS acceptor setup failed: {e}");
                    return;
                }
            };
            match crate::tls::accept_tls(&acceptor, stream).await {
                Ok(tls_stream) => {
                    run_session_io(tls_stream, peer_addr, config).await;
                }
                Err(e) => {
                    warn!(peer = %peer_addr, "TLS handshake failed: {e}");
                }
            }
        }
        _ => {
            run_session_io(stream, peer_addr, config).await;
        }
    }
}

/// Run the NNTP protocol loop on a generic async I/O stream.
///
/// Separated from `run_session` so that both plain TCP and TLS streams can
/// share the same command-dispatch logic without duplicating code.
async fn run_session_io<S>(stream: S, peer_addr: SocketAddr, config: &Config)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    info!(peer = %peer_addr, "session started");
    let start = std::time::Instant::now();

    let auth_required = config.auth.required;
    let posting_allowed = true;
    let mut ctx = SessionContext::new(peer_addr, auth_required, posting_allowed);

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

        // Trim for logging/parsing; read_line preserves the newline in line_buf.
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

        let is_quit = matches!(cmd, crate::session::command::Command::Quit);
        let is_post = matches!(cmd, crate::session::command::Command::Post);
        let resp = dispatch(&mut ctx, cmd, None);
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
