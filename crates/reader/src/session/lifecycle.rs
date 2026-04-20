use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
/// # Flow
/// 1. Send 200/201 greeting
/// 2. Command loop: read line, parse, dispatch, write response
/// 3. For POST with 340 response: read dot-terminated article, validate, write final response
/// 4. Exit on QUIT (205) or connection close
/// 5. Log session end with duration
pub async fn run_session(stream: TcpStream, config: &Config) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("failed to get peer addr: {e}");
            return;
        }
    };

    info!(peer = %peer_addr, "session started");
    let start = std::time::Instant::now();

    let auth_required = config.auth.required;
    let posting_allowed = true;
    let mut ctx = SessionContext::new(peer_addr, auth_required, posting_allowed);

    let (reader, mut writer) = stream.into_split();
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
