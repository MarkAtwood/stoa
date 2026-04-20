use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    session::{
        command::parse_command,
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
/// 3. Exit on QUIT (205) or connection close
/// 4. Log session end with duration
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
    let mut lines = BufReader::new(reader).lines();

    let greeting = if posting_allowed {
        Response::service_available_posting_allowed()
    } else {
        Response::service_available_posting_prohibited()
    };
    if writer.write_all(greeting.to_string().as_bytes()).await.is_err() {
        return;
    }

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                debug!(peer = %peer_addr, "client disconnected");
                break;
            }
            Err(e) => {
                warn!(peer = %peer_addr, "read error: {e}");
                break;
            }
        };

        debug!(peer = %peer_addr, cmd = %line, "received");

        let cmd = match parse_command(&line) {
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
        let resp = dispatch(&mut ctx, cmd);

        if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
            break;
        }

        if is_quit {
            break;
        }
    }

    let elapsed = start.elapsed();
    info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "session ended");
}
