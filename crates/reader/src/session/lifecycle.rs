use std::net::SocketAddr;
use std::sync::Arc;

use cid::Cid;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    post::{
        ipfs_write::write_article_to_ipfs,
        log_append::append_to_groups,
        pipeline::check_duplicate_msgid,
        sign::{sign_article, verify_article_sig},
    },
    session::{
        command::{parse_command, ArticleRange, ArticleRef, Command, ListSubcommand, OverArg},
        commands::{
            fetch::{article_response, xcid_response, ArticleContent},
            over::over_response,
            post::{complete_post, read_dot_terminated, DEFAULT_MAX_ARTICLE_BYTES},
        },
        context::SessionContext,
        dispatch::dispatch,
        response::Response,
        state::SessionState,
    },
    store::server_stores::ServerStores,
};

/// Run a complete NNTP session on the given TCP stream.
///
/// If `config.tls` is configured, upgrades immediately to TLS before the
/// greeting. If TLS is not configured, runs a plain-text session that
/// supports STARTTLS in-session upgrade: when the client sends STARTTLS
/// the plain loop exits, the stream is upgraded, and the command loop
/// continues on the TLS stream.
pub async fn run_session(stream: TcpStream, config: &Config, stores: Arc<ServerStores>) {
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
                run_session_io(tls_stream, peer_addr, config, false, stores).await;
            }
            Err(e) => {
                warn!(peer = %peer_addr, "TLS handshake failed: {e}");
            }
        }
    } else {
        // Plain-text session. STARTTLS not available (no TLS configured).
        // run_plain_session returns Some(stream) if STARTTLS was requested,
        // but that cannot happen here since starttls_available will be false
        // in the context and dispatch will return 580.
        let _ = run_plain_session(stream, peer_addr, config, stores).await;
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
    stores: Arc<ServerStores>,
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

        // ARTICLE <msgid>: resolve from stores before dispatching.
        if let Command::Article(Some(ArticleRef::MessageId(ref msgid))) = cmd {
            let resp = lookup_article_by_msgid(&stores, msgid).await;
            if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // ARTICLE cid:<cid>: fetch directly by CID (ADR-0007).
        if let Command::Article(Some(ArticleRef::Cid(ref cid_str))) = cmd {
            let resp = lookup_article_by_cid(&stores, cid_str).await;
            if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // XCID: return CID for current or named article (ADR-0007).
        if let Command::Xcid(ref arg) = cmd {
            let resp = handle_xcid(
                &stores,
                arg.as_deref(),
                ctx.current_group.as_ref().map(|g| g.as_str()),
                ctx.current_article_number,
            )
            .await;
            if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // XVERIFY: verify stored CID and optionally signature (ADR-0007).
        if let Command::Xverify { ref message_id, ref expected_cid, verify_sig } = cmd {
            let resp = handle_xverify(&stores, message_id, expected_cid, verify_sig).await;
            if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // GROUP: serve live article count/range from article_numbers store.
        if let Command::Group(ref name) = cmd {
            let resp = handle_group_live(&stores, &mut ctx, name).await;
            if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // LIST ACTIVE: serve live article ranges for all configured groups.
        if let Command::List(ListSubcommand::Active) = cmd {
            let resp = handle_list_active_live(&stores, &ctx).await;
            if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // OVER/XOVER: serve overview records from the overview index.
        if let Command::Over(ref arg) = cmd {
            let resp = handle_over_live(&stores, &ctx, arg.as_ref()).await;
            if write_half.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

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
            let final_resp = run_post_pipeline(&article_bytes, &stores).await;
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
    stores: Arc<ServerStores>,
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

        // ARTICLE <msgid>: resolve from stores before dispatching.
        if let Command::Article(Some(ArticleRef::MessageId(ref msgid))) = cmd {
            let resp = lookup_article_by_msgid(&stores, msgid).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // ARTICLE cid:<cid>: fetch directly by CID (ADR-0007).
        if let Command::Article(Some(ArticleRef::Cid(ref cid_str))) = cmd {
            let resp = lookup_article_by_cid(&stores, cid_str).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // XCID: return CID for current or named article (ADR-0007).
        if let Command::Xcid(ref arg) = cmd {
            let resp = handle_xcid(
                &stores,
                arg.as_deref(),
                ctx.current_group.as_ref().map(|g| g.as_str()),
                ctx.current_article_number,
            )
            .await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // XVERIFY: verify stored CID and optionally signature (ADR-0007).
        if let Command::Xverify { ref message_id, ref expected_cid, verify_sig } = cmd {
            let resp = handle_xverify(&stores, message_id, expected_cid, verify_sig).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // GROUP: serve live article count/range from article_numbers store.
        if let Command::Group(ref name) = cmd {
            let resp = handle_group_live(&stores, &mut ctx, name).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // LIST ACTIVE: serve live article ranges for all configured groups.
        if let Command::List(ListSubcommand::Active) = cmd {
            let resp = handle_list_active_live(&stores, &ctx).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        // OVER/XOVER: serve overview records from the overview index.
        if let Command::Over(ref arg) = cmd {
            let resp = handle_over_live(&stores, &ctx, arg.as_ref()).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

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

            let final_resp = run_post_pipeline(&article_bytes, &stores).await;
            if writer.write_all(final_resp.to_string().as_bytes()).await.is_err() {
                break;
            }
        }
    }

    let elapsed = start.elapsed();
    info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "session ended");
}

/// Validate and store a POSTed article through the full pipeline.
///
/// Steps:
/// 1. Validate headers via `complete_post` (sync).
/// 2. Check for duplicate message-id.
/// 3. Sign the article with the operator key.
/// 4. Write signed bytes to IPFS and record in msgid_map.
/// 5. Append to group logs and assign local article numbers.
///
/// Returns 240 on success or a 441 error response on failure.
async fn run_post_pipeline(article_bytes: &[u8], stores: &ServerStores) -> Response {
    // Step 1: Validate headers.
    let validation = complete_post(article_bytes, DEFAULT_MAX_ARTICLE_BYTES, None);
    if validation.code != 240 {
        return validation;
    }

    // Extract Message-ID and Newsgroups from the article headers.
    let (message_id, newsgroups) = match extract_post_metadata(article_bytes) {
        Ok(meta) => meta,
        Err(resp) => return resp,
    };

    // Step 2: Duplicate check.
    if let Err(resp) = check_duplicate_msgid(&stores.msgid_map, &message_id).await {
        return resp;
    }

    // Step 3: Sign the article.
    let signed_bytes = sign_article(&stores.signing_key, article_bytes);

    // Step 4: Write to IPFS and record msgid → CID.
    let cid = match write_article_to_ipfs(
        stores.ipfs_store.as_ref(),
        &stores.msgid_map,
        &signed_bytes,
        &message_id,
    )
    .await
    {
        Ok(cid) => cid,
        Err(resp) => return resp,
    };

    // Step 5: Append to group logs and assign article numbers.
    let mut clock = stores.clock.lock().await;
    if let Err(resp) = append_to_groups(
        stores.log_storage.as_ref(),
        &stores.article_numbers,
        &mut clock,
        &cid,
        &[],
        &newsgroups,
    )
    .await
    {
        return resp;
    }
    drop(clock);

    Response::new(240, "Article received OK")
}

/// Look up an article by Message-ID from stores and return a 220/430 response.
async fn lookup_article_by_msgid(stores: &ServerStores, msgid: &str) -> Response {
    let cid = match stores.msgid_map.lookup_by_msgid(msgid).await {
        Ok(Some(c)) => c,
        Ok(None) => return Response::no_article_with_message_id(),
        Err(e) => {
            warn!("msgid_map lookup error for {msgid}: {e}");
            return Response::new(500, "Internal error: storage lookup failed");
        }
    };

    let raw_bytes = match stores.ipfs_store.get_raw_block(&cid).await {
        Ok(b) => b,
        Err(e) => {
            warn!("IPFS get_raw_block error for cid {cid}: {e}");
            return Response::new(500, "Internal error: IPFS retrieval failed");
        }
    };

    // Split the stored bytes into header and body sections.
    let (header_bytes, body_bytes) = split_article(&raw_bytes);

    let content = ArticleContent {
        article_number: 0,
        message_id: msgid.to_string(),
        header_bytes,
        body_bytes,
        cid: Some(cid),
    };

    article_response(&content)
}

/// Split raw article bytes at the blank-line separator.
///
/// Returns `(header_bytes, body_bytes)`. Both slices exclude the blank line
/// itself. If no separator is found, the entire input is treated as headers.
fn split_article(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Look for \r\n\r\n first (canonical NNTP), then \n\n.
    for i in 0..bytes.len().saturating_sub(3) {
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return (bytes[..i].to_vec(), bytes[i + 4..].to_vec());
        }
    }
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i..].starts_with(b"\n\n") {
            return (bytes[..i].to_vec(), bytes[i + 2..].to_vec());
        }
    }
    (bytes.to_vec(), vec![])
}

/// Extract `Message-ID` and `Newsgroups` from article header bytes.
///
/// Returns `Err(441 response)` if either field is missing or invalid.
fn extract_post_metadata(
    article_bytes: &[u8],
) -> Result<(String, Vec<usenet_ipfs_core::article::GroupName>), Response> {
    // Find the header section.
    let header_end = find_header_end(article_bytes).unwrap_or(article_bytes.len());
    let header_section = &article_bytes[..header_end];
    let headers = String::from_utf8_lossy(header_section);

    let message_id = extract_header_value(&headers, "Message-ID")
        .ok_or_else(|| Response::new(441, "441 Missing Message-ID header"))?;

    let newsgroups_val = extract_header_value(&headers, "Newsgroups")
        .ok_or_else(|| Response::new(441, "441 Missing Newsgroups header"))?;

    let newsgroups: Vec<usenet_ipfs_core::article::GroupName> = newsgroups_val
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            usenet_ipfs_core::article::GroupName::new(s)
                .map_err(|_| Response::new(441, format!("441 Invalid group name: {s}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if newsgroups.is_empty() {
        return Err(Response::new(441, "441 Newsgroups header is empty"));
    }

    Ok((message_id, newsgroups))
}

/// Return the byte offset of the start of the blank line that separates
/// headers from body (`\r\n\r\n` or `\n\n`).
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return Some(i + 2);
        }
        if bytes[i..].starts_with(b"\n\n") {
            return Some(i + 1);
        }
    }
    None
}

/// Extract the trimmed value of the first matching header field, or `None`.
fn extract_header_value(headers: &str, name: &str) -> Option<String> {
    let prefix_colon = format!("{}:", name.to_ascii_lowercase());
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with(&prefix_colon) {
            let value = line[prefix_colon.len()..].trim().to_string();
            return Some(value);
        }
    }
    None
}

// ── CID extension handlers (ADR-0007) ─────────────────────────────────────

/// XCID [<message-id>]: return the CID for the current or named article.
///
/// If a message-id argument is supplied, look it up directly.
/// If no argument, use the current (group, article_number) from session state.
async fn handle_xcid(
    stores: &ServerStores,
    arg: Option<&str>,
    current_group: Option<&str>,
    current_number: Option<u64>,
) -> Response {
    let cid = if let Some(msgid) = arg {
        match stores.msgid_map.lookup_by_msgid(msgid).await {
            Ok(Some(c)) => c,
            Ok(None) => return Response::no_article_with_message_id(),
            Err(e) => {
                warn!("XCID msgid lookup error: {e}");
                return Response::program_fault();
            }
        }
    } else {
        let group = match current_group {
            Some(g) => g,
            None => return Response::no_newsgroup_selected(),
        };
        let number = match current_number {
            Some(n) => n,
            None => return Response::current_article_invalid(),
        };
        match stores.article_numbers.lookup_cid(group, number).await {
            Ok(Some(c)) => c,
            Ok(None) => return Response::current_article_invalid(),
            Err(e) => {
                warn!("XCID article_numbers lookup error: {e}");
                return Response::program_fault();
            }
        }
    };
    xcid_response(&cid)
}

/// XVERIFY <message-id> <expected-cid> [SIG]: verify CID match, optionally
/// also re-verify the operator ed25519 signature.
///
/// Response codes:
/// - 291: verified OK
/// - 430: message-id not found
/// - 541: CID mismatch
/// - 542: signature verification failed
async fn handle_xverify(
    stores: &ServerStores,
    message_id: &str,
    expected_cid: &str,
    verify_sig: bool,
) -> Response {
    let actual_cid = match stores.msgid_map.lookup_by_msgid(message_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Response::no_article_with_message_id(),
        Err(e) => {
            warn!("XVERIFY msgid lookup error: {e}");
            return Response::program_fault();
        }
    };

    if actual_cid.to_string() != expected_cid {
        return Response::new(541, "CID mismatch");
    }

    if verify_sig {
        let raw_bytes = match stores.ipfs_store.get_raw_block(&actual_cid).await {
            Ok(b) => b,
            Err(e) => {
                warn!("XVERIFY IPFS get error: {e}");
                return Response::program_fault();
            }
        };
        let pubkey = stores.signing_key.verifying_key();
        if verify_article_sig(&pubkey, &raw_bytes).is_err() {
            return Response::new(542, "Signature verification failed");
        }
    }

    Response::new(291, "Verified OK")
}

// ── Live GROUP / LIST ACTIVE / OVER handlers ──────────────────────────────

/// GROUP groupname: select a group and return live article count and range.
///
/// Returns 411 if the group is not in the configured known_groups list.
/// Returns 211 with live (low, high, count) from the article_numbers store.
async fn handle_group_live(
    stores: &ServerStores,
    ctx: &mut SessionContext,
    name: &str,
) -> Response {
    if !ctx.known_groups.iter().any(|g| g.name == name) {
        return Response::no_such_newsgroup();
    }
    let group_name = match usenet_ipfs_core::article::GroupName::new(name) {
        Ok(g) => g,
        Err(_) => return Response::no_such_newsgroup(),
    };
    let (low, high) = match stores.article_numbers.group_range(name).await {
        Ok(r) => r,
        Err(e) => {
            warn!("group_range error for {name}: {e}");
            return Response::program_fault();
        }
    };
    let count = if low <= high { high - low + 1 } else { 0 };
    ctx.current_group = Some(group_name);
    ctx.current_article_number = if count > 0 { Some(low) } else { None };
    ctx.state = SessionState::GroupSelected;
    Response::group_selected(name, count, low, high)
}

/// LIST ACTIVE: return live article ranges for all configured groups.
async fn handle_list_active_live(stores: &ServerStores, ctx: &SessionContext) -> Response {
    let mut body = Vec::with_capacity(ctx.known_groups.len());
    for group_info in &ctx.known_groups {
        let (low, high) = match stores.article_numbers.group_range(&group_info.name).await {
            Ok(r) => r,
            Err(e) => {
                warn!("group_range error for {}: {e}", group_info.name);
                (1, 0)
            }
        };
        let flag = if group_info.posting_allowed { 'y' } else { 'n' };
        body.push(format!("{} {} {} {}", group_info.name, high, low, flag));
    }
    Response::list_active(body)
}

/// OVER/XOVER [range]: serve overview records from the SQLite overview index.
async fn handle_over_live(
    stores: &ServerStores,
    ctx: &SessionContext,
    arg: Option<&OverArg>,
) -> Response {
    if !ctx.state.group_selected() {
        return Response::no_newsgroup_selected();
    }
    let group = match ctx.current_group.as_ref() {
        Some(g) => g.as_str().to_string(),
        None => return Response::no_newsgroup_selected(),
    };

    let (low, high) = match arg {
        None => {
            let n = match ctx.current_article_number {
                Some(n) => n,
                None => return Response::current_article_invalid(),
            };
            (n, n)
        }
        Some(OverArg::Range(r)) => match r {
            ArticleRange::Single(n) => (*n, *n),
            ArticleRange::From(n) => {
                let (_, g_high) = match stores.article_numbers.group_range(&group).await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("OVER group_range error: {e}");
                        return Response::program_fault();
                    }
                };
                (*n, g_high)
            }
            ArticleRange::Range(lo, hi) => (*lo, *hi),
        },
        Some(OverArg::MessageId(_)) => {
            return over_response(std::iter::empty());
        }
    };

    let records = match stores.overview_store.query_range(&group, low, high).await {
        Ok(r) => r,
        Err(e) => {
            warn!("OVER query_range error: {e}");
            return Response::program_fault();
        }
    };
    over_response(records)
}

/// ARTICLE cid:<cid>: fetch an article directly by its IPFS CID.
///
/// Returns 501 for an unparseable CID, 430 if the block is not found,
/// or 220 with the article on success.
async fn lookup_article_by_cid(stores: &ServerStores, cid_str: &str) -> Response {
    let cid: Cid = match cid_str.parse() {
        Ok(c) => c,
        Err(_) => return Response::syntax_error(),
    };
    let raw_bytes = match stores.ipfs_store.get_raw_block(&cid).await {
        Ok(b) => b,
        Err(_) => return Response::no_article_with_message_id(),
    };
    let (header_bytes, body_bytes) = split_article(&raw_bytes);
    let headers_str = String::from_utf8_lossy(&header_bytes);
    let message_id = extract_header_value(&headers_str, "Message-ID").unwrap_or_default();
    let content = ArticleContent {
        article_number: 0,
        message_id,
        header_bytes,
        body_bytes,
        cid: Some(cid),
    };
    article_response(&content)
}
