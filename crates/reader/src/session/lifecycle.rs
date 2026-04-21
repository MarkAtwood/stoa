use std::net::SocketAddr;
use std::sync::Arc;

use cid::Cid;
use mailparse::parse_headers;
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
    store::{overview::extract_overview, server_stores::ServerStores},
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
    let starttls_available = config.tls.cert_path.is_some() && config.tls.key_path.is_some();

    let auth_required = config.auth.required;
    let posting_allowed = true;
    let mut ctx = SessionContext::new(
        peer_addr,
        auth_required,
        posting_allowed,
        starttls_available,
    );

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let greeting = if posting_allowed {
        Response::service_available_posting_allowed()
    } else {
        Response::service_available_posting_prohibited()
    };
    if write_half
        .write_all(greeting.to_string().as_bytes())
        .await
        .is_err()
    {
        let elapsed = start.elapsed();
        info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "plain session ended");
        return None;
    }

    let do_starttls =
        run_command_loop(&mut reader, &mut write_half, &mut ctx, peer_addr, config, &stores).await;

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

/// Execute the NNTP command loop on a generic async read/write pair.
///
/// Returns `true` if the client successfully negotiated STARTTLS (response
/// code 382) so the caller can upgrade the stream. Returns `false` for all
/// normal session ends: QUIT, EOF, read/write error, or idle timeout.
async fn run_command_loop<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    ctx: &mut SessionContext,
    peer_addr: SocketAddr,
    config: &Config,
    stores: &ServerStores,
) -> bool
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut line_buf = String::new();
    let cmd_timeout = std::time::Duration::from_secs(config.limits.command_timeout_secs);

    loop {
        line_buf.clear();
        let n = match tokio::time::timeout(cmd_timeout, reader.read_line(&mut line_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                warn!(peer = %peer_addr, "read error: {e}");
                return false;
            }
            Err(_) => {
                let resp = Response::new(400, "Timeout - closing connection");
                let _ = writer.write_all(resp.to_string().as_bytes()).await;
                return false;
            }
        };

        if n == 0 {
            debug!(peer = %peer_addr, "client disconnected");
            return false;
        }

        let line = line_buf.trim_end_matches(['\r', '\n']);
        debug!(peer = %peer_addr, cmd = %line, "received");

        let cmd = match parse_command(line) {
            Ok(c) => c,
            Err(_) => {
                let resp = Response::unknown_command();
                if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                    return false;
                }
                continue;
            }
        };

        // ARTICLE <msgid>: resolve from stores before dispatching.
        if let Command::Article(Some(ArticleRef::MessageId(ref msgid))) = cmd {
            let resp = lookup_article_by_msgid(stores, msgid).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return false;
            }
            continue;
        }

        // ARTICLE cid:<cid>: fetch directly by CID (ADR-0007).
        if let Command::Article(Some(ArticleRef::Cid(ref cid_str))) = cmd {
            let resp = lookup_article_by_cid(stores, cid_str).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return false;
            }
            continue;
        }

        // XCID: return CID for current or named article (ADR-0007).
        if let Command::Xcid(ref arg) = cmd {
            let resp = handle_xcid(
                stores,
                arg.as_deref(),
                ctx.current_group.as_ref().map(|g| g.as_str()),
                ctx.current_article_number,
            )
            .await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return false;
            }
            continue;
        }

        // XVERIFY: verify stored CID and optionally signature (ADR-0007).
        if let Command::Xverify {
            ref message_id,
            ref expected_cid,
            verify_sig,
        } = cmd
        {
            let resp = handle_xverify(stores, message_id, expected_cid, verify_sig).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return false;
            }
            continue;
        }

        // GROUP: serve live article count/range from article_numbers store.
        if let Command::Group(ref name) = cmd {
            let resp = handle_group_live(stores, ctx, name).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return false;
            }
            continue;
        }

        // LIST ACTIVE: serve live article ranges for all configured groups.
        if let Command::List(ListSubcommand::Active) = cmd {
            let resp = handle_list_active_live(stores, ctx).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return false;
            }
            continue;
        }

        // OVER/XOVER: serve overview records from the overview index.
        if let Command::Over(ref arg) = cmd {
            let resp = handle_over_live(stores, ctx, arg.as_ref()).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return false;
            }
            continue;
        }

        // AUTHINFO PASS: async bcrypt credential check via CredentialStore.
        if let Command::AuthinfoPass(ref password) = cmd {
            let username = match ctx.pending_auth_user.take() {
                Some(u) => u,
                None => {
                    let resp = Response::authentication_out_of_sequence();
                    if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                        return false;
                    }
                    continue;
                }
            };
            let accepted = if config.auth.is_dev_mode() {
                true
            } else {
                stores.credential_store.check(&username, password).await
            };
            if accepted {
                ctx.state = SessionState::Active;
                ctx.authenticated_user = Some(username);
            }
            let resp = if accepted {
                Response::authentication_accepted()
            } else {
                Response::authentication_failed()
            };
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return false;
            }
            continue;
        }

        let is_quit = matches!(cmd, Command::Quit);
        let is_post = matches!(cmd, Command::Post);
        let is_starttls = matches!(cmd, Command::StartTls);
        let cmd_label = line
            .split_whitespace()
            .next()
            .unwrap_or("UNKNOWN")
            .to_uppercase();
        let cmd_start = std::time::Instant::now();
        let resp = dispatch(ctx, cmd, &config.auth, None);
        crate::metrics::NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&[cmd_label.as_str()])
            .observe(cmd_start.elapsed().as_secs_f64());
        let resp_code = resp.code;

        if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
            return false;
        }

        if is_quit {
            return false;
        }

        // STARTTLS upgrade: signal caller to wrap the stream in TLS.
        if is_starttls && resp_code == 382 {
            return true;
        }

        // POST two-phase completion: if dispatch returned 340, read the article.
        if is_post && resp_code == 340 {
            let article_bytes = match read_dot_terminated(reader).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(peer = %peer_addr, "post read error: {e}");
                    return false;
                }
            };

            let final_resp = run_post_pipeline(&article_bytes, stores).await;
            if writer
                .write_all(final_resp.to_string().as_bytes())
                .await
                .is_err()
            {
                return false;
            }
        }
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
    let mut ctx = SessionContext::new(
        peer_addr,
        auth_required,
        posting_allowed,
        starttls_available,
    );

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let greeting = if posting_allowed {
        Response::service_available_posting_allowed()
    } else {
        Response::service_available_posting_prohibited()
    };
    if writer
        .write_all(greeting.to_string().as_bytes())
        .await
        .is_err()
    {
        return;
    }

    run_command_loop(&mut reader, &mut writer, &mut ctx, peer_addr, config, &stores).await;

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
    if let Err(resp) = complete_post(article_bytes, DEFAULT_MAX_ARTICLE_BYTES, None) {
        return resp;
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
    let append_result = match append_to_groups(
        stores.log_storage.as_ref(),
        &stores.article_numbers,
        &mut clock,
        &cid,
        &[],
        &newsgroups,
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    drop(clock);

    // Step 6: Index overview fields for each assigned (group, article_number).
    let (header_bytes, body_bytes) = split_article(&signed_bytes);
    let mut overview = extract_overview(&header_bytes, &body_bytes);
    for (group, article_number) in &append_result.assignments {
        overview.article_number = *article_number;
        if let Err(e) = stores.overview_store.insert(group, &overview).await {
            warn!("overview insert failed for {group}/{article_number}: {e}");
        }
    }

    Response::new(240, "Article received OK")
}

/// Look up an article by Message-ID from stores and return a 220/430 response.
async fn lookup_article_by_msgid(stores: &ServerStores, msgid: &str) -> Response {
    let cid = match stores.msgid_map.lookup_by_msgid(msgid).await {
        Ok(Some(c)) => c,
        Ok(None) => return Response::no_article_with_message_id(),
        Err(e) => {
            warn!("msgid_map lookup error for {msgid}: {e}");
            return Response::program_fault();
        }
    };

    let raw_bytes = match stores.ipfs_store.get_raw_block(&cid).await {
        Ok(b) => b,
        Err(e) => {
            warn!("IPFS get_raw_block error for cid {cid}: {e}");
            return Response::program_fault();
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
/// Uses `mailparse::parse_headers` so that RFC 5322 folded header values
/// (continuation lines starting with whitespace) are unfolded correctly.
///
/// Returns `Err(441 response)` if either field is missing or invalid.
fn extract_post_metadata(
    article_bytes: &[u8],
) -> Result<(String, Vec<usenet_ipfs_core::article::GroupName>), Response> {
    let header_end = find_header_end(article_bytes).unwrap_or(article_bytes.len());
    let header_section = &article_bytes[..header_end];

    let (parsed, _) = parse_headers(header_section)
        .map_err(|_| Response::new(441, "Could not parse article headers"))?;

    let mut message_id: Option<String> = None;
    let mut newsgroups_val: Option<String> = None;
    for hdr in &parsed {
        let key = hdr.get_key().to_ascii_lowercase();
        if key == "message-id" && message_id.is_none() {
            message_id = Some(hdr.get_value());
        } else if key == "newsgroups" && newsgroups_val.is_none() {
            newsgroups_val = Some(hdr.get_value());
        }
    }

    let message_id =
        message_id.ok_or_else(|| Response::new(441, "Missing Message-ID header"))?;
    let newsgroups_val =
        newsgroups_val.ok_or_else(|| Response::new(441, "Missing Newsgroups header"))?;

    let newsgroups: Vec<usenet_ipfs_core::article::GroupName> = newsgroups_val
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            usenet_ipfs_core::article::GroupName::new(s)
                .map_err(|_| Response::new(441, format!("Invalid group name: {s}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if newsgroups.is_empty() {
        return Err(Response::new(441, "Newsgroups header is empty"));
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
/// Returns 411 for an invalid group name. Returns 211 with live (low, high,
/// count) from the article_numbers store for any valid name (count=0 for
/// groups that have no articles yet).
async fn handle_group_live(
    stores: &ServerStores,
    ctx: &mut SessionContext,
    name: &str,
) -> Response {
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

/// LIST ACTIVE: return live article ranges for all groups that have articles.
async fn handle_list_active_live(stores: &ServerStores, _ctx: &SessionContext) -> Response {
    let groups = match stores.article_numbers.list_groups().await {
        Ok(g) => g,
        Err(e) => {
            warn!("list_groups error: {e}");
            return Response::program_fault();
        }
    };
    let body: Vec<String> = groups
        .into_iter()
        .map(|(name, low, high)| format!("{} {} {} y", name, high, low))
        .collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::server_stores::ServerStores;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Return the current time formatted as RFC 2822 (e.g. `Mon, 20 Apr 2026 12:00:00 +0000`).
    fn now_rfc2822() -> String {
        const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs() as i64;
        let sec = (s % 60) as u32;
        let min = ((s / 60) % 60) as u32;
        let hour = ((s / 3600) % 24) as u32;
        let days_since_epoch = s / 86400;
        let wday = ((days_since_epoch % 7 + 7) % 7) as usize;
        let z = days_since_epoch + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
            DAYS[wday],
            d,
            MONTHS[(m - 1) as usize],
            y,
            hour,
            min,
            sec
        )
    }

    fn minimal_article(newsgroups: &str, subject: &str, msgid: &str) -> Vec<u8> {
        let date = now_rfc2822();
        format!(
            "Newsgroups: {newsgroups}\r\n\
             From: poster@example.com\r\n\
             Subject: {subject}\r\n\
             Date: {date}\r\n\
             Message-ID: {msgid}\r\n\
             \r\n\
             Article body.\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn post_then_over_returns_article() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "Integration Test", "<integ@test.example>");

        let resp = run_post_pipeline(&article, &stores).await;
        assert_eq!(
            resp.code, 240,
            "POST pipeline must return 240; got: {}",
            resp.text
        );

        let records = stores
            .overview_store
            .query_range("comp.test", 1, 10)
            .await
            .unwrap();
        assert_eq!(
            records.len(),
            1,
            "overview index must have exactly one record"
        );
        assert_eq!(records[0].article_number, 1);
        assert_eq!(records[0].subject, "Integration Test");
        assert_eq!(records[0].message_id, "<integ@test.example>");
    }
}
