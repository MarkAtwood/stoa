use std::net::SocketAddr;
use std::sync::Arc;

use cid::Cid;
use mailparse::parse_headers;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use usenet_ipfs_core::ArticleRootNode;

use crate::{
    config::Config,
    post::{
        find_header_boundary,
        ipfs_write::{write_ipld_article_to_ipfs, IpfsBlockStore},
        log_append::append_to_groups,
        pipeline::check_duplicate_msgid,
        sign::{sign_article, verify_article_sig},
    },
    search::{ArticleIndexRequest, SearchError},
    session::{
        command::{
            parse_command, ArticleRange, ArticleRef, Command, ListSubcommand, OverArg, SearchKey,
        },
        commands::{
            fetch::{article_response, xcid_response, ArticleContent},
            hdr::{extract_field, hdr_response, HdrRecord},
            list::GroupInfo,
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
/// `is_tls`: true for NNTPS connections (implicit TLS, accepted by the
/// caller before this function is invoked). false for plain connections
/// on port 119 — no in-session TLS upgrade is available.
pub async fn run_session(
    stream: TcpStream,
    is_tls: bool,
    config: &Config,
    stores: Arc<ServerStores>,
) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("failed to get peer addr: {e}");
            return;
        }
    };

    if is_tls {
        let cert = config.tls.cert_path.as_deref().unwrap_or("");
        let key = config.tls.key_path.as_deref().unwrap_or("");
        let acceptor = match crate::tls::load_tls_acceptor(cert, key) {
            Ok(a) => a,
            Err(e) => {
                warn!(peer = %peer_addr, "TLS acceptor setup failed: {e}");
                return;
            }
        };
        match crate::tls::accept_tls(&acceptor, stream).await {
            Ok(tls_stream) => {
                let (client_cert_fp, client_cert_der) =
                    crate::tls::extract_client_cert_data(&tls_stream);
                run_session_io(
                    tls_stream,
                    peer_addr,
                    config,
                    true,
                    client_cert_fp,
                    client_cert_der,
                    stores,
                )
                .await;
            }
            Err(e) => {
                warn!(peer = %peer_addr, "TLS handshake failed: {e}");
            }
        }
    } else {
        run_plain_session(stream, peer_addr, config, stores).await;
    }
}

/// Populate `ctx.known_groups` from the article_numbers store.
///
/// Called once at the start of each session so that GROUP and LIST commands
/// can return 411 for newsgroups not currently carried by this server.
/// Groups that have at least one article are considered "carried".
async fn load_known_groups(stores: &ServerStores, ctx: &mut SessionContext) {
    match stores.article_numbers.list_groups().await {
        Ok(groups) => {
            ctx.known_groups = groups
                .into_iter()
                .map(|(name, low, high)| GroupInfo {
                    name,
                    low,
                    high,
                    posting_allowed: true,
                    description: String::new(),
                })
                .collect();
        }
        Err(e) => {
            warn!("load_known_groups: article_numbers.list_groups failed: {e}");
        }
    }
}

/// Run a plain-text NNTP session (port 119, no TLS).
///
/// AUTHINFO returns 483 if `auth.required = true` — callers must connect
/// to the NNTPS port (563) for authenticated sessions.
async fn run_plain_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: &Config,
    stores: Arc<ServerStores>,
) {
    info!(peer = %peer_addr, "plain session started");
    let start = std::time::Instant::now();

    let auth_required = config.auth.required;
    let posting_allowed = true;
    let mut ctx = SessionContext::new(peer_addr, auth_required, posting_allowed, false);
    load_known_groups(&stores, &mut ctx).await;

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
        return;
    }

    run_command_loop(
        &mut reader,
        &mut write_half,
        &mut ctx,
        peer_addr,
        config,
        &stores,
    )
    .await;

    let elapsed = start.elapsed();
    info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "plain session ended");
}

/// Execute the NNTP command loop on a generic async read/write pair.
///
/// Runs until QUIT, EOF, read/write error, or idle timeout.
async fn run_command_loop<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    ctx: &mut SessionContext,
    peer_addr: SocketAddr,
    config: &Config,
    stores: &ServerStores,
) where
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
                return;
            }
            Err(_) => {
                let resp = Response::new(400, "Timeout - closing connection");
                let _ = writer.write_all(resp.to_string().as_bytes()).await;
                return;
            }
        };

        if n == 0 {
            debug!(peer = %peer_addr, "client disconnected");
            return;
        }

        let line = line_buf.trim_end_matches(['\r', '\n']);
        debug!(peer = %peer_addr, cmd = %line, "received");

        let cmd = match parse_command(line) {
            Ok(c) => c,
            Err(_) => {
                let resp = Response::unknown_command();
                if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                    return;
                }
                continue;
            }
        };

        // ARTICLE <msgid>: resolve from stores before dispatching.
        if let Command::Article(Some(ArticleRef::MessageId(ref msgid))) = cmd {
            let resp = lookup_article_by_msgid(stores, msgid).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return;
            }
            continue;
        }

        // ARTICLE cid:<cid>: fetch directly by CID (ADR-0007).
        if let Command::Article(Some(ArticleRef::Cid(ref cid_str))) = cmd {
            let resp = lookup_article_by_cid(stores, cid_str).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return;
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
                return;
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
                return;
            }
            continue;
        }

        // XGET: fetch a raw IPFS block by CID and return it base64-encoded.
        if let Command::Xget(ref cid_str) = cmd {
            let resp =
                crate::session::commands::xget::handle_xget(cid_str, stores.ipfs_store.as_ref())
                    .await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return;
            }
            continue;
        }

        // GROUP: serve live article count/range from article_numbers store.
        if let Command::Group(ref name) = cmd {
            let resp = handle_group_live(stores, ctx, name).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return;
            }
            continue;
        }

        // LIST ACTIVE: serve live article ranges for all configured groups.
        if let Command::List(ListSubcommand::Active) = cmd {
            let resp = handle_list_active_live(stores, ctx).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return;
            }
            continue;
        }

        // OVER/XOVER: serve overview records from the overview index.
        if let Command::Over(ref arg) = cmd {
            let resp = handle_over_live(stores, ctx, arg.as_ref()).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return;
            }
            continue;
        }

        // HDR field-name [range|message-id]: serve a single header field from
        // the overview index (RFC 3977 §8.5).
        if let Command::Hdr {
            ref field,
            ref range_or_msgid,
        } = cmd
        {
            let resp = handle_hdr_live(stores, ctx, field, range_or_msgid.as_deref()).await;
            if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                return;
            }
            continue;
        }

        // AUTHINFO PASS: async bcrypt credential check via CredentialStore.
        // RFC 3977 §7.1.1 / RFC 4643: if auth.required and TLS not active, reject 483.
        if let Command::AuthinfoPass(_) = cmd {
            if config.auth.required && !ctx.tls_active {
                let resp = Response::new(483, "Encryption required for authentication");
                if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                    return;
                }
                continue;
            }
        }
        if let Command::AuthinfoPass(ref password) = cmd {
            let username = match ctx.pending_auth_user.take() {
                Some(u) => u,
                None => {
                    let resp = Response::authentication_out_of_sequence();
                    if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                        return;
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
                ctx.auth_failure_count = 0;
                let resp = Response::authentication_accepted();
                if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                    return;
                }
            } else {
                ctx.auth_failure_count += 1;
                if ctx.auth_failure_count >= crate::session::context::MAX_AUTH_FAILURES {
                    warn!(peer = %peer_addr, "AUTHINFO: too many failures, closing connection");
                    let resp = Response::new(400, "Too many authentication failures");
                    let _ = writer.write_all(resp.to_string().as_bytes()).await;
                    return;
                }
                let resp = Response::authentication_failed();
                if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
                    return;
                }
            }
            continue;
        }

        // SEARCH key value: full-text search within the current group.
        if let Command::Search { ref key, ref value } = cmd {
            let resp = handle_nntp_search(stores, ctx, key, value).await;
            if writer.write_all(&resp).await.is_err() {
                return;
            }
            continue;
        }

        let is_quit = matches!(cmd, Command::Quit);
        let is_post = matches!(cmd, Command::Post);
        let cmd_label = line
            .split_whitespace()
            .next()
            .unwrap_or("UNKNOWN")
            .to_uppercase();
        let cmd_start = std::time::Instant::now();
        let resp = dispatch(
            ctx,
            cmd,
            &config.auth,
            &stores.client_cert_store,
            &stores.trusted_issuer_store,
            None,
        );
        crate::metrics::NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&[cmd_label.as_str()])
            .observe(cmd_start.elapsed().as_secs_f64());
        let resp_code = resp.code;

        if writer.write_all(resp.to_string().as_bytes()).await.is_err() {
            return;
        }

        if is_quit {
            return;
        }

        // POST two-phase completion: if dispatch returned 340, read the article.
        if is_post && resp_code == 340 {
            let article_bytes = match read_dot_terminated(reader, DEFAULT_MAX_ARTICLE_BYTES).await {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    // Article exceeded the size limit.  The stream was drained to
                    // the dot-terminator, so the connection is still valid.
                    warn!(peer = %peer_addr, "post rejected: article too large");
                    if writer
                        .write_all(b"441 Article too large\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                Err(e) => {
                    warn!(peer = %peer_addr, "post read error: {e}");
                    return;
                }
            };

            let final_resp = run_post_pipeline(&article_bytes, stores).await;
            if writer
                .write_all(final_resp.to_string().as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

/// Run the NNTP protocol loop on a generic async I/O stream.
///
/// `is_tls`: true for NNTPS connections, false for plain.
/// `client_cert_fingerprint`: SHA-256 fingerprint of the client's TLS cert, if
/// one was presented during the handshake.  `None` for plain connections or
/// when the client did not send a certificate.
/// `client_cert_der`: raw DER bytes of the leaf certificate for issuer-based
/// auth.  `None` for plain connections or when the client did not send a cert.
async fn run_session_io<S>(
    stream: S,
    peer_addr: SocketAddr,
    config: &Config,
    is_tls: bool,
    client_cert_fingerprint: Option<String>,
    client_cert_der: Option<Vec<u8>>,
    stores: Arc<ServerStores>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    info!(peer = %peer_addr, "session started");
    let start = std::time::Instant::now();

    let auth_required = config.auth.required;
    let posting_allowed = true;
    let mut ctx = SessionContext::new(peer_addr, auth_required, posting_allowed, is_tls);
    ctx.client_cert_fingerprint = client_cert_fingerprint;
    ctx.client_cert_der = client_cert_der;
    load_known_groups(&stores, &mut ctx).await;

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

    run_command_loop(
        &mut reader,
        &mut writer,
        &mut ctx,
        peer_addr,
        config,
        &stores,
    )
    .await;

    let elapsed = start.elapsed();
    info!(peer = %peer_addr, elapsed_ms = elapsed.as_millis(), "session ended");
}

/// Validate and store a POSTed article through the full pipeline.
///
/// Steps:
/// 1. Validate headers via `complete_post` (sync).
/// 2. Check for duplicate message-id.
/// 3. Sign the article with the operator key.
/// 4. Generate HLC timestamps (one per destination group).
/// 5. Write signed bytes to IPFS as an IPLD block set (DAG-CBOR root, 0x71)
///    and record the msgid → root CID mapping.
/// 6. Append to group logs and assign local article numbers.
/// 7. Index overview fields.
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
    // Produces signed_bytes with the X-Usenet-IPFS-Sig header inserted.
    // The group log entry signature is computed separately over log entry
    // canonical bytes inside append_to_groups, where parent CIDs are known.
    let (signed_bytes, _) = sign_article(&stores.signing_key, article_bytes);

    // Step 4: Generate HLC timestamps under the clock mutex, then release
    // before any async I/O so concurrent POSTs are not serialised by it.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let hlc_timestamps: Vec<u64> = {
        let mut clock = stores.clock.lock().await;
        newsgroups
            .iter()
            .map(|_| clock.send(now_ms).wall_ms)
            .collect()
    };
    // Use the primary HLC timestamp for the IPLD root node metadata.
    let primary_hlc = hlc_timestamps.first().copied().unwrap_or(now_ms);
    let newsgroups_str: Vec<String> = newsgroups.iter().map(|g| g.as_str().to_owned()).collect();

    // Step 5: Write to IPFS as a proper IPLD block set (root CID codec 0x71)
    // and record msgid → root CID.
    let cid = match write_ipld_article_to_ipfs(
        stores.ipfs_store.as_ref(),
        &stores.msgid_map,
        &signed_bytes,
        &message_id,
        newsgroups_str,
        primary_hlc,
    )
    .await
    {
        Ok(cid) => cid,
        Err(resp) => return resp,
    };

    // Step 6: Append to group logs and assign article numbers.
    let append_result = match append_to_groups(
        stores.log_storage.as_ref(),
        &stores.article_numbers,
        &hlc_timestamps,
        &cid,
        &stores.signing_key,
        &newsgroups,
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Step 7: Index overview fields for each assigned (group, article_number).
    let (header_bytes, body_bytes) = split_article(&signed_bytes);
    let mut overview = extract_overview(&header_bytes, &body_bytes);
    for (group, article_number) in &append_result.assignments {
        overview.article_number = *article_number;
        if let Err(e) = stores.overview_store.insert(group, &overview).await {
            warn!("overview insert failed for {group}/{article_number}: {e}");
        }
    }

    // Step 8: Best-effort full-text search indexing.
    // Failures are logged but never cause the POST to fail.
    if let Some(ref idx) = stores.search_index {
        for (group, article_number) in &append_result.assignments {
            let req = ArticleIndexRequest {
                message_id: &message_id,
                newsgroup: group,
                article_num: *article_number,
                subject: &overview.subject,
                from: &overview.from,
                date_str: &overview.date,
                body_bytes: &body_bytes,
            };
            if let Err(e) = idx.index_article(&req).await {
                tracing::warn!(
                    message_id = %message_id,
                    error = %e,
                    "search index failed; article still accepted"
                );
            }
        }
        if let Err(e) = idx.commit().await {
            tracing::warn!(error = %e, "search index commit failed");
        }
    }

    Response::new(240, "Article received OK")
}

/// Reconstruct wire-format article bytes from an IPLD DAG-CBOR root CID.
///
/// Fetches the root block (codec 0x71, DAG-CBOR `ArticleRootNode`), then
/// fetches the header and body sub-blocks referenced by the root, and
/// concatenates them as `header_bytes + "\r\n\r\n" + body_bytes`.
async fn fetch_article_wire_bytes(
    ipfs_store: &dyn IpfsBlockStore,
    root_cid: &Cid,
) -> Result<Vec<u8>, String> {
    let root_bytes = ipfs_store
        .get_raw_block(root_cid)
        .await
        .map_err(|e| format!("IPFS fetch root block {root_cid}: {e:?}"))?;
    let root: ArticleRootNode = serde_ipld_dagcbor::from_slice(&root_bytes)
        .map_err(|e| format!("DAG-CBOR decode ArticleRootNode from {root_cid}: {e}"))?;
    let header_bytes = ipfs_store
        .get_raw_block(&root.header_cid)
        .await
        .map_err(|e| format!("IPFS fetch header block {}: {e:?}", root.header_cid))?;
    let body_bytes = ipfs_store
        .get_raw_block(&root.body_cid)
        .await
        .map_err(|e| format!("IPFS fetch body block {}: {e:?}", root.body_cid))?;
    let mut wire = Vec::with_capacity(header_bytes.len() + 4 + body_bytes.len());
    wire.extend_from_slice(&header_bytes);
    wire.extend_from_slice(b"\r\n\r\n");
    wire.extend_from_slice(&body_bytes);
    Ok(wire)
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

    let wire_bytes = match fetch_article_wire_bytes(stores.ipfs_store.as_ref(), &cid).await {
        Ok(b) => b,
        Err(e) => {
            warn!("fetch_article_wire_bytes error for cid {cid}: {e}");
            return Response::program_fault();
        }
    };

    // Split the wire bytes into header and body sections.
    let (header_bytes, body_bytes) = split_article(&wire_bytes);

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
    match find_header_boundary(bytes) {
        Some(body_start) => {
            // Determine separator length: 4 for \r\n\r\n, 2 for \n\n.
            let sep_len = if body_start >= 4 && bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                4
            } else {
                2
            };
            let header_end = body_start - sep_len;
            (bytes[..header_end].to_vec(), bytes[body_start..].to_vec())
        }
        None => (bytes.to_vec(), vec![]),
    }
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
    // Pass the bytes up to and including the blank line (or the full slice if
    // none is found); mailparse::parse_headers stops at the blank line anyway.
    let parse_end = find_header_boundary(article_bytes).unwrap_or(article_bytes.len());
    let header_section = &article_bytes[..parse_end];

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

    let message_id = message_id.ok_or_else(|| Response::new(441, "Missing Message-ID header"))?;
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
        let wire_bytes =
            match fetch_article_wire_bytes(stores.ipfs_store.as_ref(), &actual_cid).await {
                Ok(b) => b,
                Err(e) => {
                    warn!("XVERIFY fetch wire bytes error: {e}");
                    return Response::program_fault();
                }
            };
        let pubkey = stores.signing_key.verifying_key();
        if verify_article_sig(&pubkey, &wire_bytes).is_err() {
            return Response::new(542, "Signature verification failed");
        }
    }

    Response::new(291, "Verified OK")
}

// ── Live GROUP / LIST ACTIVE / OVER handlers ──────────────────────────────

/// GROUP groupname: select a group and return live article count and range.
///
/// Returns 411 for an invalid group name or for a group not carried by this
/// server (RFC 3977 §6.1.1). A group is considered carried if it has at least
/// one article in the article_numbers store. Returns 211 with live (low, high,
/// count) for carried groups.
async fn handle_group_live(
    stores: &ServerStores,
    ctx: &mut SessionContext,
    name: &str,
) -> Response {
    let group_name = match usenet_ipfs_core::article::GroupName::new(name) {
        Ok(g) => g,
        Err(_) => return Response::no_such_newsgroup(),
    };
    // RFC 3977 §6.1.1: return 411 if the group is not served by this server.
    // Query list_groups() live so that articles posted during the session are
    // immediately visible (no stale session-start cache).
    let carried = match stores.article_numbers.list_groups().await {
        Ok(groups) => groups.into_iter().any(|(n, _, _)| n == name),
        Err(e) => {
            warn!("handle_group_live: list_groups error for {name}: {e}");
            return Response::program_fault();
        }
    };
    if !carried {
        return Response::no_such_newsgroup();
    }
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
    // RFC 3977 §8.3.2: message-id form does not require a currently selected newsgroup.
    if let Some(OverArg::MessageId(msgid)) = arg {
        return match stores.overview_store.query_by_msgid(msgid).await {
            Ok(Some(record)) => over_response(std::iter::once(record)),
            Ok(None) => Response::no_article_with_message_id(),
            Err(e) => {
                warn!("OVER msgid lookup error: {e}");
                Response::program_fault()
            }
        };
    }

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
        Some(OverArg::MessageId(_)) => unreachable!("MessageId handled above"),
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

/// HDR field-name [range|message-id]: return one header field per article
/// from the overview index (RFC 3977 §8.5).
///
/// Supported fields are those stored in the overview index: `Subject`, `From`,
/// `Date`, `Message-ID`, `References`, `:bytes`, `:lines`.  Unknown fields
/// return 501 per RFC 3977 §8.5.2.
async fn handle_hdr_live(
    stores: &ServerStores,
    ctx: &SessionContext,
    field: &str,
    range_or_msgid: Option<&str>,
) -> Response {
    // Reject unsupported fields early.
    let field_lower = field.to_ascii_lowercase();
    let supported = matches!(
        field_lower.as_str(),
        "subject" | "from" | "date" | "message-id" | "references" | ":bytes" | ":lines"
    );
    if !supported {
        return Response::new(501, "Field not supported");
    }

    // Message-ID form: does not require a currently selected newsgroup.
    if let Some(arg) = range_or_msgid {
        if arg.starts_with('<') {
            return match stores.overview_store.query_by_msgid(arg).await {
                Ok(Some(record)) => {
                    let value = extract_field(&record, field).unwrap_or_default();
                    hdr_response(&[HdrRecord {
                        article_number: record.article_number,
                        value,
                    }])
                }
                Ok(None) => Response::no_article_with_message_id(),
                Err(e) => {
                    warn!("HDR msgid lookup error: {e}");
                    Response::program_fault()
                }
            };
        }
    }

    // Range form: requires a currently selected newsgroup.
    if !ctx.state.group_selected() {
        return Response::no_newsgroup_selected();
    }
    let group = match ctx.current_group.as_ref() {
        Some(g) => g.as_str().to_string(),
        None => return Response::no_newsgroup_selected(),
    };

    let (low, high) = match range_or_msgid {
        None => {
            let n = match ctx.current_article_number {
                Some(n) => n,
                None => return Response::current_article_invalid(),
            };
            (n, n)
        }
        Some(arg) => {
            let range = crate::session::command::parse_range_pub(arg);
            match range {
                ArticleRange::Single(n) => (n, n),
                ArticleRange::From(n) => {
                    let (_, g_high) = match stores.article_numbers.group_range(&group).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("HDR group_range error: {e}");
                            return Response::program_fault();
                        }
                    };
                    (n, g_high)
                }
                ArticleRange::Range(lo, hi) => (lo, hi),
            }
        }
    };

    let records = match stores.overview_store.query_range(&group, low, high).await {
        Ok(r) => r,
        Err(e) => {
            warn!("HDR query_range error: {e}");
            return Response::program_fault();
        }
    };

    let hdr_records: Vec<HdrRecord> = records
        .into_iter()
        .map(|r| {
            let value = extract_field(&r, field).unwrap_or_default();
            HdrRecord {
                article_number: r.article_number,
                value,
            }
        })
        .collect();

    hdr_response(&hdr_records)
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
    let wire_bytes = match fetch_article_wire_bytes(stores.ipfs_store.as_ref(), &cid).await {
        Ok(b) => b,
        Err(_) => return Response::no_article_with_message_id(),
    };
    let (header_bytes, body_bytes) = split_article(&wire_bytes);
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

/// Escape characters that have special meaning in Tantivy's query parser.
/// This allows literal user input to be used in field:value queries safely.
fn escape_tantivy_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '+' | '-' | '&' | '|' | '!' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '"' | '~'
            | '*' | '?' | ':' | '\\' | '/' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// SEARCH key value: execute a full-text search within the current newsgroup.
///
/// Requires a selected newsgroup (412 otherwise). Returns 503 if the search
/// index is not available. On success, returns 100 followed by a list of
/// matching article numbers, dot-terminated.
async fn handle_nntp_search(
    stores: &ServerStores,
    ctx: &SessionContext,
    key: &SearchKey,
    value: &str,
) -> Vec<u8> {
    let group = match &ctx.current_group {
        Some(g) => g.as_str().to_owned(),
        None => return b"412 No newsgroup selected\r\n".to_vec(),
    };

    let idx = match &stores.search_index {
        Some(i) => i,
        None => return b"503 Search not available\r\n".to_vec(),
    };

    let query_str = match key {
        SearchKey::Subject => format!("subject:\"{}\"", escape_tantivy_query(value)),
        SearchKey::From => format!("from_header:\"{}\"", escape_tantivy_query(value)),
        SearchKey::Since | SearchKey::Before => {
            return b"501 Date range search not yet implemented\r\n".to_vec();
        }
        SearchKey::Body | SearchKey::Text => value.to_owned(),
    };

    match idx.search_in_group(&group, &query_str, 10_000).await {
        Ok(nums) => {
            if nums.is_empty() {
                return b"100 Article list follows\r\n.\r\n".to_vec();
            }
            let mut resp = b"100 Article list follows\r\n".to_vec();
            for n in nums {
                resp.extend_from_slice(format!("{n}\r\n").as_bytes());
            }
            resp.extend_from_slice(b".\r\n");
            resp
        }
        Err(SearchError::QueryTooLong { len, max }) => {
            format!("501 Query too long ({len} bytes, max {max})\r\n").into_bytes()
        }
        Err(e) => {
            tracing::warn!(error = %e, "SEARCH failed");
            b"451 Program error\r\n".to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::server_stores::ServerStores;
    use std::time::{SystemTime, UNIX_EPOCH};
    use usenet_ipfs_core::group_log::LogStorage;

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

    /// Regression test for o0r.2: verify that the group log entry produced by
    /// run_post_pipeline carries a valid operator Ed25519 signature.
    ///
    /// The fix has two parts:
    /// (1) append_to_groups now accepts a SigningKey and computes the log entry
    ///     signature over canonical bytes (hlc_timestamp || article_cid ||
    ///     sorted parent_cids) internally, where parent CIDs are known.
    /// (2) The article signature from sign_article (over raw article bytes) is
    ///     correctly used only for the X-Usenet-IPFS-Sig header, not the log.
    ///
    /// This test will fail if operator_signature in the log entry is ever left
    /// empty or set to a signature over the wrong bytes.
    #[tokio::test]
    async fn post_pipeline_log_entry_signature_verifies() {
        let stores = ServerStores::new_mem().await;
        let article = minimal_article("comp.test", "Signature Verify", "<sigverify@test.example>");

        let resp = run_post_pipeline(&article, &stores).await;
        assert_eq!(
            resp.code, 240,
            "POST pipeline must succeed; got: {}",
            resp.text
        );

        let group = usenet_ipfs_core::article::GroupName::new("comp.test").unwrap();
        let tips = stores.log_storage.list_tips(&group).await.unwrap();
        assert_eq!(tips.len(), 1, "must have exactly one tip after one POST");

        let entry = stores
            .log_storage
            .get_entry(&tips[0])
            .await
            .unwrap()
            .expect("tip entry must exist in storage");

        assert_eq!(
            entry.operator_signature.len(),
            64,
            "operator_signature must be 64 bytes (Ed25519); got {} — sign_article return value may not be threaded through",
            entry.operator_signature.len()
        );

        let pubkey = stores.signing_key.verifying_key();
        let result = usenet_ipfs_core::group_log::verify::verify_entry(
            &entry,
            &tips[0],
            stores.log_storage.as_ref(),
            &pubkey,
        )
        .await;

        assert!(
            result.is_ok(),
            "group log entry must carry a valid operator signature; got: {result:?}"
        );
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

    // ── SEARCH lifecycle tests ────────────────────────────────────────────

    /// SEARCH without a selected group must return 412.
    #[tokio::test]
    async fn nntp_search_no_group_returns_412() {
        let stores = ServerStores::new_mem().await;
        let ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            false,
            true,
            false,
        );
        let resp = handle_nntp_search(&stores, &ctx, &SearchKey::Subject, "hello").await;
        assert!(
            resp.starts_with(b"412"),
            "must return 412 when no group is selected; got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    #[test]
    fn escape_tantivy_query_escapes_parens_and_colons() {
        let input = "foo(bar):baz";
        let escaped = escape_tantivy_query(input);
        assert!(escaped.contains("\\("), "( must be escaped");
        assert!(escaped.contains("\\:"), ": must be escaped");
        assert!(!escaped.contains("foo("), "unescaped ( must not remain");
    }

    /// SEARCH with search_index = None must return 503.
    #[tokio::test]
    async fn nntp_search_no_index_returns_503() {
        let stores = ServerStores::new_mem_no_search().await;
        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            false,
            true,
            false,
        );
        ctx.current_group = Some(usenet_ipfs_core::article::GroupName::new("misc.test").unwrap());
        ctx.state = crate::session::state::SessionState::GroupSelected;

        let resp = handle_nntp_search(&stores, &ctx, &SearchKey::Subject, "hello").await;
        assert!(
            resp.starts_with(b"503"),
            "must return 503 when search index is None; got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    // ── ld7.12: Since/Before return 501, not a free-text date query ───────

    /// SEARCH SINCE must return 501, not silently pass the date string as a
    /// free-text query.  Oracle: the 501 response is the only correct answer
    /// for a key whose semantics require a dedicated date-range implementation.
    #[tokio::test]
    async fn nntp_search_since_returns_501() {
        let stores = ServerStores::new_mem().await;
        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            false,
            true,
            false,
        );
        ctx.current_group = Some(usenet_ipfs_core::article::GroupName::new("misc.test").unwrap());
        ctx.state = crate::session::state::SessionState::GroupSelected;

        let resp = handle_nntp_search(
            &stores,
            &ctx,
            &SearchKey::Since,
            "Mon, 01 Jan 2024 00:00:00 +0000",
        )
        .await;
        assert!(
            resp.starts_with(b"501"),
            "SEARCH SINCE must return 501 (not implemented), got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// SEARCH BEFORE must also return 501.
    #[tokio::test]
    async fn nntp_search_before_returns_501() {
        let stores = ServerStores::new_mem().await;
        let mut ctx = crate::session::context::SessionContext::new(
            "127.0.0.1:1234".parse().unwrap(),
            false,
            true,
            false,
        );
        ctx.current_group = Some(usenet_ipfs_core::article::GroupName::new("misc.test").unwrap());
        ctx.state = crate::session::state::SessionState::GroupSelected;

        let resp = handle_nntp_search(
            &stores,
            &ctx,
            &SearchKey::Before,
            "Mon, 01 Jan 2024 00:00:00 +0000",
        )
        .await;
        assert!(
            resp.starts_with(b"501"),
            "SEARCH BEFORE must return 501 (not implemented), got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }
}
