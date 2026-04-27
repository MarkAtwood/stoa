//! Admin HTTP server for the transit daemon.
//!
//! Listens on a configurable address and serves a small set of JSON endpoints
//! for operator inspection. Optionally requires a bearer token; bind to
//! loopback only in production (see [`crate::config::AdminConfig`]).
//!
//! Endpoints:
//! - `GET /health`           — liveness check with uptime
//! - `GET /stats`            — article, pin, group, and peer counts from SQLite
//! - `GET /log-tip?group=X`  — tip CID and entry count for a group log
//! - `GET /peers`            — list of active (non-blacklisted) peers
//! - `GET /metrics`          — Prometheus text format (delegates to [`crate::metrics`])
//! - `GET /pinning/remote`   — per-service job counts from the remote pin jobs table
//! - `GET /ipns`             — IPNS address and latest article CID per group
//! - `GET /version`          — binary name and semver version
//! - `GET /groups`           — distinct group names known to this node
//! - `POST /reload`          — stub; returns HTTP 501 with `{"reloaded":false}` until config reload is implemented
//!
//! ## Authorization model (v1 limitation)
//!
//! A single bearer token controls access to all endpoints, including
//! `/export/car` which can export complete article archives.  Any bearer token
//! holder has full read access to all data.  Do not share the admin token with
//! read-only monitoring systems in a production deployment; use network-level
//! access controls (firewall, loopback binding) to restrict `/export/car`
//! access until per-endpoint authorization is implemented in a future release.

use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stoa_core::rate_limiter::RateLimiter;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::peering::pipeline::IpfsStore;

/// SQLite pool pair for the admin server.
///
/// `transit_pool` is the transit schema (transit.db); `core_pool` is the core
/// schema (transit_core.db).  Grouped here to keep `start_admin_server` under
/// clippy's 7-argument limit.
pub struct AdminPools {
    pub transit_pool: Arc<SqlitePool>,
    pub core_pool: Arc<SqlitePool>,
}

/// Start the admin HTTP server on the given address.
///
/// Accepts `SqlitePool` for live stats queries, an optional bearer token for
/// authentication, and a per-IP rate limit in requests per minute (0 = unlimited).
/// Spawns a background tokio task. Returns immediately.
///
/// `core_pool` is the SQLite pool for the core schema (transit_core.db); it is
/// used by `build_stats_json` to query `msgid_map`. `pool` is the transit schema
/// pool (transit.db) used for all other queries.
///
/// # Fail-closed: non-loopback without bearer token
///
/// Returns `Err` if `addr` is non-loopback and `bearer_token` is `None`.
/// An unauthenticated admin endpoint on a reachable interface is a security
/// footgun in production; the server must not start in that configuration.
pub fn start_admin_server(
    addr: std::net::SocketAddr,
    pools: AdminPools,
    start_time: Instant,
    bearer_token: Option<String>,
    rate_limit_rpm: u32,
    ipfs: Arc<dyn IpfsStore>,
    ipns_path: Option<String>,
) -> Result<(), String> {
    if !addr.ip().is_loopback() && bearer_token.is_none() {
        return Err(format!(
            "admin endpoint at {addr} is on a non-loopback interface but no bearer_token \
             is configured — refusing to start an unauthenticated admin server"
        ));
    }
    let bearer_token = Arc::new(bearer_token);
    let rate_limiter = Arc::new(RateLimiter::new(rate_limit_rpm));
    let ipns_path = Arc::new(ipns_path);
    let transit_pool = pools.transit_pool;
    let core_pool = pools.core_pool;
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("admin server failed to bind {addr}: {e}");
                return;
            }
        };
        tracing::info!("admin server listening on {addr}");
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let transit_pool = Arc::clone(&transit_pool);
                    let core_pool = Arc::clone(&core_pool);
                    let bearer_token = Arc::clone(&bearer_token);
                    let rate_limiter = Arc::clone(&rate_limiter);
                    let ipfs = Arc::clone(&ipfs);
                    let ipns_path = Arc::clone(&ipns_path);
                    tokio::spawn(async move {
                        if let Err(e) = handle_admin_connection(
                            stream,
                            (&*transit_pool, &*core_pool),
                            start_time,
                            bearer_token.as_deref(),
                            &rate_limiter,
                            &*ipfs,
                            ipns_path.as_deref(),
                        )
                        .await
                        {
                            tracing::warn!("admin connection error from {peer}: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("admin server accept error: {e}");
                }
            }
        }
    });
    Ok(())
}

async fn handle_admin_connection(
    stream: tokio::net::TcpStream,
    pools: (&SqlitePool, &SqlitePool),
    start_time: Instant,
    bearer_token: Option<&str>,
    rate_limiter: &RateLimiter,
    ipfs: &dyn IpfsStore,
    ipns_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (pool, core_pool) = pools;
    let peer_ip = stream.peer_addr()?.ip();
    let mut reader = BufReader::new(stream);

    // Hard deadline for receiving the full request line + headers.  A client
    // that drips bytes one at a time (slowloris) will be dropped after this.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    // Cap on header lines: prevents an infinite loop of valid lines with no
    // blank terminator.
    const MAX_HEADER_LINES: usize = 64;

    let (method_owned, path_and_query_owned, auth_header) =
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            // Read request line.
            let mut request_line = String::new();
            reader.read_line(&mut request_line).await?;
            let rl = request_line.trim_end_matches(['\r', '\n']).to_string();
            let mut parts = rl.splitn(3, ' ');
            let method = parts.next().unwrap_or("").to_string();
            let path_and_query = parts.next().unwrap_or("").to_string();

            // Read headers until blank line.
            let mut auth_header: Option<String> = None;
            for _ in 0..MAX_HEADER_LINES {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                let line = line.trim_end_matches(['\r', '\n']);
                if line.is_empty() {
                    break;
                }
                if let Some(val) = line.strip_prefix("Authorization: ") {
                    auth_header = Some(val.to_string());
                }
            }

            Ok::<_, std::io::Error>((method, path_and_query, auth_header))
        })
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "admin request read timeout")
        })??;

    let method = method_owned.as_str();
    let path_and_query = path_and_query_owned.as_str();

    // Split path from query string (needed before rate-limit check for /metrics exemption).
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };

    // Extract the underlying stream for writing responses.
    let mut writer = reader.into_inner();

    // Check bearer token if configured. This runs before rate limiting so that
    // unauthenticated requests are rejected with 401 without consuming a
    // rate-limit slot (rbe3.22).
    // Bearer token comparison uses subtle::ConstantTimeEq (see check_bearer_token
    // below) to prevent timing-oracle attacks even on loopback.
    if !check_bearer_token(auth_header.as_deref(), bearer_token) {
        tracing::debug!("admin request rejected: missing or invalid bearer token");
        write_json(
            &mut writer,
            401,
            "Unauthorized",
            r#"{"error":"unauthorized"}"#,
        )
        .await?;
        return Ok(());
    }

    if bearer_token.is_none() {
        tracing::debug!("admin request accepted: no bearer token configured");
    }

    // Apply per-IP rate limiting. /metrics is exempt (polled frequently by Prometheus).
    if path != "/metrics" && !rate_limiter.check_and_consume(peer_ip) {
        tracing::debug!("admin request rate-limited from {peer_ip}");
        let rpm = rate_limiter.rpm();
        // clamp to [1, 60]: prevents Retry-After: 0 for high rpm (e.g. rpm=120 → 60/120=0 → 1s).
        let retry_after = if rpm > 0 {
            (60u32 / rpm).clamp(1, 60)
        } else {
            60
        };
        let body = r#"{"error":"rate limit exceeded"}"#;
        let content_length = body.len();
        let response = format!(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: {retry_after}\r\nContent-Length: {content_length}\r\n\r\n{body}"
        );
        writer.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let method_ok = match path {
        "/reload" => method == "POST",
        _ => method == "GET",
    };
    if !method_ok {
        write_json(
            &mut writer,
            405,
            "Method Not Allowed",
            r#"{"error":"method not allowed"}"#,
        )
        .await?;
        return Ok(());
    }

    match path {
        "/health" => {
            let body = build_health_json(start_time);
            write_json(&mut writer, 200, "OK", &body).await?;
        }
        "/stats" => match build_stats_json(pool, core_pool).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /stats error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/log-tip" => {
            let group = extract_query_param(query, "group");
            match group {
                None => {
                    write_json(
                        &mut writer,
                        400,
                        "Bad Request",
                        r#"{"error":"missing group parameter"}"#,
                    )
                    .await?;
                }
                Some(g) => match build_log_tip_json(pool, &g).await {
                    Some(body) => write_json(&mut writer, 200, "OK", &body).await?,
                    None => {
                        write_json(
                            &mut writer,
                            404,
                            "Not Found",
                            r#"{"error":"group not found"}"#,
                        )
                        .await?
                    }
                },
            }
        }
        "/peers" => match build_peers_json(pool).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /peers error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/metrics" => {
            let body = crate::metrics::gather_metrics();
            let content_length = body.len();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {content_length}\r\n\r\n{body}"
            );
            writer.write_all(response.as_bytes()).await?;
        }
        "/pinning/remote" => match build_pinning_remote_json(pool).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /pinning/remote error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/export/car" => {
            let group = extract_query_param(query, "group").filter(|g| !g.is_empty());
            if let Some(group) = group {
                let limit: i64 = extract_query_param(query, "limit")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(1000)
                    .clamp(1, 10000);
                match crate::export::build_export_car(pool, ipfs, &group, limit).await {
                    Ok(car_bytes) => {
                        write_binary_car(&mut writer, &car_bytes).await?;
                    }
                    Err(e) => {
                        tracing::warn!("admin /export/car error: {e}");
                        write_json(
                            &mut writer,
                            500,
                            "Internal Server Error",
                            r#"{"error":"internal server error"}"#,
                        )
                        .await?;
                    }
                }
            } else {
                write_json(
                    &mut writer,
                    400,
                    "Bad Request",
                    r#"{"error":"missing group parameter"}"#,
                )
                .await?;
            }
        }
        "/ipns" => match build_ipns_json(pool, ipns_path).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /ipns error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/version" => {
            write_json(&mut writer, 200, "OK", &build_version_json()).await?;
        }
        "/groups" => match build_groups_json(pool).await {
            Ok(body) => write_json(&mut writer, 200, "OK", &body).await?,
            Err(e) => {
                tracing::warn!("admin /groups error: {e}");
                write_json(
                    &mut writer,
                    500,
                    "Internal Server Error",
                    r#"{"error":"internal server error"}"#,
                )
                .await?;
            }
        },
        "/reload" => {
            // Config reload is not yet implemented.  Return 501 so operators
            // know to restart the daemon rather than assuming config was applied.
            write_json(
                &mut writer,
                501,
                "Not Implemented",
                r#"{"reloaded":false,"error":"config reload is not yet implemented \u2014 restart the daemon to apply changes"}"#,
            )
            .await?;
        }
        _ => {
            write_json(&mut writer, 404, "Not Found", r#"{"error":"not found"}"#).await?;
        }
    }

    Ok(())
}

/// Check whether an Authorization header satisfies the configured bearer token.
///
/// Returns `true` if:
/// - No token is configured (`bearer_token` is `None`), or
/// - The header is present and exactly matches `"Bearer <token>"`.
///
/// Returns `false` if a token is configured and the header is missing or incorrect.
///
/// The comparison is constant-time (via `subtle::ConstantTimeEq`) to prevent
/// timing oracles that could leak the token one character at a time.
pub(crate) fn check_bearer_token(auth_header: Option<&str>, bearer_token: Option<&str>) -> bool {
    use subtle::ConstantTimeEq;
    match bearer_token {
        None => true,
        Some(token) => {
            let expected = format!("Bearer {token}");
            match auth_header {
                None => false,
                Some(header) => {
                    // ct_eq returns Choice (0 or 1); lengths must match first.
                    // Comparing different-length slices returns 0 (not equal).
                    expected.as_bytes().ct_eq(header.as_bytes()).into()
                }
            }
        }
    }
}

/// Extract the value of a named query parameter from a URL query string.
///
/// Handles simple `key=value` pairs and percent-decodes the value so that
/// clients using `percent_encode` (e.g. `stoa-ctl`) get back the original
/// string regardless of whether any characters were encoded.
fn extract_query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

/// Decode a percent-encoded string (e.g. `%20` → space, `%2F` → `/`).
///
/// Invalid `%XX` sequences (non-hex digits or truncated) are left as-is.
/// If the decoded bytes are not valid UTF-8, replacement characters are
/// substituted (defensive: well-formed inputs are always valid UTF-8).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(hi), Some(lo)) = (
                i.checked_add(2)
                    .filter(|&end| end < bytes.len())
                    .and_then(|_| hex_nibble(bytes[i + 1])),
                i.checked_add(2)
                    .filter(|&end| end < bytes.len())
                    .and_then(|_| hex_nibble(bytes[i + 2])),
            ) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Convert a single ASCII hex digit byte to its numeric value, or `None`.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn write_json<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    status_text: &str,
    body: &str,
) -> std::io::Result<()> {
    let content_length = body.len();
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\n\r\n{body}"
    );
    writer.write_all(response.as_bytes()).await
}

/// Write a CARv1 binary response with the standard IPLD CAR content-type.
async fn write_binary_car<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> std::io::Result<()> {
    let content_length = body.len();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.ipld.car; version=1\r\nContent-Length: {content_length}\r\n\r\n"
    );
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(body).await
}

pub(crate) fn build_health_json(start_time: Instant) -> String {
    let uptime_secs = start_time.elapsed().as_secs();
    serde_json::json!({
        "status": "ok",
        "uptime_secs": uptime_secs,
    })
    .to_string()
}

pub(crate) async fn build_stats_json(
    pool: &SqlitePool,
    core_pool: &SqlitePool,
) -> Result<String, sqlx::Error> {
    // msgid_map lives in the core schema (transit_core.db), not the transit
    // schema (transit.db) — use core_pool here (rbe3.12).
    let articles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM msgid_map")
        .fetch_one(core_pool)
        .await
        .unwrap_or(0);

    let pinned_cids: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pinned_cids")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let groups: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT group_name) FROM articles")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let peers: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM peers WHERE blacklisted_until IS NULL OR blacklisted_until = 0",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    Ok(serde_json::json!({
        "articles": articles,
        "pinned_cids": pinned_cids,
        "groups": groups,
        "peers": peers,
    })
    .to_string())
}

pub(crate) async fn build_log_tip_json(pool: &SqlitePool, group: &str) -> Option<String> {
    let row: Option<(Option<i64>, Option<String>)> =
        sqlx::query_as("SELECT MAX(sequence_number), cid FROM group_log WHERE group_name = ?")
            .bind(group)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

    match row {
        Some((Some(seq), Some(cid))) => Some(
            serde_json::json!({
                "group": group,
                "tip_cid": cid,
                "entry_count": seq,
            })
            .to_string(),
        ),
        _ => None,
    }
}

/// Build JSON stats for `GET /pinning/remote`.
///
/// Returns a JSON array with one object per service name found in the
/// `remote_pin_jobs` table, showing counts by status.
///
/// Example response:
/// ```json
/// [{"service":"pinata","pending":2,"queued":1,"pinning":0,"pinned":10,"failed":0}]
/// ```
pub async fn build_pinning_remote_json(pool: &SqlitePool) -> Result<String, sqlx::Error> {
    // Aggregate counts per (service_name, status) in one query.
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT service_name, status, COUNT(*) as cnt \
         FROM remote_pin_jobs \
         GROUP BY service_name, status \
         ORDER BY service_name, status",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Pivot into per-service objects.
    let mut by_service: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();

    for (svc, status, count) in rows {
        let entry = by_service.entry(svc.clone()).or_insert_with(|| {
            serde_json::json!({
                "service": svc,
                "pending": 0i64,
                "queued": 0i64,
                "pinning": 0i64,
                "pinned": 0i64,
                "failed": 0i64,
            })
        });
        if let Some(v) = entry.get_mut(status.as_str()) {
            *v = serde_json::json!(count);
        }
    }

    let result: Vec<serde_json::Value> = by_service.into_values().collect();
    Ok(serde_json::to_string(&result).unwrap_or_else(|_| "[]".to_string()))
}

pub(crate) async fn build_peers_json(pool: &SqlitePool) -> Result<String, sqlx::Error> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT peer_id, address FROM peers WHERE blacklisted_until IS NULL OR blacklisted_until = 0",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let peers: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(peer_id, addr)| {
            serde_json::json!({
                "peer_id": peer_id,
                "addr": addr,
            })
        })
        .collect();

    Ok(serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string()))
}

/// Build JSON for `GET /ipns`.
///
/// Returns the stable IPNS address for this node and the latest article CID
/// per group, alphabetically sorted.
///
/// Format:
/// ```json
/// {"ipns_path":"/ipns/<peer_id>","groups":{"comp.lang.rust":"<cid>",...}}
/// ```
///
/// `ipns_path` is `null` when IPNS is disabled.
pub(crate) async fn build_ipns_json(
    pool: &SqlitePool,
    ipns_path: Option<&str>,
) -> Result<String, sqlx::Error> {
    // One row per group: the CID with the highest ingested_at_ms.
    // Correlated subquery is supported in SQLite and avoids a GROUP BY/JOIN.
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT group_name, cid FROM articles \
         WHERE ingested_at_ms = (\
           SELECT MAX(ingested_at_ms) FROM articles a2 \
           WHERE a2.group_name = articles.group_name\
         ) \
         ORDER BY group_name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Build a JSON object (serde_json::Map preserves insertion order, which is
    // alphabetical here because the SQL result is ORDER BY group_name).
    let mut groups = serde_json::Map::new();
    for (group, cid) in rows {
        groups.insert(group, serde_json::Value::String(cid));
    }

    let obj = serde_json::json!({
        "ipns_path": ipns_path,
        "groups": groups,
    });
    Ok(obj.to_string())
}

pub(crate) fn build_version_json() -> String {
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "binary": env!("CARGO_PKG_NAME"),
    })
    .to_string()
}

pub(crate) async fn build_groups_json(pool: &SqlitePool) -> Result<String, sqlx::Error> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT group_name FROM articles ORDER BY group_name")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let groups: Vec<&str> = rows.iter().map(|(g,)| g.as_str()).collect();
    Ok(serde_json::to_string(&groups).unwrap_or_else(|_| "[]".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::sync::atomic::AtomicUsize;

    static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Returns `(transit_pool, core_pool)` — each backed by a distinct in-memory SQLite
    /// database with the appropriate schema migrations applied.
    async fn make_pools() -> (Arc<SqlitePool>, Arc<SqlitePool>) {
        let n = DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let transit_url = format!("file:admin_transit_{n}?mode=memory&cache=shared");
        let transit_opts = SqliteConnectOptions::new()
            .filename(&transit_url)
            .create_if_missing(true);
        let transit_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(transit_opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&transit_pool)
            .await
            .unwrap();

        let core_url = format!("file:admin_core_{n}?mode=memory&cache=shared");
        let core_opts = SqliteConnectOptions::new()
            .filename(&core_url)
            .create_if_missing(true);
        let core_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(core_opts)
            .await
            .unwrap();
        stoa_core::migrations::run_migrations(&core_pool)
            .await
            .unwrap();

        (Arc::new(transit_pool), Arc::new(core_pool))
    }

    /// Convenience wrapper: returns only the transit pool for tests that don't
    /// exercise `build_stats_json` and don't need the core pool.
    async fn make_pool() -> Arc<SqlitePool> {
        make_pools().await.0
    }

    #[tokio::test]
    async fn health_handler_returns_ok_json() {
        let start_time = Instant::now();
        let json = build_health_json(start_time);
        assert!(json.contains("\"status\""), "missing status key: {json}");
        assert!(json.contains("\"ok\""), "missing ok value: {json}");
        assert!(
            json.contains("\"uptime_secs\""),
            "missing uptime_secs: {json}"
        );
    }

    #[tokio::test]
    async fn stats_handler_returns_zero_counts_on_empty_db() {
        let (pool, core_pool) = make_pools().await;
        let json = build_stats_json(&pool, &core_pool).await.unwrap();
        assert!(json.contains("\"articles\""), "missing articles: {json}");
        assert!(
            json.contains("\"pinned_cids\""),
            "missing pinned_cids: {json}"
        );
        assert!(json.contains("\"groups\""), "missing groups: {json}");
        assert!(json.contains("\"peers\""), "missing peers: {json}");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["articles"], 0);
        assert_eq!(v["pinned_cids"], 0);
        assert_eq!(v["groups"], 0);
        assert_eq!(v["peers"], 0);
    }

    #[tokio::test]
    async fn log_tip_returns_none_for_missing_group() {
        let pool = make_pool().await;
        let result = build_log_tip_json(&pool, "comp.lang.rust").await;
        assert!(
            result.is_none(),
            "expected None for unknown group, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn peers_returns_empty_array_on_empty_db() {
        let pool = make_pool().await;
        let json = build_peers_json(&pool).await.unwrap();
        assert_eq!(json, "[]", "expected empty array: {json}");
    }

    #[tokio::test]
    async fn health_uptime_is_non_negative() {
        let start_time = Instant::now();
        let json = build_health_json(start_time);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v["uptime_secs"].as_u64().is_some(),
            "uptime_secs must be a non-negative integer"
        );
    }

    #[test]
    fn bearer_token_correct_returns_true() {
        assert!(check_bearer_token(
            Some("Bearer secret123"),
            Some("secret123")
        ));
    }

    #[test]
    fn bearer_token_wrong_returns_false() {
        assert!(!check_bearer_token(Some("Bearer wrong"), Some("secret123")));
    }

    #[test]
    fn bearer_token_missing_returns_false() {
        assert!(!check_bearer_token(None, Some("secret123")));
    }

    #[test]
    fn no_token_configured_always_passes() {
        assert!(check_bearer_token(None, None));
        assert!(check_bearer_token(Some("anything"), None));
    }

    // ── /pinning/remote endpoint tests ────────────────────────────────────────

    /// Empty table returns an empty array.
    #[tokio::test]
    async fn pinning_remote_empty_table_returns_empty_array() {
        let pool = make_pool().await;
        let json = build_pinning_remote_json(&pool).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array(), "expected JSON array, got: {json}");
        assert_eq!(
            v.as_array().unwrap().len(),
            0,
            "expected empty array: {json}"
        );
    }

    // ── /ipns endpoint tests ───────────────────────────────────────────────────

    /// Empty articles table returns correct JSON with null ipns_path and empty groups.
    #[tokio::test]
    async fn build_ipns_json_empty_db_no_path() {
        let pool = make_pool().await;
        let json = build_ipns_json(&pool, None).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v["ipns_path"].is_null(),
            "ipns_path must be null when disabled: {json}"
        );
        assert!(v["groups"].is_object(), "groups must be object: {json}");
        assert_eq!(
            v["groups"].as_object().unwrap().len(),
            0,
            "groups must be empty: {json}"
        );
    }

    /// With an IPNS path and no articles, groups is empty but ipns_path is populated.
    #[tokio::test]
    async fn build_ipns_json_with_path_no_articles() {
        let pool = make_pool().await;
        let json = build_ipns_json(&pool, Some("/ipns/12D3KooW..."))
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["ipns_path"], "/ipns/12D3KooW...",
            "ipns_path must match supplied value: {json}"
        );
        assert_eq!(
            v["groups"].as_object().unwrap().len(),
            0,
            "no articles → empty groups: {json}"
        );
    }

    /// Latest CID per group is returned; older articles are not included.
    #[tokio::test]
    async fn build_ipns_json_returns_latest_cid_per_group() {
        let pool = make_pool().await;

        // Insert two articles for comp.lang.rust: older then newer.
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms) \
             VALUES ('cid-old', 'comp.lang.rust', 1000), \
                    ('cid-new', 'comp.lang.rust', 2000)",
        )
        .execute(&*pool)
        .await
        .unwrap();

        let json = build_ipns_json(&pool, Some("/ipns/abc")).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let groups = v["groups"].as_object().unwrap();
        assert_eq!(
            groups.get("comp.lang.rust").and_then(|v| v.as_str()),
            Some("cid-new"),
            "must return newest CID, not older: {json}"
        );
        assert_eq!(groups.len(), 1, "one group in output: {json}");
    }

    /// `build_version_json` returns an object with `version` and `binary` string fields.
    #[test]
    fn version_json_has_required_fields() {
        let json = build_version_json();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["version"].is_string(), "version must be a string: {json}");
        assert!(v["binary"].is_string(), "binary must be a string: {json}");
    }

    /// `build_groups_json` returns an empty array when the articles table is empty.
    #[tokio::test]
    async fn groups_returns_empty_array_on_empty_db() {
        let pool = make_pool().await;
        let json = build_groups_json(&pool).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array(), "expected JSON array: {json}");
        assert_eq!(
            v.as_array().unwrap().len(),
            0,
            "expected empty array: {json}"
        );
    }

    // ── percent_decode tests ───────────────────────────────────────────────────

    #[test]
    fn percent_decode_plain_string_unchanged() {
        assert_eq!(percent_decode("comp.lang.rust"), "comp.lang.rust");
    }

    #[test]
    fn percent_decode_space_encoded() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    #[test]
    fn percent_decode_slash_encoded() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
    }

    #[test]
    fn percent_decode_uppercase_hex() {
        assert_eq!(percent_decode("%2F"), "/");
    }

    #[test]
    fn percent_decode_invalid_sequence_passed_through() {
        // %GG is not valid hex — leave it as-is.
        assert_eq!(percent_decode("%GG"), "%GG");
    }

    #[test]
    fn percent_decode_truncated_sequence_passed_through() {
        // % at end of string — leave it as-is.
        assert_eq!(percent_decode("foo%"), "foo%");
    }

    #[test]
    fn extract_query_param_decodes_percent_encoding() {
        let query = "group=alt.test%2Bfoo&limit=10";
        assert_eq!(
            extract_query_param(query, "group").as_deref(),
            Some("alt.test+foo")
        );
    }

    /// Groups appear in alphabetical order in the JSON output.
    #[tokio::test]
    async fn build_ipns_json_groups_alphabetical() {
        let pool = make_pool().await;

        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms) \
             VALUES ('cid-z', 'sci.math', 1000), \
                    ('cid-a', 'alt.test', 1000), \
                    ('cid-c', 'comp.lang.rust', 1000)",
        )
        .execute(&*pool)
        .await
        .unwrap();

        let json = build_ipns_json(&pool, None).await.unwrap();
        let alt_pos = json.find("alt.test").expect("alt.test must appear");
        let comp_pos = json
            .find("comp.lang.rust")
            .expect("comp.lang.rust must appear");
        let sci_pos = json.find("sci.math").expect("sci.math must appear");
        assert!(alt_pos < comp_pos, "alt.test must precede comp.lang.rust");
        assert!(comp_pos < sci_pos, "comp.lang.rust must precede sci.math");
    }

    /// Inserting jobs for two services returns one object per service with correct counts.
    #[tokio::test]
    async fn pinning_remote_counts_by_service_and_status() {
        let pool = make_pool().await;

        // Seed three rows for "pinata": 2 pending, 1 pinned.
        sqlx::query(
            "INSERT INTO remote_pin_jobs (cid, service_name, status) \
             VALUES ('Qm1', 'pinata', 'pending'), \
                    ('Qm2', 'pinata', 'pending'), \
                    ('Qm3', 'pinata', 'pinned')",
        )
        .execute(&*pool)
        .await
        .unwrap();

        // Seed one row for "web3": 1 queued.
        sqlx::query(
            "INSERT INTO remote_pin_jobs (cid, service_name, status) VALUES ('Qm4', 'web3', 'queued')",
        )
        .execute(&*pool)
        .await
        .unwrap();

        let json = build_pinning_remote_json(&pool).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().expect("expected array");
        assert_eq!(arr.len(), 2, "expected 2 service entries: {json}");

        // BTreeMap ordering: "pinata" < "web3"
        let pinata = &arr[0];
        assert_eq!(pinata["service"], "pinata");
        assert_eq!(pinata["pending"], 2);
        assert_eq!(pinata["pinned"], 1);
        assert_eq!(pinata["queued"], 0);

        let web3 = &arr[1];
        assert_eq!(web3["service"], "web3");
        assert_eq!(web3["queued"], 1);
        assert_eq!(web3["pending"], 0);
    }
}
