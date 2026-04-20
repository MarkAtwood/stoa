//! Admin HTTP server for the transit daemon.
//!
//! Listens on a configurable address and serves a small set of JSON endpoints
//! for operator inspection. No authentication; bind to loopback only in
//! production (see [`crate::config::AdminConfig`]).
//!
//! Endpoints:
//! - `GET /health`           — liveness check with uptime
//! - `GET /stats`            — article, pin, group, and peer counts from SQLite
//! - `GET /log-tip?group=X`  — tip CID and entry count for a group log
//! - `GET /peers`            — list of active (non-blacklisted) peers
//! - `GET /metrics`          — Prometheus text format (delegates to [`crate::metrics`])

use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use sqlx::SqlitePool;

/// Start the admin HTTP server on the given address.
///
/// Accepts `SqlitePool` for live stats queries. Spawns a background tokio task.
/// Returns immediately.
pub fn start_admin_server(
    addr: std::net::SocketAddr,
    pool: Arc<SqlitePool>,
    start_time: Instant,
) {
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
                    let pool = Arc::clone(&pool);
                    tokio::spawn(async move {
                        if let Err(e) = handle_admin_connection(stream, &pool, start_time).await {
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
}

async fn handle_admin_connection(
    mut stream: tokio::net::TcpStream,
    pool: &SqlitePool,
    start_time: Instant,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");

    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let path_and_query = parts.next().unwrap_or("");

    // Split path from query string.
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };

    if method != "GET" {
        write_json(&mut stream, 405, "Method Not Allowed", r#"{"error":"method not allowed"}"#).await?;
        return Ok(());
    }

    match path {
        "/health" => {
            let body = build_health_json(start_time);
            write_json(&mut stream, 200, "OK", &body).await?;
        }
        "/stats" => {
            match build_stats_json(pool).await {
                Ok(body) => write_json(&mut stream, 200, "OK", &body).await?,
                Err(e) => {
                    tracing::warn!("admin /stats error: {e}");
                    write_json(&mut stream, 500, "Internal Server Error", r#"{"error":"internal server error"}"#).await?;
                }
            }
        }
        "/log-tip" => {
            let group = extract_query_param(query, "group");
            match group {
                None => {
                    write_json(&mut stream, 400, "Bad Request", r#"{"error":"missing group parameter"}"#).await?;
                }
                Some(g) => {
                    match build_log_tip_json(pool, &g).await {
                        Some(body) => write_json(&mut stream, 200, "OK", &body).await?,
                        None => write_json(&mut stream, 404, "Not Found", r#"{"error":"group not found"}"#).await?,
                    }
                }
            }
        }
        "/peers" => {
            match build_peers_json(pool).await {
                Ok(body) => write_json(&mut stream, 200, "OK", &body).await?,
                Err(e) => {
                    tracing::warn!("admin /peers error: {e}");
                    write_json(&mut stream, 500, "Internal Server Error", r#"{"error":"internal server error"}"#).await?;
                }
            }
        }
        "/metrics" => {
            let body = crate::metrics::gather_metrics();
            let content_length = body.len();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {content_length}\r\n\r\n{body}"
            );
            stream.write_all(response.as_bytes()).await?;
        }
        _ => {
            write_json(&mut stream, 404, "Not Found", r#"{"error":"not found"}"#).await?;
        }
    }

    Ok(())
}

/// Extract the value of a named query parameter from a URL query string.
/// Only handles simple `key=value` pairs; does not decode percent-encoding.
fn extract_query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
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

pub(crate) fn build_health_json(start_time: Instant) -> String {
    let uptime_secs = start_time.elapsed().as_secs();
    serde_json::json!({
        "status": "ok",
        "uptime_secs": uptime_secs,
    })
    .to_string()
}

pub(crate) async fn build_stats_json(pool: &SqlitePool) -> Result<String, sqlx::Error> {
    let articles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM msgid_map")
        .fetch_one(pool)
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
    let row: Option<(Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT MAX(sequence_number), cid FROM group_log WHERE group_name = ?",
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::sync::atomic::AtomicUsize;

    static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

    async fn make_pool() -> Arc<SqlitePool> {
        let n = DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let url = format!("file:admin_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::new()
            .filename(&url)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        Arc::new(pool)
    }

    #[tokio::test]
    async fn health_handler_returns_ok_json() {
        let start_time = Instant::now();
        let json = build_health_json(start_time);
        assert!(json.contains("\"status\""), "missing status key: {json}");
        assert!(json.contains("\"ok\""), "missing ok value: {json}");
        assert!(json.contains("\"uptime_secs\""), "missing uptime_secs: {json}");
    }

    #[tokio::test]
    async fn stats_handler_returns_zero_counts_on_empty_db() {
        let pool = make_pool().await;
        let json = build_stats_json(&pool).await.unwrap();
        assert!(json.contains("\"articles\""), "missing articles: {json}");
        assert!(json.contains("\"pinned_cids\""), "missing pinned_cids: {json}");
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
        assert!(result.is_none(), "expected None for unknown group, got: {result:?}");
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
        assert!(v["uptime_secs"].as_u64().is_some(), "uptime_secs must be a non-negative integer");
    }
}
