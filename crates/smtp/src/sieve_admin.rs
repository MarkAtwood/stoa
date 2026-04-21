/// HTTP admin API for per-user Sieve script management.
///
/// ManageSieve (RFC 5804) requires TLS before PLAIN auth, which is out of scope
/// for v1.  This HTTP API provides the same functionality over loopback TCP,
/// with access control enforced by the bind address (default 127.0.0.1:4190).
///
/// # Endpoints
///
/// | Method | Path                                        | Description       |
/// |--------|---------------------------------------------|-------------------|
/// | GET    | /admin/sieve/{username}                     | List scripts      |
/// | GET    | /admin/sieve/{username}/{name}              | Get script bytes  |
/// | PUT    | /admin/sieve/{username}/{name}              | Upload script     |
/// | DELETE | /admin/sieve/{username}/{name}              | Delete script     |
/// | POST   | /admin/sieve/{username}/{name}/activate     | Set active script |
/// | POST   | /admin/sieve/check                          | Validate (no save)|
use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;
use crate::session::SieveCache;
use crate::store;

/// Returns `true` if `addr` resolves to a loopback address.
fn is_loopback_addr(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost",
    }
}

#[derive(Clone)]
struct AdminState {
    config: Arc<Config>,
    pool: SqlitePool,
    sieve_cache: SieveCache,
}

/// Validate a script name: must be non-empty, no path separators, no null bytes.
fn valid_script_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
}

/// Axum middleware that enforces the bearer token configured in
/// `sieve_admin.bearer_token`.
///
/// If no token is configured, all requests pass through (backward compatible).
/// If a token is configured, requests must include `Authorization: Bearer <token>`;
/// missing or incorrect tokens receive `401 Unauthorized`.
async fn require_bearer_token(
    State(s): State<AdminState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(expected) = &s.config.sieve_admin.bearer_token {
        use subtle::ConstantTimeEq as _;
        let auth = request
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let expected_header = format!("Bearer {expected}");
        let ok: bool = match auth {
            None => false,
            Some(header) => expected_header.as_bytes().ct_eq(header.as_bytes()).into(),
        };
        if !ok {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    }
    next.run(request).await
}

/// Performs the fail-closed startup check and, if the configuration is safe,
/// spawns the Sieve admin HTTP server task.
///
/// Returns `Err` immediately when the endpoint is bound to a non-loopback
/// address without a bearer token and without `allow_non_loopback = true`.
/// The caller must treat this as a fatal startup error.
pub fn start_sieve_admin_server(
    config: Arc<Config>,
    pool: SqlitePool,
    sieve_cache: SieveCache,
) -> Result<(), String> {
    let bind = &config.sieve_admin.bind;
    let has_token = config.sieve_admin.bearer_token.is_some();
    if !is_loopback_addr(bind) && !config.sieve_admin.allow_non_loopback && !has_token {
        return Err(format!(
            "sieve admin endpoint at {bind} is on a non-loopback interface but no \
             bearer_token is configured — refusing to start an unauthenticated admin server"
        ));
    }
    tokio::spawn(run_admin_server(config, pool, sieve_cache));
    Ok(())
}

/// Inner async loop: bind and serve.  Called only after the fail-closed check
/// in `start_sieve_admin_server` has passed.
async fn run_admin_server(config: Arc<Config>, pool: SqlitePool, sieve_cache: SieveCache) {
    let bind = &config.sieve_admin.bind;

    let listener = match TcpListener::bind(bind).await {
        Ok(l) => {
            info!(%bind, "Sieve admin API listening");
            l
        }
        Err(e) => {
            tracing::error!(%bind, "failed to bind Sieve admin API: {e}");
            return;
        }
    };

    let state = AdminState { config, pool, sieve_cache };
    let app = Router::new()
        .route("/admin/sieve/{username}", get(list_scripts))
        .route("/admin/sieve/{username}/{name}", get(get_script))
        .route("/admin/sieve/{username}/{name}", put(put_script))
        .route("/admin/sieve/{username}/{name}", delete(delete_script))
        .route("/admin/sieve/{username}/{name}/activate", post(activate_script))
        .route("/admin/sieve/check", post(check_script))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer_token,
        ))
        .with_state(state);

    if let Err(e) = axum::serve(listener, app).await {
        // Log the error but do not panic — a panic in a spawned task is caught
        // by the tokio runtime and silently aborts only that task, so the
        // operator would have no indication the admin API has stopped.
        tracing::error!("Sieve admin server stopped with error: {e}");
    }
}

/// GET /admin/sieve/{username}
/// Returns a JSON array of `{"name": "...", "active": true|false}` objects.
async fn list_scripts(
    State(s): State<AdminState>,
    Path(username): Path<String>,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    match store::list_scripts(&s.pool, &username).await {
        Ok(scripts) => {
            let json = scripts
                .iter()
                .map(|(name, active)| {
                    format!(r#"{{"name":{:?},"active":{}}}"#, name, active)
                })
                .collect::<Vec<_>>()
                .join(",");
            (
                StatusCode::OK,
                [("Content-Type", "application/json")],
                format!("[{}]", json),
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /admin/sieve/{username}/{name}
/// Returns the raw Sieve script bytes (text/plain).
async fn get_script(
    State(s): State<AdminState>,
    Path((username, name)): Path<(String, String)>,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    if !valid_script_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid script name").into_response();
    }
    match store::get_script(&s.pool, &username, &name).await {
        Ok(Some(bytes)) => (
            StatusCode::OK,
            [("Content-Type", "text/plain; charset=utf-8")],
            bytes,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "script not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// PUT /admin/sieve/{username}/{name}
/// Body: raw Sieve script bytes.
/// Returns 201 on success, 413 if too large, 422 if script fails to parse.
async fn put_script(
    State(s): State<AdminState>,
    Path((username, name)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    if !valid_script_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid script name").into_response();
    }
    if body.len() as u64 > s.config.sieve_admin.max_script_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, "script exceeds size limit").into_response();
    }
    if let Err(e) = usenet_ipfs_sieve::compile(&body) {
        return (StatusCode::UNPROCESSABLE_ENTITY, format!("Sieve parse error: {e}"))
            .into_response();
    }
    match store::save_script(&s.pool, &username, &name, &body, false).await {
        Ok(()) => {
            s.sieve_cache.lock().await.remove(&username);
            (StatusCode::CREATED, "").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// DELETE /admin/sieve/{username}/{name}
async fn delete_script(
    State(s): State<AdminState>,
    Path((username, name)): Path<(String, String)>,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    if !valid_script_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid script name").into_response();
    }
    match store::delete_script(&s.pool, &username, &name).await {
        Ok(true) => {
            s.sieve_cache.lock().await.remove(&username);
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "script not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /admin/sieve/{username}/{name}/activate
async fn activate_script(
    State(s): State<AdminState>,
    Path((username, name)): Path<(String, String)>,
) -> Response {
    if !user_exists(&s, &username) {
        return (StatusCode::NOT_FOUND, "user not found").into_response();
    }
    if !valid_script_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid script name").into_response();
    }
    match store::set_active(&s.pool, &username, &name).await {
        Ok(true) => {
            s.sieve_cache.lock().await.remove(&username);
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "script not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /admin/sieve/check
/// Validates the body as a Sieve script without storing it.
/// Returns 200 on success, 422 with error text on failure.
async fn check_script(body: Bytes) -> Response {
    match usenet_ipfs_sieve::compile(&body) {
        Ok(_) => (StatusCode::OK, "OK").into_response(),
        Err(e) => {
            (StatusCode::UNPROCESSABLE_ENTITY, format!("Sieve parse error: {e}")).into_response()
        }
    }
}

fn user_exists(s: &AdminState, username: &str) -> bool {
    s.config.users.iter().any(|u| u.username == username)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt as _;

    use crate::config::{DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, ReaderConfig, TlsConfig, UserConfig};

    fn test_config(users: Vec<UserConfig>) -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig { port_25: "127.0.0.1:0".into(), port_587: "127.0.0.1:0".into() },
            tls: TlsConfig { cert_path: None, key_path: None },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users,
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig::default(),
            dns_resolver: "system".to_string(),
        })
    }

    fn alice() -> UserConfig {
        UserConfig { username: "alice".into(), email: "alice@example.com".into() }
    }

    async fn app_with_alice() -> (Router, SqlitePool) {
        let (app, pool, _cache) = app_with_alice_and_cache().await;
        (app, pool)
    }

    async fn app_with_alice_and_cache() -> (Router, SqlitePool, crate::session::SieveCache) {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let config = test_config(vec![alice()]);
        let cache = crate::session::new_sieve_cache();
        let state = AdminState { config, pool: pool.clone(), sieve_cache: cache.clone() };
        let app = Router::new()
            .route("/admin/sieve/{username}", get(list_scripts))
            .route("/admin/sieve/{username}/{name}", get(get_script))
            .route("/admin/sieve/{username}/{name}", put(put_script))
            .route("/admin/sieve/{username}/{name}", delete(delete_script))
            .route("/admin/sieve/{username}/{name}/activate", post(activate_script))
            .route("/admin/sieve/check", post(check_script))
            .with_state(state);
        (app, pool, cache)
    }

    async fn response_body(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn putscript_valid_stores_and_returns_201() {
        let (app, pool) = app_with_alice().await;
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/alice/default")
            .body(Body::from("keep;"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let stored = store::get_script(&pool, "alice", "default").await.unwrap();
        assert_eq!(stored.as_deref(), Some(b"keep;" as &[u8]));
    }

    #[tokio::test]
    async fn putscript_invalid_sieve_returns_422() {
        let (app, _) = app_with_alice().await;
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/alice/default")
            .body(Body::from("this is not valid sieve @@@@"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn putscript_too_large_returns_413() {
        let (app, _) = app_with_alice().await;
        let big = vec![b'#'; 65_537]; // one byte over 64 KiB default
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/alice/default")
            .body(Body::from(big))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn putscript_unknown_user_returns_404() {
        let (app, _) = app_with_alice().await;
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/unknown/default")
            .body(Body::from("keep;"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn getscript_returns_stored_bytes() {
        let (app, pool) = app_with_alice().await;
        store::save_script(&pool, "alice", "work", b"discard;", false).await.unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/alice/work")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert_eq!(body, "discard;");
    }

    #[tokio::test]
    async fn getscript_missing_returns_404() {
        let (app, _) = app_with_alice().await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/alice/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn listscripts_returns_names_and_active_flag() {
        let (app, pool) = app_with_alice().await;
        store::save_script(&pool, "alice", "a", b"keep;", false).await.unwrap();
        store::save_script(&pool, "alice", "b", b"discard;", true).await.unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/alice")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert!(body.contains("\"a\""), "expected script a in list: {body}");
        assert!(body.contains("\"b\""), "expected script b in list: {body}");
    }

    #[tokio::test]
    async fn deletescript_removes_row() {
        let (app, pool) = app_with_alice().await;
        store::save_script(&pool, "alice", "tmp", b"keep;", false).await.unwrap();

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/sieve/alice/tmp")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let remaining = store::get_script(&pool, "alice", "tmp").await.unwrap();
        assert!(remaining.is_none(), "expected script to be deleted");
    }

    #[tokio::test]
    async fn deletescript_missing_returns_404() {
        let (app, _) = app_with_alice().await;
        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/sieve/alice/ghost")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn setactive_switches_active_script() {
        let (app, pool) = app_with_alice().await;
        store::save_script(&pool, "alice", "first", b"keep;", true).await.unwrap();
        store::save_script(&pool, "alice", "second", b"discard;", false).await.unwrap();

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/sieve/alice/second/activate")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let scripts = store::list_scripts(&pool, "alice").await.unwrap();
        let first_active = scripts.iter().find(|(n, _)| n == "first").map(|(_, a)| *a);
        let second_active = scripts.iter().find(|(n, _)| n == "second").map(|(_, a)| *a);
        assert_eq!(first_active, Some(false), "first should be deactivated");
        assert_eq!(second_active, Some(true), "second should be active");
    }

    #[tokio::test]
    async fn checkscript_valid_returns_200_no_storage() {
        let (app, pool) = app_with_alice().await;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/sieve/check")
            .body(Body::from("keep;"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Nothing should be stored.
        let scripts = store::list_scripts(&pool, "alice").await.unwrap();
        assert!(scripts.is_empty(), "check must not store anything");
    }

    #[tokio::test]
    async fn checkscript_invalid_returns_422() {
        let (app, _) = app_with_alice().await;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/sieve/check")
            .body(Body::from("bogus @@ !! script"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    fn test_config_with_token(users: Vec<UserConfig>, token: &str) -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig { port_25: "127.0.0.1:0".into(), port_587: "127.0.0.1:0".into() },
            tls: TlsConfig { cert_path: None, key_path: None },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users,
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig {
                bearer_token: Some(token.to_string()),
                ..Default::default()
            },
            dns_resolver: "system".to_string(),
        })
    }

    async fn app_with_token(token: &str) -> Router {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let config = test_config_with_token(vec![alice()], token);
        let cache = crate::session::new_sieve_cache();
        let state = AdminState { config, pool, sieve_cache: cache };
        Router::new()
            .route("/admin/sieve/{username}", get(list_scripts))
            .route("/admin/sieve/{username}/{name}", get(get_script))
            .route("/admin/sieve/{username}/{name}", put(put_script))
            .route("/admin/sieve/{username}/{name}", delete(delete_script))
            .route("/admin/sieve/{username}/{name}/activate", post(activate_script))
            .route("/admin/sieve/check", post(check_script))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_bearer_token,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn bearer_token_missing_returns_401() {
        let app = app_with_token("secret").await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/alice")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_token_wrong_returns_401() {
        let app = app_with_token("secret").await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/alice")
            .header("Authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_token_correct_allows_request() {
        let app = app_with_token("secret").await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/sieve/alice")
            .header("Authorization", "Bearer secret")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Cache invalidation tests ──────────────────────────────────────────

    #[tokio::test]
    async fn put_script_invalidates_cache_entry() {
        let (app, _pool, cache) = app_with_alice_and_cache().await;

        // Pre-populate the cache with a stale entry.
        cache.lock().await.insert(
            "alice".to_string(),
            std::sync::Arc::new(usenet_ipfs_sieve::compile(b"discard;").unwrap()),
        );

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/sieve/alice/default")
            .body(Body::from("keep;"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(
            !cache.lock().await.contains_key("alice"),
            "cache entry must be removed after PUT"
        );
    }

    #[tokio::test]
    async fn delete_script_invalidates_cache_entry() {
        let (app, pool, cache) = app_with_alice_and_cache().await;
        store::save_script(&pool, "alice", "tmp", b"keep;", true).await.unwrap();

        cache.lock().await.insert(
            "alice".to_string(),
            std::sync::Arc::new(usenet_ipfs_sieve::compile(b"keep;").unwrap()),
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/sieve/alice/tmp")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            !cache.lock().await.contains_key("alice"),
            "cache entry must be removed after DELETE"
        );
    }

    #[tokio::test]
    async fn activate_script_invalidates_cache_entry() {
        let (app, pool, cache) = app_with_alice_and_cache().await;
        store::save_script(&pool, "alice", "s", b"discard;", false).await.unwrap();

        cache.lock().await.insert(
            "alice".to_string(),
            std::sync::Arc::new(usenet_ipfs_sieve::compile(b"discard;").unwrap()),
        );

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/sieve/alice/s/activate")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            !cache.lock().await.contains_key("alice"),
            "cache entry must be removed after activate"
        );
    }

    // ── Fail-closed startup check ─────────────────────────────────────────

    fn fail_closed_config(
        bind: &str,
        bearer_token: Option<&str>,
        allow_non_loopback: bool,
    ) -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".into(),
                port_587: "127.0.0.1:0".into(),
            },
            tls: TlsConfig { cert_path: None, key_path: None },
            limits: LimitsConfig::default(),
            log: LogConfig::default(),
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users: vec![],
            database: DatabaseConfig::default(),
            sieve_admin: crate::config::SieveAdminConfig {
                bind: bind.to_string(),
                allow_non_loopback,
                bearer_token: bearer_token.map(str::to_string),
                max_script_bytes: 65_536,
            },
            dns_resolver: "system".to_string(),
        })
    }

    #[tokio::test]
    async fn start_non_loopback_no_token_returns_err() {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let cache = crate::session::new_sieve_cache();
        let config = fail_closed_config("0.0.0.0:4190", None, false);
        let result = start_sieve_admin_server(config, pool, cache);
        assert!(result.is_err(), "expected Err for non-loopback without token");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("non-loopback"),
            "error message should mention non-loopback: {msg}"
        );
    }

    #[tokio::test]
    async fn start_non_loopback_with_token_returns_ok() {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let cache = crate::session::new_sieve_cache();
        let config = fail_closed_config("0.0.0.0:0", Some("secret"), false);
        let result = start_sieve_admin_server(config, pool, cache);
        assert!(result.is_ok(), "expected Ok for non-loopback with token: {:?}", result.err());
    }

    #[tokio::test]
    async fn start_non_loopback_allow_override_returns_ok() {
        let pool = crate::store::open(":memory:").await.expect("open db");
        let cache = crate::session::new_sieve_cache();
        let config = fail_closed_config("0.0.0.0:0", None, true);
        let result = start_sieve_admin_server(config, pool, cache);
        assert!(result.is_ok(), "expected Ok when allow_non_loopback=true: {:?}", result.err());
    }
}
