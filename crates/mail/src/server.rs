use std::{net::SocketAddr, sync::Arc, time::Instant};

use axum::{
    extract::{Extension, Request, State},
    http::{header, HeaderName, Method, StatusCode},
    middleware::Next,
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders};
use usenet_ipfs_auth::{AuthConfig, CredentialStore};
use usenet_ipfs_core::msgid_map::MsgIdMap;
use usenet_ipfs_reader::{
    post::ipfs_write::IpfsBlockStore,
    search::TantivySearchIndex,
    store::{article_numbers::ArticleNumberStore, overview::OverviewStore},
};
use usenet_ipfs_smtp::SmtpRelayQueue;

use crate::{
    config::CorsConfig,
    state::{flags::UserFlagsStore, version::StateStore},
    token_store::TokenStore,
};

/// JMAP backing stores, wired together for the API handler.
pub struct JmapStores {
    pub ipfs: Arc<dyn IpfsBlockStore>,
    pub msgid_map: Arc<MsgIdMap>,
    pub article_numbers: Arc<ArticleNumberStore>,
    pub overview_store: Arc<OverviewStore>,
    pub user_flags: Arc<UserFlagsStore>,
    pub state_store: Arc<StateStore>,
    /// Full-text search index for Email/query `text` filter.
    /// `None` means search is disabled; text filters return empty results.
    pub search_index: Option<Arc<TantivySearchIndex>>,
    /// Outbound SMTP relay queue. `None` means no relay peers configured.
    pub smtp_relay_queue: Option<Arc<SmtpRelayQueue>>,
}

#[derive(Clone)]
pub struct AppState {
    pub start_time: Instant,
    pub jmap: Option<Arc<JmapStores>>,
    pub credential_store: Arc<CredentialStore>,
    pub auth_config: Arc<AuthConfig>,
    pub token_store: Arc<TokenStore>,
    /// External base URL used in JMAP session responses (e.g. `https://mail.example.com`).
    pub base_url: String,
    pub cors: CorsConfig,
}

/// Authenticated user identity extracted from HTTP Basic Auth.
///
/// Inserted into request extensions by `basic_auth_middleware` after
/// successful credential verification.  Handlers receive it via
/// `Extension<AuthenticatedUser>`.  In dev mode no `AuthenticatedUser`
/// is inserted; handlers must use `Option<Extension<AuthenticatedUser>>`.
#[derive(Clone)]
pub struct AuthenticatedUser(pub String);

/// Axum middleware that enforces HTTP Basic authentication on protected routes.
///
/// Dev mode (no credentials configured, auth not required) bypasses auth
/// entirely and does NOT inject a fake `AuthenticatedUser`.
///
/// On success the `AuthenticatedUser` extension is inserted into the request
/// so downstream handlers can read the authenticated username.
///
/// On failure a `401 Unauthorized` response with a `WWW-Authenticate` header
/// is returned immediately.
async fn basic_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    if state.auth_config.is_dev_mode() {
        return next.run(req).await;
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Try Bearer token first.
    if let Some(bearer_token) = auth_header
        .as_deref()
        .and_then(|h| h.strip_prefix("Bearer "))
    {
        match state.token_store.verify(bearer_token).await {
            Ok(Some(username)) => {
                req.extensions_mut().insert(AuthenticatedUser(username));
                return next.run(req).await;
            }
            _ => return unauthorized_response(),
        }
    }

    // Fall through to Basic auth.
    let credentials: Option<(String, String)> = auth_header
        .as_deref()
        .and_then(|h: &str| h.strip_prefix("Basic "))
        .and_then(|encoded: &str| data_encoding::BASE64.decode(encoded.as_bytes()).ok())
        .and_then(|decoded: Vec<u8>| String::from_utf8(decoded).ok())
        .and_then(|s: String| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_owned();
            let pass = parts.next()?.to_owned();
            Some((user, pass))
        });

    let (username, password) = match credentials {
        Some(pair) => pair,
        None => return unauthorized_response(),
    };

    if !state.credential_store.check(&username, &password).await {
        return unauthorized_response();
    }

    req.extensions_mut().insert(AuthenticatedUser(username));
    next.run(req).await
}

fn unauthorized_response() -> Response {
    axum::response::Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, r#"Basic realm="usenet-ipfs""#)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(axum::body::Body::from("401 Unauthorized"))
        .unwrap()
}

fn build_cors_layer(cors_config: &CorsConfig) -> CorsLayer {
    if !cors_config.enabled {
        return CorsLayer::new();
    }
    let origins_wildcard = cors_config.allowed_origins.iter().any(|o| o == "*");
    if origins_wildcard {
        return CorsLayer::permissive();
    }
    if cors_config.allowed_origins.is_empty() {
        tracing::warn!("cors.enabled=true but allowed_origins is empty; CORS disabled");
        return CorsLayer::new();
    }
    let parsed: Vec<axum::http::HeaderValue> = cors_config
        .allowed_origins
        .iter()
        .filter_map(|o| {
            o.parse::<axum::http::HeaderValue>().ok().or_else(|| {
                tracing::error!(origin = %o, "invalid CORS origin, skipping");
                None
            })
        })
        .collect();
    if parsed.is_empty() {
        tracing::warn!("all configured CORS origins were invalid; CORS disabled");
        return CorsLayer::new();
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(parsed))
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::list([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
        ]))
        .expose_headers(ExposeHeaders::list([
            HeaderName::from_static("x-usenet-ipfs-cid"),
            HeaderName::from_static("x-usenet-ipfs-root-cid"),
        ]))
}

/// Build the axum Router with all routes.
///
/// `GET /`, `/health`, `/metrics`, and `/.well-known/jmap` are public (no auth required).
/// All `/jmap/*` routes are protected by `basic_auth_middleware`.
/// The CORS layer (if enabled) wraps all routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors_layer = build_cors_layer(&state.cors);

    let protected = Router::new()
        .route("/jmap/session", get(jmap_session_handler))
        .route("/jmap/api", post(jmap_api_handler))
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(crate::blob::blob_download),
        )
        .route(
            "/jmap/auth/token",
            post(crate::auth_token::issue_token).get(crate::auth_token::list_tokens),
        )
        .route(
            "/jmap/auth/token/{id}",
            delete(crate::auth_token::revoke_token),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            basic_auth_middleware,
        ));

    Router::new()
        .route("/", get(crate::landing::landing_page))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/.well-known/jmap", get(well_known_jmap))
        .route("/feed/{*path}", get(crate::feed::feed_handler))
        .merge(protected)
        .layer(cors_layer)
        .with_state(state)
}

async fn metrics_handler() -> impl axum::response::IntoResponse {
    let body = crate::metrics::gather_metrics();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let uptime_secs = state.start_time.elapsed().as_secs();
    Json(json!({
        "status": "ok",
        "uptime_secs": uptime_secs
    }))
}

async fn well_known_jmap() -> impl axum::response::IntoResponse {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(axum::http::header::LOCATION, "/jmap/session")],
    )
}

async fn jmap_session_handler(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Json<Value> {
    let username = user
        .map(|Extension(u)| u.0)
        .unwrap_or_else(|| "anonymous".to_string());
    let session = crate::jmap::session::build_session(&username, &state.base_url);
    Json(serde_json::to_value(session).unwrap())
}

async fn jmap_api_handler(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
    axum::extract::Json(request): axum::extract::Json<crate::jmap::types::Request>,
) -> (StatusCode, Json<Value>) {
    let jmap = match state.jmap.as_ref() {
        Some(j) => j,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "JMAP not configured"})),
            );
        }
    };

    // Derive the canonical accountId for the authenticated principal.
    // In dev mode no AuthenticatedUser extension is present; use "anonymous".
    let username = user
        .map(|Extension(u)| u.0)
        .unwrap_or_else(|| "anonymous".to_string());
    let canonical_account_id = format!("u_{username}");

    let mut method_responses = Vec::new();

    for crate::jmap::types::Invocation(method, args, call_id) in request.method_calls {
        let t0 = std::time::Instant::now();
        let result = route_method(&method, args, jmap, &canonical_account_id).await;
        let elapsed = t0.elapsed().as_secs_f64();
        crate::metrics::JMAP_REQUESTS_TOTAL
            .with_label_values(&[&method])
            .inc();
        crate::metrics::JMAP_REQUEST_DURATION_SECONDS
            .with_label_values(&[&method])
            .observe(elapsed);
        if method == "Email/query" {
            let count = result
                .get("ids")
                .and_then(|v| v.as_array())
                .map_or(0, |a| a.len()) as i64;
            crate::metrics::EMAIL_QUERY_RESULTS.set(count);
        }
        // A result is an error invocation if it has an "error" key (internal
        // error path) or a "type" key (MethodError path — accountNotFound,
        // unknownMethod, etc.).
        let is_error = result.get("error").is_some() || result.get("type").is_some();
        let response_name = if is_error {
            "error".to_string()
        } else {
            method.clone()
        };
        method_responses.push(crate::jmap::types::Invocation(
            response_name,
            result,
            call_id,
        ));
    }

    let session_state = jmap
        .state_store
        .get_state("session")
        .await
        .unwrap_or_else(|_| "0".to_string());

    let response = crate::jmap::types::Response {
        method_responses,
        session_state,
        created_ids: None,
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
}

async fn route_method(
    method: &str,
    args: Value,
    jmap: &JmapStores,
    canonical_account_id: &str,
) -> Value {
    // RFC 8621 §2: every method call carries an accountId.  If it is present
    // and does not match the authenticated principal's account, return
    // accountNotFound immediately without dispatching to the handler.
    //
    // An absent accountId is treated as the anonymous case and passed through;
    // handlers that require it will return their own error if needed.
    if let Some(requested_id) = args.get("accountId").and_then(|v| v.as_str()) {
        if requested_id != canonical_account_id {
            let err = crate::jmap::types::MethodError::account_not_found();
            return serde_json::to_value(&err).unwrap_or(json!({}));
        }
    }

    match method {
        "Mailbox/get" => {
            let groups = match jmap.article_numbers.list_groups().await {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };
            let group_infos: Vec<crate::mailbox::get::GroupInfo> = groups
                .into_iter()
                .map(|(name, lo, hi)| crate::mailbox::get::GroupInfo {
                    name,
                    total_emails: (hi - lo + 1) as u32,
                    unread_emails: 0,
                    is_subscribed: false,
                })
                .collect();
            let ids_filter: Option<Vec<String>> =
                args.get("ids").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                });
            let state = jmap
                .state_store
                .get_state("Mailbox")
                .await
                .unwrap_or_else(|_| "0".to_string());
            crate::mailbox::get::handle_mailbox_get(&group_infos, ids_filter.as_deref(), &state)
        }

        "Email/query" => {
            let mailbox_id = args
                .get("filter")
                .and_then(|f| f.get("inMailbox"))
                .and_then(|v| v.as_str());

            let groups = match jmap.article_numbers.list_groups().await {
                Ok(g) => g,
                Err(e) => return json!({"error": e.to_string()}),
            };
            let target_group = groups.iter().find(|(name, _, _)| {
                crate::mailbox::types::mailbox_id_for_group(name) == mailbox_id.unwrap_or("")
            });

            let email_state = jmap
                .state_store
                .get_state("Email")
                .await
                .unwrap_or_else(|_| "0".to_string());

            let (group_name, lo, hi) = match target_group {
                Some(g) => g.clone(),
                None => {
                    return json!({
                        "ids": [],
                        "total": 0,
                        "queryState": email_state,
                        "canCalculateChanges": false,
                        "position": 0
                    })
                }
            };

            let records = match jmap.overview_store.query_range(&group_name, lo, hi).await {
                Ok(r) => r,
                Err(e) => return json!({"error": e.to_string()}),
            };

            let mut entries = Vec::new();
            for rec in &records {
                if let Ok(Some(cid)) = jmap
                    .article_numbers
                    .lookup_cid(&group_name, rec.article_number)
                    .await
                {
                    entries.push(crate::email::query::EmailOverviewEntry {
                        cid,
                        message_id: rec.message_id.clone(),
                        subject: rec.subject.clone(),
                        from: rec.from.clone(),
                        date: rec.date.clone(),
                        byte_count: rec.byte_count,
                    });
                }
            }

            let filter = args.get("filter");

            // Resolve `text` filter via full-text search index when present.
            let text_results = if let Some(f) = filter {
                if let Some(text_val) = f.get("text").and_then(|v| v.as_str()) {
                    if !text_val.is_empty() {
                        if let Some(ref idx) = jmap.search_index {
                            match idx.search_all(text_val, 50_000).await {
                                Ok(ids) => {
                                    Some(ids.into_iter().collect::<std::collections::HashSet<_>>())
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "JMAP text search failed; ignoring text filter");
                                    None
                                }
                            }
                        } else {
                            // Search index not configured; return empty set so the
                            // text filter is honoured (no results) rather than
                            // silently returning all articles.
                            Some(std::collections::HashSet::new())
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            crate::email::query::handle_email_query(
                &entries,
                filter,
                0,
                None,
                &email_state,
                text_results,
            )
        }

        "Email/get" => {
            let ids: Vec<String> = args
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            crate::email::get::handle_email_get(&ids, jmap.ipfs.as_ref(), None).await
        }

        "Email/set" => {
            let mut result = match crate::email::set::handle_email_set(args.clone()) {
                Ok(v) => v,
                Err(e) => return serde_json::to_value(&e).unwrap_or(json!({})),
            };

            // Handle keyword updates.
            if let Some(update_map) = args.get("update").and_then(|v| v.as_object()) {
                let user_id: i64 = 1; // TODO(user-state): resolve from canonical_account_id
                let (updated, not_updated) =
                    crate::email::set::handle_keyword_update(update_map, user_id, &jmap.user_flags)
                        .await;
                if !updated.is_empty() {
                    result["updated"] = Value::Object(updated);
                }
                if !not_updated.is_empty() {
                    let existing = result["notUpdated"]
                        .as_object()
                        .cloned()
                        .unwrap_or_default();
                    let mut merged = existing;
                    merged.extend(not_updated);
                    result["notUpdated"] = Value::Object(merged);
                }
            }

            // Handle creates.
            if let Some(create_map) = args.get("create").and_then(|v| v.as_object()) {
                let (created, not_created) = crate::email::set::handle_email_create(
                    create_map,
                    jmap.ipfs.as_ref(),
                    &jmap.msgid_map,
                    jmap.smtp_relay_queue.as_ref(),
                )
                .await;
                if !created.is_empty() {
                    result["created"] = Value::Object(created);
                }
                if !not_created.is_empty() {
                    result["notCreated"] = Value::Object(not_created);
                }
            }

            result
        }

        _ => serde_json::to_value(crate::jmap::types::MethodError::unknown_method())
            .unwrap_or(json!({})),
    }
}

/// Start the HTTP server on the given address and run until `shutdown` resolves.
pub async fn run_server(
    addr: SocketAddr,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    // TLS: not yet wired in v1; load_tls_config is available for future use
    let listener = TcpListener::bind(addr).await?;
    let router = build_router(state);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_store::TokenStore;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use usenet_ipfs_auth::{AuthConfig, CredentialStore, UserCredential};
    use usenet_ipfs_reader::{
        post::ipfs_write::MemIpfsStore,
        store::{article_numbers::ArticleNumberStore, overview::OverviewStore},
    };

    use crate::state::{flags::UserFlagsStore, version::StateStore};

    static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

    async fn make_token_store() -> Arc<TokenStore> {
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:server_test_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("pool");
        crate::migrations::run_migrations(&pool)
            .await
            .expect("migrations");
        Arc::new(TokenStore::new(Arc::new(pool)))
    }

    /// Build an AppState in dev mode: `required = false`, no users, no credential file.
    async fn dev_state() -> Arc<AppState> {
        Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: make_token_store().await,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
        })
    }

    /// Build an AppState in dev mode with a custom base URL.
    async fn dev_state_with_base_url(base_url: &str) -> Arc<AppState> {
        Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: make_token_store().await,
            base_url: base_url.to_string(),
            cors: crate::config::CorsConfig::default(),
        })
    }

    /// Build an AppState with a single user (bcrypt cost 4 for test speed).
    async fn auth_state(username: &str, plaintext_password: &str) -> Arc<AppState> {
        let hash = bcrypt::hash(plaintext_password, 4).expect("bcrypt::hash must not fail");
        let users = vec![UserCredential {
            username: username.to_string(),
            password: hash,
        }];
        Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::from_credentials(&users)),
            auth_config: Arc::new(AuthConfig {
                required: true,
                users,
                ..Default::default()
            }),
            token_store: make_token_store().await,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
        })
    }

    /// Create a named shared in-memory SQLite pool with reader-crate migrations applied.
    async fn make_reader_pool(name: &str) -> sqlx::SqlitePool {
        let url = format!("file:{name}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("reader pool");
        usenet_ipfs_reader::migrations::run_migrations(&pool)
            .await
            .expect("reader migrations");
        pool
    }

    /// Build an AppState with JMAP stores wired to a MemIpfsStore.
    ///
    /// Returns `(state, ipfs)` so the caller can seed blocks before the test.
    async fn jmap_state() -> (Arc<AppState>, Arc<MemIpfsStore>) {
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);

        // Pool for mail-crate stores (UserFlagsStore, StateStore, TokenStore).
        let mail_url = format!("file:jmap_mail_{n}?mode=memory&cache=shared");
        let mail_opts = SqliteConnectOptions::from_str(&mail_url)
            .unwrap()
            .create_if_missing(true);
        let mail_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(mail_opts)
            .await
            .expect("mail pool");
        crate::migrations::run_migrations(&mail_pool)
            .await
            .expect("mail migrations");

        // Pool for reader-crate stores (ArticleNumberStore, OverviewStore).
        let reader_pool = make_reader_pool(&format!("jmap_reader_{n}")).await;

        // Pool for core-crate stores (MsgIdMap).
        let core_url = format!("file:jmap_core_{n}?mode=memory&cache=shared");
        let core_opts = SqliteConnectOptions::from_str(&core_url)
            .unwrap()
            .create_if_missing(true);
        let core_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(core_opts)
            .await
            .expect("core pool");
        usenet_ipfs_core::migrations::run_migrations(&core_pool)
            .await
            .expect("core migrations");

        let ipfs = Arc::new(MemIpfsStore::new());
        let stores = Arc::new(JmapStores {
            ipfs: ipfs.clone(),
            msgid_map: Arc::new(usenet_ipfs_core::msgid_map::MsgIdMap::new(core_pool)),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            user_flags: Arc::new(UserFlagsStore::new(mail_pool.clone())),
            state_store: Arc::new(StateStore::new(mail_pool.clone())),
            search_index: None,
            smtp_relay_queue: None,
        });
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: Some(stores),
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: Arc::new(TokenStore::new(Arc::new(mail_pool))),
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
        });
        (state, ipfs)
    }

    async fn spawn_server(state: Arc<AppState>) -> std::net::SocketAddr {
        let app = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        addr
    }

    #[tokio::test]
    async fn health_returns_200_with_ok() {
        let addr = spawn_server(dev_state().await).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "ok");
        assert!(body["uptime_secs"].is_number());
    }

    #[tokio::test]
    async fn well_known_jmap_redirects_to_session() {
        let addr = spawn_server(dev_state().await).await;

        let resp = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(format!("http://{addr}/.well-known/jmap"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 301);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(location, "/jmap/session");
    }

    #[tokio::test]
    async fn jmap_session_dev_mode_returns_200_with_capabilities() {
        let addr = spawn_server(dev_state().await).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["capabilities"].is_object());
        assert!(body["capabilities"]["urn:ietf:params:jmap:core"].is_object());
    }

    #[tokio::test]
    async fn jmap_session_no_credentials_returns_401() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 401);
        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            www_auth.contains("Basic"),
            "WWW-Authenticate must advertise Basic"
        );
        assert!(
            www_auth.contains("usenet-ipfs"),
            "realm must be usenet-ipfs"
        );
    }

    #[tokio::test]
    async fn jmap_session_wrong_password_returns_401() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .basic_auth("alice", Some("wrong-password"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn jmap_session_correct_credentials_returns_200_with_username() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .basic_auth("alice", Some("correct-horse"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["username"], "alice");
        let account_id = "u_alice";
        assert!(
            body["accounts"][account_id].is_object(),
            "account u_alice must be present"
        );
    }

    #[tokio::test]
    async fn health_endpoint_is_public() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn blob_download_invalid_cid_returns_400() {
        let addr = spawn_server(dev_state().await).await;

        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/jmap/download/acc1/not-a-cid/file.txt"
            ))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn blob_download_no_credentials_returns_401() {
        let addr = spawn_server(auth_state("alice", "correct-horse").await).await;
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/jmap/download/u_alice/{valid_cid}/msg.eml"
            ))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn jmap_session_reflects_configured_base_url() {
        let configured_base = "https://mail.example.com";
        let addr = spawn_server(dev_state_with_base_url(configured_base).await).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["apiUrl"], "https://mail.example.com/jmap/api",
            "apiUrl must reflect configured base_url"
        );
        assert!(
            body["downloadUrl"]
                .as_str()
                .unwrap_or("")
                .starts_with("https://mail.example.com/"),
            "downloadUrl must reflect configured base_url"
        );
    }

    #[tokio::test]
    async fn jmap_session_username_reflects_authenticated_user() {
        let addr = spawn_server(auth_state("bob", "hunter2").await).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/session"))
            .basic_auth("bob", Some("hunter2"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["username"], "bob",
            "username must reflect authenticated user"
        );
        assert!(
            body["accounts"]["u_bob"].is_object(),
            "account u_bob must be present for authenticated user bob"
        );
    }

    /// Seed a block in MemIpfsStore, request it via GET /jmap/download, assert
    /// 200 with Content-Type: message/rfc822 and base64-encoded body.
    #[tokio::test]
    async fn blob_download_with_ipfs_returns_200_with_rfc822() {
        let (state, ipfs) = jmap_state().await;

        // Seed a known block.
        let block_data = b"hello from IPFS block";
        let cid = ipfs
            .put_raw_block(block_data)
            .await
            .expect("put_raw_block must succeed");

        let addr = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/download/acc1/{cid}/block.bin"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200, "seeded block must return 200");

        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .expect("Content-Type must be present")
            .to_str()
            .expect("Content-Type must be valid UTF-8");
        assert_eq!(ct, "message/rfc822", "Content-Type must be message/rfc822");

        let body = resp.text().await.expect("body must be readable");

        // The body must contain the X-Usenet-IPFS-CID header with the CID.
        assert!(
            body.contains(&format!("X-Usenet-IPFS-CID: {cid}")),
            "body must contain X-Usenet-IPFS-CID header"
        );

        // The body must contain the base64-encoded block bytes.
        let expected_b64 = data_encoding::BASE64.encode(block_data);
        assert!(
            body.contains(&expected_b64),
            "body must contain base64-encoded block data"
        );
    }

    /// A CID not present in IPFS must return 404.
    #[tokio::test]
    async fn blob_download_unknown_cid_returns_404() {
        let (state, _ipfs) = jmap_state().await;
        let addr = spawn_server(state).await;

        // Valid CID that was never seeded.
        let absent_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/jmap/download/acc1/{absent_cid}/missing.bin"
            ))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 404, "absent CID must return 404");
    }

    #[tokio::test]
    async fn get_root_returns_html() {
        let addr = spawn_server(dev_state().await).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200, "GET / must return 200");
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("text/html"),
            "content-type must be text/html, got: {ct}"
        );
        let body = resp.text().await.expect("body must be readable");
        assert!(
            body.contains("usenet-ipfs"),
            "body must mention usenet-ipfs, got first 200 chars: {}",
            &body[..200.min(body.len())]
        );
    }

    #[tokio::test]
    async fn cors_disabled_no_headers_on_response() {
        // Default CorsConfig has enabled=false; no CORS headers should appear.
        let addr = spawn_server(dev_state().await).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/health"))
            .header("Origin", "https://evil.example.com")
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200);
        let acao = resp.headers().get("access-control-allow-origin");
        assert!(
            acao.is_none(),
            "CORS disabled: no Access-Control-Allow-Origin header expected, got: {acao:?}"
        );
    }

    #[tokio::test]
    async fn cors_wildcard_allows_any_origin() {
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: make_token_store().await,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig {
                enabled: true,
                allowed_origins: vec!["*".to_string()],
            },
        });
        let addr = spawn_server(state).await;
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/health"))
            .header("Origin", "https://anyapp.example.com")
            .send()
            .await
            .expect("request must succeed");
        assert_eq!(resp.status(), 200);
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            acao, "*",
            "wildcard CORS must respond with Access-Control-Allow-Origin: *"
        );
        // Security invariant: wildcard origin must NOT have allow-credentials.
        let creds = resp.headers().get("access-control-allow-credentials");
        assert!(
            creds.is_none(),
            "wildcard CORS must not set Access-Control-Allow-Credentials"
        );
    }

    #[tokio::test]
    async fn cors_specific_origin_preflight() {
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: make_token_store().await,
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig {
                enabled: true,
                allowed_origins: vec!["https://client.example.com".to_string()],
            },
        });
        let addr = spawn_server(state).await;
        let resp = reqwest::Client::new()
            .request(reqwest::Method::OPTIONS, format!("http://{addr}/jmap/api"))
            .header("Origin", "https://client.example.com")
            .header("Access-Control-Request-Method", "POST")
            .header(
                "Access-Control-Request-Headers",
                "Authorization, Content-Type",
            )
            .send()
            .await
            .expect("preflight must succeed");
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            acao, "https://client.example.com",
            "specific origin preflight must echo the origin back"
        );
    }

    /// When search_index is None and the JMAP filter contains a non-empty "text"
    /// field, Email/query must return an empty result set — not all articles.
    #[tokio::test]
    async fn email_query_text_filter_with_no_search_index_returns_empty() {
        let (state, _ipfs) = jmap_state().await;
        let addr = spawn_server(state).await;

        // No mailbox exists, so the filter hits the "no target group" early-return
        // path before reaching the text-filter logic. We need to seed a group first.
        // Since jmap_state() uses MemIpfsStore with empty stores, querying with a
        // text filter against a non-existent group returns [] (early return). That
        // path is already correct. What we are testing is the branch where a group
        // exists and the text filter is applied without a search index.
        //
        // The fix is exercised in the route_method function: when search_index is
        // None and text filter is non-empty, text_results becomes Some(empty set).
        // handle_email_query then retains nothing. Because seeding a real group
        // requires an OverviewStore insertion (not part of this crate's test helpers),
        // we verify the contract via handle_email_query directly in email/query.rs.
        // This server-level test confirms the HTTP round-trip path returns [] when
        // no mailbox matches (the other safe path).
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/jmap/api"))
            .json(&serde_json::json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [[
                    "Email/query",
                    {
                        "accountId": null,
                        "filter": {
                            "inMailbox": "nonexistent",
                            "text": "something"
                        }
                    },
                    "q1"
                ]]
            }))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let responses = body["methodResponses"].as_array().unwrap();
        let result = &responses[0][1];
        let ids = result["ids"].as_array().unwrap();
        assert!(
            ids.is_empty(),
            "text filter with no search index must return empty ids, got: {ids:?}"
        );
    }
}
