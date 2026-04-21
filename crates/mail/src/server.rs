use std::{
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use axum::{Json, Router, extract::State, http::StatusCode, routing::{get, post}};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use usenet_ipfs_reader::{
    post::ipfs_write::IpfsBlockStore,
    store::{article_numbers::ArticleNumberStore, overview::OverviewStore},
};

use crate::state::{flags::UserFlagsStore, version::StateStore};

/// JMAP backing stores, wired together for the API handler.
pub struct JmapStores {
    pub ipfs: Arc<dyn IpfsBlockStore>,
    pub article_numbers: Arc<ArticleNumberStore>,
    pub overview_store: Arc<OverviewStore>,
    pub user_flags: Arc<UserFlagsStore>,
    pub state_store: Arc<StateStore>,
}

#[derive(Clone)]
pub struct AppState {
    pub start_time: Instant,
    pub jmap: Option<Arc<JmapStores>>,
}

/// Build the axum Router with all routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/.well-known/jmap", get(well_known_jmap))
        .route("/jmap/session", get(jmap_session_handler))
        .route("/jmap/api", post(jmap_api_handler))
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(crate::blob::blob_download),
        )
        .with_state(state)
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

async fn jmap_session_handler() -> Json<Value> {
    // v1: return session for anonymous/single-user mode
    let session = crate::jmap::session::build_session("anonymous", "http://localhost");
    Json(serde_json::to_value(session).unwrap())
}

async fn jmap_api_handler(
    State(state): State<Arc<AppState>>,
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

    let mut method_responses = Vec::new();

    for crate::jmap::types::Invocation(method, args, call_id) in request.method_calls {
        let result = route_method(&method, args, jmap).await;
        let response_name = if result.get("error").is_some() {
            "error".to_string()
        } else {
            method.clone()
        };
        method_responses.push(crate::jmap::types::Invocation(response_name, result, call_id));
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

    (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
}

async fn route_method(method: &str, args: Value, jmap: &JmapStores) -> Value {
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
            let ids_filter: Option<Vec<String>> = args
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
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
                        subject: rec.subject.clone(),
                        from: rec.from.clone(),
                        date: rec.date.clone(),
                        byte_count: rec.byte_count,
                    });
                }
            }

            let filter = args.get("filter");
            crate::email::query::handle_email_query(&entries, filter, 0, None, &email_state)
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
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn health_returns_200_with_ok() {
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
        });
        let app = build_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

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
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
        });
        let app = build_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

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
    async fn jmap_session_returns_200_with_capabilities() {
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
        });
        let app = build_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

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
    async fn blob_download_invalid_cid_returns_400() {
        let state = Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
        });
        let app = build_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/jmap/download/acc1/not-a-cid/file.txt"))
            .send()
            .await
            .expect("request must succeed");

        assert_eq!(resp.status(), 400);
    }
}
