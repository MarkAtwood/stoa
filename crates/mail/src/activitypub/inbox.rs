//! ActivityPub inbox handler — Follow / Undo{Follow} lifecycle.
//!
//! Receives POST requests to `/ap/groups/{group_name}/inbox`.
//! Processes `Follow` and `Undo{Follow}` activities:
//!
//! - **Follow**: stores the follower, then sends an asynchronous `Accept{Follow}`
//!   back to the actor's inbox.
//! - **Undo{Follow}**: removes the follower.
//!
//! Inbound HTTP Signature verification is not yet implemented — a future
//! hardening pass will add it.  For v1, we trust the `actor` field in the
//! activity body.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;
use std::sync::Arc;
use tracing::{info, warn};

use crate::server::AppState;

/// POST `/ap/groups/{group_name}/inbox`
pub async fn inbox_handler(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
    Json(activity): Json<Value>,
) -> Response {
    if !state.activitypub_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let ap_state = match &state.activitypub {
        Some(s) => Arc::clone(s),
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let activity_type = activity["type"].as_str().unwrap_or("");
    match activity_type {
        "Follow" => handle_follow(&ap_state, &state.base_url, &group_name, &activity).await,
        "Undo" => {
            let inner = &activity["object"];
            if inner["type"].as_str() == Some("Follow") {
                handle_undo_follow(&ap_state, &group_name, inner).await
            } else {
                StatusCode::ACCEPTED.into_response()
            }
        }
        other => {
            info!(
                group = %group_name,
                activity_type = %other,
                "ActivityPub inbox: unhandled activity type"
            );
            StatusCode::ACCEPTED.into_response()
        }
    }
}

async fn handle_follow(
    ap_state: &Arc<crate::activitypub::ActivityPubState>,
    base_url: &str,
    group_name: &str,
    activity: &Value,
) -> Response {
    let actor_url = match activity["actor"].as_str() {
        Some(u) => u.to_string(),
        None => {
            warn!(group = %group_name, "Follow activity missing actor field");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    // Derive inbox URL: fetch actor document to get inbox, or use a heuristic.
    // For v1, we look for a pre-filled inbox in the activity or fall back to
    // actor_url + "/inbox".  Remote delivery is best-effort.
    let inbox_url = activity["object"]
        .as_str()
        .and_then(|_| activity["actor"].as_str())
        .map(|_| format!("{}/inbox", actor_url))
        .unwrap_or_else(|| format!("{}/inbox", actor_url));

    if let Err(e) = ap_state
        .follower_store
        .add(group_name, &actor_url, &inbox_url)
        .await
    {
        warn!(group = %group_name, actor = %actor_url, error = %e, "failed to store follower");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    info!(group = %group_name, actor = %actor_url, "ActivityPub: new follower");

    // Send Accept{Follow} asynchronously — fire and forget.
    let ap_state = Arc::clone(ap_state);
    let activity_id = activity["id"].as_str().unwrap_or("").to_string();
    let actor_url_owned = actor_url.clone();
    let group_actor_url = format!("{}/ap/groups/{}", base_url, group_name);
    let inbox_url_owned = inbox_url.clone();
    tokio::spawn(async move {
        deliver_accept(
            &ap_state,
            &group_actor_url,
            &actor_url_owned,
            &activity_id,
            &inbox_url_owned,
        )
        .await;
    });

    StatusCode::ACCEPTED.into_response()
}

async fn handle_undo_follow(
    ap_state: &Arc<crate::activitypub::ActivityPubState>,
    group_name: &str,
    follow_activity: &Value,
) -> Response {
    let actor_url = match follow_activity["actor"].as_str() {
        Some(u) => u,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(e) = ap_state.follower_store.remove(group_name, actor_url).await {
        warn!(group = %group_name, actor = %actor_url, error = %e, "failed to remove follower");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    info!(group = %group_name, actor = %actor_url, "ActivityPub: follower removed");
    StatusCode::ACCEPTED.into_response()
}

/// Extract (host, path) from a URL string without pulling in the `url` crate.
fn extract_host_path(url: &str) -> (String, String) {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    match without_scheme.find('/') {
        Some(i) => (
            without_scheme[..i].to_string(),
            without_scheme[i..].to_string(),
        ),
        None => (without_scheme.to_string(), "/".to_string()),
    }
}

/// Deliver an Accept{Follow} activity to the remote actor's inbox.
async fn deliver_accept(
    ap_state: &crate::activitypub::ActivityPubState,
    group_actor_url: &str,
    actor_url: &str,
    follow_activity_id: &str,
    remote_inbox_url: &str,
) {
    let accept = serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Accept",
        "actor": group_actor_url,
        "object": {
            "type": "Follow",
            "id": follow_activity_id,
            "actor": actor_url,
            "object": group_actor_url
        }
    });
    let body = match serde_json::to_vec(&accept) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to serialize Accept activity");
            return;
        }
    };

    // Build HTTP Signature if a key is available.
    let (host, path) = extract_host_path(remote_inbox_url);
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();

    let mut req = reqwest::Client::new()
        .post(remote_inbox_url)
        .header("Content-Type", "application/activity+json")
        .header("Date", &date)
        .header("Host", &host);

    if let Some(key) = &ap_state.key {
        match key.sign_post(&host, &path, &date, &body) {
            Ok(sig_header) => {
                req = req.header("Signature", sig_header);
            }
            Err(e) => {
                warn!(error = %e, "failed to sign Accept delivery");
            }
        }
    }

    match req.body(body).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!(inbox = %remote_inbox_url, "delivered Accept{{Follow}}");
        }
        Ok(resp) => {
            warn!(inbox = %remote_inbox_url, status = %resp.status(), "Accept delivery returned error status");
        }
        Err(e) => {
            warn!(inbox = %remote_inbox_url, error = %e, "Accept delivery failed");
        }
    }
}
