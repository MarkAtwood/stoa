//! ActivityPub federation — newsgroup Actor model and WebFinger endpoint.
//!
//! # Endpoints
//!
//! - `GET  /.well-known/webfinger?resource=acct:{group}@{domain}` — WebFinger (RFC 7033)
//! - `GET  /ap/groups/{group_name}` — ActivityPub Group Actor JSON-LD document
//! - `GET  /ap/groups/{group_name}/followers` — followers OrderedCollection
//! - `POST /ap/groups/{group_name}/inbox` — receive Follow / Undo{Follow}
//!
//! All endpoints return 404 when `[activitypub] enabled = false` (the default).

pub mod follower_store;
pub mod http_sign;
pub mod inbound;
pub mod inbox;
pub mod outbound;

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Runtime ActivityPub state: key, follower store, and dedup store.
///
/// Placed in `AppState.activitypub` when `[activitypub] enabled = true` and
/// a key is available.  `None` means ActivityPub is disabled.
pub struct ActivityPubState {
    /// RSA key pair for HTTP Signatures.  `None` = AP endpoints work but
    /// outbound signing is skipped (useful in development / tests).
    pub key: Option<http_sign::RsaActorKey>,
    pub follower_store: Arc<follower_store::FollowerStore>,
    pub received_store: Arc<inbound::ReceivedActivityStore>,
}

use crate::server::AppState;

// ── WebFinger (RFC 7033) ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct WebFingerLink {
    pub rel: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub link_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebFingerResource {
    pub subject: String,
    pub links: Vec<WebFingerLink>,
}

#[derive(Debug, Deserialize)]
pub struct WebFingerQuery {
    pub resource: String,
}

/// `GET /.well-known/webfinger?resource=acct:{group}@{domain}`
pub async fn webfinger_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WebFingerQuery>,
) -> Response {
    if !state.activitypub_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let domain = ap_domain(&state.base_url);
    let acct = match query.resource.strip_prefix("acct:") {
        Some(a) => a,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let (group_name, resource_domain) = match acct.rsplit_once('@') {
        Some(pair) => pair,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    if resource_domain != domain {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_group_name(group_name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let actor_url = format!("{}/ap/groups/{}", state.base_url, group_name);
    let jrd = WebFingerResource {
        subject: format!("acct:{}@{}", group_name, domain),
        links: vec![WebFingerLink {
            rel: "self".to_string(),
            link_type: Some("application/activity+json".to_string()),
            href: Some(actor_url),
        }],
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/jrd+json")],
        Json(jrd),
    )
        .into_response()
}

// ── Actor Document (JSON-LD) ───────────────────────────────────────────────────

/// ActivityPub Group Actor for a newsgroup.
#[derive(Debug, Serialize)]
pub struct GroupActor {
    #[serde(rename = "@context")]
    pub context: Vec<&'static str>,
    #[serde(rename = "type")]
    pub actor_type: &'static str,
    pub id: String,
    pub name: String,
    #[serde(rename = "preferredUsername")]
    pub preferred_username: String,
    pub inbox: String,
    pub outbox: String,
    pub followers: String,
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyStub,
}

/// Public key stub; populated by the HTTP Signatures implementation (usenet-ipfs-4ecs).
#[derive(Debug, Serialize)]
pub struct PublicKeyStub {
    pub id: String,
    pub owner: String,
    #[serde(rename = "publicKeyPem")]
    pub public_key_pem: String,
}

/// `GET /ap/groups/{group_name}` — returns the Group Actor JSON-LD document.
pub async fn actor_handler(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
) -> Response {
    if !state.activitypub_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_group_name(&group_name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let base = &state.base_url;
    let actor_url = format!("{}/ap/groups/{}", base, group_name);
    let actor = GroupActor {
        context: vec![
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        ],
        actor_type: "Group",
        id: actor_url.clone(),
        name: group_name.clone(),
        preferred_username: group_name.clone(),
        inbox: format!("{}/inbox", actor_url),
        outbox: format!("{}/outbox", actor_url),
        followers: format!("{}/followers", actor_url),
        public_key: PublicKeyStub {
            id: format!("{}#main-key", actor_url),
            owner: actor_url.clone(),
            public_key_pem: state
                .activitypub
                .as_ref()
                .and_then(|ap| ap.key.as_ref())
                .and_then(|k| k.public_key_pem().ok())
                .unwrap_or_default(),
        },
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/activity+json")],
        Json(actor),
    )
        .into_response()
}

/// `GET /ap/groups/{group_name}/followers` — empty followers OrderedCollection.
pub async fn followers_handler(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
) -> Response {
    if !state.activitypub_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_group_name(&group_name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let followers_url = format!("{}/ap/groups/{}/followers", state.base_url, group_name);
    let follower_urls: Vec<String> = if let Some(ap) = &state.activitypub {
        ap.follower_store
            .list(&group_name)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|f| f.actor_url)
            .collect()
    } else {
        Vec::new()
    };
    let collection = serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "OrderedCollection",
        "id": followers_url,
        "totalItems": follower_urls.len(),
        "orderedItems": follower_urls
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/activity+json")],
        Json(collection),
    )
        .into_response()
}

/// `GET /ap/groups/{group_name}/outbox` — empty outbox OrderedCollection.
///
/// Activity history storage is not yet implemented; this endpoint advertises
/// the outbox URL with `totalItems: 0`.  Remote servers can still Follow the
/// group; they will receive new activities pushed to their inboxes.
pub async fn outbox_handler(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
) -> Response {
    if !state.activitypub_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_group_name(&group_name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let outbox_url = format!("{}/ap/groups/{}/outbox", state.base_url, group_name);
    let collection = serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "OrderedCollection",
        "id": outbox_url,
        "totalItems": 0,
        "orderedItems": []
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/activity+json")],
        Json(collection),
    )
        .into_response()
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Extract (host, path) from a URL string without the `url` crate.
pub(super) fn extract_host_path(url: &str) -> (String, String) {
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

fn is_valid_group_name(name: &str) -> bool {
    !name.is_empty() && name.contains('.') && !name.chars().any(|c| c.is_whitespace())
}

/// Extract the domain (host without port) from a base URL.
pub fn ap_domain(base_url: &str) -> String {
    let without_scheme = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .unwrap_or(base_url);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    host_port.split(':').next().unwrap_or(host_port).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ap_domain_strips_https() {
        assert_eq!(ap_domain("https://news.example.com"), "news.example.com");
    }

    #[test]
    fn ap_domain_strips_http_port() {
        assert_eq!(ap_domain("http://localhost:8080"), "localhost");
    }

    #[test]
    fn ap_domain_no_scheme() {
        assert_eq!(ap_domain("localhost"), "localhost");
    }

    #[test]
    fn valid_group_name_accepts_dotted() {
        assert!(is_valid_group_name("comp.lang.rust"));
        assert!(is_valid_group_name("alt.test"));
    }

    #[test]
    fn valid_group_name_rejects_no_dot() {
        assert!(!is_valid_group_name("inbox"));
        assert!(!is_valid_group_name(""));
    }

    #[test]
    fn valid_group_name_rejects_spaces() {
        assert!(!is_valid_group_name("comp lang rust"));
        assert!(!is_valid_group_name("comp.lang rust"));
    }
}
