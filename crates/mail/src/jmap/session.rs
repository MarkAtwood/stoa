//! JMAP Session Resource (RFC 8620 §2).
//!
//! # Implementation status
//!
//! The session object advertises all required RFC 8620 fields and the following
//! optional URLs, which are partially or not yet implemented:
//!
//! - **`uploadUrl`** – advertised but the `/jmap/upload` endpoint is not wired in v1.
//!   Clients attempting upload will receive a 404 or 405 response.
//! - **`eventSourceUrl`** – advertised but the `/jmap/eventsource` endpoint is not wired in v1.
//!   Server-Sent Events / push notifications are deferred to a future epic.
//! - **`state`** – hardcoded to `"0"` in v1; dynamic session state change tracking is deferred.
//!
//! # Operator requirement
//!
//! `[listen] base_url` in the server config **must** be set to the externally-reachable
//! server hostname (e.g. `https://mail.example.com`).  All URLs in the session object
//! (apiUrl, downloadUrl, uploadUrl, eventSourceUrl) are derived from this value.
//! Leaving it as the default `http://localhost` will break blob downloads and
//! client autodiscovery for remote browsers.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// RFC 8620 §2 Session Resource.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResource {
    pub capabilities: HashMap<String, Value>,
    pub accounts: HashMap<String, AccountInfo>,
    #[serde(rename = "primaryAccounts")]
    pub primary_accounts: HashMap<String, String>,
    pub username: String,
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    #[serde(rename = "downloadUrl")]
    pub download_url: String,
    #[serde(rename = "uploadUrl")]
    pub upload_url: String,
    #[serde(rename = "eventSourceUrl")]
    pub event_source_url: String,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    pub name: String,
    #[serde(rename = "isPersonal")]
    pub is_personal: bool,
    #[serde(rename = "isReadOnly")]
    pub is_read_only: bool,
    #[serde(rename = "accountCapabilities")]
    pub account_capabilities: HashMap<String, Value>,
}

/// Build a SessionResource for the given username.
///
/// When `is_operator` is true, the `urn:ietf:params:jmap:usenet-ipfs-admin`
/// capability is added so the client can discover and call admin methods.
pub fn build_session(username: &str, base_url: &str, is_operator: bool) -> SessionResource {
    let mut capabilities: HashMap<String, Value> = HashMap::new();
    capabilities.insert(
        "urn:ietf:params:jmap:core".to_string(),
        serde_json::json!({
            "maxSizeUpload": 50_000_000u64,
            "maxConcurrentUpload": 4,
            "maxSizeRequest": 10_000_000u64,
            "maxConcurrentRequests": 4,
            "maxCallsInRequest": 16,
            "maxObjectsInGet": 500,
            "maxObjectsInSet": 500,
            "collationAlgorithms": []
        }),
    );
    capabilities.insert(
        "urn:ietf:params:jmap:mail".to_string(),
        serde_json::json!({}),
    );
    // Custom capability: signals that Email objects carry the
    // "x-stoa-cid" property containing the DAG-CBOR root CID.
    // Clients that do not recognise this capability may ignore it (RFC 8620 §3.3).
    capabilities.insert("urn:stoa:jmap:cid".to_string(), serde_json::json!({}));
    // RFC 9404: Blob management capability (Blob/get and Blob/copy methods).
    capabilities.insert(
        "urn:ietf:params:jmap:blob".to_string(),
        serde_json::json!({}),
    );
    // Operator-role admin capability: advertised only for users in operator_usernames.
    // Enables ServerStatus/get, Peer/get, GroupLog/get admin JMAP methods.
    if is_operator {
        capabilities.insert(
            "urn:ietf:params:jmap:usenet-ipfs-admin".to_string(),
            serde_json::json!({}),
        );
    }

    let account_id = format!("u_{username}");
    let mut account_capabilities: HashMap<String, Value> = HashMap::new();
    account_capabilities.insert(
        "urn:ietf:params:jmap:mail".to_string(),
        serde_json::json!({}),
    );

    let mut accounts: HashMap<String, AccountInfo> = HashMap::new();
    accounts.insert(
        account_id.clone(),
        AccountInfo {
            name: username.to_string(),
            is_personal: true,
            is_read_only: false,
            account_capabilities,
        },
    );

    let mut primary_accounts: HashMap<String, String> = HashMap::new();
    primary_accounts.insert("urn:ietf:params:jmap:mail".to_string(), account_id);

    SessionResource {
        capabilities,
        accounts,
        primary_accounts,
        username: username.to_string(),
        api_url: format!("{base_url}/jmap/api"),
        download_url: format!("{base_url}/jmap/download/{{accountId}}/{{blobId}}/{{name}}"),
        upload_url: format!("{base_url}/jmap/upload/{{accountId}}/"),
        event_source_url: format!("{base_url}/jmap/eventsource/"),
        state: "0".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_has_required_capabilities() {
        let s = build_session("alice", "https://example.com", false);
        assert!(s.capabilities.contains_key("urn:ietf:params:jmap:core"));
        assert!(s.capabilities.contains_key("urn:ietf:params:jmap:mail"));
        assert_eq!(s.username, "alice");
    }

    #[test]
    fn session_has_stoa_cid_capability() {
        let s = build_session("alice", "https://example.com", false);
        assert!(
            s.capabilities.contains_key("urn:stoa:jmap:cid"),
            "session must advertise urn:stoa:jmap:cid capability"
        );
    }

    #[test]
    fn session_api_url_correct() {
        let s = build_session("alice", "https://example.com", false);
        assert_eq!(s.api_url, "https://example.com/jmap/api");
    }

    #[test]
    fn session_serializes_to_json() {
        let s = build_session("bob", "http://localhost:8080", false);
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("urn:ietf:params:jmap:core"));
        assert!(json.contains("apiUrl"));
    }

    #[test]
    fn non_operator_session_lacks_admin_capability() {
        let s = build_session("alice", "https://example.com", false);
        assert!(
            !s.capabilities
                .contains_key("urn:ietf:params:jmap:usenet-ipfs-admin"),
            "non-operator session must not have admin capability"
        );
    }

    #[test]
    fn operator_session_has_admin_capability() {
        let s = build_session("alice", "https://example.com", true);
        assert!(
            s.capabilities
                .contains_key("urn:ietf:params:jmap:usenet-ipfs-admin"),
            "operator session must have admin capability"
        );
    }
}
