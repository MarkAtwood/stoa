use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// A single method call in a JMAP Request.
/// Tuple: (method_name, arguments, call_id)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Invocation(pub String, pub Value, pub String);

/// RFC 8620 §3.3: JMAP API Request object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Capability identifiers the client claims to use.
    pub using: Vec<String>,
    /// Method calls to execute.
    #[serde(rename = "methodCalls")]
    pub method_calls: Vec<Invocation>,
    /// Client-provided creation IDs (optional).
    #[serde(rename = "createdIds", skip_serializing_if = "Option::is_none")]
    pub created_ids: Option<HashMap<String, String>>,
}

/// RFC 8620 §3.4: JMAP API Response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Method responses in the same order as the request calls.
    #[serde(rename = "methodResponses")]
    pub method_responses: Vec<Invocation>,
    /// Opaque server state string.
    #[serde(rename = "sessionState")]
    pub session_state: String,
    /// Created IDs returned by the server.
    #[serde(rename = "createdIds", skip_serializing_if = "Option::is_none")]
    pub created_ids: Option<HashMap<String, String>>,
}

/// RFC 8620 §3.6: standard JMAP error types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ErrorType {
    UnknownCapability,
    NotJSON,
    NotRequest,
    Limit,
    Forbidden,
    OverQuota,
    NotFound,
    InvalidArguments,
    InvalidResultReference,
    Singleton,
    RequestTooLarge,
    StateMismatch,
    #[serde(other)]
    Other,
}

/// A JMAP method-level error response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodError {
    #[serde(rename = "type")]
    pub error_type: ErrorType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl MethodError {
    pub fn unknown_method() -> Self {
        Self {
            error_type: ErrorType::Other,
            description: Some("unknownMethod".to_string()),
        }
    }

    pub fn invalid_arguments(description: impl Into<String>) -> Self {
        Self {
            error_type: ErrorType::InvalidArguments,
            description: Some(description.into()),
        }
    }

    pub fn not_found() -> Self {
        Self {
            error_type: ErrorType::NotFound,
            description: None,
        }
    }

    pub fn forbidden() -> Self {
        Self {
            error_type: ErrorType::Forbidden,
            description: None,
        }
    }

    pub fn account_not_found() -> Self {
        Self {
            error_type: ErrorType::Other,
            description: Some("accountNotFound".to_string()),
        }
    }

    /// RFC 8620 §3.3: returned when ids.len() exceeds maxObjectsInGet.
    pub fn request_too_large(limit: usize) -> Self {
        Self {
            error_type: ErrorType::RequestTooLarge,
            description: Some(format!("ids exceeds maxObjectsInGet limit of {limit}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_round_trip() {
        let inv = Invocation(
            "Mailbox/get".to_string(),
            serde_json::json!({"accountId": "a1"}),
            "c1".to_string(),
        );
        let json = serde_json::to_string(&inv).unwrap();
        let back: Invocation = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn request_round_trip() {
        let req = Request {
            using: vec!["urn:ietf:params:jmap:core".to_string()],
            method_calls: vec![Invocation(
                "Core/echo".to_string(),
                serde_json::json!({}),
                "c0".to_string(),
            )],
            created_ids: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back.using, req.using);
        assert_eq!(back.method_calls.len(), 1);
        assert_eq!(back.method_calls[0].0, "Core/echo");
    }

    #[test]
    fn response_omits_null_created_ids() {
        let resp = Response {
            method_responses: vec![],
            session_state: "s1".to_string(),
            created_ids: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains("createdIds"),
            "null createdIds must be omitted: {json}"
        );
    }

    #[test]
    fn error_type_serializes_camel_case() {
        let err = MethodError {
            error_type: ErrorType::InvalidArguments,
            description: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("invalidArguments"), "got: {json}");
    }

    #[test]
    fn request_too_large_serializes_correctly() {
        let err = MethodError::request_too_large(500);
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("requestTooLarge"), "got: {json}");
        assert!(
            json.contains("500"),
            "description must include limit, got: {json}"
        );
    }
}
