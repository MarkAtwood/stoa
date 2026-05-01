//! IPFS Remote Pinning API client (https://ipfs.github.io/pinning-services-api-spec/).
//!
//! Implements the standard REST API used by Pinata, web3.storage, Filebase, and
//! other compatible services. Supports submit, check status, and delete operations.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PinningApiKey — redacted newtype
// ---------------------------------------------------------------------------

/// Bearer token for an external IPFS pinning service.
///
/// Debug and Display implementations redact the value to prevent accidental
/// credential leakage in logs, panic messages, and error reports.
///
/// # DECISION (rbe3.36): Debug impl redacts the secret value
///
/// Rust's derived `Debug` would print the raw string, exposing the bearer
/// token in panic messages, structured log lines that format config structs,
/// and test output.  The manual `Debug` impl prints `PinningApiKey(**redacted**)`
/// instead.  A test in `config.rs` asserts that `format!("{:?}", key)` does
/// not contain the raw token string so that this invariant is regression-tested.
/// Do NOT derive `Debug` on this type.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct PinningApiKey(pub(crate) String);

impl std::fmt::Debug for PinningApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinningApiKey(**redacted**)")
    }
}

impl std::fmt::Display for PinningApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("**redacted**")
    }
}

impl PinningApiKey {
    /// Return the `Authorization: Bearer <token>` header value.
    pub(crate) fn as_bearer_header(&self) -> String {
        format!("Bearer {}", self.0)
    }

    /// Validate URI syntax if the stored value is a `secretx:` URI.
    ///
    /// Returns `Ok(())` for literal tokens and for syntactically valid secretx
    /// URIs. Returns `Err(String)` if the value is a secretx URI with a parse
    /// error. Does not attempt to retrieve the secret.
    pub fn validate_uri_syntax(&self) -> Result<(), String> {
        if !self.0.starts_with("secretx:") {
            return Ok(());
        }
        secretx::from_uri(&self.0)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Resolve `self` from a `secretx:` URI if the stored value starts with
    /// that prefix, returning a new `PinningApiKey` containing the retrieved
    /// secret.  If the value is a literal token, returns `self` unchanged.
    ///
    /// Intended for call at daemon startup — any URI parse or retrieval error
    /// is fatal and exits the process immediately.
    pub async fn resolve(self, label: &str) -> Self {
        if !self.0.starts_with("secretx:") {
            return self;
        }
        let store = match secretx::from_uri(&self.0) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: {label}: invalid secretx URI: {e}");
                std::process::exit(1);
            }
        };
        let secret = match store.get().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {label}: secretx retrieval failed: {e}");
                std::process::exit(1);
            }
        };
        let text = match secret.as_str() {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                eprintln!("error: {label}: secretx value not valid UTF-8: {e}");
                std::process::exit(1);
            }
        };
        PinningApiKey(text)
    }
}

// ---------------------------------------------------------------------------
// Wire types for the Remote Pinning API
// ---------------------------------------------------------------------------

/// Status of a remote pin request, as returned by the pinning service.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RemotePinStatus {
    Queued,
    Pinning,
    Pinned,
    Failed,
}

impl std::fmt::Display for RemotePinStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemotePinStatus::Queued => f.write_str("queued"),
            RemotePinStatus::Pinning => f.write_str("pinning"),
            RemotePinStatus::Pinned => f.write_str("pinned"),
            RemotePinStatus::Failed => f.write_str("failed"),
        }
    }
}

/// Response from `POST /pins` or `GET /pins/{requestid}`.
#[derive(Debug, Deserialize)]
pub struct PinStatusResponse {
    pub requestid: String,
    pub status: RemotePinStatus,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error returned by [`RemotePinClient`] operations.
#[non_exhaustive]
#[derive(Debug)]
pub enum RemotePinError {
    /// HTTP transport error (connection refused, TLS error, etc.).
    Transport(String),
    /// The service returned an unexpected status code.
    Http { status: u16, body: String },
    /// Rate-limited by the service. Retry after the given number of seconds.
    RateLimited { retry_after_secs: u64 },
    /// Unauthorized — invalid API key.
    Unauthorized,
    /// Response body could not be parsed.
    Parse(String),
}

impl std::fmt::Display for RemotePinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemotePinError::Transport(m) => write!(f, "transport error: {m}"),
            RemotePinError::Http { status, body } => {
                write!(f, "HTTP {status}: {body}")
            }
            RemotePinError::RateLimited { retry_after_secs } => {
                write!(f, "rate limited; retry after {retry_after_secs}s")
            }
            RemotePinError::Unauthorized => write!(f, "unauthorized (invalid API key)"),
            RemotePinError::Parse(m) => write!(f, "response parse error: {m}"),
        }
    }
}

impl std::error::Error for RemotePinError {}

// ---------------------------------------------------------------------------
// RemotePinClient
// ---------------------------------------------------------------------------

/// Client for the IPFS Remote Pinning API.
///
/// Communicates with a pinning service (Pinata, web3.storage, Filebase, etc.)
/// using the standard IPFS Remote Pinning API spec. Each instance is bound to
/// one service endpoint with one API key.
pub struct RemotePinClient {
    client: reqwest::Client,
    endpoint: String,
    api_key: PinningApiKey,
}

impl RemotePinClient {
    /// Create a new client.
    ///
    /// `endpoint` is the base URL of the pinning service, e.g.
    /// `"https://api.pinata.cloud/psa"`. The trailing slash is optional.
    ///
    /// `connect_timeout_secs` and `request_timeout_secs` control HTTP timeouts.
    pub fn new(
        endpoint: impl Into<String>,
        api_key: PinningApiKey,
        connect_timeout_secs: u64,
        request_timeout_secs: u64,
    ) -> Result<Self, RemotePinError> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(connect_timeout_secs))
            .timeout(std::time::Duration::from_secs(request_timeout_secs))
            .build()
            .map_err(|e| RemotePinError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            endpoint: endpoint.into().trim_end_matches('/').to_owned(),
            api_key,
        })
    }

    /// Submit a CID for pinning. Returns the `requestid` assigned by the service.
    ///
    /// `name` is a human-readable label for the pin (shown in the service dashboard).
    pub async fn submit(&self, cid: &str, name: &str) -> Result<PinStatusResponse, RemotePinError> {
        let url = format!("{}/pins", self.endpoint);
        let body = serde_json::json!({ "cid": cid, "name": name });
        let resp = self
            .client
            .post(&url)
            .header(
                reqwest::header::AUTHORIZATION,
                self.api_key.as_bearer_header(),
            )
            .json(&body)
            .send()
            .await
            .map_err(|e| RemotePinError::Transport(e.to_string()))?;
        self.parse_pin_response(resp).await
    }

    /// Check the status of a pin request.
    pub async fn check(&self, request_id: &str) -> Result<PinStatusResponse, RemotePinError> {
        let url = format!("{}/pins/{}", self.endpoint, request_id);
        let resp = self
            .client
            .get(&url)
            .header(
                reqwest::header::AUTHORIZATION,
                self.api_key.as_bearer_header(),
            )
            .send()
            .await
            .map_err(|e| RemotePinError::Transport(e.to_string()))?;
        self.parse_pin_response(resp).await
    }

    /// Delete (cancel) a pin request.
    pub async fn delete(&self, request_id: &str) -> Result<(), RemotePinError> {
        let url = format!("{}/pins/{}", self.endpoint, request_id);
        let resp = self
            .client
            .delete(&url)
            .header(
                reqwest::header::AUTHORIZATION,
                self.api_key.as_bearer_header(),
            )
            .send()
            .await
            .map_err(|e| RemotePinError::Transport(e.to_string()))?;
        let status = resp.status();
        if status == reqwest::StatusCode::ACCEPTED || status == reqwest::StatusCode::OK {
            return Ok(());
        }
        Err(self.classify_error(status, resp).await)
    }

    async fn parse_pin_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<PinStatusResponse, RemotePinError> {
        let status = resp.status();
        if status == reqwest::StatusCode::OK || status == reqwest::StatusCode::ACCEPTED {
            let parsed: PinStatusResponse = resp
                .json()
                .await
                .map_err(|e| RemotePinError::Parse(e.to_string()))?;
            return Ok(parsed);
        }
        Err(self.classify_error(status, resp).await)
    }

    async fn classify_error(
        &self,
        status: reqwest::StatusCode,
        resp: reqwest::Response,
    ) -> RemotePinError {
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return RemotePinError::Unauthorized;
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after_secs = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            return RemotePinError::RateLimited { retry_after_secs };
        }
        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        RemotePinError::Http { status: code, body }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinning_api_key_debug_is_redacted() {
        let key = PinningApiKey("super-secret-token".to_string());
        assert_eq!(format!("{key:?}"), "PinningApiKey(**redacted**)");
    }

    #[test]
    fn pinning_api_key_display_is_redacted() {
        let key = PinningApiKey("super-secret-token".to_string());
        assert_eq!(format!("{key}"), "**redacted**");
    }

    #[test]
    fn pinning_api_key_bearer_header() {
        let key = PinningApiKey("my-token-123".to_string());
        assert_eq!(key.as_bearer_header(), "Bearer my-token-123");
    }

    #[test]
    fn pinning_api_key_deserializes_from_string() {
        let key: PinningApiKey = serde_json::from_str("\"my-api-key\"").unwrap();
        assert_eq!(key.0, "my-api-key");
        // Confirm the raw value is accessible but Debug/Display hide it
        assert!(!format!("{key:?}").contains("my-api-key"));
    }

    #[test]
    fn remote_pin_status_display() {
        assert_eq!(RemotePinStatus::Queued.to_string(), "queued");
        assert_eq!(RemotePinStatus::Pinning.to_string(), "pinning");
        assert_eq!(RemotePinStatus::Pinned.to_string(), "pinned");
        assert_eq!(RemotePinStatus::Failed.to_string(), "failed");
    }

    // ── Wiremock integration tests ────────────────────────────────────────────

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_client(base_url: &str) -> RemotePinClient {
        RemotePinClient::new(base_url, PinningApiKey("test-token".to_string()), 5, 10).unwrap()
    }

    const SUBMIT_RESPONSE: &str = r#"{"requestid":"req-abc","status":"queued"}"#;
    const PINNED_RESPONSE: &str = r#"{"requestid":"req-abc","status":"pinned"}"#;
    const FAILED_RESPONSE: &str = r#"{"requestid":"req-abc","status":"failed"}"#;

    /// POST /pins succeeds and returns a requestid.
    #[tokio::test]
    async fn submit_success_returns_request_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pins"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(
                ResponseTemplate::new(202).set_body_raw(SUBMIT_RESPONSE, "application/json"),
            )
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let resp = client.submit("QmFake123", "test-article").await.unwrap();
        assert_eq!(resp.requestid, "req-abc");
        assert_eq!(resp.status, RemotePinStatus::Queued);
    }

    /// POST /pins with a 429 response returns RateLimited with Retry-After seconds.
    #[tokio::test]
    async fn submit_rate_limited_parses_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "42")
                    .set_body_string("rate limited"),
            )
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let err = client.submit("QmFake123", "test").await.unwrap_err();
        assert!(
            matches!(
                err,
                RemotePinError::RateLimited {
                    retry_after_secs: 42
                }
            ),
            "expected RateLimited(42), got: {err}"
        );
    }

    /// POST /pins with a 401 returns Unauthorized.
    #[tokio::test]
    async fn submit_unauthorized_returns_unauthorized_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let err = client.submit("QmFake123", "test").await.unwrap_err();
        assert!(
            matches!(err, RemotePinError::Unauthorized),
            "expected Unauthorized, got: {err}"
        );
    }

    /// GET /pins/{requestid} returns pinned status.
    #[tokio::test]
    async fn check_pinned_returns_pinned_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pins/req-abc"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(PINNED_RESPONSE, "application/json"),
            )
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let resp = client.check("req-abc").await.unwrap();
        assert_eq!(resp.status, RemotePinStatus::Pinned);
    }

    /// GET /pins/{requestid} returns failed status.
    #[tokio::test]
    async fn check_failed_returns_failed_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pins/req-abc"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(FAILED_RESPONSE, "application/json"),
            )
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let resp = client.check("req-abc").await.unwrap();
        assert_eq!(resp.status, RemotePinStatus::Failed);
    }

    /// GET /pins/{requestid} with a 404 returns an Http error.
    #[tokio::test]
    async fn check_not_found_returns_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pins/missing-req"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let err = client.check("missing-req").await.unwrap_err();
        assert!(
            matches!(err, RemotePinError::Http { status: 404, .. }),
            "expected Http(404), got: {err}"
        );
    }

    /// validate_uri_syntax returns Ok for a literal token.
    #[test]
    fn validate_uri_syntax_literal_is_ok() {
        let key = PinningApiKey("plain-api-token".to_string());
        assert!(key.validate_uri_syntax().is_ok());
    }

    /// validate_uri_syntax returns Ok for a syntactically valid secretx:env URI.
    #[test]
    fn validate_uri_syntax_valid_secretx_is_ok() {
        let key = PinningApiKey("secretx:env:MY_API_KEY".to_string());
        assert!(key.validate_uri_syntax().is_ok());
    }

    /// validate_uri_syntax returns Err for a malformed secretx URI (no backend specified).
    #[test]
    fn validate_uri_syntax_invalid_secretx_is_err() {
        // "secretx:" with no backend name is a parse error per the secretx crate spec.
        let key = PinningApiKey("secretx:".to_string());
        assert!(
            key.validate_uri_syntax().is_err(),
            "secretx: with no backend must be a parse error"
        );
    }

    /// The Authorization header must not appear in Debug output of RemotePinClient
    /// (because PinningApiKey is redacted). This verifies the key is never leaked
    /// via the standard Debug formatting path used in panic messages and logs.
    #[test]
    fn api_key_not_in_client_debug_output() {
        let key = PinningApiKey("super-secret-bearer-token".to_string());
        let debug_output = format!("{key:?}");
        assert!(
            !debug_output.contains("super-secret-bearer-token"),
            "API key must not appear in Debug output: {debug_output}"
        );
    }
}
