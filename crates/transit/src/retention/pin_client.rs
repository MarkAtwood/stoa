//! IPFS pin API wrapper with retry and backoff.
//!
//! `PinClient` abstracts pin/unpin/is_pinned over any IPFS backend.
//! The concrete `HttpPinClient` uses the IPFS HTTP API (Kubo-compatible).
//! `MemPinClient` is an in-memory implementation for tests.
//!
//! Retry policy: 3 attempts with exponential backoff (200ms, 400ms).

use async_trait::async_trait;
use cid::Cid;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Error type for pin operations.
#[derive(Debug)]
pub enum PinError {
    Unreachable(String),
    Failed(String),
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::Unreachable(m) => write!(f, "IPFS node unreachable: {m}"),
            PinError::Failed(m) => write!(f, "pin operation failed: {m}"),
        }
    }
}
impl std::error::Error for PinError {}

/// Abstraction over IPFS pin operations.
#[async_trait]
pub trait PinClient: Send + Sync {
    /// Pin a CID. Idempotent: pinning an already-pinned CID is not an error.
    async fn pin(&self, cid: &Cid) -> Result<(), PinError>;

    /// Unpin a CID. Idempotent: unpinning a non-pinned CID is not an error.
    async fn unpin(&self, cid: &Cid) -> Result<(), PinError>;

    /// Return true if the CID is currently pinned.
    async fn is_pinned(&self, cid: &Cid) -> Result<bool, PinError>;

    /// Return all currently pinned CIDs.
    async fn list_pinned(&self) -> Result<Vec<Cid>, PinError>;
}

/// Retry `op` up to `max_attempts` times with exponential backoff.
///
/// Delays: 200ms, 400ms, ... (doubles each attempt after the first).
/// Returns the last error if all attempts fail.
async fn with_retry<F, Fut, T>(op: F, max_attempts: usize) -> Result<T, PinError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, PinError>>,
{
    let mut delay_ms = 200u64;
    let mut last_err = PinError::Unreachable("no attempts made".to_string());
    for attempt in 0..max_attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = e;
                if attempt + 1 < max_attempts {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2;
                }
            }
        }
    }
    Err(last_err)
}

// ---------------------------------------------------------------------------
// In-memory implementation (for tests)
// ---------------------------------------------------------------------------

/// In-memory PinClient for unit tests.
pub struct MemPinClient {
    pinned: Arc<RwLock<HashSet<String>>>,
    /// If set, every call returns this error (for testing retry logic).
    pub force_error: Arc<RwLock<Option<String>>>,
    /// Count of calls to `pin`.
    pub pin_call_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl MemPinClient {
    pub fn new() -> Self {
        Self {
            pinned: Arc::new(RwLock::new(HashSet::new())),
            force_error: Arc::new(RwLock::new(None)),
            pin_call_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn check_force_error(&self) -> Option<PinError> {
        self.force_error
            .read()
            .unwrap()
            .as_ref()
            .map(|m| PinError::Unreachable(m.clone()))
    }
}

impl Default for MemPinClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PinClient for MemPinClient {
    async fn pin(&self, cid: &Cid) -> Result<(), PinError> {
        self.pin_call_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(e) = self.check_force_error() {
            return Err(e);
        }
        self.pinned.write().unwrap().insert(cid.to_string());
        Ok(())
    }

    async fn unpin(&self, cid: &Cid) -> Result<(), PinError> {
        if let Some(e) = self.check_force_error() {
            return Err(e);
        }
        self.pinned.write().unwrap().remove(&cid.to_string());
        Ok(())
    }

    async fn is_pinned(&self, cid: &Cid) -> Result<bool, PinError> {
        if let Some(e) = self.check_force_error() {
            return Err(e);
        }
        Ok(self.pinned.read().unwrap().contains(&cid.to_string()))
    }

    async fn list_pinned(&self) -> Result<Vec<Cid>, PinError> {
        if let Some(e) = self.check_force_error() {
            return Err(e);
        }
        let guard = self.pinned.read().unwrap();
        let mut strings: Vec<&str> = guard.iter().map(|s| s.as_str()).collect();
        strings.sort_unstable();
        let cids = strings
            .iter()
            .map(|s| {
                s.parse::<Cid>()
                    .map_err(|e| PinError::Failed(format!("invalid CID in store: {e}")))
            })
            .collect::<Result<Vec<Cid>, PinError>>()?;
        Ok(cids)
    }
}

// ---------------------------------------------------------------------------
// HTTP implementation (Kubo-compatible IPFS HTTP API)
// ---------------------------------------------------------------------------

/// Production PinClient that talks to a Kubo-compatible IPFS HTTP API.
pub struct HttpPinClient {
    client: reqwest::Client,
    base_url: String,
}

impl HttpPinClient {
    /// Create a new HttpPinClient.
    ///
    /// `base_url` should be the IPFS API root, e.g. `"http://127.0.0.1:5001"`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }
}

#[async_trait]
impl PinClient for HttpPinClient {
    async fn pin(&self, cid: &Cid) -> Result<(), PinError> {
        let url = format!("{}/api/v0/pin/add?arg={}", self.base_url, cid);
        self.client
            .post(&url)
            .send()
            .await
            .map_err(|e| PinError::Unreachable(e.to_string()))?
            .error_for_status()
            .map_err(|e| PinError::Failed(e.to_string()))?;
        Ok(())
    }

    async fn unpin(&self, cid: &Cid) -> Result<(), PinError> {
        let url = format!("{}/api/v0/pin/rm?arg={}", self.base_url, cid);
        self.client
            .post(&url)
            .send()
            .await
            .map_err(|e| PinError::Unreachable(e.to_string()))?
            .error_for_status()
            .map_err(|e| PinError::Failed(e.to_string()))?;
        Ok(())
    }

    async fn is_pinned(&self, cid: &Cid) -> Result<bool, PinError> {
        let url = format!(
            "{}/api/v0/pin/ls?type=recursive&arg={}",
            self.base_url, cid
        );
        let resp = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| PinError::Unreachable(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
            return Ok(false);
        }
        resp.error_for_status()
            .map_err(|e| PinError::Failed(e.to_string()))?;
        Ok(true)
    }

    async fn list_pinned(&self) -> Result<Vec<Cid>, PinError> {
        let url = format!("{}/api/v0/pin/ls?type=recursive", self.base_url);
        let resp = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| PinError::Unreachable(e.to_string()))?
            .error_for_status()
            .map_err(|e| PinError::Failed(e.to_string()))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| PinError::Failed(format!("failed to parse pin/ls response: {e}")))?;
        let keys = body
            .get("Keys")
            .and_then(|v| v.as_object())
            .ok_or_else(|| PinError::Failed("missing Keys object in pin/ls response".to_string()))?;
        let mut cids = keys
            .keys()
            .map(|s| {
                s.parse::<Cid>()
                    .map_err(|e| PinError::Failed(format!("invalid CID in pin/ls response: {e}")))
            })
            .collect::<Result<Vec<Cid>, PinError>>()?;
        cids.sort_by_key(|c| c.to_string());
        Ok(cids)
    }
}

/// Retry wrapper: wraps any `PinClient` implementation with 3-attempt retry.
pub struct RetryPinClient<P: PinClient> {
    inner: P,
    max_attempts: usize,
}

impl<P: PinClient> RetryPinClient<P> {
    /// Wrap a PinClient with retries. Default: 3 attempts.
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            max_attempts: 3,
        }
    }

    pub fn with_attempts(inner: P, max_attempts: usize) -> Self {
        Self {
            inner,
            max_attempts,
        }
    }
}

#[async_trait]
impl<P: PinClient + Sync> PinClient for RetryPinClient<P> {
    async fn pin(&self, cid: &Cid) -> Result<(), PinError> {
        with_retry(|| self.inner.pin(cid), self.max_attempts).await
    }

    async fn unpin(&self, cid: &Cid) -> Result<(), PinError> {
        with_retry(|| self.inner.unpin(cid), self.max_attempts).await
    }

    async fn is_pinned(&self, cid: &Cid) -> Result<bool, PinError> {
        with_retry(|| self.inner.is_pinned(cid), self.max_attempts).await
    }

    async fn list_pinned(&self) -> Result<Vec<Cid>, PinError> {
        with_retry(|| self.inner.list_pinned(), self.max_attempts).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    fn make_cid(data: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(data))
    }

    #[tokio::test]
    async fn pin_and_is_pinned() {
        let client = MemPinClient::new();
        let cid = make_cid(b"article-1");
        assert!(!client.is_pinned(&cid).await.unwrap());
        client.pin(&cid).await.unwrap();
        assert!(client.is_pinned(&cid).await.unwrap());
    }

    #[tokio::test]
    async fn unpin_removes_pin() {
        let client = MemPinClient::new();
        let cid = make_cid(b"article-2");
        client.pin(&cid).await.unwrap();
        client.unpin(&cid).await.unwrap();
        assert!(!client.is_pinned(&cid).await.unwrap());
    }

    #[tokio::test]
    async fn pin_is_idempotent() {
        let client = MemPinClient::new();
        let cid = make_cid(b"article-3");
        client.pin(&cid).await.unwrap();
        client.pin(&cid).await.unwrap();
        assert!(client.is_pinned(&cid).await.unwrap());
    }

    #[tokio::test]
    async fn unpin_nonpinned_is_idempotent() {
        let client = MemPinClient::new();
        let cid = make_cid(b"article-4");
        client.unpin(&cid).await.unwrap();
    }

    #[tokio::test]
    async fn retry_client_exhausts_attempts_on_persistent_error() {
        let inner = MemPinClient::new();
        *inner.force_error.write().unwrap() = Some("transient".to_string());
        let inner_count = inner.pin_call_count.clone();

        let client = RetryPinClient::new(inner);
        let cid = make_cid(b"retry-article");

        let result = client.pin(&cid).await;
        assert!(result.is_err(), "should fail when force_error is always set");
        assert_eq!(
            inner_count.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "should retry 3 times"
        );
    }

    #[tokio::test]
    async fn retry_client_succeeds_without_error() {
        let inner = MemPinClient::new();
        let client = RetryPinClient::new(inner);
        let cid = make_cid(b"no-error-article");
        assert!(client.pin(&cid).await.is_ok());
        assert!(client.is_pinned(&cid).await.is_ok());
    }

    #[tokio::test]
    async fn list_pinned_returns_all_pinned_cids() {
        let client = MemPinClient::new();
        let cid_a = make_cid(b"list-article-a");
        let cid_b = make_cid(b"list-article-b");
        let cid_c = make_cid(b"list-article-c");
        client.pin(&cid_a).await.unwrap();
        client.pin(&cid_b).await.unwrap();
        client.pin(&cid_c).await.unwrap();
        let result = client.list_pinned().await.unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&cid_a));
        assert!(result.contains(&cid_b));
        assert!(result.contains(&cid_c));
    }
}
