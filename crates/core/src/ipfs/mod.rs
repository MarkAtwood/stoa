//! Kubo HTTP RPC client for IPFS block operations.
//!
//! Wraps the Kubo daemon's `/api/v0/block/*` and `/api/v0/name/publish`
//! endpoints so that transit and reader can store and retrieve IPLD blocks
//! without embedding a rust-ipfs node.

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::Deserialize;

// ── Error type ────────────────────────────────────────────────────────────────

#[non_exhaustive]
#[derive(Debug)]
pub enum KuboError {
    Http(reqwest::Error),
    /// Kubo returned a non-success status or an error JSON body.
    Api(String),
    /// CID returned by Kubo could not be parsed.
    BadCid(String),
}

impl std::fmt::Display for KuboError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KuboError::Http(e) => write!(f, "Kubo HTTP error: {e}"),
            KuboError::Api(m) => write!(f, "Kubo API error: {m}"),
            KuboError::BadCid(m) => write!(f, "Kubo returned unparseable CID: {m}"),
        }
    }
}

impl std::error::Error for KuboError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KuboError::Http(e) => Some(e),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for KuboError {
    fn from(e: reqwest::Error) -> Self {
        KuboError::Http(e)
    }
}

// ── DeletionOutcome ───────────────────────────────────────────────────────────

/// Outcome of a [`KuboHttpClient::pin_rm`] or store `delete()` call.
///
/// Block stores have different reclaim semantics: some remove immediately,
/// others mark the block for future collection (Kubo GC, S3 lifecycle rule).
/// Callers must not assume a block is inaccessible after receiving `Deferred`.
#[derive(Debug, Clone, PartialEq)]
pub enum DeletionOutcome {
    /// Block has been removed immediately; subsequent `get()` calls return `NotFound`.
    Immediate,
    /// Block has been marked for deletion but remains readable until the backend's
    /// own reclaim process runs (e.g. `ipfs repo gc`, an S3 lifecycle rule, `git gc`).
    ///
    /// `readable_for_approx_secs` is a best-effort estimate; `None` means unknown.
    Deferred {
        readable_for_approx_secs: Option<u64>,
    },
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BlockPutResponse {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Deserialize)]
struct NamePublishResponse {
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Deserialize)]
struct IdResponse {
    #[serde(rename = "ID")]
    id: String,
}

// ── KuboHttpClient ────────────────────────────────────────────────────────────

/// HTTP client for the Kubo IPFS daemon's RPC API.
///
/// All calls use the Kubo `/api/v0/*` endpoint. The daemon must be running and
/// reachable at `api_url` before any method is called.
#[derive(Clone)]
pub struct KuboHttpClient {
    client: reqwest::Client,
    api_base: String,
}

impl KuboHttpClient {
    /// Create a new client targeting `api_url` (e.g. `"http://127.0.0.1:5001"`).
    pub fn new(api_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: api_url.trim_end_matches('/').to_owned(),
        }
    }

    /// Store a block in Kubo and return the CID Kubo assigned.
    ///
    /// `codec` is the IPLD multicodec number for the block content:
    /// - `0x55` — Raw (article bytes, JSON index)
    /// - `0x71` — DAG-CBOR (IPLD article nodes from `build_article`)
    ///
    /// The local CID is computed and verified against Kubo's response.
    #[tracing::instrument(skip(self, data), fields(codec, cid = tracing::field::Empty))]
    pub async fn block_put(&self, data: &[u8], codec: u64) -> Result<Cid, KuboError> {
        let codec_name = match codec {
            0x55 => "raw",
            0x71 => "dag-cbor",
            other => return Err(KuboError::Api(format!("unsupported codec 0x{other:x}"))),
        };

        // Compute the expected CID locally so we can verify the round-trip.
        let digest = Code::Sha2_256.digest(data);
        let expected_cid = Cid::new_v1(codec, digest);
        tracing::Span::current().record("cid", expected_cid.to_string().as_str());

        let part = reqwest::multipart::Part::bytes(data.to_vec());
        let form = reqwest::multipart::Form::new().part("data", part);

        let resp = self
            .client
            .post(format!("{}/api/v0/block/put", self.api_base))
            .query(&[("cid-codec", codec_name), ("mhtype", "sha2-256")])
            .multipart(form)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(KuboError::Api(format!("block/put HTTP {status}: {body}")));
        }

        let parsed: BlockPutResponse = resp.json().await?;

        let returned_cid: Cid = parsed
            .key
            .parse()
            .map_err(|e| KuboError::BadCid(format!("{}: {e}", parsed.key)))?;

        if returned_cid != expected_cid {
            return Err(KuboError::Api(format!(
                "block/put CID mismatch: expected {expected_cid}, got {returned_cid}"
            )));
        }

        Ok(returned_cid)
    }

    /// Retrieve a block from Kubo by CID.
    ///
    /// Returns `None` on HTTP 404 (block not present in the local Kubo store).
    /// Returns `Err` on any other non-2xx status or network error.
    #[tracing::instrument(skip(self), fields(cid = %cid))]
    pub async fn block_get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, KuboError> {
        let resp = self
            .client
            .post(format!("{}/api/v0/block/get", self.api_base))
            .query(&[("arg", cid.to_string())])
            .send()
            .await?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(KuboError::Api(format!("block/get HTTP {status}: {body}")));
        }

        Ok(Some(resp.bytes().await?.to_vec()))
    }

    /// Publish an IPNS record pointing to `cid` under the node's default key.
    ///
    /// Returns the IPNS address (`/ipns/<peer-id>`) on success.
    pub async fn name_publish(&self, cid: &Cid) -> Result<String, KuboError> {
        let arg = format!("/ipfs/{cid}");

        let resp = self
            .client
            .post(format!("{}/api/v0/name/publish", self.api_base))
            .query(&[("arg", arg.as_str())])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(KuboError::Api(format!(
                "name/publish HTTP {status}: {body}"
            )));
        }

        let parsed: NamePublishResponse = resp.json().await?;
        Ok(format!("/ipns/{}", parsed.name))
    }

    /// Remove the pin for `cid` from Kubo's pinset.
    ///
    /// After unpinning, the block remains in Kubo's block store and is still
    /// readable until `ipfs repo gc` runs.  This corresponds to
    /// [`DeletionOutcome::Deferred`] in the store abstraction.
    ///
    /// Returns `Ok(())` if the pin was removed or was never present.
    pub async fn pin_rm(&self, cid: &Cid) -> Result<(), KuboError> {
        let resp = self
            .client
            .post(format!("{}/api/v0/pin/rm", self.api_base))
            .query(&[("arg", cid.to_string())])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Kubo returns an error when the pin is not present. Treat that
            // as success: the postcondition (block is unpinned) is already met.
            if body.contains("not pinned") {
                return Ok(());
            }
            return Err(KuboError::Api(format!("pin/rm HTTP {status}: {body}")));
        }

        Ok(())
    }

    /// Return the Kubo node's libp2p peer ID string.
    ///
    /// Used to derive the stable IPNS address at startup.
    pub async fn node_id(&self) -> Result<String, KuboError> {
        let resp = self
            .client
            .post(format!("{}/api/v0/id", self.api_base))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(KuboError::Api(format!("id HTTP {status}: {body}")));
        }

        let parsed: IdResponse = resp.json().await?;
        Ok(parsed.id)
    }
}

// ── CircuitBreakerKuboClient ──────────────────────────────────────────────────

/// [`KuboHttpClient`] wrapped in a [`crate::circuit_breaker::CircuitBreaker`].
///
/// Exposes the same methods as [`KuboHttpClient`].  When the circuit is in the
/// [`crate::circuit_breaker::CbState::Open`] state, all calls return
/// `Err(KuboError::Api("circuit breaker open: block store unavailable"))`
/// without making an HTTP request.
///
/// Cheaply cloneable via `Arc`; all clones share the same circuit state.
#[derive(Clone)]
pub struct CircuitBreakerKuboClient {
    inner: KuboHttpClient,
    cb: crate::circuit_breaker::CircuitBreaker,
}

impl CircuitBreakerKuboClient {
    /// Create a new circuit-breaker-wrapped Kubo client.
    pub fn new(api_url: &str, config: crate::circuit_breaker::CircuitBreakerConfig) -> Self {
        Self {
            inner: KuboHttpClient::new(api_url),
            cb: crate::circuit_breaker::CircuitBreaker::new(config),
        }
    }

    /// Attach a state-change callback (see
    /// [`crate::circuit_breaker::CircuitBreaker::with_state_change_callback`]).
    pub fn with_state_change_callback<F>(self, f: F) -> Self
    where
        F: Fn(crate::circuit_breaker::CbState, crate::circuit_breaker::CbState)
            + Send
            + Sync
            + 'static,
    {
        Self {
            cb: self.cb.with_state_change_callback(f),
            ..self
        }
    }

    /// Borrow the underlying circuit breaker for state inspection.
    pub fn circuit_breaker(&self) -> &crate::circuit_breaker::CircuitBreaker {
        &self.cb
    }

    /// Borrow the underlying [`KuboHttpClient`].
    ///
    /// Useful for operations that bypass the circuit breaker (e.g. IPNS
    /// publish, which is managed by a separate rate limiter and advisory lock).
    pub fn inner(&self) -> &KuboHttpClient {
        &self.inner
    }

    fn cb_err() -> KuboError {
        KuboError::Api("circuit breaker open: block store unavailable".into())
    }

    /// Store a block, or immediately fail if the circuit is open.
    pub async fn block_put(&self, data: &[u8], codec: u64) -> Result<Cid, KuboError> {
        if !self.cb.allow_request() {
            return Err(Self::cb_err());
        }
        match self.inner.block_put(data, codec).await {
            Ok(cid) => {
                self.cb.record_success();
                Ok(cid)
            }
            Err(e) => {
                self.cb.record_failure();
                Err(e)
            }
        }
    }

    /// Retrieve a block, or immediately fail if the circuit is open.
    pub async fn block_get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, KuboError> {
        if !self.cb.allow_request() {
            return Err(Self::cb_err());
        }
        match self.inner.block_get(cid).await {
            Ok(result) => {
                self.cb.record_success();
                Ok(result)
            }
            Err(e) => {
                self.cb.record_failure();
                Err(e)
            }
        }
    }

    /// Publish an IPNS record, or immediately fail if the circuit is open.
    pub async fn name_publish(&self, cid: &Cid) -> Result<String, KuboError> {
        if !self.cb.allow_request() {
            return Err(Self::cb_err());
        }
        match self.inner.name_publish(cid).await {
            Ok(addr) => {
                self.cb.record_success();
                Ok(addr)
            }
            Err(e) => {
                self.cb.record_failure();
                Err(e)
            }
        }
    }

    /// Unpin a block, or immediately fail if the circuit is open.
    pub async fn pin_rm(&self, cid: &Cid) -> Result<(), KuboError> {
        if !self.cb.allow_request() {
            return Err(Self::cb_err());
        }
        match self.inner.pin_rm(cid).await {
            Ok(()) => {
                self.cb.record_success();
                Ok(())
            }
            Err(e) => {
                self.cb.record_failure();
                Err(e)
            }
        }
    }

    /// Return the Kubo node's peer ID, or immediately fail if the circuit is open.
    pub async fn node_id(&self) -> Result<String, KuboError> {
        if !self.cb.allow_request() {
            return Err(Self::cb_err());
        }
        match self.inner.node_id().await {
            Ok(id) => {
                self.cb.record_success();
                Ok(id)
            }
            Err(e) => {
                self.cb.record_failure();
                Err(e)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_breaker::{CbState, CircuitBreakerConfig};
    use std::time::{Duration, Instant};

    fn fast_cb_client() -> CircuitBreakerKuboClient {
        CircuitBreakerKuboClient::new(
            "http://127.0.0.1:1", // port 1 is always unreachable
            CircuitBreakerConfig {
                failure_threshold: 1,
                window: Duration::from_secs(60),
                probe_interval: Duration::from_millis(1),
            },
        )
    }

    /// When the circuit is open, `block_put` must return `Err` immediately
    /// — not waiting for an HTTP connect timeout.
    #[tokio::test]
    async fn open_circuit_block_put_returns_immediately() {
        let client = fast_cb_client();
        client.circuit_breaker().record_failure(); // force open
        assert_eq!(client.circuit_breaker().state(), CbState::Open);

        let start = Instant::now();
        let result = client.block_put(b"test data", 0x55).await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "open circuit must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("circuit breaker open"),
            "error must mention 'circuit breaker open', got: {msg}",
        );
        assert!(
            elapsed < Duration::from_millis(50),
            "open circuit must return immediately (no HTTP attempt), took {elapsed:?}",
        );
    }

    /// Same fast-fail guarantee for `block_get`.
    #[tokio::test]
    async fn open_circuit_block_get_returns_immediately() {
        let client = fast_cb_client();
        client.circuit_breaker().record_failure();

        let cid = Cid::new_v1(0x55, Code::Sha2_256.digest(b"x"));
        let start = Instant::now();
        let result = client.block_get(&cid).await;
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "open circuit must return Err for block_get"
        );
        assert!(
            elapsed < Duration::from_millis(50),
            "block_get on open circuit must return immediately, took {elapsed:?}",
        );
    }

    /// After a simulated successful probe the circuit closes again.
    #[tokio::test]
    async fn circuit_closes_after_successful_probe() {
        let client = fast_cb_client();
        client.circuit_breaker().record_failure(); // open
        assert_eq!(client.circuit_breaker().state(), CbState::Open);

        std::thread::sleep(Duration::from_millis(5)); // probe interval elapsed
        assert!(client.circuit_breaker().allow_request()); // → HalfOpen
        assert_eq!(client.circuit_breaker().state(), CbState::HalfOpen);

        client.circuit_breaker().record_success(); // → Closed
        assert_eq!(client.circuit_breaker().state(), CbState::Closed);
    }

    /// State-change callback wired through `with_state_change_callback` fires.
    #[tokio::test]
    async fn state_change_callback_fires() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let opens = Arc::new(AtomicU32::new(0));
        let opens2 = Arc::clone(&opens);

        let client = CircuitBreakerKuboClient::new(
            "http://127.0.0.1:1",
            CircuitBreakerConfig {
                failure_threshold: 1,
                window: Duration::from_secs(60),
                probe_interval: Duration::from_millis(1),
            },
        )
        .with_state_change_callback(move |_old, new| {
            if new == CbState::Open {
                opens2.fetch_add(1, Ordering::Relaxed);
            }
        });

        client.circuit_breaker().record_failure(); // triggers Open
        assert_eq!(
            opens.load(Ordering::Relaxed),
            1,
            "callback must fire on open"
        );
    }
}
