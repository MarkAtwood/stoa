//! Kubo HTTP RPC client for IPFS block operations.
//!
//! Wraps the Kubo daemon's `/api/v0/block/*` and `/api/v0/name/publish`
//! endpoints so that transit and reader can store and retrieve IPLD blocks
//! without embedding a rust-ipfs node.

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::Deserialize;

// ── Error type ────────────────────────────────────────────────────────────────

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
    pub async fn block_put(&self, data: &[u8], codec: u64) -> Result<Cid, KuboError> {
        let codec_name = match codec {
            0x55 => "raw",
            0x71 => "dag-cbor",
            other => return Err(KuboError::Api(format!("unsupported codec 0x{other:x}"))),
        };

        // Compute the expected CID locally so we can verify the round-trip.
        let digest = Code::Sha2_256.digest(data);
        let expected_cid = Cid::new_v1(codec, digest);

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
    /// Returns `None` if the block is not available locally in the Kubo node
    /// (not pinned, not yet retrieved from the network). Returns `Err` on
    /// network or Kubo API errors.
    pub async fn block_get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, KuboError> {
        let resp = self
            .client
            .post(format!("{}/api/v0/block/get", self.api_base))
            .query(&[("arg", cid.to_string())])
            .send()
            .await?;

        if resp.status().as_u16() == 500 {
            // Kubo returns 500 when the block is not locally available.
            // Distinguish "not found" from genuine errors by checking the body.
            let body = resp.text().await.unwrap_or_default();
            if body.contains("not found") || body.contains("blockstore") {
                return Ok(None);
            }
            return Err(KuboError::Api(format!("block/get HTTP 500: {body}")));
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
            return Err(KuboError::Api(format!("name/publish HTTP {status}: {body}")));
        }

        let parsed: NamePublishResponse = resp.json().await?;
        Ok(format!("/ipns/{}", parsed.name))
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
