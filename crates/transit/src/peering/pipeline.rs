//! Store-and-forward pipeline for the transit daemon.
//!
//! After an article passes `check_ingest`, `run_pipeline` writes it to IPFS,
//! records the Message-ID → CID mapping, appends to each group log, and
//! publishes tip advertisements via gossipsub.

use async_trait::async_trait;
use cid::Cid;
use mail_auth::MessageAuthenticator;
use multihash_codetable::{Code, MultihashDigest};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use usenet_ipfs_core::{
    article::GroupName,
    group_log::{storage::LogStorage, types::LogEntry},
    hlc::HlcTimestamp,
    msgid_map::MsgIdMap,
};
use usenet_ipfs_verify::VerificationStore;

// ── IPFS abstraction ──────────────────────────────────────────────────────────

/// Error returned by [`IpfsStore::put_raw`].
#[derive(Debug)]
pub enum IpfsError {
    WriteFailed(String),
}

impl std::fmt::Display for IpfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpfsError::WriteFailed(m) => write!(f, "IPFS write failed: {m}"),
        }
    }
}

impl std::error::Error for IpfsError {}

/// Abstraction over IPFS raw block storage.
///
/// The trait is object-safe and mockable; production code uses [`KuboStore`]
/// backed by a Kubo daemon; tests use [`MemIpfsStore`].
#[async_trait]
pub trait IpfsStore: Send + Sync {
    /// Write `data` to IPFS. Returns the CID of the stored block.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError>;

    /// Fetch the raw block bytes for `cid`.
    ///
    /// Returns `None` if the block is not locally available (not pinned,
    /// not yet retrieved from the network). Returns `Err` on I/O or
    /// internal errors.
    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError>;
}

// ── In-memory IPFS store for tests ───────────────────────────────────────────

/// In-memory IPFS block store for tests.
pub struct MemIpfsStore {
    blocks: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemIpfsStore {
    pub fn new() -> Self {
        Self {
            blocks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemIpfsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IpfsStore for MemIpfsStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let digest = Code::Sha2_256.digest(data);
        // Raw codec (0x55) — article bytes are opaque blobs at the block layer.
        let cid = Cid::new_v1(0x55, digest);
        self.blocks
            .write()
            .unwrap()
            .insert(cid.to_string(), data.to_vec());
        Ok(cid)
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        Ok(self.blocks.read().unwrap().get(&cid.to_string()).cloned())
    }
}

// ── Production Kubo store ─────────────────────────────────────────────────────

/// IPFS block store backed by a Kubo daemon via its HTTP RPC API.
///
/// Requires a running Kubo node reachable at the configured `api_url`.
/// `KuboStore` is cheaply cloneable — the underlying `KuboHttpClient` holds
/// only a `reqwest::Client` (connection-pooled) and the API URL string.
pub struct KuboStore {
    client: usenet_ipfs_core::ipfs::KuboHttpClient,
}

impl KuboStore {
    /// Create a store targeting the Kubo daemon at `api_url`
    /// (e.g. `"http://127.0.0.1:5001"`).
    pub fn new(api_url: &str) -> Self {
        Self {
            client: usenet_ipfs_core::ipfs::KuboHttpClient::new(api_url),
        }
    }

    /// Return a clone of the underlying Kubo HTTP client.
    ///
    /// Used by the IPNS publisher to call `name_publish` without going through
    /// the `IpfsStore` trait.
    pub fn kubo_client(&self) -> usenet_ipfs_core::ipfs::KuboHttpClient {
        self.client.clone()
    }
}

#[async_trait]
impl IpfsStore for KuboStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        self.client
            .block_put(data, 0x55)
            .await
            .map_err(|e| IpfsError::WriteFailed(e.to_string()))
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        self.client
            .block_get(cid)
            .await
            .map_err(|e| IpfsError::WriteFailed(e.to_string()))
    }
}

// ── Pipeline context and result types ────────────────────────────────────────

/// Per-invocation context for `run_pipeline`.
///
/// Groups the parameters that vary per article ingestion event, keeping the
/// pipeline function signature under the clippy argument-count limit.
pub struct PipelineCtx<'a> {
    /// HLC timestamp to stamp the log entry with.
    pub timestamp: HlcTimestamp,
    /// Operator Ed25519 signature over this article.
    pub operator_signature: ed25519_dalek::Signature,
    /// Optional gossipsub send channel; `None` disables tip publication.
    pub gossip_tx: Option<&'a mpsc::Sender<(String, Vec<u8>)>>,
    /// Sending peer's identity string, embedded in tip advertisements.
    pub sender_peer_id: &'a str,
    /// Local FQDN prepended to the `Path:` header (Son-of-RFC-1036 §3.3).
    pub local_hostname: &'a str,
    /// Verification store. `None` disables signature recording.
    pub verify_store: Option<&'a VerificationStore>,
    /// Trusted verifying keys for `X-Usenet-IPFS-Sig` checks.
    pub trusted_keys: &'a [ed25519_dalek::VerifyingKey],
    /// DKIM authenticator. `None` disables DKIM checks.
    pub dkim_auth: Option<&'a MessageAuthenticator>,
}

/// Result of running the store-and-forward pipeline.
#[derive(Debug)]
pub struct PipelineResult {
    /// CID of the stored article block.
    pub cid: Cid,
    /// Groups the article was appended to (successfully validated group names).
    pub groups: Vec<String>,
}

/// Counters produced by a single pipeline run.
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    pub articles_ingested_total: u64,
    pub ipfs_write_latency_ms: u64,
}

// ── Verification helper ───────────────────────────────────────────────────────

/// Verify article signatures (best-effort; never blocks ingestion).
///
/// Runs X-Usenet-IPFS-Sig verification against `trusted_keys` (pass an
/// empty slice to record `NoKey` when the header is present, or receive no
/// result when it is absent).  Runs DKIM verification when `dkim_auth` is
/// `Some`.  Records all results via `store`.  Any failure is logged and
/// silently dropped — verification is non-fatal.
pub async fn verify_article(
    article_bytes: &[u8],
    cid: &Cid,
    store: &VerificationStore,
    trusted_keys: &[ed25519_dalek::VerifyingKey],
    dkim_auth: Option<&MessageAuthenticator>,
) {
    use usenet_ipfs_verify::dkim::verify_dkim_headers;
    use usenet_ipfs_verify::x_sig::verify_x_sig;

    let x_sig_results = verify_x_sig(trusted_keys, article_bytes);
    let dkim_results = if let Some(auth) = dkim_auth {
        verify_dkim_headers(auth, article_bytes).await
    } else {
        vec![]
    };
    let all_verifications: Vec<_> = x_sig_results.into_iter().chain(dkim_results).collect();
    let verified_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    if let Err(e) = store
        .record_verifications(cid, &all_verifications, verified_at_ms)
        .await
    {
        tracing::warn!(cid = %cid, error = %e, "verification record failed");
    }
    let pass_count = all_verifications
        .iter()
        .filter(|v| v.result.is_pass())
        .count();
    tracing::info!(
        cid = %cid,
        checks = all_verifications.len(),
        passed = pass_count,
        "article verification complete"
    );
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Run the store-and-forward pipeline for a single article.
///
/// Steps:
/// 1. Write article bytes to IPFS → CID.
/// 2. Insert Message-ID → CID in `msgid_map`.
/// 3. Append a [`LogEntry`] to each group named in `Newsgroups:`.
/// 4. Publish a [`TipAdvertisement`] for each group via `ctx.gossip_tx` (best-effort).
///
/// Returns `Err` immediately if the IPFS write or articles table insert fails.
/// Log-append failures are logged as warnings but do not abort the pipeline.
/// Gossipsub publish failures are logged but not propagated.
pub async fn run_pipeline<I, S>(
    article_bytes: &[u8],
    ipfs: &I,
    msgid_map: &MsgIdMap,
    log_storage: &S,
    pool: &SqlitePool,
    ctx: PipelineCtx<'_>,
) -> Result<(PipelineResult, PipelineMetrics), String>
where
    I: IpfsStore + ?Sized,
    S: LogStorage,
{
    use crate::gossip::tip_advert::TipAdvertisement;
    use crate::peering::ingestion::prepend_path_header;

    // Snapshot original bytes for signature verification before Path: is prepended.
    // The X-Usenet-IPFS-Sig is computed over the article as received from the peer,
    // before any local transit modifications.
    let original_bytes = article_bytes;

    // 0. Prepend local hostname to Path: header (Son-of-RFC-1036 §3.3).
    let article_bytes_owned = prepend_path_header(article_bytes.to_vec(), ctx.local_hostname);
    let article_bytes = article_bytes_owned.as_slice();

    // 1. Write to IPFS.
    let t0 = Instant::now();
    let cid = ipfs
        .put_raw(article_bytes)
        .await
        .map_err(|e| format!("IPFS write failed: {e}"))?;
    let elapsed = t0.elapsed();
    crate::metrics::IPFS_WRITE_LATENCY_SECONDS.observe(elapsed.as_secs_f64());
    let ipfs_write_latency_ms = elapsed.as_millis() as u64;

    // 1b. Verify article signatures against the original received bytes.
    // Signature was computed by the peer before transit Path: modification.
    if let Some(store) = ctx.verify_store {
        verify_article(original_bytes, &cid, store, ctx.trusted_keys, ctx.dkim_auth).await;
    }

    // 2+3. Parse Message-ID and Newsgroups in a single header scan.
    let (message_id, group_name_strs) = parse_message_id_and_newsgroups(article_bytes)
        .ok_or_else(|| "missing Message-ID header".to_string())?;
    msgid_map
        .insert(&message_id, &cid)
        .await
        .map_err(|e| format!("msgid insert failed: {e}"))?;

    // 3. Append a log entry to each valid group.
    let sig_bytes = ctx.operator_signature.to_bytes().to_vec();

    // Pairs of (group_name, entry_id) for successful appends; entry_id is used
    // in tip advertisements so that peers can reconcile via LogEntryId, not
    // the raw article CID.
    let mut appended_groups: Vec<(String, usenet_ipfs_core::group_log::LogEntryId)> = Vec::new();
    for group_name_str in &group_name_strs {
        let group = match GroupName::new(group_name_str.clone()) {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!("invalid group name in Newsgroups: {group_name_str:?}");
                continue;
            }
        };
        let entry = LogEntry {
            // LogEntry.hlc_timestamp is u64 wall-clock milliseconds.
            hlc_timestamp: ctx.timestamp.wall_ms,
            article_cid: cid,
            operator_signature: sig_bytes.clone(),
            // Genesis entry: no parent chain; peers reconcile via CRDT.
            parent_cids: vec![],
        };
        match usenet_ipfs_core::group_log::append::append(log_storage, &group, entry).await {
            Err(e) => {
                tracing::warn!("log append failed for group {group_name_str}: {e}");
            }
            Ok(entry_id) => {
                crate::metrics::ARTICLES_INGESTED_GROUP_TOTAL
                    .with_label_values(&[group_name_str])
                    .inc();
                appended_groups.push((group_name_str.clone(), entry_id));
            }
        }
    }

    // 3.5. Record in articles table for GC tracking.
    //
    // This is a hard error: if IPFS write, msgid_map, and group log all succeed
    // but the articles table insert fails, the block exists in IPFS but is
    // invisible to select_gc_candidates — it will never be collected.
    //
    // `ingested_at_ms` MUST be the current wall-clock time (SystemTime::now()),
    // NOT from the article's Date header or ctx.timestamp — those are
    // peer-supplied.  The grace period check in gc_candidates.rs only protects
    // newly ingested articles from immediate collection when this invariant holds.
    {
        let cid_str = cid.to_string();
        let primary_group = group_name_strs.first().map(String::as_str).unwrap_or("");
        let ingested_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let byte_count = article_bytes.len() as i64;
        sqlx::query(
            "INSERT OR IGNORE INTO articles (cid, group_name, ingested_at_ms, byte_count) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&cid_str)
        .bind(primary_group)
        .bind(ingested_at_ms)
        .bind(byte_count)
        .execute(pool)
        .await
        .map_err(|e| format!("articles table insert failed for CID {cid_str}: {e}"))?;
    }

    // 4. Publish tip advertisements (best-effort).
    // Advertise the LogEntryId wrapped as a CID so that receiving peers can
    // use the digest directly as a LogEntryId during reconciliation.
    if let Some(tx) = ctx.gossip_tx {
        for (group_name_str, entry_id) in &appended_groups {
            let tip_cid_str = entry_id.to_cid().to_string();
            let advert = TipAdvertisement {
                group_name: group_name_str.clone(),
                tip_cids: vec![tip_cid_str],
                hlc_ms: ctx.timestamp.wall_ms,
                hlc_logical: ctx.timestamp.logical,
                hlc_node_id: hex::encode(ctx.timestamp.node_id),
                sender_peer_id: ctx.sender_peer_id.to_owned(),
            };
            let hierarchy = group_name_str.split('.').next().unwrap_or(group_name_str);
            let topic = format!("usenet.hier.{hierarchy}");
            let bytes = advert.to_bytes();
            if let Err(e) = tx.send((topic, bytes)).await {
                tracing::warn!("gossip tip publish failed for {group_name_str}: {e}");
            }
        }
    }

    let group_names: Vec<String> = appended_groups.into_iter().map(|(name, _)| name).collect();

    Ok((
        PipelineResult {
            cid,
            groups: group_names,
        },
        PipelineMetrics {
            articles_ingested_total: 1,
            ipfs_write_latency_ms,
        },
    ))
}

// ── Header extraction helpers ─────────────────────────────────────────────────

/// Extract the value of a header field from raw article bytes.
///
/// Scans the header section (lines before the first blank line) for
/// `name:` (case-insensitive). Returns the trimmed value, or `None` if
/// not found or the bytes are not valid UTF-8 on that line.
#[cfg(test)]
fn extract_header<'a>(article_bytes: &'a [u8], name: &str) -> Option<&'a str> {
    let name_lower = name.to_ascii_lowercase();
    let needle = format!("{name_lower}:");

    for line in article_bytes.split(|&b| b == b'\n') {
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.is_empty() {
            break;
        }
        let s = std::str::from_utf8(trimmed).ok()?;
        if s.to_ascii_lowercase().starts_with(&needle) {
            return Some(s[needle.len()..].trim());
        }
    }
    None
}

/// Extract `Message-ID` and `Newsgroups` from article bytes in a single pass.
///
/// Returns `None` if `Message-ID` is absent. `Newsgroups` defaults to an
/// empty list when the header is missing.
fn parse_message_id_and_newsgroups(article_bytes: &[u8]) -> Option<(String, Vec<String>)> {
    let mut message_id: Option<String> = None;
    let mut newsgroups_val: Option<String> = None;

    for line in article_bytes.split(|&b| b == b'\n') {
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.is_empty() {
            break;
        }
        let s = match std::str::from_utf8(trimmed) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let lower = s.to_ascii_lowercase();
        if message_id.is_none() && lower.starts_with("message-id:") {
            message_id = Some(s["message-id:".len()..].trim().to_owned());
        } else if newsgroups_val.is_none() && lower.starts_with("newsgroups:") {
            newsgroups_val = Some(s["newsgroups:".len()..].trim().to_owned());
        }
        if message_id.is_some() && newsgroups_val.is_some() {
            break;
        }
    }

    let mid = message_id?;
    let groups = newsgroups_val
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    Some((mid, groups))
}

#[cfg(test)]
/// Parse the `Newsgroups:` header into a list of group name strings.
fn parse_newsgroups(article_bytes: &[u8]) -> Vec<String> {
    let value = match extract_header(article_bytes, "Newsgroups") {
        Some(v) => v,
        None => return vec![],
    };
    value
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
/// Extract the `Message-ID:` value from article bytes.
fn extract_message_id(article_bytes: &[u8]) -> Option<String> {
    extract_header(article_bytes, "Message-ID").map(|s| s.to_owned())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;

    async fn make_transit_pool() -> SqlitePool {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        pool
    }

    async fn make_msgid_map() -> (MsgIdMap, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        usenet_ipfs_core::migrations::run_migrations(&pool)
            .await
            .unwrap();
        (MsgIdMap::new(pool), tmp)
    }

    fn make_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn make_timestamp() -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: 1_700_000_000_000,
            logical: 0,
            node_id: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    fn make_ctx(key: &SigningKey, ts: HlcTimestamp) -> PipelineCtx<'static> {
        PipelineCtx {
            timestamp: ts,
            operator_signature: ed25519_dalek::Signer::sign(key, b""),
            gossip_tx: None,
            sender_peer_id: "peer1",
            local_hostname: "local.test.example.com",
            verify_store: None,
            trusted_keys: &[],
            dkim_auth: None,
        }
    }

    fn make_article(msgid: &str, newsgroups: &str) -> Vec<u8> {
        format!(
            "From: sender@example.com\r\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
             Message-ID: {msgid}\r\n\
             Newsgroups: {newsgroups}\r\n\
             Subject: Test Article\r\n\
             \r\n\
             This is the body.\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn pipeline_success_records_cid() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = usenet_ipfs_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let article = make_article("<test@example.com>", "comp.lang.rust");
        let transit_pool = make_transit_pool().await;

        let result = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(&key, make_timestamp()),
        )
        .await;

        assert!(result.is_ok(), "pipeline should succeed: {result:?}");
        let (pr, _metrics) = result.unwrap();
        assert_eq!(pr.groups, vec!["comp.lang.rust"]);

        // CID must be recorded in msgid_map.
        let cid = msgid_map
            .lookup_by_msgid("<test@example.com>")
            .await
            .unwrap();
        assert!(cid.is_some(), "CID must be recorded in msgid_map");
        assert_eq!(cid.unwrap(), pr.cid);
    }

    #[tokio::test]
    async fn pipeline_records_article_in_articles_table() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = usenet_ipfs_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let article = make_article("<articles-table@example.com>", "alt.test");
        let transit_pool = make_transit_pool().await;

        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let (pr, _metrics) = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(&key, make_timestamp()),
        )
        .await
        .unwrap();

        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let row: Option<(String, String, i64, i64)> = sqlx::query_as(
            "SELECT cid, group_name, ingested_at_ms, byte_count FROM articles WHERE cid = ?1",
        )
        .bind(pr.cid.to_string())
        .fetch_optional(&transit_pool)
        .await
        .unwrap();

        let (cid_str, group_name, ingested_at_ms, byte_count) =
            row.expect("articles table must contain the ingested article");

        // byte_count reflects the bytes written to IPFS — after prepend_path_header
        // is applied. Compute the expected size independently.
        let expected_bytes = crate::peering::ingestion::prepend_path_header(
            article.clone(),
            "local.test.example.com",
        );
        assert_eq!(cid_str, pr.cid.to_string());
        assert_eq!(group_name, "alt.test");
        assert!(
            ingested_at_ms >= before_ms && ingested_at_ms <= after_ms,
            "ingested_at_ms {ingested_at_ms} must be within [{before_ms}, {after_ms}]"
        );
        assert_eq!(byte_count as usize, expected_bytes.len());
    }

    #[tokio::test]
    async fn pipeline_publishes_gossip_tip() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = usenet_ipfs_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let article = make_article("<gossip@example.com>", "comp.lang.rust");

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let ctx = PipelineCtx {
            timestamp: make_timestamp(),
            operator_signature: ed25519_dalek::Signer::sign(&key, b""),
            gossip_tx: Some(&tx),
            sender_peer_id: "peer1",
            local_hostname: "local.test.example.com",
            verify_store: None,
            trusted_keys: &[],
            dkim_auth: None,
        };
        let transit_pool = make_transit_pool().await;
        let result = run_pipeline(&article, &ipfs, &msgid_map, &storage, &transit_pool, ctx)
            .await;
        assert!(result.is_ok(), "pipeline should succeed: {result:?}");

        // Should have received a gossip message.
        let (topic, bytes) = rx.try_recv().expect("should have gossip message");
        assert_eq!(topic, "usenet.hier.comp");
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["group_name"], "comp.lang.rust");
    }

    #[test]
    fn parse_newsgroups_single() {
        let article = b"Newsgroups: comp.lang.rust\r\n\r\n";
        assert_eq!(parse_newsgroups(article), vec!["comp.lang.rust"]);
    }

    #[test]
    fn parse_newsgroups_multiple() {
        let article = b"Newsgroups: comp.lang.rust,sci.math\r\n\r\n";
        let groups = parse_newsgroups(article);
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&"comp.lang.rust".to_string()));
        assert!(groups.contains(&"sci.math".to_string()));
    }

    #[test]
    fn extract_message_id_found() {
        let article = b"Message-ID: <abc@example.com>\r\n\r\n";
        assert_eq!(
            extract_message_id(article),
            Some("<abc@example.com>".to_string())
        );
    }

    #[tokio::test]
    async fn pipeline_missing_message_id_returns_err() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = usenet_ipfs_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let transit_pool = make_transit_pool().await;
        // Article with no Message-ID header.
        let article = b"From: x@example.com\r\nNewsgroups: alt.test\r\n\r\nBody.\r\n";

        let result = run_pipeline(
            article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(&key, make_timestamp()),
        )
        .await;
        assert!(result.is_err(), "missing Message-ID must return Err");
        assert!(result.unwrap_err().contains("Message-ID"));
    }

    #[tokio::test]
    async fn pipeline_metrics_latency_set() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = usenet_ipfs_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let article = make_article("<metrics@example.com>", "alt.test");
        let transit_pool = make_transit_pool().await;

        let (_pr, metrics) = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(&key, make_timestamp()),
        )
        .await
        .unwrap();
        assert_eq!(metrics.articles_ingested_total, 1);
        // Latency is in ms; MemIpfsStore is effectively instant so it should be very low.
        assert!(
            metrics.ipfs_write_latency_ms < 1000,
            "latency should be sub-second"
        );
    }

    /// Son-of-RFC-1036 §3.3: the pipeline must prepend the local hostname to
    /// the `Path:` header in the bytes written to IPFS.
    #[tokio::test]
    async fn pipeline_prepends_local_hostname_to_path_header() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = usenet_ipfs_core::group_log::MemLogStorage::new();
        let key = make_signing_key();
        let transit_pool = make_transit_pool().await;

        // Article with an existing Path: from a peer.
        let article = format!(
            "From: sender@example.com\r\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
             Message-ID: <path-test@example.com>\r\n\
             Newsgroups: alt.test\r\n\
             Subject: Path Test\r\n\
             Path: peer.example.com\r\n\
             \r\n\
             Body.\r\n"
        )
        .into_bytes();

        let (pr, _metrics) = run_pipeline(
            &article,
            &ipfs,
            &msgid_map,
            &storage,
            &transit_pool,
            make_ctx(&key, make_timestamp()),
        )
        .await
        .unwrap();

        // Retrieve the stored bytes from MemIpfsStore to verify Path: was patched.
        let stored = ipfs
            .blocks
            .read()
            .unwrap()
            .get(&pr.cid.to_string())
            .cloned()
            .expect("block must be stored in MemIpfsStore");

        let stored_text = String::from_utf8(stored).expect("stored bytes must be valid UTF-8");
        assert!(
            stored_text.contains("Path: local.test.example.com!peer.example.com\r\n"),
            "stored article must have local hostname prepended to Path: header: {stored_text:?}"
        );
        assert!(
            !stored_text.contains("Path: peer.example.com\r\n"),
            "old standalone Path: must not remain in stored article: {stored_text:?}"
        );
    }

    /// Create an in-memory SQLite pool with verify-crate migrations applied.
    async fn make_verify_pool() -> SqlitePool {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:pipeline_verify_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::new()
            .filename(&url)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("verify pool must open");
        usenet_ipfs_verify::run_migrations(&pool)
            .await
            .expect("verify migrations must succeed");
        pool
    }

    /// Append `X-Usenet-IPFS-Sig` to article headers, signed with `key`.
    ///
    /// Replicates the signing convention from the verify crate's x_sig tests:
    /// the signature is computed over the article bytes (without the sig header),
    /// then the header is inserted just before the blank separator line.
    fn sign_article_bytes(key: &SigningKey, article_bytes: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;

        let sig: ed25519_dalek::Signature = key.sign(article_bytes);
        let sig_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let sig_line = format!("X-Usenet-IPFS-Sig: {sig_value}\r\n");

        // Find the blank line separating headers from body (\r\n\r\n).
        let body_start = article_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .or_else(|| {
                article_bytes
                    .windows(2)
                    .position(|w| w == b"\n\n")
                    .map(|p| p + 2)
            })
            .unwrap_or(article_bytes.len());

        let sep_len =
            if body_start >= 4 && article_bytes[body_start - 4..body_start] == *b"\r\n\r\n" {
                2
            } else {
                1
            };
        let insert_at = body_start - sep_len;

        let mut out = Vec::with_capacity(article_bytes.len() + sig_line.len());
        out.extend_from_slice(&article_bytes[..insert_at]);
        out.extend_from_slice(sig_line.as_bytes());
        out.extend_from_slice(&article_bytes[insert_at..]);
        out
    }

    /// An article with a valid `X-Usenet-IPFS-Sig` header → pipeline must record
    /// an `article_verifications` row with `result = 'pass'`.
    #[tokio::test]
    async fn pipeline_verify_x_sig_records_pass_row() {
        let ipfs = MemIpfsStore::new();
        let (msgid_map, _tmp) = make_msgid_map().await;
        let storage = usenet_ipfs_core::group_log::MemLogStorage::new();
        let transit_pool = make_transit_pool().await;
        let verify_pool = make_verify_pool().await;

        let signing_key = make_signing_key();
        let verifying_key = signing_key.verifying_key();

        // Build an unsigned article, then sign it with the known key.
        let unsigned = make_article("<sig-test@example.com>", "alt.test");
        let signed = sign_article_bytes(&signing_key, &unsigned);

        let verify_store = usenet_ipfs_verify::VerificationStore::new(verify_pool.clone());

        let ctx = PipelineCtx {
            timestamp: make_timestamp(),
            operator_signature: ed25519_dalek::Signer::sign(&signing_key, b""),
            gossip_tx: None,
            sender_peer_id: "peer1",
            local_hostname: "local.test.example.com",
            verify_store: Some(&verify_store),
            trusted_keys: &[verifying_key],
            dkim_auth: None,
        };
        let (pr, _metrics) = run_pipeline(&signed, &ipfs, &msgid_map, &storage, &transit_pool, ctx)
            .await
            .expect("pipeline must succeed with signed article");

        // Verify that the article_verifications table contains a pass row.
        let rows: Vec<(Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT cid, sig_type, result FROM article_verifications WHERE result = 'pass'",
        )
        .fetch_all(&verify_pool)
        .await
        .expect("article_verifications query must succeed");

        assert!(
            !rows.is_empty(),
            "article_verifications must contain at least one pass row after pipeline run"
        );
        let cid_bytes = pr.cid.to_bytes();
        let pass_row = rows.iter().find(|(cid, _, _)| *cid == cid_bytes);
        assert!(
            pass_row.is_some(),
            "pass row must be for the ingested article CID {}; rows: {rows:?}",
            pr.cid
        );
        let (_, sig_type, result) = pass_row.unwrap();
        assert_eq!(sig_type, "x-usenet-ipfs-sig");
        assert_eq!(result, "pass");
    }
}
