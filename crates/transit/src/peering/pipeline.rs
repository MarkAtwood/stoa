//! Store-and-forward pipeline for the transit daemon.
//!
//! After an article passes `check_ingest`, `run_pipeline` writes it to IPFS,
//! records the Message-ID → CID mapping, appends to each group log, and
//! publishes tip advertisements via gossipsub.

use async_trait::async_trait;
use cid::Cid;
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
/// The trait is object-safe and mockable; production code will implement it
/// against `rust-ipfs` 0.15; tests use [`MemIpfsStore`].
#[async_trait]
pub trait IpfsStore: Send + Sync {
    /// Write `data` to IPFS. Returns the CID of the stored block.
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError>;
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
}

// ── Production rust-ipfs store ────────────────────────────────────────────────

/// IPFS block store backed by `rust-ipfs` 0.15 (in-process node).
///
/// Blocks are stored in the node's local repository. No external IPFS daemon
/// is required. `rust_ipfs::Ipfs` is `Clone`; the handle is cheaply shared.
pub struct RustIpfsStore {
    ipfs: rust_ipfs::Ipfs,
}

impl RustIpfsStore {
    /// Start an in-process IPFS node and return a store backed by it.
    pub async fn new() -> Result<Self, String> {
        let ipfs = rust_ipfs::builder::DefaultIpfsBuilder::new()
            .start()
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { ipfs })
    }
}

#[async_trait]
impl IpfsStore for RustIpfsStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        let block = rust_ipfs::Block::new(cid, data.to_vec())
            .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
        self.ipfs
            .put_block(&block)
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

    // 2+3. Parse Message-ID and Newsgroups in a single header scan.
    let (message_id, group_name_strs) = parse_message_id_and_newsgroups(article_bytes)
        .ok_or_else(|| "missing Message-ID header".to_string())?;
    msgid_map
        .insert(&message_id, &cid)
        .await
        .map_err(|e| format!("msgid insert failed: {e}"))?;

    // 3. Append a log entry to each valid group.
    let sig_bytes = ctx.operator_signature.to_bytes().to_vec();

    let mut appended_groups: Vec<String> = Vec::new();
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
        if let Err(e) =
            usenet_ipfs_core::group_log::append::append(log_storage, &group, entry).await
        {
            tracing::warn!("log append failed for group {group_name_str}: {e}");
        } else {
            crate::metrics::ARTICLES_INGESTED_GROUP_TOTAL
                .with_label_values(&[group_name_str])
                .inc();
            appended_groups.push(group_name_str.clone());
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
    if let Some(tx) = ctx.gossip_tx {
        for group_name_str in &group_name_strs {
            // Build the advertisement using the existing TipAdvertisement type
            // so the wire format stays consistent with handle_tip_advertisement.
            let advert = TipAdvertisement {
                group_name: group_name_str.clone(),
                tip_cids: vec![cid.to_string()],
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

    Ok((
        PipelineResult {
            cid,
            groups: appended_groups,
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
        };
        let transit_pool = make_transit_pool().await;
        let result = run_pipeline(&article, &ipfs, &msgid_map, &storage, &transit_pool, ctx).await;
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
}
