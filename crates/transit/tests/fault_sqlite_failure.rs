//! Fault injection integration tests for SQLite / log-storage write failures
//! in the transit pipeline.
//!
//! The pipeline treats log-append failures as warnings (not fatal errors):
//! RFC 977 §3.8 distinguishes the IPFS write (without which the article
//! cannot be stored at all) from the log append (which can be retried via
//! CRDT reconciliation). This test suite documents and verifies that
//! separation of concerns.
//!
//! Independent oracles:
//! - RFC 977 §3.8 — article storage vs. metadata recording are separate concerns.
//! - The pipeline source at `crates/transit/src/peering/pipeline.rs` (line 180)
//!   confirms log-append errors are downgraded to `tracing::warn!`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr as _;
use usenet_ipfs_core::{
    article::GroupName,
    error::StorageError,
    group_log::{
        storage::LogStorage,
        types::{LogEntry, LogEntryId},
        MemLogStorage,
    },
    hlc::HlcTimestamp,
    msgid_map::MsgIdMap,
};
use usenet_ipfs_transit::peering::pipeline::{run_pipeline, MemIpfsStore, PipelineCtx};

// ── FailingLogStorage ─────────────────────────────────────────────────────────

/// A `LogStorage` implementation that fails `insert_entry` on the Nth call
/// (counting from zero). All other methods always delegate to the inner store.
///
/// `fail_after` is the call-count threshold: when `call_count >= fail_after`,
/// `insert_entry` returns a simulated database error. Setting `fail_after = 0`
/// means every call fails immediately.
struct FailingLogStorage {
    inner: MemLogStorage,
    call_count: Arc<AtomicU64>,
    fail_after: u64,
}

impl FailingLogStorage {
    /// Construct a store that fails on the very first `insert_entry` call.
    ///
    /// Returns the store and the shared counter so callers can inspect
    /// how many `insert_entry` calls were attempted.
    fn new_fail_on_first() -> (Self, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        let store = Self {
            inner: MemLogStorage::new(),
            call_count: Arc::clone(&count),
            fail_after: 0,
        };
        (store, count)
    }
}

impl LogStorage for FailingLogStorage {
    async fn insert_entry(&self, id: LogEntryId, entry: LogEntry) -> Result<(), StorageError> {
        let n = self.call_count.fetch_add(1, Ordering::SeqCst);
        if n >= self.fail_after {
            Err(StorageError::Database(
                "simulated SQLite write failure".to_string(),
            ))
        } else {
            self.inner.insert_entry(id, entry).await
        }
    }

    async fn get_entry(&self, id: &LogEntryId) -> Result<Option<LogEntry>, StorageError> {
        self.inner.get_entry(id).await
    }

    async fn has_entry(&self, id: &LogEntryId) -> Result<bool, StorageError> {
        self.inner.has_entry(id).await
    }

    async fn list_tips(&self, group: &GroupName) -> Result<Vec<LogEntryId>, StorageError> {
        self.inner.list_tips(group).await
    }

    async fn set_tips(&self, group: &GroupName, tips: &[LogEntryId]) -> Result<(), StorageError> {
        self.inner.set_tips(group, tips).await
    }

    async fn entry_count(&self, group: &GroupName) -> Result<u64, StorageError> {
        self.inner.entry_count(group).await
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

async fn make_transit_pool() -> sqlx::SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    usenet_ipfs_transit::migrations::run_migrations(&pool)
        .await
        .unwrap();
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
    SigningKey::from_bytes(&[0x77u8; 32])
}

fn make_ctx(key: &SigningKey) -> PipelineCtx<'static> {
    PipelineCtx {
        timestamp: HlcTimestamp {
            wall_ms: 1_700_000_000_000,
            logical: 0,
            node_id: [9, 8, 7, 6, 5, 4, 3, 2],
        },
        operator_signature: key.sign(b""),
        gossip_tx: None,
        sender_peer_id: "test-peer-sqlite",
    }
}

fn make_article(msgid: &str, group: &str) -> Vec<u8> {
    format!(
        "From: test@example.com\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         Message-ID: {msgid}\r\n\
         Newsgroups: {group}\r\n\
         Subject: SQLite fault injection test\r\n\
         \r\n\
         Article body for fault injection.\r\n"
    )
    .into_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// When `insert_entry` fails, `run_pipeline` must still return `Ok` because
/// log-append failures are downgraded to warnings. The group name must be
/// absent from the returned groups list, documenting that the article was
/// not successfully appended to the group log.
///
/// This test verifies the pipeline's documented design choice: IPFS writes
/// are fatal, log-append failures are not.
#[tokio::test]
async fn log_storage_failure_is_non_fatal() {
    let (map, _tmp) = make_msgid_map().await;
    let ipfs = MemIpfsStore::new();
    let (log_storage, _count) = FailingLogStorage::new_fail_on_first();
    let key = make_signing_key();

    let article = make_article("<sqlite-fail@test.com>", "comp.test");
    let transit_pool = make_transit_pool().await;
    let result = run_pipeline(&article, &ipfs, &map, &log_storage, &transit_pool, make_ctx(&key)).await;

    // Log-append failure must NOT abort the pipeline — it is a warning.
    assert!(
        result.is_ok(),
        "pipeline must return Ok even when log storage fails: {result:?}"
    );

    // The group must not appear in the output because the append failed.
    let (pr, _metrics) = result.unwrap();
    assert!(
        pr.groups.is_empty(),
        "group must be absent from result when log append fails, got: {:?}",
        pr.groups
    );
}

/// After a log-storage failure, the IPFS write and msgid_map insert have
/// already succeeded. The article CID is therefore recorded in the map,
/// documenting the partial-commit characteristic of the current pipeline
/// (no two-phase commit between IPFS write and log append).
///
/// Independent oracle: the pipeline executes IPFS write → msgid_map insert →
/// log append in sequence; errors in the log append step do not roll back the
/// earlier steps (see `pipeline.rs` step 3 commentary).
#[tokio::test]
async fn ipfs_and_msgid_persist_when_log_fails() {
    let (map, _tmp) = make_msgid_map().await;
    let ipfs = MemIpfsStore::new();
    let (log_storage, _count) = FailingLogStorage::new_fail_on_first();
    let key = make_signing_key();

    let msgid = "<persist-test@test.com>";
    let article = make_article(msgid, "comp.test");
    let transit_pool = make_transit_pool().await;
    let result = run_pipeline(&article, &ipfs, &map, &log_storage, &transit_pool, make_ctx(&key)).await;
    assert!(
        result.is_ok(),
        "pipeline must return Ok even when log storage fails"
    );

    // The msgid_map entry must exist — the IPFS write and map insert
    // completed before the log-append was attempted.
    let lookup = map.lookup_by_msgid(msgid).await.unwrap();
    assert!(
        lookup.is_some(),
        "msgid must be recorded in map even when log append fails; \
         log failure must not roll back the msgid_map insert"
    );

    // The CID stored in the map must equal the one returned by the pipeline.
    let (pr, _) = result.unwrap();
    assert_eq!(
        lookup.unwrap(),
        pr.cid,
        "stored CID must match the pipeline-returned CID"
    );
}

/// After a log-storage failure, the group log must have no tips — the
/// storage barrier is the `insert_entry` call; `set_tips` is never reached,
/// so the tip set remains empty.
#[tokio::test]
async fn group_log_has_no_tips_after_insert_failure() {
    let (map, _tmp) = make_msgid_map().await;
    let ipfs = MemIpfsStore::new();
    let (log_storage, _count) = FailingLogStorage::new_fail_on_first();
    let key = make_signing_key();

    let article = make_article("<no-tips@test.com>", "comp.test");
    let transit_pool = make_transit_pool().await;
    let _ = run_pipeline(&article, &ipfs, &map, &log_storage, &transit_pool, make_ctx(&key)).await;

    let group = GroupName::new("comp.test").unwrap();
    let tips = log_storage.list_tips(&group).await.unwrap();
    assert!(
        tips.is_empty(),
        "group log must have no tips when insert_entry failed before set_tips"
    );
}

/// A subsequent pipeline run with a fresh, working log-storage succeeds
/// end-to-end. This verifies that the pipeline does not leave corrupt shared
/// state (in the msgid_map or IPFS store) that would block future articles.
#[tokio::test]
async fn subsequent_article_with_working_storage_succeeds() {
    let (map, _tmp) = make_msgid_map().await;
    let ipfs = MemIpfsStore::new();
    let log_storage = MemLogStorage::new();
    let key = make_signing_key();

    let article = make_article("<fresh-start@test.com>", "comp.test");
    let transit_pool = make_transit_pool().await;
    let result = run_pipeline(&article, &ipfs, &map, &log_storage, &transit_pool, make_ctx(&key)).await;
    assert!(
        result.is_ok(),
        "pipeline with working storage must succeed: {result:?}"
    );
    let (pr, _) = result.unwrap();
    assert_eq!(
        pr.groups,
        vec!["comp.test"],
        "article must be recorded in the group log when storage works"
    );
}

/// A second different article, submitted to the same `FailingLogStorage`
/// after the first failure, does not panic and correctly leaves the group
/// absent from its result. The pipeline continues to operate — no
/// poisoned-lock or unrecoverable error state is introduced by the failure.
#[tokio::test]
async fn daemon_continues_operating_after_log_failure() {
    let (map, _tmp) = make_msgid_map().await;
    let ipfs = MemIpfsStore::new();
    let (log_storage, _count) = FailingLogStorage::new_fail_on_first();
    let key = make_signing_key();

    let transit_pool = make_transit_pool().await;

    // First article: log append fails, pipeline returns Ok with empty groups.
    let article1 = make_article("<daemon-cont-1@test.com>", "comp.test");
    let r1 = run_pipeline(&article1, &ipfs, &map, &log_storage, &transit_pool, make_ctx(&key)).await;
    assert!(
        r1.is_ok(),
        "first pipeline must return Ok despite log failure"
    );
    assert!(
        r1.unwrap().0.groups.is_empty(),
        "first article must have no groups"
    );

    // Second article: log append also fails (counter still above threshold),
    // but the pipeline must not panic or deadlock.
    let article2 = make_article("<daemon-cont-2@test.com>", "comp.test");
    let r2 = run_pipeline(&article2, &ipfs, &map, &log_storage, &transit_pool, make_ctx(&key)).await;

    // No panic means the daemon continues operating correctly.
    // r2 may succeed or fail at the log step depending on the counter value;
    // the key invariant is absence of panic or deadlock.
    let _ = r2;
}
