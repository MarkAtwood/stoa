//! Shared server-side storage handles for the NNTP POST pipeline and article
//! retrieval.
//!
//! `ServerStores` is constructed once at server startup and shared (via `Arc`)
//! across all sessions. It holds the in-process IPFS block store, the
//! message-id map, the group log, the article number store, the HLC clock,
//! and the operator signing key.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

use usenet_ipfs_core::group_log::MemLogStorage;
use usenet_ipfs_core::hlc::HlcClock;
use usenet_ipfs_core::msgid_map::MsgIdMap;
use usenet_ipfs_core::signing::SigningKey;

use crate::post::ipfs_write::{IpfsBlockStore, MemIpfsStore};
use crate::store::article_numbers::ArticleNumberStore;
use crate::store::overview::OverviewStore;

/// All storage handles needed by the POST pipeline and article retrieval.
///
/// Constructed once at startup and cloned (`Arc`) into each session task.
pub struct ServerStores {
    pub ipfs_store: Arc<dyn IpfsBlockStore>,
    pub msgid_map: Arc<MsgIdMap>,
    pub log_storage: Arc<MemLogStorage>,
    pub article_numbers: Arc<ArticleNumberStore>,
    pub overview_store: Arc<OverviewStore>,
    /// HLC clock — shared across sessions, protected by a mutex.
    pub clock: Arc<Mutex<HlcClock>>,
    /// Operator signing key — ephemeral in-process key (no PEM file required).
    pub signing_key: Arc<SigningKey>,
}

impl ServerStores {
    /// Construct an ephemeral `ServerStores` backed entirely by in-memory
    /// stores and in-memory SQLite databases.
    ///
    /// The reader-crate migrations (article_numbers) and core-crate migrations
    /// (msgid_map) use overlapping version numbers, so they run against
    /// separate pools.
    pub async fn new_mem() -> Self {
        let reader_pool = make_pool_with_reader_migrations().await;
        let core_pool = make_pool_with_core_migrations().await;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            ipfs_store: Arc::new(MemIpfsStore::new()),
            msgid_map: Arc::new(MsgIdMap::new(core_pool)),
            log_storage: Arc::new(MemLogStorage::new()),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            clock: Arc::new(Mutex::new(HlcClock::new([0x01u8; 8], now_ms))),
            signing_key: Arc::new(SigningKey::from_bytes(&[0x42u8; 32])),
        }
    }
}

/// Create a named shared in-memory SQLite pool with reader-crate migrations.
///
/// Uses `file:reader_stores_N?mode=memory&cache=shared` so all connections in
/// the pool share the same in-memory database (`:memory:` gives each connection
/// its own empty database, which loses the migrated schema on the next query).
async fn make_pool_with_reader_migrations() -> SqlitePool {
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("file:reader_stores_{n}?mode=memory&cache=shared");
    let opts = SqliteConnectOptions::new()
        .filename(&url)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("failed to create reader in-memory SQLite pool");
    crate::migrations::run_migrations(&pool)
        .await
        .expect("reader migrations failed on in-memory pool");
    pool
}

/// Create a named shared in-memory SQLite pool with core-crate migrations.
async fn make_pool_with_core_migrations() -> SqlitePool {
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("file:core_stores_{n}?mode=memory&cache=shared");
    let opts = SqliteConnectOptions::new()
        .filename(&url)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("failed to create core in-memory SQLite pool");
    usenet_ipfs_core::migrations::run_migrations(&pool)
        .await
        .expect("core migrations failed on in-memory pool");
    pool
}
