//! Shared server-side storage handles for the NNTP POST pipeline and article
//! retrieval.
//!
//! `ServerStores` is constructed once at server startup and shared (via `Arc`)
//! across all sessions. It holds the in-process IPFS block store, the
//! message-id map, the group log, the article number store, the HLC clock,
//! and the operator signing key.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use multihash_codetable::{Code, MultihashDigest};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

use usenet_ipfs_core::group_log::MemLogStorage;
use usenet_ipfs_core::hlc::HlcClock;
use usenet_ipfs_core::msgid_map::MsgIdMap;
use usenet_ipfs_core::signing::{generate_signing_key, SigningKey};

use crate::post::ipfs_write::{IpfsBlockStore, MemIpfsStore, RustIpfsStore};
use crate::store::article_numbers::ArticleNumberStore;
use crate::store::credentials::CredentialStore;
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
    pub credential_store: Arc<CredentialStore>,
    /// HLC clock — shared across sessions, protected by a mutex.
    pub clock: Arc<Mutex<HlcClock>>,
    /// Operator signing key — ephemeral in-process key (no PEM file required).
    pub signing_key: Arc<SigningKey>,
}

impl ServerStores {
    /// Construct a `ServerStores` backed by a real `RustIpfsStore` in-process
    /// node, credential store from config, and in-memory SQLite databases.
    ///
    /// Returns `Err` if the IPFS node fails to start.
    pub async fn new_with_ipfs(config: &crate::config::Config) -> Result<Self, String> {
        let ipfs_store = RustIpfsStore::new()
            .await
            .map_err(|e| format!("IPFS node startup failed: {e}"))?;
        let reader_pool = make_pool_with_reader_migrations().await;
        let core_pool = make_pool_with_core_migrations().await;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let signing_key = load_or_generate_signing_key(&config.operator.signing_key_path)?;
        let node_id = hlc_node_id(&signing_key);

        Ok(Self {
            ipfs_store: Arc::new(ipfs_store),
            msgid_map: Arc::new(MsgIdMap::new(core_pool)),
            log_storage: Arc::new(MemLogStorage::new()),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            credential_store: Arc::new(build_credential_store(&config.auth)?),
            clock: Arc::new(Mutex::new(HlcClock::new(node_id, now_ms))),
            signing_key: Arc::new(signing_key),
        })
    }

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

        // Generate a fresh random key per test instance; derive node ID from it.
        let signing_key = generate_signing_key();
        let node_id = hlc_node_id(&signing_key);

        Self {
            ipfs_store: Arc::new(MemIpfsStore::new()),
            msgid_map: Arc::new(MsgIdMap::new(core_pool)),
            log_storage: Arc::new(MemLogStorage::new()),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            credential_store: Arc::new(CredentialStore::empty()),
            clock: Arc::new(Mutex::new(HlcClock::new(node_id, now_ms))),
            signing_key: Arc::new(signing_key),
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

/// Build a `CredentialStore` from the `[auth]` section of the config.
///
/// Loads inline `users` first, then merges any entries from `credential_file`
/// (file entries override inline entries with the same username).
fn build_credential_store(auth: &crate::config::AuthConfig) -> Result<CredentialStore, String> {
    let mut store = CredentialStore::from_credentials(&auth.users);
    if let Some(ref path) = auth.credential_file {
        store.merge_from_file(path)?;
    }
    Ok(store)
}

/// Load a 32-byte Ed25519 signing key from the given file path, or generate a
/// fresh random key if no path is configured.
///
/// If `path` is `None`, a random ephemeral key is generated and a warning is
/// emitted.  This is acceptable for development but insecure for production
/// because the signing key changes on every restart.
fn load_or_generate_signing_key(path: &Option<String>) -> Result<SigningKey, String> {
    match path {
        Some(p) => {
            let bytes = std::fs::read(p)
                .map_err(|e| format!("failed to read signing key from '{p}': {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "signing key file '{p}' must contain exactly 32 bytes, got {}",
                    bytes.len()
                ));
            }
            let arr: [u8; 32] = bytes.try_into().unwrap();
            Ok(SigningKey::from_bytes(&arr))
        }
        None => {
            let key = generate_signing_key();
            tracing::warn!(
                "no operator.signing_key_path configured — \
                 using an ephemeral signing key that changes on every restart; \
                 set [operator] signing_key_path in config for a stable production key"
            );
            Ok(key)
        }
    }
}

/// Derive the 8-byte HLC node ID from the operator signing key.
///
/// Uses the first 8 bytes of SHA-256(public_key) so the node ID is:
/// - Stable across restarts (as long as the key is the same).
/// - Unique per operator (Ed25519 key pairs are effectively unique).
/// - Not the key itself (exposing only a hash is fine; the public key is
///   already public, but this makes the derivation explicit).
fn hlc_node_id(signing_key: &SigningKey) -> [u8; 8] {
    let vk = signing_key.verifying_key();
    let digest = Code::Sha2_256.digest(vk.as_bytes());
    let mut node_id = [0u8; 8];
    node_id.copy_from_slice(&digest.digest()[..8]);
    node_id
}
