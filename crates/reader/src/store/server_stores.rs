//! Shared server-side storage handles for the NNTP POST pipeline and article
//! retrieval.
//!
//! `ServerStores` is constructed once at server startup and shared (via `Arc`)
//! across all sessions. It holds the in-process IPFS block store, the
//! message-id map, the group log, the article number store, the HLC clock,
//! and the operator signing key.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

use usenet_ipfs_core::group_log::MemLogStorage;
use usenet_ipfs_core::hlc::HlcClock;
use usenet_ipfs_core::msgid_map::MsgIdMap;
use usenet_ipfs_core::signing::{generate_signing_key, hlc_node_id, SigningKey};

use mail_auth::MessageAuthenticator;
use usenet_ipfs_auth::TrustedIssuerStore;
use usenet_ipfs_smtp::SmtpRelayQueue;
use usenet_ipfs_verify::VerificationStore;

use crate::post::ipfs_write::{IpfsBlockStore, KuboBlockStore, MemIpfsStore};
use crate::search::TantivySearchIndex;
use crate::store::article_numbers::ArticleNumberStore;
use crate::store::client_cert_store::ClientCertStore;
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
    /// Client certificate fingerprint → username store for TLS cert-based auth.
    pub client_cert_store: Arc<ClientCertStore>,
    /// Trusted CA issuer store for issuer-chain certificate auth.
    ///
    /// Consulted after fingerprint-based auth fails: if the leaf cert was
    /// signed by a configured CA and the CN matches the requested username,
    /// the session is authenticated without a password.
    pub trusted_issuer_store: Arc<TrustedIssuerStore>,
    /// HLC clock — shared across sessions, protected by a mutex.
    pub clock: Arc<Mutex<HlcClock>>,
    /// Operator signing key — ephemeral in-process key (no PEM file required).
    pub signing_key: Arc<SigningKey>,
    /// Full-text search index (Tantivy-backed). None when search is disabled.
    pub search_index: Option<Arc<TantivySearchIndex>>,
    /// Outbound SMTP relay queue. None when smtp_relay is not configured.
    pub smtp_relay_queue: Option<Arc<SmtpRelayQueue>>,
    /// Article signature verification store (article_verifications + seen_keys).
    pub verification_store: Arc<VerificationStore>,
    /// DKIM verifier backed by system DNS resolver.
    pub dkim_authenticator: Arc<MessageAuthenticator>,
}

impl ServerStores {
    /// Construct a `ServerStores` backed by a `KuboBlockStore` (Kubo HTTP RPC)
    /// with optional local FS cache, credential store from config, and on-disk
    /// SQLite databases with WAL mode.
    ///
    /// Database parent directories are created at startup if they do not exist.
    pub async fn new_with_ipfs(config: &crate::config::Config) -> Result<Self, String> {
        let cache_dir = config
            .ipfs
            .cache_path
            .as_deref()
            .map(std::path::PathBuf::from);
        if let Some(ref dir) = cache_dir {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|e| format!("failed to create IPFS cache dir '{}': {e}", dir.display()))?;
        }
        let ipfs_store = KuboBlockStore::new(&config.ipfs.api_url, cache_dir);

        // Ensure database parent directories exist before opening pools.
        for path_str in [
            &config.database.reader_path,
            &config.database.core_path,
            &config.database.verify_path,
        ] {
            let p = std::path::Path::new(path_str.as_str());
            if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "cannot create database directory '{}': {e}",
                        parent.display()
                    )
                })?;
            }
        }

        let reader_pool = make_disk_pool_with_reader_migrations(&config.database.reader_path).await?;
        let core_pool = make_disk_pool_with_core_migrations(&config.database.core_path).await?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let signing_key = load_or_generate_signing_key(&config.operator.signing_key_path)?;
        let node_id = hlc_node_id(&signing_key);

        let trusted_issuer_store = build_trusted_issuer_store(&config.auth.trusted_issuers)?;

        let smtp_relay_queue = build_smtp_relay_queue(&config.smtp_relay)
            .map_err(|e| format!("smtp relay queue init failed: {e}"))?;

        let verify_pool = make_disk_pool_with_verify_migrations(&config.database.verify_path).await?;
        let dkim_authenticator = MessageAuthenticator::new_cloudflare_tls()
            .map_err(|e| format!("DKIM authenticator init failed: {e}"))?;

        Ok(Self {
            ipfs_store: Arc::new(ipfs_store),
            msgid_map: Arc::new(MsgIdMap::new(core_pool)),
            log_storage: Arc::new(MemLogStorage::new()),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            credential_store: Arc::new(build_credential_store(&config.auth)?),
            client_cert_store: Arc::new(ClientCertStore::from_config(&config.auth.client_certs)),
            trusted_issuer_store: Arc::new(trusted_issuer_store),
            clock: Arc::new(Mutex::new(HlcClock::new(node_id, now_ms))),
            signing_key: Arc::new(signing_key),
            search_index: TantivySearchIndex::open(&config.search)
                .map_err(|e| format!("search index init failed: {e}"))?
                .map(Arc::new),
            smtp_relay_queue,
            verification_store: Arc::new(VerificationStore::new(verify_pool)),
            dkim_authenticator: Arc::new(dkim_authenticator),
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

        let verify_pool = make_pool_with_verify_migrations().await;
        Self {
            ipfs_store: Arc::new(MemIpfsStore::new()),
            msgid_map: Arc::new(MsgIdMap::new(core_pool)),
            log_storage: Arc::new(MemLogStorage::new()),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            credential_store: Arc::new(CredentialStore::empty()),
            client_cert_store: Arc::new(ClientCertStore::empty()),
            trusted_issuer_store: Arc::new(TrustedIssuerStore::empty()),
            clock: Arc::new(Mutex::new(HlcClock::new(node_id, now_ms))),
            signing_key: Arc::new(signing_key),
            search_index: {
                let cfg = crate::config::SearchConfig::default();
                Some(Arc::new(
                    TantivySearchIndex::open_in_memory(&cfg)
                        .expect("in-memory tantivy index cannot fail"),
                ))
            },
            smtp_relay_queue: None,
            verification_store: Arc::new(VerificationStore::new(verify_pool)),
            dkim_authenticator: Arc::new(
                MessageAuthenticator::new_cloudflare_tls()
                    .expect("DKIM authenticator init must not fail"),
            ),
        }
    }

    /// Identical to `new_mem` but with `search_index: None`, for testing
    /// the 503 code path when search is disabled.
    #[cfg(test)]
    pub async fn new_mem_no_search() -> Self {
        let reader_pool = make_pool_with_reader_migrations().await;
        let core_pool = make_pool_with_core_migrations().await;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let signing_key = generate_signing_key();
        let node_id = hlc_node_id(&signing_key);

        let verify_pool = make_pool_with_verify_migrations().await;
        Self {
            ipfs_store: Arc::new(MemIpfsStore::new()),
            msgid_map: Arc::new(MsgIdMap::new(core_pool)),
            log_storage: Arc::new(MemLogStorage::new()),
            article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
            overview_store: Arc::new(OverviewStore::new(reader_pool)),
            credential_store: Arc::new(CredentialStore::empty()),
            client_cert_store: Arc::new(ClientCertStore::empty()),
            trusted_issuer_store: Arc::new(TrustedIssuerStore::empty()),
            clock: Arc::new(Mutex::new(HlcClock::new(node_id, now_ms))),
            signing_key: Arc::new(signing_key),
            search_index: None,
            smtp_relay_queue: None,
            verification_store: Arc::new(VerificationStore::new(verify_pool)),
            dkim_authenticator: Arc::new(
                MessageAuthenticator::new_cloudflare_tls()
                    .expect("DKIM authenticator init must not fail"),
            ),
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

/// Create a named shared in-memory SQLite pool with verify-crate migrations.
async fn make_pool_with_verify_migrations() -> SqlitePool {
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("file:verify_stores_{n}?mode=memory&cache=shared");
    let opts = SqliteConnectOptions::new()
        .filename(&url)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("failed to create verify in-memory SQLite pool");
    usenet_ipfs_verify::run_migrations(&pool)
        .await
        .expect("verify migrations failed on in-memory pool");
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

/// Open an on-disk SQLite pool with WAL mode and reader-crate migrations.
async fn make_disk_pool_with_reader_migrations(path: &str) -> Result<SqlitePool, String> {
    let url = format!("sqlite://{path}");
    let opts = SqliteConnectOptions::from_str(&url)
        .map_err(|e| format!("invalid reader database path '{path}': {e}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .map_err(|e| format!("failed to open reader database '{path}': {e}"))?;
    crate::migrations::run_migrations(&pool)
        .await
        .map_err(|e| format!("reader database migration failed: {e}"))?;
    Ok(pool)
}

/// Open an on-disk SQLite pool with WAL mode and core-crate migrations.
async fn make_disk_pool_with_core_migrations(path: &str) -> Result<SqlitePool, String> {
    let url = format!("sqlite://{path}");
    let opts = SqliteConnectOptions::from_str(&url)
        .map_err(|e| format!("invalid core database path '{path}': {e}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .map_err(|e| format!("failed to open core database '{path}': {e}"))?;
    usenet_ipfs_core::migrations::run_migrations(&pool)
        .await
        .map_err(|e| format!("core database migration failed: {e}"))?;
    Ok(pool)
}

/// Open an on-disk SQLite pool with WAL mode and verify-crate migrations.
async fn make_disk_pool_with_verify_migrations(path: &str) -> Result<SqlitePool, String> {
    let url = format!("sqlite://{path}");
    let opts = SqliteConnectOptions::from_str(&url)
        .map_err(|e| format!("invalid verify database path '{path}': {e}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .map_err(|e| format!("failed to open verify database '{path}': {e}"))?;
    usenet_ipfs_verify::run_migrations(&pool)
        .await
        .map_err(|e| format!("verify database migration failed: {e}"))?;
    Ok(pool)
}

/// Build a `TrustedIssuerStore` from the reader's `[auth]` trusted_issuers list.
///
/// Converts the reader's local `TrustedIssuerEntry` type to the auth crate's
/// type, then delegates to `TrustedIssuerStore::from_config`.
fn build_trusted_issuer_store(
    entries: &[crate::config::TrustedIssuerEntry],
) -> Result<TrustedIssuerStore, String> {
    let auth_entries: Vec<usenet_ipfs_auth::TrustedIssuerEntry> = entries
        .iter()
        .map(|e| usenet_ipfs_auth::TrustedIssuerEntry {
            cert_path: e.cert_path.clone(),
        })
        .collect();
    TrustedIssuerStore::from_config(&auth_entries)
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
            usenet_ipfs_core::signing::load_signing_key(std::path::Path::new(p))
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

/// Construct a `SmtpRelayQueue` from the reader's `[smtp_relay]` config section.
///
/// Returns `None` when `queue_dir` is absent or `peers` is empty — both
/// conditions disable relay.  Returns `Err` only if the queue directory
/// cannot be created.
fn build_smtp_relay_queue(
    cfg: &crate::config::SmtpRelayConfig,
) -> std::io::Result<Option<Arc<SmtpRelayQueue>>> {
    let queue_dir = match cfg.queue_dir.as_deref() {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(None),
    };
    if cfg.peers.is_empty() {
        return Ok(None);
    }
    let down_backoff = std::time::Duration::from_secs(cfg.peer_down_secs);
    let queue = SmtpRelayQueue::new(queue_dir, cfg.peers.clone(), down_backoff)?;
    Ok(Some(queue))
}

