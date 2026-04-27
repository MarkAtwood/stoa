use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::MessageAuthenticator;
use rand_core::OsRng;
use stoa_core::{
    audit::{start_audit_logger, AuditLogger},
    group_log::SqliteLogStorage,
    hlc::HlcClock,
    msgid_map::MsgIdMap,
    wildmat::GroupFilter,
};
use stoa_transit::{
    admin::{start_admin_server, AdminPools},
    config::{check_admin_addr, Config},
    hlc_persist::{load_hlc_checkpoint, save_hlc_checkpoint},
    peering::{
        auth::parse_trusted_peer_keys,
        blacklist::BlacklistConfig,
        ingestion_queue::ingestion_queue,
        pipeline::{run_pipeline, IpfsStore, PipelineCtx},
        rate_limit::{ExhaustionAction, PeerRateLimiter},
        session::{run_peering_session, PeeringShared},
    },
    retention::{
        ipns_publisher::{IpnsEvent, IpnsPublisher},
        remote_pin_worker::RemotePinWorker,
    },
    staging::StagingStore,
};
use stoa_verify::VerificationStore;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{error, info, warn};

fn parse_args() -> (PathBuf, bool) {
    let args: Vec<String> = std::env::args().collect();

    // Subcommand dispatch: `stoa-transit keygen --output <path> [--force]`
    if args.get(1).map(|s| s.as_str()) == Some("keygen") {
        cmd_keygen(&args[2..]);
    }

    let mut config_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                if let Some(path) = args.get(i + 1) {
                    config_path = Some(PathBuf::from(path));
                    i += 2;
                } else {
                    eprintln!("error: --config requires a path argument");
                    std::process::exit(1);
                }
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    match config_path {
        Some(p) => (p, check_only),
        None => {
            eprintln!("error: --config <path> is required");
            std::process::exit(1);
        }
    }
}

/// Handle `stoa-transit keygen --output <path> [--force]`.
///
/// Generates a random 32-byte Ed25519 seed, writes it to `<path>` (mode 0600),
/// and prints the public key hex + HLC node ID to stdout.  Exits 0 on success,
/// 1 on any error.  Never returns — always calls `std::process::exit`.
fn cmd_keygen(args: &[String]) -> ! {
    let mut output: Option<&str> = None;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                output = args.get(i + 1).map(|s| s.as_str());
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => {
                eprintln!("error: unknown keygen argument: {other}");
                std::process::exit(1);
            }
        }
    }
    let output_path = match output {
        Some(p) => std::path::Path::new(p),
        None => {
            eprintln!("error: keygen requires --output <path>");
            std::process::exit(1);
        }
    };
    let key = stoa_core::signing::generate_signing_key();
    if let Err(e) = stoa_core::signing::write_signing_key(&key, output_path, force) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
    let node_id = stoa_core::signing::hlc_node_id(&key);
    let node_id_hex = hex::encode(node_id);
    println!("public_key: {pubkey_hex}");
    println!("node_id:    {node_id_hex}");
    println!("key_file:   {}", output_path.display());
    std::process::exit(0);
}

async fn run_startup_checks(config: &stoa_transit::config::Config) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    // Kubo reachability check (skipped for non-Kubo backends).
    if let Some(url) = config.kubo_api_url() {
        let url = url.to_owned();
        let client = stoa_core::ipfs::KuboHttpClient::new(&url);
        match tokio::time::timeout(Duration::from_secs(5), client.node_id()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                errors.push(format!(
                    "Kubo unreachable at {url}: {e} — is 'ipfs daemon' running?"
                ));
            }
            Err(_) => {
                errors.push(format!(
                    "Kubo unreachable at {url}: timed out after 5s — is 'ipfs daemon' running?"
                ));
            }
        }
    }

    // TLS file readability check.
    if let Some(ref tls_cfg) = config.tls {
        if let Err(e) = std::fs::read(&tls_cfg.cert_path) {
            errors.push(format!("TLS file unreadable: {}: {e}", tls_cfg.cert_path));
        }
        // For secretx: URIs, validate URI syntax here; resolution happens at startup.
        if tls_cfg.key_path.starts_with("secretx:") {
            if let Err(e) = secretx::from_uri(&tls_cfg.key_path) {
                errors.push(format!("tls.key_path: invalid secretx URI: {e}"));
            }
        } else if let Err(e) = std::fs::read(&tls_cfg.key_path) {
            errors.push(format!("TLS file unreadable: {}: {e}", tls_cfg.key_path));
        }
    }

    // Signing key check.
    if let Some(ref path) = config.operator.signing_key_path {
        if path.starts_with("secretx:") {
            // Validate URI syntax; retrieval and byte validation happen at load time.
            if let Err(e) = secretx::from_uri(path) {
                errors.push(format!(
                    "operator.signing_key_path: invalid secretx URI: {e}"
                ));
            }
        } else if let Err(e) = stoa_core::signing::load_signing_key(std::path::Path::new(path)) {
            errors.push(e.to_string());
        }
    }

    // Validate secretx URI syntax for remaining string secrets.
    if let Some(ref tok) = config.admin.bearer_token {
        if tok.starts_with("secretx:") {
            if let Err(e) = secretx::from_uri(tok) {
                errors.push(format!("admin.bearer_token: invalid secretx URI: {e}"));
            }
        }
    }
    for svc in &config.pinning.external_services {
        if let Err(e) = svc.api_key.validate_uri_syntax() {
            errors.push(format!(
                "pinning.external_services[{}].api_key: invalid secretx URI: {e}",
                svc.name
            ));
        }
    }

    // Admin bind address check.
    match TcpListener::bind(&config.admin.addr).await {
        Ok(_) => {}
        Err(e) => {
            errors.push(format!(
                "Admin address {} already in use or invalid: {e}",
                config.admin.addr
            ));
        }
    }

    errors
}

/// Notify the IPNS publisher of the new article tip for each group.
///
/// Called from both the ingestion drain and the staging drain after a
/// successful `run_pipeline` to avoid duplicating the channel-send loop.
fn publish_ipns_tip(
    result: &stoa_transit::peering::pipeline::PipelineResult,
    ipns_tx: &Option<tokio::sync::mpsc::Sender<IpnsEvent>>,
) {
    if let Some(ref tx) = ipns_tx {
        for group in &result.groups {
            let event = IpnsEvent {
                group: group.clone(),
                cid: result.cid,
            };
            if let Err(e) = tx.try_send(event) {
                warn!(group, "IPNS channel full, skipping publish: {e}");
            }
        }
    }
}

/// Enqueue successfully stored articles for external pinning services.
///
/// Called from both the ingestion drain and the staging drain after a
/// successful `run_pipeline` to avoid duplicating the SQL insert loop.
async fn enqueue_pin_jobs(
    result: &stoa_transit::peering::pipeline::PipelineResult,
    pin_service_filters: &[(String, Option<Arc<GroupFilter>>)],
    pool: &sqlx::SqlitePool,
) {
    if pin_service_filters.is_empty() {
        return;
    }
    let cid_str = result.cid.to_string();
    for (svc_name, filter) in pin_service_filters {
        let should_pin = match filter {
            None => true,
            Some(f) => result.groups.iter().any(|g| f.accepts(g)),
        };
        if should_pin {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO remote_pin_jobs \
                 (cid, service_name) VALUES (?1, ?2)",
            )
            .bind(&cid_str)
            .bind(svc_name)
            .execute(pool)
            .await
            {
                warn!(
                    cid = %cid_str,
                    service = %svc_name,
                    "failed to enqueue remote pin job: {e}"
                );
            }
        }
    }
}

/// Run `run_pipeline`, emit structured telemetry, and drive post-success hooks
/// (IPNS publish + remote pin enqueue).  Common to the ingestion drain and the
/// staging drain; the only difference is the success log message.
///
/// Returns `true` on success, `false` on pipeline error (already logged).
#[allow(clippy::too_many_arguments)]
async fn run_pipeline_and_notify(
    bytes: &[u8],
    message_id: &str,
    success_label: &'static str,
    hlc: &tokio::sync::Mutex<HlcClock>,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    local_hostname: &str,
    verify_store: Option<&VerificationStore>,
    trusted_keys: &[ed25519_dalek::VerifyingKey],
    dkim_auth: Option<&MessageAuthenticator>,
    group_filter: Option<Arc<GroupFilter>>,
    ipfs: &dyn IpfsStore,
    msgid_map: &MsgIdMap,
    log_storage: &SqliteLogStorage,
    transit_pool: &sqlx::SqlitePool,
    ipns_tx: &Option<tokio::sync::mpsc::Sender<IpnsEvent>>,
    pin_service_filters: &[(String, Option<Arc<GroupFilter>>)],
) -> bool {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let timestamp = hlc.lock().await.send(now_ms);
    let ctx = PipelineCtx {
        timestamp,
        operator_signing_key: signing_key,
        local_hostname,
        verify_store,
        trusted_keys,
        dkim_auth,
        group_filter,
    };
    match run_pipeline(bytes, ipfs, msgid_map, log_storage, transit_pool, ctx).await {
        Ok((result, _metrics)) => {
            info!(
                cid = %result.cid,
                groups = ?result.groups,
                msgid = %message_id,
                "{success_label}",
            );
            publish_ipns_tip(&result, ipns_tx);
            enqueue_pin_jobs(&result, pin_service_filters, transit_pool).await;
            true
        }
        Err(e) => {
            warn!(msgid = %message_id, "pipeline failed: {e}");
            false
        }
    }
}

#[tokio::main]
async fn main() {
    let start_time = Instant::now();
    let (config_path, check_only) = parse_args();

    let mut config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: failed to load config from {}: {}",
                config_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log.level));

    if config.log.format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let check_errors = run_startup_checks(&config).await;
    if !check_errors.is_empty() {
        for msg in &check_errors {
            eprintln!("error: {msg}");
        }
        std::process::exit(1);
    }
    if check_only {
        println!("startup checks passed");
        std::process::exit(0);
    }

    // Build group filter from config. Empty names list means accept all groups.
    let group_filter: Option<Arc<GroupFilter>> = if config.groups.names.is_empty() {
        None
    } else {
        Some(Arc::new(
            GroupFilter::new(&config.groups.names)
                .expect("config already validated group patterns"),
        ))
    };

    info!(
        listen_addr = %config.listen.addr,
        peer_count = config.peers.addresses.len() + config.peers.peer.len(),
        group_count = config.groups.names.len(),
        "stoa-transit starting"
    );
    if !config.groups.names.is_empty() {
        info!(
            patterns = %config.groups.names.join(", "),
            "group filter active: accepting articles matching configured patterns"
        );
    } else {
        info!("group filter inactive: accepting articles from all groups");
    }

    if let Err(e) = check_admin_addr(&config.admin) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    // ── SQLite databases (two separate pools: core schema + transit schema) ───

    let core_pool =
        Arc::new(open_pool(&config.database.core_path, config.database.pool_size).await);
    if let Err(e) = stoa_core::migrations::run_migrations(&core_pool).await {
        eprintln!("error: core database migration failed: {e}");
        std::process::exit(1);
    }
    let msgid_map = Arc::new(MsgIdMap::new((*core_pool).clone()));
    let log_storage = Arc::new(SqliteLogStorage::new((*core_pool).clone()));

    let transit_pool = Arc::new(open_pool(&config.database.path, config.database.pool_size).await);
    if let Err(e) = stoa_transit::migrations::run_migrations(&transit_pool).await {
        eprintln!("error: transit database migration failed: {e}");
        std::process::exit(1);
    }

    // ── Verify pool (separate schema; no version conflicts with transit) ───────

    let verify_pool = open_pool(&config.database.verify_path, config.database.pool_size).await;
    if let Err(e) = stoa_verify::run_migrations(&verify_pool).await {
        eprintln!("error: verify database migration failed: {e}");
        std::process::exit(1);
    }
    let verification_store = Arc::new(VerificationStore::new(verify_pool));

    let dkim_authenticator = match MessageAuthenticator::new_cloudflare_tls() {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("error: DKIM authenticator init failed: {e}");
            std::process::exit(1);
        }
    };

    // ── Remote pinning worker ─────────────────────────────────────────────────

    // Resolve any secretx: URIs in pinning service API keys before the worker starts.
    for svc in config.pinning.external_services.iter_mut() {
        let label = format!("pinning.external_services[{}].api_key", svc.name);
        svc.api_key = svc.api_key.clone().resolve(&label).await;
    }

    if !config.pinning.external_services.is_empty() {
        match RemotePinWorker::from_config(
            (*transit_pool).clone(),
            &config.pinning.external_services,
        ) {
            Ok(worker) => {
                info!(
                    services = config.pinning.external_services.len(),
                    "remote pin worker started"
                );
                tokio::spawn(worker.run());
            }
            Err(e) => {
                eprintln!("error: failed to build remote pin worker: {e}");
                std::process::exit(1);
            }
        }
    }

    // ── IPFS block store ──────────────────────────────────────────────────────

    let build_result = match stoa_transit::peering::pipeline::build_store(&config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to build IPFS store: {e}");
            std::process::exit(1);
        }
    };
    if let Some(url) = config.kubo_api_url() {
        info!(api_url = %url, "connecting to Kubo IPFS node");
    }
    // Extract the Kubo client before boxing so the IPNS publisher can use it.
    let kubo_client_for_ipns = if config.ipns.enabled {
        build_result.kubo_client
    } else {
        None
    };
    let mut ipfs_store: Arc<dyn stoa_transit::peering::pipeline::IpfsStore> = build_result.store;

    // ── Block cache (optional) ─────────────────────────────────────────────────

    if let Some(cache_cfg) = config.cache.take() {
        match tokio::fs::create_dir_all(&cache_cfg.path).await {
            Ok(()) => {
                info!(path = %cache_cfg.path, "block cache directory ready");
                ipfs_store = Arc::new(stoa_transit::block_cache::BlockCache::new(
                    cache_cfg,
                    Arc::clone(&transit_pool),
                    ipfs_store,
                ));
            }
            Err(e) => {
                eprintln!("error: could not create block cache directory: {e}");
                std::process::exit(1);
            }
        }
    }

    // ── IPNS channel ──────────────────────────────────────────────────────────

    let ipns_tx: Option<tokio::sync::mpsc::Sender<IpnsEvent>> = if config.ipns.enabled {
        let (tx, rx) = tokio::sync::mpsc::channel::<IpnsEvent>(256);
        let client = kubo_client_for_ipns
            .clone()
            .expect("kubo_client_for_ipns set when enabled");
        let interval = config.ipns.republish_interval_secs;
        tokio::spawn(IpnsPublisher::new(client, interval).run(rx));
        info!(
            "IPNS publishing enabled (interval {}s)",
            config.ipns.republish_interval_secs
        );
        Some(tx)
    } else {
        None
    };

    // Derive the IPNS path string (/ipns/<peer_id>) for the admin endpoint.
    // Only set when IPNS is enabled; the admin /ipns endpoint returns null otherwise.
    let ipns_path_string: Option<String> = if let Some(ref client) = kubo_client_for_ipns {
        match client.node_id().await {
            Ok(peer_id) => {
                let path = format!("/ipns/{peer_id}");
                info!(ipns_path = %path, "IPNS address ready");
                Some(path)
            }
            Err(e) => {
                warn!("IPNS: failed to get Kubo node peer identity: {e}");
                None
            }
        }
    } else {
        None
    };

    // ── Operator signing key ──────────────────────────────────────────────────

    // DECISION (rbe3.35): signing key required for non-loopback listeners
    //
    // An ephemeral key (generated at startup, not saved) changes on every
    // restart, breaking X-Stoa-Sig verification for peers that cached the
    // operator's public key.  Loopback-only deployments (dev/test mode) are
    // permitted to use ephemeral keys with a warn-level log; production
    // deployments that accept external peering connections must supply a
    // persistent key file so that signatures remain verifiable across restarts.
    // Do NOT remove this check for non-loopback listeners.
    // Enforce signing_key_path for non-loopback deployments (zn0k).
    if config.operator.signing_key_path.is_none()
        && !stoa_transit::config::is_loopback_addr(&config.listen.addr)
    {
        eprintln!(
            "error: operator.signing_key_path must be set when listening on a non-loopback \
             address ({}). Run `stoa-transit keygen --output <path>` to generate \
             a key, then set [operator] signing_key_path in your config.",
            config.listen.addr
        );
        std::process::exit(1);
    }

    let signing_key = Arc::new(match &config.operator.signing_key_path {
        Some(path) if path.starts_with("secretx:") => {
            let store = match secretx::from_uri(path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: operator.signing_key_path: invalid secretx URI: {e}");
                    std::process::exit(1);
                }
            };
            let secret = match store.get().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: operator.signing_key_path: secretx retrieval failed: {e}");
                    std::process::exit(1);
                }
            };
            match stoa_core::signing::load_signing_key_from_bytes(secret.as_bytes()) {
                Ok(k) => {
                    info!(path, "loaded operator signing key via secretx");
                    k
                }
                Err(e) => {
                    eprintln!("error: operator.signing_key_path: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(path) => match stoa_core::signing::load_signing_key(std::path::Path::new(path)) {
            Ok(k) => {
                info!(path, "loaded operator signing key");
                k
            }
            Err(e) => {
                eprintln!("error: cannot load operator signing key from '{path}': {e}");
                std::process::exit(1);
            }
        },
        None => {
            warn!(
                "operator.signing_key_path not set — using ephemeral key; \
                 article signatures will not survive restart"
            );
            ed25519_dalek::SigningKey::generate(&mut OsRng)
        }
    });

    // ── Trusted peer keys ─────────────────────────────────────────────────────

    let trusted_keys = parse_trusted_peer_keys(&config.peering.trusted_peers).unwrap_or_else(|e| {
        error!(
            "invalid trusted_peers key in config: {e} — \
             peering auth is a security control; startup aborted"
        );
        std::process::exit(1);
    });

    // ── HLC clock and ingestion queue ─────────────────────────────────────────

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // Derive node_id from SHA-256 of the operator signing key's public bytes.
    // Using the public key (not the libp2p peer_id) ensures the node_id is
    // stable across restarts as long as the operator key file is unchanged,
    // and is globally unique assuming Ed25519 keys are not reused across
    // distinct operators.
    let node_id = {
        use sha2::{Digest, Sha256};
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        let hash = Sha256::digest(pubkey_bytes);
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[..8]);
        id
    };
    // DECISION (rbe3.34): HLC checkpoint persisted across restarts for monotone timestamps
    //
    // Without persistence, a server restart resets the HLC logical counter to 0.
    // If the wall-clock millisecond at restart equals the last emitted timestamp's
    // wall millisecond, the new timestamp would collide with or regress below a
    // previous one, violating the HLC ordering guarantee that the Merkle-CRDT
    // group log depends on for causal consistency.  Loading the checkpoint and
    // seeding the clock ensures the first post-restart timestamp is strictly
    // greater than any previously emitted one.
    // Do NOT remove the checkpoint load; do NOT seed the clock with zero on startup.
    // Load persisted HLC checkpoint so the first send() after restart is
    // strictly greater than any previously emitted timestamp (usenet-ipfs-gq0z).
    let hlc = {
        let clock = match load_hlc_checkpoint(&transit_pool).await {
            Ok(Some(checkpoint)) => {
                info!(
                    wall_ms = checkpoint.wall_ms,
                    logical = checkpoint.logical,
                    "loaded HLC checkpoint"
                );
                HlcClock::new_seeded(node_id, now_ms, checkpoint)
            }
            Ok(None) => {
                info!("no HLC checkpoint found; starting from wall clock");
                HlcClock::new(node_id, now_ms)
            }
            Err(e) => {
                warn!("failed to load HLC checkpoint: {e}; starting from wall clock");
                HlcClock::new(node_id, now_ms)
            }
        };
        Arc::new(Mutex::new(clock))
    };

    // Background task: persist the HLC state every 30 seconds so that after a
    // restart the clock continues above the last emitted timestamp.
    {
        let hlc_bg = Arc::clone(&hlc);
        let pool_bg = transit_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let ts = hlc_bg.lock().await.last_timestamp();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                if let Err(e) = save_hlc_checkpoint(&pool_bg, ts, now).await {
                    warn!("HLC checkpoint save failed: {e}");
                }
            }
        });
    }

    let (ingestion_sender, mut ingestion_receiver) =
        ingestion_queue(config.peering.ingestion_queue_capacity);
    let ingestion_sender = Arc::new(ingestion_sender);

    // ── Local hostname for Path: header (Son-of-RFC-1036 §3.3) ───────────────

    let local_hostname: String = config
        .operator
        .hostname
        .clone()
        .unwrap_or_else(resolve_local_hostname);
    info!(hostname = %local_hostname, "local hostname for Path: header");

    // ── Optional TLS acceptor for inbound peering ─────────────────────────────

    let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> = if let Some(ref tls_cfg) = config.tls
    {
        let server_config_result = if tls_cfg.key_path.starts_with("secretx:") {
            let store = match secretx::from_uri(&tls_cfg.key_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: tls.key_path: invalid secretx URI: {e}");
                    std::process::exit(1);
                }
            };
            let secret = match store.get().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: tls.key_path: secretx retrieval failed: {e}");
                    std::process::exit(1);
                }
            };
            stoa_tls::load_tls_server_config_with_key_bytes(
                &tls_cfg.cert_path,
                secret.as_bytes(),
                &tls_cfg.key_path,
            )
        } else {
            stoa_tls::load_tls_server_config(&tls_cfg.cert_path, &tls_cfg.key_path)
        };
        match server_config_result {
            Ok(server_config) => {
                info!("peering TLS enabled");
                Some(Arc::new(tokio_rustls::TlsAcceptor::from(server_config)))
            }
            Err(e) => {
                eprintln!("error: failed to load peering TLS config: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // ── Write-ahead staging area (optional) ───────────────────────────────────

    let staging_store: Option<Arc<StagingStore>> = if let Some(staging_cfg) = config.staging {
        match tokio::fs::create_dir_all(&staging_cfg.path).await {
            Ok(()) => {
                info!(path = %staging_cfg.path, "write-ahead staging directory ready");
                Some(Arc::new(StagingStore::new(
                    staging_cfg,
                    Arc::clone(&transit_pool),
                )))
            }
            Err(e) => {
                eprintln!("error: could not create staging directory: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // ── Shared state for peering sessions ─────────────────────────────────────

    let shared = Arc::new(PeeringShared {
        ipfs: Arc::clone(&ipfs_store),
        msgid_map: Arc::clone(&msgid_map),
        signing_key: Arc::clone(&signing_key),
        hlc: Arc::clone(&hlc),
        ingestion_sender: Arc::clone(&ingestion_sender),
        local_hostname: local_hostname.clone(),
        // Per-IP rate limiter: all connections from one host share this budget.
        peer_rate_limiter: Arc::new(std::sync::Mutex::new(PeerRateLimiter::new(
            config.peering.rate_limit_rps,
            config.peering.rate_limit_burst,
            ExhaustionAction::Respond431,
        ))),
        transit_pool: Arc::clone(&transit_pool),
        blacklist_config: BlacklistConfig::default(),
        trusted_keys,
        tls_acceptor,
        staging: staging_store.clone(),
        verification_store: Some(Arc::clone(&verification_store)),
        dkim_authenticator: Some(Arc::clone(&dkim_authenticator)),
    });

    // ── Pipeline drain task ───────────────────────────────────────────────────

    // Extract (service_name, filter) pairs for the pipeline hook.
    // Avoids moving the full config (with PinningApiKey) into the async closure.
    // GroupFilter patterns were validated in Config::validate(), so expect() cannot fail.
    let pin_service_filters: Vec<(String, Option<Arc<GroupFilter>>)> = config
        .pinning
        .external_services
        .iter()
        .map(|svc| {
            let filter = if svc.groups.is_empty() {
                None
            } else {
                Some(Arc::new(GroupFilter::new(&svc.groups).expect(
                    "config already validated pin service group patterns",
                )))
            };
            (svc.name.clone(), filter)
        })
        .collect();

    // Pre-clone values that both drain tasks need.  String::clone is a heap copy.
    let ipns_tx_staging = ipns_tx.clone();
    let local_hostname_staging = local_hostname.clone();
    let pin_service_filters_staging = pin_service_filters.clone();
    let verification_store_staging = Arc::clone(&verification_store);
    let dkim_authenticator_staging = Arc::clone(&dkim_authenticator);
    let group_filter_staging = group_filter.clone();
    // trusted_keys is moved into PeeringShared; clone for drain tasks before that.
    let trusted_keys_drain = shared.trusted_keys.clone();
    let trusted_keys_staging = shared.trusted_keys.clone();

    // Clone the metrics Arc before moving the sender into PeeringShared, so we can
    // read queue depth from the drain timeout log without holding a Sender (which
    // would prevent the channel from closing — see nzr6.17).
    let ingestion_metrics = ingestion_sender.clone_metrics();

    let ingestion_handle = {
        let ipfs = Arc::clone(&ipfs_store);
        let msgid_map_drain = Arc::clone(&msgid_map);
        let log_storage_drain = Arc::clone(&log_storage);
        let signing_key_drain = Arc::clone(&signing_key);
        let hlc_drain = Arc::clone(&hlc);
        let local_hostname_drain = local_hostname;
        let transit_pool_drain = Arc::clone(&transit_pool);
        let ingestion_metrics_task = Arc::clone(&ingestion_metrics);
        let ipns_tx_drain = ipns_tx;
        let verification_store_drain = Arc::clone(&verification_store);
        let dkim_authenticator_drain = Arc::clone(&dkim_authenticator);
        let trusted_keys_for_drain = trusted_keys_drain;
        let group_filter_drain = group_filter.clone();

        tokio::spawn(async move {
            while let Some(article) = ingestion_receiver.recv().await {
                stoa_transit::metrics::INGESTION_QUEUE_DEPTH
                    .set(ingestion_metrics_task.current_depth() as i64);
                run_pipeline_and_notify(
                    &article.bytes,
                    &article.message_id,
                    "article ingested",
                    &hlc_drain,
                    Arc::clone(&signing_key_drain),
                    &local_hostname_drain,
                    Some(&verification_store_drain),
                    &trusted_keys_for_drain,
                    Some(&dkim_authenticator_drain),
                    group_filter_drain.clone(),
                    &*ipfs,
                    &msgid_map_drain,
                    &*log_storage_drain,
                    &transit_pool_drain,
                    &ipns_tx_drain,
                    &pin_service_filters,
                )
                .await;
            }
            info!("ingestion drain task stopped");
        })
    };

    // ── Staging drain task (only when [staging] is configured) ────────────────

    let mut staging_shutdown_opt: Option<tokio::sync::watch::Sender<bool>> = None;
    let mut staging_drain_opt: Option<tokio::task::JoinHandle<()>> = None;

    if let Some(staging) = staging_store {
        // Log how many articles survived the previous run.
        match staging.pending_count().await {
            Ok(n) if n > 0 => info!(count = n, "re-draining staged articles from previous run"),
            _ => {}
        }
        // Clear stale claims left by a previous run that crashed after claiming
        // but before completing an article, so they can be re-drained.
        if let Err(e) = staging.reset_claims().await {
            warn!("staging: reset_claims failed: {e}");
        }
        // Remove orphaned staging files: written by try_stage but never
        // committed to the DB (e.g. future cancelled on peer disconnect).
        match staging.cleanup_orphaned_files().await {
            Ok(0) => {}
            Ok(n) => info!(count = n, "staging: removed orphaned files from previous run"),
            Err(e) => warn!("staging: cleanup_orphaned_files failed: {e}"),
        }

        let (staging_shutdown_tx, mut staging_shutdown_rx) = tokio::sync::watch::channel(false);
        staging_shutdown_opt = Some(staging_shutdown_tx);

        let ipfs = Arc::clone(&ipfs_store);
        let msgid_map_drain = Arc::clone(&msgid_map);
        let log_storage_drain = Arc::clone(&log_storage);
        let signing_key_drain = Arc::clone(&signing_key);
        let hlc_drain = Arc::clone(&hlc);
        let local_hostname_drain = local_hostname_staging;
        let transit_pool_drain = Arc::clone(&transit_pool);
        let ipns_tx_drain = ipns_tx_staging;
        let pin_service_filters = pin_service_filters_staging;
        let verification_store_drain = verification_store_staging;
        let dkim_authenticator_drain = dkim_authenticator_staging;
        let trusted_keys_for_drain = trusted_keys_staging;
        let group_filter_drain = group_filter_staging;

        staging_drain_opt = Some(tokio::spawn(async move {
            loop {
                match staging.drain_one().await {
                    Ok(None) => {
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                            _ = staging_shutdown_rx.changed() => { break; }
                        }
                    }
                    Ok(Some(article)) => {
                        let success = run_pipeline_and_notify(
                            &article.bytes,
                            &article.message_id,
                            "staged article ingested",
                            &hlc_drain,
                            Arc::clone(&signing_key_drain),
                            &local_hostname_drain,
                            Some(&verification_store_drain),
                            &trusted_keys_for_drain,
                            Some(&dkim_authenticator_drain),
                            group_filter_drain.clone(),
                            &*ipfs,
                            &msgid_map_drain,
                            &*log_storage_drain,
                            &transit_pool_drain,
                            &ipns_tx_drain,
                            &pin_service_filters,
                        )
                        .await;
                        if success {
                            if let Err(e) = staging.complete(&article).await {
                                warn!(
                                    msgid = %article.message_id,
                                    "could not complete staging record: {e}"
                                );
                            }
                        }
                        // On failure, leave the row in place; it will be retried on next drain_one().
                    }
                    Err(e) => {
                        warn!("staging drain error: {e}");
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                            _ = staging_shutdown_rx.changed() => { break; }
                        }
                    }
                }
            }
            info!("staging drain task stopped");
        }));
    }

    // ── Peering TCP listener (atu) ────────────────────────────────────────────

    let listener = match TcpListener::bind(&config.listen.addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind {}: {e}", config.listen.addr);
            std::process::exit(1);
        }
    };
    info!(addr = %config.listen.addr, "peering TCP listener bound");

    // ── Admin HTTP server (5vc) ───────────────────────────────────────────────

    match config.admin.addr.parse::<std::net::SocketAddr>() {
        Ok(admin_addr) => {
            let admin_bearer_token = stoa_core::secret::resolve_secret_uri(
                config.admin.bearer_token.clone(),
                "admin.bearer_token",
            )
            .await
            .unwrap_or_else(|msg| {
                eprintln!("{msg}");
                std::process::exit(1);
            });
            let admin_audit_logger: Arc<dyn AuditLogger> = Arc::new(start_audit_logger(
                (*core_pool).clone(),
                100,
                Duration::from_secs(5),
            ));
            if let Err(e) = start_admin_server(
                admin_addr,
                AdminPools {
                    transit_pool: Arc::clone(&transit_pool),
                    core_pool: Arc::clone(&core_pool),
                    audit_logger: Some(admin_audit_logger),
                },
                start_time,
                admin_bearer_token,
                config.admin.rate_limit_rpm,
                Arc::clone(&ipfs_store),
                ipns_path_string.clone(),
            ) {
                eprintln!("error: admin server: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("error: invalid admin addr '{}': {e}", config.admin.addr);
            std::process::exit(1);
        }
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────

    let drain_timeout_secs = config.peering.drain_timeout_secs.unwrap_or(30);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received CTRL-C, shutting down");
        }
        _ = sigterm() => {
            info!("received SIGTERM, shutting down");
        }
        result = accept_loop(listener, shared) => {
            if let Err(e) = result {
                warn!("accept loop error: {e}");
            }
        }
    }

    // Signal the staging drain task to stop (if running), then wait briefly.
    if let Some(shutdown_tx) = staging_shutdown_opt {
        let _ = shutdown_tx.send(true);
        if let Some(staging_handle) = staging_drain_opt {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(drain_timeout_secs),
                staging_handle,
            )
            .await;
        }
    }

    // Signal the ingestion task to stop by dropping the last sender, then
    // wait for it to finish processing any queued articles.
    info!("shutting down, draining ingestion queue");
    drop(ingestion_sender);
    let drain_result = tokio::time::timeout(
        std::time::Duration::from_secs(drain_timeout_secs),
        ingestion_handle,
    )
    .await;
    match drain_result {
        Ok(Ok(())) => {
            info!("ingestion task drained cleanly");
        }
        Ok(Err(e)) => {
            warn!("ingestion task panicked: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            let remaining = ingestion_metrics.current_depth();
            warn!(
                remaining_queue_depth = remaining,
                "ingestion drain timeout, forcing exit"
            );
            std::process::exit(1);
        }
    }

    info!("stoa-transit stopped");
}

async fn accept_loop(listener: TcpListener, shared: Arc<PeeringShared>) -> std::io::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let peer_addr = addr.to_string();
        let peer_ip = addr.ip().to_string();
        tracing::debug!(%peer_addr, "new peering connection");
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Some(ref acceptor) = shared.tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        run_peering_session(tls_stream, peer_addr, peer_ip, shared).await;
                    }
                    Err(e) => {
                        tracing::warn!(%peer_addr, "peering TLS accept failed: {e}");
                    }
                }
            } else {
                run_peering_session(stream, peer_addr, peer_ip, shared).await;
            }
        });
    }
}

async fn open_pool(path: &str, pool_size: u32) -> sqlx::SqlitePool {
    let url = format!("sqlite://{path}");
    let opts = match <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str(&url) {
        Ok(o) => o
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
        Err(e) => {
            eprintln!("error: invalid database path '{path}': {e}");
            std::process::exit(1);
        }
    };
    match sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(pool_size)
        .connect_with(opts)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to open database '{path}': {e}");
            std::process::exit(1);
        }
    }
}

/// Resolve the local FQDN for use in the `Path:` header.
///
/// Tries `/etc/hostname` first (reliable on Linux), then falls back to
/// `"localhost"`.  Operators should set `operator.hostname` in config.
fn resolve_local_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    // SAFETY: signal() is safe to call; it only registers an OS signal handler.
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
