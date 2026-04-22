use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Instant};

use cid::Cid;
use ed25519_dalek::Signer as _;
use rand_core::OsRng;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{info, warn};
use usenet_ipfs_core::{
    group_log::{backfill, reconcile, LogEntryId, SqliteLogStorage, VerifiedEntry},
    hlc::HlcClock,
    msgid_map::MsgIdMap,
    GroupName,
};
use usenet_ipfs_transit::{
    admin::start_admin_server,
    config::{check_admin_addr, Config},
    gossip::{swarm::start_swarm, tip_advert::handle_tip_advertisement},
    peering::{
        blacklist::BlacklistConfig,
        ingestion_queue::ingestion_queue,
        pipeline::{run_pipeline, PipelineCtx, RustIpfsStore},
        rate_limit::{ExhaustionAction, PeerRateLimiter},
        session::{run_peering_session, PeeringShared},
    },
};

fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" {
            if let Some(path) = args.get(i + 1) {
                return PathBuf::from(path);
            }
            eprintln!("error: --config requires a path argument");
            std::process::exit(1);
        }
        i += 1;
    }
    eprintln!("error: --config <path> is required");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let start_time = Instant::now();
    let config_path = parse_args();

    let config = match Config::from_file(&config_path) {
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

    info!(
        listen_addr = %config.listen.addr,
        peer_count = config.peers.addresses.len(),
        group_count = config.groups.names.len(),
        "usenet-ipfs-transit starting"
    );

    if let Some(warning) = check_admin_addr(&config.admin) {
        warn!("{}", warning);
    }

    // ── SQLite databases (two separate pools: core schema + transit schema) ───

    let core_pool = open_pool(&config.database.core_path, config.database.pool_size).await;
    if let Err(e) = usenet_ipfs_core::migrations::run_migrations(&core_pool).await {
        eprintln!("error: core database migration failed: {e}");
        std::process::exit(1);
    }
    let msgid_map = Arc::new(MsgIdMap::new(core_pool.clone()));
    let log_storage = Arc::new(SqliteLogStorage::new(core_pool));

    let transit_pool = Arc::new(open_pool(&config.database.path, config.database.pool_size).await);
    if let Err(e) = usenet_ipfs_transit::migrations::run_migrations(&transit_pool).await {
        eprintln!("error: transit database migration failed: {e}");
        std::process::exit(1);
    }

    // ── rust-ipfs node (y3o) ──────────────────────────────────────────────────

    info!("starting rust-ipfs node");
    let ipfs_store: Arc<dyn usenet_ipfs_transit::peering::pipeline::IpfsStore> =
        match RustIpfsStore::new().await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("error: failed to start IPFS node: {e}");
                std::process::exit(1);
            }
        };
    info!("rust-ipfs node started");

    // ── Operator signing key ──────────────────────────────────────────────────

    let signing_key = Arc::new(match &config.operator.signing_key_path {
        Some(path) => {
            match usenet_ipfs_core::signing::load_signing_key(std::path::Path::new(path)) {
                Ok(k) => {
                    info!(path, "loaded operator signing key");
                    k
                }
                Err(e) => {
                    eprintln!("error: cannot load operator signing key from '{path}': {e}");
                    std::process::exit(1);
                }
            }
        }
        None => {
            warn!(
                "operator.signing_key_path not set — using ephemeral key; \
                 article signatures will not survive restart"
            );
            ed25519_dalek::SigningKey::generate(&mut OsRng)
        }
    });

    // ── Gossipsub swarm (j7n) ─────────────────────────────────────────────────

    info!("starting gossipsub swarm");
    let (gossip_handle, subscribe_handle, peer_id) = match start_swarm("/ip4/0.0.0.0/tcp/0").await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: gossipsub swarm failed to start: {e}");
            std::process::exit(1);
        }
    };
    info!(%peer_id, "gossipsub swarm started");

    let mut seen_hier: HashSet<String> = HashSet::new();
    for group in &config.groups.names {
        let hier = group.split('.').next().unwrap_or(group.as_str());
        if seen_hier.insert(hier.to_owned()) {
            let topic = format!("usenet.hier.{hier}");
            if let Err(e) = subscribe_handle.subscribe(&topic).await {
                warn!(topic, "gossipsub subscribe failed: {e}");
            } else {
                info!(topic, "subscribed to gossipsub topic");
            }
        }
    }

    // Wire inbound gossip tips → group-log reconciliation.
    let gossip_tx = gossip_handle.tx;
    let mut gossip_rx = gossip_handle.rx;
    {
        let log_storage_gossip = Arc::clone(&log_storage);
        tokio::spawn(async move {
            while let Some((_topic, data)) = gossip_rx.recv().await {
                let Some(advert) = handle_tip_advertisement(&data) else {
                    continue;
                };

                let group = match GroupName::new(&advert.group_name) {
                    Ok(g) => g,
                    Err(_) => {
                        warn!(group = %advert.group_name, "gossip: invalid group name");
                        continue;
                    }
                };

                // Convert tip CID strings → LogEntryIds via their multihash digest.
                let mut remote_tips: Vec<LogEntryId> = Vec::new();
                for cid_str in &advert.tip_cids {
                    let cid = match Cid::try_from(cid_str.as_str()) {
                        Ok(c) => c,
                        Err(_) => {
                            warn!(group = %group, cid = %cid_str, "gossip: unparseable tip CID");
                            continue;
                        }
                    };
                    match <[u8; 32]>::try_from(cid.hash().digest()) {
                        Ok(raw) => remote_tips.push(LogEntryId::from_bytes(raw)),
                        Err(_) => {
                            warn!(group = %group, "gossip: tip CID digest is not 32 bytes");
                        }
                    }
                }

                let result = match reconcile(&*log_storage_gossip, &group, &remote_tips).await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(group = %group, "gossip: reconcile error: {e}");
                        continue;
                    }
                };

                if result.want.is_empty() && result.have.is_empty() {
                    continue;
                }

                info!(
                    group = %group,
                    want = result.want.len(),
                    have = result.have.len(),
                    sender = %advert.sender_peer_id,
                    "gossip: reconcile result"
                );

                // Backfill missing entries.
                // v1: peer block fetch is not yet implemented; log and move on.
                // When this stub is replaced, the callback must return VerifiedEntry
                // produced by verify_signature() — the type enforces the invariant.
                for entry_id in &result.want {
                    let fetch = |_: LogEntryId| async {
                        Err::<VerifiedEntry, String>(
                            "v1: peer block fetch not yet implemented".to_string(),
                        )
                    };
                    match backfill(&*log_storage_gossip, entry_id.clone(), fetch).await {
                        Ok(n) if n > 0 => {
                            info!(group = %group, fetched = n, "gossip: backfilled entries");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(group = %group, entry = %entry_id, "gossip: backfill failed: {e}");
                        }
                    }
                }
            }
        });
    }

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
    let hlc = Arc::new(Mutex::new(HlcClock::new(node_id, now_ms)));

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

    // ── Shared state for peering sessions ─────────────────────────────────────

    let shared = Arc::new(PeeringShared {
        ipfs: Arc::clone(&ipfs_store),
        msgid_map: Arc::clone(&msgid_map),
        log_storage: Arc::clone(&log_storage),
        gossip_tx: Some(gossip_tx.clone()),
        signing_key: Arc::clone(&signing_key),
        hlc: Arc::clone(&hlc),
        ingestion_sender: Arc::clone(&ingestion_sender),
        local_peer_id: peer_id.to_string(),
        local_hostname: local_hostname.clone(),
        // Per-IP rate limiter: all connections from one host share this budget.
        peer_rate_limiter: Arc::new(std::sync::Mutex::new(PeerRateLimiter::new(
            config.peering.rate_limit_rps,
            config.peering.rate_limit_burst,
            ExhaustionAction::Respond431,
        ))),
        transit_pool: Arc::clone(&transit_pool),
        blacklist_config: BlacklistConfig::default(),
    });

    // ── Pipeline drain task ───────────────────────────────────────────────────

    {
        let ipfs = Arc::clone(&ipfs_store);
        let msgid_map_drain = Arc::clone(&msgid_map);
        let log_storage_drain = Arc::clone(&log_storage);
        let signing_key_drain = Arc::clone(&signing_key);
        let hlc_drain = Arc::clone(&hlc);
        let gossip_tx_drain = gossip_tx;
        let local_peer_id = peer_id.to_string();
        let local_hostname_drain = local_hostname;
        let transit_pool_drain = Arc::clone(&transit_pool);
        let ingestion_sender_drain = Arc::clone(&ingestion_sender);

        tokio::spawn(async move {
            while let Some(article) = ingestion_receiver.recv().await {
                usenet_ipfs_transit::metrics::INGESTION_QUEUE_DEPTH
                    .set(ingestion_sender_drain.depth() as i64);
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let timestamp = hlc_drain.lock().await.send(now_ms);
                let sig = signing_key_drain.sign(article.bytes.as_slice());
                let ctx = PipelineCtx {
                    timestamp,
                    operator_signature: sig,
                    gossip_tx: Some(&gossip_tx_drain),
                    sender_peer_id: &local_peer_id,
                    local_hostname: &local_hostname_drain,
                };
                match run_pipeline(
                    &article.bytes,
                    &*ipfs,
                    &msgid_map_drain,
                    &*log_storage_drain,
                    &transit_pool_drain,
                    ctx,
                )
                .await
                {
                    Ok((result, _metrics)) => {
                        info!(
                            cid = %result.cid,
                            groups = ?result.groups,
                            msgid = %article.message_id,
                            "article ingested"
                        );
                    }
                    Err(e) => {
                        warn!(msgid = %article.message_id, "pipeline failed: {e}");
                    }
                }
            }
            info!("ingestion drain task stopped");
        });
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
            if let Err(e) = start_admin_server(
                admin_addr,
                Arc::clone(&transit_pool),
                start_time,
                config.admin.bearer_token.clone(),
                config.admin.rate_limit_rpm,
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

    info!("usenet-ipfs-transit stopped");
}

async fn accept_loop(listener: TcpListener, shared: Arc<PeeringShared>) -> std::io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        tracing::debug!(%peer_addr, "new peering connection");
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            run_peering_session(stream, shared).await;
        });
    }
}

async fn open_pool(path: &str, pool_size: u32) -> sqlx::SqlitePool {
    let url = format!("sqlite://{path}");
    let opts = match <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str(&url) {
        Ok(o) => o.create_if_missing(true),
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
