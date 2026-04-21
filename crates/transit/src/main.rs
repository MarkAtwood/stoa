use std::{collections::HashSet, path::PathBuf, sync::Arc};

use ed25519_dalek::Signer as _;
use rand_core::OsRng;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{info, warn};
use usenet_ipfs_core::{group_log::SqliteLogStorage, hlc::HlcClock, msgid_map::MsgIdMap};
use usenet_ipfs_transit::{
    config::{check_admin_addr, Config},
    gossip::swarm::start_swarm,
    peering::{
        ingestion_queue::ingestion_queue,
        pipeline::{run_pipeline, PipelineCtx, RustIpfsStore},
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

    let core_pool = open_pool(&config.database.core_path).await;
    if let Err(e) = usenet_ipfs_core::migrations::run_migrations(&core_pool).await {
        eprintln!("error: core database migration failed: {e}");
        std::process::exit(1);
    }
    let msgid_map = Arc::new(MsgIdMap::new(core_pool.clone()));
    let log_storage = Arc::new(SqliteLogStorage::new(core_pool));

    let transit_pool = open_pool(&config.database.path).await;
    if let Err(e) = usenet_ipfs_transit::migrations::run_migrations(&transit_pool).await {
        eprintln!("error: transit database migration failed: {e}");
        std::process::exit(1);
    }
    drop(transit_pool); // transit-specific tables wired in future epics

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

    // ── Operator signing key (ephemeral for v1) ───────────────────────────────

    let signing_key = Arc::new(ed25519_dalek::SigningKey::generate(&mut OsRng));
    warn!("using ephemeral operator signing key — add key persistence before production");

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

    // Keep gossip rx alive; inbound tips are wired in usenet-ipfs-3m7.
    let gossip_tx = gossip_handle.tx;
    let mut gossip_rx = gossip_handle.rx;
    tokio::spawn(async move {
        while gossip_rx.recv().await.is_some() {}
    });

    // ── HLC clock and ingestion queue ─────────────────────────────────────────

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let peer_bytes = peer_id.to_bytes();
    let node_id = {
        let mut id = [0u8; 8];
        let copy_len = id.len().min(peer_bytes.len());
        id[..copy_len].copy_from_slice(&peer_bytes[..copy_len]);
        id
    };
    let hlc = Arc::new(Mutex::new(HlcClock::new(node_id, now_ms)));

    let (ingestion_sender, mut ingestion_receiver) = ingestion_queue(1024);
    let ingestion_sender = Arc::new(ingestion_sender);

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

        tokio::spawn(async move {
            while let Some(article) = ingestion_receiver.recv().await {
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
                };
                match run_pipeline(
                    &article.bytes,
                    &*ipfs,
                    &msgid_map_drain,
                    &*log_storage_drain,
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

async fn open_pool(path: &str) -> sqlx::SqlitePool {
    let url = format!("sqlite://{path}");
    let opts = match <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str(&url) {
        Ok(o) => o.create_if_missing(true),
        Err(e) => {
            eprintln!("error: invalid database path '{path}': {e}");
            std::process::exit(1);
        }
    };
    match sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(8)
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

async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    // SAFETY: signal() is safe to call; it only registers an OS signal handler.
    let mut stream = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    stream.recv().await;
}
