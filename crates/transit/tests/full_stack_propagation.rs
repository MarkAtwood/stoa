//! Integration test: three-node full-stack propagation.
//!
//! Simulates a transit node A ingesting an article, propagating a tip
//! advertisement to transit node B via in-process gossipsub, and a reader
//! connected to B retrieving the article byte-for-byte.
//!
//! No live IPFS daemon is required. All storage is in-memory or SQLite.
//! The `TestSwarmHandle` / `start_test_swarm` harness is duplicated from
//! `gossip_propagation.rs` because integration test files cannot import
//! from one another.

use cid::Cid;
use ed25519_dalek::{Signer, SigningKey};
use libp2p::{
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use multihash_codetable::{Code, MultihashDigest};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr as _;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use usenet_ipfs_core::{hlc::HlcTimestamp, msgid_map::MsgIdMap};
use usenet_ipfs_transit::{
    gossip::tip_advert::handle_tip_advertisement,
    peering::pipeline::{run_pipeline, IpfsStore, MemIpfsStore, PipelineCtx},
};

// ---------------------------------------------------------------------------
// Test swarm harness (verbatim copy from gossip_propagation.rs)
// ---------------------------------------------------------------------------

struct TestSwarmHandle {
    /// Send (topic, data) to publish from this node.
    gossip_tx: mpsc::Sender<(String, Vec<u8>)>,
    /// Receive (topic, data) messages arriving from peers.
    gossip_rx: mpsc::Receiver<(String, Vec<u8>)>,
    /// Subscribe this node to a gossipsub topic by name.
    subscribe_tx: mpsc::Sender<String>,
    /// Dial a remote multiaddr from this node.
    dial_tx: mpsc::Sender<Multiaddr>,
    /// The actual listen address assigned by the OS (port 0 resolved).
    listen_addr: Multiaddr,
    /// This node's libp2p PeerId.
    peer_id: PeerId,
}

async fn start_test_swarm() -> TestSwarmHandle {
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .mesh_outbound_min(1)
        .mesh_n(2)
        .mesh_n_low(2)
        .mesh_n_high(4)
        .heartbeat_interval(Duration::from_millis(200))
        .max_transmit_size(1_048_576)
        .build()
        .expect("gossipsub config must be valid");

    let mut swarm: Swarm<gossipsub::Behaviour> = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .expect("TCP transport must initialise")
        .with_behaviour(|key| {
            gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), gossipsub_config)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })
        })
        .expect("gossipsub behaviour must attach")
        .build();

    let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm.listen_on(listen).expect("listen_on must succeed");

    let peer_id = *swarm.local_peer_id();

    let (pub_tx, mut pub_rx) = mpsc::channel::<(String, Vec<u8>)>(64);
    let (recv_tx, recv_rx) = mpsc::channel::<(String, Vec<u8>)>(64);
    let (sub_tx, mut sub_rx) = mpsc::channel::<String>(16);
    let (dial_tx, mut dial_rx) = mpsc::channel::<Multiaddr>(8);
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();
    let mut addr_tx_opt = Some(addr_tx);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                maybe_pub = pub_rx.recv() => {
                    match maybe_pub {
                        None => break,
                        Some((topic_name, data)) => {
                            let topic = IdentTopic::new(topic_name);
                            if let Err(e) = swarm.behaviour_mut().publish(topic, data) {
                                tracing::warn!("publish error: {e}");
                            }
                        }
                    }
                }
                maybe_sub = sub_rx.recv() => {
                    if let Some(topic_name) = maybe_sub {
                        let topic = IdentTopic::new(topic_name.clone());
                        match swarm.behaviour_mut().subscribe(&topic) {
                            Ok(true) => tracing::debug!("subscribed to {topic_name}"),
                            Ok(false) => tracing::debug!("already subscribed to {topic_name}"),
                            Err(e) => tracing::warn!("subscribe error for {topic_name}: {e}"),
                        }
                    }
                }
                maybe_dial = dial_rx.recv() => {
                    if let Some(addr) = maybe_dial {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            tracing::warn!("dial {addr} failed: {e}");
                        }
                    }
                }
                event = swarm.next() => {
                    match event {
                        Some(SwarmEvent::NewListenAddr { address, .. }) => {
                            tracing::debug!("listening on {address}");
                            if let Some(tx) = addr_tx_opt.take() {
                                let _ = tx.send(address);
                            }
                        }
                        Some(SwarmEvent::Behaviour(gossipsub::Event::Message {
                            message, ..
                        })) => {
                            let topic = message.topic.as_str().to_owned();
                            if recv_tx.send((topic, message.data)).await.is_err() {
                                break;
                            }
                        }
                        Some(_) | None => {}
                    }
                }
            }
        }
        tracing::debug!("test swarm task exiting");
    });

    let listen_addr = addr_rx.await.expect("must receive listen address");

    TestSwarmHandle {
        gossip_tx: pub_tx,
        gossip_rx: recv_rx,
        subscribe_tx: sub_tx,
        dial_tx,
        listen_addr,
        peer_id,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an isolated in-memory SQLite pool with core migrations applied.
///
/// The `name` parameter is used to give each pool a unique shared-cache URL
/// so concurrent tests do not collide on `_sqlx_migrations`.
async fn make_msgid_map(name: &str) -> (MsgIdMap, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    let opts = SqliteConnectOptions::from_str(&url)
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap_or_else(|e| panic!("failed to open SQLite pool {name}: {e}"));
    usenet_ipfs_core::migrations::run_migrations(&pool)
        .await
        .unwrap_or_else(|e| panic!("migrations failed for {name}: {e}"));
    (MsgIdMap::new(pool), tmp)
}

fn make_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

fn make_timestamp() -> HlcTimestamp {
    HlcTimestamp {
        wall_ms: 1_700_000_000_000,
        logical: 0,
        node_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    }
}

/// Build a minimal valid RFC 5536-compatible article.
fn make_article(msgid: &str, newsgroups: &str, body: &str) -> Vec<u8> {
    format!(
        "From: sender@example.com\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         Message-ID: {msgid}\r\n\
         Newsgroups: {newsgroups}\r\n\
         Subject: Full-stack propagation test article\r\n\
         \r\n\
         {body}\r\n"
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Three-node full-stack propagation:
///
/// 1. Transit A ingests an article (MemIpfsStore + MsgIdMap + MemLogStorage)
///    and publishes a TipAdvertisement over gossipsub.
/// 2. Transit B receives the TipAdvertisement over gossipsub, parses it, and
///    extracts the article CID.
/// 3. Simulated pull: the article bytes (transferred out-of-band in the test)
///    are written into B's MemIpfsStore and recorded in B's MsgIdMap.
/// 4. Simulated reader on B: looks up the Message-ID in B's MsgIdMap and
///    retrieves the CID. The CID is byte-identical to what A computed, proving
///    content-addressed identity.
#[tokio::test]
async fn full_stack_propagation() {
    let topic = "usenet.hier.comp";
    let msgid = "<full-stack-test-001@example.com>";
    let newsgroup = "comp.lang.rust";
    let article_body = "This is the full-stack propagation test body.\r\n";
    let article_bytes = make_article(msgid, newsgroup, article_body);

    // --- Node A: transit ingest ---
    let node_a = start_test_swarm().await;
    let mut node_b = start_test_swarm().await;

    // Both nodes subscribe to the comp hierarchy topic.
    node_a
        .subscribe_tx
        .send(topic.to_owned())
        .await
        .expect("node A subscribe must succeed");
    node_b
        .subscribe_tx
        .send(topic.to_owned())
        .await
        .expect("node B subscribe must succeed");

    // B dials A to form the mesh.
    node_b
        .dial_tx
        .send(node_a.listen_addr.clone())
        .await
        .expect("dial must succeed");

    // Wait for the gossipsub mesh to form.
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    // Node A: set up storage.
    let ipfs_a = MemIpfsStore::new();
    let (msgid_map_a, _tmp_a) = make_msgid_map("full_stack_node_a").await;
    let log_storage_a = usenet_ipfs_core::group_log::MemLogStorage::new();
    let signing_key = make_signing_key();
    let ts = make_timestamp();

    let ctx_a = PipelineCtx {
        timestamp: ts,
        operator_signature: signing_key.sign(b""),
        gossip_tx: Some(&node_a.gossip_tx),
        sender_peer_id: &node_a.peer_id.to_string(),
    };

    // Run the transit pipeline on A: writes to IPFS, records msgid→CID,
    // appends to group log, and publishes a TipAdvertisement over gossipsub.
    let transit_pool = {
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        use std::str::FromStr as _;
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
    };
    let (pipeline_result, _metrics) = run_pipeline(
        &article_bytes,
        &ipfs_a,
        &msgid_map_a,
        &log_storage_a,
        &transit_pool,
        ctx_a,
    )
    .await
    .expect("pipeline on node A must succeed");

    let cid_a = pipeline_result.cid;
    assert_eq!(
        pipeline_result.groups,
        vec!["comp.lang.rust"],
        "pipeline must record comp.lang.rust group"
    );

    // --- Node B: receive TipAdvertisement from gossipsub ---
    let recv_result = tokio::time::timeout(Duration::from_secs(5), node_b.gossip_rx.recv()).await;

    let advert = match recv_result {
        Ok(Some((_recv_topic, recv_bytes))) => handle_tip_advertisement(&recv_bytes)
            .expect("node B must parse a valid TipAdvertisement from node A"),
        Ok(None) => panic!("gossip_rx channel closed before TipAdvertisement arrived at node B"),
        Err(_) => panic!("timeout: node B did not receive TipAdvertisement from node A within 5 s"),
    };

    assert_eq!(
        advert.group_name, newsgroup,
        "advertisement must carry correct group name"
    );
    assert_eq!(
        advert.sender_peer_id,
        node_a.peer_id.to_string(),
        "advertisement must identify node A as sender"
    );
    assert_eq!(
        advert.tip_cids.len(),
        1,
        "advertisement must carry exactly one tip CID"
    );

    // The tip CID string received over the wire must match what A computed.
    let tip_cid_str = &advert.tip_cids[0];
    let cid_from_wire: Cid = tip_cid_str
        .parse()
        .unwrap_or_else(|e| panic!("tip CID must be a valid CID string: {e}"));
    assert_eq!(
        cid_from_wire, cid_a,
        "CID received by B over gossipsub must equal CID computed by A"
    );

    // --- Simulate B fetching the article from A (out-of-band pull) ---
    // In production, B would fetch the raw block from A via bitswap/request.
    // Here we simulate that by writing the same article bytes into B's stores.
    let ipfs_b = MemIpfsStore::new();
    let (msgid_map_b, _tmp_b) = make_msgid_map("full_stack_node_b").await;

    let cid_b = ipfs_b
        .put_raw(&article_bytes)
        .await
        .expect("writing article bytes to node B's IPFS store must succeed");

    // Content-addressable identity: same bytes must produce same CID.
    assert_eq!(
        cid_b, cid_a,
        "node B's CID for the article bytes must be byte-identical to node A's CID"
    );

    msgid_map_b
        .insert(msgid, &cid_b)
        .await
        .expect("recording msgid→CID in node B's map must succeed");

    // --- Simulated reader on B: look up article by Message-ID ---
    // In production the reader daemon queries this same MsgIdMap to resolve
    // ARTICLE <msgid> commands from newsreader clients.
    let reader_cid = msgid_map_b
        .lookup_by_msgid(msgid)
        .await
        .expect("msgid_map lookup must not return a database error")
        .unwrap_or_else(|| panic!("reader on B must find Message-ID {msgid} in msgid_map"));

    assert_eq!(
        reader_cid, cid_a,
        "CID returned by reader lookup must be byte-identical to CID computed by transit A"
    );

    // Verify the CID encodes the correct content: re-derive from article bytes.
    let digest = Code::Sha2_256.digest(&article_bytes);
    let expected_cid = Cid::new_v1(0x55, digest);
    assert_eq!(
        reader_cid, expected_cid,
        "reader CID must match independently-computed content-addressed CID"
    );
}
