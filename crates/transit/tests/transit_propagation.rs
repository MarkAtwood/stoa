//! Integration test: bidirectional article propagation between two transit nodes.
//!
//! Verifies that a `TipAdvertisement` published by one in-process gossipsub
//! swarm is received and correctly parsed by the other, in both directions.
//!
//! The `TestSwarmHandle` / `start_test_swarm` harness is duplicated from
//! `gossip_propagation.rs` because integration test files cannot import from
//! one another.

use cid::Cid;
use libp2p::{
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use multihash_codetable::{Code, MultihashDigest};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use usenet_ipfs_core::hlc::HlcTimestamp;
use usenet_ipfs_transit::gossip::tip_advert::{handle_tip_advertisement, TipAdvertisement};

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

/// Start an in-process gossipsub swarm on 127.0.0.1:0 with test-appropriate
/// mesh parameters (mesh_n = 2, mesh_n_low = 1, heartbeat = 200 ms).
///
/// Returns a `TestSwarmHandle` once the swarm is listening (the actual
/// listen address has been resolved).
async fn start_test_swarm() -> TestSwarmHandle {
    // mesh_outbound_min (default 2) must satisfy:
    //   mesh_outbound_min <= mesh_n_low <= mesh_n <= mesh_n_high
    //   mesh_outbound_min * 2 <= mesh_n
    // With mesh_n = 2 the default mesh_outbound_min = 2 violates both
    // constraints. Set mesh_outbound_min = 1 so the two-node test mesh forms.
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
            gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
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

fn make_cid(data: &[u8]) -> Cid {
    let digest = Code::Sha2_256.digest(data);
    Cid::new_v1(0x71, digest)
}

fn make_timestamp() -> HlcTimestamp {
    HlcTimestamp {
        wall_ms: 1_700_000_000_000,
        logical: 0,
        node_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A `TipAdvertisement` published by node A must be received and correctly
/// parsed by node B.
#[tokio::test]
async fn test_a_to_b_propagation() {
    let topic = "usenet.hier.comp";

    let node_a = start_test_swarm().await;
    let mut node_b = start_test_swarm().await;

    node_a
        .subscribe_tx
        .send(topic.to_owned())
        .await
        .expect("subscribe_tx send must succeed");
    node_b
        .subscribe_tx
        .send(topic.to_owned())
        .await
        .expect("subscribe_tx send must succeed");

    // B dials A so they connect.
    node_b
        .dial_tx
        .send(node_a.listen_addr.clone())
        .await
        .expect("dial_tx send must succeed");

    // Allow the gossipsub mesh to form before publishing.
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    let cid = make_cid(b"comp.lang.rust-article-1");
    let ts = make_timestamp();
    let advert = TipAdvertisement::build("comp.lang.rust", &[cid], &ts, &node_a.peer_id);
    let bytes = advert.to_bytes();

    node_a
        .gossip_tx
        .send((topic.to_owned(), bytes))
        .await
        .expect("gossip_tx send must succeed");

    let result = tokio::time::timeout(Duration::from_secs(5), node_b.gossip_rx.recv()).await;

    match result {
        Ok(Some((_recv_topic, recv_bytes))) => {
            let parsed = handle_tip_advertisement(&recv_bytes)
                .expect("node B must parse a valid TipAdvertisement from node A");
            assert_eq!(parsed.group_name, "comp.lang.rust");
            assert_eq!(parsed.sender_peer_id, node_a.peer_id.to_string());
            assert_eq!(parsed.tip_cids.len(), 1);
        }
        Ok(None) => panic!("gossip_rx channel closed before TipAdvertisement arrived at node B"),
        Err(_) => panic!("timeout: node B did not receive TipAdvertisement from node A within 5 s"),
    }
}

/// A `TipAdvertisement` published by node B must be received and correctly
/// parsed by node A.
#[tokio::test]
async fn test_b_to_a_propagation() {
    let topic = "usenet.hier.comp";

    let mut node_a = start_test_swarm().await;
    let node_b = start_test_swarm().await;

    node_a
        .subscribe_tx
        .send(topic.to_owned())
        .await
        .expect("subscribe_tx send must succeed");
    node_b
        .subscribe_tx
        .send(topic.to_owned())
        .await
        .expect("subscribe_tx send must succeed");

    // B dials A so they connect.
    node_b
        .dial_tx
        .send(node_a.listen_addr.clone())
        .await
        .expect("dial_tx send must succeed");

    // Allow the gossipsub mesh to form before publishing.
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    let cid = make_cid(b"comp.lang.rust-article-2");
    let ts = make_timestamp();
    let advert = TipAdvertisement::build("comp.lang.rust", &[cid], &ts, &node_b.peer_id);
    let bytes = advert.to_bytes();

    node_b
        .gossip_tx
        .send((topic.to_owned(), bytes))
        .await
        .expect("gossip_tx send must succeed");

    let result = tokio::time::timeout(Duration::from_secs(5), node_a.gossip_rx.recv()).await;

    match result {
        Ok(Some((_recv_topic, recv_bytes))) => {
            let parsed = handle_tip_advertisement(&recv_bytes)
                .expect("node A must parse a valid TipAdvertisement from node B");
            assert_eq!(parsed.group_name, "comp.lang.rust");
            assert_eq!(parsed.sender_peer_id, node_b.peer_id.to_string());
            assert_eq!(parsed.tip_cids.len(), 1);
        }
        Ok(None) => panic!("gossip_rx channel closed before TipAdvertisement arrived at node A"),
        Err(_) => panic!("timeout: node A did not receive TipAdvertisement from node B within 5 s"),
    }
}
