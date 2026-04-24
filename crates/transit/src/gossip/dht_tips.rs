//! DHT-based tip discovery for transit nodes.
//!
//! Uses libp2p Kademlia to store and retrieve group tip CIDs.
//! Used by nodes that have been offline and cannot rely on gossipsub.

use std::collections::HashMap;

use libp2p::{
    futures::StreamExt,
    kad::{
        self, store::MemoryStore, Event as KademliaEvent, GetRecordOk, QueryId, QueryResult,
        Quorum, Record, RecordKey,
    },
    swarm::SwarmEvent,
    PeerId,
};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

/// Returns the Kademlia record key for a group's tip CID.
///
/// Key = SHA-256 of `b"stoa.tip." + group_name.as_bytes()`, encoded as 32 bytes.
pub fn dht_key_for_group(group_name: &str) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(b"stoa.tip.");
    hasher.update(group_name.as_bytes());
    let hash = hasher.finalize();
    RecordKey::new(&hash.as_slice())
}

/// A handle to the background DHT swarm task.
pub struct DhtHandle {
    /// Send `(group_name, tip_cid_string)` to store in DHT.
    pub put_tx: mpsc::Sender<(String, String)>,
    /// Send `(group_name, reply_tx)` to look up tip CIDs from DHT.
    pub get_tx: mpsc::Sender<(String, oneshot::Sender<Vec<String>>)>,
    /// The local peer identity of this DHT swarm node.
    pub local_peer_id: PeerId,
}

/// Start a Kademlia-only DHT swarm and return a handle to it.
///
/// The swarm listens on `listen_addr` (e.g. `"/ip4/127.0.0.1/tcp/0"`).
/// It runs in a background `tokio::spawn` task. The swarm uses an
/// in-memory record store and operates in Server mode so that it can
/// store records for other peers.
pub async fn start_dht_swarm(listen_addr: &str) -> Result<DhtHandle, Box<dyn std::error::Error>> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let local_peer_id = key.public().to_peer_id();
            let store = MemoryStore::new(local_peer_id);
            kad::Behaviour::new(local_peer_id, store)
        })?
        .build();

    swarm
        .behaviour_mut()
        .set_mode(Some(libp2p::kad::Mode::Server));

    let listen: libp2p::Multiaddr = listen_addr.parse()?;
    swarm.listen_on(listen)?;

    let local_peer_id = *swarm.local_peer_id();

    let (put_tx, mut put_rx) = mpsc::channel::<(String, String)>(64);
    let (get_tx, mut get_rx) = mpsc::channel::<(String, oneshot::Sender<Vec<String>>)>(64);

    tokio::spawn(async move {
        // Tracks in-flight get_record queries: query_id -> (reply_tx, accumulated_values).
        let mut pending_gets: HashMap<QueryId, (oneshot::Sender<Vec<String>>, Vec<String>)> =
            HashMap::new();

        loop {
            tokio::select! {
                maybe_put = put_rx.recv() => {
                    match maybe_put {
                        None => break,
                        Some((group_name, tip_cid)) => {
                            let key = dht_key_for_group(&group_name);
                            let record = Record {
                                key,
                                value: tip_cid.into_bytes(),
                                publisher: None,
                                expires: None,
                            };
                            if let Err(e) = swarm.behaviour_mut().put_record(record, Quorum::One) {
                                tracing::warn!(group = %group_name, "DHT put_record error: {e}");
                            }
                        }
                    }
                }

                maybe_get = get_rx.recv() => {
                    match maybe_get {
                        None => break,
                        Some((group_name, reply_tx)) => {
                            let key = dht_key_for_group(&group_name);
                            let query_id = swarm.behaviour_mut().get_record(key);
                            pending_gets.insert(query_id, (reply_tx, Vec::new()));
                        }
                    }
                }

                event = swarm.next() => {
                    match event {
                        Some(SwarmEvent::NewListenAddr { address, .. }) => {
                            tracing::info!(%address, "DHT swarm listening");
                        }
                        Some(SwarmEvent::Behaviour(KademliaEvent::OutboundQueryProgressed {
                            id,
                            result,
                            step,
                            ..
                        })) => {
                            match result {
                                QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
                                    if let Some((_reply_tx, values)) = pending_gets.get_mut(&id) {
                                        if let Ok(s) = String::from_utf8(peer_record.record.value) {
                                            values.push(s);
                                        }
                                    }
                                    if step.last {
                                        if let Some((reply_tx, values)) = pending_gets.remove(&id) {
                                            let _ = reply_tx.send(values);
                                        }
                                    }
                                }
                                QueryResult::GetRecord(Ok(
                                    GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                                )) => {
                                    if let Some((reply_tx, values)) = pending_gets.remove(&id) {
                                        let _ = reply_tx.send(values);
                                    }
                                }
                                QueryResult::GetRecord(Err(e)) => {
                                    tracing::debug!("DHT get_record query failed: {e:?}");
                                    if let Some((reply_tx, _)) = pending_gets.remove(&id) {
                                        let _ = reply_tx.send(Vec::new());
                                    }
                                }
                                QueryResult::PutRecord(Ok(ok)) => {
                                    tracing::debug!(key = ?ok.key, "DHT put_record succeeded");
                                }
                                QueryResult::PutRecord(Err(e)) => {
                                    tracing::warn!("DHT put_record query failed: {e:?}");
                                }
                                _ => {}
                            }
                        }
                        Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                            tracing::debug!(%peer_id, "DHT connection established");
                        }
                        Some(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                            tracing::debug!(%peer_id, "DHT connection closed");
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
        }
        tracing::debug!("DHT swarm task exiting");
    });

    Ok(DhtHandle {
        put_tx,
        get_tx,
        local_peer_id,
    })
}

/// Query the DHT for tip CIDs for a group and parse them as [`cid::Cid`].
///
/// Returns an empty vec if the query fails, times out, or finds nothing.
pub async fn find_tips_via_dht(handle: &DhtHandle, group_name: &str) -> Vec<cid::Cid> {
    let (tx, rx) = oneshot::channel();
    let _ = handle.get_tx.send((group_name.to_owned(), tx)).await;
    let strings = rx.await.unwrap_or_default();
    strings
        .iter()
        .filter_map(|s| s.parse::<cid::Cid>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dht_key_is_deterministic() {
        let k1 = dht_key_for_group("comp.lang.rust");
        let k2 = dht_key_for_group("comp.lang.rust");
        assert_eq!(k1, k2);
    }

    #[test]
    fn dht_key_differs_for_different_groups() {
        let k1 = dht_key_for_group("comp.lang.rust");
        let k2 = dht_key_for_group("alt.test");
        assert_ne!(k1, k2);
    }

    #[tokio::test]
    async fn two_node_put_get_roundtrip() {
        let h1 = start_dht_swarm("/ip4/127.0.0.1/tcp/0")
            .await
            .expect("node1 should start");
        let h2 = start_dht_swarm("/ip4/127.0.0.1/tcp/0")
            .await
            .expect("node2 should start");

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            !h1.local_peer_id.to_string().is_empty(),
            "node1 peer ID must be non-empty"
        );
        assert!(
            !h2.local_peer_id.to_string().is_empty(),
            "node2 peer ID must be non-empty"
        );
        assert_ne!(
            h1.local_peer_id, h2.local_peer_id,
            "two independent nodes must have distinct peer IDs"
        );
    }
}
