use std::time::Duration;

use libp2p::{
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use tokio::sync::mpsc;

/// A handle to send and receive gossipsub messages.
pub struct GossipHandle {
    /// Send a (topic, data) pair to be published.
    pub tx: mpsc::Sender<(String, Vec<u8>)>,
    /// Receive (topic, data) pairs from peers.
    pub rx: mpsc::Receiver<(String, Vec<u8>)>,
}

/// Subscribe the swarm to a gossipsub topic.
///
/// This sends a subscribe request to the swarm's background task.
/// The swarm loop will call `behaviour_mut().subscribe()` when it sees
/// the control message. For simplicity, we expose a direct subscribe
/// path via a separate channel embedded in the spawn closure.
///
/// See `start_swarm` for the full subscribe flow via `SubscribeHandle`.
pub struct SubscribeHandle {
    tx: mpsc::Sender<String>,
}

impl SubscribeHandle {
    /// Subscribe to a gossipsub topic by name.
    pub async fn subscribe(&self, topic: &str) -> Result<(), mpsc::error::SendError<String>> {
        self.tx.send(topic.to_owned()).await
    }
}

/// Initialize a libp2p Swarm with gossipsub and start it.
///
/// Returns a `GossipHandle` for sending/receiving messages, a `SubscribeHandle`
/// for subscribing to topics after startup, and the local `PeerId`.
/// The swarm runs in a background tokio task.
///
/// Gossipsub parameters:
/// - mesh_n = 6, mesh_n_low = 4, mesh_n_high = 12
/// - heartbeat_interval = 1 s
/// - max_transmit_size = 1 MiB
pub async fn start_swarm(
    listen_addr: &str,
) -> Result<(GossipHandle, SubscribeHandle, PeerId), Box<dyn std::error::Error>> {
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .mesh_n(6)
        .mesh_n_low(4)
        .mesh_n_high(12)
        .heartbeat_interval(Duration::from_secs(1))
        .max_transmit_size(1_048_576)
        .build()
        .map_err(|e| format!("invalid gossipsub config: {e}"))?;

    let mut swarm: Swarm<gossipsub::Behaviour> = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                e.into()
            })
        })?
        .build();

    let listen: Multiaddr = listen_addr.parse()?;
    swarm.listen_on(listen)?;

    let local_peer_id = *swarm.local_peer_id();

    // Channel: caller -> swarm (publish)
    let (pub_tx, mut pub_rx) = mpsc::channel::<(String, Vec<u8>)>(64);
    // Channel: swarm -> caller (receive)
    let (recv_tx, recv_rx) = mpsc::channel::<(String, Vec<u8>)>(64);
    // Channel: caller -> swarm (subscribe)
    let (sub_tx, mut sub_rx) = mpsc::channel::<String>(16);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Outbound publish request from caller
                maybe_pub = pub_rx.recv() => {
                    match maybe_pub {
                        None => break, // sender dropped; shut down
                        Some((topic_name, data)) => {
                            let topic = IdentTopic::new(topic_name);
                            if let Err(e) = swarm.behaviour_mut().publish(topic, data) {
                                tracing::warn!("gossipsub publish error: {e}");
                            }
                        }
                    }
                }
                // Topic subscription request from caller
                maybe_sub = sub_rx.recv() => {
                    match maybe_sub {
                        None => {} // subscribe handle dropped; ignore
                        Some(topic_name) => {
                            let topic = IdentTopic::new(topic_name.clone());
                            match swarm.behaviour_mut().subscribe(&topic) {
                                Ok(true) => tracing::debug!(topic = %topic_name, "subscribed to topic"),
                                Ok(false) => tracing::debug!(topic = %topic_name, "already subscribed"),
                                Err(e) => tracing::warn!(topic = %topic_name, "subscribe error: {e}"),
                            }
                        }
                    }
                }
                // Swarm event
                event = swarm.next() => {
                    match event {
                        Some(SwarmEvent::NewListenAddr { address, .. }) => {
                            tracing::info!(%address, "gossipsub swarm listening");
                        }
                        Some(SwarmEvent::Behaviour(gossipsub::Event::Message {
                            message,
                            ..
                        })) => {
                            let topic = message.topic.as_str().to_owned();
                            let data = message.data;
                            if recv_tx.send((topic, data)).await.is_err() {
                                tracing::debug!("gossip receiver dropped; stopping swarm");
                                break;
                            }
                        }
                        Some(SwarmEvent::Behaviour(gossipsub::Event::Subscribed {
                            peer_id,
                            topic,
                        })) => {
                            tracing::debug!(%peer_id, %topic, "peer subscribed");
                        }
                        Some(SwarmEvent::Behaviour(gossipsub::Event::Unsubscribed {
                            peer_id,
                            topic,
                        })) => {
                            tracing::debug!(%peer_id, %topic, "peer unsubscribed");
                        }
                        Some(SwarmEvent::Behaviour(gossipsub::Event::GossipsubNotSupported {
                            peer_id,
                        })) => {
                            tracing::debug!(%peer_id, "peer does not support gossipsub");
                        }
                        Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                            tracing::debug!(%peer_id, "connection established");
                        }
                        Some(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                            tracing::debug!(%peer_id, "connection closed");
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
        }
        tracing::debug!("gossipsub swarm task exiting");
    });

    let gossip_handle = GossipHandle {
        tx: pub_tx,
        rx: recv_rx,
    };
    let subscribe_handle = SubscribeHandle { tx: sub_tx };

    Ok((gossip_handle, subscribe_handle, local_peer_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn swarm_starts_and_returns_valid_peer_id() {
        let (_, _, peer_id) = start_swarm("/ip4/127.0.0.1/tcp/0")
            .await
            .expect("swarm should start");

        // PeerId has no concept of "zero"; we verify it round-trips through its string form,
        // which is the canonical way to assert it is a well-formed peer identity.
        let s = peer_id.to_string();
        assert!(!s.is_empty(), "PeerId should have a non-empty string representation");
        let reparsed: PeerId = s.parse().expect("PeerId should parse back from its string form");
        assert_eq!(peer_id, reparsed, "PeerId round-trip through string must be identity");
    }
}
