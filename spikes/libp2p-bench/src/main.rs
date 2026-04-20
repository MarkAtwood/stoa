/// libp2p-bench: minimal bitswap-style block exchange benchmark
///
/// Approach: implements Want/Have/Block exchange semantics using libp2p's
/// request_response behaviour over TCP (loopback). This is the same logical
/// exchange as bitswap's core path (requester sends a want-block message,
/// responder replies with the block) without the full bitswap session/ledger/
/// want-list machinery.  Using request_response was chosen over implementing
/// the full bitswap state machine because the goal is a latency signal, not a
/// bitswap-compatible peer — the extra complexity of sessions/ledgers/want-lists
/// would not change the per-round-trip latency being measured.
///
/// Two in-process swarms on TCP loopback. Provider holds one block; requester
/// fetches it 1000 times. p50/p99/p99.9 latencies in microseconds are reported.
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    noise, request_response,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use sha2::{Digest, Sha256};
use sysinfo::System;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Wire types: Want/Block exchange
// ---------------------------------------------------------------------------

/// A want-block request: the raw CID bytes the requester wants.
#[derive(Debug, Clone)]
struct WantRequest {
    cid_bytes: Vec<u8>,
}

/// A block response: the CID and its raw data bytes.
#[derive(Debug, Clone)]
struct BlockResponse {
    cid_bytes: Vec<u8>,
    data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Codec: simple 4-byte big-endian length-prefixed encoding
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct BitswapCodec;

#[async_trait]
impl request_response::Codec for BitswapCodec {
    type Protocol = StreamProtocol;
    type Request = WantRequest;
    type Response = BlockResponse;

    async fn read_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let cid_bytes = read_lp(io).await?;
        Ok(WantRequest { cid_bytes })
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let cid_bytes = read_lp(io).await?;
        let data = read_lp(io).await?;
        Ok(BlockResponse { cid_bytes, data })
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_lp(io, &req.cid_bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_lp(io, &resp.cid_bytes).await?;
        write_lp(io, &resp.data).await
    }
}

// ---------------------------------------------------------------------------
// Minimal framing: 4-byte big-endian length prefix
// ---------------------------------------------------------------------------

async fn read_lp<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 4 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_lp<T: AsyncWrite + Unpin + Send>(io: &mut T, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(data).await
}

// ---------------------------------------------------------------------------
// CID helpers: CIDv1 sha2-256 raw codec (0x55)
// Multihash layout: varint(0x12) || varint(32) || sha256_digest
// CID layout:       varint(1)    || varint(0x55) || multihash
// ---------------------------------------------------------------------------

fn encode_varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}

fn make_cid(data: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(data);
    let mut mh = Vec::with_capacity(34);
    encode_varint(0x12, &mut mh); // sha2-256 function code
    encode_varint(32, &mut mh);   // digest length
    mh.extend_from_slice(&digest);

    let mut cid = Vec::with_capacity(2 + 34);
    encode_varint(1, &mut cid);    // CIDv1
    encode_varint(0x55, &mut cid); // raw codec
    cid.extend_from_slice(&mh);
    cid
}

// ---------------------------------------------------------------------------
// Swarm builder
// ---------------------------------------------------------------------------

type Behaviour = request_response::Behaviour<BitswapCodec>;
type BenchSwarm = Swarm<Behaviour>;

fn make_swarm() -> BenchSwarm {
    let protocol = StreamProtocol::new("/usenet-ipfs/bitswap/1.0.0");
    let behaviour = request_response::Behaviour::new(
        vec![(protocol, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    );

    libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("tcp transport")
        .with_behaviour(|_| behaviour)
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build()
}

// ---------------------------------------------------------------------------
// Statistics helpers
// ---------------------------------------------------------------------------

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p / 100.0).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ---------------------------------------------------------------------------
// Provider task: listens for want requests, serves the block it holds
// ---------------------------------------------------------------------------

async fn run_provider(
    mut swarm: BenchSwarm,
    store: HashMap<Vec<u8>, Vec<u8>>,
    addr_tx: tokio::sync::oneshot::Sender<(Multiaddr, PeerId)>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let peer_id = *swarm.local_peer_id();
    let mut addr_tx_opt = Some(addr_tx);

    loop {
        tokio::select! {
            event = swarm.next() => {
                let event = match event {
                    Some(e) => e,
                    None => break,
                };
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if let Some(tx) = addr_tx_opt.take() {
                            let _ = tx.send((address, peer_id));
                        }
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Request { request, channel, .. },
                        ..
                    }) => {
                        let resp = if let Some(data) = store.get(&request.cid_bytes) {
                            BlockResponse {
                                cid_bytes: request.cid_bytes,
                                data: data.clone(),
                            }
                        } else {
                            BlockResponse {
                                cid_bytes: vec![],
                                data: vec![],
                            }
                        };
                        let _ = swarm.behaviour_mut().send_response(channel, resp);
                    }
                    _ => {}
                }
            }
            _ = shutdown_rx.recv() => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Requester: connects to provider, sends N want requests, records latencies
// ---------------------------------------------------------------------------

async fn run_requester(
    mut swarm: BenchSwarm,
    provider_addr: Multiaddr,
    provider_peer: PeerId,
    cid: Vec<u8>,
    iterations: usize,
) -> Vec<u64> {
    swarm.dial(provider_addr).unwrap();

    // Wait for connection establishment
    loop {
        if let SwarmEvent::ConnectionEstablished { .. } = swarm.next().await.unwrap() {
            break;
        }
    }

    let mut latencies = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let req = WantRequest { cid_bytes: cid.clone() };
        let t0 = Instant::now();
        swarm.behaviour_mut().send_request(&provider_peer, req);

        loop {
            match swarm.next().await.unwrap() {
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { .. },
                    ..
                }) => {
                    latencies.push(t0.elapsed().as_micros() as u64);
                    break;
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure {
                    error, ..
                }) => {
                    panic!("outbound failure: {error:?}");
                }
                _ => {}
            }
        }
    }

    latencies
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let iterations = 1000usize;
    let block_data =
        b"Hello, usenet-ipfs! This is a test block for the libp2p bitswap benchmark.".to_vec();
    let block_cid = make_cid(&block_data);

    println!("libp2p bitswap-style block exchange benchmark");
    println!("Protocol: request_response over TCP loopback");
    println!("Exchange: WantRequest(cid) -> BlockResponse(cid, data)");
    println!("Block:    {} bytes", block_data.len());
    println!("Iterations: {iterations}");
    println!();

    // RSS before
    let mut sys = System::new_all();
    sys.refresh_all();
    let self_pid = sysinfo::Pid::from(std::process::id() as usize);
    let rss_before = sys.process(self_pid).map(|p| p.memory()).unwrap_or(0);

    // Build provider store
    let mut store = HashMap::new();
    store.insert(block_cid.clone(), block_data.clone());

    // Spin up provider
    let provider_swarm = make_swarm();
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    let provider_handle = tokio::spawn(run_provider(
        provider_swarm,
        store,
        addr_tx,
        shutdown_rx,
    ));

    let (provider_addr, provider_peer) = addr_rx.await.expect("provider ready");
    println!("Provider: {provider_addr}/p2p/{provider_peer}");

    // Warm-up: one round-trip not counted
    {
        let ws = make_swarm();
        let _warmup = run_requester(ws, provider_addr.clone(), provider_peer, block_cid.clone(), 1).await;
    }

    // Benchmark
    let requester_swarm = make_swarm();
    let latencies = run_requester(
        requester_swarm,
        provider_addr,
        provider_peer,
        block_cid,
        iterations,
    )
    .await;

    // Shut down provider
    let _ = shutdown_tx.send(()).await;
    drop(shutdown_tx);
    let _ = provider_handle.await;

    // RSS after
    sys.refresh_all();
    let rss_after = sys.process(self_pid).map(|p| p.memory()).unwrap_or(0);
    let peak_rss_kb = rss_after / 1024;
    let rss_delta_kb = rss_after.saturating_sub(rss_before) / 1024;

    // Statistics
    let mut sorted = latencies.clone();
    sorted.sort_unstable();

    let p50 = percentile(&sorted, 50.0);
    let p99 = percentile(&sorted, 99.0);
    let p999 = percentile(&sorted, 99.9);
    let mean = sorted.iter().sum::<u64>() / sorted.len() as u64;
    let min = sorted[0];
    let max = *sorted.last().unwrap();

    println!();
    println!("=== Results ===");
    println!("Iterations:  {iterations}");
    println!("Min:         {min} µs");
    println!("Mean:        {mean} µs");
    println!("p50:         {p50} µs");
    println!("p99:         {p99} µs");
    println!("p99.9:       {p999} µs");
    println!("Max:         {max} µs");
    println!("Peak RSS:    {peak_rss_kb} KB");
    println!("RSS delta:   {rss_delta_kb} KB");
}
