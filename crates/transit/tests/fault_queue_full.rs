//! Regression tests for stoa-bt5.1: queue-full must return 431/436,
//! not 239/235 with a silently discarded article.
//!
//! Independent oracle: RFC 4644 §2.5 — 239 "Article transferred OK" must only
//! be sent when the article has been accepted.  431 "Try sending it again
//! later" is the correct transient-failure code for TAKETHIS.
//! RFC 977 §3.8 — 436 "Transfer failed, try again later" is the correct code
//! for IHAVE when the server cannot accept the article due to a transient error.
//!
//! Each test spins up a real `run_peering_session` task over a loopback TCP
//! connection, pre-fills the ingestion queue to capacity, then sends an
//! article and checks that no 239/235 response is returned.

use ed25519_dalek::SigningKey;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr as _;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use stoa_core::{group_log::SqliteLogStorage, hlc::HlcClock, msgid_map::MsgIdMap};
use stoa_transit::peering::{
    blacklist::BlacklistConfig,
    ingestion_queue::{ingestion_queue, QueuedArticle},
    pipeline::MemIpfsStore,
    rate_limit::{ExhaustionAction, PeerRateLimiter},
    session::{run_peering_session, PeeringShared},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn make_core_pool() -> (MsgIdMap, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().unwrap());
    let opts = SqliteConnectOptions::from_str(&url)
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    stoa_core::migrations::run_migrations(&pool).await.unwrap();
    (MsgIdMap::new(pool), tmp)
}

async fn make_transit_pool() -> sqlx::SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    stoa_transit::migrations::run_migrations(&pool)
        .await
        .unwrap();
    pool
}

async fn make_log_storage() -> SqliteLogStorage {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    stoa_core::migrations::run_migrations(&pool).await.unwrap();
    SqliteLogStorage::new(pool)
}

fn make_article(msgid: &str) -> String {
    format!(
        "From: test@example.com\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         Message-ID: {msgid}\r\n\
         Newsgroups: comp.test\r\n\
         Subject: Queue full regression test\r\n\
         \r\n\
         Body text.\r\n"
    )
}

/// Dot-stuff and terminate an article for the NNTP wire.
fn dot_stuff(article: &str) -> String {
    let mut out = String::new();
    for line in article.split("\r\n") {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(".\r\n");
    out
}

/// Bind a loopback listener and return it plus its local address.
async fn bind_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

// ── Test 1: TAKETHIS returns 431 when queue is full ───────────────────────────

/// RFC 4644 §2.5: 239 must only be sent when the article is accepted.
/// When the ingestion queue is full, 431 must be returned and record_accepted()
/// must not be called.
///
/// Verified by:
/// 1. Pre-filling the queue to capacity so the next enqueue will fail.
/// 2. Confirming the session returns 431 (not 239) for TAKETHIS.
/// 3. Confirming the `rejected_full_total` metric incremented (proving the
///    article was never placed in the queue).
#[tokio::test]
async fn takethis_queue_full_returns_431_not_239() {
    let (msgid_map, _tmp) = make_core_pool().await;
    let transit_pool = make_transit_pool().await;
    let log_storage = make_log_storage().await;

    // Queue depth = 1; we fill it before the session starts.
    let (sender, _rx) = ingestion_queue(1);
    let filler = QueuedArticle {
        bytes: b"filler".to_vec(),
        message_id: "<filler@fill.test>".to_owned(),
    };
    sender.try_enqueue(filler).await.unwrap();
    assert_eq!(sender.depth(), 1, "queue must be full before test");

    let rejected_before = sender.metrics().rejected_full_total.load(Ordering::Relaxed);

    let shared = Arc::new(PeeringShared {
        ipfs: Arc::new(MemIpfsStore::new()),
        msgid_map: Arc::new(msgid_map),
        log_storage: Arc::new(log_storage),
        signing_key: Arc::new(SigningKey::from_bytes(&[0x42u8; 32])),
        hlc: Arc::new(Mutex::new(HlcClock::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            1_700_000_000_000,
        ))),
        ingestion_sender: Arc::new(sender),
        local_hostname: "test.local".to_owned(),
        peer_rate_limiter: Arc::new(std::sync::Mutex::new(PeerRateLimiter::new(
            1000.0,
            10000,
            ExhaustionAction::Respond431,
        ))),
        transit_pool: Arc::new(transit_pool),
        blacklist_config: BlacklistConfig::default(),
        trusted_keys: Vec::new(),
        tls_acceptor: None,
        staging: None,
        verification_store: None,
        dkim_authenticator: None,
    });

    let (listener, addr) = bind_listener().await;
    let shared_clone = Arc::clone(&shared);
    tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();
        run_peering_session(
            stream,
            addr.to_string(),
            addr.ip().to_string(),
            shared_clone,
        )
        .await;
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let (reader_half, mut writer) = client.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read greeting (200).
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.starts_with("200"),
        "expected 200 greeting, got: {line:?}"
    );

    // Enter streaming mode.
    writer.write_all(b"MODE STREAM\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.starts_with("203"),
        "expected 203 MODE STREAM, got: {line:?}"
    );

    // Send TAKETHIS for a new article.
    let msgid = "<queue-full-takethis@test.example>";
    let cmd = format!("TAKETHIS {msgid}\r\n");
    writer.write_all(cmd.as_bytes()).await.unwrap();

    let article = make_article(msgid);
    let wire = dot_stuff(&article);
    writer.write_all(wire.as_bytes()).await.unwrap();

    // Read response.
    line.clear();
    reader.read_line(&mut line).await.unwrap();

    // Must be 431 (try again later), NOT 239 (accepted).
    assert!(
        line.starts_with("431"),
        "queue-full TAKETHIS must return 431 (RFC 4644 §2.5), got: {line:?}"
    );
    assert!(
        !line.starts_with("239"),
        "queue-full TAKETHIS must NOT return 239, got: {line:?}"
    );

    // Confirm the queue metric recorded the rejection.
    let rejected_after = shared
        .ingestion_sender
        .metrics()
        .rejected_full_total
        .load(Ordering::Relaxed);
    assert_eq!(
        rejected_after,
        rejected_before + 1,
        "rejected_full_total must increment by 1 when queue is full"
    );

    writer.write_all(b"QUIT\r\n").await.unwrap();
}

// ── Test 2: IHAVE returns 436 when queue is full ──────────────────────────────

/// RFC 977 §3.8: 235 must only be sent when the article is accepted.
/// When the ingestion queue is full, 436 must be returned and record_accepted()
/// must not be called.
#[tokio::test]
async fn ihave_queue_full_returns_436_not_235() {
    let (msgid_map, _tmp) = make_core_pool().await;
    let transit_pool = make_transit_pool().await;
    let log_storage = make_log_storage().await;

    // Queue depth = 1; fill it before the session starts.
    let (sender, _rx) = ingestion_queue(1);
    let filler = QueuedArticle {
        bytes: b"filler".to_vec(),
        message_id: "<filler2@fill.test>".to_owned(),
    };
    sender.try_enqueue(filler).await.unwrap();
    assert_eq!(sender.depth(), 1, "queue must be full before test");

    let rejected_before = sender.metrics().rejected_full_total.load(Ordering::Relaxed);

    let shared = Arc::new(PeeringShared {
        ipfs: Arc::new(MemIpfsStore::new()),
        msgid_map: Arc::new(msgid_map),
        log_storage: Arc::new(log_storage),
        signing_key: Arc::new(SigningKey::from_bytes(&[0x42u8; 32])),
        hlc: Arc::new(Mutex::new(HlcClock::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            1_700_000_000_000,
        ))),
        ingestion_sender: Arc::new(sender),
        local_hostname: "test.local".to_owned(),
        peer_rate_limiter: Arc::new(std::sync::Mutex::new(PeerRateLimiter::new(
            1000.0,
            10000,
            ExhaustionAction::Respond431,
        ))),
        transit_pool: Arc::new(transit_pool),
        blacklist_config: BlacklistConfig::default(),
        trusted_keys: Vec::new(),
        tls_acceptor: None,
        staging: None,
        verification_store: None,
        dkim_authenticator: None,
    });

    let (listener, addr) = bind_listener().await;
    let shared_clone = Arc::clone(&shared);
    tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();
        run_peering_session(
            stream,
            addr.to_string(),
            addr.ip().to_string(),
            shared_clone,
        )
        .await;
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let (reader_half, mut writer) = client.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read greeting.
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.starts_with("200"),
        "expected 200 greeting, got: {line:?}"
    );

    // IHAVE pre-check: offer the article.
    let msgid = "<queue-full-ihave@test.example>";
    let cmd = format!("IHAVE {msgid}\r\n");
    writer.write_all(cmd.as_bytes()).await.unwrap();

    // Server must respond 335 "Send it".
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.starts_with("335"),
        "expected 335 Send it from IHAVE pre-check, got: {line:?}"
    );

    // Send the article.
    let article = make_article(msgid);
    let wire = dot_stuff(&article);
    writer.write_all(wire.as_bytes()).await.unwrap();

    // Read final response.
    line.clear();
    reader.read_line(&mut line).await.unwrap();

    // Must be 436 (transient failure), NOT 235 (accepted).
    assert!(
        line.starts_with("436"),
        "queue-full IHAVE must return 436 (RFC 977 §3.8), got: {line:?}"
    );
    assert!(
        !line.starts_with("235"),
        "queue-full IHAVE must NOT return 235, got: {line:?}"
    );

    // Confirm the queue metric recorded the rejection.
    let rejected_after = shared
        .ingestion_sender
        .metrics()
        .rejected_full_total
        .load(Ordering::Relaxed);
    assert_eq!(
        rejected_after,
        rejected_before + 1,
        "rejected_full_total must increment by 1 when queue is full"
    );

    writer.write_all(b"QUIT\r\n").await.unwrap();
}

// ── Test 3: TAKETHIS succeeds (239) when queue has space ─────────────────────

/// Positive control: when the queue is not full, TAKETHIS must return 239.
/// This ensures the fix did not break the normal success path.
#[tokio::test]
async fn takethis_queue_not_full_returns_239() {
    let (msgid_map, _tmp) = make_core_pool().await;
    let transit_pool = make_transit_pool().await;
    let log_storage = make_log_storage().await;

    // Queue has plenty of space.
    let (sender, _rx) = ingestion_queue(100);

    let shared = Arc::new(PeeringShared {
        ipfs: Arc::new(MemIpfsStore::new()),
        msgid_map: Arc::new(msgid_map),
        log_storage: Arc::new(log_storage),
        signing_key: Arc::new(SigningKey::from_bytes(&[0x42u8; 32])),
        hlc: Arc::new(Mutex::new(HlcClock::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            1_700_000_000_000,
        ))),
        ingestion_sender: Arc::new(sender),
        local_hostname: "test.local".to_owned(),
        peer_rate_limiter: Arc::new(std::sync::Mutex::new(PeerRateLimiter::new(
            1000.0,
            10000,
            ExhaustionAction::Respond431,
        ))),
        transit_pool: Arc::new(transit_pool),
        blacklist_config: BlacklistConfig::default(),
        trusted_keys: Vec::new(),
        tls_acceptor: None,
        staging: None,
        verification_store: None,
        dkim_authenticator: None,
    });

    let (listener, addr) = bind_listener().await;
    let shared_clone = Arc::clone(&shared);
    tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();
        run_peering_session(
            stream,
            addr.to_string(),
            addr.ip().to_string(),
            shared_clone,
        )
        .await;
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let (reader_half, mut writer) = client.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Greeting.
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("200"), "expected 200 greeting: {line:?}");

    // Enter streaming mode.
    writer.write_all(b"MODE STREAM\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("203"), "expected 203: {line:?}");

    // TAKETHIS with a new article.
    let msgid = "<success-takethis@test.example>";
    let cmd = format!("TAKETHIS {msgid}\r\n");
    writer.write_all(cmd.as_bytes()).await.unwrap();
    let wire = dot_stuff(&make_article(msgid));
    writer.write_all(wire.as_bytes()).await.unwrap();

    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.starts_with("239"),
        "TAKETHIS with space in queue must return 239 (RFC 4644 §2.5), got: {line:?}"
    );

    assert_eq!(
        shared.ingestion_sender.depth(),
        1,
        "queue depth must be 1 after one successful TAKETHIS"
    );

    writer.write_all(b"QUIT\r\n").await.unwrap();
}
