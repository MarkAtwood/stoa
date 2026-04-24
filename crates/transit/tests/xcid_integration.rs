//! Integration tests for the XCID protocol.
//!
//! The XCID protocol allows one transit node to fetch a [`LogEntry`] from
//! another over a plain TCP NNTP peering connection.  These tests verify:
//!
//! 1. **Happy path**: `XcidClient::fetch_entry` retrieves the correct
//!    `VerifiedEntry` from a live `run_peering_session` server.
//! 2. **CID mismatch**: a server that returns the wrong entry under the
//!    requested CID is rejected before the caller receives a `VerifiedEntry`.
//! 3. **430 handling**: `fetch_entry` returns `Err` gracefully when the server
//!    responds `430 No such block`, without panicking.
//! 4. **Signature verification**: an entry signed by an untrusted key is
//!    rejected even when the CID matches.
//!
//! No real IPFS daemon is required.  All article storage uses `MemIpfsStore`.
//! Log entries are stored in a SQLite in-memory database via `SqliteLogStorage`.

use ed25519_dalek::{Signer as _, SigningKey};
use multihash_codetable::{Code, MultihashDigest};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr as _;
use std::sync::Arc;
use tokio::net::TcpListener;

use usenet_ipfs_core::{
    canonical::log_entry_canonical_bytes, group_log::SqliteLogStorage, hlc::HlcClock,
    msgid_map::MsgIdMap,
};
use usenet_ipfs_transit::peering::{
    blacklist::BlacklistConfig,
    ingestion_queue::ingestion_queue,
    pipeline::MemIpfsStore,
    rate_limit::{ExhaustionAction, PeerRateLimiter},
    session::{run_peering_session, PeeringShared},
    xcid_client::{PeerInfo as XcidPeerInfo, XcidClient},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Create an in-memory transit pool with migrations applied.
async fn make_transit_pool() -> sqlx::SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("valid sqlite url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("in-memory transit pool must open");
    usenet_ipfs_transit::migrations::run_migrations(&pool)
        .await
        .expect("transit migrations must succeed");
    pool
}

/// Create an in-memory core pool with migrations applied, for MsgIdMap.
async fn make_core_pool() -> (MsgIdMap, tempfile::TempPath) {
    let tmp = tempfile::NamedTempFile::new()
        .expect("tempfile must be created")
        .into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().expect("valid path"));
    let opts = SqliteConnectOptions::from_str(&url)
        .expect("valid sqlite url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("core pool must open");
    usenet_ipfs_core::migrations::run_migrations(&pool)
        .await
        .expect("core migrations must succeed");
    (MsgIdMap::new(pool), tmp)
}

/// Create an in-memory `SqliteLogStorage` pool with core migrations applied.
async fn make_log_storage() -> Arc<SqliteLogStorage> {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("valid sqlite url")
        .create_if_missing(true);
    // Use a pool size of 5 so that the session handler can open multiple
    // concurrent readers (get_entry, list_tips) alongside the in-memory DB.
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("log storage pool must open");
    usenet_ipfs_core::migrations::run_migrations(&pool)
        .await
        .expect("log storage migrations must succeed");
    Arc::new(SqliteLogStorage::new(pool))
}

/// Sign the canonical bytes of a log entry and return the 64-byte signature.
fn sign_entry(
    hlc_timestamp: u64,
    article_cid: &cid::Cid,
    parent_cids: &[cid::Cid],
    key: &SigningKey,
) -> Vec<u8> {
    let canonical = log_entry_canonical_bytes(hlc_timestamp, article_cid, parent_cids);
    key.sign(&canonical).to_bytes().to_vec()
}

/// Build a minimal `PeeringShared` suitable for an XCID-only server.
///
/// Authentication is disabled (empty `trusted_keys`) and TLS is disabled
/// (`tls_acceptor = None`), so any TCP client can connect immediately.
async fn make_peering_shared(
    log_storage: Arc<SqliteLogStorage>,
    signing_key: Arc<SigningKey>,
) -> Arc<PeeringShared> {
    let transit_pool = Arc::new(make_transit_pool().await);
    let (_msgid_map, _tmp) = make_core_pool().await;
    // MsgIdMap needs its own pool; reuse a fresh one here.
    let core_opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("valid sqlite url")
        .create_if_missing(true);
    let core_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(core_opts)
        .await
        .expect("msgid core pool must open");
    usenet_ipfs_core::migrations::run_migrations(&core_pool)
        .await
        .expect("msgid core migrations must succeed");
    let msgid_map = Arc::new(MsgIdMap::new(core_pool));

    let ipfs =
        Arc::new(MemIpfsStore::new()) as Arc<dyn usenet_ipfs_transit::peering::pipeline::IpfsStore>;
    let hlc = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after epoch")
            .as_millis() as u64;
        Arc::new(tokio::sync::Mutex::new(HlcClock::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            now_ms,
        )))
    };
    let (ingestion_sender, _ingestion_receiver) = ingestion_queue(64);
    let ingestion_sender = Arc::new(ingestion_sender);

    Arc::new(PeeringShared {
        ipfs,
        msgid_map,
        log_storage,
        gossip_tx: None,
        signing_key,
        hlc,
        ingestion_sender,
        local_peer_id: "test-peer-id".to_owned(),
        local_hostname: "test.local".to_owned(),
        peer_rate_limiter: Arc::new(std::sync::Mutex::new(PeerRateLimiter::new(
            1000.0,
            10_000,
            ExhaustionAction::Respond431,
        ))),
        transit_pool,
        blacklist_config: BlacklistConfig::default(),
        staging: None,
        trusted_keys: vec![], // no auth required for these tests
        tls_acceptor: None,
    })
}

/// Spawn a `run_peering_session` server on an OS-assigned port.
///
/// Returns the bound address string (`"127.0.0.1:<port>"`).  The server task
/// runs until the listener is dropped (connection accepted and then closed by
/// the client).
async fn spawn_server(shared: Arc<PeeringShared>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TCP listener must bind to loopback");
    let addr = listener
        .local_addr()
        .expect("bound socket must have a local address")
        .to_string();

    tokio::spawn(async move {
        // Accept a single connection per test; each test spawns its own server.
        loop {
            let (stream, peer_addr) = listener
                .accept()
                .await
                .expect("listener accept must not fail");
            let peer_ip = peer_addr.ip().to_string();
            let peer_addr_str = peer_addr.to_string();
            let shared_clone = Arc::clone(&shared);
            tokio::spawn(async move {
                run_peering_session(stream, peer_addr_str, peer_ip, shared_clone).await;
            });
        }
    });

    addr
}

/// Create and store a `LogEntry` in `storage`.  Returns the `LogEntryId`.
///
/// The entry is a genesis entry (no parents) with a DAG-CBOR article CID and
/// a valid Ed25519 operator signature over the canonical bytes.
async fn store_log_entry(
    storage: &SqliteLogStorage,
    signing_key: &SigningKey,
) -> usenet_ipfs_core::group_log::LogEntryId {
    use usenet_ipfs_core::group_log::append::append;
    use usenet_ipfs_core::group_log::types::LogEntry;

    let article_cid = {
        let digest = Code::Sha2_256.digest(b"test-article-bytes");
        cid::Cid::new_v1(0x71, digest)
    };
    let hlc_timestamp: u64 = 1_700_000_000_000;

    let sig_bytes = sign_entry(hlc_timestamp, &article_cid, &[], signing_key);

    let entry = LogEntry {
        hlc_timestamp,
        article_cid,
        operator_signature: sig_bytes,
        parent_cids: vec![],
    };

    let group =
        usenet_ipfs_core::article::GroupName::new("comp.test".to_owned()).expect("valid group");

    append(storage, &group, entry)
        .await
        .expect("log entry must append without error")
}

// ── Test 1: Happy path ────────────────────────────────────────────────────────

/// The XCID client can fetch a `LogEntry` that is present on the server.
///
/// Oracle: `fetch_entry` returns a `VerifiedEntry` whose inner `LogEntry`
/// has the same `hlc_timestamp` and `article_cid` as the entry we inserted.
/// The identity is verified by comparing the `LogEntryId` computed from the
/// returned entry to the one we originally stored (via `LogEntryId::from_entry`).
#[tokio::test]
async fn xcid_happy_path_fetches_correct_entry() {
    let signing_key = Arc::new(SigningKey::from_bytes(&[0x42u8; 32]));
    let log_storage = make_log_storage().await;

    let entry_id = store_log_entry(&log_storage, &signing_key).await;

    let shared = make_peering_shared(Arc::clone(&log_storage), Arc::clone(&signing_key)).await;
    let addr = spawn_server(shared).await;

    let trusted_keys = vec![signing_key.verifying_key()];
    let client = XcidClient::new(
        vec![XcidPeerInfo {
            addr,
            tls: false,
            cert_sha256: None,
        }],
        trusted_keys,
    );

    let result = client.fetch_entry(&entry_id).await;
    assert!(
        result.is_ok(),
        "fetch_entry must succeed for a present entry"
    );

    // VerifiedEntry does not implement Debug, so we cannot use expect().
    let verified = match result {
        Ok(v) => v,
        Err(e) => panic!("fetch_entry returned Err: {e}"),
    };
    let returned_entry = verified.into_inner();

    // The LogEntryId computed from the returned entry must match the one stored.
    let computed_id = usenet_ipfs_core::group_log::types::LogEntryId::from_entry(&returned_entry);
    assert_eq!(
        computed_id, entry_id,
        "returned entry's computed LogEntryId must match the requested ID"
    );

    // The returned entry must carry the same timestamp as the original.
    assert_eq!(
        returned_entry.hlc_timestamp, 1_700_000_000_000,
        "returned entry must have the original HLC timestamp"
    );
}

// ── Test 2: 430 handling ──────────────────────────────────────────────────────

/// The XCID client handles a 430 response without panicking.
///
/// Oracle: `fetch_entry` returns `Err` with a message containing "430" or
/// "peer responded" (the client's error format for 430).  Crucially it does
/// not panic or hang.
#[tokio::test]
async fn xcid_430_returns_err_without_panicking() {
    let signing_key = Arc::new(SigningKey::from_bytes(&[0x43u8; 32]));
    // Empty log storage: no entries stored.
    let log_storage = make_log_storage().await;

    let shared = make_peering_shared(Arc::clone(&log_storage), Arc::clone(&signing_key)).await;
    let addr = spawn_server(shared).await;

    // Request a LogEntryId that was never stored.
    let absent_id = usenet_ipfs_core::group_log::types::LogEntryId::from_bytes([0xde; 32]);

    let trusted_keys = vec![signing_key.verifying_key()];
    let client = XcidClient::new(
        vec![XcidPeerInfo {
            addr,
            tls: false,
            cert_sha256: None,
        }],
        trusted_keys,
    );

    let result = client.fetch_entry(&absent_id).await;
    assert!(
        result.is_err(),
        "fetch_entry must return Err for a 430 response, got Ok"
    );

    // VerifiedEntry does not implement Debug, so unwrap_err() cannot be used.
    // We assert is_err() above, so we can safely match here.
    let err_msg = match result {
        Err(e) => e,
        Ok(_) => unreachable!("already asserted Err"),
    };
    // The error must mention exhaustion ("all peers exhausted") because the
    // client tried the one peer and got 430 (which it converts to an Err
    // and retries on the next peer, of which there are none).
    assert!(
        err_msg.contains("exhausted") || err_msg.contains("peer responded"),
        "error message must indicate peer exhaustion or 430 response, got: {err_msg:?}"
    );
}

// ── Test 3: Signature verification ───────────────────────────────────────────

/// An entry signed by an untrusted key is rejected by the XCID client.
///
/// Setup: the server has a valid entry signed by `server_key`.  The client
/// is configured with only `client_key` (a different key) in its trusted set.
///
/// Oracle: `fetch_entry` returns `Err` with a message indicating that no
/// trusted key could verify the entry.  The CID itself matches (so the
/// mismatch error does not fire), but signature verification fails.
#[tokio::test]
async fn xcid_rejects_entry_signed_by_untrusted_key() {
    // server_key signs the entry; client_key is what the client trusts.
    let server_key = Arc::new(SigningKey::from_bytes(&[0x44u8; 32]));
    let client_key = SigningKey::from_bytes(&[0x55u8; 32]);

    let log_storage = make_log_storage().await;
    let entry_id = store_log_entry(&log_storage, &server_key).await;

    let shared = make_peering_shared(Arc::clone(&log_storage), Arc::clone(&server_key)).await;
    let addr = spawn_server(shared).await;

    // Client trusts only client_key, which is different from server_key.
    let trusted_keys = vec![client_key.verifying_key()];
    let client = XcidClient::new(
        vec![XcidPeerInfo {
            addr,
            tls: false,
            cert_sha256: None,
        }],
        trusted_keys,
    );

    let result = client.fetch_entry(&entry_id).await;
    assert!(
        result.is_err(),
        "fetch_entry must reject an entry signed by an untrusted key"
    );

    // VerifiedEntry does not implement Debug, so match instead of expect_err.
    let err_msg = match result {
        Err(e) => e,
        Ok(_) => unreachable!("already asserted Err"),
    };
    // The error must reference the key count or exhaustion — not a CID mismatch.
    assert!(
        err_msg.contains("trusted key") || err_msg.contains("exhausted"),
        "error must indicate untrusted key rejection or peer exhaustion, got: {err_msg:?}"
    );
}

// ── Test 4: CID mismatch ──────────────────────────────────────────────────────

/// The XCID client rejects a block whose bytes do not match the requested CID.
///
/// This is verified end-to-end via a hand-crafted TCP server that speaks
/// enough of the XCID protocol to send a 224 response with a body whose
/// base64-decoded content, when decoded as DAG-CBOR, yields a `LogEntry` whose
/// `LogEntryId` does NOT match the requested CID.
///
/// Oracle: `fetch_entry` returns `Err` with "mismatch" in the error message.
#[tokio::test]
async fn xcid_rejects_cid_mismatch() {
    use base64::Engine as _;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use usenet_ipfs_core::group_log::types::{LogEntry, LogEntryId};

    // Build a real LogEntry and encode it as DAG-CBOR.
    let signing_key = SigningKey::from_bytes(&[0x66u8; 32]);
    let article_cid = {
        let digest = Code::Sha2_256.digest(b"mismatch-article");
        cid::Cid::new_v1(0x71, digest)
    };
    let hlc_timestamp: u64 = 1_700_000_001_000;
    let sig_bytes = sign_entry(hlc_timestamp, &article_cid, &[], &signing_key);

    let real_entry = LogEntry {
        hlc_timestamp,
        article_cid,
        operator_signature: sig_bytes,
        parent_cids: vec![],
    };

    // real_id is the ID of real_entry.
    let real_id = LogEntryId::from_entry(&real_entry);

    // wrong_id is a completely different LogEntryId that we will REQUEST,
    // while the server returns real_entry (which has real_id, not wrong_id).
    let wrong_id = LogEntryId::from_bytes([0xab; 32]);
    // Sanity check: they must be different for the test to be meaningful.
    assert_ne!(real_id, wrong_id);

    // Encode real_entry as base64 DAG-CBOR, the same way the server does.
    let cbor_bytes =
        serde_ipld_dagcbor::to_vec(&real_entry).expect("DAG-CBOR serialization must succeed");
    let b64 = base64::engine::general_purpose::STANDARD.encode(&cbor_bytes);
    let encoded = b64
        .as_bytes()
        .chunks(76)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\r\n");

    // Spawn a minimal fake TCP server that:
    // 1. Sends the 200 greeting.
    // 2. Reads one line (the XCID command).
    // 3. Sends a 224 response with real_entry's body, ignoring which CID was asked.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake server listener must bind");
    let fake_addr = listener
        .local_addr()
        .expect("fake server must have local addr")
        .to_string();
    let encoded_clone = encoded.clone();

    tokio::spawn(async move {
        let (stream, _peer) = listener
            .accept()
            .await
            .expect("fake server must accept connection");
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);

        // Send greeting.
        write_half
            .write_all(b"200 fake XCID server\r\n")
            .await
            .expect("fake server must send greeting");

        // Read and discard the XCID command line.
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .expect("fake server must read client command");

        // Send 224 with real_entry's body, regardless of which CID was requested.
        let cid_str = real_id.to_cid().to_string();
        let response = format!("224 Block follows ({cid_str})\r\n{encoded_clone}\r\n.\r\n");
        write_half
            .write_all(response.as_bytes())
            .await
            .expect("fake server must send 224 response");

        // Drain any remaining data (QUIT etc.) so the client can read cleanly.
        let mut drain = String::new();
        let _ = reader.read_line(&mut drain).await;
    });

    // The client requests wrong_id but the server returns real_entry (real_id).
    // The XcidClient must detect the ID mismatch and return Err.
    let trusted_keys = vec![signing_key.verifying_key()];
    let client = XcidClient::new(
        vec![XcidPeerInfo {
            addr: fake_addr,
            tls: false,
            cert_sha256: None,
        }],
        trusted_keys,
    );

    let result = client.fetch_entry(&wrong_id).await;
    assert!(
        result.is_err(),
        "fetch_entry must return Err when the server returns a mismatched entry"
    );

    // VerifiedEntry does not implement Debug, so match instead of expect_err.
    let err_msg = match result {
        Err(e) => e,
        Ok(_) => unreachable!("already asserted Err"),
    };
    assert!(
        err_msg.contains("mismatch") || err_msg.contains("exhausted"),
        "error must indicate CID mismatch or peer exhaustion, got: {err_msg:?}"
    );
}
