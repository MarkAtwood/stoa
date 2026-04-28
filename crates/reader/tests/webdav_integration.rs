//! WebDAV block store live integration tests.
//!
//! These tests require a running WebDAV server. Set `TEST_WEBDAV_URL` to the
//! server base URL before running:
//!
//! ```sh
//! docker-compose -f docker-compose.webdav.yml up -d
//! TEST_WEBDAV_URL=http://localhost:8181/ \
//!   cargo test -p stoa-reader --test webdav_integration
//! docker-compose -f docker-compose.webdav.yml down -v
//! ```
//!
//! Optional credentials: `TEST_WEBDAV_USERNAME`, `TEST_WEBDAV_PASSWORD`.
//!
//! If `TEST_WEBDAV_URL` is not set, every test returns immediately (skip).

use stoa_core::ipfs::DeletionOutcome;
use stoa_core::ipfs_backend::WebDavBackendConfig;
use stoa_reader::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};
use stoa_reader::post::webdav_store::WebDavBlockStore;

/// Build a live `WebDavBlockStore` from env vars.  Returns `None` to skip.
async fn live_store() -> Option<WebDavBlockStore> {
    let url = std::env::var("TEST_WEBDAV_URL").ok()?;
    let cfg = WebDavBackendConfig {
        url,
        username: std::env::var("TEST_WEBDAV_USERNAME").ok(),
        password: std::env::var("TEST_WEBDAV_PASSWORD").ok(),
        allow_http: Some(true),
    };
    match WebDavBlockStore::new(&cfg).await {
        Ok(store) => Some(store),
        Err(e) => panic!("WebDavBlockStore::new failed: {e}"),
    }
}

/// Put a block and read it back; bytes must match exactly.
#[tokio::test]
async fn live_round_trip() {
    let store = match live_store().await {
        Some(s) => s,
        None => return,
    };

    let data = b"stoa webdav live round-trip test payload";
    let cid = store.put_raw(data).await.expect("put_raw must succeed");
    let got = store.get_raw(&cid).await.expect("get_raw must succeed");
    assert_eq!(got, data.as_slice(), "round-trip data must match");
}

/// Putting the same block twice must succeed (idempotent put).
#[tokio::test]
async fn live_idempotent_put() {
    let store = match live_store().await {
        Some(s) => s,
        None => return,
    };

    let data = b"idempotent put test block";
    let cid = store.put_raw(data).await.expect("first put must succeed");
    store
        .put_block(cid, data.to_vec())
        .await
        .expect("second put of same CID must succeed");
    let got = store.get_raw(&cid).await.expect("get after idempotent put");
    assert_eq!(got, data.as_slice());
}

/// Deleting a block that does not exist must return `Ok(Immediate)` — not an error.
#[tokio::test]
async fn live_delete_missing_is_ok() {
    let store = match live_store().await {
        Some(s) => s,
        None => return,
    };

    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    // Fabricate a CID that was never written.
    let phantom_cid = Cid::new_v1(
        0x55,
        Code::Sha2_256.digest(b"phantom-block-that-was-never-written"),
    );

    let outcome = store
        .delete(&phantom_cid)
        .await
        .expect("delete of missing block must return Ok, not Err");
    assert_eq!(
        outcome,
        DeletionOutcome::Immediate,
        "delete of missing block must return Immediate"
    );
}

/// Reading a block that was deleted must return `NotFound`.
#[tokio::test]
async fn live_get_after_delete_returns_not_found() {
    let store = match live_store().await {
        Some(s) => s,
        None => return,
    };

    let data = b"block to be deleted";
    let cid = store.put_raw(data).await.expect("put must succeed");
    store.delete(&cid).await.expect("delete must succeed");

    match store.get_raw(&cid).await {
        Err(IpfsWriteError::NotFound(_)) => {}
        other => panic!("expected NotFound after delete, got: {other:?}"),
    }
}
