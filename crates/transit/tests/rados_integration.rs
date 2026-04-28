//! Integration tests for the Ceph RADOS block store backend.
//!
//! These tests require a live Ceph cluster.  They are skipped automatically
//! when the `TEST_RADOS_CONF` environment variable is not set.
//!
//! ## Running locally
//!
//! ```sh
//! docker-compose -f docker-compose.ceph.yml up -d
//! # Wait ~60 s for the cluster to become healthy.
//! docker exec stoa_test_ceph ceph osd pool create stoa_test 8
//! docker exec stoa_test_ceph cat /etc/ceph/ceph.conf > /tmp/ceph.conf
//! export TEST_RADOS_CONF=/tmp/ceph.conf
//! export TEST_RADOS_POOL=stoa_test
//! export TEST_RADOS_USER=admin
//! cargo test --features rados -p stoa-transit --test rados_integration
//! docker-compose -f docker-compose.ceph.yml down -v
//! ```

#![cfg(feature = "rados")]

use stoa_core::ipfs_backend::RadosBackendConfig;
use stoa_transit::peering::pipeline::IpfsStore;
use stoa_transit::peering::rados_store::RadosStore;

/// Returns `Some(RadosBackendConfig)` when env vars are set, `None` to skip.
fn live_config() -> Option<RadosBackendConfig> {
    let conf_path = std::env::var("TEST_RADOS_CONF").ok()?;
    let pool = std::env::var("TEST_RADOS_POOL").ok()?;
    let user = std::env::var("TEST_RADOS_USER").unwrap_or_else(|_| "admin".into());
    Some(RadosBackendConfig {
        conf_path,
        pool,
        user,
    })
}

#[tokio::test]
async fn live_round_trip() {
    let cfg = match live_config() {
        Some(c) => c,
        None => return,
    };
    let store = RadosStore::open(&cfg).expect("RADOS connect must succeed");
    let data = b"stoa RADOS round-trip test payload";
    let cid = store.put_raw(data).await.expect("put_raw");
    let got = store
        .get_raw(&cid)
        .await
        .expect("get_raw")
        .expect("must be Some");
    assert_eq!(got, data.as_slice());
    store.delete(&cid).await.expect("delete");
}

#[tokio::test]
async fn live_idempotent_put() {
    let cfg = match live_config() {
        Some(c) => c,
        None => return,
    };
    let store = RadosStore::open(&cfg).expect("RADOS connect must succeed");
    let data = b"idempotent RADOS block";
    let cid = store.put_raw(data).await.expect("first put");
    store
        .put_raw(data)
        .await
        .expect("second put must succeed (rados_write_full is idempotent)");
    let got = store
        .get_raw(&cid)
        .await
        .expect("get_raw")
        .expect("must be Some");
    assert_eq!(got, data.as_slice());
    store.delete(&cid).await.expect("cleanup");
}

#[tokio::test]
async fn live_get_missing_returns_none() {
    let cfg = match live_config() {
        Some(c) => c,
        None => return,
    };
    let store = RadosStore::open(&cfg).expect("RADOS connect must succeed");
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};
    let phantom = Cid::new_v1(
        0x55,
        Code::Sha2_256.digest(b"phantom-rados-object-never-written"),
    );
    let result = store
        .get_raw(&phantom)
        .await
        .expect("get_raw must not error");
    assert!(result.is_none(), "get of missing object must return None");
}

#[tokio::test]
async fn live_delete_missing_is_ok() {
    let cfg = match live_config() {
        Some(c) => c,
        None => return,
    };
    let store = RadosStore::open(&cfg).expect("RADOS connect must succeed");
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};
    let phantom = Cid::new_v1(0x55, Code::Sha2_256.digest(b"phantom-rados-delete-missing"));
    store
        .delete(&phantom)
        .await
        .expect("delete of missing object must be Ok (idempotent)");
}

#[tokio::test]
async fn live_delete_makes_get_return_none() {
    let cfg = match live_config() {
        Some(c) => c,
        None => return,
    };
    let store = RadosStore::open(&cfg).expect("RADOS connect must succeed");
    let data = b"block to delete";
    let cid = store.put_raw(data).await.expect("put");
    store.delete(&cid).await.expect("delete");
    let result = store
        .get_raw(&cid)
        .await
        .expect("get after delete must not error");
    assert!(result.is_none(), "get after delete must return None");
}
