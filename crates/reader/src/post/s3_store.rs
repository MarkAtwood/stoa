//! S3-compatible object storage block store backend for the reader daemon.
//!
//! Wraps [`ObjectStoreBlockBackend`] with an AWS S3 / S3-compatible constructor.
//! Compatible with AWS S3, MinIO, Backblaze B2, Wasabi, Cloudflare R2, Garage,
//! and any other S3-compatible service via the `object_store` crate.
//!
//! The `IpfsBlockStore` implementation lives in [`object_store_backend`].

use object_store::ObjectStore;
use std::sync::Arc;

use stoa_core::ipfs_backend::S3BackendConfig;
use stoa_core::secret::resolve_secret_uri;

use crate::post::object_store_backend::ObjectStoreBlockBackend;

/// IPFS block store backed by S3-compatible object storage.
#[derive(Debug)]
pub struct S3BlockStore(ObjectStoreBlockBackend);

impl S3BlockStore {
    /// Build from operator config, resolving any `secretx://` URIs.
    pub async fn new(cfg: &S3BackendConfig) -> Result<Self, String> {
        use object_store::aws::AmazonS3Builder;

        let access_key =
            resolve_secret_uri(cfg.access_key_id.clone(), "backend.s3.access_key_id").await?;
        let secret_key =
            resolve_secret_uri(cfg.secret_access_key.clone(), "backend.s3.secret_access_key")
                .await?;

        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&cfg.bucket)
            .with_region(&cfg.region);
        if let Some(endpoint) = &cfg.endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        if let Some(key) = access_key {
            builder = builder.with_access_key_id(key);
        }
        if let Some(secret) = secret_key {
            builder = builder.with_secret_access_key(secret);
        }
        if cfg.allow_http.unwrap_or(false) {
            builder = builder.with_allow_http(true);
        }
        let store = Arc::new(
            builder
                .build()
                .map_err(|e| format!("S3 backend init failed: {e}"))?,
        ) as Arc<dyn ObjectStore>;
        let prefix = cfg.prefix.as_deref().unwrap_or("blocks").to_string();

        let context = format!("S3 bucket '{}', prefix '{}', region '{}'", cfg.bucket, prefix, cfg.region);
        super::object_store_backend::startup_probe(&store, &prefix, &context).await?;

        Ok(Self(ObjectStoreBlockBackend::new_with_store(store, Some(&prefix))))
    }

    /// Construct with a caller-supplied `ObjectStore`.  Intended for unit tests.
    pub fn new_with_store(store: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        Self(ObjectStoreBlockBackend::new_with_store(store, prefix))
    }
}

crate::impl_ipfs_block_store_via_inner!(S3BlockStore);


// ── Tests ─────────────────────────────────────────────────────────────────────
//
// Smoke tests for the S3BlockStore wrapper constructor.  Full get/put/delete
// coverage (idempotency, prefix handling, codec round-trips) lives in
// `object_store_backend` tests, which exercise the shared implementation path
// that all object-store backends (S3, Azure, GCS) go through.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};
    use object_store::memory::InMemory;
    use stoa_core::ipfs::DeletionOutcome;

    fn make_test_store() -> S3BlockStore {
        S3BlockStore::new_with_store(Arc::new(InMemory::new()) as Arc<dyn ObjectStore>, None)
    }

    #[tokio::test]
    async fn round_trip() {
        let store = make_test_store();
        let data = b"s3 reader round trip";
        let cid = store.put_raw(data).await.expect("put");
        assert_eq!(store.get_raw(&cid).await.expect("get"), data.to_vec());
    }

    #[tokio::test]
    async fn delete_removes_object() {
        let store = make_test_store();
        let data = b"to be deleted";
        let cid = store.put_raw(data).await.expect("put");
        assert_eq!(store.delete(&cid).await.expect("delete"), DeletionOutcome::Immediate);
        assert!(matches!(store.get_raw(&cid).await, Err(IpfsWriteError::NotFound(_))));
    }
}
