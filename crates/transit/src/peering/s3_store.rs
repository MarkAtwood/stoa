//! S3-compatible object storage block store backend for the transit daemon.
//!
//! Stores raw block bytes as objects keyed by CID string under a configurable
//! prefix.  Compatible with AWS S3, MinIO, Backblaze B2, Wasabi, and any
//! S3-compatible service via the `object_store` crate.
//!
//! ## Object layout
//!
//! Each block is stored as `<prefix>/<cid-base32-lowercase>`.
//! The prefix defaults to `"blocks"`.
//!
//! ## Idempotency
//!
//! `put_raw` always issues a PUT; S3 PUT with the same key and content is a
//! no-op at the data level.  The object remains unchanged.
//!
//! ## Deletion
//!
//! `delete` issues a DELETE.  If the object does not exist, the call succeeds.
//! Returns [`DeletionOutcome::Immediate`].

use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use object_store::{ObjectStore, PutPayload, path::Path as OPath};
use std::sync::Arc;

use stoa_core::ipfs::DeletionOutcome;
use stoa_core::ipfs_backend::S3BackendConfig;
use stoa_core::secret::resolve_secret_uri;

use crate::peering::pipeline::{IpfsError, IpfsStore};

/// IPFS block store backed by S3-compatible object storage.
#[derive(Debug)]
pub struct S3Store {
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

impl S3Store {
    /// Build an `S3Store` from operator config, resolving any `secretx://` URIs.
    ///
    /// Performs a startup write probe (PUT + DELETE of a zero-byte object) to
    /// verify bucket access before returning.  Returns `Err` if the probe fails.
    pub async fn new(cfg: &S3BackendConfig) -> Result<Self, String> {
        use object_store::aws::AmazonS3Builder;

        let access_key = resolve_secret_uri(cfg.access_key_id.clone(), "backend.s3.access_key_id").await?;
        let secret_key = resolve_secret_uri(cfg.secret_access_key.clone(), "backend.s3.secret_access_key").await?;

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

        // Startup probe: verify bucket reachability and write access under the
        // configured prefix so that prefix-restricted IAM policies are exercised.
        let probe = OPath::from(format!("{prefix}/_stoa_write_probe"));
        store
            .put(&probe, PutPayload::from_static(b""))
            .await
            .map_err(|e| {
                format!(
                    "S3 backend startup probe failed (bucket '{}', prefix '{prefix}', region '{}'): {e}",
                    cfg.bucket, cfg.region
                )
            })?;
        let _ = store.delete(&probe).await; // best-effort; harmless if it lingers

        Ok(Self { store, prefix })
    }

    /// Construct with a caller-supplied `ObjectStore` implementation.
    ///
    /// Intended for unit tests; use `new` in production.
    pub fn new_with_store(store: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        Self {
            store,
            prefix: prefix.unwrap_or("blocks").to_string(),
        }
    }

    fn block_path(&self, cid: &Cid) -> OPath {
        OPath::from(format!("{}/{}", self.prefix, cid))
    }
}

#[async_trait]
impl IpfsStore for S3Store {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        let path = self.block_path(&cid);
        self.store
            .put(&path, PutPayload::from(Bytes::copy_from_slice(data)))
            .await
            .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
        Ok(cid)
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Option<Vec<u8>>, IpfsError> {
        let path = self.block_path(cid);
        match self.store.get(&path).await {
            Ok(result) => {
                let bytes = result
                    .bytes()
                    .await
                    .map_err(|e| IpfsError::WriteFailed(e.to_string()))?;
                Ok(Some(bytes.to_vec()))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(IpfsError::WriteFailed(e.to_string())),
        }
    }

    /// Remove the object for `cid`.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: if the object does
    /// not exist the call succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsError> {
        let path = self.block_path(cid);
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(DeletionOutcome::Immediate),
            Err(e) => Err(IpfsError::WriteFailed(e.to_string())),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    fn make_test_store() -> S3Store {
        S3Store::new_with_store(Arc::new(InMemory::new()) as Arc<dyn ObjectStore>, None)
    }

    #[tokio::test]
    async fn round_trip_put_and_get() {
        let store = make_test_store();
        let data = b"hello, s3 transit store";
        let cid = store.put_raw(data).await.expect("put");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(
            retrieved,
            Some(data.to_vec()),
            "retrieved bytes must match stored bytes"
        );
    }

    #[tokio::test]
    async fn put_is_idempotent() {
        let store = make_test_store();
        let data = b"idempotent write";
        let cid1 = store.put_raw(data).await.expect("put 1");
        let cid2 = store.put_raw(data).await.expect("put 2");
        assert_eq!(cid1, cid2, "same content must produce same CID");
        let retrieved = store.get_raw(&cid1).await.expect("get").expect("Some");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = make_test_store();
        let digest = Code::Sha2_256.digest(b"not stored");
        let cid = Cid::new_v1(0x55, digest);
        let result = store.get_raw(&cid).await.expect("get");
        assert!(result.is_none(), "missing block must return None");
    }

    #[tokio::test]
    async fn delete_removes_object_immediately() {
        let store = make_test_store();
        let data = b"to be deleted";
        let cid = store.put_raw(data).await.expect("put");

        assert!(store.get_raw(&cid).await.expect("get before").is_some());

        let outcome = store.delete(&cid).await.expect("delete");
        assert_eq!(outcome, DeletionOutcome::Immediate);

        assert!(
            store.get_raw(&cid).await.expect("get after").is_none(),
            "object must be gone after delete"
        );
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let store = make_test_store();
        let data = b"double delete";
        let cid = store.put_raw(data).await.expect("put");
        store.delete(&cid).await.expect("delete 1");
        store.delete(&cid).await.expect("delete 2 must not error");
    }

    #[tokio::test]
    async fn delete_nonexistent_cid_succeeds() {
        let store = make_test_store();
        let digest = Code::Sha2_256.digest(b"never stored");
        let cid = Cid::new_v1(0x55, digest);
        store
            .delete(&cid)
            .await
            .expect("delete of missing CID must succeed");
    }

    #[tokio::test]
    async fn prefix_is_applied_to_object_path() {
        let inner = Arc::new(InMemory::new());
        let store = S3Store::new_with_store(
            Arc::clone(&inner) as Arc<dyn ObjectStore>,
            Some("myprefix"),
        );
        let data = b"prefix test";
        let cid = store.put_raw(data).await.expect("put");
        let expected_path = OPath::from(format!("myprefix/{cid}"));
        let result = inner.get(&expected_path).await;
        assert!(
            result.is_ok(),
            "object must be stored under the configured prefix"
        );
    }

    #[tokio::test]
    async fn concurrent_reads_no_contention() {
        let store = Arc::new(make_test_store());
        let data = b"concurrent read data";
        let cid = store.put_raw(data).await.expect("put");

        let mut handles = Vec::new();
        for _ in 0..10 {
            let store = Arc::clone(&store);
            let cid = cid.clone();
            handles.push(tokio::spawn(async move { store.get_raw(&cid).await }));
        }
        for handle in handles {
            let result = handle.await.expect("task").expect("get");
            assert_eq!(result, Some(data.to_vec()));
        }
    }
}
