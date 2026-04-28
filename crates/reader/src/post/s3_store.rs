//! S3-compatible object storage block store backend for the reader daemon.
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
//! `put_raw` and `put_block` always issue a PUT; S3 PUT with the same key and
//! identical content is a no-op at the data level.
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

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};

/// IPFS block store backed by S3-compatible object storage.
#[derive(Debug)]
pub struct S3BlockStore {
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

impl S3BlockStore {
    /// Build an `S3BlockStore` from operator config, resolving any `secretx://` URIs.
    ///
    /// Performs a startup write probe (PUT + DELETE of a zero-byte object) to
    /// verify bucket access before returning.  Returns `Err` if the probe fails.
    pub async fn new(cfg: &S3BackendConfig) -> Result<Self, String> {
        use object_store::aws::AmazonS3Builder;

        let access_key = resolve_secret_or_literal(cfg.access_key_id.as_deref()).await?;
        let secret_key = resolve_secret_or_literal(cfg.secret_access_key.as_deref()).await?;

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

        // Startup probe: verify bucket reachability and write access.
        let probe = OPath::from("_stoa_write_probe");
        store
            .put(&probe, PutPayload::from_static(b""))
            .await
            .map_err(|e| {
                format!(
                    "S3 backend startup probe failed (bucket '{}', region '{}'): {e}",
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

    async fn put_object(&self, cid: &Cid, data: &[u8]) -> Result<(), IpfsWriteError> {
        let path = self.block_path(cid);
        self.store
            .put(&path, PutPayload::from(Bytes::copy_from_slice(data)))
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl IpfsBlockStore for S3BlockStore {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        self.put_object(&cid, data).await?;
        Ok(cid)
    }

    /// Store a block with a caller-supplied pre-computed CID.
    ///
    /// The caller is responsible for ensuring `cid` matches `data`.
    /// Idempotent: re-putting the same CID overwrites with identical content.
    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        self.put_object(&cid, &data).await
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        let path = self.block_path(cid);
        match self.store.get(&path).await {
            Ok(result) => {
                let bytes = result
                    .bytes()
                    .await
                    .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
                Ok(bytes.to_vec())
            }
            Err(object_store::Error::NotFound { .. }) => {
                Err(IpfsWriteError::NotFound(cid.to_string()))
            }
            Err(e) => Err(IpfsWriteError::WriteFailed(e.to_string())),
        }
    }

    /// Remove the object for `cid`.
    ///
    /// Returns [`DeletionOutcome::Immediate`].  Idempotent: if the object does
    /// not exist the call succeeds without error.
    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsWriteError> {
        let path = self.block_path(cid);
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(DeletionOutcome::Immediate),
            Err(e) => Err(IpfsWriteError::WriteFailed(e.to_string())),
        }
    }
}

/// Resolve a config value that may be a `secretx://` URI or a literal string.
///
/// Returns `Ok(None)` if `val` is `None` (credential omitted — use instance
/// profile / IRSA on AWS).
async fn resolve_secret_or_literal(val: Option<&str>) -> Result<Option<String>, String> {
    match val {
        None => Ok(None),
        Some(s) if s.starts_with("secretx:") => {
            let store =
                secretx::from_uri(s).map_err(|e| format!("invalid secretx URI '{s}': {e}"))?;
            let secret = store
                .get()
                .await
                .map_err(|e| format!("secretx retrieval failed for '{s}': {e}"))?;
            let string = std::str::from_utf8(secret.as_bytes())
                .map_err(|e| format!("secretx value for '{s}' is not valid UTF-8: {e}"))?
                .trim_end_matches('\n')
                .to_string();
            Ok(Some(string))
        }
        Some(s) => Ok(Some(s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    fn make_test_store() -> S3BlockStore {
        S3BlockStore::new_with_store(Arc::new(InMemory::new()) as Arc<dyn ObjectStore>, None)
    }

    #[tokio::test]
    async fn round_trip_put_raw_and_get() {
        let store = make_test_store();
        let data = b"hello, s3 reader store";
        let cid = store.put_raw(data).await.expect("put");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn put_block_and_get() {
        let store = make_test_store();
        let data = b"dag-cbor block";
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x71, digest);
        store
            .put_block(cid.clone(), data.to_vec())
            .await
            .expect("put_block");
        let retrieved = store.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn put_is_idempotent() {
        let store = make_test_store();
        let data = b"idempotent write";
        let cid1 = store.put_raw(data).await.expect("put 1");
        let cid2 = store.put_raw(data).await.expect("put 2");
        assert_eq!(cid1, cid2, "same content must produce same CID");
        let retrieved = store.get_raw(&cid1).await.expect("get").to_vec();
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let store = make_test_store();
        let digest = Code::Sha2_256.digest(b"not stored");
        let cid = Cid::new_v1(0x55, digest);
        let result = store.get_raw(&cid).await;
        assert!(
            matches!(result, Err(IpfsWriteError::NotFound(_))),
            "missing block must return NotFound: {result:?}"
        );
    }

    #[tokio::test]
    async fn delete_removes_object_immediately() {
        let store = make_test_store();
        let data = b"to be deleted";
        let cid = store.put_raw(data).await.expect("put");

        store.get_raw(&cid).await.expect("get before must succeed");

        let outcome = store.delete(&cid).await.expect("delete");
        assert_eq!(outcome, DeletionOutcome::Immediate);

        let result = store.get_raw(&cid).await;
        assert!(
            matches!(result, Err(IpfsWriteError::NotFound(_))),
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
    async fn delete_nonexistent_succeeds() {
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
        let store = S3BlockStore::new_with_store(
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
}
