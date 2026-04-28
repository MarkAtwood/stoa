//! Generic `object_store`-backed block store for the transit daemon.
//!
//! `ObjectStoreBackend` wraps any `object_store::ObjectStore` implementation
//! and exposes the `IpfsStore` trait.  All S3, Azure, and GCS backends share
//! this implementation; each backend module provides only a constructor.

use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use object_store::{ObjectStore, PutPayload, path::Path as OPath};
use std::sync::Arc;

use stoa_core::ipfs::DeletionOutcome;

use crate::peering::pipeline::{IpfsError, IpfsStore};

/// Block store backed by any `object_store`-compatible backend.
///
/// Used by the S3, Azure, and GCS store modules; each provides only a
/// backend-specific constructor that builds an `ObjectStore` and wraps it
/// here.
#[derive(Debug)]
pub struct ObjectStoreBackend {
    pub(crate) store: Arc<dyn ObjectStore>,
    pub(crate) prefix: String,
}

impl ObjectStoreBackend {
    /// Construct with an already-built `ObjectStore`.
    ///
    /// `prefix` defaults to `"blocks"` if `None`.
    /// Intended for unit tests; production constructors live in the backend modules.
    pub fn new_with_store(store: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        let raw = prefix.unwrap_or("blocks");
        Self {
            store,
            prefix: raw.trim_matches('/').to_string(),
        }
    }

    pub(crate) fn block_path(&self, cid: &Cid) -> OPath {
        OPath::from(format!("{}/{}", self.prefix, cid))
    }
}

#[async_trait]
impl IpfsStore for ObjectStoreBackend {
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
                    .map_err(|e| IpfsError::ReadFailed(e.to_string()))?;
                Ok(Some(bytes.to_vec()))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(IpfsError::ReadFailed(e.to_string())),
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

    fn make_backend() -> ObjectStoreBackend {
        ObjectStoreBackend::new_with_store(
            Arc::new(InMemory::new()) as Arc<dyn ObjectStore>,
            None,
        )
    }

    #[tokio::test]
    async fn round_trip_put_and_get() {
        let b = make_backend();
        let data = b"object_store backend round trip";
        let cid = b.put_raw(data).await.expect("put");
        let retrieved = b.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn put_is_idempotent() {
        let b = make_backend();
        let data = b"idempotent write";
        let cid1 = b.put_raw(data).await.expect("put 1");
        let cid2 = b.put_raw(data).await.expect("put 2");
        assert_eq!(cid1, cid2);
        assert_eq!(b.get_raw(&cid1).await.expect("get"), Some(data.to_vec()));
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let b = make_backend();
        let digest = Code::Sha2_256.digest(b"not stored");
        let cid = Cid::new_v1(0x55, digest);
        assert!(b.get_raw(&cid).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn delete_removes_object_immediately() {
        let b = make_backend();
        let data = b"to be deleted";
        let cid = b.put_raw(data).await.expect("put");
        assert!(b.get_raw(&cid).await.expect("get before").is_some());
        assert_eq!(b.delete(&cid).await.expect("delete"), DeletionOutcome::Immediate);
        assert!(b.get_raw(&cid).await.expect("get after").is_none());
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let b = make_backend();
        let data = b"double delete";
        let cid = b.put_raw(data).await.expect("put");
        b.delete(&cid).await.expect("delete 1");
        b.delete(&cid).await.expect("delete 2 must not error");
    }

    #[tokio::test]
    async fn delete_nonexistent_succeeds() {
        let b = make_backend();
        let digest = Code::Sha2_256.digest(b"never stored");
        let cid = Cid::new_v1(0x55, digest);
        b.delete(&cid).await.expect("delete of missing CID must succeed");
    }

    #[tokio::test]
    async fn prefix_is_applied_to_object_path() {
        let inner = Arc::new(InMemory::new());
        let b = ObjectStoreBackend::new_with_store(
            Arc::clone(&inner) as Arc<dyn ObjectStore>,
            Some("myprefix"),
        );
        let data = b"prefix test";
        let cid = b.put_raw(data).await.expect("put");
        let expected_path = OPath::from(format!("myprefix/{cid}"));
        assert!(inner.get(&expected_path).await.is_ok());
    }
}
