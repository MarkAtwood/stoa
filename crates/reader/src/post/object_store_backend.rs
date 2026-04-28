//! Generic `object_store`-backed block store for the reader daemon.
//!
//! `ObjectStoreBlockBackend` wraps any `object_store::ObjectStore` and
//! exposes the `IpfsBlockStore` trait.  S3, Azure, and GCS backends share
//! this implementation; each provides only a constructor.

use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use object_store::{ObjectStore, PutPayload, path::Path as OPath};
use std::sync::Arc;

use stoa_core::ipfs::DeletionOutcome;

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};

/// Block store backed by any `object_store`-compatible backend.
#[derive(Debug)]
pub struct ObjectStoreBlockBackend {
    pub(crate) store: Arc<dyn ObjectStore>,
    pub(crate) prefix: String,
}

impl ObjectStoreBlockBackend {
    /// Construct with an already-built `ObjectStore`.
    ///
    /// `prefix` defaults to `"blocks"` if `None`.
    pub fn new_with_store(store: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        Self {
            store,
            prefix: prefix.unwrap_or("blocks").to_string(),
        }
    }

    pub(crate) fn block_path(&self, cid: &Cid) -> OPath {
        OPath::from(format!("{}/{}", self.prefix, cid))
    }

    pub(crate) async fn put_object(&self, cid: &Cid, data: &[u8]) -> Result<(), IpfsWriteError> {
        let path = self.block_path(cid);
        self.store
            .put(&path, PutPayload::from(Bytes::copy_from_slice(data)))
            .await
            .map_err(|e| IpfsWriteError::WriteFailed(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl IpfsBlockStore for ObjectStoreBlockBackend {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        self.put_object(&cid, data).await?;
        Ok(cid)
    }

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

    async fn delete(&self, cid: &Cid) -> Result<DeletionOutcome, IpfsWriteError> {
        let path = self.block_path(cid);
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(DeletionOutcome::Immediate),
            Err(e) => Err(IpfsWriteError::WriteFailed(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    fn make_backend() -> ObjectStoreBlockBackend {
        ObjectStoreBlockBackend::new_with_store(
            Arc::new(InMemory::new()) as Arc<dyn ObjectStore>,
            None,
        )
    }

    #[tokio::test]
    async fn round_trip_put_raw_and_get() {
        let b = make_backend();
        let data = b"object_store backend round trip";
        let cid = b.put_raw(data).await.expect("put");
        let retrieved = b.get_raw(&cid).await.expect("get");
        assert_eq!(retrieved, data.to_vec());
    }

    #[tokio::test]
    async fn put_block_and_get() {
        let b = make_backend();
        let data = b"dag-cbor block";
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x71, digest);
        b.put_block(cid.clone(), data.to_vec()).await.expect("put_block");
        assert_eq!(b.get_raw(&cid).await.expect("get"), data.to_vec());
    }

    #[tokio::test]
    async fn put_is_idempotent() {
        let b = make_backend();
        let data = b"idempotent write";
        let cid1 = b.put_raw(data).await.expect("put 1");
        let cid2 = b.put_raw(data).await.expect("put 2");
        assert_eq!(cid1, cid2);
        assert_eq!(b.get_raw(&cid1).await.expect("get"), data.to_vec());
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let b = make_backend();
        let digest = Code::Sha2_256.digest(b"not stored");
        let cid = Cid::new_v1(0x55, digest);
        let result = b.get_raw(&cid).await;
        assert!(matches!(result, Err(IpfsWriteError::NotFound(_))));
    }

    #[tokio::test]
    async fn delete_removes_object_immediately() {
        let b = make_backend();
        let data = b"to be deleted";
        let cid = b.put_raw(data).await.expect("put");
        b.get_raw(&cid).await.expect("get before must succeed");
        assert_eq!(b.delete(&cid).await.expect("delete"), DeletionOutcome::Immediate);
        assert!(matches!(b.get_raw(&cid).await, Err(IpfsWriteError::NotFound(_))));
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
        let b = ObjectStoreBlockBackend::new_with_store(
            Arc::clone(&inner) as Arc<dyn ObjectStore>,
            Some("myprefix"),
        );
        let data = b"prefix test";
        let cid = b.put_raw(data).await.expect("put");
        let expected_path = OPath::from(format!("myprefix/{cid}"));
        assert!(inner.get(&expected_path).await.is_ok());
    }
}
