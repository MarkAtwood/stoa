//! Google Cloud Storage block store backend for the reader daemon.
//!
//! Wraps [`ObjectStoreBlockBackend`] with a GCS constructor.
//! The `IpfsBlockStore` implementation lives in [`object_store_backend`].

use object_store::ObjectStore;
use std::sync::Arc;

use stoa_core::ipfs_backend::GcsBackendConfig;
use stoa_core::secret::resolve_secret_uri;

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};
use crate::post::object_store_backend::ObjectStoreBlockBackend;

/// IPFS block store backed by Google Cloud Storage.
#[derive(Debug)]
pub struct GcsBlockStore(ObjectStoreBlockBackend);

impl GcsBlockStore {
    /// Build from operator config, resolving any `secretx://` URIs.
    pub async fn new(cfg: &GcsBackendConfig) -> Result<Self, String> {
        use object_store::gcp::GoogleCloudStorageBuilder;

        let sa_key =
            resolve_secret_uri(cfg.service_account_key.clone(), "backend.gcs.service_account_key")
                .await?;

        let mut builder = GoogleCloudStorageBuilder::new().with_bucket_name(&cfg.bucket);
        if let Some(path) = &cfg.service_account_path {
            builder = builder.with_service_account_path(path);
        }
        if let Some(key_json) = sa_key {
            builder = builder.with_service_account_key(key_json);
        }
        let store = Arc::new(
            builder
                .build()
                .map_err(|e| format!("GCS backend init failed: {e}"))?,
        ) as Arc<dyn ObjectStore>;
        let prefix = cfg.prefix.as_deref().unwrap_or("blocks").to_string();

        let context = format!("GCS bucket '{}', prefix '{}'", cfg.bucket, prefix);
        super::object_store_backend::startup_probe(&store, &prefix, &context).await?;

        Ok(Self(ObjectStoreBlockBackend::new_with_store(store, Some(&prefix))))
    }

    /// Construct with a caller-supplied `ObjectStore`.  Intended for unit tests.
    pub fn new_with_store(store: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        Self(ObjectStoreBlockBackend::new_with_store(store, prefix))
    }
}

#[async_trait::async_trait]
impl IpfsBlockStore for GcsBlockStore {
    async fn put_raw(&self, data: &[u8]) -> Result<cid::Cid, IpfsWriteError> {
        self.0.put_raw(data).await
    }
    async fn put_block(&self, cid: cid::Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        self.0.put_block(cid, data).await
    }
    async fn get_raw(&self, cid: &cid::Cid) -> Result<Vec<u8>, IpfsWriteError> {
        self.0.get_raw(cid).await
    }
    async fn delete(
        &self,
        cid: &cid::Cid,
    ) -> Result<stoa_core::ipfs::DeletionOutcome, IpfsWriteError> {
        self.0.delete(cid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use stoa_core::ipfs::DeletionOutcome;

    fn make_test_store() -> GcsBlockStore {
        GcsBlockStore::new_with_store(Arc::new(InMemory::new()) as Arc<dyn ObjectStore>, None)
    }

    #[tokio::test]
    async fn round_trip() {
        let store = make_test_store();
        let data = b"gcs reader round trip";
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
