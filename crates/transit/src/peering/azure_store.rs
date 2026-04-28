//! Azure Blob Storage block store backend for the transit daemon.
//!
//! Wraps [`ObjectStoreBackend`] with a Microsoft Azure Blob Storage constructor.
//! Supports Azure Blob Storage (account + access key, managed identity, SAS) and
//! the Azurite local emulator.
//!
//! The `IpfsStore` implementation lives in [`object_store_backend`].

use object_store::ObjectStore;
use std::sync::Arc;

use stoa_core::ipfs_backend::AzureBackendConfig;
use stoa_core::secret::resolve_secret_uri;

use crate::peering::object_store_backend::ObjectStoreBackend;
use crate::peering::pipeline::IpfsStore;

/// IPFS block store backed by Azure Blob Storage.
///
/// Startup: performs a PUT + DELETE probe under `<prefix>/_stoa_write_probe`
/// to verify container access before accepting articles.
#[derive(Debug)]
pub struct AzureStore(ObjectStoreBackend);

impl AzureStore {
    /// Build from operator config, resolving any `secretx://` URIs.
    pub async fn new(cfg: &AzureBackendConfig) -> Result<Self, String> {
        use object_store::azure::MicrosoftAzureBuilder;

        let access_key =
            resolve_secret_uri(cfg.access_key.clone(), "backend.azure.access_key").await?;

        let mut builder = MicrosoftAzureBuilder::new()
            .with_account(&cfg.account)
            .with_container_name(&cfg.container);
        if let Some(key) = access_key {
            builder = builder.with_access_key(key);
        }
        if let Some(endpoint) = &cfg.endpoint {
            builder = builder.with_endpoint(endpoint.clone());
        }
        if cfg.use_emulator.unwrap_or(false) {
            builder = builder.with_use_emulator(true);
        }
        if cfg.allow_http.unwrap_or(false) {
            builder = builder.with_allow_http(true);
        }
        let store = Arc::new(
            builder
                .build()
                .map_err(|e| format!("Azure backend init failed: {e}"))?,
        ) as Arc<dyn ObjectStore>;
        let prefix = cfg.prefix.as_deref().unwrap_or("blocks").to_string();

        startup_probe(&store, &prefix, &cfg.account, &cfg.container).await?;

        Ok(Self(ObjectStoreBackend::new_with_store(store, Some(&prefix))))
    }

    /// Construct with a caller-supplied `ObjectStore`.  Intended for unit tests.
    pub fn new_with_store(store: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        Self(ObjectStoreBackend::new_with_store(store, prefix))
    }
}

#[async_trait::async_trait]
impl IpfsStore for AzureStore {
    async fn put_raw(&self, data: &[u8]) -> Result<cid::Cid, crate::peering::pipeline::IpfsError> {
        self.0.put_raw(data).await
    }
    async fn get_raw(
        &self,
        cid: &cid::Cid,
    ) -> Result<Option<Vec<u8>>, crate::peering::pipeline::IpfsError> {
        self.0.get_raw(cid).await
    }
    async fn delete(
        &self,
        cid: &cid::Cid,
    ) -> Result<stoa_core::ipfs::DeletionOutcome, crate::peering::pipeline::IpfsError> {
        self.0.delete(cid).await
    }
}

async fn startup_probe(
    store: &Arc<dyn ObjectStore>,
    prefix: &str,
    account: &str,
    container: &str,
) -> Result<(), String> {
    use object_store::{PutPayload, path::Path as OPath};
    let probe = OPath::from(format!("{prefix}/_stoa_write_probe"));
    store
        .put(&probe, PutPayload::from_static(b""))
        .await
        .map_err(|e| {
            format!(
                "Azure backend startup probe failed (account '{account}', container '{container}', prefix '{prefix}'): {e}"
            )
        })?;
    store.delete(&probe).await.map_err(|e| {
        format!(
            "Azure backend startup probe: DELETE failed (account '{account}', \
             container '{container}', prefix '{prefix}'): {e} — \
             verify the storage account allows delete operations on this container"
        )
    })?;
    Ok(())
}
