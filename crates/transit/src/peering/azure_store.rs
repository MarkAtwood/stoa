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
use stoa_core::secret::{resolve_secret_uri, SecretError};

use crate::peering::object_store_backend::ObjectStoreBackend;

/// IPFS block store backed by Azure Blob Storage.
///
/// Startup: performs a PUT + DELETE probe under `<prefix>/_stoa_write_probe`
/// to verify container access before accepting articles.
#[derive(Debug)]
pub struct AzureStore(ObjectStoreBackend);

impl AzureStore {
    /// Build from operator config, resolving any `secretx://` URIs.
    pub async fn new(cfg: &AzureBackendConfig) -> Result<Self, SecretError> {
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
            if !cfg.use_emulator.unwrap_or(false) {
                tracing::warn!(
                    "Azure backend: allow_http = true without use_emulator; \
                     traffic to Azure Blob Storage will be transmitted unencrypted"
                );
            }
            builder = builder.with_allow_http(true);
        }
        let store = Arc::new(
            builder
                .build()
                .map_err(|e| SecretError::Retrieval(format!("Azure backend init failed: {e}")))?,
        ) as Arc<dyn ObjectStore>;
        let prefix = cfg.prefix.as_deref().unwrap_or("blocks").to_string();

        let context = format!(
            "Azure account '{}', container '{}', prefix '{}'",
            cfg.account, cfg.container, prefix
        );
        super::object_store_backend::startup_probe(&store, &prefix, &context)
            .await
            .map_err(SecretError::Retrieval)?;

        Ok(Self(ObjectStoreBackend::new_with_store(
            store,
            Some(&prefix),
        )))
    }

    /// Construct with a caller-supplied `ObjectStore`.  Intended for unit tests.
    pub fn new_with_store(store: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        Self(ObjectStoreBackend::new_with_store(store, prefix))
    }
}

crate::impl_ipfs_store_via_inner!(AzureStore);
