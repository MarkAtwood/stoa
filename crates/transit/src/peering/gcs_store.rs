//! Google Cloud Storage block store backend for the transit daemon.
//!
//! Wraps [`ObjectStoreBackend`] with a Google Cloud Storage constructor.
//! Supports service account JSON key file, service account JSON key string
//! (via `secretx://`), and Application Default Credentials (ADC).
//!
//! The `IpfsStore` implementation lives in [`object_store_backend`].

use object_store::ObjectStore;
use std::sync::Arc;

use stoa_core::ipfs_backend::GcsBackendConfig;
use stoa_core::secret::resolve_secret_uri;

use crate::peering::object_store_backend::ObjectStoreBackend;

/// IPFS block store backed by Google Cloud Storage.
///
/// Startup: performs a PUT + DELETE probe under `<prefix>/_stoa_write_probe`
/// to verify bucket access before accepting articles.
#[derive(Debug)]
pub struct GcsStore(ObjectStoreBackend);

impl GcsStore {
    /// Build from operator config, resolving any `secretx://` URIs.
    pub async fn new(cfg: &GcsBackendConfig) -> Result<Self, String> {
        use object_store::gcp::GoogleCloudStorageBuilder;

        let sa_key = resolve_secret_uri(
            cfg.service_account_key.clone(),
            "backend.gcs.service_account_key",
        )
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

crate::impl_ipfs_store_via_inner!(GcsStore);
