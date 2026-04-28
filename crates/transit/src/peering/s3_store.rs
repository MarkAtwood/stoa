//! S3-compatible object storage block store backend for the transit daemon.
//!
//! Wraps [`ObjectStoreBackend`] with an AWS S3 / S3-compatible constructor.
//! Compatible with AWS S3, MinIO, Backblaze B2, Wasabi, Cloudflare R2, Garage,
//! and any other S3-compatible service via the `object_store` crate.
//!
//! The `IpfsStore` implementation lives in [`object_store_backend`].

use object_store::ObjectStore;
use std::sync::Arc;

use stoa_core::ipfs_backend::S3BackendConfig;
use stoa_core::secret::{resolve_secret_uri, SecretError};

use crate::peering::object_store_backend::ObjectStoreBackend;

/// IPFS block store backed by S3-compatible object storage.
///
/// Startup: performs a PUT + DELETE probe under `<prefix>/_stoa_write_probe`
/// to verify bucket access and IAM permissions before accepting articles.
#[derive(Debug)]
pub struct S3Store(ObjectStoreBackend);

impl S3Store {
    /// Build from operator config, resolving any `secretx://` URIs.
    pub async fn new(cfg: &S3BackendConfig) -> Result<Self, SecretError> {
        use object_store::aws::AmazonS3Builder;

        let access_key =
            resolve_secret_uri(cfg.access_key_id.clone(), "backend.s3.access_key_id").await?;
        let secret_key = resolve_secret_uri(
            cfg.secret_access_key.clone(),
            "backend.s3.secret_access_key",
        )
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
                .map_err(|e| SecretError::Retrieval(format!("S3 backend init failed: {e}")))?,
        ) as Arc<dyn ObjectStore>;
        let prefix = cfg.prefix.as_deref().unwrap_or("blocks").to_string();

        let context = format!(
            "S3 bucket '{}', prefix '{}', region '{}'",
            cfg.bucket, prefix, cfg.region
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

crate::impl_ipfs_store_via_inner!(S3Store);
