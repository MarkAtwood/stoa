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
use stoa_core::secret::resolve_secret_uri;

use crate::peering::object_store_backend::ObjectStoreBackend;
use crate::peering::pipeline::IpfsStore;

/// IPFS block store backed by S3-compatible object storage.
///
/// Startup: performs a PUT + DELETE probe under `<prefix>/_stoa_write_probe`
/// to verify bucket access and IAM permissions before accepting articles.
#[derive(Debug)]
pub struct S3Store(ObjectStoreBackend);

impl S3Store {
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

        startup_probe(&store, &prefix, &cfg.bucket, &cfg.region).await?;

        Ok(Self(ObjectStoreBackend::new_with_store(store, Some(&prefix))))
    }

    /// Construct with a caller-supplied `ObjectStore`.  Intended for unit tests.
    pub fn new_with_store(store: Arc<dyn ObjectStore>, prefix: Option<&str>) -> Self {
        Self(ObjectStoreBackend::new_with_store(store, prefix))
    }
}

#[async_trait::async_trait]
impl IpfsStore for S3Store {
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

/// PUT + DELETE a zero-byte probe object under the configured prefix to verify
/// bucket access and IAM permissions before accepting articles.
async fn startup_probe(
    store: &Arc<dyn ObjectStore>,
    prefix: &str,
    bucket: &str,
    region: &str,
) -> Result<(), String> {
    use object_store::{PutPayload, path::Path as OPath};
    let probe = OPath::from(format!("{prefix}/_stoa_write_probe"));
    store
        .put(&probe, PutPayload::from_static(b""))
        .await
        .map_err(|e| {
            format!(
                "S3 backend startup probe failed (bucket '{bucket}', prefix '{prefix}', region '{region}'): {e}"
            )
        })?;
    store.delete(&probe).await.map_err(|e| {
        format!(
            "S3 backend startup probe: DELETE failed (bucket '{bucket}', prefix '{prefix}', \
             region '{region}'): {e} — verify the IAM policy grants s3:DeleteObject on this prefix"
        )
    })?;
    Ok(())
}
