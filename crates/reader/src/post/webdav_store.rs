//! WebDAV block store backend for the reader daemon.
//!
//! Wraps [`ObjectStoreBlockBackend`] with an HTTP/WebDAV constructor.
//! The `IpfsBlockStore` implementation lives in [`object_store_backend`].

use object_store::ObjectStore;
use std::sync::Arc;

use stoa_core::ipfs_backend::WebDavBackendConfig;
use stoa_core::secret::resolve_secret_uri;

use crate::post::ipfs_write::{IpfsBlockStore, IpfsWriteError};
use crate::post::object_store_backend::ObjectStoreBlockBackend;

/// IPFS block store backed by a WebDAV server.
#[derive(Debug)]
pub struct WebDavBlockStore(ObjectStoreBlockBackend);

impl WebDavBlockStore {
    /// Build from operator config, resolving any `secretx://` URIs.
    pub async fn new(cfg: &WebDavBackendConfig) -> Result<Self, String> {
        use base64::Engine as _;
        use object_store::ClientOptions;
        use object_store::http::HttpBuilder;
        use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

        let password =
            resolve_secret_uri(cfg.password.clone(), "backend.webdav.password").await?;

        let mut client_options = ClientOptions::new();
        if cfg.allow_http.unwrap_or(false) {
            client_options = client_options.with_allow_http(true);
        }
        if let (Some(username), Some(pwd)) = (&cfg.username, &password) {
            let credentials =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{pwd}"));
            let auth_value = HeaderValue::from_str(&format!("Basic {credentials}"))
                .map_err(|e| format!("WebDAV backend: invalid credentials: {e}"))?;
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, auth_value);
            client_options = client_options.with_default_headers(headers);
        }

        let store = Arc::new(
            HttpBuilder::new()
                .with_url(&cfg.url)
                .with_client_options(client_options)
                .build()
                .map_err(|e| format!("WebDAV backend init failed: {e}"))?,
        ) as Arc<dyn ObjectStore>;

        let context = format!("WebDAV url '{}'", cfg.url);
        super::object_store_backend::startup_probe(&store, "", &context).await?;

        Ok(Self(ObjectStoreBlockBackend::new_with_store(store, Some(""))))
    }

    /// Construct with a caller-supplied `ObjectStore`.  Intended for unit tests.
    pub fn new_with_store(store: Arc<dyn ObjectStore>) -> Self {
        Self(ObjectStoreBlockBackend::new_with_store(store, Some("")))
    }
}

#[async_trait::async_trait]
impl IpfsBlockStore for WebDavBlockStore {
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

    fn make_test_store() -> WebDavBlockStore {
        WebDavBlockStore::new_with_store(Arc::new(InMemory::new()) as Arc<dyn ObjectStore>)
    }

    #[tokio::test]
    async fn round_trip() {
        let store = make_test_store();
        let data = b"webdav reader round trip";
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
