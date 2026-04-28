//! WebDAV block store backend for the transit daemon.
//!
//! Wraps [`ObjectStoreBackend`] with an HTTP/WebDAV constructor.
//! The `IpfsStore` implementation lives in [`object_store_backend`].

use object_store::ObjectStore;
use std::sync::Arc;

use stoa_core::ipfs_backend::WebDavBackendConfig;
use stoa_core::secret::resolve_secret_uri;

use crate::peering::object_store_backend::ObjectStoreBackend;
use crate::peering::pipeline::IpfsStore;

/// IPFS block store backed by a WebDAV server.
///
/// Startup: performs a PUT + DELETE probe at `<url>/_stoa_write_probe`
/// to verify server access and write permissions before accepting articles.
#[derive(Debug)]
pub struct WebDavStore(ObjectStoreBackend);

impl WebDavStore {
    /// Build from operator config, resolving any `secretx://` URIs.
    pub async fn new(cfg: &WebDavBackendConfig) -> Result<Self, String> {
        use base64::Engine as _;
        use object_store::http::HttpBuilder;
        use object_store::ClientOptions;
        use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

        let password = resolve_secret_uri(cfg.password.clone(), "backend.webdav.password").await?;

        let mut client_options = ClientOptions::new();
        if cfg.allow_http.unwrap_or(false) {
            if password.is_some() {
                tracing::warn!(
                    "WebDAV backend: allow_http = true with credentials configured; \
                     password will be transmitted in plaintext"
                );
            }
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
        // The WebDAV URL is the collection root; no subdirectory prefix is used.
        // Passing Some("") to new_with_store results in blocks stored at
        // <url>/<cid> and the startup probe at <url>/_stoa_write_probe.
        super::object_store_backend::startup_probe(&store, "", &context).await?;

        Ok(Self(ObjectStoreBackend::new_with_store(store, Some(""))))
    }

    /// Construct with a caller-supplied `ObjectStore`.  Intended for unit tests.
    pub fn new_with_store(store: Arc<dyn ObjectStore>) -> Self {
        Self(ObjectStoreBackend::new_with_store(store, Some("")))
    }
}

#[async_trait::async_trait]
impl IpfsStore for WebDavStore {
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

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use stoa_core::ipfs::DeletionOutcome;

    fn make_test_store() -> WebDavStore {
        WebDavStore::new_with_store(Arc::new(InMemory::new()) as Arc<dyn ObjectStore>)
    }

    #[tokio::test]
    async fn round_trip() {
        let store = make_test_store();
        let data = b"webdav transit round trip";
        let cid = store.put_raw(data).await.expect("put");
        assert_eq!(store.get_raw(&cid).await.expect("get"), Some(data.to_vec()));
    }

    #[tokio::test]
    async fn delete_removes_object() {
        let store = make_test_store();
        let data = b"to be deleted";
        let cid = store.put_raw(data).await.expect("put");
        assert_eq!(
            store.delete(&cid).await.expect("delete"),
            DeletionOutcome::Immediate
        );
        assert_eq!(store.get_raw(&cid).await.expect("get"), None);
    }
}
