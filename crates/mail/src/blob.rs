use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
    Extension,
};

use crate::server::{AppState, AuthenticatedUser};
use stoa_reader::post::ipfs_write::IpfsWriteError;

/// GET /jmap/download/{accountId}/{blobId}/{name}
///
/// Parses blobId as a CID string, fetches the raw block from IPFS, wraps it
/// in a synthetic RFC 5322 MIME message, and returns that as the body with
/// Content-Type: message/rfc822.
///
/// Error mapping:
/// - 400: blobId is not a valid CID.
/// - 403: authenticated user does not own the requested account.
/// - 404: CID not found in IPFS.
/// - 503: JMAP stores not configured (server in stub/dev mode).
/// - 500: any other IPFS error.
pub async fn blob_download(
    State(state): State<Arc<AppState>>,
    user: Option<Extension<AuthenticatedUser>>,
    Path((account_id, blob_id, _name)): Path<(String, String, String)>,
) -> Response<Body> {
    // In authenticated mode, verify the caller owns the requested account.
    if let Some(Extension(ref authenticated_user)) = user {
        let expected = format!("u_{}", authenticated_user.0);
        if account_id != expected {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("403 Forbidden"))
                .unwrap();
        }
    }

    // Validate that blobId looks like a CID.
    let cid = match cid::Cid::try_from(blob_id.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("invalid blobId"))
                .unwrap();
        }
    };

    // Require JMAP stores to be configured.
    let jmap = match state.jmap.as_ref() {
        Some(j) => j,
        None => {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("503 JMAP not configured"))
                .unwrap();
        }
    };

    // Fetch the raw block from IPFS.
    let bytes = match jmap.ipfs.get_raw_block(&cid).await {
        Ok(b) => b,
        Err(IpfsWriteError::NotFound(_)) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("404 blob not found"))
                .unwrap();
        }
        Err(e) => {
            tracing::error!(cid = %cid, "blob_download IPFS error: {e}");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("500 IPFS error"))
                .unwrap();
        }
    };

    // Base64-encode the block bytes.
    let b64 = data_encoding::BASE64.encode(&bytes);

    // Build a synthetic RFC 5322 MIME message wrapping the block.
    let message = format!(
        "From: ipfs-gateway@localhost\r\n\
         Subject: IPFS:{cid}\r\n\
         Message-ID: <{cid}@ipfs.local>\r\n\
         X-Stoa-CID: {cid}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {b64}\r\n"
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "message/rfc822")
        .body(Body::from(message))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::StatusCode;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;
    use stoa_auth::{AuthConfig, CredentialStore};

    static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

    async fn make_dev_state() -> Arc<AppState> {
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:blob_test_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("pool");
        crate::migrations::run_migrations(&pool)
            .await
            .expect("migrations");
        Arc::new(AppState {
            start_time: Instant::now(),
            jmap: None,
            credential_store: Arc::new(CredentialStore::empty()),
            auth_config: Arc::new(AuthConfig::default()),
            token_store: Arc::new(crate::token_store::TokenStore::new(Arc::new(pool))),
            base_url: "http://localhost".to_string(),
            cors: crate::config::CorsConfig::default(),
        })
    }

    #[tokio::test]
    async fn invalid_blob_id_returns_400() {
        let resp = blob_download(
            State(make_dev_state().await),
            None,
            Path((
                "acc1".to_string(),
                "not-a-cid".to_string(),
                "message.eml".to_string(),
            )),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn valid_cid_jmap_not_configured_returns_503() {
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = blob_download(
            State(make_dev_state().await),
            None,
            Path((
                "acc1".to_string(),
                valid_cid.to_string(),
                "message.eml".to_string(),
            )),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn wrong_account_id_returns_403() {
        let user = Some(Extension(AuthenticatedUser("alice".to_string())));
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = blob_download(
            State(make_dev_state().await),
            user,
            Path((
                "u_bob".to_string(),
                valid_cid.to_string(),
                "message.eml".to_string(),
            )),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn correct_account_id_passes_account_check_returns_503_without_jmap() {
        let user = Some(Extension(AuthenticatedUser("alice".to_string())));
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = blob_download(
            State(make_dev_state().await),
            user,
            Path((
                "u_alice".to_string(),
                valid_cid.to_string(),
                "message.eml".to_string(),
            )),
        )
        .await;
        // Passes account check; returns 503 because jmap is not configured.
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
