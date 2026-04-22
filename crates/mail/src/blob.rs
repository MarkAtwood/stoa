use axum::{
    body::Body,
    extract::Path,
    http::{header, StatusCode},
    response::Response,
    Extension,
};

use crate::server::AuthenticatedUser;

/// GET /jmap/download/{accountId}/{blobId}/{name}
///
/// v1: parses blobId as a CID string. Returns 400 if blobId is not a valid CID.
/// When an authenticated user is present (non-dev mode), the path account_id
/// must equal `u_{username}` — any other account returns 403.
/// Actual IPFS fetch is stubbed — returns 501 Not Implemented until IPFS
/// is wired into the server AppState.
pub async fn blob_download(
    user: Option<Extension<AuthenticatedUser>>,
    Path((account_id, blob_id, name)): Path<(String, String, String)>,
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
    if cid::Cid::try_from(blob_id.as_str()).is_err() {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("invalid blobId"))
            .unwrap();
    }

    // v1: IPFS fetch not yet wired; return 501.
    tracing::warn!(
        account_id = %account_id,
        blob_id = %blob_id,
        name = %name,
        "Blob/get: IPFS fetch not yet implemented in v1"
    );
    Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("v1: blob fetch not yet implemented"))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn invalid_blob_id_returns_400() {
        let resp = blob_download(
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
    async fn valid_cid_returns_501_in_v1() {
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = blob_download(
            None,
            Path((
                "acc1".to_string(),
                valid_cid.to_string(),
                "message.eml".to_string(),
            )),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn wrong_account_id_returns_403() {
        let user = Some(Extension(AuthenticatedUser("alice".to_string())));
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = blob_download(
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
    async fn correct_account_id_passes_account_check() {
        let user = Some(Extension(AuthenticatedUser("alice".to_string())));
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = blob_download(
            user,
            Path((
                "u_alice".to_string(),
                valid_cid.to_string(),
                "message.eml".to_string(),
            )),
        )
        .await;
        // Passes account check; v1 returns 501 because IPFS is not wired.
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
