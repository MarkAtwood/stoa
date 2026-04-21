use axum::{
    body::Body,
    extract::Path,
    http::{StatusCode, header},
    response::Response,
};

/// GET /jmap/download/{accountId}/{blobId}/{name}
///
/// v1: parses blobId as a CID string. Returns 400 if blobId is not a valid CID.
/// Actual IPFS fetch is stubbed — returns 501 Not Implemented until IPFS
/// is wired into the server AppState.
pub async fn blob_download(
    Path((account_id, blob_id, name)): Path<(String, String, String)>,
) -> Response<Body> {
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
        let resp = blob_download(Path((
            "acc1".to_string(),
            "not-a-cid".to_string(),
            "message.eml".to_string(),
        )))
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn valid_cid_returns_501_in_v1() {
        let valid_cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let resp = blob_download(Path((
            "acc1".to_string(),
            valid_cid.to_string(),
            "message.eml".to_string(),
        )))
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
