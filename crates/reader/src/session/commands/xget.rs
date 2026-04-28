use base64::Engine as _;
use cid::Cid;
use stoa_core::msgid_map::MsgIdMap;

use crate::{
    post::ipfs_write::{IpfsBlockStore, IpfsWriteError},
    session::response::Response,
};

/// XGET <cid> — fetch a raw IPFS block by CID and return it as a MIME-wrapped
/// base64 message.
///
/// The CID must be present in the msgid_map (i.e., it must be a known article)
/// before the block is returned. This prevents authenticated NNTP users from
/// fetching arbitrary IPFS blocks that the server can reach but that are not
/// known articles.
///
/// Response codes:
/// - 290: success, followed by a synthetic RFC 5322/MIME message with the
///   block data base64-encoded in the body.
/// - 403: CID is not a known article CID (group membership check failed), or
///   internal fetch error.
/// - 430: CID not found in the local block store.
/// - 501: argument is not a valid CID.
pub async fn handle_xget(
    cid_str: &str,
    ipfs_store: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
) -> Response {
    let cid: Cid = match cid_str.parse() {
        Ok(c) => c,
        Err(_) => return Response::new(501, "Syntax error: not a valid CID"),
    };

    // Verify the CID is a known article before returning any block data.
    match msgid_map.lookup_by_cid(&cid).await {
        Ok(Some(_)) => {}
        Ok(None) => return Response::new(403, "Not a known article CID"),
        Err(_) => return Response::new(403, "Internal error during article lookup"),
    }

    let bytes = match ipfs_store.get_raw(&cid).await {
        Ok(b) => b,
        Err(IpfsWriteError::NotFound(_)) => return Response::new(430, "CID not found"),
        Err(_) => return Response::new(403, "Internal error fetching block"),
    };

    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

    // Build a synthetic RFC 5322/MIME message carrying the raw block bytes.
    // The body is base64-encoded; apply dot-stuffing to the body lines.
    // Base64 output uses A-Z, a-z, 0-9, +, /, =.  No line starts with '.',
    // so dot-stuffing is a no-op in practice, but we apply it anyway for
    // strict RFC 3977 §3.1.1 compliance.
    let mut body_lines: Vec<String> = Vec::new();
    body_lines.push("From: ipfs-gateway@localhost".to_string());
    body_lines.push(format!("Subject: IPFS:{cid_str}"));
    body_lines.push(format!("Message-ID: <{cid_str}@ipfs.local>"));
    body_lines.push(format!("X-Stoa-CID: {cid_str}"));
    body_lines.push("MIME-Version: 1.0".to_string());
    body_lines.push("Content-Type: application/octet-stream".to_string());
    body_lines.push("Content-Transfer-Encoding: base64".to_string());
    body_lines.push(String::new()); // blank line separating headers from body

    // Dot-stuff each base64 line: prepend '.' to any line starting with '.'.
    for line in b64.lines() {
        if line.starts_with('.') {
            body_lines.push(format!(".{line}"));
        } else {
            body_lines.push(line.to_string());
        }
    }

    Response {
        code: 290,
        text: format!("{cid_str} article follows"),
        body: body_lines,
        multiline: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post::ipfs_write::MemIpfsStore;
    use multihash_codetable::{Code, MultihashDigest};
    use stoa_core::msgid_map::MsgIdMap;

    /// Compute a CIDv1 SHA-256 raw-leaf CID for the given bytes,
    /// matching what MemIpfsStore uses internally.
    fn cid_for(data: &[u8]) -> Cid {
        let mh = Code::Sha2_256.digest(data);
        // codec 0x55 = raw
        Cid::new_v1(0x55, mh)
    }

    /// Create a MsgIdMap backed by a temporary on-disk SQLite DB.
    async fn make_msgid_map() -> MsgIdMap {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        stoa_core::migrations::run_migrations(&url)
            .await
            .expect("core migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        // Unlink the file; pool holds the fd open (POSIX semantics).
        std::mem::forget(tmp);
        MsgIdMap::new(pool)
    }

    #[tokio::test]
    async fn xget_invalid_cid_returns_501() {
        let store = MemIpfsStore::new();
        let msgid_map = make_msgid_map().await;
        let resp = handle_xget("not-a-cid", &store, &msgid_map).await;
        assert_eq!(resp.code, 501);
    }

    #[tokio::test]
    async fn xget_unknown_cid_returns_403() {
        let store = MemIpfsStore::new();
        let msgid_map = make_msgid_map().await;
        // A syntactically valid CID with no msgid_map entry — must be rejected.
        let data = b"not a known article";
        let cid = cid_for(data);
        let resp = handle_xget(&cid.to_string(), &store, &msgid_map).await;
        assert_eq!(resp.code, 403);
    }

    #[tokio::test]
    async fn xget_known_but_missing_from_store_returns_430() {
        let store = MemIpfsStore::new();
        let msgid_map = make_msgid_map().await;
        // A CID registered in msgid_map but not present in the block store.
        let data = b"registered but not stored";
        let cid = cid_for(data);
        msgid_map
            .insert("<missing@example.com>", &cid)
            .await
            .unwrap();
        let resp = handle_xget(&cid.to_string(), &store, &msgid_map).await;
        assert_eq!(resp.code, 430);
    }

    #[tokio::test]
    async fn xget_present_cid_returns_290_with_base64_body() {
        let store = MemIpfsStore::new();
        let msgid_map = make_msgid_map().await;
        let payload = b"hello xget test";
        let cid = store.put_raw(payload).await.unwrap();
        // Register the CID so the group membership check passes.
        msgid_map
            .insert("<xget-test@example.com>", &cid)
            .await
            .unwrap();

        let resp = handle_xget(&cid.to_string(), &store, &msgid_map).await;
        assert_eq!(
            resp.code, 290,
            "expected 290, got: {} {}",
            resp.code, resp.text
        );
        assert!(resp.multiline);

        // Confirm mandatory headers are present.
        let body_str = resp.body.join("\r\n");
        assert!(
            body_str.contains("MIME-Version: 1.0"),
            "missing MIME-Version"
        );
        assert!(
            body_str.contains("Content-Transfer-Encoding: base64"),
            "missing CTE header"
        );
        assert!(
            body_str.contains(&format!("X-Stoa-CID: {}", cid)),
            "missing X-Stoa-CID header"
        );

        // Decode the base64 body and verify it round-trips to the original payload.
        let b64_lines: Vec<&str> = resp
            .body
            .iter()
            .skip_while(|l| !l.is_empty())
            .skip(1) // skip blank separator line
            .map(|l| l.as_str())
            .collect();
        let b64_str = b64_lines.join("");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64_str)
            .expect("base64 body must decode cleanly");
        assert_eq!(decoded, payload, "decoded body must match original payload");
    }
}
