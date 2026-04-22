use cid::Cid;
use serde::{Deserialize, Serialize};

/// Current schema version. Increment on breaking changes.
/// Consumers must reject root nodes with schema_version > their maximum known.
pub const SCHEMA_VERSION: u32 = 1;

/// The article root node stored as a DAG-CBOR block in IPFS.
///
/// Links to raw blocks for verbatim wire bytes and to IPLD sub-nodes for
/// parsed MIME content and derived metadata. All CIDs are CIDv1 SHA-256.
///
/// # Schema versioning
///
/// `schema_version` increments on breaking changes (removed fields, changed
/// semantics). Additive changes (new optional fields) do NOT increment the
/// version; consumers must ignore unknown fields during deserialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArticleRootNode {
    /// Schema version; currently 1.
    pub schema_version: u32,
    /// CID of the raw block containing verbatim RFC 5536 wire headers.
    pub header_cid: Cid,
    /// CID of the DAG-CBOR block containing the structured header map
    /// (`HeaderMapNode`). Enables `ipfs dag get <root>/header_map_cid/<name>`
    /// for per-header IPLD traversal. `None` only for legacy articles that
    /// predate this field.
    pub header_map_cid: Option<Cid>,
    /// CID of the raw block containing verbatim NNTP body bytes.
    pub body_cid: Cid,
    /// CID of the MIME parsed node, or None if MIME parsing was skipped.
    pub mime_cid: Option<Cid>,
    /// Derived metadata for preview and routing without fetching sub-blocks.
    pub metadata: ArticleMetadata,
}

/// Derived metadata embedded in the article root node.
///
/// Contains enough information for Corundum (and other consumers) to render
/// a preview and route the article without fetching sub-blocks. Fields must
/// be computable deterministically from the article wire bytes.
///
/// # Extensibility
///
/// New optional fields may be added without incrementing `schema_version`.
/// Consumers using standard serde deserialization will silently ignore unknown
/// fields: DAG-CBOR map keys not present in this struct are dropped on
/// deserialization. This is the correct default behaviour for forward
/// compatibility.
///
/// If unknown-field preservation is required in the future (e.g. for a
/// schema-migration tool that must not lose data), add:
/// ```ignore
/// #[serde(flatten)]
/// extra: std::collections::HashMap<String, ciborium::Value>,
/// ```
/// Do not add that field now — it changes the serialized shape and must be a
/// deliberate, versioned decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArticleMetadata {
    /// RFC 5536 Message-ID header value, including angle brackets.
    pub message_id: String,
    /// Destination newsgroups, in lexicographic order.
    pub newsgroups: Vec<String>,
    /// Hybrid Logical Clock timestamp (milliseconds since Unix epoch).
    pub hlc_timestamp: u64,
    /// Ed25519 signature by the operator key over the root node CID bytes.
    /// Empty until signing is wired in (l62.2.6).
    pub operator_signature: Vec<u8>,
    /// Total byte count of the article (header + body wire bytes).
    pub byte_count: u64,
    /// Line count of the article body.
    pub line_count: u64,
    /// Summary of the MIME content type (e.g. "text/plain", "multipart/mixed").
    /// "text/plain" for non-MIME articles.
    pub content_type_summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn test_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x71, digest)
    }

    fn make_root_node() -> ArticleRootNode {
        ArticleRootNode {
            schema_version: SCHEMA_VERSION,
            header_cid: test_cid(b"header bytes"),
            header_map_cid: Some(test_cid(b"header map")),
            body_cid: test_cid(b"body bytes"),
            mime_cid: Some(test_cid(b"mime node")),
            metadata: ArticleMetadata {
                message_id: "<test-123@example.com>".into(),
                newsgroups: vec!["comp.lang.rust".into(), "comp.lang.c".into()],
                hlc_timestamp: 1_700_000_000_000,
                operator_signature: vec![0xde, 0xad, 0xbe, 0xef],
                byte_count: 512,
                line_count: 10,
                content_type_summary: "text/plain".into(),
            },
        }
    }

    #[test]
    fn root_node_dagcbor_serialization_is_deterministic() {
        let node = make_root_node();
        let bytes1 = serde_ipld_dagcbor::to_vec(&node).expect("first serialize");
        let bytes2 = serde_ipld_dagcbor::to_vec(&node).expect("second serialize");
        assert_eq!(bytes1, bytes2, "same value must produce identical bytes");
    }

    #[test]
    fn schema_version_constant_is_one() {
        assert_eq!(SCHEMA_VERSION, 1);
    }
}
