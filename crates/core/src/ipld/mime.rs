use cid::Cid;
use serde::{Deserialize, Serialize};

/// MIME parsed node for a single-part or multipart article body.
///
/// v1 scope: text parts are fully represented; binary parts are flagged
/// with `is_binary = true` and `decoded_cid` pointing to raw bytes, but
/// no further parsing is performed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MimeNode {
    SinglePart(SinglePartMime),
    Multipart(MultipartMime),
}

/// MIME representation for a single-part article.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SinglePartMime {
    /// MIME Content-Type value (e.g. "text/plain; charset=utf-8").
    pub content_type: String,
    /// Content-Transfer-Encoding value (e.g. "7bit", "quoted-printable").
    pub transfer_encoding: String,
    /// CID of the decoded content bytes.
    pub decoded_cid: Cid,
    /// True if the part is binary (not further parsed in v1).
    pub is_binary: bool,
}

/// MIME representation for a multipart article.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MultipartMime {
    /// MIME Content-Type value (e.g. "multipart/mixed; boundary=...").
    pub content_type: String,
    /// Parsed parts.
    pub parts: Vec<MimePart>,
}

/// A single part within a multipart article.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MimePart {
    /// MIME Content-Type value for this part.
    pub content_type: String,
    /// CID of the decoded content bytes.
    pub decoded_cid: Cid,
    /// True if the part is binary (not further parsed in v1).
    pub is_binary: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn test_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x55, digest) // RAW codec
    }

    fn make_single_part() -> MimeNode {
        MimeNode::SinglePart(SinglePartMime {
            content_type: "text/plain; charset=utf-8".into(),
            transfer_encoding: "7bit".into(),
            decoded_cid: test_cid(b"article body text"),
            is_binary: false,
        })
    }

    #[test]
    fn single_part_dagcbor_roundtrip() {
        let original = make_single_part();
        let encoded =
            serde_ipld_dagcbor::to_vec(&original).expect("DAG-CBOR serialization failed");
        let decoded: MimeNode =
            serde_ipld_dagcbor::from_slice(&encoded).expect("DAG-CBOR deserialization failed");
        assert_eq!(original, decoded, "round-tripped value must equal original");
    }

    #[test]
    fn multipart_dagcbor_roundtrip() {
        let original = MimeNode::Multipart(MultipartMime {
            content_type: "multipart/mixed; boundary=abc123".into(),
            parts: vec![
                MimePart {
                    content_type: "text/plain; charset=utf-8".into(),
                    decoded_cid: test_cid(b"part one body"),
                    is_binary: false,
                },
                MimePart {
                    content_type: "text/html; charset=utf-8".into(),
                    decoded_cid: test_cid(b"part two body"),
                    is_binary: false,
                },
            ],
        });
        let encoded =
            serde_ipld_dagcbor::to_vec(&original).expect("DAG-CBOR serialization failed");
        let decoded: MimeNode =
            serde_ipld_dagcbor::from_slice(&encoded).expect("DAG-CBOR deserialization failed");
        assert_eq!(original, decoded, "round-tripped value must equal original");
    }

    #[test]
    fn dagcbor_is_deterministic() {
        let node = make_single_part();
        let bytes1 = serde_ipld_dagcbor::to_vec(&node).expect("first serialize");
        let bytes2 = serde_ipld_dagcbor::to_vec(&node).expect("second serialize");
        assert_eq!(bytes1, bytes2, "same value must produce identical bytes");
    }

    #[test]
    fn binary_part_representable() {
        let original = MimeNode::SinglePart(SinglePartMime {
            content_type: "application/octet-stream".into(),
            transfer_encoding: "base64".into(),
            decoded_cid: test_cid(b"raw binary blob"),
            is_binary: true,
        });
        let encoded =
            serde_ipld_dagcbor::to_vec(&original).expect("DAG-CBOR serialization failed");
        let decoded: MimeNode =
            serde_ipld_dagcbor::from_slice(&encoded).expect("DAG-CBOR deserialization failed");
        assert_eq!(original, decoded, "binary SinglePartMime must round-trip without loss");
        if let MimeNode::SinglePart(ref part) = decoded {
            assert!(part.is_binary, "is_binary flag must survive round-trip");
        } else {
            panic!("expected SinglePart after round-trip");
        }
    }
}
