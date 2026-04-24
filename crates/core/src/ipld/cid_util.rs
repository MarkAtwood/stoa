//! CID utilities and the dual-CID model for stoa articles.
//!
//! # The Dual-CID Model
//!
//! Every article in stoa has **two distinct CIDs**, and they must never
//! be confused with each other.
//!
//! ## Canonical CID (codec 0x55, raw)
//!
//! The *canonical CID* is a CIDv1 SHA-256 of the **deterministic canonical
//! bytes** of an article — specifically the concatenation of the wire header
//! bytes and the dot-unstuffed body bytes.  Because these bytes are fixed for
//! a given article, the canonical CID is stable across ingest paths and
//! independent of any IPLD encoding.
//!
//! **Uses:**
//! - Key in the `message_id → CID` deduplication map (`msgid_map`).
//! - Detecting duplicate articles arriving from multiple peers.
//!
//! **Do not** use the canonical CID as an IPFS address.  Requesting it from
//! IPFS will not return the article root node; it references raw bytes that
//! are stored separately as the header and body sub-blocks.
//!
//! ## Root CID (codec 0x71, DAG-CBOR)
//!
//! The *root CID* is the CIDv1 SHA-256 of the DAG-CBOR encoding of the
//! [`ArticleRootNode`](crate::ipld::root_node::ArticleRootNode) block.  It is
//! the IPFS content address that actually locates the article in the block
//! store.
//!
//! **Uses:**
//! - Addressing the article in IPFS (`ipfs block get <root-cid>`).
//! - NNTP `X-Stoa-CID` article header.
//! - JMAP `x-stoa-cid` custom Email property.
//! - Group log entries.
//! - JMAP email `id` and `blobId` fields.
//!
//! **Do not** use the root CID as a map key for deduplication.  Two ingests
//! of the same article may produce different root CIDs if metadata fields
//! (e.g. `hlc_timestamp`) differ; use the canonical CID for identity checks.
//!
//! ## Summary
//!
//! | Property | Canonical CID | Root CID |
//! |---|---|---|
//! | Codec | 0x55 (raw) | 0x71 (DAG-CBOR) |
//! | Content hashed | wire header ++ body bytes | DAG-CBOR ArticleRootNode |
//! | IPFS address? | No | Yes |
//! | Map key / dedup? | Yes | No |
//! | Stable across ingests? | Yes | No (HLC differs) |

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::ipld::codec::CODEC_RAW;

/// Compute the canonical CID (CIDv1 SHA-256, codec 0x55 raw) for an article.
///
/// The canonical CID is derived from the raw wire bytes of the article —
/// header bytes concatenated with body bytes — with no IPLD encoding applied.
/// It is stable across ingest paths and is the correct key to use in the
/// `message_id → CID` deduplication map.
///
/// See the [module-level documentation](self) for the distinction between the
/// canonical CID and the root CID.
///
/// # Arguments
/// - `header_bytes`: verbatim RFC 5536 wire header bytes
/// - `body_bytes`: dot-unstuffed NNTP body bytes
pub fn cid_for_article(header_bytes: &[u8], body_bytes: &[u8]) -> Cid {
    let mut combined = Vec::with_capacity(header_bytes.len() + body_bytes.len());
    combined.extend_from_slice(header_bytes);
    combined.extend_from_slice(body_bytes);
    let digest = Code::Sha2_256.digest(&combined);
    Cid::new_v1(CODEC_RAW, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipld::codec::{CODEC_DAG_CBOR, CODEC_RAW};

    #[test]
    fn canonical_cid_uses_raw_codec() {
        let cid = cid_for_article(b"From: a@b.com\r\n", b"body\r\n");
        assert_eq!(
            cid.codec(),
            CODEC_RAW,
            "canonical CID must use raw codec (0x55)"
        );
    }

    #[test]
    fn canonical_cid_is_not_dag_cbor() {
        let cid = cid_for_article(b"From: a@b.com\r\n", b"body\r\n");
        assert_ne!(
            cid.codec(),
            CODEC_DAG_CBOR,
            "canonical CID must not use DAG-CBOR codec"
        );
    }

    #[test]
    fn canonical_cid_is_deterministic() {
        let headers = b"From: user@example.com\r\nMessage-ID: <x@y.com>\r\n";
        let body = b"Hello.\r\n";
        let cid1 = cid_for_article(headers, body);
        let cid2 = cid_for_article(headers, body);
        assert_eq!(cid1, cid2, "same bytes must produce same canonical CID");
    }

    #[test]
    fn different_bodies_produce_different_canonical_cids() {
        let headers = b"From: user@example.com\r\n";
        let cid1 = cid_for_article(headers, b"body one\r\n");
        let cid2 = cid_for_article(headers, b"body two\r\n");
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn canonical_cid_uses_sha256() {
        let cid = cid_for_article(b"Subject: Test\r\n", b"text\r\n");
        // SHA-256 multihash code is 0x12.
        assert_eq!(cid.hash().code(), 0x12u64);
    }
}
