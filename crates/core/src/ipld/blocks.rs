use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

/// RAW IPLD codec code.
const RAW: u64 = 0x55;

/// Produce a raw IPLD block and its CIDv1 SHA-256 from verbatim header bytes.
///
/// The input bytes must be the exact RFC 5536 wire bytes — no transformation.
/// The returned `Vec<u8>` equals the input exactly (verified by round-trip tests).
pub fn header_block(header_bytes: &[u8]) -> (Cid, Vec<u8>) {
    raw_block(header_bytes)
}

/// Produce a raw IPLD block and its CIDv1 SHA-256 from verbatim body bytes.
///
/// The input bytes are post-dot-unstuffing NNTP body bytes, before any MIME
/// decoding.
pub fn body_block(body_bytes: &[u8]) -> (Cid, Vec<u8>) {
    raw_block(body_bytes)
}

fn raw_block(data: &[u8]) -> (Cid, Vec<u8>) {
    let digest = Code::Sha2_256.digest(data);
    let cid = Cid::new_v1(RAW, digest);
    (cid, data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_block_round_trip() {
        let bytes = b"From: user@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n";
        let (cid, block) = header_block(bytes);
        assert_eq!(
            block,
            bytes.to_vec(),
            "block bytes must equal input exactly"
        );
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), RAW);
    }

    #[test]
    fn body_block_round_trip() {
        let bytes = b"Hello, world!\r\n.\r\n";
        let (cid, block) = body_block(bytes);
        assert_eq!(block, bytes.to_vec());
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), RAW);
    }

    #[test]
    fn header_block_cid_is_sha256() {
        let bytes = b"Subject: Test\r\n";
        let (cid, _) = header_block(bytes);
        // The multihash varint code 0x12 identifies SHA2-256.
        assert_eq!(cid.hash().code(), 0x12u64);
    }

    #[test]
    fn body_block_cid_is_sha256() {
        let bytes = b"body text\r\n";
        let (cid, _) = body_block(bytes);
        assert_eq!(cid.hash().code(), 0x12u64);
    }

    #[test]
    fn same_bytes_same_cid() {
        let bytes = b"deterministic";
        let (cid1, _) = raw_block(bytes);
        let (cid2, _) = raw_block(bytes);
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn different_bytes_different_cid() {
        let (cid1, _) = raw_block(b"aaa");
        let (cid2, _) = raw_block(b"bbb");
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn empty_bytes_is_valid() {
        let (cid, block) = raw_block(b"");
        assert_eq!(block, b"".to_vec());
        assert_eq!(cid.version(), cid::Version::V1);
    }
}
