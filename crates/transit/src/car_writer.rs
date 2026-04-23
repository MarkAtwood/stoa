//! CARv1 (Content Addressable aRchive v1) binary encoder.
//!
//! Format reference: <https://ipld.io/specs/transport/car/carv1/>
//!
//! Layout:
//!   varint(header_len) || CBOR-header || blocks…
//!   block: varint(cid_len + data_len) || CID-bytes || data
//!
//! CBOR header encodes `{"version": 1, "roots": [<cid>…]}`.
//! The encoder is hand-rolled; no external CBOR or CAR crate is required.

use cid::Cid;

/// Build a complete CARv1 archive in memory and return it as raw bytes.
///
/// `roots` is the list of root CIDs (may be empty for a plain export slice).
/// `blocks` is an ordered sequence of `(cid, raw_block_data)` pairs; each pair
/// is written as one block frame.
pub fn build_car(roots: &[Cid], blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let header = encode_cbor_header(roots);
    let mut out = Vec::new();
    write_varint(&mut out, header.len() as u64);
    out.extend_from_slice(&header);
    for (cid, data) in blocks {
        write_block_frame(&mut out, cid, data);
    }
    out
}

// ── Block framing ─────────────────────────────────────────────────────────────

/// Write one block frame: `varint(cid_len + data_len) || CID-bytes || data`.
fn write_block_frame(out: &mut Vec<u8>, cid: &Cid, data: &[u8]) {
    let cid_bytes = cid.to_bytes();
    write_varint(out, (cid_bytes.len() + data.len()) as u64);
    out.extend_from_slice(&cid_bytes);
    out.extend_from_slice(data);
}

// ── CBOR header ───────────────────────────────────────────────────────────────

/// Encode the CARv1 CBOR header.
///
/// Key order: `"version"` first, `"roots"` second (matches reference
/// implementations and produces a deterministic byte stream).
fn encode_cbor_header(roots: &[Cid]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_write_ai(&mut out, 5, 2); // map(2)
    cbor_write_text(&mut out, "version");
    cbor_write_ai(&mut out, 0, 1); // uint(1)
    cbor_write_text(&mut out, "roots");
    cbor_write_ai(&mut out, 4, roots.len() as u64); // array(n)
    for cid in roots {
        cbor_write_cid(&mut out, cid);
    }
    out
}

/// Encode a CID as `tag(42) || bytes(0x00 || cid.to_bytes())`.
///
/// The `0x00` byte is the IPLD multibase identity prefix required by the CAR
/// spec when encoding CIDs in CBOR.
fn cbor_write_cid(out: &mut Vec<u8>, cid: &Cid) {
    out.push(0xd8); // tag major type + 1-byte argument
    out.push(0x2a); // 42
    let cid_bytes = cid.to_bytes();
    cbor_write_ai(out, 2, (cid_bytes.len() + 1) as u64); // bytes(cid_len + 1)
    out.push(0x00); // multibase identity prefix
    out.extend_from_slice(&cid_bytes);
}

fn cbor_write_text(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    cbor_write_ai(out, 3, b.len() as u64); // text(len)
    out.extend_from_slice(b);
}

/// Emit a CBOR initial byte plus any additional length bytes.
///
/// `major` is the CBOR major type (0–7); `n` is the integer argument.
fn cbor_write_ai(out: &mut Vec<u8>, major: u8, n: u64) {
    let base = major << 5;
    match n {
        0..=23 => out.push(base | n as u8),
        24..=0xff => {
            out.push(base | 24);
            out.push(n as u8);
        }
        0x100..=0xffff => {
            out.push(base | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(base | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(base | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

// ── Varint ────────────────────────────────────────────────────────────────────

/// Write an unsigned LEB128 varint (standard throughout IPFS/IPLD wire formats).
pub fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn make_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x55, digest)
    }

    /// Varint encoding oracle: known byte sequences from the LEB128 spec.
    #[test]
    fn varint_known_vectors() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
            (16383, &[0xff, 0x7f]),
            (16384, &[0x80, 0x80, 0x01]),
        ];
        for (n, expected) in cases {
            let mut out = Vec::new();
            write_varint(&mut out, *n);
            assert_eq!(out, *expected, "varint({n}) mismatch");
        }
    }

    /// Empty-roots CAR: header must parse to a byte sequence parseable as
    /// CARv1 (varint-prefixed CBOR map with version=1, roots=[]).
    ///
    /// We verify the raw bytes against the reference encoding rather than
    /// round-tripping through our own decoder.
    ///
    /// Reference: hand-computed from the CBOR spec.
    ///   map(2)              = A2          (1 byte)
    ///   text(7)"version"    = 67 76657273696F6E  (8 bytes)
    ///   uint(1)             = 01          (1 byte)
    ///   text(5)"roots"      = 65 726F6F7473      (6 bytes)
    ///   array(0)            = 80          (1 byte)
    ///   Total header bytes  = 17
    ///   Varint(17)          = 11
    #[test]
    fn empty_roots_car_header_bytes() {
        let car = build_car(&[], &[]);
        let expected_header: &[u8] = &[
            0x11, // varint(17)
            0xa2, // map(2)
            0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
            0x01, // uint(1)
            0x65, 0x72, 0x6f, 0x6f, 0x74, 0x73, // "roots"
            0x80, // array(0)
        ];
        assert_eq!(
            car, expected_header,
            "empty-roots CAR must match reference byte sequence"
        );
    }

    /// Single-block CAR with one root: block frame must appear immediately
    /// after the header and encode `varint(cid_len + data_len) || cid || data`.
    ///
    /// We verify structure by parsing block frame length and checking that
    /// the CID bytes at the start of the frame match `cid.to_bytes()`.
    #[test]
    fn single_block_car_frame_structure() {
        let data = b"hello car";
        let cid = make_cid(data);
        let car = build_car(&[cid], &[(cid, data.to_vec())]);

        // Skip header: first byte is varint of header length.
        let (header_len, header_varint_len) = read_varint(&car);
        let block_start = header_varint_len + header_len as usize;

        // Parse block frame varint.
        let (frame_len, frame_varint_len) = read_varint(&car[block_start..]);
        let payload_start = block_start + frame_varint_len;
        let cid_bytes = cid.to_bytes();
        assert_eq!(
            frame_len as usize,
            cid_bytes.len() + data.len(),
            "block frame length must equal cid_len + data_len"
        );

        // CID bytes must immediately follow the frame varint.
        assert_eq!(
            &car[payload_start..payload_start + cid_bytes.len()],
            cid_bytes.as_slice(),
            "CID bytes must appear at start of block payload"
        );

        // Data bytes must follow CID.
        let data_start = payload_start + cid_bytes.len();
        assert_eq!(
            &car[data_start..],
            data,
            "block data must appear after CID bytes"
        );
    }

    /// Two blocks with two roots: total CAR length must equal
    /// header_varint + header + sum of frame varints + cid bytes + data bytes.
    #[test]
    fn two_block_car_total_length() {
        let d1 = b"first block";
        let d2 = b"second block";
        let c1 = make_cid(d1);
        let c2 = make_cid(d2);
        let blocks = vec![(c1, d1.to_vec()), (c2, d2.to_vec())];
        let car = build_car(&[c1, c2], &blocks);

        let (header_len, hv_len) = read_varint(&car);
        let mut pos = hv_len + header_len as usize;

        for (cid, data) in &blocks {
            let (frame_len, fv_len) = read_varint(&car[pos..]);
            assert_eq!(
                frame_len as usize,
                cid.to_bytes().len() + data.len(),
                "frame length mismatch"
            );
            pos += fv_len + frame_len as usize;
        }
        assert_eq!(pos, car.len(), "all bytes must be accounted for");
    }

    /// Decode a single LEB128 varint from the start of `buf`.
    /// Returns `(value, bytes_consumed)`.
    fn read_varint(buf: &[u8]) -> (u64, usize) {
        let mut n: u64 = 0;
        let mut shift = 0u32;
        for (i, &byte) in buf.iter().enumerate() {
            n |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return (n, i + 1);
            }
        }
        panic!("varint not terminated");
    }
}
