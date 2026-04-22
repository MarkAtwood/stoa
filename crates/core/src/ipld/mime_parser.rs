use base64::Engine as _;
use cid::Cid;
use mailparse::{parse_content_type, parse_headers, parse_mail};
use multihash_codetable::{Code, MultihashDigest};

use crate::ipld::mime::{MimeNode, MimePart, MultipartMime, SinglePartMime};

use crate::ipld::codec::CODEC_RAW;

/// Result of MIME parsing: the MIME node and all decoded content blocks
/// (indexed by their CIDs) that will need to be stored in IPFS.
pub struct ParsedMime {
    pub node: MimeNode,
    /// Raw content blocks keyed by CID; each must be written to IPFS storage.
    pub blocks: Vec<(Cid, Vec<u8>)>,
}

/// Parse an article's body as MIME, producing a MimeNode and decoded content blocks.
///
/// # Arguments
/// - `header_bytes`: verbatim RFC 5536 wire headers (used to find Content-Type etc.)
/// - `body_bytes`: NNTP body bytes after dot-unstuffing, before any decoding
///
/// # Returns
/// - `None` if no Content-Type header is present (treat as untyped text)
/// - `Some(ParsedMime)` with the MimeNode and all decoded content blocks
pub fn parse_mime(header_bytes: &[u8], body_bytes: &[u8]) -> Option<ParsedMime> {
    let (headers, _) = parse_headers(header_bytes).ok()?;

    let content_type_value = headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case("content-type"))?
        .get_value();

    let ct = parse_content_type(&content_type_value);
    let top_type = ct
        .mimetype
        .split('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    if top_type == "multipart" {
        parse_multipart(&content_type_value, header_bytes, body_bytes)
    } else {
        let cte = headers
            .iter()
            .find(|h| {
                h.get_key()
                    .eq_ignore_ascii_case("content-transfer-encoding")
            })
            .map(|h| h.get_value())
            .unwrap_or_else(|| "7bit".to_string());

        let is_binary = !top_type.eq_ignore_ascii_case("text");
        let (decoded, cte_canonical) = decode_body(body_bytes, &cte);
        let (decoded_cid, block_bytes) = make_raw_block(&decoded);

        Some(ParsedMime {
            node: MimeNode::SinglePart(SinglePartMime {
                content_type: ct.mimetype.clone(),
                transfer_encoding: cte_canonical,
                decoded_cid,
                is_binary,
            }),
            blocks: vec![(decoded_cid, block_bytes)],
        })
    }
}

/// Parse a multipart body using mailparse's boundary splitting via `.subparts`.
///
/// `parse_mail` requires the full RFC 822 message (headers + blank line + body)
/// so we reassemble it before calling. This correctly handles both CRLF and bare-LF
/// line endings, nested multipart, and all edge cases that the hand-rolled
/// `split_on_boundary()` got wrong.
fn parse_multipart(
    content_type_value: &str,
    header_bytes: &[u8],
    body_bytes: &[u8],
) -> Option<ParsedMime> {
    // Reassemble the full message so mailparse can do boundary splitting.
    let mut full_message = header_bytes.to_vec();
    // Ensure there is a blank line between headers and body.
    if !full_message.ends_with(b"\r\n\r\n") && !full_message.ends_with(b"\n\n") {
        if full_message.ends_with(b"\r\n") {
            full_message.extend_from_slice(b"\r\n");
        } else {
            full_message.extend_from_slice(b"\n\n");
        }
    }
    full_message.extend_from_slice(body_bytes);

    let parsed = parse_mail(&full_message).ok()?;

    let mut parts: Vec<MimePart> = Vec::new();
    let mut blocks: Vec<(Cid, Vec<u8>)> = Vec::new();

    for subpart in &parsed.subparts {
        let mimetype = subpart.ctype.mimetype.clone();
        let top_type = mimetype
            .split('/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_binary = !top_type.eq_ignore_ascii_case("text");

        // get_body_raw() applies the part's Content-Transfer-Encoding.
        // RFC 2046 §5.1.1: the CRLF immediately preceding the boundary delimiter
        // belongs to the delimiter, not the body.  mailparse includes it; strip it.
        let mut decoded = subpart.get_body_raw().unwrap_or_default();
        if decoded.ends_with(b"\r\n") {
            decoded.truncate(decoded.len() - 2);
        } else if decoded.ends_with(b"\n") {
            decoded.truncate(decoded.len() - 1);
        }
        let (decoded_cid, block_bytes) = make_raw_block(&decoded);

        blocks.push((decoded_cid, block_bytes));
        parts.push(MimePart {
            content_type: mimetype,
            decoded_cid,
            is_binary,
        });
    }

    Some(ParsedMime {
        node: MimeNode::Multipart(MultipartMime {
            content_type: content_type_value.to_string(),
            parts,
        }),
        blocks,
    })
}

/// Decode `body_bytes` according to the Content-Transfer-Encoding.
/// Returns `(decoded_bytes, canonical_cte_name)`.
/// On any decoding error, falls back to raw bytes.
fn decode_body(body_bytes: &[u8], cte: &str) -> (Vec<u8>, String) {
    let cte_lower = cte.trim().to_ascii_lowercase();
    match cte_lower.as_str() {
        "7bit" | "8bit" | "binary" => (body_bytes.to_vec(), cte_lower),
        "quoted-printable" => {
            let decoded = quoted_printable::decode(body_bytes, quoted_printable::ParseMode::Robust)
                .unwrap_or_else(|_| body_bytes.to_vec());
            (decoded, "quoted-printable".to_string())
        }
        "base64" => {
            // Strip all whitespace before decoding.
            let stripped: Vec<u8> = body_bytes
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&stripped)
                .unwrap_or_else(|_| body_bytes.to_vec());
            (decoded, "base64".to_string())
        }
        _ => (body_bytes.to_vec(), cte_lower),
    }
}

/// Compute a CIDv1 CODEC_RAW SHA-256 block from bytes.
fn make_raw_block(data: &[u8]) -> (Cid, Vec<u8>) {
    let digest = Code::Sha2_256.digest(data);
    let cid = Cid::new_v1(CODEC_RAW, digest);
    (cid, data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal single-part MIME message (returns headers and body separately).
    fn make_single_part(content_type: &str, cte: &str, body: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let headers = format!(
            "From: test@example.com\r\nContent-Type: {content_type}\r\nContent-Transfer-Encoding: {cte}\r\n"
        );
        (headers.into_bytes(), body.to_vec())
    }

    /// RFC 2045 §6.7 quoted-printable example.
    ///
    /// Input (soft-line-break form):
    ///   Now's the time =\r\n
    ///   for all folk to come=\r\n
    ///    to the aid of their country.
    ///
    /// Decoded: "Now's the time for all folk to come to the aid of their country."
    #[test]
    fn test_qp_decoding_rfc2045_example() {
        let qp_body = b"Now's the time =\r\nfor all folk to come=\r\n to the aid of their country.";
        let expected = "Now's the time for all folk to come to the aid of their country.";

        let (headers, body) =
            make_single_part("text/plain; charset=us-ascii", "quoted-printable", qp_body);
        let parsed =
            parse_mime(&headers, &body).expect("parse_mime must return Some for text/plain");

        let MimeNode::SinglePart(ref sp) = parsed.node else {
            panic!("expected SinglePart");
        };

        // Find the block by CID.
        let (_, block_bytes) = parsed
            .blocks
            .iter()
            .find(|(cid, _)| *cid == sp.decoded_cid)
            .expect("decoded block must be in blocks vec");

        assert_eq!(
            std::str::from_utf8(block_bytes).expect("decoded bytes must be valid UTF-8"),
            expected,
            "QP decoded output must match RFC 2045 §6.7 example"
        );
    }

    /// RFC 4648 §10 base64 test vector: "Zm9vYmFy" decodes to "foobar".
    #[test]
    fn test_base64_decoding_rfc4648_vector() {
        let b64_body = b"Zm9vYmFy";
        let expected = b"foobar";

        let (headers, body) = make_single_part("application/octet-stream", "base64", b64_body);
        let parsed = parse_mime(&headers, &body).expect("parse_mime must return Some");

        let MimeNode::SinglePart(ref sp) = parsed.node else {
            panic!("expected SinglePart");
        };

        let (_, block_bytes) = parsed
            .blocks
            .iter()
            .find(|(cid, _)| *cid == sp.decoded_cid)
            .expect("decoded block must be in blocks vec");

        assert_eq!(
            block_bytes.as_slice(),
            expected,
            "base64 decode must match RFC 4648 §10 vector"
        );
    }

    /// Article with no Content-Type header must return None.
    #[test]
    fn test_no_content_type_returns_none() {
        let headers = b"From: test@example.com\r\nSubject: no content type here\r\n";
        let body = b"Just some body text.";
        assert!(
            parse_mime(headers, body).is_none(),
            "missing Content-Type must produce None"
        );
    }

    /// Well-formed text/plain with 7bit CTE: decoded bytes == body bytes, is_binary == false.
    #[test]
    fn test_single_part_text_plain() {
        let body = b"Hello, world!\r\nThis is a plain text article.\r\n";
        let (headers, body_vec) = make_single_part("text/plain; charset=utf-8", "7bit", body);
        let parsed = parse_mime(&headers, &body_vec).expect("parse_mime must return Some");

        let MimeNode::SinglePart(ref sp) = parsed.node else {
            panic!("expected SinglePart");
        };

        assert!(!sp.is_binary, "text/plain must not be flagged as binary");
        assert_eq!(sp.transfer_encoding, "7bit");

        let (_, block_bytes) = parsed
            .blocks
            .iter()
            .find(|(cid, _)| *cid == sp.decoded_cid)
            .expect("decoded block must be in blocks vec");

        assert_eq!(block_bytes.as_slice(), body, "7bit body must be unchanged");
    }

    /// Multipart/mixed with two text/plain parts produces Multipart with two parts.
    #[test]
    fn test_multipart_mixed_two_parts() {
        let boundary = "unique_boundary_12345";
        let body = format!(
            "--{boundary}\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             First part body.\r\n\
             --{boundary}\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             Second part body.\r\n\
             --{boundary}--\r\n"
        );
        let ct = format!("multipart/mixed; boundary={boundary}");
        let headers = format!("From: test@example.com\r\nContent-Type: {ct}\r\n");

        let parsed = parse_mime(headers.as_bytes(), body.as_bytes())
            .expect("parse_mime must return Some for multipart");

        let MimeNode::Multipart(ref mp) = parsed.node else {
            panic!("expected Multipart");
        };

        assert_eq!(mp.parts.len(), 2, "must have exactly two parts");
        assert!(!mp.parts[0].is_binary, "first part must not be binary");
        assert!(!mp.parts[1].is_binary, "second part must not be binary");
        assert_eq!(parsed.blocks.len(), 2, "must have two decoded blocks");
    }

    /// image/jpeg Content-Type must produce is_binary = true.
    #[test]
    fn test_binary_part_is_flagged() {
        let (headers, body) = make_single_part("image/jpeg", "base64", b"AAAA");
        let parsed = parse_mime(&headers, &body).expect("parse_mime must return Some");

        let MimeNode::SinglePart(ref sp) = parsed.node else {
            panic!("expected SinglePart");
        };

        assert!(sp.is_binary, "image/jpeg must be flagged as binary");
    }

    /// Multipart message with bare-LF line endings (\n not \r\n) must parse correctly.
    ///
    /// RFC 2046 §5.1.1 requires CRLF, but real-world messages often use bare LF.
    /// mailparse handles this correctly; the old hand-rolled split_on_boundary() did not.
    #[test]
    fn test_multipart_bare_lf_line_endings() {
        let boundary = "bare_lf_boundary";
        // Intentionally use bare \n throughout (no \r\n).
        let body = format!(
            "--{boundary}\n\
             Content-Type: text/plain; charset=utf-8\n\
             \n\
             Bare LF first part.\n\
             --{boundary}\n\
             Content-Type: text/plain; charset=utf-8\n\
             \n\
             Bare LF second part.\n\
             --{boundary}--\n"
        );
        let ct = format!("multipart/mixed; boundary={boundary}");
        // Headers also use bare LF.
        let headers = format!("From: test@example.com\nContent-Type: {ct}\n");

        let parsed = parse_mime(headers.as_bytes(), body.as_bytes())
            .expect("parse_mime must return Some for bare-LF multipart");

        let MimeNode::Multipart(ref mp) = parsed.node else {
            panic!("expected Multipart");
        };

        assert_eq!(
            mp.parts.len(),
            2,
            "bare-LF multipart must yield exactly two parts"
        );
        assert_eq!(
            parsed.blocks.len(),
            2,
            "bare-LF multipart must yield two decoded blocks"
        );
    }

    /// The decoded_cid in any result must use the CODEC_RAW codec (0x55).
    #[test]
    fn test_decoded_cid_is_raw_codec() {
        let body = b"Some article body text.";
        let (headers, body_vec) = make_single_part("text/plain", "7bit", body);
        let parsed = parse_mime(&headers, &body_vec).expect("parse_mime must return Some");

        let MimeNode::SinglePart(ref sp) = parsed.node else {
            panic!("expected SinglePart");
        };

        assert_eq!(
            sp.decoded_cid.codec(),
            CODEC_RAW,
            "decoded_cid must use CODEC_RAW codec (0x55)"
        );

        for (cid, _) in &parsed.blocks {
            assert_eq!(
                cid.codec(),
                CODEC_RAW,
                "all blocks must use CODEC_RAW codec (0x55)"
            );
        }
    }
}
