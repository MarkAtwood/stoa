//! HeaderMapNode: structured DAG-CBOR representation of RFC 5322 headers.
//!
//! The canonical header map stores each header name (lowercased) mapped to
//! either a single string value or a list of values for multi-occurrence
//! headers such as `Received`. The BTreeMap ensures lexicographic key order
//! for deterministic DAG-CBOR serialization and stable CIDs.
//!
//! Date-bearing headers (`date`, `injection-date`, `nntp-posting-date`,
//! `expires`) are transformed from RFC 2822 to RFC 3339 format. If the date
//! cannot be parsed the raw string is stored unchanged — ingestion must not
//! fail on a malformed `Expires:` header.

use std::collections::BTreeMap;

use base64::Engine;
use chrono::DateTime;
use serde::{Deserialize, Serialize};

/// The value of a header field in the structured header map.
///
/// Single-occurrence headers (e.g. `From`, `Subject`) are stored as
/// `Single(String)`, which serializes to a plain CBOR text string.
/// Multi-occurrence headers (e.g. `Received`) are stored as
/// `Multi(Vec<String>)`, which serializes to a CBOR array of text strings.
/// The `#[serde(untagged)]` attribute means no enum tag appears in the CBOR
/// output — the variant is inferred from the CBOR type on deserialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HeaderValue {
    Single(String),
    Multi(Vec<String>),
}

/// A structured map of RFC 5322 header fields for an NNTP article.
///
/// Keys are header names lowercased to ASCII. Values are `HeaderValue::Single`
/// for headers that appear exactly once, or `HeaderValue::Multi` for headers
/// that appear more than once. `BTreeMap` guarantees ascending lexicographic
/// key order, producing deterministic DAG-CBOR bytes and a stable CID.
pub type HeaderMapNode = BTreeMap<String, HeaderValue>;

/// Header names that contain standalone RFC 2822 dates and should be
/// transformed to RFC 3339 format.
const DATE_HEADERS: &[&str] = &["date", "injection-date", "nntp-posting-date", "expires"];

/// Build a structured header map from raw RFC 5322 header bytes.
///
/// - Header names are lowercased to ASCII; names outside `[A-Za-z0-9-]` are
///   dropped to prevent injection of malformed keys into the IPLD DAG.
/// - RFC 2047 encoded words in values are decoded to UTF-8.
/// - Date-bearing headers (`date`, `injection-date`, `nntp-posting-date`,
///   `expires`) are transformed from RFC 2822 to RFC 3339.  Unparseable
///   dates fall back to the raw string so ingestion never fails.
/// - Headers with the same name accumulate into `HeaderValue::Multi`; a
///   single-occurrence header is stored as `HeaderValue::Single`.
///
/// Returns an empty map if `raw_headers` is empty or cannot be parsed.
pub fn build_header_map(raw_headers: &[u8]) -> HeaderMapNode {
    let parsed = match mailparse::parse_headers(raw_headers) {
        Ok((headers, _)) => headers,
        Err(_) => return BTreeMap::new(),
    };

    let mut acc: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for hdr in &parsed {
        let raw_key = hdr.get_key();
        if !is_valid_header_name(&raw_key) {
            continue;
        }
        let key = raw_key.to_ascii_lowercase();
        let raw_value = hdr.get_value();
        let value = if DATE_HEADERS.contains(&key.as_str()) {
            rfc2822_to_rfc3339(&raw_value).unwrap_or(raw_value)
        } else {
            decode_rfc2047(&raw_value)
        };
        acc.entry(key).or_default().push(value);
    }

    acc.into_iter()
        .map(|(k, mut v)| {
            if v.len() == 1 {
                (k, HeaderValue::Single(v.remove(0)))
            } else {
                (k, HeaderValue::Multi(v))
            }
        })
        .collect()
}

/// Returns true if `name` consists only of ASCII letters, digits, and hyphens.
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Decode RFC 2047 encoded words (e.g. `=?utf-8?Q?caf=C3=A9?=`) in a header
/// value string to plain UTF-8.
///
/// Adjacent encoded words are decoded independently and concatenated. Any text
/// between encoded words is preserved as-is. Unknown charsets fall back to
/// UTF-8 lossy decoding.
fn decode_rfc2047(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut remaining = input;

    while let Some(start) = remaining.find("=?") {
        result.push_str(&remaining[..start]);
        remaining = &remaining[start + 2..];

        if let Some(end) = remaining.find("?=") {
            let word = &remaining[..end];
            remaining = &remaining[end + 2..];

            let parts: Vec<&str> = word.splitn(3, '?').collect();
            if parts.len() == 3 {
                let charset = parts[0].to_ascii_lowercase();
                let encoding = parts[1].to_ascii_uppercase();
                let text = parts[2];

                let decoded_bytes: Option<Vec<u8>> = match encoding.as_str() {
                    "B" => base64::engine::general_purpose::STANDARD.decode(text).ok(),
                    "Q" => {
                        // RFC 2047 Q-encoding: underscore stands for 0x20 (space).
                        let qp: String = text
                            .chars()
                            .map(|c| if c == '_' { ' ' } else { c })
                            .collect();
                        quoted_printable::decode(qp.as_bytes(), quoted_printable::ParseMode::Robust)
                            .ok()
                    }
                    _ => None,
                };

                if let Some(bytes) = decoded_bytes {
                    result.push_str(&charset_bytes_to_utf8(&bytes, &charset));
                } else {
                    result.push_str("=?");
                    result.push_str(word);
                    result.push_str("?=");
                }
            } else {
                result.push_str("=?");
                result.push_str(word);
                result.push_str("?=");
            }
        } else {
            result.push_str("=?");
            result.push_str(remaining);
            remaining = "";
            break;
        }
    }
    result.push_str(remaining);
    result
}

/// Convert charset-encoded bytes to a UTF-8 String.
fn charset_bytes_to_utf8(bytes: &[u8], charset: &str) -> String {
    match charset {
        "utf-8" | "utf8" | "us-ascii" | "ascii" => String::from_utf8_lossy(bytes).into_owned(),
        // ISO-8859-1 / Latin-1: codepoints 0x00–0xFF match Unicode exactly.
        "iso-8859-1" | "latin-1" | "latin1" | "iso8859-1" => {
            bytes.iter().map(|&b| b as char).collect()
        }
        // Unknown charset: best-effort UTF-8 lossy.
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Transform an RFC 2822 date string to RFC 3339.
///
/// Returns `Some(rfc3339)` on success, `None` on parse failure so the caller
/// can fall back to the raw string.
///
/// Python oracle:
/// ```python
/// from email.utils import parsedate_to_datetime
/// dt = parsedate_to_datetime("Mon, 01 Jan 2024 00:00:00 +0000")
/// print(dt.isoformat())  # 2024-01-01T00:00:00+00:00
/// ```
/// Note: chrono emits `Z` for UTC offsets (+00:00), Python emits `+00:00`.
/// Both are valid RFC 3339 representations of the same instant.
fn rfc2822_to_rfc3339(s: &str) -> Option<String> {
    DateTime::parse_from_rfc2822(s)
        .ok()
        .map(|dt| dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── HeaderValue serialization ─────────────────────────────────────────────

    #[test]
    fn single_value_roundtrip() {
        let mut map: HeaderMapNode = BTreeMap::new();
        map.insert(
            "from".into(),
            HeaderValue::Single("alice@example.com".into()),
        );
        map.insert("subject".into(), HeaderValue::Single("Hello world".into()));

        let encoded = serde_ipld_dagcbor::to_vec(&map).expect("encode");
        let decoded: HeaderMapNode = serde_ipld_dagcbor::from_slice(&encoded).expect("decode");
        assert_eq!(map, decoded);
    }

    #[test]
    fn multi_value_roundtrip() {
        let mut map: HeaderMapNode = BTreeMap::new();
        map.insert(
            "received".into(),
            HeaderValue::Multi(vec![
                "from a.example by b.example".into(),
                "from c.example by d.example".into(),
            ]),
        );

        let encoded = serde_ipld_dagcbor::to_vec(&map).expect("encode");
        let decoded: HeaderMapNode = serde_ipld_dagcbor::from_slice(&encoded).expect("decode");
        assert_eq!(map, decoded);
    }

    #[test]
    fn empty_map_roundtrip() {
        let map: HeaderMapNode = BTreeMap::new();
        let encoded = serde_ipld_dagcbor::to_vec(&map).expect("encode");
        let decoded: HeaderMapNode = serde_ipld_dagcbor::from_slice(&encoded).expect("decode");
        assert_eq!(map, decoded);
    }

    #[test]
    fn keys_are_sorted() {
        let mut map: HeaderMapNode = BTreeMap::new();
        map.insert("zebra".into(), HeaderValue::Single("z".into()));
        map.insert("apple".into(), HeaderValue::Single("a".into()));
        map.insert("middle".into(), HeaderValue::Single("m".into()));

        let keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["apple", "middle", "zebra"]);
    }

    #[test]
    fn serialization_is_deterministic() {
        let mut map: HeaderMapNode = BTreeMap::new();
        map.insert(
            "from".into(),
            HeaderValue::Single("alice@example.com".into()),
        );
        map.insert(
            "received".into(),
            HeaderValue::Multi(vec!["hop1".into(), "hop2".into()]),
        );

        let bytes1 = serde_ipld_dagcbor::to_vec(&map).expect("encode 1");
        let bytes2 = serde_ipld_dagcbor::to_vec(&map).expect("encode 2");
        assert_eq!(bytes1, bytes2, "serialization must be byte-identical");
    }

    // ── build_header_map ──────────────────────────────────────────────────────

    // Test article header block: Content-Type + one From + two Received headers.
    const SAMPLE_HEADERS: &[u8] = b"\
From: alice@example.com\r\n\
Subject: Test article\r\n\
Content-Type: text/plain; charset=UTF-8\r\n\
Received: from a.example by b.example\r\n\
Received: from c.example by d.example\r\n\
\r\n";

    #[test]
    fn header_name_lowercased() {
        let map = build_header_map(SAMPLE_HEADERS);
        assert!(map.contains_key("from"), "From -> from");
        assert!(map.contains_key("subject"), "Subject -> subject");
        assert!(
            map.contains_key("content-type"),
            "Content-Type -> content-type"
        );
        assert!(!map.contains_key("From"), "must not have mixed-case key");
    }

    #[test]
    fn single_occurrence_is_single_variant() {
        let map = build_header_map(SAMPLE_HEADERS);
        assert!(
            matches!(map.get("from"), Some(HeaderValue::Single(_))),
            "From appears once -> Single"
        );
    }

    #[test]
    fn multi_occurrence_is_multi_variant() {
        let map = build_header_map(SAMPLE_HEADERS);
        match map.get("received") {
            Some(HeaderValue::Multi(v)) => {
                assert_eq!(v.len(), 2);
                assert!(v[0].contains("a.example"));
                assert!(v[1].contains("c.example"));
            }
            other => panic!("expected Multi, got {:?}", other),
        }
    }

    #[test]
    fn empty_input_produces_empty_map() {
        let map = build_header_map(b"");
        assert!(map.is_empty());
    }

    // ── RFC 2047 decoding ─────────────────────────────────────────────────────

    #[test]
    fn rfc2047_base64_utf8() {
        // Python oracle:
        //   import email.header
        //   email.header.decode_header("=?utf-8?B?Y2Fmw6k=?=")
        //   -> [(b'caf\xc3\xa9', 'utf-8')]  # decodes to "café"
        let input = "=?utf-8?B?Y2Fmw6k=?=";
        assert_eq!(decode_rfc2047(input), "café");
    }

    #[test]
    fn rfc2047_quoted_printable_utf8() {
        // Python oracle:
        //   import email.header
        //   email.header.decode_header("=?utf-8?Q?caf=C3=A9?=")
        //   -> [(b'caf\xc3\xa9', 'utf-8')]  # decodes to "café"
        let input = "=?utf-8?Q?caf=C3=A9?=";
        assert_eq!(decode_rfc2047(input), "café");
    }

    #[test]
    fn rfc2047_underscore_is_space() {
        // Python oracle:
        //   email.header.decode_header("=?utf-8?Q?Hello_world?=")
        //   -> [(b'Hello world', 'utf-8')]
        let input = "=?utf-8?Q?Hello_world?=";
        assert_eq!(decode_rfc2047(input), "Hello world");
    }

    #[test]
    fn rfc2047_latin1() {
        // Python oracle:
        //   email.header.decode_header("=?iso-8859-1?Q?caf=E9?=")
        //   -> [(b'caf\xe9', 'iso-8859-1')]  # decodes to "café"
        // ISO-8859-1 byte 0xE9 -> Unicode U+00E9 -> 'é'
        let input = "=?iso-8859-1?Q?caf=E9?=";
        assert_eq!(decode_rfc2047(input), "café");
    }

    #[test]
    fn rfc2047_no_encoded_words_unchanged() {
        let input = "Plain ASCII value";
        assert_eq!(decode_rfc2047(input), "Plain ASCII value");
    }

    #[test]
    fn rfc2047_encoded_word_in_header() {
        let raw = format!("Subject: {}\r\n\r\n", "=?utf-8?Q?Hello_world?=");
        let map = build_header_map(raw.as_bytes());
        assert_eq!(
            map.get("subject"),
            Some(&HeaderValue::Single("Hello world".into()))
        );
    }

    // ── Date transform (za1) ──────────────────────────────────────────────────

    #[test]
    fn date_header_rfc2822_to_rfc3339_utc() {
        // Python oracle:
        //   from email.utils import parsedate_to_datetime
        //   parsedate_to_datetime("Mon, 01 Jan 2024 00:00:00 +0000").isoformat()
        //   -> '2024-01-01T00:00:00+00:00'
        // chrono emits +00:00 (not Z) for this offset — both are valid RFC 3339.
        let raw = b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n";
        let map = build_header_map(raw);
        match map.get("date") {
            Some(HeaderValue::Single(s)) => {
                assert!(
                    s == "2024-01-01T00:00:00+00:00" || s == "2024-01-01T00:00:00Z",
                    "unexpected RFC 3339 output: {s}"
                );
            }
            other => panic!("expected Single date, got {:?}", other),
        }
    }

    #[test]
    fn date_header_rfc2822_to_rfc3339_negative_offset() {
        // Python oracle:
        //   parsedate_to_datetime("Wed, 03 Jan 2024 12:00:00 -0500").isoformat()
        //   -> '2024-01-03T12:00:00-05:00'
        let raw = b"Date: Wed, 03 Jan 2024 12:00:00 -0500\r\n\r\n";
        let map = build_header_map(raw);
        match map.get("date") {
            Some(HeaderValue::Single(s)) => {
                assert_eq!(s, "2024-01-03T12:00:00-05:00");
            }
            other => panic!("expected Single date, got {:?}", other),
        }
    }

    #[test]
    fn unparseable_date_stored_as_raw() {
        let raw = b"Expires: not-a-date-at-all\r\n\r\n";
        let map = build_header_map(raw);
        assert_eq!(
            map.get("expires"),
            Some(&HeaderValue::Single("not-a-date-at-all".into()))
        );
    }

    #[test]
    fn received_header_not_date_transformed() {
        let raw = b"Received: from a.example by b.example; Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n";
        let map = build_header_map(raw);
        match map.get("received") {
            Some(HeaderValue::Single(s)) => {
                assert!(
                    s.contains("a.example"),
                    "Received should be stored verbatim, not transformed: {s}"
                );
                assert!(
                    !s.starts_with("20"),
                    "Received should not be transformed to date-only: {s}"
                );
            }
            other => panic!("expected Single received, got {:?}", other),
        }
    }

    #[test]
    fn injection_date_transformed() {
        let raw = b"Injection-Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n";
        let map = build_header_map(raw);
        match map.get("injection-date") {
            Some(HeaderValue::Single(s)) => {
                assert!(
                    s.starts_with("2024-01-01"),
                    "Injection-Date should be RFC 3339: {s}"
                );
            }
            other => panic!("expected Single date, got {:?}", other),
        }
    }

    // ── Security: header name validation ────────────────────────────────────

    #[test]
    fn invalid_header_names_are_dropped() {
        // Header names with control chars, colons, or spaces must be dropped.
        let raw = b"X-Valid: ok\r\nX Bad: dropped\r\nX\x00Null: dropped\r\n\r\n";
        let map = build_header_map(raw);
        assert!(map.contains_key("x-valid"), "valid header present");
        assert!(!map.contains_key("x bad"), "space in name must be dropped");
        // null-containing keys can't be tested as string keys easily, but the
        // filter runs before insertion, so the key would never reach the map.
    }
}
