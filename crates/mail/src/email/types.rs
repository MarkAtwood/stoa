use std::collections::HashMap;

use cid::Cid;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use stoa_core::ipld::{
    header_map::{HeaderMapNode, HeaderValue},
    root_node::ArticleRootNode,
};

use crate::mailbox::types::mailbox_id_for_group;

/// One verification result entry for the `x-stoa-verifications` JMAP property.
///
/// Mirrors `stoa_verify::ArticleVerification` but uses plain `String` fields
/// so the mail crate does not depend on the verify crate.  The JMAP handler converts
/// from `ArticleVerification` to `VerificationSummary` before populating the Email.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationSummary {
    /// Signature scheme: `"x-stoa-sig"` or `"dkim"`.
    #[serde(rename = "sigType")]
    pub sig_type: String,
    /// Outcome: `"pass"`, `"fail"`, `"no-key"`, `"dns-error"`, or `"parse-error"`.
    pub result: String,
    /// Signing identity: pubkey hex (x-stoa-sig) or domain (DKIM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// A single email address (RFC 8621 §4.1.2.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub email: String,
}

/// A minimal JMAP Email object derived from an ArticleRootNode.
///
/// Fields follow RFC 8621 §4.1. Unknown or unavailable fields are omitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Email {
    /// JMAP id (= CID string).
    pub id: String,
    /// Blob id for downloading raw content (= CID string).
    #[serde(rename = "blobId")]
    pub blob_id: String,
    /// Map of mailbox-id → true.
    #[serde(rename = "mailboxIds")]
    pub mailbox_ids: HashMap<String, bool>,
    /// JMAP keywords (\Seen etc.) — empty until user-flags are wired.
    pub keywords: HashMap<String, bool>,
    /// Received-at timestamp in RFC 3339 format (from HLC timestamp).
    #[serde(rename = "receivedAt")]
    pub received_at: String,
    /// Total size in bytes.
    pub size: u64,
    /// From header addresses.
    pub from: Option<Vec<EmailAddress>>,
    /// Subject header value.
    pub subject: Option<String>,
    /// Message-ID header value.
    #[serde(rename = "messageId")]
    pub message_id: Option<Vec<String>>,
    /// In-Reply-To header values.
    #[serde(rename = "inReplyTo")]
    pub in_reply_to: Option<Vec<String>>,
    /// References header values.
    pub references: Option<Vec<String>>,
    /// First 256 chars of body text (None unless body is provided).
    pub preview: Option<String>,
    /// Custom property: IPFS root CID string (DAG-CBOR, codec 0x71).
    ///
    /// Identical to `id` and `blob_id`.  Advertised via the
    /// `urn:stoa:jmap:cid` session capability.  Clients that do not
    /// recognise this property may ignore it per RFC 8620 §3.3.
    #[serde(rename = "x-stoa-cid")]
    pub ipfs_cid: String,
    /// Custom property: base64url-no-pad encoded operator Ed25519 signature.
    ///
    /// Present only when the article carries an `X-Stoa-Sig` operator
    /// signature (i.e. `metadata.operator_signature` is non-empty).  Absent
    /// on unsigned articles.  Clients can verify by downloading the blob,
    /// stripping this header value, and running ed25519 verify over the
    /// resulting bytes against the operator's public key.
    #[serde(rename = "x-stoa-sig", skip_serializing_if = "Option::is_none")]
    pub ipfs_sig: Option<String>,
    /// Custom property: verification results for all signatures checked on this article.
    ///
    /// Absent when no verification has been performed (i.e. the verify store returned
    /// no entries for this CID).  Populated by the JMAP handler from the verify store;
    /// `from_root_node` always sets this to `None`.  Callers that have access to a
    /// verify store should set it after construction.
    #[serde(
        rename = "x-stoa-verifications",
        skip_serializing_if = "Option::is_none"
    )]
    pub ipfs_verifications: Option<Vec<VerificationSummary>>,
}

impl Email {
    /// Build a JMAP Email from an ArticleRootNode and its CID.
    ///
    /// `header_map` may be None if the structured header block is unavailable;
    /// in that case, subject/from/etc. are extracted from metadata.message_id only.
    pub fn from_root_node(
        cid: &Cid,
        root: &ArticleRootNode,
        header_map: Option<&HeaderMapNode>,
        keywords: HashMap<String, bool>,
        preview: Option<String>,
    ) -> Self {
        let cid_str = cid.to_string();

        // Build mailboxIds from newsgroups.
        let mailbox_ids: HashMap<String, bool> = root
            .metadata
            .newsgroups
            .iter()
            .map(|g| (mailbox_id_for_group(g), true))
            .collect();

        // receivedAt: HLC timestamp (ms) → RFC 3339.
        let received_at = hlc_ms_to_rfc3339(root.metadata.hlc_timestamp);

        // Extract headers from header_map if available.
        let subject = header_map.and_then(|hm| get_single(hm, "subject"));
        let from = header_map
            .and_then(|hm| get_single(hm, "from"))
            .map(|s| parse_addresses(&s));
        let message_id = Some(vec![root.metadata.message_id.clone()]);
        let in_reply_to = header_map
            .and_then(|hm| get_single(hm, "in-reply-to"))
            .map(|s| vec![s]);
        let references = header_map
            .and_then(|hm| get_single(hm, "references"))
            .map(|s| s.split_whitespace().map(str::to_string).collect());

        // Encode operator signature bytes as base64url-no-pad, or None if unsigned.
        let ipfs_sig = if root.metadata.operator_signature.is_empty() {
            None
        } else {
            Some(BASE64URL_NOPAD.encode(&root.metadata.operator_signature))
        };

        Email {
            id: cid_str.clone(),
            blob_id: cid_str.clone(),
            mailbox_ids,
            keywords,
            received_at,
            size: root.metadata.byte_count,
            from,
            subject,
            message_id,
            in_reply_to,
            references,
            preview,
            ipfs_cid: cid_str,
            ipfs_sig,
            ipfs_verifications: None,
        }
    }
}

/// Convert HLC millisecond timestamp to RFC 3339 UTC string.
///
/// Uses `chrono` for correct calendar arithmetic. Returns the RFC 3339
/// representation with `+00:00` UTC offset (e.g. `"2024-01-01T00:00:00+00:00"`).
/// On the extremely unlikely case that `hlc_ms` is out of chrono's representable
/// range, logs a warning and returns the Unix epoch sentinel.
fn hlc_ms_to_rfc3339(hlc_ms: u64) -> String {
    use chrono::{DateTime, Utc};
    match DateTime::<Utc>::from_timestamp_millis(hlc_ms as i64) {
        Some(dt) => dt.to_rfc3339(),
        None => {
            tracing::warn!(
                hlc_ms,
                "HLC timestamp out of chrono range; using epoch sentinel"
            );
            "1970-01-01T00:00:00+00:00".to_string()
        }
    }
}

fn get_single(hm: &HeaderMapNode, key: &str) -> Option<String> {
    match hm.get(key) {
        Some(HeaderValue::Single(s)) => Some(s.clone()),
        Some(HeaderValue::Multi(v)) => v.first().cloned(),
        None => None,
    }
}

/// Parse a comma-separated RFC 5322 address list into EmailAddress structs.
///
/// Handles display names (`Name <addr@example.com>`) and bare addresses
/// (`addr@example.com`). Silently ignores group addresses and unparseable
/// entries rather than returning a single opaque raw string.
fn parse_addresses(raw: &str) -> Vec<EmailAddress> {
    let parsed = match mailparse::addrparse(raw) {
        Ok(list) => list,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    for entry in parsed.iter() {
        match entry {
            mailparse::MailAddr::Single(info) => {
                out.push(EmailAddress {
                    name: info.display_name.clone(),
                    email: info.addr.clone(),
                });
            }
            mailparse::MailAddr::Group(group) => {
                for info in &group.addrs {
                    out.push(EmailAddress {
                        name: info.display_name.clone(),
                        email: info.addr.clone(),
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};
    use stoa_core::ipld::root_node::{ArticleMetadata, ArticleRootNode};

    fn dummy_cid(seed: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(seed))
    }

    fn dummy_root(newsgroups: Vec<String>, hlc_ms: u64, byte_count: u64) -> ArticleRootNode {
        ArticleRootNode {
            schema_version: 1,
            header_cid: dummy_cid(b"header"),
            header_map_cid: None,
            body_cid: dummy_cid(b"body"),
            mime_cid: None,
            metadata: ArticleMetadata {
                message_id: "<test@example.com>".to_string(),
                newsgroups,
                hlc_timestamp: hlc_ms,
                operator_signature: vec![],
                byte_count,
                line_count: 1,
                content_type_summary: "text/plain".to_string(),
            },
        }
    }

    #[test]
    fn from_root_node_basic() {
        let cid = dummy_cid(b"article");
        let root = dummy_root(vec!["comp.lang.rust".to_string()], 1_000_000_000_000, 512);
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        assert_eq!(email.id, cid.to_string());
        assert_eq!(email.blob_id, cid.to_string());
        assert_eq!(email.size, 512);
        assert!(email.mailbox_ids.values().all(|v| *v));
        assert_eq!(email.mailbox_ids.len(), 1);
    }

    #[test]
    fn ipfs_cid_property_equals_id() {
        let cid = dummy_cid(b"article_cid_prop");
        let root = dummy_root(vec!["comp.test".to_string()], 1_000_000_000_000, 128);
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        assert_eq!(
            email.ipfs_cid,
            cid.to_string(),
            "x-stoa-cid must equal the email id (root CID)"
        );
    }

    #[test]
    fn ipfs_cid_serializes_as_custom_property() {
        let cid = dummy_cid(b"article_serial");
        let root = dummy_root(vec!["comp.test".to_string()], 1_000_000_000_000, 64);
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        let json = serde_json::to_string(&email).unwrap();
        assert!(
            json.contains("\"x-stoa-cid\""),
            "serialized email must contain x-stoa-cid key"
        );
        assert!(
            json.contains(&cid.to_string()),
            "serialized email must contain the CID value"
        );
    }

    #[test]
    fn received_at_is_rfc3339() {
        let cid = dummy_cid(b"article2");
        let root = dummy_root(vec!["alt.test".to_string()], 1_714_560_000_000, 100);
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        // chrono::to_rfc3339() emits UTC offset as "+00:00", which is a valid RFC 3339 form.
        assert!(
            email.received_at.ends_with("+00:00"),
            "must end with +00:00: {}",
            email.received_at
        );
        assert!(
            email.received_at.contains('T'),
            "must contain T: {}",
            email.received_at
        );
    }

    // ---------- hlc_ms_to_rfc3339 pinned test vectors ----------
    //
    // Independent oracle: Python `datetime.utcfromtimestamp(ms/1000).isoformat()` and
    // `date -d '...' +%s` on Linux, cross-checked against RFC 3339 §5.8 examples.
    // chrono::to_rfc3339() emits "+00:00" not "Z"; both are valid per RFC 3339 §4.2.

    #[test]
    fn hlc_ms_to_rfc3339_unix_epoch() {
        // ms=0 is the Unix epoch: 1970-01-01T00:00:00 UTC.
        // Oracle: universally agreed reference point; no computation required.
        assert_eq!(hlc_ms_to_rfc3339(0), "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn hlc_ms_to_rfc3339_2024_01_01() {
        // ms=1704067200000 → 2024-01-01T00:00:00 UTC.
        // Oracle: `date -d '2024-01-01 00:00:00 UTC' +%s` → 1704067200 (verified on Linux).
        // Python: datetime(2024,1,1,tzinfo=timezone.utc).timestamp() == 1704067200.0
        assert_eq!(
            hlc_ms_to_rfc3339(1_704_067_200_000),
            "2024-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn hlc_ms_to_rfc3339_fractional_seconds() {
        // ms=1704067200500 → 2024-01-01T00:00:00.500 UTC.
        // Oracle: base timestamp 1704067200000 (verified above) plus 500 ms.
        assert_eq!(
            hlc_ms_to_rfc3339(1_704_067_200_500),
            "2024-01-01T00:00:00.500+00:00"
        );
    }

    #[test]
    fn hlc_ms_to_rfc3339_leap_day() {
        // ms=1709251200000 → 2024-03-01T00:00:00 UTC (day after 2024 leap day Feb 29).
        // Oracle: `date -d '2024-03-01 00:00:00 UTC' +%s` → 1709251200.
        // This catches off-by-one errors in leap-year month boundaries.
        assert_eq!(
            hlc_ms_to_rfc3339(1_709_251_200_000),
            "2024-03-01T00:00:00+00:00"
        );
    }

    #[test]
    fn message_id_from_metadata() {
        let cid = dummy_cid(b"article3");
        let root = dummy_root(vec!["comp.test".to_string()], 0, 100);
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        assert_eq!(
            email.message_id,
            Some(vec!["<test@example.com>".to_string()])
        );
    }

    #[test]
    fn subject_from_header_map() {
        use stoa_core::ipld::header_map::HeaderMapNode;
        let cid = dummy_cid(b"article4");
        let root = dummy_root(vec!["comp.test".to_string()], 0, 100);
        let mut hm = HeaderMapNode::new();
        hm.insert(
            "subject".to_string(),
            HeaderValue::Single("Test Subject".to_string()),
        );
        let email = Email::from_root_node(&cid, &root, Some(&hm), HashMap::new(), None);
        assert_eq!(email.subject, Some("Test Subject".to_string()));
    }

    #[test]
    fn parse_addresses_bare_addr() {
        let addrs = parse_addresses("alice@example.com");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].email, "alice@example.com");
        assert_eq!(addrs[0].name, None);
    }

    #[test]
    fn parse_addresses_display_name_and_angle_addr() {
        let addrs = parse_addresses("Alice Smith <alice@example.com>");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].email, "alice@example.com");
        assert_eq!(addrs[0].name, Some("Alice Smith".to_string()));
    }

    #[test]
    fn parse_addresses_comma_separated_list() {
        let addrs = parse_addresses("alice@example.com, Bob <bob@example.com>");
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].email, "alice@example.com");
        assert_eq!(addrs[1].email, "bob@example.com");
        assert_eq!(addrs[1].name, Some("Bob".to_string()));
    }

    #[test]
    fn parse_addresses_empty_returns_empty() {
        assert!(parse_addresses("").is_empty());
    }

    fn dummy_root_signed(
        newsgroups: Vec<String>,
        hlc_ms: u64,
        byte_count: u64,
        sig_bytes: Vec<u8>,
    ) -> ArticleRootNode {
        ArticleRootNode {
            schema_version: 1,
            header_cid: dummy_cid(b"header"),
            header_map_cid: None,
            body_cid: dummy_cid(b"body"),
            mime_cid: None,
            metadata: ArticleMetadata {
                message_id: "<test@example.com>".to_string(),
                newsgroups,
                hlc_timestamp: hlc_ms,
                operator_signature: sig_bytes,
                byte_count,
                line_count: 1,
                content_type_summary: "text/plain".to_string(),
            },
        }
    }

    #[test]
    fn ipfs_sig_absent_when_unsigned() {
        // Oracle: empty operator_signature bytes → field must not appear in JSON.
        let cid = dummy_cid(b"unsigned");
        let root = dummy_root(vec!["comp.test".to_string()], 1_000_000_000_000, 64);
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        assert!(
            email.ipfs_sig.is_none(),
            "unsigned article must have None ipfs_sig"
        );
        let json = serde_json::to_string(&email).unwrap();
        assert!(
            !json.contains("x-stoa-sig"),
            "unsigned article must omit x-stoa-sig from JSON"
        );
    }

    #[test]
    fn ipfs_sig_present_when_signed() {
        // Oracle: base64url-no-pad([0x01,0x02,0x03,0x04]) = "AQIDBA" (standard test vector).
        let sig_bytes = vec![0x01u8, 0x02, 0x03, 0x04];
        let cid = dummy_cid(b"signed");
        let root = dummy_root_signed(
            vec!["comp.test".to_string()],
            1_000_000_000_000,
            64,
            sig_bytes,
        );
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        assert_eq!(
            email.ipfs_sig.as_deref(),
            Some("AQIDBA"),
            "base64url-no-pad encoding of [0x01,0x02,0x03,0x04] must equal AQIDBA"
        );
    }

    #[test]
    fn ipfs_sig_serializes_in_json_and_roundtrips() {
        // Oracle: base64url-no-pad([0x01,0x02,0x03,0x04]) = "AQIDBA"; decode back yields original.
        let sig_bytes = vec![0x01u8, 0x02, 0x03, 0x04];
        let cid = dummy_cid(b"signed_rt");
        let root = dummy_root_signed(
            vec!["comp.test".to_string()],
            1_000_000_000_000,
            64,
            sig_bytes.clone(),
        );
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        let json = serde_json::to_string(&email).unwrap();
        assert!(
            json.contains("\"x-stoa-sig\""),
            "signed article must include x-stoa-sig key in JSON"
        );
        // Decode the serialized value and verify it matches the original bytes.
        let sig_val = email.ipfs_sig.as_deref().unwrap();
        let decoded = BASE64URL_NOPAD.decode(sig_val.as_bytes()).unwrap();
        assert_eq!(
            decoded, sig_bytes,
            "base64url-no-pad decode must recover original bytes"
        );
    }

    #[test]
    fn verifications_absent_when_none() {
        // When ipfs_verifications is None (default from from_root_node), the property
        // must not appear in serialized JSON.
        let cid = dummy_cid(b"no_verif");
        let root = dummy_root(vec!["comp.test".to_string()], 1_000_000_000_000, 64);
        let email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        assert!(
            email.ipfs_verifications.is_none(),
            "from_root_node must leave ipfs_verifications as None"
        );
        let json = serde_json::to_string(&email).unwrap();
        assert!(
            !json.contains("x-stoa-verifications"),
            "x-stoa-verifications must be absent from JSON when None"
        );
    }

    #[test]
    fn verifications_serializes_correctly() {
        // Oracle: hand-crafted expected JSON structure verified against the field spec.
        let cid = dummy_cid(b"with_verif");
        let root = dummy_root(vec!["comp.test".to_string()], 1_000_000_000_000, 64);
        let mut email = Email::from_root_node(&cid, &root, None, HashMap::new(), None);
        email.ipfs_verifications = Some(vec![
            VerificationSummary {
                sig_type: "x-stoa-sig".to_string(),
                result: "pass".to_string(),
                identity: Some("abc123".to_string()),
            },
            VerificationSummary {
                sig_type: "dkim".to_string(),
                result: "fail".to_string(),
                identity: Some("example.com".to_string()),
            },
        ]);
        let json = serde_json::to_string(&email).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let verifs = parsed["x-stoa-verifications"]
            .as_array()
            .expect("x-stoa-verifications must be a JSON array");
        assert_eq!(verifs.len(), 2, "must have exactly 2 verification entries");
        assert_eq!(
            verifs[0]["sigType"].as_str().unwrap(),
            "x-stoa-sig",
            "first entry sigType must be x-stoa-sig"
        );
        assert_eq!(
            verifs[0]["result"].as_str().unwrap(),
            "pass",
            "first entry result must be pass"
        );
        assert_eq!(
            verifs[0]["identity"].as_str().unwrap(),
            "abc123",
            "first entry identity must be abc123"
        );
        assert_eq!(
            verifs[1]["sigType"].as_str().unwrap(),
            "dkim",
            "second entry sigType must be dkim"
        );
        assert_eq!(
            verifs[1]["result"].as_str().unwrap(),
            "fail",
            "second entry result must be fail"
        );
        assert_eq!(
            verifs[1]["identity"].as_str().unwrap(),
            "example.com",
            "second entry identity must be example.com"
        );
    }

    #[test]
    fn verification_summary_identity_omitted_when_none() {
        // When identity is None, it must not appear in the serialized JSON entry.
        let summary = VerificationSummary {
            sig_type: "dkim".to_string(),
            result: "no-key".to_string(),
            identity: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(
            !json.contains("identity"),
            "identity must be absent from JSON when None"
        );
        assert!(
            json.contains("\"sigType\""),
            "sigType must be present in JSON"
        );
        assert!(
            json.contains("\"no-key\""),
            "result value must be present in JSON"
        );
    }
}
