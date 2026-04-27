//! Canonical serialization for articles and log entries.
//!
//! The canonical byte representation is used for hashing and signing. It must
//! be deterministic: the same logical article always produces the same bytes,
//! regardless of the order in which `extra_headers` were inserted.
//!
//! # Format
//!
//! ```text
//! From: {value}\r\n
//! Date: {value}\r\n
//! Message-ID: {value}\r\n
//! Newsgroups: {sorted-groups-comma-separated}\r\n
//! Subject: {value}\r\n
//! Path: {value}\r\n
//! {extra_headers sorted by key, then by value, each as "Key: value\r\n"}
//! \x00\n
//! {raw body bytes}
//! ```
//!
//! The `\x00\n` separator is chosen so that it cannot appear in well-formed
//! RFC 5322 header values (NUL is forbidden), making the header/body boundary
//! unambiguous in the canonical stream.

use cid::Cid;

use crate::article::Article;

/// Serialize `article` to a deterministic byte string suitable for hashing or
/// signing.
///
/// See module-level documentation for the exact format.
pub fn canonical_bytes(article: &Article) -> Vec<u8> {
    let h = &article.header;
    let mut out = Vec::new();

    // Mandatory headers in fixed order.
    push_header(&mut out, "From", &h.from);
    push_header(&mut out, "Date", &h.date);
    push_header(&mut out, "Message-ID", &h.message_id);

    // Newsgroups: sort group names lexicographically before joining.
    let mut groups: Vec<&str> = h.newsgroups.iter().map(|g| g.as_str()).collect();
    groups.sort_unstable();
    push_header(&mut out, "Newsgroups", &groups.join(","));

    push_header(&mut out, "Subject", &h.subject);
    push_header(&mut out, "Path", &h.path);

    // Extra headers: sort by key (primary), then by value (secondary) so that
    // duplicate keys are also ordered deterministically.
    let mut extra: Vec<(&str, &str)> = h
        .extra_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    extra.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));
    for (k, v) in extra {
        push_header(&mut out, k, v);
    }

    // Header/body separator.
    out.extend_from_slice(b"\x00\n");

    // Raw body bytes.
    out.extend_from_slice(&article.body.bytes);

    out
}

/// Compute the canonical bytes for a log entry that are covered by the
/// operator signature.
///
/// Layout: `hlc_timestamp` as 8 big-endian bytes, followed by `article_cid`
/// bytes, followed by each parent CID's bytes sorted lexicographically.
///
/// This is the byte string that [`crate::signing::sign`] produces and
/// [`crate::signing::verify`] checks. The signature field itself is excluded
/// from the signed content.
pub fn log_entry_canonical_bytes(
    hlc_timestamp: u64,
    article_cid: &Cid,
    parent_cids: &[Cid],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&hlc_timestamp.to_be_bytes());
    out.extend_from_slice(&article_cid.to_bytes());
    let mut parent_bytes: Vec<Vec<u8>> = parent_cids.iter().map(|c| c.to_bytes()).collect();
    parent_bytes.sort();
    for pb in &parent_bytes {
        out.extend_from_slice(pb);
    }
    out
}

/// Compute the byte string from which a [`LogEntryId`] is derived.
///
/// Layout: `hlc_timestamp` as 8 big-endian bytes, `article_cid` bytes,
/// `operator_signature` bytes, then each parent CID's bytes sorted
/// lexicographically.
///
/// Unlike [`log_entry_canonical_bytes`] (which is signed over and therefore
/// excludes the signature), this function *includes* the signature so that
/// two entries that are identical except for their signature produce
/// different IDs.
///
/// # DECISION (rbe3.74): signature is included for ID uniqueness
///
/// `entry_id_bytes` includes `operator_signature` while
/// `log_entry_canonical_bytes` (the thing actually signed) excludes it.
/// This asymmetry is intentional and must not be "unified":
/// - If IDs excluded the signature, two operators signing the same article
///   at identical HLC timestamps would produce the same ID, and one entry
///   would overwrite the other in the group log store.
/// - If the signing input included the signature, it would be circular
///   (you cannot sign data that includes its own signature).
/// Do NOT add `operator_signature` to `log_entry_canonical_bytes` and do
/// NOT remove it from `entry_id_bytes`.
pub fn entry_id_bytes(
    hlc_timestamp: u64,
    article_cid: &Cid,
    operator_signature: &[u8],
    parent_cids: &[Cid],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&hlc_timestamp.to_be_bytes());
    out.extend_from_slice(&article_cid.to_bytes());
    out.extend_from_slice(operator_signature);
    let mut parent_bytes: Vec<Vec<u8>> = parent_cids.iter().map(|c| c.to_bytes()).collect();
    parent_bytes.sort();
    for pb in &parent_bytes {
        out.extend_from_slice(pb);
    }
    out
}

fn push_header(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::article::{Article, ArticleBody, ArticleHeader, GroupName};

    fn base_article() -> Article {
        Article {
            header: ArticleHeader {
                from: "user@example.com".into(),
                date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
                message_id: "<test@example.com>".into(),
                newsgroups: vec![GroupName::new("comp.lang.rust").unwrap()],
                subject: "Test subject".into(),
                path: "news.example.com!user".into(),
                extra_headers: vec![],
            },
            body: ArticleBody::from_text("Body text.\r\n"),
        }
    }

    /// Stability regression: the canonical bytes of a known article must not
    /// change across code changes. This is the authoritative test vector for
    /// the canonical format; the expected bytes were computed by hand from the
    /// format specification above, not derived from the implementation.
    ///
    /// # DECISION (rbe3.76): independent oracle is mandatory
    ///
    /// The expected bytes MUST be constructed by hand from the format spec,
    /// not derived from calling `canonical_bytes()` itself.  A test that
    /// calls the function twice and compares the results verifies idempotency
    /// only — it cannot detect a systematic encoding bug.  If you need to
    /// update this test, re-derive the expected bytes from the spec, byte by
    /// byte, and document the derivation in a comment.
    #[test]
    fn stability_regression() {
        let article = base_article();
        let bytes = canonical_bytes(&article);

        // Build expected bytes by hand according to the spec.
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"From: user@example.com\r\n");
        expected.extend_from_slice(b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n");
        expected.extend_from_slice(b"Message-ID: <test@example.com>\r\n");
        expected.extend_from_slice(b"Newsgroups: comp.lang.rust\r\n");
        expected.extend_from_slice(b"Subject: Test subject\r\n");
        expected.extend_from_slice(b"Path: news.example.com!user\r\n");
        expected.extend_from_slice(b"\x00\n");
        expected.extend_from_slice(b"Body text.\r\n");

        assert_eq!(bytes, expected);
    }

    /// Extra-header order independence: inserting extra headers in different
    /// orders must produce the same canonical bytes.
    #[test]
    fn extra_header_order_independence() {
        let mut a = base_article();
        a.header.extra_headers = vec![
            ("X-Mailer".into(), "newsraft".into()),
            ("Organization".into(), "ACME Corp".into()),
        ];

        let mut b = base_article();
        b.header.extra_headers = vec![
            ("Organization".into(), "ACME Corp".into()),
            ("X-Mailer".into(), "newsraft".into()),
        ];

        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
    }

    /// Newsgroups multi-group sort: groups must appear in lexicographic order
    /// regardless of insertion order.
    #[test]
    fn newsgroups_multi_group_sort() {
        let mut a = base_article();
        a.header.newsgroups = vec![
            GroupName::new("talk.origins").unwrap(),
            GroupName::new("alt.atheism").unwrap(),
            GroupName::new("sci.skeptic").unwrap(),
        ];

        let mut b = base_article();
        b.header.newsgroups = vec![
            GroupName::new("alt.atheism").unwrap(),
            GroupName::new("sci.skeptic").unwrap(),
            GroupName::new("talk.origins").unwrap(),
        ];

        let bytes_a = canonical_bytes(&a);
        let bytes_b = canonical_bytes(&b);
        assert_eq!(bytes_a, bytes_b);

        // The Newsgroups line must be in sorted order.
        assert!(std::str::from_utf8(&bytes_a)
            .unwrap()
            .contains("Newsgroups: alt.atheism,sci.skeptic,talk.origins\r\n"));
    }

    /// Roundtrip consistency: canonical_bytes called twice on the same article
    /// must return identical results (idempotency).
    #[test]
    fn canonical_bytes_idempotent() {
        let article = base_article();
        assert_eq!(canonical_bytes(&article), canonical_bytes(&article));
    }
}
