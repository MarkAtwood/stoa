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

fn push_header(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Placeholder for future log-entry canonical serialization.
///
/// Will serialize a `LogEntry` to deterministic bytes for CID computation.
/// Not yet implemented; returns an empty `Vec` as a stub.
pub fn canonical_bytes_for_log_entry(_entry: &crate::group_log::types::LogEntry) -> Vec<u8> {
    // TODO(l62.3.x): implement when log-entry CID computation is scoped.
    Vec::new()
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
        assert!(
            std::str::from_utf8(&bytes_a)
                .unwrap()
                .contains("Newsgroups: alt.atheism,sci.skeptic,talk.origins\r\n")
        );
    }

    /// Log-entry stub returns empty bytes (not yet implemented).
    #[test]
    fn log_entry_stub_returns_empty() {
        use crate::group_log::types::LogEntry;
        use cid::Cid;
        use multihash_codetable::{Code, MultihashDigest};

        let digest = Code::Sha2_256.digest(b"stub");
        // RAW codec = 0x55
        let cid = Cid::new_v1(0x55, digest);
        let entry = LogEntry {
            hlc_timestamp: 0,
            article_cid: cid,
            operator_signature: vec![],
            parent_cids: vec![],
        };
        assert_eq!(canonical_bytes_for_log_entry(&entry), Vec::<u8>::new());
    }

    /// Roundtrip consistency: canonical_bytes called twice on the same article
    /// must return identical results (idempotency).
    #[test]
    fn canonical_bytes_idempotent() {
        let article = base_article();
        assert_eq!(canonical_bytes(&article), canonical_bytes(&article));
    }
}
