/// CID computation for stoa articles.
///
/// `cid_for_article` computes a CIDv1 RAW (codec 0x55) SHA2-256 digest of an
/// article's canonical byte representation.  The canonical bytes are defined by
/// [`crate::canonical::canonical_bytes`].  This CID is used as the stable
/// content-address for deduplication and Message-ID mapping.
///
/// # Codec choice
/// RAW (0x55) is used here because the input is an opaque byte string — the
/// canonical serialisation is not an IPLD node in its own right.  The article
/// *root node* CID (stored in IPFS) uses DAG-CBOR (0x71) and is computed by
/// [`crate::ipld::build_article`].
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::article::Article;
use crate::canonical::canonical_bytes;
use crate::ipld::codec::CODEC_RAW;

/// Compute a CIDv1 RAW SHA2-256 content address for `article`.
///
/// The hash input is [`canonical_bytes`] of the article, which is
/// deterministic for a given logical article regardless of insertion order of
/// `extra_headers` or `newsgroups`.
pub fn cid_for_article(article: &Article) -> Cid {
    let bytes = canonical_bytes(article);
    let digest = Code::Sha2_256.digest(&bytes);
    Cid::new_v1(CODEC_RAW, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::article::{ArticleBody, ArticleHeader, GroupName};

    /// Build the same article used by the canonical-serialisation stability
    /// regression test so this test can cross-validate against the Python
    /// reference vector computed independently with `hashlib.sha256`.
    fn reference_article() -> Article {
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

    /// Reference vector computed by Python `hashlib`:
    ///
    /// ```python
    /// import hashlib
    /// canonical = (
    ///     b"From: user@example.com\r\n"
    ///     b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
    ///     b"Message-ID: <test@example.com>\r\n"
    ///     b"Newsgroups: comp.lang.rust\r\n"
    ///     b"Subject: Test subject\r\n"
    ///     b"Path: news.example.com!user\r\n"
    ///     b"\x00\n"
    ///     b"Body text.\r\n"
    /// )
    /// print(hashlib.sha256(canonical).hexdigest())
    /// # 1e6a730aeedb59c8be15d0d602e80b56f90786e607b386be542b47665b586a79
    /// ```
    ///
    /// CIDv1 RAW = 0x01 (version) + 0x55 (codec) + 0x12 (sha2-256 fn) + 0x20 (32 bytes) + digest
    #[test]
    fn cid_for_article_matches_python_reference_vector() {
        let article = reference_article();
        let cid = cid_for_article(&article);

        // Codec must be RAW (0x55).
        assert_eq!(cid.codec(), CODEC_RAW, "codec must be RAW (0x55)");

        // Hash must be SHA2-256.
        assert_eq!(
            cid.hash().code(),
            0x12,
            "multihash function must be SHA2-256 (0x12)"
        );

        // Digest bytes must match the Python reference vector.
        let expected_digest =
            hex::decode("1e6a730aeedb59c8be15d0d602e80b56f90786e607b386be542b47665b586a79")
                .unwrap();
        assert_eq!(
            cid.hash().digest(),
            expected_digest.as_slice(),
            "SHA2-256 digest must match Python hashlib reference"
        );
    }

    /// Two calls on the same article must return the same CID (idempotency).
    #[test]
    fn cid_for_article_is_idempotent() {
        let article = reference_article();
        assert_eq!(cid_for_article(&article), cid_for_article(&article));
    }

    /// Changing any byte of the body must produce a different CID.
    #[test]
    fn different_body_produces_different_cid() {
        let mut a = reference_article();
        let mut b = reference_article();
        a.body = ArticleBody::from_text("Body A\r\n");
        b.body = ArticleBody::from_text("Body B\r\n");
        assert_ne!(cid_for_article(&a), cid_for_article(&b));
    }
}
