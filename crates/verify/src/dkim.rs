//! DKIM signature verification via `mail-auth`.
//!
//! Wraps `mail_auth::MessageAuthenticator::verify_dkim` to return
//! `ArticleVerification` results.  One result is produced per DKIM-Signature
//! header present in the article.

use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};

use crate::types::{ArticleVerification, SigType, VerifResult};

/// Verify all `DKIM-Signature` headers in `article_bytes`.
///
/// Returns one `ArticleVerification` per DKIM-Signature header found.
/// Returns an empty vec when no DKIM-Signature header is present.
///
/// Never panics or returns an error: DNS failures, parse errors, and
/// verification failures are all represented as non-Pass results.
pub async fn verify_dkim_headers(
    authenticator: &MessageAuthenticator,
    article_bytes: &[u8],
) -> Vec<ArticleVerification> {
    let msg = match AuthenticatedMessage::parse(article_bytes) {
        Some(m) => m,
        None => {
            return vec![ArticleVerification {
                sig_type: SigType::Dkim,
                result: VerifResult::ParseError {
                    reason: "mail-auth could not parse the article as an RFC 5322 message"
                        .to_owned(),
                },
                identity: None,
            }];
        }
    };

    let dkim_outputs = authenticator.verify_dkim(&msg).await;
    if dkim_outputs.is_empty() {
        return vec![];
    }

    dkim_outputs
        .iter()
        .map(|output| {
            let identity = output
                .signature()
                .map(|s| s.d.clone());

            let result = match output.result() {
                DkimResult::Pass => VerifResult::Pass,
                DkimResult::None => {
                    return ArticleVerification {
                        sig_type: SigType::Dkim,
                        result: VerifResult::NoKey,
                        identity,
                    };
                }
                DkimResult::Neutral(err) => VerifResult::Fail {
                    reason: format!("{err:?}"),
                },
                DkimResult::Fail(err) => VerifResult::Fail {
                    reason: format!("{err:?}"),
                },
                DkimResult::PermError(err) => VerifResult::Fail {
                    reason: format!("perm-error: {err:?}"),
                },
                DkimResult::TempError(err) => VerifResult::DnsError {
                    domain: identity.clone().unwrap_or_default(),
                    err: format!("{err:?}"),
                },
            };

            ArticleVerification {
                sig_type: SigType::Dkim,
                result,
                identity,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Under test cfg, mail-auth DNS resolver returns NXDomain for all lookups,
    /// so a real DKIM-Signature will result in a TempError or NoKey.
    /// This test just confirms the function returns results without panicking
    /// on a well-formed article.
    #[tokio::test]
    async fn no_dkim_header_returns_empty() {
        let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
        let article = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody.\r\n";
        let results = verify_dkim_headers(&authenticator, article).await;
        assert!(results.is_empty(), "article without DKIM header must produce no results");
    }

    #[tokio::test]
    async fn malformed_article_returns_parse_error() {
        let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
        // Completely malformed bytes that mail-auth cannot parse as an email.
        let bad = b"\x00\x01\x02";
        let results = verify_dkim_headers(&authenticator, bad).await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, VerifResult::ParseError { .. }));
    }
}
