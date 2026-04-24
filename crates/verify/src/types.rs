//! Shared types for verification results.

use serde::{Deserialize, Serialize};

/// Which signature scheme produced this result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigType {
    /// `X-Usenet-IPFS-Sig` Ed25519 article signature.
    XUsenetIpfsSig,
    /// `DKIM-Signature` header, verified via DNS TXT lookup.
    Dkim,
}

impl SigType {
    /// Short string used as the `sig_type` column value in SQLite.
    pub fn as_str(&self) -> &'static str {
        match self {
            SigType::XUsenetIpfsSig => "x-usenet-ipfs-sig",
            SigType::Dkim => "dkim",
        }
    }
}

/// Outcome of verifying one signature on an article.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifResult {
    /// Signature verified successfully.
    Pass,
    /// Signature was present and parseable but did not verify.
    Fail { reason: String },
    /// DNS lookup required for verification failed transiently.
    DnsError { domain: String, err: String },
    /// No usable public key found.
    NoKey,
    /// The signature header could not be parsed.
    ParseError { reason: String },
}

impl VerifResult {
    /// Short string stored as the `result` column value in SQLite.
    pub fn as_str(&self) -> &'static str {
        match self {
            VerifResult::Pass => "pass",
            VerifResult::Fail { .. } => "fail",
            VerifResult::DnsError { .. } => "dns-error",
            VerifResult::NoKey => "no-key",
            VerifResult::ParseError { .. } => "parse-error",
        }
    }

    /// Human-readable failure reason, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            VerifResult::Fail { reason } => Some(reason),
            VerifResult::DnsError { err, .. } => Some(err),
            VerifResult::ParseError { reason } => Some(reason),
            _ => None,
        }
    }

    /// True when the signature positively verified.
    pub fn is_pass(&self) -> bool {
        matches!(self, VerifResult::Pass)
    }
}

/// One signature verification result for an article.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArticleVerification {
    pub sig_type: SigType,
    pub result: VerifResult,
    /// Signing identity: pubkey hex (x-usenet-ipfs-sig) or domain (DKIM).
    pub identity: Option<String>,
}
