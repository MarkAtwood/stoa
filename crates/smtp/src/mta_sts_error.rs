use std::fmt;

/// Typed errors for MTA-STS policy lookup, fetch, parse, and enforcement.
#[derive(Debug)]
pub enum MtaStsError {
    /// No `_mta-sts.<domain>` TXT record found.
    DnsTxtNotFound,
    /// TXT record found but failed validation (wrong version, bad id, multiple records).
    DnsTxtInvalid(String),
    /// HTTPS fetch of policy file failed (network, cert, redirect, timeout, size).
    PolicyFetchFailed(String),
    /// Policy file body failed to parse (missing field, bad value, oversized body).
    PolicyParseFailed(String),
    /// Cached policy_id does not match the current DNS TXT record id.
    PolicyIdMismatch { cached: String, dns: String },
    /// Connecting MX hostname does not match any pattern in the policy.
    MxNotMatched { mx: String },
    /// Next-hop MTA did not advertise REQUIRETLS but REQUIRETLS was required.
    TlsRequiredNotAdvertised,
    /// TLS certificate validation failed on outbound connection.
    TlsCertInvalid(String),
}

impl fmt::Display for MtaStsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MtaStsError::DnsTxtNotFound => {
                write!(f, "MTA-STS: no TXT record found")
            }
            MtaStsError::DnsTxtInvalid(msg) => {
                write!(f, "MTA-STS: invalid TXT record: {}", msg)
            }
            MtaStsError::PolicyFetchFailed(msg) => {
                write!(f, "MTA-STS: policy fetch failed: {}", msg)
            }
            MtaStsError::PolicyParseFailed(msg) => {
                write!(f, "MTA-STS: policy parse error: {}", msg)
            }
            MtaStsError::PolicyIdMismatch { cached, dns } => {
                write!(
                    f,
                    "MTA-STS: policy id mismatch (cached={}, dns={})",
                    cached, dns
                )
            }
            MtaStsError::MxNotMatched { mx } => {
                write!(f, "MTA-STS: MX hostname '{}' not in policy", mx)
            }
            MtaStsError::TlsRequiredNotAdvertised => {
                write!(f, "MTA-STS: REQUIRETLS not advertised by remote MTA")
            }
            MtaStsError::TlsCertInvalid(msg) => {
                write!(f, "MTA-STS: TLS certificate invalid: {}", msg)
            }
        }
    }
}

impl std::error::Error for MtaStsError {}
