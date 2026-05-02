use std::fmt;

/// Typed errors for MTA-STS policy lookup, fetch, parse, and enforcement.
#[derive(Debug)]
#[non_exhaustive]
pub enum MtaStsError {
    /// DNS/network failure while resolving or querying `_mta-sts.<domain>`.
    DnsLookupFailed { message: String },
    /// Multiple STSv1 TXT records found; RFC 8461 §3.1 requires exactly one.
    DnsTxtMultipleRecords,
    /// TXT record is missing the required `id=` field.
    DnsTxtMissingId,
    /// TXT record `id=` value exceeds 32 characters.
    DnsTxtIdTooLong,
    /// TXT record `id=` value contains non-alphanumeric characters.
    DnsTxtIdInvalid,
    /// HTTPS fetch of policy file failed (network, cert, timeout, or other I/O error).
    PolicyFetchFailed { message: String },
    /// Policy fetch returned a redirect response; RFC 8461 §3.3 forbids following redirects.
    PolicyFetchRedirectForbidden,
    /// Policy fetch returned a non-2xx HTTP status code.
    PolicyFetchHttpError { status: u16 },
    /// Policy fetch response body exceeded the configured size limit.
    PolicyFetchTooLarge,
    /// Policy file body failed to parse (missing field, bad value, oversized body).
    PolicyParseFailed { message: String },
    /// Cached policy_id does not match the current DNS TXT record id.
    PolicyIdMismatch { cached: String, dns: String },
    /// Connecting MX hostname does not match any pattern in the policy.
    MxNotMatched { mx: String },
}

impl fmt::Display for MtaStsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MtaStsError::DnsLookupFailed { message } => {
                write!(f, "MTA-STS: DNS lookup failed: {}", message)
            }
            MtaStsError::DnsTxtMultipleRecords => {
                write!(f, "MTA-STS: multiple STSv1 TXT records found")
            }
            MtaStsError::DnsTxtMissingId => {
                write!(f, "MTA-STS: TXT record missing id= field")
            }
            MtaStsError::DnsTxtIdTooLong => {
                write!(f, "MTA-STS: TXT record id= exceeds 32 characters")
            }
            MtaStsError::DnsTxtIdInvalid => {
                write!(
                    f,
                    "MTA-STS: TXT record id= contains non-alphanumeric characters"
                )
            }
            MtaStsError::PolicyFetchFailed { message } => {
                write!(f, "MTA-STS: policy fetch failed: {}", message)
            }
            MtaStsError::PolicyFetchRedirectForbidden => {
                write!(
                    f,
                    "MTA-STS: policy fetch redirect not allowed (RFC 8461 §3.3)"
                )
            }
            MtaStsError::PolicyFetchHttpError { status } => {
                write!(f, "MTA-STS: policy fetch HTTP {}", status)
            }
            MtaStsError::PolicyFetchTooLarge => {
                write!(f, "MTA-STS: policy fetch response body too large")
            }
            MtaStsError::PolicyParseFailed { message } => {
                write!(f, "MTA-STS: policy parse error: {}", message)
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
        }
    }
}

impl std::error::Error for MtaStsError {}
