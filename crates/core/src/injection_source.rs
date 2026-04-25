use serde::{Deserialize, Serialize};

/// Identifies how an article entered the system.
///
/// Used to decide whether an article is added to the group log (and thus
/// replicated to transit peers via IHAVE/TAKETHIS) or stored locally only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionSource {
    /// Article arrived via a direct NNTP POST command.
    NntpPost,
    /// Article arrived via SMTP with an explicit `Newsgroups:` header.
    SmtpNewsgroups,
    /// Article arrived via SMTP and was routed by a Sieve `fileinto "newsgroup:..."` action.
    SmtpSieve,
    /// Article arrived via SMTP and was routed by List-ID fallback (no Newsgroups header, no explicit Sieve rule).
    SmtpListId,
}

impl InjectionSource {
    /// Returns true if the article should be written to the group log and replicated to peers.
    ///
    /// Uses positive matching: only explicitly listed variants return `true`.
    /// Any future variant is non-peerable by default until explicitly added here.
    pub fn is_peerable(self) -> bool {
        matches!(self, Self::NntpPost | Self::SmtpNewsgroups | Self::SmtpSieve)
    }
}

/// Default injection source for backward-compatible deserialization of old queue files.
pub fn default_injection_source() -> InjectionSource {
    InjectionSource::SmtpSieve
}
