/// RFC 3977 NNTP session states.
///
/// # DECISION (rbe3.39): three-state enum prevents unauthenticated command dispatch
///
/// The `Authenticating` variant makes it a compile-time impossibility to
/// omit the authentication check at the dispatch layer: any match arm that
/// handles `Active | GroupSelected` without matching `Authenticating` is a
/// non-exhaustive match and will not compile.  Do NOT collapse `Authenticating`
/// and `Active` into a single variant (e.g. a boolean `is_authenticated` field)
/// — that removes the compiler guarantee and requires a runtime check that can
/// be silently omitted.
///
/// # Valid command sets per state
///
/// `Authenticating`:
///   - CAPABILITIES, QUIT, AUTHINFO USER, AUTHINFO PASS, STARTTLS
///   - All other commands → 480 Authentication required
///
/// `Active` (authenticated, no group selected):
///   - CAPABILITIES, MODE READER, QUIT, LIST (all variants), NEWGROUPS, NEWNEWS
///   - ARTICLE/HEAD/BODY/STAT with a message-ID argument (no group needed)
///   - POST, IHAVE, AUTHINFO, STARTTLS
///   - GROUP → transitions to GroupSelected
///   - NEXT, LAST without a selected group → 412 No newsgroup has been selected
///
/// `GroupSelected` (authenticated, group selected):
///   - All commands valid in Active, plus NEXT/LAST/OVER with ranges
///   - GROUP transitions to a different group (stays in GroupSelected)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Waiting for authentication. auth_required=true in config.
    Authenticating,
    /// Authenticated (or auth not required), no group selected.
    Active,
    /// Authenticated, GROUP has been issued; article pointer is valid.
    GroupSelected,
}

impl SessionState {
    /// Returns true if commands requiring a selected group are allowed.
    pub fn group_selected(&self) -> bool {
        matches!(self, Self::GroupSelected)
    }

    /// Returns true if the session is authenticated (past auth phase).
    pub fn is_authenticated(&self) -> bool {
        !matches!(self, Self::Authenticating)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_selected_initial_false() {
        assert!(!SessionState::Active.group_selected());
        assert!(!SessionState::Authenticating.group_selected());
        assert!(SessionState::GroupSelected.group_selected());
    }

    #[test]
    fn test_is_authenticated() {
        assert!(!SessionState::Authenticating.is_authenticated());
        assert!(SessionState::Active.is_authenticated());
        assert!(SessionState::GroupSelected.is_authenticated());
    }
}
