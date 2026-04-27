use std::fmt;

/// Returns true if `name` matches `pattern` using wildmat rules:
/// `*` matches any sequence of characters, `?` matches any single character.
/// Comparison is case-insensitive.
pub fn matches_wildmat(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains(['*', '?']) {
        return name.eq_ignore_ascii_case(pattern);
    }
    let name = name.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    wildmat_match(name.as_bytes(), pattern.as_bytes())
}

/// Iterative DP wildmat matching — O(text.len() * pattern.len()) time,
/// O(pattern.len()) space (two-row rolling buffer).
///
/// `prev[j]` / `curr[j]` is true when `text[..i-1]` / `text[..i]` matches
/// `pattern[..j]`.  This avoids the exponential blowup of recursive
/// backtracking on patterns like `*a*a*a*a*a` against long strings.
///
/// # DECISION (rbe3.4): iterative DP algorithm avoids ReDoS
///
/// Recursive backtracking wildmat/glob matching has worst-case exponential
/// time: a pattern like `*a*a*a*a*a` against a long non-matching string forces
/// the matcher to exhaust all O(2^n) backtrack paths.  This is a ReDoS-class
/// vulnerability — patterns come from operator config but names come from
/// untrusted peers, so adversarial names could trigger worst-case behaviour.
/// The iterative DP approach fills a (text.len()+1) × (pattern.len()+1) boolean
/// table in O(n*m) time regardless of pattern adversarialness.
/// Do NOT replace this with a recursive backtracking implementation.
fn wildmat_match(text: &[u8], pattern: &[u8]) -> bool {
    let m = text.len();
    let n = pattern.len();

    let mut prev = vec![false; n + 1];
    prev[0] = true;
    for j in 1..=n {
        if pattern[j - 1] == b'*' {
            prev[j] = prev[j - 1];
        } else {
            break;
        }
    }

    let mut curr = vec![false; n + 1];
    for i in 1..=m {
        curr[0] = false;
        for j in 1..=n {
            curr[j] = match pattern[j - 1] {
                b'*' => curr[j - 1] || prev[j],
                b'?' => prev[j - 1],
                pc => prev[j - 1] && text[i - 1] == pc,
            };
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

/// Like `matches_wildmat` but assumes `pattern_bytes` is already ASCII-lowercased.
/// Only lowercases `name`. Saves one allocation in the hot path.
fn matches_wildmat_prefolded(name: &str, pattern_bytes: &[u8]) -> bool {
    if !pattern_bytes.contains(&b'*') && !pattern_bytes.contains(&b'?') {
        return name.len() == pattern_bytes.len()
            && name
                .as_bytes()
                .iter()
                .zip(pattern_bytes)
                .all(|(a, b)| a.to_ascii_lowercase() == *b);
    }
    let name = name.to_ascii_lowercase();
    wildmat_match(name.as_bytes(), pattern_bytes)
}

/// Error returned when a wildmat pattern or filter is invalid.
#[derive(Debug, Clone, PartialEq)]
pub enum WildmatError {
    /// Every pattern in the filter is a negation; at least one positive pattern is required.
    AllNegation,
    /// A pattern (or the bare pattern after stripping `!`) is empty.
    EmptyPattern,
}

impl fmt::Display for WildmatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WildmatError::AllNegation => write!(
                f,
                "wildmat filter must contain at least one non-negated pattern"
            ),
            WildmatError::EmptyPattern => write!(f, "wildmat pattern must not be empty"),
        }
    }
}

impl std::error::Error for WildmatError {}

/// A single wildmat pattern, optionally negated (prefixed with `!`).
#[derive(Debug, Clone, PartialEq)]
pub struct WildmatPattern {
    /// True when the original pattern started with `!`.
    pub is_negated: bool,
    /// The pattern string with the leading `!` removed (if any).
    pub bare_pattern: String,
}

impl WildmatPattern {
    /// Parse a single pattern entry.
    ///
    /// Leading `!` marks the pattern as a negation.  An empty input or an
    /// empty bare pattern (e.g. the string `"!"`) returns `Err(EmptyPattern)`.
    pub fn parse(s: &str) -> Result<Self, WildmatError> {
        if s.is_empty() {
            return Err(WildmatError::EmptyPattern);
        }
        let (is_negated, bare_pattern) = if let Some(stripped) = s.strip_prefix('!') {
            (true, stripped.to_ascii_lowercase())
        } else {
            (false, s.to_ascii_lowercase())
        };
        if bare_pattern.is_empty() {
            return Err(WildmatError::EmptyPattern);
        }
        Ok(WildmatPattern {
            is_negated,
            bare_pattern,
        })
    }
}

/// An ordered list of wildmat patterns used to decide whether a newsgroup name
/// is accepted or rejected.
///
/// Patterns are evaluated in order; the first match wins.  If no pattern
/// matches the name, the name is rejected (default deny).  The filter must
/// contain at least one non-negated pattern; a filter where every entry is
/// negated would accept nothing and is rejected at construction time.
pub struct GroupFilter {
    patterns: Vec<WildmatPattern>,
}

impl GroupFilter {
    /// Build a `GroupFilter` from a slice of raw pattern strings.
    ///
    /// Returns `Err(AllNegation)` if the slice is empty or every parsed
    /// pattern is negated.
    ///
    /// # DECISION (rbe3.10): all-negation filter rejected at construction
    ///
    /// A filter where every entry is a negation (`!comp.*`, `!alt.*`) can
    /// never accept any group name — it would silently black-hole all articles
    /// without error.  Rejecting it at construction time (config load) produces
    /// an immediate startup error rather than a silent operational failure that
    /// is only discovered when traffic stops flowing.  The check is O(n) over
    /// the pattern count.  Do NOT weaken this to a warning at construction time;
    /// silent black-holes are worse than startup failures.
    pub fn new(raw_patterns: &[impl AsRef<str>]) -> Result<Self, WildmatError> {
        let patterns: Result<Vec<WildmatPattern>, WildmatError> = raw_patterns
            .iter()
            .map(|s| WildmatPattern::parse(s.as_ref()))
            .collect();
        let patterns = patterns?;
        if patterns.is_empty() || patterns.iter().all(|p| p.is_negated) {
            return Err(WildmatError::AllNegation);
        }
        Ok(GroupFilter { patterns })
    }

    /// Returns `true` if `name` is accepted by this filter.
    ///
    /// An empty `name` is always rejected (defensive: empty group names are
    /// invalid in NNTP).  Patterns are tested in order; the first match
    /// determines the outcome.  If no pattern matches, the name is rejected.
    ///
    /// # DECISION (rbe3.38): empty name rejected as defensive guard
    ///
    /// An empty string cannot be a valid NNTP group name (RFC 3977 §4).
    /// Explicitly rejecting it here prevents a wildmat `*` pattern from
    /// accidentally accepting empty strings that could arise from splitting a
    /// comma-separated newsgroup list on consecutive commas.  The check is
    /// O(1) and has no downside.  Do NOT remove the empty-check guard.
    ///
    /// # DECISION (rbe3.37): first-match-wins implements ordered policy
    ///
    /// First-match-wins is the standard wildmat semantics (RFC 3977 §4).  It
    /// allows operators to write policies like `["comp.*", "!comp.binaries"]`
    /// where `comp.*` pins everything under comp but the `!` pattern then
    /// exempts binaries — the exception must come second.  Reversing to
    /// last-match-wins or any-match-wins would break this composability.
    /// Do NOT change the evaluation order to last-match or union semantics.
    pub fn accepts(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        for pattern in &self.patterns {
            if matches_wildmat_prefolded(name, pattern.bare_pattern.as_bytes()) {
                return !pattern.is_negated;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildmat_star_matches_hierarchy() {
        assert!(matches_wildmat("comp.lang.rust", "comp.*"));
        assert!(!matches_wildmat("alt.test", "comp.*"));
    }

    #[test]
    fn wildmat_question_mark() {
        assert!(matches_wildmat("alt.x", "alt.?"));
        assert!(!matches_wildmat("alt.xy", "alt.?"));
    }

    #[test]
    fn wildmat_case_insensitive() {
        assert!(matches_wildmat("COMP.LANG.RUST", "comp.*"));
        assert!(matches_wildmat("comp.lang.rust", "COMP.*"));
    }

    #[test]
    fn wildmat_exact_match() {
        assert!(matches_wildmat("alt.test", "alt.test"));
        assert!(!matches_wildmat("alt.test2", "alt.test"));
    }

    #[test]
    fn wildmat_star_only() {
        assert!(matches_wildmat("anything.goes", "*"));
        assert!(matches_wildmat("", "*"));
    }

    /// Adversarial pattern that causes exponential backtracking in a recursive
    /// implementation but runs in O(n*m) with the iterative DP approach.
    ///
    /// Pattern `*a*a*a*a*a*a*a*a*a` (no trailing star) cannot match a string
    /// of 'a's followed by 'b' because the pattern requires the last character
    /// to be 'a'.  A recursive matcher must exhaust all 2^18 backtracking paths
    /// before determining this; the DP table fills in O(19 * 20) = O(380) steps.
    ///
    /// # DECISION (rbe3.5): adversarial backtracking test with wall-clock bound
    ///
    /// Most wildmat test suites only check correctness.  This test also asserts
    /// that the worst-case pattern completes in <100 ms, catching any regression
    /// to a recursive implementation.  The 100 ms bound is generous (the DP
    /// matcher runs in microseconds) but tight enough to catch exponential blowup.
    /// Do NOT remove this test; it is the automated enforcement of the O(n*m)
    /// complexity guarantee from DECISION (rbe3.4).
    #[test]
    fn wildmat_no_catastrophic_backtracking() {
        let pattern = "*a*a*a*a*a*a*a*a*a"; // ends with literal 'a', not '*'
        let text = "aaaaaaaaaaaaaaaaaab"; // 18 'a's then 'b' — never matches

        let start = std::time::Instant::now();
        let result = matches_wildmat(text, pattern);
        let elapsed = start.elapsed();

        assert!(!result, "pattern must not match text ending in 'b'");
        assert!(
            elapsed.as_millis() < 100,
            "wildmat must complete in <100 ms; took {}ms",
            elapsed.as_millis()
        );
    }

    // --- GroupFilter tests (RFC 3977 §4.1 oracle) ---

    #[test]
    fn groupfilter_star_crosses_dots() {
        let f = GroupFilter::new(&["comp.*"]).unwrap();
        assert!(f.accepts("comp.lang.rust"));
    }

    #[test]
    fn groupfilter_star_no_match() {
        let f = GroupFilter::new(&["comp.*"]).unwrap();
        assert!(!f.accepts("alt.test"));
    }

    #[test]
    fn groupfilter_negation_excludes_first_match() {
        let f = GroupFilter::new(&["comp.*", "sci.*", "!alt.binaries.*", "alt.test"]).unwrap();
        assert!(!f.accepts("alt.binaries.pictures"));
    }

    #[test]
    fn groupfilter_positive_after_negation_miss() {
        let f = GroupFilter::new(&["comp.*", "sci.*", "!alt.binaries.*", "alt.test"]).unwrap();
        assert!(f.accepts("alt.test"));
    }

    #[test]
    fn groupfilter_first_positive_match() {
        let f = GroupFilter::new(&["comp.*", "sci.*", "!alt.binaries.*", "alt.test"]).unwrap();
        assert!(f.accepts("comp.lang.rust"));
    }

    #[test]
    fn groupfilter_default_deny() {
        let f = GroupFilter::new(&["comp.*", "sci.*", "!alt.binaries.*", "alt.test"]).unwrap();
        assert!(!f.accepts("rec.humor"));
    }

    #[test]
    fn groupfilter_exact_match() {
        let f = GroupFilter::new(&["alt.test"]).unwrap();
        assert!(f.accepts("alt.test"));
        assert!(!f.accepts("alt.test2"));
    }

    #[test]
    fn groupfilter_all_negation_rejected() {
        assert!(matches!(
            GroupFilter::new(&["!comp.*"]),
            Err(WildmatError::AllNegation)
        ));
    }

    #[test]
    fn groupfilter_empty_list_rejected() {
        assert!(matches!(
            GroupFilter::new(&[] as &[&str]),
            Err(WildmatError::AllNegation)
        ));
    }

    #[test]
    fn groupfilter_case_insensitive_pattern_upper() {
        let f = GroupFilter::new(&["COMP.*"]).unwrap();
        assert!(f.accepts("comp.lang.rust"));
    }

    #[test]
    fn groupfilter_case_insensitive_name_upper() {
        let f = GroupFilter::new(&["comp.*"]).unwrap();
        assert!(f.accepts("COMP.LANG.RUST"));
    }

    #[test]
    fn groupfilter_empty_name_always_false() {
        let f = GroupFilter::new(&["*"]).unwrap();
        assert!(!f.accepts(""));
    }

    #[test]
    fn parse_negated_pattern() {
        let p = WildmatPattern::parse("!comp.*").unwrap();
        assert!(p.is_negated);
        assert_eq!(p.bare_pattern, "comp.*");
    }

    #[test]
    fn parse_positive_pattern() {
        let p = WildmatPattern::parse("comp.*").unwrap();
        assert!(!p.is_negated);
        assert_eq!(p.bare_pattern, "comp.*");
    }

    #[test]
    fn parse_negation_only_empty() {
        assert!(matches!(
            WildmatPattern::parse("!"),
            Err(WildmatError::EmptyPattern)
        ));
    }

    #[test]
    fn parse_empty_string() {
        assert!(matches!(
            WildmatPattern::parse(""),
            Err(WildmatError::EmptyPattern)
        ));
    }

    /// Issue .9: WildmatPattern::parse must store bare_pattern pre-lowercased.
    /// Oracle: RFC 3977 §4.1 case-insensitive wildmat.
    #[test]
    fn parse_positive_pattern_stored_lowercase() {
        let p = WildmatPattern::parse("COMP.*").unwrap();
        assert!(!p.is_negated);
        assert_eq!(
            p.bare_pattern, "comp.*",
            "bare_pattern must be stored lowercase; got {:?}",
            p.bare_pattern
        );
    }

    /// Issue .9: negated patterns must also have bare_pattern pre-lowercased.
    #[test]
    fn parse_negated_pattern_stored_lowercase() {
        let p = WildmatPattern::parse("!COMP.*").unwrap();
        assert!(p.is_negated);
        assert_eq!(
            p.bare_pattern, "comp.*",
            "bare_pattern must be stored lowercase; got {:?}",
            p.bare_pattern
        );
    }

    /// Issue .7: exercises all three DP branches (literal, `?`, `*`) in one pattern.
    /// Pattern `a?.r*` against `ab.rust` (true) and `ab.java` (false).
    /// Hand-verified: a→a (literal), ?→b, .→. (literal), r→r (literal), *→ust.
    /// Oracle: RFC 3977 §4.1 semantics.
    #[test]
    fn wildmat_mixed_branches_single_pattern() {
        assert!(
            matches_wildmat("ab.rust", "a?.r*"),
            "a?.r* should match ab.rust"
        );
        assert!(
            !matches_wildmat("ab.java", "a?.r*"),
            "a?.r* should not match ab.java"
        );
    }
}
