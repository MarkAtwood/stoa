use serde::Deserialize;

/// Errors returned by [`PinPolicy::validate`].
#[derive(Debug)]
pub enum PolicyValidationError {
    EmptyPolicy,
    InvalidGroupPattern(String),
    UselessRule { rule_index: usize, reason: String },
}

impl std::fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyValidationError::EmptyPolicy => {
                write!(
                    f,
                    "retention policy has no rules; at least one rule is required"
                )
            }
            PolicyValidationError::InvalidGroupPattern(p) => {
                write!(f, "invalid group pattern: '{p}'")
            }
            PolicyValidationError::UselessRule { rule_index, reason } => {
                write!(f, "rule at index {rule_index} is useless: {reason}")
            }
        }
    }
}

impl std::error::Error for PolicyValidationError {}

/// Metadata about an article used to evaluate pinning policy rules.
///
/// `group` holds the raw `Newsgroups:` header value, which may be a
/// comma-separated list for cross-posted articles (e.g.
/// `"comp.lang.rust, alt.test"`).  [`PinPolicy::should_pin`] splits on
/// commas and pins the article if **any** listed group matches a pin rule.
pub struct ArticleMeta {
    pub group: String,
    pub size_bytes: usize,
    /// Days elapsed since the article's Date header.
    pub age_days: u64,
}

/// A single pinning policy rule, deserializable from TOML.
///
/// Rules are evaluated in order by [`PinPolicy::should_pin`]. The first rule
/// whose conditions all match determines the outcome. Unknown `action` values
/// are treated as no-match (rule is skipped) rather than panicking.
#[derive(Debug, Deserialize, Clone)]
pub struct PinRule {
    /// Group pattern for this rule, using the **pinning glob syntax** (NOT RFC 3977 wildmat).
    ///
    /// Supported patterns (evaluated by `matches_group_glob`):
    /// - `"all"` — matches every group name.
    /// - `"comp.*"` or `"comp.**"` — matches any group whose name begins with `"comp."`.
    /// - `"comp.lang.rust"` — exact, case-sensitive match for that group only.
    ///
    /// RFC 3977 wildmat operators (`?`, `!`, character classes) are **not supported** here
    /// and will silently fail to match.  Use them in `groups.names` (which calls
    /// `GroupFilter::new` with full wildmat support), not in pinning rules.
    pub groups: String,
    /// If `Some`, only articles no older than this many days match this rule.
    pub max_age_days: Option<u64>,
    /// If `Some`, only articles no larger than this many bytes match this rule.
    pub max_article_bytes: Option<usize>,
    /// `"pin"` to pin matching articles; `"skip"` to leave them unpinned.
    pub action: String,
}

/// Ordered list of pinning rules evaluated against each incoming article.
///
/// Rules are checked in declaration order; the first matching rule wins.
/// If no rule matches the article, `should_pin` returns `false` — pinning
/// is explicit opt-in, not opt-out.
#[derive(Clone)]
pub struct PinPolicy {
    rules: Vec<PinRule>,
}

impl PinPolicy {
    pub fn new(rules: Vec<PinRule>) -> Self {
        Self { rules }
    }

    /// Return the number of rules in this policy.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` if the article described by `meta` should be pinned.
    ///
    /// `meta.group` may be a comma-separated list of newsgroup names as it
    /// appears in the `Newsgroups:` header (e.g. `"comp.lang.rust, alt.test"`).
    /// Each group name is trimmed of whitespace and evaluated independently.
    /// The article is pinned if **any** of its groups causes a rule to return
    /// `"pin"` and no earlier group caused a rule to return `"skip"`.
    ///
    /// More precisely: rules are evaluated in declaration order for each
    /// group in turn.  The first `(rule, group)` pair that fully matches
    /// determines the outcome for that group.  If any group resolves to
    /// `"pin"`, the article is pinned; if all groups resolve to `"skip"` or
    /// no-match, the article is not pinned.
    pub fn should_pin(&self, meta: &ArticleMeta) -> bool {
        for group in meta
            .group
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let single = ArticleMeta {
                group: group.to_string(),
                size_bytes: meta.size_bytes,
                age_days: meta.age_days,
            };
            for rule in &self.rules {
                if Self::matches_rule(rule, &single) {
                    if rule.action == "pin" {
                        return true;
                    }
                    break;
                }
            }
        }
        false
    }

    /// Validates the policy rules for correctness.
    ///
    /// Returns an error for:
    /// - An empty policy (no rules).
    /// - Any rule whose `groups` field is not a recognised pattern.
    /// - Any rule that can never match an article (`max_age_days=0` with `groups="all"`).
    ///
    /// Emits a [`tracing::warn!`] (not an error) when the same `groups` pattern
    /// appears on more than one rule.
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        if self.rules.is_empty() {
            return Err(PolicyValidationError::EmptyPolicy);
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if !is_valid_group_pattern(&rule.groups) {
                return Err(PolicyValidationError::InvalidGroupPattern(
                    rule.groups.clone(),
                ));
            }
            if rule.max_age_days == Some(0) && rule.groups == "all" {
                return Err(PolicyValidationError::UselessRule {
                    rule_index: i,
                    reason: "max_age_days=0 matches no articles".to_string(),
                });
            }
        }
        // Warn on duplicate group patterns (not an error).
        let mut seen: Vec<&str> = Vec::new();
        let mut warned: Vec<&str> = Vec::new();
        for rule in &self.rules {
            if seen.contains(&rule.groups.as_str()) && !warned.contains(&rule.groups.as_str()) {
                tracing::warn!(
                    pattern = %rule.groups,
                    "retention policy: group pattern appears in multiple rules; \
                     only the first matching rule takes effect"
                );
                warned.push(&rule.groups);
            }
            seen.push(&rule.groups);
        }
        Ok(())
    }

    fn matches_rule(rule: &PinRule, meta: &ArticleMeta) -> bool {
        if !matches_group_glob(&rule.groups, &meta.group) {
            return false;
        }
        if let Some(max_age) = rule.max_age_days {
            if meta.age_days > max_age {
                return false;
            }
        }
        if let Some(max_bytes) = rule.max_article_bytes {
            if meta.size_bytes > max_bytes {
                return false;
            }
        }
        true
    }
}

/// Returns `true` if `group` matches the glob `pattern`.
///
/// Matching rules (evaluated in order):
/// - `"all"` matches any group name.
/// - A pattern ending in `".**"` or `".*"` matches any group whose name
///   starts with the prefix before the wildcard suffix (e.g. `"comp.*"`
///   matches `"comp.lang.rust"`).
/// - Any other pattern is an exact, case-sensitive comparison.
pub fn matches_group_glob(pattern: &str, group: &str) -> bool {
    if pattern == "all" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".**") {
        let expected_start = format!("{}.", prefix);
        return group.starts_with(&expected_start);
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        let expected_start = format!("{}.", prefix);
        return group.starts_with(&expected_start);
    }
    pattern == group
}

/// Returns `true` if `pattern` is a syntactically valid group pattern for a
/// [`PinRule`].
///
/// Valid forms:
/// - `"all"` — matches every group.
/// - A dotted name followed by `".*"` or `".**"` — glob prefix.
/// - An exact dotted name — matches only that group.
///
/// Each dotted-name component must match `[a-zA-Z][a-zA-Z0-9]*`.
fn is_valid_group_pattern(pattern: &str) -> bool {
    if pattern == "all" {
        return true;
    }
    let base = if let Some(p) = pattern.strip_suffix(".**") {
        p
    } else if let Some(p) = pattern.strip_suffix(".*") {
        p
    } else {
        pattern
    };
    is_valid_dotted_name(base)
}

/// Returns `true` if `s` is a non-empty dot-separated sequence of components
/// where every component matches `[a-zA-Z][a-zA-Z0-9]*`.
fn is_valid_dotted_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    for component in s.split('.') {
        if component.is_empty() {
            return false;
        }
        let mut chars = component.chars();
        let first = chars.next().unwrap();
        if !first.is_ascii_alphabetic() {
            return false;
        }
        if !chars.all(|c| c.is_ascii_alphanumeric()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(group: &str, age_days: u64, size_bytes: usize) -> ArticleMeta {
        ArticleMeta {
            group: group.to_string(),
            age_days,
            size_bytes,
        }
    }

    fn pin_rule(
        groups: &str,
        max_age_days: Option<u64>,
        max_article_bytes: Option<usize>,
        action: &str,
    ) -> PinRule {
        PinRule {
            groups: groups.to_string(),
            max_age_days,
            max_article_bytes,
            action: action.to_string(),
        }
    }

    #[test]
    fn pin_rule_matches_all_groups() {
        let policy = PinPolicy::new(vec![pin_rule("all", None, None, "pin")]);
        assert!(policy.should_pin(&meta("comp.lang.rust", 1, 512)));
        assert!(policy.should_pin(&meta("alt.test", 1, 512)));
    }

    #[test]
    fn skip_rule_matches_specific_group() {
        let policy = PinPolicy::new(vec![pin_rule("comp.lang.rust", None, None, "skip")]);
        assert!(!policy.should_pin(&meta("comp.lang.rust", 1, 512)));
    }

    #[test]
    fn max_age_excludes_old_article() {
        let policy = PinPolicy::new(vec![pin_rule("all", Some(30), None, "pin")]);
        assert!(!policy.should_pin(&meta("comp.lang.rust", 60, 512)));
    }

    #[test]
    fn max_age_includes_new_article() {
        let policy = PinPolicy::new(vec![pin_rule("all", Some(30), None, "pin")]);
        assert!(policy.should_pin(&meta("comp.lang.rust", 5, 512)));
    }

    #[test]
    fn max_bytes_excludes_large_article() {
        let policy = PinPolicy::new(vec![pin_rule("all", None, Some(1024), "pin")]);
        assert!(!policy.should_pin(&meta("comp.lang.rust", 1, 2048)));
    }

    #[test]
    fn glob_comp_star_matches_subgroup() {
        assert!(matches_group_glob("comp.*", "comp.lang.rust"));
    }

    #[test]
    fn glob_comp_star_no_match_alt() {
        assert!(!matches_group_glob("comp.*", "alt.test"));
    }

    #[test]
    fn no_matching_rule_returns_false() {
        let policy = PinPolicy::new(vec![]);
        assert!(!policy.should_pin(&meta("comp.lang.rust", 1, 512)));
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = PinPolicy::new(vec![
            pin_rule("all", None, None, "pin"),
            pin_rule("all", None, None, "skip"),
        ]);
        assert!(policy.should_pin(&meta("comp.lang.rust", 1, 512)));
    }

    #[test]
    fn validate_empty_policy_returns_error() {
        let policy = PinPolicy::new(vec![]);
        let err = policy.validate().expect_err("empty policy must be invalid");
        assert!(matches!(err, PolicyValidationError::EmptyPolicy));
    }

    #[test]
    fn validate_single_valid_rule_ok() {
        let policy = PinPolicy::new(vec![pin_rule("comp.lang.rust", Some(30), None, "pin")]);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_invalid_group_pattern_returns_error() {
        for bad in &["123abc", "comp..lang", ".leading-dot", ""] {
            let policy = PinPolicy::new(vec![pin_rule(bad, None, None, "pin")]);
            let err = policy
                .validate()
                .expect_err(&format!("pattern '{}' must be invalid", bad));
            assert!(
                matches!(err, PolicyValidationError::InvalidGroupPattern(_)),
                "expected InvalidGroupPattern for '{}'",
                bad
            );
        }
    }

    #[test]
    fn validate_useless_rule_zero_max_age_all_groups() {
        let policy = PinPolicy::new(vec![pin_rule("all", Some(0), None, "pin")]);
        let err = policy
            .validate()
            .expect_err("max_age_days=0 with groups=all must be invalid");
        assert!(matches!(
            err,
            PolicyValidationError::UselessRule { rule_index: 0, .. }
        ));
    }

    #[test]
    fn crosspost_pinned_if_any_group_is_pinned() {
        // Policy: pin sci.math only.
        // Article cross-posted to comp.lang.rust and sci.math → should be pinned.
        let policy = PinPolicy::new(vec![pin_rule("sci.math", None, None, "pin")]);
        let m = ArticleMeta {
            group: "comp.lang.rust, sci.math".to_string(),
            age_days: 1,
            size_bytes: 512,
        };
        assert!(
            policy.should_pin(&m),
            "cross-post must be pinned when any listed group is in the policy"
        );
    }

    #[test]
    fn crosspost_not_pinned_when_no_group_matches() {
        // Policy: pin sci.math only.
        // Article cross-posted to comp.lang.rust and alt.test → should not be pinned.
        let policy = PinPolicy::new(vec![pin_rule("sci.math", None, None, "pin")]);
        let m = ArticleMeta {
            group: "comp.lang.rust, alt.test".to_string(),
            age_days: 1,
            size_bytes: 512,
        };
        assert!(
            !policy.should_pin(&m),
            "cross-post must not be pinned when no listed group is in the policy"
        );
    }

    #[test]
    fn validate_overlapping_rules_warns_not_errors() {
        let policy = PinPolicy::new(vec![
            pin_rule("comp.*", Some(30), None, "pin"),
            pin_rule("comp.*", None, None, "skip"),
        ]);
        assert!(
            policy.validate().is_ok(),
            "duplicate group pattern should warn, not error"
        );
    }
}
