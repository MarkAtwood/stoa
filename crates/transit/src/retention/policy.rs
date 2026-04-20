use serde::Deserialize;

/// Metadata about an article used to evaluate pinning policy rules.
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
    /// Glob pattern for group names. `"all"` matches every group.
    /// `"comp.*"` matches any group whose name begins with `"comp."`.
    /// `"comp.**"` is an explicit any-depth variant with identical behavior.
    /// Exact names such as `"comp.lang.rust"` match only that group.
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
pub struct PinPolicy {
    rules: Vec<PinRule>,
}

impl PinPolicy {
    pub fn new(rules: Vec<PinRule>) -> Self {
        Self { rules }
    }

    /// Returns `true` if the article described by `meta` should be pinned.
    ///
    /// Evaluates rules in order. The first rule whose group pattern and all
    /// optional constraints match determines the outcome: `"pin"` → `true`,
    /// `"skip"` → `false`. If no rule matches, returns `false`.
    pub fn should_pin(&self, meta: &ArticleMeta) -> bool {
        for rule in &self.rules {
            if Self::matches_rule(rule, meta) {
                return rule.action == "pin";
            }
        }
        false
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
}
