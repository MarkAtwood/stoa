//! Pinning policy engine for usenet-ipfs-transit.
//!
//! `PolicyEngine::should_pin` evaluates configured rules against article
//! metadata. Rules are AND'd: the article must pass ALL applicable checks.

/// Article metadata for policy evaluation (decoupled from IPLD schema).
#[derive(Debug, Clone)]
pub struct ArticleInfo {
    /// Group name (e.g. "comp.lang.rust").
    pub group: String,
    /// Article post date as Unix timestamp milliseconds.
    pub date_ms: u64,
    /// Article total byte count.
    pub byte_count: u64,
}

/// Configuration for the pinning policy engine.
#[derive(Debug, Clone)]
pub struct PinPolicy {
    /// If true, pin all articles regardless of other rules.
    pub pin_all_groups: bool,
    /// If non-empty and `pin_all_groups` is false, only pin articles
    /// whose group is in this list.
    pub pin_groups: Vec<String>,
    /// If Some, reject articles older than this many days.
    /// `None` means no age limit.
    pub max_age_days: Option<u32>,
    /// If Some, reject articles larger than this many bytes.
    /// `None` means no size limit.
    pub max_size_bytes: Option<u64>,
}

impl Default for PinPolicy {
    fn default() -> Self {
        Self {
            pin_all_groups: true,
            pin_groups: vec![],
            max_age_days: None,
            max_size_bytes: None,
        }
    }
}

/// Policy engine that evaluates `PinPolicy` against article metadata.
pub struct PolicyEngine {
    policy: PinPolicy,
    /// Current Unix timestamp in milliseconds (injected for testability).
    now_ms: u64,
}

impl PolicyEngine {
    pub fn new(policy: PinPolicy, now_ms: u64) -> Self {
        Self { policy, now_ms }
    }

    /// Decide whether to pin the given article.
    ///
    /// Rules applied in order (all must pass):
    /// 1. Group filter: if `pin_all_groups=false` and `pin_groups` is non-empty,
    ///    the article's group must be in the list.
    /// 2. Age filter: if `max_age_days` is set, reject articles older than that.
    ///    Age is computed from `article.date_ms` (Unix ms) against `now_ms`.
    /// 3. Size filter: if `max_size_bytes` is set, reject larger articles.
    ///    Size is computed from `article.byte_count`.
    pub fn should_pin(&self, article: &ArticleInfo) -> bool {
        // Rule 1: group filter.
        // When pin_all_groups is false, the article's group must appear in
        // pin_groups. An empty pin_groups list matches nothing.
        if !self.policy.pin_all_groups
            && !self.policy.pin_groups.iter().any(|g| g == &article.group)
        {
            return false;
        }

        // Rule 2: age filter.
        if let Some(max_days) = self.policy.max_age_days {
            let max_age_ms = (max_days as u64) * 24 * 60 * 60 * 1000;
            if article.date_ms + max_age_ms < self.now_ms {
                return false;
            }
        }

        // Rule 3: size filter.
        if let Some(max_bytes) = self.policy.max_size_bytes {
            if article.byte_count > max_bytes {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 1_700_000_000_000u64; // arbitrary "now"

    fn make_info(group: &str, age_days: u64, byte_count: u64) -> ArticleInfo {
        let age_ms = age_days * 24 * 60 * 60 * 1000;
        ArticleInfo {
            group: group.to_string(),
            date_ms: NOW_MS.saturating_sub(age_ms),
            byte_count,
        }
    }

    fn engine(policy: PinPolicy) -> PolicyEngine {
        PolicyEngine::new(policy, NOW_MS)
    }

    #[test]
    fn pin_all_groups_pins_everything() {
        let eng = engine(PinPolicy { pin_all_groups: true, ..Default::default() });
        let art = make_info("comp.lang.rust", 0, 1024);
        assert!(eng.should_pin(&art));
    }

    #[test]
    fn pin_specific_group_allows_matching() {
        let policy = PinPolicy {
            pin_all_groups: false,
            pin_groups: vec!["comp.lang.rust".to_string()],
            ..Default::default()
        };
        let eng = engine(policy);
        assert!(eng.should_pin(&make_info("comp.lang.rust", 0, 1024)));
        assert!(!eng.should_pin(&make_info("sci.math", 0, 1024)));
    }

    #[test]
    fn max_age_days_rejects_old_articles() {
        let policy = PinPolicy {
            pin_all_groups: true,
            max_age_days: Some(30),
            ..Default::default()
        };
        let eng = engine(policy);
        assert!(eng.should_pin(&make_info("comp.lang.rust", 29, 1024)));
        assert!(!eng.should_pin(&make_info("comp.lang.rust", 31, 1024)));
    }

    #[test]
    fn max_size_bytes_rejects_large_articles() {
        let policy = PinPolicy {
            pin_all_groups: true,
            max_size_bytes: Some(1_048_576), // 1 MiB
            ..Default::default()
        };
        let eng = engine(policy);
        assert!(eng.should_pin(&make_info("comp.lang.rust", 0, 512)));
        assert!(!eng.should_pin(&make_info("comp.lang.rust", 0, 2_097_152)));
    }

    #[test]
    fn rules_are_anded_group_and_age() {
        let policy = PinPolicy {
            pin_all_groups: false,
            pin_groups: vec!["comp.lang.rust".to_string()],
            max_age_days: Some(30),
            max_size_bytes: None,
        };
        let eng = engine(policy);
        // Right group, right age: pin.
        assert!(eng.should_pin(&make_info("comp.lang.rust", 10, 1024)));
        // Right group, too old: don't pin.
        assert!(!eng.should_pin(&make_info("comp.lang.rust", 60, 1024)));
        // Wrong group, right age: don't pin.
        assert!(!eng.should_pin(&make_info("sci.math", 10, 1024)));
    }

    #[test]
    fn rules_are_anded_all_three() {
        let policy = PinPolicy {
            pin_all_groups: false,
            pin_groups: vec!["comp.lang.rust".to_string()],
            max_age_days: Some(30),
            max_size_bytes: Some(1_048_576),
        };
        let eng = engine(policy);
        // All rules satisfied.
        assert!(eng.should_pin(&make_info("comp.lang.rust", 10, 512)));
        // Fails size only.
        assert!(!eng.should_pin(&make_info("comp.lang.rust", 10, 2_097_152)));
        // Fails age only.
        assert!(!eng.should_pin(&make_info("comp.lang.rust", 60, 512)));
        // Fails group only.
        assert!(!eng.should_pin(&make_info("sci.math", 10, 512)));
    }

    #[test]
    fn empty_pin_groups_with_pin_all_false_pins_nothing() {
        // If pin_all_groups=false but pin_groups is empty, nothing matches.
        let policy = PinPolicy {
            pin_all_groups: false,
            pin_groups: vec![],
            ..Default::default()
        };
        let eng = engine(policy);
        assert!(!eng.should_pin(&make_info("comp.lang.rust", 0, 1024)));
    }
}
