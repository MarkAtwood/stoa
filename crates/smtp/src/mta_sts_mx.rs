/// Check if an MX hostname matches a single MTA-STS pattern.
///
/// Rules per RFC 8461 §4.1 (referencing RFC 6125 §6.4):
/// - Case-insensitive exact match: `mx.example.com` matches `mx.example.com`
/// - Wildcard `*.example.com` matches exactly one sub-label: `foo.example.com`
/// - `*.example.com` does NOT match `foo.bar.example.com` (two labels deep)
/// - `*.example.com` does NOT match `example.com` (base domain itself)
/// - No other wildcard forms are valid
pub fn mx_matches_pattern(mx_hostname: &str, pattern: &str) -> bool {
    let mx = mx_hostname.to_ascii_lowercase();
    let pat = pattern.to_ascii_lowercase();

    if let Some(base) = pat.strip_prefix("*.") {
        // Wildcard branch: mx must end with ".<base>" and the prefix must be a single label.
        let suffix = format!(".{}", base);
        if let Some(label) = mx.strip_suffix(suffix.as_str()) {
            // label must be non-empty and contain no dots (exactly one label)
            !label.is_empty() && !label.contains('.')
        } else {
            false
        }
    } else {
        mx == pat
    }
}

/// Check if an MX hostname matches any pattern in the policy's mx list.
pub fn check_mx_against_policy<S: AsRef<str>>(mx: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|p| mx_matches_pattern(mx, p.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- exact match ---

    #[test]
    fn exact_match_identical() {
        assert!(mx_matches_pattern("mx.example.com", "mx.example.com"));
    }

    #[test]
    fn exact_match_case_insensitive() {
        assert!(mx_matches_pattern("MX.Example.COM", "mx.example.com"));
        assert!(mx_matches_pattern("mx.example.com", "MX.EXAMPLE.COM"));
    }

    #[test]
    fn exact_match_different() {
        assert!(!mx_matches_pattern("mail.example.com", "mx.example.com"));
    }

    // --- wildcard: one label deep ---

    #[test]
    fn wildcard_one_label_matches() {
        assert!(mx_matches_pattern("foo.example.com", "*.example.com"));
        assert!(mx_matches_pattern("mx1.example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_case_insensitive() {
        assert!(mx_matches_pattern("FOO.EXAMPLE.COM", "*.example.com"));
        assert!(mx_matches_pattern("foo.example.com", "*.EXAMPLE.COM"));
    }

    #[test]
    fn wildcard_two_labels_deep_no_match() {
        assert!(!mx_matches_pattern("foo.bar.example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_base_domain_itself_no_match() {
        assert!(!mx_matches_pattern("example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_empty_label_no_match() {
        // ".example.com" — the label before the suffix is empty
        assert!(!mx_matches_pattern(".example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_unrelated_domain_no_match() {
        assert!(!mx_matches_pattern("foo.other.com", "*.example.com"));
    }

    // --- check_mx_against_policy ---

    #[test]
    fn policy_any_pattern_matches() {
        let patterns = vec!["mx1.example.com".to_string(), "*.example.net".to_string()];
        assert!(check_mx_against_policy("mx1.example.com", &patterns));
        assert!(check_mx_against_policy("relay.example.net", &patterns));
    }

    #[test]
    fn policy_no_pattern_matches() {
        let patterns = vec!["mx1.example.com".to_string(), "*.example.net".to_string()];
        assert!(!check_mx_against_policy("evil.attacker.com", &patterns));
    }

    #[test]
    fn policy_empty_list_never_matches() {
        assert!(!check_mx_against_policy("mx.example.com", &[] as &[&str]));
    }
}
