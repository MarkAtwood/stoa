use mail_parser::{HeaderName, MessageParser};
use serde::Deserialize;

/// A rule mapping a List-ID pattern to a newsgroup name.
#[derive(Debug, Clone, Deserialize)]
pub struct ListRoutingRule {
    pub list_id_pattern: String,
    pub newsgroup: String,
}

/// Parse the List-ID value from an RFC 2919 header value string.
///
/// Input is the full header value, e.g. `<rust-users.lists.rust-lang.org>`.
/// Returns the value between `<` and `>`, or `None` if not present or unparseable.
pub fn parse_list_id(header_value: &str) -> Option<String> {
    let trimmed = header_value.trim();
    let start = trimmed.find('<')?;
    let end = trimmed.rfind('>')?;
    if end <= start {
        return None;
    }
    let inner = trimmed[start + 1..end].trim();
    if inner.is_empty() {
        return None;
    }
    Some(inner.to_string())
}

/// Extract the List-ID header value from raw RFC 5322 message bytes.
///
/// Uses `mail_parser::MessageParser` to parse the message. Returns the
/// parsed List-ID value (the content between `<` and `>`), or `None`.
pub fn extract_list_id(raw_message: &[u8]) -> Option<String> {
    let msg = MessageParser::default().parse(raw_message)?;
    let raw = msg.header_raw(HeaderName::ListId)?;
    parse_list_id(raw)
}

/// Apply configured routing rules to a List-ID value.
///
/// Rules are checked in order; the first match wins.
/// Pattern `"*"` matches anything.
/// Pattern `"*.example.org"` matches any string ending in `".example.org"`.
/// Exact patterns match literally.
pub fn apply_routing_rules(list_id: &str, rules: &[ListRoutingRule]) -> Option<String> {
    for rule in rules {
        if pattern_matches(&rule.list_id_pattern, list_id) {
            return Some(rule.newsgroup.clone());
        }
    }
    None
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return value.ends_with(&format!(".{suffix}")) || value == suffix;
    }
    pattern == value
}

/// Synthesize a `Newsgroups:` header into raw article bytes.
///
/// Prepends `"Newsgroups: <newsgroup>\r\n"` at the front of the message.
pub fn add_newsgroups_header(raw_message: &[u8], newsgroup: &str) -> Vec<u8> {
    let header = format!("Newsgroups: {newsgroup}\r\n");
    let mut result = Vec::with_capacity(header.len() + raw_message.len());
    result.extend_from_slice(header.as_bytes());
    result.extend_from_slice(raw_message);
    result
}

/// Extract the Message-ID header value from raw message bytes.
pub fn extract_message_id(raw_message: &[u8]) -> Option<String> {
    let msg = MessageParser::default().parse(raw_message)?;
    let value = msg.message_id()?;
    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_list_id ---

    #[test]
    fn parse_list_id_standard() {
        assert_eq!(
            parse_list_id("<rust-users.lists.rust-lang.org>"),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    #[test]
    fn parse_list_id_with_display_name() {
        // RFC 2919 allows: "Display Name <list-id>"
        assert_eq!(
            parse_list_id("Rust Users <rust-users.lists.rust-lang.org>"),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    #[test]
    fn parse_list_id_with_whitespace() {
        assert_eq!(
            parse_list_id("  <rust-users.lists.rust-lang.org>  "),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    #[test]
    fn parse_list_id_no_angle_brackets() {
        assert_eq!(parse_list_id("rust-users.lists.rust-lang.org"), None);
    }

    #[test]
    fn parse_list_id_empty_angle_brackets() {
        assert_eq!(parse_list_id("<>"), None);
    }

    #[test]
    fn parse_list_id_reversed_brackets() {
        assert_eq!(parse_list_id(">rust-users.lists.rust-lang.org<"), None);
    }

    // --- extract_list_id ---

    #[test]
    fn extract_list_id_present() {
        let msg = b"From: sender@example.com\r\nList-Id: <rust-users.lists.rust-lang.org>\r\nSubject: test\r\n\r\nbody\r\n";
        assert_eq!(
            extract_list_id(msg),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    #[test]
    fn extract_list_id_absent() {
        let msg = b"From: sender@example.com\r\nSubject: no list here\r\n\r\nbody\r\n";
        assert_eq!(extract_list_id(msg), None);
    }

    #[test]
    fn extract_list_id_with_display_name() {
        let msg = b"From: sender@example.com\r\nList-Id: Rust Users <rust-users.lists.rust-lang.org>\r\nSubject: test\r\n\r\nbody\r\n";
        assert_eq!(
            extract_list_id(msg),
            Some("rust-users.lists.rust-lang.org".to_string())
        );
    }

    // --- apply_routing_rules ---

    fn rule(pattern: &str, newsgroup: &str) -> ListRoutingRule {
        ListRoutingRule {
            list_id_pattern: pattern.to_string(),
            newsgroup: newsgroup.to_string(),
        }
    }

    #[test]
    fn apply_routing_exact_match() {
        let rules = vec![rule(
            "rust-users.lists.rust-lang.org",
            "comp.lang.rust.users",
        )];
        assert_eq!(
            apply_routing_rules("rust-users.lists.rust-lang.org", &rules),
            Some("comp.lang.rust.users".to_string())
        );
    }

    #[test]
    fn apply_routing_exact_no_match() {
        let rules = vec![rule(
            "rust-users.lists.rust-lang.org",
            "comp.lang.rust.users",
        )];
        assert_eq!(
            apply_routing_rules("other.lists.rust-lang.org", &rules),
            None
        );
    }

    #[test]
    fn apply_routing_wildcard_star() {
        let rules = vec![rule("*", "misc.lists.catchall")];
        assert_eq!(
            apply_routing_rules("anything.at.all", &rules),
            Some("misc.lists.catchall".to_string())
        );
    }

    #[test]
    fn apply_routing_prefix_wildcard_match() {
        let rules = vec![rule("*.lists.rust-lang.org", "misc.lists.rust-lang")];
        assert_eq!(
            apply_routing_rules("rust-users.lists.rust-lang.org", &rules),
            Some("misc.lists.rust-lang".to_string())
        );
    }

    #[test]
    fn apply_routing_prefix_wildcard_no_match() {
        let rules = vec![rule("*.lists.rust-lang.org", "misc.lists.rust-lang")];
        assert_eq!(
            apply_routing_rules("rust-users.lists.python.org", &rules),
            None
        );
    }

    #[test]
    fn apply_routing_first_match_wins() {
        let rules = vec![
            rule("rust-users.lists.rust-lang.org", "first.match"),
            rule("*.lists.rust-lang.org", "second.match"),
        ];
        assert_eq!(
            apply_routing_rules("rust-users.lists.rust-lang.org", &rules),
            Some("first.match".to_string())
        );
    }

    #[test]
    fn apply_routing_empty_rules() {
        assert_eq!(
            apply_routing_rules("rust-users.lists.rust-lang.org", &[]),
            None
        );
    }

    // --- add_newsgroups_header ---

    #[test]
    fn add_newsgroups_header_prepends() {
        let msg = b"From: a@b.com\r\n\r\nbody\r\n";
        let result = add_newsgroups_header(msg, "comp.lang.rust");
        assert!(result.starts_with(b"Newsgroups: comp.lang.rust\r\n"));
        assert!(result.ends_with(b"From: a@b.com\r\n\r\nbody\r\n"));
    }

    #[test]
    fn add_newsgroups_header_correct_length() {
        let msg = b"Subject: test\r\n\r\nbody";
        let header = b"Newsgroups: misc.test\r\n";
        let result = add_newsgroups_header(msg, "misc.test");
        assert_eq!(result.len(), header.len() + msg.len());
    }

    // --- extract_message_id ---

    #[test]
    fn extract_message_id_present() {
        let msg = b"Message-ID: <abc123@example.com>\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        assert_eq!(
            extract_message_id(msg),
            Some("abc123@example.com".to_string())
        );
    }

    #[test]
    fn extract_message_id_absent() {
        let msg = b"From: a@b.com\r\nSubject: no msgid\r\n\r\nbody\r\n";
        assert_eq!(extract_message_id(msg), None);
    }
}
