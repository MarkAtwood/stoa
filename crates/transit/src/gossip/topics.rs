use libp2p::gossipsub::IdentTopic;
use std::collections::HashSet;

/// Return the gossipsub topic for a newsgroup.
///
/// The topic is `usenet.hier.<hierarchy>` where `<hierarchy>` is the first
/// dot-separated component of the group name. For example:
/// - `comp.lang.rust` → `usenet.hier.comp`
/// - `sci.math` → `usenet.hier.sci`
/// - `local` (no dots) → `usenet.hier.local`
pub fn topic_for_group(group_name: &str) -> IdentTopic {
    let hierarchy = group_name.split('.').next().unwrap_or(group_name);
    IdentTopic::new(format!("usenet.hier.{hierarchy}"))
}

/// Compute the minimal set of hierarchy topics that cover all listed groups.
///
/// Returns deduplicated `IdentTopic` values, one per unique hierarchy.
/// Order is not guaranteed.
pub fn subscribe_hierarchies(groups: &[&str]) -> Vec<IdentTopic> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut topics = Vec::new();
    for &group in groups {
        let hierarchy = group.split('.').next().unwrap_or(group).to_owned();
        if seen.insert(hierarchy.clone()) {
            topics.push(IdentTopic::new(format!("usenet.hier.{hierarchy}")));
        }
    }
    topics
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: get the topic string from an IdentTopic for assertions.
    ///
    /// `IdentTopic` uses identity hashing, so `Display` returns the raw topic
    /// string and `TopicHash::as_str()` returns the same value.
    fn topic_str(t: &IdentTopic) -> String {
        t.to_string()
    }

    #[test]
    fn comp_lang_rust_maps_to_comp_hierarchy() {
        let t = topic_for_group("comp.lang.rust");
        assert_eq!(topic_str(&t), "usenet.hier.comp");
    }

    #[test]
    fn comp_os_linux_maps_to_same_topic_as_comp_lang_rust() {
        let t1 = topic_for_group("comp.lang.rust");
        let t2 = topic_for_group("comp.os.linux");
        assert_eq!(t1.hash(), t2.hash(), "both should be usenet.hier.comp");
    }

    #[test]
    fn sci_math_maps_to_different_topic_than_comp() {
        let t1 = topic_for_group("comp.lang.rust");
        let t2 = topic_for_group("sci.math");
        assert_ne!(t1.hash(), t2.hash(), "comp and sci should be different topics");
    }

    #[test]
    fn subscribe_hierarchies_deduplicates() {
        let topics = subscribe_hierarchies(&["comp.lang.rust", "comp.os.linux", "sci.math"]);
        assert_eq!(topics.len(), 2, "comp.lang.rust and comp.os.linux share a hierarchy");
    }

    #[test]
    fn single_component_group_maps_to_local_hierarchy() {
        let t = topic_for_group("local");
        assert_eq!(topic_str(&t), "usenet.hier.local");
    }

    #[test]
    fn subscribe_hierarchies_empty_input() {
        let topics = subscribe_hierarchies(&[]);
        assert!(topics.is_empty());
    }

    #[test]
    fn subscribe_hierarchies_single_group() {
        let topics = subscribe_hierarchies(&["alt.test"]);
        assert_eq!(topics.len(), 1);
        assert_eq!(topic_str(&topics[0]), "usenet.hier.alt");
    }
}
