use crate::session::response::Response;
use stoa_core::wildmat::matches_wildmat;

/// Information about a single newsgroup, passed to LIST handlers.
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub name: String,
    pub high: u64,
    pub low: u64,
    pub posting_allowed: bool,
    pub description: String,
}

/// LIST ACTIVE [wildmat]: returns one line per matching group.
///
/// Format per RFC 3977 §7.6.3: `name high low flag`
/// Flag: `y` if posting allowed, `n` if not.
pub fn list_active(groups: &[GroupInfo], wildmat: Option<&str>) -> Response {
    let mut body = Vec::new();
    for g in groups {
        if let Some(pat) = wildmat {
            if !matches_wildmat(&g.name, pat) {
                continue;
            }
        }
        let flag = if g.posting_allowed { 'y' } else { 'n' };
        body.push(format!("{} {} {} {}", g.name, g.high, g.low, flag));
    }
    Response::list_active(body)
}

/// LIST NEWSGROUPS [wildmat]: returns one line per matching group.
///
/// Format per RFC 3977 §7.6.6: `name description`
pub fn list_newsgroups(groups: &[GroupInfo], wildmat: Option<&str>) -> Response {
    let mut body = Vec::new();
    for g in groups {
        if let Some(pat) = wildmat {
            if !matches_wildmat(&g.name, pat) {
                continue;
            }
        }
        body.push(format!("{} {}", g.name, g.description));
    }
    Response::list_newsgroups(body)
}

/// NEWGROUPS date time: groups created after the given timestamp.
///
/// V1 conservative behaviour: return all groups, since we have no creation
/// timestamps. Better to return too many than too few.
pub fn newgroups(groups: &[GroupInfo], _since_timestamp: u64) -> Response {
    let body: Vec<String> = groups
        .iter()
        .map(|g| {
            let flag = if g.posting_allowed { 'y' } else { 'n' };
            format!("{} {} {} {}", g.name, g.high, g.low, flag)
        })
        .collect();
    Response::newgroups(body)
}

/// LIST OVERVIEW.FMT: return the static list of overview fields in order.
///
/// RFC 6048 §2.1 — fields are in the order: Subject, From, Date, Message-ID,
/// References, :bytes, :lines. The colon prefix means "not a real header name
/// but a computed value".
pub fn list_overview_fmt() -> Response {
    let body = vec![
        "Subject:".to_string(),
        "From:".to_string(),
        "Date:".to_string(),
        "Message-ID:".to_string(),
        "References:".to_string(),
        ":bytes".to_string(),
        ":lines".to_string(),
    ];
    Response::list_overview_fmt(body)
}

/// Convert a cache entry into the GroupInfo expected by list handlers.
/// `posting_allowed` defaults to `true` (conservative: allow posting).
pub fn group_info_from_cache(meta: &crate::store::group_cache::GroupMetadata) -> GroupInfo {
    GroupInfo {
        name: meta.name.clone(),
        high: meta.high,
        low: meta.low,
        posting_allowed: true,
        description: meta.description.clone(),
    }
}

/// NEWNEWS wildmat date time: Message-IDs of articles newer than timestamp.
///
/// V1 conservative behaviour: return empty list. Clients will catch up via
/// GROUP/ARTICLE once they select a group.
pub fn newnews(_groups: &[GroupInfo], _since_timestamp: u64, _wildmat: Option<&str>) -> Response {
    Response::newnews(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_groups() -> Vec<GroupInfo> {
        vec![
            GroupInfo {
                name: "comp.lang.rust".into(),
                high: 100,
                low: 1,
                posting_allowed: true,
                description: "The Rust programming language".into(),
            },
            GroupInfo {
                name: "alt.test".into(),
                high: 50,
                low: 1,
                posting_allowed: false,
                description: "Testing only".into(),
            },
        ]
    }

    // ---- list_active ----

    #[test]
    fn list_active_empty() {
        let resp = list_active(&[], None);
        assert_eq!(resp.code, 215);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn list_active_with_groups() {
        let groups = sample_groups();
        let resp = list_active(&groups, None);
        assert_eq!(resp.code, 215);
        assert_eq!(resp.body.len(), 2);
        assert!(resp.body[0].contains("comp.lang.rust"));
        assert!(resp.body[0].ends_with(" y"));
        assert!(resp.body[1].contains("alt.test"));
        assert!(resp.body[1].ends_with(" n"));
    }

    #[test]
    fn list_active_wildmat_filter() {
        let groups = sample_groups();
        let resp = list_active(&groups, Some("comp.*"));
        assert_eq!(resp.code, 215);
        assert_eq!(resp.body.len(), 1);
        assert!(resp.body[0].starts_with("comp.lang.rust "));
    }

    #[test]
    fn list_active_format_fields() {
        let groups = vec![GroupInfo {
            name: "misc.test".into(),
            high: 42,
            low: 7,
            posting_allowed: true,
            description: "".into(),
        }];
        let resp = list_active(&groups, None);
        assert_eq!(resp.body[0], "misc.test 42 7 y");
    }

    // ---- list_newsgroups ----

    #[test]
    fn list_newsgroups_format() {
        let groups = sample_groups();
        let resp = list_newsgroups(&groups, None);
        assert_eq!(resp.code, 215);
        assert_eq!(resp.body.len(), 2);
        assert_eq!(resp.body[0], "comp.lang.rust The Rust programming language");
        assert_eq!(resp.body[1], "alt.test Testing only");
    }

    #[test]
    fn list_newsgroups_wildmat_filter() {
        let groups = sample_groups();
        let resp = list_newsgroups(&groups, Some("alt.*"));
        assert_eq!(resp.code, 215);
        assert_eq!(resp.body.len(), 1);
        assert!(resp.body[0].starts_with("alt.test "));
    }

    // ---- newgroups ----

    #[test]
    fn newgroups_returns_all() {
        let groups = sample_groups();
        let resp = newgroups(&groups, 0);
        assert_eq!(resp.code, 231);
        assert_eq!(resp.body.len(), 2);
    }

    #[test]
    fn newgroups_empty() {
        let resp = newgroups(&[], 0);
        assert_eq!(resp.code, 231);
        assert!(resp.body.is_empty());
    }

    // ---- newnews ----

    #[test]
    fn newnews_returns_empty() {
        let groups = sample_groups();
        let resp = newnews(&groups, 0, None);
        assert_eq!(resp.code, 230);
        assert!(resp.body.is_empty());
    }

    // ---- list_overview_fmt ----

    #[test]
    fn list_overview_fmt_code() {
        let resp = list_overview_fmt();
        assert_eq!(resp.code, 215);
    }

    #[test]
    fn list_overview_fmt_contains_subject() {
        let resp = list_overview_fmt();
        assert!(resp.body.iter().any(|l| l == "Subject:"));
    }

    #[test]
    fn list_overview_fmt_contains_bytes() {
        let resp = list_overview_fmt();
        assert!(resp.body.iter().any(|l| l == ":bytes"));
    }

    // ---- group_info_from_cache ----

    #[test]
    fn group_info_from_cache_maps_fields() {
        use crate::store::group_cache::GroupMetadata;
        let meta = GroupMetadata {
            name: "comp.lang.rust".to_string(),
            count: 100,
            low: 1,
            high: 100,
            description: "Rust programming language".to_string(),
        };
        let info = group_info_from_cache(&meta);
        assert_eq!(info.name, "comp.lang.rust");
        assert_eq!(info.high, 100);
        assert_eq!(info.low, 1);
        assert!(info.posting_allowed);
        assert_eq!(info.description, "Rust programming language");
    }
}
