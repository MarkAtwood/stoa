use cid::Cid;
use serde_json::{json, Value};

/// An overview record enriched with its CID.
pub struct EmailOverviewEntry {
    pub cid: Cid,
    pub subject: String,
    pub from: String,
    pub date: String,
    pub byte_count: u64,
}

/// Handle Email/query.
///
/// `filter` supports:
///   - `inMailbox`: String — mailbox id (required if no inMailboxOtherThan)
///   - `after`: String — RFC 3339 date; include only emails received after
///   - `before`: String — RFC 3339 date; include only emails received before
///   - `from`: String — substring match in from header
///   - `subject`: String — case-insensitive substring match in subject
///
/// `entries` is all emails in the target mailbox, pre-fetched by the caller.
/// The caller is responsible for filtering to the right group.
///
/// Returns JMAP QueryResponse.
pub fn handle_email_query(
    entries: &[EmailOverviewEntry],
    filter: Option<&Value>,
    position: u64,
    limit: Option<u64>,
) -> Value {
    let mut filtered: Vec<&EmailOverviewEntry> = entries.iter().collect();

    if let Some(f) = filter {
        if let Some(after) = f.get("after").and_then(|v| v.as_str()) {
            filtered.retain(|e| e.date.as_str() >= after);
        }
        if let Some(before) = f.get("before").and_then(|v| v.as_str()) {
            filtered.retain(|e| e.date.as_str() < before);
        }
        if let Some(from_filter) = f.get("from").and_then(|v| v.as_str()) {
            let lower = from_filter.to_lowercase();
            filtered.retain(|e| e.from.to_lowercase().contains(&lower));
        }
        if let Some(subj_filter) = f.get("subject").and_then(|v| v.as_str()) {
            let lower = subj_filter.to_lowercase();
            filtered.retain(|e| e.subject.to_lowercase().contains(&lower));
        }
    }

    // Sort by date descending (newest first).
    filtered.sort_by(|a, b| b.date.cmp(&a.date));

    let total = filtered.len() as u64;

    let start = position as usize;
    let page: Vec<Value> = filtered
        .iter()
        .skip(start)
        .take(limit.unwrap_or(u64::MAX) as usize)
        .map(|e| Value::String(e.cid.to_string()))
        .collect();

    json!({
        "accountId": null,
        "queryState": "0",
        "canCalculateChanges": false,
        "position": position,
        "ids": page,
        "total": total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn test_cid(seed: &[u8]) -> Cid {
        Cid::new_v1(0x71, Code::Sha2_256.digest(seed))
    }

    fn make_entries() -> Vec<EmailOverviewEntry> {
        vec![
            EmailOverviewEntry {
                cid: test_cid(b"article-a"),
                subject: "Rust is great".to_string(),
                from: "alice@example.com".to_string(),
                date: "2026-04-01T10:00:00Z".to_string(),
                byte_count: 100,
            },
            EmailOverviewEntry {
                cid: test_cid(b"article-b"),
                subject: "Testing JMAP".to_string(),
                from: "bob@example.com".to_string(),
                date: "2026-04-02T10:00:00Z".to_string(),
                byte_count: 200,
            },
            EmailOverviewEntry {
                cid: test_cid(b"article-c"),
                subject: "Another Rust post".to_string(),
                from: "carol@example.com".to_string(),
                date: "2026-04-03T10:00:00Z".to_string(),
                byte_count: 300,
            },
        ]
    }

    #[test]
    fn no_filter_returns_all_sorted_desc() {
        let entries = make_entries();
        let resp = handle_email_query(&entries, None, 0, None);
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 3);
        // Newest first: article-c (2026-04-03) > article-b (2026-04-02) > article-a (2026-04-01)
        assert_eq!(
            ids[0].as_str().unwrap(),
            test_cid(b"article-c").to_string()
        );
        assert_eq!(
            ids[2].as_str().unwrap(),
            test_cid(b"article-a").to_string()
        );
    }

    #[test]
    fn filter_by_subject_substring() {
        let entries = make_entries();
        let filter = json!({"subject": "rust"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None);
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 2, "Should match 'Rust is great' and 'Another Rust post'");
    }

    #[test]
    fn filter_by_from() {
        let entries = make_entries();
        let filter = json!({"from": "bob"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None);
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids[0].as_str().unwrap(),
            test_cid(b"article-b").to_string()
        );
    }

    #[test]
    fn filter_after_date() {
        let entries = make_entries();
        let filter = json!({"after": "2026-04-01T20:00:00Z"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None);
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 2, "Should return articles from 2026-04-02 and 2026-04-03");
    }

    #[test]
    fn pagination_position_and_limit() {
        let entries = make_entries();
        let resp = handle_email_query(&entries, None, 1, Some(1));
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 1, "limit=1 should return exactly 1 item");
        assert_eq!(resp["total"].as_u64().unwrap(), 3, "total must reflect full count");
    }

    #[test]
    fn empty_result() {
        let entries: Vec<EmailOverviewEntry> = vec![];
        let resp = handle_email_query(&entries, None, 0, None);
        let ids = resp["ids"].as_array().unwrap();
        assert!(ids.is_empty());
        assert_eq!(resp["total"].as_u64().unwrap(), 0);
    }
}
