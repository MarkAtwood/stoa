use serde_json::{json, Value};

use crate::mailbox::types::mailbox_id_for_group;

use super::get::GroupInfo;

/// Handle Mailbox/query.
///
/// Supports optional filter: `{isSubscribed: true}` returns only subscribed groups.
/// Supports sort by name (ascending).
/// `state` is the current JMAP Mailbox state string from StateStore.
pub fn handle_mailbox_query(
    groups: &[GroupInfo],
    filter: Option<&Value>,
    _sort: Option<&Value>,
    state: &str,
    account_id: &str,
) -> Value {
    let mut filtered: Vec<&GroupInfo> = groups.iter().collect();

    // Apply isSubscribed filter if present.
    if let Some(f) = filter {
        if let Some(is_sub) = f.get("isSubscribed").and_then(|v| v.as_bool()) {
            filtered.retain(|g| g.is_subscribed == is_sub);
        }
    }

    // Sort by name ascending (default).
    filtered.sort_by(|a, b| a.name.cmp(&b.name));

    let ids: Vec<Value> = filtered
        .iter()
        .map(|g| Value::String(mailbox_id_for_group(&g.name)))
        .collect();
    let total = ids.len() as u64;

    json!({
        "accountId": account_id,
        "queryState": state,
        "canCalculateChanges": false,
        "position": 0,
        "ids": ids,
        "total": total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::types::mailbox_id_for_group;

    fn sample_groups() -> Vec<GroupInfo> {
        vec![
            GroupInfo {
                name: "comp.lang.rust".to_string(),
                total_emails: 5,
                unread_emails: 2,
                is_subscribed: true,
            },
            GroupInfo {
                name: "alt.test".to_string(),
                total_emails: 1,
                unread_emails: 0,
                is_subscribed: false,
            },
        ]
    }

    #[test]
    fn query_no_filter_returns_all_sorted() {
        let resp = handle_mailbox_query(&sample_groups(), None, None, "0", "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 2);
        // sorted: alt.test < comp.lang.rust
        assert_eq!(ids[0].as_str().unwrap(), mailbox_id_for_group("alt.test"));
        assert_eq!(
            ids[1].as_str().unwrap(),
            mailbox_id_for_group("comp.lang.rust")
        );
    }

    #[test]
    fn query_filter_subscribed() {
        let filter = json!({"isSubscribed": true});
        let resp = handle_mailbox_query(&sample_groups(), Some(&filter), None, "0", "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids[0].as_str().unwrap(),
            mailbox_id_for_group("comp.lang.rust")
        );
    }

    #[test]
    fn query_filter_unsubscribed() {
        let filter = json!({"isSubscribed": false});
        let resp = handle_mailbox_query(&sample_groups(), Some(&filter), None, "0", "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].as_str().unwrap(), mailbox_id_for_group("alt.test"));
    }

    #[test]
    fn query_returns_correct_total() {
        let resp = handle_mailbox_query(&sample_groups(), None, None, "0", "test");
        assert_eq!(resp["total"].as_u64().unwrap(), 2);
    }

    #[test]
    fn state_string_is_passed_through() {
        let resp = handle_mailbox_query(&sample_groups(), None, None, "7", "test");
        assert_eq!(resp["queryState"].as_str().unwrap(), "7");
    }
}
