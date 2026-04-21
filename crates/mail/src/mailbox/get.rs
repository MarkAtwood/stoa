use std::collections::HashMap;

use serde_json::{json, Value};

use crate::mailbox::types::Mailbox;

/// Data about a newsgroup available to Mailbox/get.
pub struct GroupInfo {
    pub name: String,
    pub total_emails: u32,
    pub unread_emails: u32,
    pub is_subscribed: bool,
}

/// Handle Mailbox/get given a list of group infos.
///
/// `ids` is the JMAP ids argument (null means return all).
/// `state` is the current JMAP Mailbox state string from StateStore.
pub fn handle_mailbox_get(groups: &[GroupInfo], ids: Option<&[String]>, state: &str) -> Value {
    let all_mailboxes: Vec<Mailbox> = groups
        .iter()
        .map(|g| Mailbox::from_group(&g.name, g.total_emails, g.unread_emails, g.is_subscribed))
        .collect();

    let (list, not_found) = match ids {
        None => (all_mailboxes, vec![]),
        Some(requested) => {
            // Build lookup by id.
            let by_id: HashMap<String, &Mailbox> = all_mailboxes
                .iter()
                .map(|m| (m.id.clone(), m))
                .collect();
            let mut found = Vec::new();
            let mut not_found = Vec::new();
            for id in requested {
                match by_id.get(id.as_str()) {
                    Some(m) => found.push((*m).clone()),
                    None => not_found.push(id.clone()),
                }
            }
            (found, not_found)
        }
    };

    json!({
        "accountId": null,
        "state": state,
        "list": list,
        "notFound": not_found,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::types::mailbox_id_for_group;

    fn sample_groups() -> Vec<GroupInfo> {
        vec![
            GroupInfo { name: "comp.lang.rust".to_string(), total_emails: 5, unread_emails: 2, is_subscribed: true },
            GroupInfo { name: "alt.test".to_string(), total_emails: 1, unread_emails: 0, is_subscribed: false },
        ]
    }

    #[test]
    fn get_all_returns_both() {
        let resp = handle_mailbox_get(&sample_groups(), None, "0");
        let list = resp["list"].as_array().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn get_by_id_found() {
        let groups = sample_groups();
        let id = mailbox_id_for_group("comp.lang.rust");
        let resp = handle_mailbox_get(&groups, Some(&[id.clone()]), "0");
        let list = resp["list"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"].as_str().unwrap(), &id);
        let not_found = resp["notFound"].as_array().unwrap();
        assert!(not_found.is_empty());
    }

    #[test]
    fn get_by_id_not_found() {
        let groups = sample_groups();
        let resp = handle_mailbox_get(&groups, Some(&["nonexistent-id".to_string()]), "0");
        let list = resp["list"].as_array().unwrap();
        assert!(list.is_empty());
        let not_found = resp["notFound"].as_array().unwrap();
        assert_eq!(not_found.len(), 1);
    }

    #[test]
    fn state_string_is_passed_through() {
        let resp = handle_mailbox_get(&sample_groups(), None, "99");
        assert_eq!(resp["state"].as_str().unwrap(), "99");
    }
}
