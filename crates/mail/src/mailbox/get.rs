use std::collections::HashMap;

use serde_json::{json, Value};

use crate::mailbox::types::{Mailbox, SpecialMailbox};

/// Data about a newsgroup available to Mailbox/get.
pub struct GroupInfo {
    pub name: String,
    pub total_emails: u32,
    pub unread_emails: u32,
    pub is_subscribed: bool,
}

/// Handle Mailbox/get given provisioned special folders and newsgroup infos.
///
/// `special_mailboxes` are the RFC 6154 special-use folders for this user.
/// `groups` are the newsgroups visible to this user.
/// `ids` is the JMAP ids argument (None means return all).
/// `state` is the current JMAP Mailbox state string from StateStore.
/// `account_id` is echoed verbatim into the response (RFC 8621 §3.1).
pub fn handle_mailbox_get(
    special_mailboxes: &[SpecialMailbox],
    groups: &[GroupInfo],
    ids: Option<&[String]>,
    state: &str,
    account_id: &str,
) -> Value {
    let special: Vec<Mailbox> = special_mailboxes
        .iter()
        .map(Mailbox::from_special)
        .collect();
    let newsgroup: Vec<Mailbox> = groups
        .iter()
        .map(|g| Mailbox::from_group(&g.name, g.total_emails, g.unread_emails, g.is_subscribed))
        .collect();
    // Include the virtual "News" root only when there are newsgroups to show.
    let news_root: Vec<Mailbox> = if groups.is_empty() {
        vec![]
    } else {
        vec![Mailbox::news_root()]
    };
    let all_mailboxes: Vec<Mailbox> = [special, news_root, newsgroup].concat();

    let (list, not_found) = match ids {
        None => (all_mailboxes, vec![]),
        Some(requested) => {
            // Build lookup by id.
            let by_id: HashMap<String, &Mailbox> =
                all_mailboxes.iter().map(|m| (m.id.clone(), m)).collect();
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
        "accountId": account_id,
        "state": state,
        "list": list,
        "notFound": not_found,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::types::{MailboxRights, SpecialMailbox};

    // Oracle: RFC 8621 §2 specifies all nine myRights field names.
    fn inbox_special() -> SpecialMailbox {
        SpecialMailbox {
            id: "XHEK6XD6CFURMHQFSXIALKNX6A".to_string(),
            role: "inbox".to_string(),
            name: "INBOX".to_string(),
            sort_order: 1,
        }
    }

    fn sent_special() -> SpecialMailbox {
        SpecialMailbox {
            id: "4ZAA5SOFZU7P5STWROOWLLRNOM".to_string(),
            role: "sent".to_string(),
            name: "Sent".to_string(),
            sort_order: 2,
        }
    }

    fn rust_group() -> GroupInfo {
        GroupInfo {
            name: "comp.lang.rust".to_string(),
            total_emails: 5,
            unread_emails: 2,
            is_subscribed: true,
        }
    }

    #[test]
    fn mailbox_rights_serializes_all_nine_fields() {
        let rights = MailboxRights {
            may_read_items: true,
            may_add_items: true,
            may_remove_items: true,
            may_set_seen: true,
            may_set_keywords: true,
            may_create_child: true,
            may_rename: true,
            may_delete: true,
            may_submit: true,
        };
        let v = serde_json::to_value(&rights).unwrap();
        let obj = v.as_object().unwrap();
        for key in &[
            "mayReadItems",
            "mayAddItems",
            "mayRemoveItems",
            "maySetSeen",
            "maySetKeywords",
            "mayCreateChild",
            "mayRename",
            "mayDelete",
            "maySubmit",
        ] {
            assert!(obj.contains_key(*key), "missing key: {key}");
            assert_eq!(obj[*key].as_bool().unwrap(), true);
        }
        assert_eq!(obj.len(), 9);
    }

    #[test]
    fn newsgroup_mailbox_has_null_role() {
        let mb = Mailbox::from_group("comp.lang.rust", 10, 3, true);
        assert_eq!(mb.role, None);
        let v = serde_json::to_value(&mb).unwrap();
        assert!(!v.as_object().unwrap().contains_key("role"));
    }

    #[test]
    fn special_mailbox_has_role() {
        let mb = Mailbox::from_special(&inbox_special());
        assert_eq!(mb.role.as_deref(), Some("inbox"));
        let v = serde_json::to_value(&mb).unwrap();
        assert_eq!(v["role"].as_str().unwrap(), "inbox");
    }

    #[test]
    fn special_inbox_my_rights_readable_but_not_writable() {
        let mb = Mailbox::from_special(&inbox_special());
        let r = &mb.my_rights;
        assert!(r.may_read_items);
        assert!(!r.may_add_items);
        assert!(!r.may_remove_items);
        assert!(r.may_set_seen);
        assert!(r.may_set_keywords);
        assert!(!r.may_create_child);
        assert!(!r.may_rename);
        assert!(!r.may_delete);
        assert!(!r.may_submit);
    }

    #[test]
    fn handle_mailbox_get_account_id_echoed() {
        let resp = handle_mailbox_get(&[inbox_special()], &[rust_group()], None, "0", "u_alice");
        assert_eq!(resp["accountId"].as_str().unwrap(), "u_alice");
    }

    #[test]
    fn handle_mailbox_get_special_folders_in_list() {
        // 2 special + 1 News root + 1 newsgroup = 4
        let resp = handle_mailbox_get(
            &[inbox_special(), sent_special()],
            &[rust_group()],
            None,
            "0",
            "u_alice",
        );
        assert_eq!(resp["list"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn handle_mailbox_get_special_folders_have_role() {
        let resp = handle_mailbox_get(
            &[inbox_special(), sent_special()],
            &[],
            None,
            "0",
            "u_alice",
        );
        let list = resp["list"].as_array().unwrap();
        let roles: Vec<&str> = list.iter().map(|e| e["role"].as_str().unwrap()).collect();
        assert!(roles.contains(&"inbox"));
        assert!(roles.contains(&"sent"));
    }

    #[test]
    fn handle_mailbox_get_newsgroup_has_null_role() {
        let resp = handle_mailbox_get(&[inbox_special()], &[rust_group()], None, "0", "u_alice");
        let ng = resp["list"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"].as_str() == Some("comp.lang.rust"))
            .unwrap();
        assert!(!ng.as_object().unwrap().contains_key("role"));
    }

    #[test]
    fn handle_mailbox_get_all_entries_have_my_rights() {
        let nine = [
            "mayReadItems",
            "mayAddItems",
            "mayRemoveItems",
            "maySetSeen",
            "maySetKeywords",
            "mayCreateChild",
            "mayRename",
            "mayDelete",
            "maySubmit",
        ];
        let resp = handle_mailbox_get(&[inbox_special()], &[rust_group()], None, "0", "u_alice");
        for entry in resp["list"].as_array().unwrap() {
            let name = entry["name"].as_str().unwrap_or("?");
            let mr = entry
                .get("myRights")
                .and_then(|v| v.as_object())
                .unwrap_or_else(|| panic!("{name}: missing myRights"));
            for k in &nine {
                assert!(mr.contains_key(*k), "{name}: missing myRights.{k}");
                assert!(mr[*k].is_boolean());
            }
        }
    }

    // Preserved from original tests (adapted for new signature):
    #[test]
    fn get_all_returns_both() {
        // 1 News root + 2 newsgroups = 3
        let resp = handle_mailbox_get(
            &[],
            &[
                rust_group(),
                GroupInfo {
                    name: "alt.test".into(),
                    total_emails: 1,
                    unread_emails: 0,
                    is_subscribed: false,
                },
            ],
            None,
            "0",
            "u_test",
        );
        assert_eq!(resp["list"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn get_by_id_not_found() {
        let resp = handle_mailbox_get(
            &[],
            &[rust_group()],
            Some(&["nonexistent-id".to_string()]),
            "0",
            "u_test",
        );
        assert!(resp["list"].as_array().unwrap().is_empty());
        assert_eq!(resp["notFound"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn state_string_is_passed_through() {
        let resp = handle_mailbox_get(&[], &[rust_group()], None, "99", "u_test");
        assert_eq!(resp["state"].as_str().unwrap(), "99");
    }

    #[test]
    fn news_root_included_when_groups_present() {
        use crate::mailbox::types::mailbox_id_for_news_root;

        let resp = handle_mailbox_get(&[], &[rust_group()], None, "0", "u_test");
        let list = resp["list"].as_array().unwrap();
        let news_root = list
            .iter()
            .find(|e| e["name"].as_str() == Some("News"))
            .expect("News root mailbox must be present when newsgroups are returned");
        assert_eq!(
            news_root["id"].as_str().unwrap(),
            mailbox_id_for_news_root(),
        );
        assert!(
            news_root["parentId"].is_null(),
            "News root must have null parentId"
        );
    }

    #[test]
    fn news_root_absent_when_no_groups() {
        let resp = handle_mailbox_get(&[inbox_special()], &[], None, "0", "u_test");
        let list = resp["list"].as_array().unwrap();
        let has_news_root = list.iter().any(|e| e["name"].as_str() == Some("News"));
        assert!(
            !has_news_root,
            "News root must not appear when there are no newsgroups"
        );
    }

    #[test]
    fn newsgroup_parent_id_is_news_root() {
        use crate::mailbox::types::mailbox_id_for_news_root;

        let resp = handle_mailbox_get(&[], &[rust_group()], None, "0", "u_test");
        let list = resp["list"].as_array().unwrap();
        let ng = list
            .iter()
            .find(|e| e["name"].as_str() == Some("comp.lang.rust"))
            .unwrap();
        assert_eq!(
            ng["parentId"].as_str().unwrap(),
            mailbox_id_for_news_root(),
            "newsgroup parentId must equal the News root id"
        );
    }
}
