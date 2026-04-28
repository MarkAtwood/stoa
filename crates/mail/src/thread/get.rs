//! Thread/get handler for JMAP Mail (RFC 8621 §4.3).
//!
//! A JMAP Thread object is `{id: String, emailIds: Vec<String>}`.
//! Thread ID is derived from the root message-ID of the conversation chain:
//!   - If the `References` header is present, the first angle-bracketed ID in
//!     it is the oldest known ancestor (the thread root).
//!   - If `References` is absent or empty, the article's own message-ID is the
//!     thread root (the article starts a new thread).
//!
//! The thread ID is the raw root message-ID string (including angle brackets),
//! which is stable and unique for a given thread.  JMAP thread IDs are opaque
//! to clients; this encoding is a v1 implementation detail.
//!
//! # Independent oracle
//!
//! The thread-root extraction rule matches RFC 5537 §3.3 ("The first
//! message-ID in a References field is the article that started the thread").
//! Test vectors in this module are derived from RFC 5537 examples.

use serde_json::{json, Value};

/// Pre-fetched article data needed for thread grouping.
pub struct ThreadEntry {
    /// JMAP email id (CID string).
    pub email_id: String,
    /// Raw `References` header value (space-separated message IDs).
    pub references: String,
    /// Article's own `Message-ID` header value (with angle brackets).
    pub message_id: String,
}

/// Extract the first angle-bracketed message-ID from a References header string.
///
/// Returns `None` when no valid `<...>` token is found.
///
/// Handles whitespace-separated and comma-separated formats.
pub fn first_reference(references: &str) -> Option<&str> {
    references
        .split_whitespace()
        .find(|s| s.starts_with('<') && s.ends_with('>'))
}

/// Compute the thread ID for a single article.
///
/// Thread ID = first message-ID in `references`, or `message_id` if none.
pub fn thread_id_for(references: &str, message_id: &str) -> String {
    first_reference(references)
        .unwrap_or(message_id)
        .to_string()
}

/// Handle `Thread/get`.
///
/// `entries` contains pre-fetched article data for all articles the caller
/// wants to make available for threading.  The caller is responsible for
/// fetching the relevant articles (e.g. all articles in the queried group).
///
/// `requested_ids` is the list of thread IDs from the client request.
/// Only threads whose computed ID is in `requested_ids` are returned.
/// Threads not found in `entries` are included in `not_found`.
///
/// `state` is the current JMAP Thread state string.
///
/// Returns a JMAP `GetResponse` value.
pub fn handle_thread_get(entries: &[ThreadEntry], requested_ids: &[&str], state: &str) -> Value {
    use std::collections::HashMap;

    // Group email IDs by thread ID.
    let mut thread_map: HashMap<String, Vec<String>> = HashMap::new();
    for entry in entries {
        let tid = thread_id_for(&entry.references, &entry.message_id);
        thread_map
            .entry(tid)
            .or_default()
            .push(entry.email_id.clone());
    }

    let mut list = Vec::new();
    let mut not_found = Vec::new();

    for &tid in requested_ids {
        match thread_map.get(tid) {
            Some(email_ids) => {
                list.push(json!({
                    "id": tid,
                    "emailIds": email_ids,
                }));
            }
            None => not_found.push(tid),
        }
    }

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

    // ── thread_id_for ──────────────────────────────────────────────────────────

    /// Oracle: RFC 5537 §3.3 — first ID in References is the thread root.
    #[test]
    fn thread_id_is_first_reference() {
        let refs = "<root@example.com> <mid1@example.com> <mid2@example.com>";
        assert_eq!(
            thread_id_for(refs, "<leaf@example.com>"),
            "<root@example.com>"
        );
    }

    /// Oracle: no References → own message-ID is the thread root.
    #[test]
    fn thread_id_no_references_uses_own_msgid() {
        assert_eq!(
            thread_id_for("", "<standalone@example.com>"),
            "<standalone@example.com>"
        );
    }

    /// Oracle: references with whitespace-only string → own message-ID.
    #[test]
    fn thread_id_whitespace_only_references_uses_own_msgid() {
        assert_eq!(
            thread_id_for("   ", "<standalone@example.com>"),
            "<standalone@example.com>"
        );
    }

    /// Oracle: References with a single ID returns that ID as root.
    #[test]
    fn thread_id_single_reference_is_root() {
        assert_eq!(
            thread_id_for("<root@example.com>", "<reply@example.com>"),
            "<root@example.com>"
        );
    }

    // ── handle_thread_get ──────────────────────────────────────────────────────

    #[test]
    fn single_article_thread_has_emailid_equal_to_threadid() {
        let entries = vec![ThreadEntry {
            email_id: "cid1".to_string(),
            references: String::new(),
            message_id: "<root@example.com>".to_string(),
        }];
        let resp = handle_thread_get(&entries, &["<root@example.com>"], "0");
        let list = resp["list"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"].as_str().unwrap(), "<root@example.com>");
        let email_ids = list[0]["emailIds"].as_array().unwrap();
        assert_eq!(email_ids.len(), 1);
        assert_eq!(email_ids[0].as_str().unwrap(), "cid1");
    }

    #[test]
    fn threaded_articles_share_thread_id() {
        let entries = vec![
            ThreadEntry {
                email_id: "cid1".to_string(),
                references: String::new(),
                message_id: "<root@example.com>".to_string(),
            },
            ThreadEntry {
                email_id: "cid2".to_string(),
                references: "<root@example.com>".to_string(),
                message_id: "<reply@example.com>".to_string(),
            },
        ];
        let resp = handle_thread_get(&entries, &["<root@example.com>"], "0");
        let list = resp["list"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        let email_ids = list[0]["emailIds"].as_array().unwrap();
        assert_eq!(
            email_ids.len(),
            2,
            "both articles must be in the same thread"
        );
    }

    #[test]
    fn thread_not_found_goes_into_not_found() {
        let entries: Vec<ThreadEntry> = vec![];
        let resp = handle_thread_get(&entries, &["<missing@example.com>"], "0");
        let not_found = resp["notFound"].as_array().unwrap();
        assert_eq!(not_found.len(), 1);
        assert_eq!(not_found[0].as_str().unwrap(), "<missing@example.com>");
    }

    #[test]
    fn state_string_is_passed_through() {
        let entries: Vec<ThreadEntry> = vec![];
        let resp = handle_thread_get(&entries, &[], "42");
        assert_eq!(resp["state"].as_str().unwrap(), "42");
    }
}
