use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// JMAP Mailbox object (RFC 8621 §2).
///
/// In stoa, each newsgroup maps to a Mailbox. The id is stable and
/// derived from the group name — it is never stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Mailbox {
    /// Stable id derived from the group name.
    pub id: String,
    /// Human-readable name (the newsgroup name).
    pub name: String,
    /// Always null in stoa (flat hierarchy).
    #[serde(rename = "parentId")]
    pub parent_id: Option<String>,
    /// JMAP role (e.g. "inbox" if configured, else null).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Client sort hint (use 10 for all groups by default).
    #[serde(rename = "sortOrder")]
    pub sort_order: u32,
    /// Total emails in this mailbox.
    #[serde(rename = "totalEmails")]
    pub total_emails: u32,
    /// Unread email count (0 until user-flags are wired).
    #[serde(rename = "unreadEmails")]
    pub unread_emails: u32,
    /// Whether this user is subscribed to the group.
    #[serde(rename = "isSubscribed")]
    pub is_subscribed: bool,
}

/// Derive a stable, collision-resistant JMAP id from a newsgroup name.
///
/// Algorithm: SHA-256 of UTF-8 group name bytes → first 16 bytes →
/// base32-encode with no padding (uppercase, URL-safe A-Z2-7 alphabet).
/// Result is always 26 characters.
pub fn mailbox_id_for_group(group_name: &str) -> String {
    let digest = Sha256::digest(group_name.as_bytes());
    BASE32_NOPAD.encode(&digest[..16])
}

impl Mailbox {
    /// Construct a Mailbox from a group name and article counts.
    pub fn from_group(
        group_name: &str,
        total_emails: u32,
        unread_emails: u32,
        is_subscribed: bool,
    ) -> Self {
        Self {
            id: mailbox_id_for_group(group_name),
            name: group_name.to_string(),
            parent_id: None,
            role: None,
            sort_order: 10,
            total_emails,
            unread_emails,
            is_subscribed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn id_is_stable() {
        let id1 = mailbox_id_for_group("comp.lang.rust");
        let id2 = mailbox_id_for_group("comp.lang.rust");
        assert_eq!(id1, id2);
    }

    #[test]
    fn id_is_26_chars() {
        let id = mailbox_id_for_group("comp.lang.rust");
        assert_eq!(id.len(), 26, "base32 of 16 bytes must be 26 chars: {id}");
    }

    #[test]
    fn id_is_url_safe() {
        let id = mailbox_id_for_group("alt.test");
        assert!(
            id.chars().all(|c| c.is_ascii_alphanumeric()),
            "id must be alphanumeric: {id}"
        );
    }

    #[test]
    fn different_groups_different_ids() {
        let groups = [
            "comp.lang.rust",
            "comp.lang.c",
            "alt.test",
            "sci.math",
            "misc.misc",
            "news.admin.announce",
            "rec.arts.movies",
            "talk.politics.misc",
            "soc.culture.british",
            "humanities.classics",
        ];
        let ids: HashSet<String> = groups.iter().map(|g| mailbox_id_for_group(g)).collect();
        assert_eq!(
            ids.len(),
            groups.len(),
            "all group names must produce unique ids"
        );
    }

    #[test]
    fn collision_test_50_groups() {
        let groups: Vec<String> = (0..50).map(|i| format!("comp.test.group{i}")).collect();
        let ids: HashSet<String> = groups.iter().map(|g| mailbox_id_for_group(g)).collect();
        assert_eq!(
            ids.len(),
            50,
            "50 distinct groups must produce 50 distinct ids"
        );
    }

    #[test]
    fn mailbox_from_group_round_trips_json() {
        let mb = Mailbox::from_group("comp.lang.rust", 42, 5, true);
        assert_eq!(mb.name, "comp.lang.rust");
        assert_eq!(mb.total_emails, 42);
        assert_eq!(mb.unread_emails, 5);
        assert!(mb.is_subscribed);
        assert_eq!(mb.id, mailbox_id_for_group("comp.lang.rust"));
        // round-trip through JSON
        let json = serde_json::to_string(&mb).unwrap();
        let back: Mailbox = serde_json::from_str(&json).unwrap();
        assert_eq!(back, mb);
    }
}
