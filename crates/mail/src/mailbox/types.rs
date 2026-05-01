use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Per-mailbox client permissions (RFC 8621 §2, myRights).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MailboxRights {
    #[serde(rename = "mayReadItems")]
    pub may_read_items: bool,
    #[serde(rename = "mayAddItems")]
    pub may_add_items: bool,
    #[serde(rename = "mayRemoveItems")]
    pub may_remove_items: bool,
    #[serde(rename = "maySetSeen")]
    pub may_set_seen: bool,
    #[serde(rename = "maySetKeywords")]
    pub may_set_keywords: bool,
    #[serde(rename = "mayCreateChild")]
    pub may_create_child: bool,
    #[serde(rename = "mayRename")]
    pub may_rename: bool,
    #[serde(rename = "mayDelete")]
    pub may_delete: bool,
    #[serde(rename = "maySubmit")]
    pub may_submit: bool,
}

impl MailboxRights {
    /// INBOX: server-delivered; clients may read and flag but not add/remove.
    pub fn inbox_defaults() -> Self {
        Self {
            may_read_items: true,
            may_add_items: false,
            may_remove_items: false,
            may_set_seen: true,
            may_set_keywords: true,
            may_create_child: false,
            may_rename: false,
            may_delete: false,
            may_submit: false,
        }
    }

    /// Sent: clients may read, add (copy-on-send), flag, and submit.
    pub fn sent_defaults() -> Self {
        Self {
            may_read_items: true,
            may_add_items: true,
            may_remove_items: false,
            may_set_seen: true,
            may_set_keywords: true,
            may_create_child: false,
            may_rename: false,
            may_delete: false,
            may_submit: true,
        }
    }

    /// Drafts: clients may read, add, remove, and flag.
    pub fn drafts_defaults() -> Self {
        Self {
            may_read_items: true,
            may_add_items: true,
            may_remove_items: true,
            may_set_seen: true,
            may_set_keywords: true,
            may_create_child: false,
            may_rename: false,
            may_delete: false,
            may_submit: false,
        }
    }

    /// Trash: clients may read, add, remove, and flag.
    pub fn trash_defaults() -> Self {
        Self {
            may_read_items: true,
            may_add_items: true,
            may_remove_items: true,
            may_set_seen: true,
            may_set_keywords: true,
            may_create_child: false,
            may_rename: false,
            may_delete: false,
            may_submit: false,
        }
    }

    /// Junk: same as trash.
    pub fn junk_defaults() -> Self {
        Self::trash_defaults()
    }

    /// Archive: clients may read, add, remove, and flag.
    pub fn archive_defaults() -> Self {
        Self {
            may_read_items: true,
            may_add_items: true,
            may_remove_items: true,
            may_set_seen: true,
            may_set_keywords: true,
            may_create_child: false,
            may_rename: false,
            may_delete: false,
            may_submit: false,
        }
    }

    /// Newsgroup: read-only; no add/remove/rename/delete.
    pub fn newsgroup_defaults() -> Self {
        Self {
            may_read_items: true,
            may_add_items: false,
            may_remove_items: false,
            may_set_seen: true,
            may_set_keywords: true,
            may_create_child: false,
            may_rename: false,
            may_delete: false,
            may_submit: false,
        }
    }
}

/// A special-use (RFC 6154) mailbox row as read from the database.
#[derive(Debug, Clone)]
pub struct SpecialMailbox {
    pub id: String,
    pub role: String,
    pub name: String,
    pub sort_order: u32,
}

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
    /// `None` for top-level mailboxes (e.g. the virtual "News" root);
    /// `Some(news_root_id)` for newsgroup mailboxes.
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
    /// Per-mailbox client permissions (RFC 8621 §2).
    #[serde(rename = "myRights")]
    pub my_rights: MailboxRights,
}

/// Derive a stable, collision-resistant JMAP id from a newsgroup name.
///
/// Algorithm: SHA-256 of UTF-8 group name bytes → first 16 bytes →
/// base32-encode with no padding (uppercase, URL-safe A-Z2-7 alphabet).
/// Result is always 26 characters.
///
/// The hash input is always the raw group name (e.g. `"comp.lang.rust"`),
/// never the display path — this ensures ID stability if the naming
/// convention changes.
pub fn mailbox_id_for_group(group_name: &str) -> String {
    let digest = Sha256::digest(group_name.as_bytes());
    BASE32_NOPAD.encode(&digest[..16])
}

/// Derive the stable JMAP id for the virtual "News" root mailbox.
///
/// The sentinel `"__news_root__"` is a fixed string that will never collide
/// with any real newsgroup name (group names do not contain underscores).
/// Result is always 26 characters.
pub fn mailbox_id_for_news_root() -> String {
    let digest = Sha256::digest(b"__news_root__");
    BASE32_NOPAD.encode(&digest[..16])
}

impl Mailbox {
    /// Construct the virtual "News" root mailbox.
    ///
    /// This mailbox is not stored in the database; it is synthesised on every
    /// response.  It is `\Noselect` and `\HasChildren` (JMAP has no exact
    /// equivalent flags, but `role = None` and `parentId = None` convey the
    /// hierarchy root).
    pub fn news_root() -> Self {
        Self {
            id: mailbox_id_for_news_root(),
            name: "News".to_string(),
            parent_id: None,
            role: None,
            sort_order: 5,
            total_emails: 0,
            unread_emails: 0,
            is_subscribed: false,
            my_rights: MailboxRights::newsgroup_defaults(),
        }
    }

    /// Construct a Mailbox from a group name and article counts.
    ///
    /// The mailbox `name` is the raw group name (e.g. `"comp.lang.rust"`)
    /// for display; `parentId` points to the virtual "News" root so JMAP
    /// clients see the correct hierarchy.
    pub fn from_group(
        group_name: &str,
        total_emails: u32,
        unread_emails: u32,
        is_subscribed: bool,
    ) -> Self {
        Self {
            id: mailbox_id_for_group(group_name),
            name: group_name.to_string(),
            parent_id: Some(mailbox_id_for_news_root()),
            role: None,
            sort_order: 10,
            total_emails,
            unread_emails,
            is_subscribed,
            my_rights: MailboxRights::newsgroup_defaults(),
        }
    }

    /// Construct a Mailbox from a provisioned special-use folder row.
    pub fn from_special(special: &SpecialMailbox) -> Self {
        let my_rights = match special.role.as_str() {
            "inbox" => MailboxRights::inbox_defaults(),
            "sent" => MailboxRights::sent_defaults(),
            "drafts" => MailboxRights::drafts_defaults(),
            "trash" | "junk" => MailboxRights::trash_defaults(),
            "archive" => MailboxRights::archive_defaults(),
            _ => MailboxRights::inbox_defaults(),
        };
        Self {
            id: special.id.clone(),
            name: special.name.clone(),
            parent_id: None,
            role: Some(special.role.clone()),
            sort_order: special.sort_order,
            total_emails: 0,
            unread_emails: 0,
            is_subscribed: true,
            my_rights,
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

    #[test]
    fn newsgroup_parent_id_is_news_root() {
        // Oracle: mailbox_id_for_news_root() — SHA-256("__news_root__") first 16 bytes,
        // base32-encoded without padding.
        let mb = Mailbox::from_group("comp.lang.rust", 0, 0, false);
        assert_eq!(
            mb.parent_id,
            Some(mailbox_id_for_news_root()),
            "newsgroup mailbox parentId must point to the News root"
        );
    }

    #[test]
    fn news_root_mailbox_has_no_parent() {
        let root = Mailbox::news_root();
        assert_eq!(root.name, "News");
        assert_eq!(root.parent_id, None);
        assert_eq!(root.id, mailbox_id_for_news_root());
    }

    #[test]
    fn news_root_id_is_stable() {
        assert_eq!(mailbox_id_for_news_root(), mailbox_id_for_news_root());
    }

    #[test]
    fn news_root_id_differs_from_any_group_id() {
        let root_id = mailbox_id_for_news_root();
        // News root sentinel "__news_root__" is not a valid group name, so no
        // collision with real groups is expected.
        for group in &["comp.lang.rust", "alt.test", "news.admin.announce"] {
            assert_ne!(
                mailbox_id_for_group(group),
                root_id,
                "news root id must not collide with group id for {group}"
            );
        }
    }
}
