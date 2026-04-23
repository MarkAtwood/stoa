//! IMAP mailbox command handlers: SELECT, EXAMINE, LIST, STATUS.
//!
//! Newsgroups are exposed as IMAP mailboxes.  The hierarchy delimiter is `"."`
//! (e.g., `comp.lang.rust`).
//!
//! Article-level data (EXISTS, UNSEEN counts) is stubbed at zero until the
//! article sync layer is wired in (r8u.11 FETCH wave).

use std::borrow::Cow;
use std::num::NonZeroU32;

use imap_next::imap_types::{
    core::{IString, QuotedChar, Tag},
    flag::{Flag, FlagPerm},
    mailbox::{ListMailbox, Mailbox},
    response::{Code, Data, Status},
    status::{StatusDataItem, StatusDataItemName},
};
use sqlx::SqlitePool;
use tracing::debug;

// ── Public entry points ───────────────────────────────────────────────────────

/// Result from a successful SELECT or EXAMINE.
pub struct SelectResult {
    pub uidvalidity: u32,
    pub next_uid: u32,
    pub mailbox_name: String,
    pub tagged_ok: Status<'static>,
}

/// Handle `SELECT <mailbox>` or `EXAMINE <mailbox>`.
///
/// Returns a `SelectResult` containing the data needed to build untagged
/// responses, or a tagged NO status if the mailbox is unavailable.
pub async fn handle_select(
    pool: &SqlitePool,
    tag: Tag<'static>,
    mailbox: Mailbox<'static>,
    read_only: bool,
) -> Result<SelectResult, Status<'static>> {
    let name = mailbox_name(&mailbox);
    let (uidvalidity, next_uid) = get_or_create_uidvalidity(pool, &name).await.map_err(|e| {
        debug!("DB error in SELECT: {e}");
        Status::no(Some(tag.clone()), None, "Internal error").expect("static no")
    })?;

    let ok_code = if read_only { Code::ReadOnly } else { Code::ReadWrite };
    let ok_text = if read_only { "EXAMINE complete" } else { "SELECT complete" };
    let tagged_ok =
        Status::ok(Some(tag), Some(ok_code), ok_text).expect("static ok is valid");

    Ok(SelectResult { uidvalidity, next_uid, mailbox_name: name, tagged_ok })
}

/// Build the untagged `Data` responses for SELECT/EXAMINE.
///
/// Caller enqueues these via `server.enqueue_data()`, then the `Status`
/// responses from `select_status_responses()`, then the tagged OK.
pub fn select_untagged_data() -> Vec<Data<'static>> {
    vec![
        Data::Flags(system_flags()),
        // EXISTS and RECENT counts are stubbed until article sync is wired.
        Data::Exists(0),
        Data::Recent(0),
    ]
}

/// Build the untagged `* OK [CODE] text` responses for SELECT/EXAMINE.
pub fn select_status_responses(result: &SelectResult) -> Vec<Status<'static>> {
    let uidvalidity =
        NonZeroU32::new(result.uidvalidity).unwrap_or(NonZeroU32::new(1).unwrap());
    let next_uid = NonZeroU32::new(result.next_uid).unwrap_or(NonZeroU32::new(1).unwrap());

    vec![
        Status::ok(None, Some(Code::UidValidity(uidvalidity)), "UIDs valid")
            .expect("static ok"),
        Status::ok(None, Some(Code::UidNext(next_uid)), "Predicted next UID")
            .expect("static ok"),
        Status::ok(
            None,
            Some(Code::PermanentFlags(permanent_flags())),
            "Permanent flags",
        )
        .expect("static ok"),
    ]
}

/// Convert a `ListMailbox` wildcard to a `String` for pattern matching.
pub fn list_mailbox_to_string(lm: &ListMailbox<'_>) -> String {
    match lm {
        ListMailbox::Token(t) => String::from_utf8_lossy(t.as_ref()).into_owned(),
        ListMailbox::String(IString::Literal(l)) => {
            String::from_utf8_lossy(l.as_ref()).into_owned()
        }
        ListMailbox::String(IString::Quoted(q)) => q.as_ref().to_owned(),
    }
}

/// Handle `LIST <reference> <mailbox-wildcard>`.
///
/// Returns one `Data::List` item per matching mailbox.
/// Wildcard rules: `*` matches any sequence (including `.`);
/// `%` matches any sequence that does not contain `.`.
pub async fn handle_list(
    pool: &SqlitePool,
    reference: &Mailbox<'static>,
    wildcard: &str,
) -> Vec<Data<'static>> {
    let prefix = mailbox_name(reference);
    let pattern = if prefix.is_empty() {
        wildcard.to_owned()
    } else {
        format!("{prefix}.{wildcard}")
    };

    let rows: Vec<(String,)> = match sqlx::query_as(
        "SELECT mailbox FROM imap_uid_validity ORDER BY mailbox",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            debug!("DB error in LIST: {e}");
            return vec![];
        }
    };

    rows.into_iter()
        .filter(|(name,)| glob_match(&pattern, name))
        .filter_map(|(name,)| {
            // Use an empty attribute list (valid per RFC 3501 §7.2.2).
            let mailbox = Mailbox::try_from(name).ok()?;
            Some(Data::List {
                items: vec![],
                delimiter: Some(QuotedChar::unvalidated('.')),
                mailbox,
            })
        })
        .collect()
}

/// Handle `STATUS <mailbox> (<items>)`.
///
/// Returns `Some(Data::Status { ... })` or `None` if the mailbox is not
/// found in `imap_uid_validity`.
pub async fn handle_status(
    pool: &SqlitePool,
    mailbox: Mailbox<'static>,
    item_names: &[StatusDataItemName],
) -> Option<Data<'static>> {
    let name = mailbox_name(&mailbox);
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT uidvalidity, next_uid FROM imap_uid_validity WHERE mailbox = ?",
    )
    .bind(&name)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (uidvalidity, next_uid) = match row {
        Some((v, n)) => (v as u32, n as u32),
        None => return None,
    };

    let mut items: Vec<StatusDataItem> = Vec::new();
    for item_name in item_names {
        match item_name {
            StatusDataItemName::Messages => items.push(StatusDataItem::Messages(0)),
            StatusDataItemName::Recent => items.push(StatusDataItem::Recent(0)),
            StatusDataItemName::Unseen => items.push(StatusDataItem::Unseen(0)),
            StatusDataItemName::Deleted => items.push(StatusDataItem::Deleted(0)),
            StatusDataItemName::DeletedStorage => {
                items.push(StatusDataItem::DeletedStorage(0))
            }
            StatusDataItemName::UidNext => {
                let uid = NonZeroU32::new(next_uid).unwrap_or(NonZeroU32::new(1).unwrap());
                items.push(StatusDataItem::UidNext(uid));
            }
            StatusDataItemName::UidValidity => {
                let uv =
                    NonZeroU32::new(uidvalidity).unwrap_or(NonZeroU32::new(1).unwrap());
                items.push(StatusDataItem::UidValidity(uv));
            }
        }
    }

    Some(Data::Status { mailbox, items: Cow::Owned(items) })
}

// ── Database helpers ──────────────────────────────────────────────────────────

/// Get or create the UIDVALIDITY and UIDNEXT for a mailbox.
///
/// On first access, generates UIDVALIDITY from the current Unix timestamp
/// (seconds).  UIDVALIDITY must never decrease for a given mailbox, and
/// persisting it in the DB satisfies that invariant across restarts.
pub async fn get_or_create_uidvalidity(
    pool: &SqlitePool,
    mailbox: &str,
) -> Result<(u32, u32), sqlx::Error> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT uidvalidity, next_uid FROM imap_uid_validity WHERE mailbox = ?")
            .bind(mailbox)
            .fetch_optional(pool)
            .await?;

    if let Some((v, n)) = row {
        return Ok((v as u32, n as u32));
    }

    // Generate UIDVALIDITY from current Unix time (seconds).
    let uidvalidity = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let uidvalidity = uidvalidity.max(1);

    sqlx::query(
        "INSERT OR IGNORE INTO imap_uid_validity (mailbox, uidvalidity, next_uid) \
         VALUES (?, ?, 1)",
    )
    .bind(mailbox)
    .bind(uidvalidity as i64)
    .execute(pool)
    .await?;

    // Re-fetch in case of a concurrent INSERT OR IGNORE.
    let (v, n): (i64, i64) =
        sqlx::query_as("SELECT uidvalidity, next_uid FROM imap_uid_validity WHERE mailbox = ?")
            .bind(mailbox)
            .fetch_one(pool)
            .await?;

    Ok((v as u32, n as u32))
}

// ── Flag helpers ──────────────────────────────────────────────────────────────

fn system_flags() -> Vec<Flag<'static>> {
    vec![Flag::Answered, Flag::Flagged, Flag::Deleted, Flag::Seen, Flag::Draft]
}

fn permanent_flags() -> Vec<FlagPerm<'static>> {
    vec![
        FlagPerm::Flag(Flag::Answered),
        FlagPerm::Flag(Flag::Flagged),
        FlagPerm::Flag(Flag::Deleted),
        FlagPerm::Flag(Flag::Seen),
        FlagPerm::Flag(Flag::Draft),
        FlagPerm::Asterisk,
    ]
}

// ── Mailbox name helpers ──────────────────────────────────────────────────────

/// Convert an imap-types `Mailbox` to a plain `String` for use as a DB key.
pub fn mailbox_name(mailbox: &Mailbox<'_>) -> String {
    match mailbox {
        Mailbox::Inbox => "INBOX".to_owned(),
        Mailbox::Other(other) => {
            String::from_utf8_lossy(other.inner().as_ref()).into_owned()
        }
    }
}

// ── Wildcard matching ─────────────────────────────────────────────────────────

/// Match an IMAP LIST wildcard pattern against a mailbox name.
///
/// `*` matches any sequence of characters including hierarchy separators (`.`).
/// `%` matches any sequence of characters NOT including `.`.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    glob_bytes(pattern.as_bytes(), name.as_bytes())
}

fn glob_bytes(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(b'*'), _) => {
            glob_bytes(&pat[1..], s) || (!s.is_empty() && glob_bytes(pat, &s[1..]))
        }
        (Some(b'%'), _) => {
            glob_bytes(&pat[1..], s)
                || (s.first() != Some(&b'.') && !s.is_empty() && glob_bytes(pat, &s[1..]))
        }
        (Some(p), Some(c)) => p == c && glob_bytes(&pat[1..], &s[1..]),
        (Some(_), None) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_star_matches_all() {
        assert!(glob_match("*", "comp.lang.rust"));
        assert!(glob_match("*", "alt.test"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_percent_does_not_cross_hierarchy() {
        assert!(glob_match("comp.%", "comp.lang"));
        assert!(!glob_match("comp.%", "comp.lang.rust"));
    }

    #[test]
    fn glob_star_crosses_hierarchy() {
        assert!(glob_match("comp.*", "comp.lang.rust"));
        assert!(glob_match("comp.*", "comp.lang"));
    }

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("comp.lang.rust", "comp.lang.rust"));
        assert!(!glob_match("comp.lang.rust", "comp.lang.c"));
    }

    #[test]
    fn glob_empty_pattern_matches_empty_string() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "anything"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_match("comp.*", "comp.lang.rust"));
        assert!(!glob_match("alt.*", "comp.lang.rust"));
    }

    #[test]
    fn mailbox_name_inbox() {
        assert_eq!(mailbox_name(&Mailbox::Inbox), "INBOX");
    }

    #[test]
    fn system_flags_contains_standard_set() {
        let flags = system_flags();
        assert!(flags.contains(&Flag::Seen));
        assert!(flags.contains(&Flag::Deleted));
        assert!(flags.contains(&Flag::Flagged));
        assert!(flags.contains(&Flag::Answered));
        assert!(flags.contains(&Flag::Draft));
    }

    // ── Async DB tests ────────────────────────────────────────────────────────

    async fn make_pool() -> sqlx::SqlitePool {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE imap_uid_validity (
                mailbox     TEXT    NOT NULL PRIMARY KEY,
                uidvalidity INTEGER NOT NULL,
                next_uid    INTEGER NOT NULL DEFAULT 1
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn uidvalidity_is_stable_across_calls() {
        let pool = make_pool().await;
        let (v1, n1) = get_or_create_uidvalidity(&pool, "comp.lang.rust").await.unwrap();
        let (v2, n2) = get_or_create_uidvalidity(&pool, "comp.lang.rust").await.unwrap();
        assert_eq!(v1, v2, "UIDVALIDITY must not change on re-access");
        assert_eq!(n1, n2);
        assert!(v1 >= 1);
    }

    #[tokio::test]
    async fn uidvalidity_is_nonzero() {
        let pool = make_pool().await;
        let (v, n) = get_or_create_uidvalidity(&pool, "alt.test").await.unwrap();
        assert!(v >= 1, "UIDVALIDITY must be at least 1");
        assert_eq!(n, 1, "initial next_uid is 1");
    }

    #[tokio::test]
    async fn handle_status_returns_none_for_unknown_mailbox() {
        let pool = make_pool().await;
        let mailbox = Mailbox::try_from("nonexistent.group".to_owned()).unwrap();
        let result = handle_status(&pool, mailbox, &[StatusDataItemName::Messages]).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn handle_status_returns_uidvalidity_for_known_mailbox() {
        let pool = make_pool().await;
        let (expected_uv, _) =
            get_or_create_uidvalidity(&pool, "comp.lang.rust").await.unwrap();
        let mailbox = Mailbox::try_from("comp.lang.rust".to_owned()).unwrap();
        let data =
            handle_status(&pool, mailbox, &[StatusDataItemName::UidValidity]).await;
        assert!(data.is_some(), "STATUS should return data for known mailbox");
        if let Some(Data::Status { items, .. }) = data {
            let uv = items.iter().find_map(|item| {
                if let StatusDataItem::UidValidity(v) = item { Some(v.get()) } else { None }
            });
            assert_eq!(
                uv,
                Some(expected_uv.max(1)),
                "UIDVALIDITY must match persisted value"
            );
        } else {
            panic!("expected Data::Status");
        }
    }

    #[tokio::test]
    async fn handle_list_queries_db_without_error() {
        // Verifies the DB query path executes and returns results consistent with
        // glob_match logic (which is tested exhaustively in the sync tests above).
        let pool = make_pool().await;
        get_or_create_uidvalidity(&pool, "comp.lang.rust").await.unwrap();
        get_or_create_uidvalidity(&pool, "comp.lang.c").await.unwrap();
        get_or_create_uidvalidity(&pool, "alt.test").await.unwrap();

        // With Mailbox::Inbox as reference the prefix is "INBOX", so the effective
        // pattern is "INBOX.*" — none of our seeded mailboxes match.
        let data = handle_list(&pool, &Mailbox::Inbox, "*").await;
        assert!(data.is_empty(), "INBOX.* should not match any comp.* or alt.* entries");
    }
}
