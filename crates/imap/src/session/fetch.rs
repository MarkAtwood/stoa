//! IMAP FETCH, STORE, SEARCH, EXPUNGE, and CLOSE command handlers.
//!
//! Article-level data is stubbed: the mailbox always has 0 messages (EXISTS=0),
//! so FETCH/STORE/SEARCH return empty results and EXPUNGE produces no untagged
//! responses.

use imap_next::imap_types::{
    core::Tag,
    flag::{Flag, StoreResponse, StoreType},
    response::{Data, Status},
    sequence::SequenceSet,
};
use sqlx::SqlitePool;
use tracing::debug;

/// Handle `FETCH <sequence-set> <items>`.
///
/// With 0 messages (EXISTS=0) any sequence set is vacuously empty — return
/// tagged OK with no message data items.
pub fn handle_fetch(tag: Tag<'static>) -> Status<'static> {
    Status::ok(Some(tag), None, "FETCH complete").expect("static ok")
}

/// Handle `SEARCH [CHARSET x] <criteria>`.
///
/// Returns `* SEARCH` (empty result list) + tagged OK.
pub fn handle_search(tag: Tag<'static>, uid: bool) -> (Data<'static>, Status<'static>) {
    let data = Data::Search(vec![]);
    let text = if uid {
        "UID SEARCH complete"
    } else {
        "SEARCH complete"
    };
    let ok = Status::ok(Some(tag), None, text).expect("static ok");
    (data, ok)
}

/// Handle `STORE <sequence-set> [+/-]FLAGS[.SILENT] (<flags>)`.
///
/// With 0 messages the sequence set matches nothing so flag storage is a
/// no-op.  Returns tagged OK with no `* n FETCH (FLAGS ...)` untagged data.
#[allow(clippy::too_many_arguments)]
pub async fn handle_store(
    _pool: &SqlitePool,
    _username: &str,
    _mailbox: &str,
    tag: Tag<'static>,
    _sequence_set: &SequenceSet,
    _kind: StoreType,
    _response: StoreResponse,
    _flags: &[Flag<'static>],
    _uid: bool,
) -> Status<'static> {
    debug!("STORE no-op (0 messages in mailbox)");
    Status::ok(Some(tag), None, "STORE complete").expect("static ok")
}

#[cfg(test)]
mod tests {
    use super::*;

    use imap_next::imap_types::{
        core::Tag,
        response::{StatusKind, Tagged},
    };

    fn make_tag(s: &'static str) -> Tag<'static> {
        Tag::unvalidated(s)
    }

    fn is_tagged_ok(status: &Status<'static>) -> bool {
        matches!(status, Status::Tagged(Tagged { body, .. }) if body.kind == StatusKind::Ok)
    }

    #[test]
    fn handle_fetch_returns_ok() {
        let status = handle_fetch(make_tag("A001"));
        assert!(is_tagged_ok(&status));
    }

    #[test]
    fn handle_search_returns_empty_data_and_ok() {
        let (data, status) = handle_search(make_tag("A002"), false);
        assert!(matches!(data, Data::Search(ref v) if v.is_empty()));
        assert!(is_tagged_ok(&status));
    }

    #[test]
    fn handle_search_uid_returns_ok() {
        let (data, status) = handle_search(make_tag("A003"), true);
        assert!(matches!(data, Data::Search(ref v) if v.is_empty()));
        assert!(is_tagged_ok(&status));
    }
}
