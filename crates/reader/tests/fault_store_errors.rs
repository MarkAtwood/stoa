//! Fault injection tests for reader command handlers.
//!
//! Tests that correct NNTP error codes are returned when storage operations
//! fail or return no data. The handlers are pure functions — no mock storage
//! needed. Each test corresponds to an RFC 3977 error path that the session
//! layer would hit when a storage lookup returns nothing or fails.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use usenet_ipfs_reader::session::{
    commands::{
        fetch::{
            article_response, body_response, head_response, no_group_selected, no_such_msgid,
            no_such_number, ArticleContent,
        },
        group::{group_select, last_article, next_article, stat_article, GroupData},
        list::{list_active, list_newsgroups, newgroups, newnews, GroupInfo},
        post::complete_post,
    },
    context::SessionContext,
    response::Response,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn peer_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 119)
}

fn active_ctx() -> SessionContext {
    SessionContext::new(peer_addr(), false, true, false)
}

fn make_group(name: &str, numbers: Vec<u64>) -> GroupData {
    let low = numbers.first().copied().unwrap_or(1);
    let high = numbers.last().copied().unwrap_or(0);
    GroupData {
        name: name.into(),
        count: numbers.len() as u64,
        low,
        high,
        article_numbers: numbers,
    }
}

/// Format a Unix timestamp (seconds) as an RFC 2822 date string.
fn epoch_to_rfc2822(secs: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let s = secs;
    let sec = (s % 60) as u32;
    let min = ((s / 60) % 60) as u32;
    let hour = ((s / 3600) % 24) as u32;
    let days_since_epoch = s / 86400;
    let wday = ((days_since_epoch % 7 + 7) % 7) as usize;
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[wday],
        d,
        MONTHS[(m - 1) as usize],
        y,
        hour,
        min,
        sec
    )
}

/// Build a minimal RFC 5536-compliant article with the given optional headers.
/// Always includes Subject, a current-time Date, and Message-ID.
/// Pass `newsgroups` and `from` as `Some(value)` to include them.
fn make_article(newsgroups: Option<&str>, from: Option<&str>) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let date_str = epoch_to_rfc2822(now);
    let mut out = String::new();
    if let Some(ng) = newsgroups {
        out.push_str(&format!("Newsgroups: {ng}\r\n"));
    }
    if let Some(f) = from {
        out.push_str(&format!("From: {f}\r\n"));
    }
    out.push_str("Subject: test\r\n");
    out.push_str(&format!("Date: {date_str}\r\n"));
    out.push_str("Message-ID: <test@example.com>\r\n");
    out.push_str("\r\n");
    out.push_str("Body text.\r\n");
    out.into_bytes()
}

// ── fetch error paths ─────────────────────────────────────────────────────────

/// When a message-ID lookup returns no result (article not in IPFS / not in
/// the msgid map), the handler must respond 430 per RFC 3977 §6.2.1.
#[test]
fn article_not_found_by_msgid_returns_430() {
    let resp = no_such_msgid();
    assert_eq!(
        resp.code, 430,
        "RFC 3977 §6.2.1: unknown message-ID must yield 430"
    );
}

/// When a local article-number lookup returns no row (e.g. SQLite returns
/// zero rows for the requested (group, number) pair), the handler must
/// respond 423 per RFC 3977 §6.2.1.
#[test]
fn article_not_found_by_number_returns_423() {
    let resp = no_such_number();
    assert_eq!(
        resp.code, 423,
        "RFC 3977 §6.2.1: no article with that number must yield 423"
    );
}

/// When the client issues ARTICLE/HEAD/BODY with a bare number but has not
/// yet selected a group (e.g. GROUP lookup returned empty), the handler
/// must respond 412 per RFC 3977 §6.1.1.
#[test]
fn article_fetch_without_group_returns_412() {
    let resp = no_group_selected();
    assert_eq!(
        resp.code, 412,
        "RFC 3977 §6.1.1: no group selected must yield 412"
    );
}

/// The 430 response must contain only a single-line status (no body lines).
/// A multi-line 430 would confuse newsreader clients expecting single-line.
#[test]
fn no_such_msgid_is_single_line() {
    let resp = no_such_msgid();
    assert!(
        resp.body.is_empty(),
        "430 response must be single-line per RFC 3977 §3.2"
    );
}

/// The 423 response must be single-line.
#[test]
fn no_such_number_is_single_line() {
    let resp = no_such_number();
    assert!(
        resp.body.is_empty(),
        "423 response must be single-line per RFC 3977 §3.2"
    );
}

/// The 412 response must be single-line.
#[test]
fn no_group_selected_is_single_line() {
    let resp = no_group_selected();
    assert!(
        resp.body.is_empty(),
        "412 response must be single-line per RFC 3977 §3.2"
    );
}

/// A successful ARTICLE fetch must return 220.  Verifying the success path
/// alongside the error paths confirms the handler switches correctly.
#[test]
fn article_response_on_success_returns_220() {
    let content = ArticleContent {
        article_number: 1,
        message_id: "<test@example.com>".to_string(),
        header_bytes: b"Subject: Test\r\nFrom: a@b.com".to_vec(),
        body_bytes: b"Hello world.\r\n".to_vec(),
        cid: None,
    };
    let resp = article_response(&content);
    assert_eq!(
        resp.code, 220,
        "RFC 3977 §6.2.1: successful ARTICLE must yield 220"
    );
    // RFC 3977 §6.2.1: status line is "220 n <msgid> Article follows".
    assert_eq!(
        resp.text, "1 <test@example.com> Article follows",
        "status line must carry article number and message-id"
    );
    assert!(resp.multiline, "ARTICLE response must be multiline");
    // Body must contain headers, blank separator, then body text.
    assert!(
        resp.body.contains(&"Subject: Test".to_string()),
        "body must include headers"
    );
    let blank_pos = resp.body.iter().position(|l| l.is_empty());
    let body_pos = resp.body.iter().position(|l| l.contains("Hello world."));
    assert!(blank_pos.is_some(), "body must have blank line separating headers from body");
    assert!(body_pos.is_some(), "body must include body text");
    assert!(
        blank_pos.unwrap() < body_pos.unwrap(),
        "blank line must appear before body text"
    );
}

/// HEAD succeeds with 221; confirms the branch taken when storage delivers data.
#[test]
fn head_response_on_success_returns_221() {
    let content = ArticleContent {
        article_number: 2,
        message_id: "<head@example.com>".to_string(),
        header_bytes: b"Subject: Head Test".to_vec(),
        body_bytes: b"".to_vec(),
        cid: None,
    };
    let resp = head_response(&content);
    assert_eq!(
        resp.code, 221,
        "RFC 3977 §6.2.2: successful HEAD must yield 221"
    );
    // RFC 3977 §6.2.2: status line is "221 n <msgid> Headers follow".
    assert_eq!(
        resp.text, "2 <head@example.com> Headers follow",
        "status line must carry article number and message-id"
    );
    assert!(resp.multiline, "HEAD response must be multiline");
    // HEAD body contains only headers — no blank line, no body text.
    assert!(
        resp.body.contains(&"Subject: Head Test".to_string()),
        "body must include header line"
    );
    assert!(
        !resp.body.iter().any(|l| l.is_empty()),
        "HEAD response body must not contain a blank line (no body section)"
    );
}

/// BODY succeeds with 222; confirms the branch taken when storage delivers data.
#[test]
fn body_response_on_success_returns_222() {
    let content = ArticleContent {
        article_number: 3,
        message_id: "<body@example.com>".to_string(),
        header_bytes: b"Subject: Body Test".to_vec(),
        body_bytes: b"Body text.\r\n".to_vec(),
        cid: None,
    };
    let resp = body_response(&content);
    assert_eq!(
        resp.code, 222,
        "RFC 3977 §6.2.3: successful BODY must yield 222"
    );
    // RFC 3977 §6.2.3: status line is "222 n <msgid> Body follows".
    assert_eq!(
        resp.text, "3 <body@example.com> Body follows",
        "status line must carry article number and message-id"
    );
    assert!(resp.multiline, "BODY response must be multiline");
    // BODY response contains only body text — no headers.
    assert!(
        resp.body.contains(&"Body text.".to_string()),
        "body must include body text"
    );
    assert!(
        !resp.body.iter().any(|l| l.contains("Subject:")),
        "BODY response must not contain headers"
    );
}

// ── group command error paths ─────────────────────────────────────────────────

/// When the group-metadata lookup finds no row (storage failure or unknown
/// group name), GROUP must return 411 per RFC 3977 §6.1.1.
#[test]
fn group_select_unknown_group_returns_411() {
    let mut ctx = active_ctx();
    let resp = group_select(&mut ctx, None); // None simulates a storage miss
    assert_eq!(
        resp.code, 411,
        "RFC 3977 §6.1.1: no such newsgroup must yield 411"
    );
}

/// After GROUP succeeds, the session is in GroupSelected state and the
/// response code is 211.  This validates the positive branch.
#[test]
fn group_select_known_group_returns_211() {
    let mut ctx = active_ctx();
    let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
    let resp = group_select(&mut ctx, Some(&gd));
    assert_eq!(
        resp.code, 211,
        "RFC 3977 §6.1.1: successful GROUP must yield 211"
    );
}

/// An empty group (no articles stored yet) must still return 211 with
/// count=0.  Storage returning an empty article-number list is not a failure.
#[test]
fn group_select_empty_group_returns_211_with_zero_count() {
    let mut ctx = active_ctx();
    let gd = make_group("comp.test.empty", vec![]);
    let resp = group_select(&mut ctx, Some(&gd));
    assert_eq!(
        resp.code, 211,
        "RFC 3977 §6.1.1: empty group must still yield 211"
    );
    assert!(
        resp.text.starts_with("0 "),
        "count must be zero for an empty group"
    );
}

/// NEXT when no group is selected must return 412 per RFC 3977 §6.1.3.
/// This simulates the session attempting NEXT before any GROUP command.
#[test]
fn next_without_group_returns_412() {
    let mut ctx = active_ctx(); // state = Active, no group
    let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
    let resp = next_article(&mut ctx, Some(&gd));
    assert_eq!(
        resp.code, 412,
        "RFC 3977 §6.1.3: NEXT without GROUP must yield 412"
    );
}

/// NEXT when the cursor is already at the last article (or the group has no
/// articles after the current position) must return 421 per RFC 3977 §6.1.3.
#[test]
fn next_at_end_of_group_returns_421() {
    let mut ctx = active_ctx();
    let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
    group_select(&mut ctx, Some(&gd));
    ctx.current_article_number = Some(3); // already at the last article
    let resp = next_article(&mut ctx, Some(&gd));
    assert_eq!(
        resp.code, 421,
        "RFC 3977 §6.1.3: no next article must yield 421"
    );
}

/// LAST when no group is selected must return 412 per RFC 3977 §6.1.4.
#[test]
fn last_without_group_returns_412() {
    let mut ctx = active_ctx(); // state = Active, no group
    let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
    let resp = last_article(&mut ctx, Some(&gd));
    assert_eq!(
        resp.code, 412,
        "RFC 3977 §6.1.4: LAST without GROUP must yield 412"
    );
}

/// LAST at the first article must return 422 per RFC 3977 §6.1.4.
#[test]
fn last_at_beginning_of_group_returns_422() {
    let mut ctx = active_ctx();
    let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
    group_select(&mut ctx, Some(&gd));
    // After group_select the cursor is at article 1 (first).
    let resp = last_article(&mut ctx, Some(&gd));
    assert_eq!(
        resp.code, 422,
        "RFC 3977 §6.1.4: no previous article must yield 422"
    );
}

/// STAT with a number when no group is selected must return 412 per
/// RFC 3977 §6.2.4.
#[test]
fn stat_without_group_returns_412() {
    let mut ctx = active_ctx();
    let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
    let resp = stat_article(&mut ctx, Some(&gd), Some("1"));
    assert_eq!(
        resp.code, 412,
        "RFC 3977 §6.2.4: STAT number without GROUP must yield 412"
    );
}

/// STAT with a number that does not exist in the group must return 423 per
/// RFC 3977 §6.2.4.  This represents the storage returning a miss.
#[test]
fn stat_missing_number_returns_423() {
    let mut ctx = active_ctx();
    let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
    group_select(&mut ctx, Some(&gd));
    let resp = stat_article(&mut ctx, Some(&gd), Some("999"));
    assert_eq!(
        resp.code, 423,
        "RFC 3977 §6.2.4: no article with that number must yield 423"
    );
}

/// STAT with a message-ID form returns 430 (the v1 stub; message-ID lookups
/// are not yet wired to IPFS storage).
#[test]
fn stat_msgid_form_returns_430() {
    let mut ctx = active_ctx();
    let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
    group_select(&mut ctx, Some(&gd));
    let resp = stat_article(&mut ctx, Some(&gd), Some("<foo@example.com>"));
    assert_eq!(
        resp.code, 430,
        "RFC 3977 §6.2.4: STAT <msgid> with no match must yield 430"
    );
}

// ── list command error paths ──────────────────────────────────────────────────

/// LIST ACTIVE with an empty group table must return 215 with no body lines.
/// This is the correct response when the storage layer returns zero rows —
/// an empty list is valid, not an error, per RFC 3977 §7.6.3.
#[test]
fn list_active_empty_store_returns_215_with_no_lines() {
    let resp = list_active(&[], None);
    assert_eq!(
        resp.code, 215,
        "RFC 3977 §7.6.3: LIST ACTIVE must always return 215"
    );
    assert!(
        resp.body.is_empty(),
        "empty group table must produce zero body lines"
    );
}

/// LIST ACTIVE with a wildmat that matches nothing must return 215 with no
/// body lines.  Storage returned rows but the wildmat filter excluded them all.
#[test]
fn list_active_wildmat_no_match_returns_215_with_no_lines() {
    let groups = vec![GroupInfo {
        name: "comp.lang.rust".to_string(),
        high: 100,
        low: 1,
        posting_allowed: true,
        description: "Rust".to_string(),
    }];
    let resp = list_active(&groups, Some("alt.*"));
    assert_eq!(
        resp.code, 215,
        "RFC 3977 §7.6.3: LIST ACTIVE with no match must still yield 215"
    );
    assert!(
        resp.body.is_empty(),
        "wildmat that matches nothing must produce zero body lines"
    );
}

/// LIST NEWSGROUPS with an empty store must return 215 with no body lines
/// per RFC 3977 §7.6.6.
#[test]
fn list_newsgroups_empty_store_returns_215_with_no_lines() {
    let resp = list_newsgroups(&[], None);
    assert_eq!(
        resp.code, 215,
        "RFC 3977 §7.6.6: LIST NEWSGROUPS must always return 215"
    );
    assert!(resp.body.is_empty());
}

/// NEWGROUPS with an empty group table must return 231 with no body lines
/// per RFC 3977 §7.3.
#[test]
fn newgroups_empty_store_returns_231_with_no_lines() {
    let resp = newgroups(&[], 0);
    assert_eq!(resp.code, 231, "RFC 3977 §7.3: NEWGROUPS must return 231");
    assert!(resp.body.is_empty());
}

/// NEWNEWS always returns 230 with an empty body in v1 (conservative).
/// This is correct even if storage fails — we return "no new articles",
/// letting clients catch up via GROUP per RFC 3977 §7.4.
#[test]
fn newnews_returns_230_empty() {
    let resp = newnews(&[], 0, None);
    assert_eq!(resp.code, 230, "RFC 3977 §7.4: NEWNEWS must return 230");
    assert!(resp.body.is_empty());
}

// ── post validation error paths ───────────────────────────────────────────────

/// POST: article that exceeds the size limit must return 441 per RFC 3977
/// §6.3.1.  This simulates the storage-layer check rejecting an oversized
/// article before any IPFS write.
#[test]
fn post_oversized_article_returns_441() {
    let article =
        b"Newsgroups: comp.lang.rust\r\nFrom: user@example.com\r\nSubject: x\r\n\r\nbody\r\n";
    let err = complete_post(article, 1, None).unwrap_err(); // limit of 1 byte forces rejection
    assert_eq!(
        err.code, 441,
        "RFC 3977 §6.3.1: oversized article must yield 441"
    );
}

/// POST: article missing the Newsgroups header must return 441 per RFC 3977
/// §6.3.1.  The article contains all other mandatory headers (From, Date,
/// Message-ID, Subject) so that validate_post_headers reaches the Newsgroups
/// check and returns its specific error.
#[test]
fn post_missing_newsgroups_header_returns_441() {
    let article = make_article(None, Some("user@example.com"));
    let err = complete_post(&article, 1_048_576, None).unwrap_err();
    assert_eq!(
        err.code, 441,
        "RFC 3977 §6.3.1: missing Newsgroups must yield 441"
    );
    assert!(
        err.text.contains("Newsgroups"),
        "error text must identify missing header"
    );
}

/// POST: article missing the From header must return 441 per RFC 3977 §6.3.1.
#[test]
fn post_missing_from_header_returns_441() {
    let article = make_article(Some("comp.lang.rust"), None);
    let err = complete_post(&article, 1_048_576, None).unwrap_err();
    assert_eq!(
        err.code, 441,
        "RFC 3977 §6.3.1: missing From must yield 441"
    );
    assert!(
        err.text.contains("From"),
        "error text must identify missing header"
    );
}

/// POST: valid article with all required RFC 5536 headers and within size
/// limit must be accepted.
#[test]
fn post_valid_article_returns_240() {
    let article = make_article(Some("comp.lang.rust"), Some("user@example.com"));
    assert!(
        complete_post(&article, 1_048_576, None).is_ok(),
        "RFC 3977 §6.3.1: valid POST must pass validation"
    );
}

// ── Response builder — storage-failure-mapped codes ──────────────────────────

/// When a storage operation fails fatally (e.g. SQLite connection lost,
/// IPFS node unreachable), the session layer returns 503 Program fault.
/// Verify the Response builder produces the correct code.
#[test]
fn program_fault_response_is_503() {
    let resp = Response::program_fault();
    assert_eq!(
        resp.code, 503,
        "RFC 3977 §3.2: unrecoverable server fault must yield 503"
    );
}

/// Service temporarily unavailable (e.g. storage backend starting up) maps
/// to 400 per RFC 3977 §3.2.
#[test]
fn service_unavailable_response_is_400() {
    let resp = Response::service_unavailable();
    assert_eq!(
        resp.code, 400,
        "RFC 3977 §3.2: temporary unavailability must yield 400"
    );
}

/// Posting failed (e.g. IPFS write error after article validation passed)
/// maps to 441 per RFC 3977 §6.3.1.
#[test]
fn posting_failed_response_is_441() {
    let resp = Response::posting_failed();
    assert_eq!(
        resp.code, 441,
        "RFC 3977 §6.3.1: post failure must yield 441"
    );
}
