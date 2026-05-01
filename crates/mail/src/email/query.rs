use cid::Cid;
use serde_json::{json, Value};

/// Parse a date string to a Unix timestamp (seconds).
///
/// Tries RFC 2822 first (the format used in NNTP Date: headers,
/// e.g. "Mon, 01 Jan 2024 00:00:00 +0000"), then falls back to RFC 3339
/// (used in JMAP filter arguments, e.g. "2024-01-01T00:00:00Z").
/// Returns None if both formats fail.
fn parse_date_timestamp(date_str: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(date_str)
        .ok()
        .or_else(|| chrono::DateTime::parse_from_rfc3339(date_str).ok())
        .map(|dt| dt.timestamp())
}

/// Maximum number of results returned by a single Email/query call.
///
/// Caps the client-supplied `limit` parameter to prevent silent truncation
/// when converting a large u64 to usize and to bound memory usage.
pub const MAX_FETCH_LIMIT: u64 = 10_000;

/// An overview record enriched with its CID.
pub struct EmailOverviewEntry {
    pub cid: Cid,
    pub message_id: String,
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
///   - `text`: String — full-text search; caller must resolve to message-IDs
///     and pass them in `text_search_results`
///
/// `entries` is all emails in the target mailbox, pre-fetched by the caller.
/// The caller is responsible for filtering to the right group.
///
/// `text_search_results` is `Some(set)` when the filter contains a `text`
/// field and the caller has already executed a full-text search.  Only entries
/// whose `message_id` appears in the set are kept.  `None` means no text
/// filter is active (all entries pass this check).
///
/// `state` is the current JMAP Email query state string from StateStore.
///
/// Returns JMAP QueryResponse.
pub fn handle_email_query(
    entries: &[EmailOverviewEntry],
    filter: Option<&Value>,
    position: u64,
    limit: Option<u64>,
    state: &str,
    text_search_results: Option<std::collections::HashSet<String>>,
    account_id: &str,
) -> Value {
    let mut filtered: Vec<&EmailOverviewEntry> = entries.iter().collect();

    if let Some(f) = filter {
        if let Some(after) = f.get("after").and_then(|v| v.as_str()) {
            if let Some(after_ts) = parse_date_timestamp(after) {
                // map_or(true, ...): articles with unparseable dates pass the filter.
                // Policy: prefer false negatives (include ambiguous) over false positives (drop valid).
                filtered.retain(|e| parse_date_timestamp(&e.date).map_or(true, |ts| ts > after_ts));
            }
        }
        if let Some(before) = f.get("before").and_then(|v| v.as_str()) {
            if let Some(before_ts) = parse_date_timestamp(before) {
                // Same policy: unparseable-date articles pass the before filter.
                filtered
                    .retain(|e| parse_date_timestamp(&e.date).map_or(true, |ts| ts < before_ts));
            }
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

    if let Some(ref id_set) = text_search_results {
        filtered.retain(|e| id_set.contains(&e.message_id));
    }

    // Pre-compute timestamps once, then sort — avoids O(N log N) repeated parses.
    let mut with_ts: Vec<(i64, &EmailOverviewEntry)> = filtered
        .iter()
        .map(|e| (parse_date_timestamp(&e.date).unwrap_or(i64::MIN), *e))
        .collect();
    with_ts.sort_by(|(ta, _), (tb, _)| tb.cmp(ta));

    let total = with_ts.len() as u64;

    let start = position as usize;
    let capped_limit = limit.unwrap_or(MAX_FETCH_LIMIT).min(MAX_FETCH_LIMIT) as usize;
    let page: Vec<Value> = with_ts
        .iter()
        .skip(start)
        .take(capped_limit)
        .map(|(_, e)| Value::String(e.cid.to_string()))
        .collect();

    json!({
        "accountId": account_id,
        "queryState": state,
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
                message_id: "<article-a@example.com>".to_string(),
                subject: "Rust is great".to_string(),
                from: "alice@example.com".to_string(),
                date: "2026-04-01T10:00:00Z".to_string(),
                byte_count: 100,
            },
            EmailOverviewEntry {
                cid: test_cid(b"article-b"),
                message_id: "<article-b@example.com>".to_string(),
                subject: "Testing JMAP".to_string(),
                from: "bob@example.com".to_string(),
                date: "2026-04-02T10:00:00Z".to_string(),
                byte_count: 200,
            },
            EmailOverviewEntry {
                cid: test_cid(b"article-c"),
                message_id: "<article-c@example.com>".to_string(),
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
        let resp = handle_email_query(&entries, None, 0, None, "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 3);
        // Newest first: article-c (2026-04-03) > article-b (2026-04-02) > article-a (2026-04-01)
        assert_eq!(ids[0].as_str().unwrap(), test_cid(b"article-c").to_string());
        assert_eq!(ids[2].as_str().unwrap(), test_cid(b"article-a").to_string());
    }

    #[test]
    fn filter_by_subject_substring() {
        let entries = make_entries();
        let filter = json!({"subject": "rust"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None, "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(
            ids.len(),
            2,
            "Should match 'Rust is great' and 'Another Rust post'"
        );
    }

    #[test]
    fn filter_by_from() {
        let entries = make_entries();
        let filter = json!({"from": "bob"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None, "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].as_str().unwrap(), test_cid(b"article-b").to_string());
    }

    #[test]
    fn filter_after_date() {
        let entries = make_entries();
        let filter = json!({"after": "2026-04-01T20:00:00Z"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None, "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(
            ids.len(),
            2,
            "Should return articles from 2026-04-02 and 2026-04-03"
        );
    }

    #[test]
    fn filter_before_date() {
        let entries = make_entries();
        let filter = json!({"before": "2026-04-02T20:00:00Z"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None, "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(
            ids.len(),
            2,
            "Should return articles from 2026-04-01 and 2026-04-02"
        );
    }

    /// Verify that the date filter actually rejects articles when the OverviewRecord
    /// date field contains RFC 2822 format (the real format from NNTP Date: headers).
    /// Before the fix, parse_date_timestamp used only RFC 3339 and silently
    /// passed all articles through via the map_or(true, …) fallback.
    #[test]
    fn filter_date_rejects_rfc2822_articles_outside_range() {
        // These entries have RFC 2822 dates, as they would come from NNTP headers.
        let entries = vec![
            EmailOverviewEntry {
                cid: test_cid(b"rfc2822-a"),
                message_id: "<rfc2822-a@example.com>".to_string(),
                subject: "Early article".to_string(),
                from: "a@example.com".to_string(),
                // RFC 2822: 2024-01-01 00:00:00 UTC
                date: "Mon, 01 Jan 2024 00:00:00 +0000".to_string(),
                byte_count: 100,
            },
            EmailOverviewEntry {
                cid: test_cid(b"rfc2822-b"),
                message_id: "<rfc2822-b@example.com>".to_string(),
                subject: "Later article".to_string(),
                from: "b@example.com".to_string(),
                // RFC 2822: 2024-06-15 12:00:00 UTC
                date: "Sat, 15 Jun 2024 12:00:00 +0000".to_string(),
                byte_count: 200,
            },
            EmailOverviewEntry {
                cid: test_cid(b"rfc2822-c"),
                message_id: "<rfc2822-c@example.com>".to_string(),
                subject: "Last article".to_string(),
                from: "c@example.com".to_string(),
                // RFC 2822: 2024-12-31 23:59:59 UTC
                date: "Tue, 31 Dec 2024 23:59:59 +0000".to_string(),
                byte_count: 300,
            },
        ];

        // after: 2024-06-01 (RFC 3339 as used in JMAP filter) — should keep b and c only.
        let filter = json!({"after": "2024-06-01T00:00:00Z"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None, "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(
            ids.len(),
            2,
            "after filter must reject the January article; got {ids:?}"
        );
        let returned: Vec<String> = ids
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(
            !returned.contains(&test_cid(b"rfc2822-a").to_string()),
            "early article must be excluded by after filter"
        );

        // before: 2024-06-30 — should keep a and b only.
        let filter2 = json!({"before": "2024-06-30T00:00:00Z"});
        let resp2 = handle_email_query(&entries, Some(&filter2), 0, None, "0", None, "test");
        let ids2 = resp2["ids"].as_array().unwrap();
        assert_eq!(
            ids2.len(),
            2,
            "before filter must reject the December article; got {ids2:?}"
        );
        let returned2: Vec<String> = ids2
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(
            !returned2.contains(&test_cid(b"rfc2822-c").to_string()),
            "late article must be excluded by before filter"
        );
    }

    #[test]
    fn sort_uses_timestamp_not_lexicographic() {
        // Dates with different timezone offsets that sort differently lexicographically vs by value.
        // 2026-04-01T23:00:00+05:00 = 2026-04-01T18:00:00Z (earlier)
        // 2026-04-01T20:00:00Z (later)
        let entries = vec![
            EmailOverviewEntry {
                cid: test_cid(b"tz-a"),
                message_id: "<tz-a@example.com>".to_string(),
                subject: "TZ test A".to_string(),
                from: "a@example.com".to_string(),
                date: "2026-04-01T23:00:00+05:00".to_string(),
                byte_count: 100,
            },
            EmailOverviewEntry {
                cid: test_cid(b"tz-b"),
                message_id: "<tz-b@example.com>".to_string(),
                subject: "TZ test B".to_string(),
                from: "b@example.com".to_string(),
                date: "2026-04-01T20:00:00Z".to_string(),
                byte_count: 200,
            },
        ];
        let resp = handle_email_query(&entries, None, 0, None, "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        // tz-b (18:00 UTC) is later than tz-a (18:00 UTC)... wait
        // 23:00+05:00 = 23:00 - 5:00 = 18:00 UTC
        // 20:00Z = 20:00 UTC
        // So tz-b (20:00 UTC) is newer; should appear first.
        assert_eq!(
            ids[0].as_str().unwrap(),
            test_cid(b"tz-b").to_string(),
            "20:00Z (newer) should sort before 23:00+05:00 (18:00 UTC)"
        );
    }

    #[test]
    fn state_string_is_passed_through() {
        let entries = make_entries();
        let resp = handle_email_query(&entries, None, 0, None, "42", None, "test");
        assert_eq!(resp["queryState"].as_str().unwrap(), "42");
    }

    #[test]
    fn pagination_position_and_limit() {
        let entries = make_entries();
        let resp = handle_email_query(&entries, None, 1, Some(1), "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 1, "limit=1 should return exactly 1 item");
        assert_eq!(
            resp["total"].as_u64().unwrap(),
            3,
            "total must reflect full count"
        );
    }

    #[test]
    fn empty_result() {
        let entries: Vec<EmailOverviewEntry> = vec![];
        let resp = handle_email_query(&entries, None, 0, None, "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        assert!(ids.is_empty());
        assert_eq!(resp["total"].as_u64().unwrap(), 0);
    }

    #[test]
    fn text_search_results_filters_by_message_id() {
        let entries = make_entries();
        // Simulate: search index returned only article-b's message-id.
        let matched: std::collections::HashSet<String> =
            ["<article-b@example.com>".to_string()].into();
        let resp = handle_email_query(&entries, None, 0, None, "0", Some(matched), "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(
            ids.len(),
            1,
            "only the article matching the text search must be returned"
        );
        assert_eq!(ids[0].as_str().unwrap(), test_cid(b"article-b").to_string());
    }

    #[test]
    fn text_search_empty_set_returns_no_results() {
        let entries = make_entries();
        let matched: std::collections::HashSet<String> = std::collections::HashSet::new();
        let resp = handle_email_query(&entries, None, 0, None, "0", Some(matched), "test");
        let ids = resp["ids"].as_array().unwrap();
        assert!(
            ids.is_empty(),
            "empty search result set must produce empty response"
        );
        assert_eq!(resp["total"].as_u64().unwrap(), 0);
    }

    #[test]
    fn text_search_combined_with_subject_filter() {
        let entries = make_entries();
        // Search matched article-a and article-c (both have "Rust" in subject),
        // but subject filter "great" further restricts to article-a only.
        let matched: std::collections::HashSet<String> = [
            "<article-a@example.com>".to_string(),
            "<article-c@example.com>".to_string(),
        ]
        .into();
        let filter = json!({"subject": "great"});
        let resp = handle_email_query(&entries, Some(&filter), 0, None, "0", Some(matched), "test");
        let ids = resp["ids"].as_array().unwrap();
        assert_eq!(
            ids.len(),
            1,
            "text+subject combined filter must intersect both"
        );
        assert_eq!(ids[0].as_str().unwrap(), test_cid(b"article-a").to_string());
    }

    /// A client-supplied limit of u64::MAX must be silently capped to MAX_FETCH_LIMIT.
    ///
    /// Before the fix, `limit.unwrap_or(u64::MAX) as usize` would produce usize::MAX
    /// on 32-bit platforms (silent truncation) and allowed unbounded allocations on
    /// 64-bit platforms.  The cap prevents both.
    ///
    /// Oracle: the result length must equal min(entry_count, MAX_FETCH_LIMIT) because
    /// there are only 3 test entries; the cap must not cause any entries to be dropped.
    #[test]
    fn limit_u64_max_is_capped_to_max_fetch_limit() {
        let entries = make_entries(); // 3 entries
                                      // Pass u64::MAX as the limit — this is the boundary case from the bug report.
        let resp = handle_email_query(&entries, None, 0, Some(u64::MAX), "0", None, "test");
        let ids = resp["ids"].as_array().unwrap();
        // 3 < MAX_FETCH_LIMIT, so all 3 entries are returned (cap does not truncate).
        assert_eq!(
            ids.len(),
            3,
            "u64::MAX limit must be capped; with only 3 entries all should be returned"
        );
        // Also verify that a limit explicitly equal to MAX_FETCH_LIMIT is accepted.
        let resp2 = handle_email_query(&entries, None, 0, Some(MAX_FETCH_LIMIT), "0", None, "test");
        let ids2 = resp2["ids"].as_array().unwrap();
        assert_eq!(
            ids2.len(),
            3,
            "limit equal to MAX_FETCH_LIMIT must return all available entries"
        );
        // And a limit exceeding MAX_FETCH_LIMIT is silently capped (not rejected).
        let resp3 = handle_email_query(
            &entries,
            None,
            0,
            Some(MAX_FETCH_LIMIT + 1),
            "0",
            None,
            "test",
        );
        let ids3 = resp3["ids"].as_array().unwrap();
        assert_eq!(
            ids3.len(),
            3,
            "limit above MAX_FETCH_LIMIT must be capped; all 3 entries should still be returned"
        );
    }
}
