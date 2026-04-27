//! SQLite-backed overview index for OVER/XOVER.
//!
//! Stores the 7 RFC 3977 required overview fields per article, keyed by
//! `(group_name, article_number)`.

use sqlx::SqlitePool;

/// Maximum number of records returned by a single `query_range` call.
///
/// Prevents unbounded memory allocation when a client requests a very wide
/// article range. RFC 3977 imposes no limit itself; 10 000 is a generous
/// practical ceiling that fits within a single NNTP OVER response without
/// per-connection buffering pressure.
const MAX_OVER_RESULTS: usize = 10_000;

/// SQLite row returned by `query_range`; mapped to `OverviewRecord`.
#[derive(sqlx::FromRow)]
struct OverviewRow {
    article_number: i64,
    subject: String,
    from_header: String,
    date_header: String,
    message_id: String,
    references_header: String,
    byte_count: i64,
    line_count: i64,
    did_sig_valid: Option<i64>,
}

/// The 7 RFC 3977 overview fields for one article, plus optional DID sig status.
#[derive(Debug, Clone)]
pub struct OverviewRecord {
    pub article_number: u64,
    pub subject: String,
    pub from: String,
    pub date: String,
    pub message_id: String,
    pub references: String,
    pub byte_count: u64,
    pub line_count: u64,
    /// DID signature verification result.
    ///
    /// `None`  — no `X-Stoa-DID-Sig` header was present.
    /// `Some(false)` — signature verification failed.
    /// `Some(true)`  — signature verified successfully.
    pub did_sig_valid: Option<bool>,
}

/// Stores and retrieves overview records from SQLite.
pub struct OverviewStore {
    pool: SqlitePool,
}

impl OverviewStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert an overview record.
    ///
    /// Idempotent: if `(group, article_number)` already exists, does nothing.
    pub async fn insert(&self, group: &str, record: &OverviewRecord) -> Result<(), sqlx::Error> {
        let article_number = record.article_number as i64;
        let byte_count = record.byte_count as i64;
        let line_count = record.line_count as i64;
        let did_sig_valid: Option<i64> = record.did_sig_valid.map(|v| v as i64);

        sqlx::query(
            "INSERT OR IGNORE INTO overview \
             (group_name, article_number, subject, from_header, date_header, \
              message_id, references_header, byte_count, line_count, did_sig_valid) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(group)
        .bind(article_number)
        .bind(&record.subject)
        .bind(&record.from)
        .bind(&record.date)
        .bind(&record.message_id)
        .bind(&record.references)
        .bind(byte_count)
        .bind(line_count)
        .bind(did_sig_valid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Look up a single overview record by Message-ID across all groups.
    ///
    /// Returns `None` if no article with that Message-ID is in the index.
    /// If the same Message-ID appears in multiple groups (cross-posted), returns
    /// the record with the lowest article_number (arbitrary but deterministic).
    pub async fn query_by_msgid(
        &self,
        message_id: &str,
    ) -> Result<Option<OverviewRecord>, sqlx::Error> {
        let row: Option<OverviewRow> = sqlx::query_as(
            "SELECT article_number, subject, from_header, date_header, \
             message_id, references_header, byte_count, line_count, did_sig_valid \
             FROM overview \
             WHERE message_id = ? \
             ORDER BY article_number ASC \
             LIMIT 1",
        )
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| OverviewRecord {
            article_number: r.article_number as u64,
            subject: r.subject,
            from: r.from_header,
            date: r.date_header,
            message_id: r.message_id,
            references: r.references_header,
            byte_count: r.byte_count as u64,
            line_count: r.line_count as u64,
            did_sig_valid: r.did_sig_valid.map(|v| v != 0),
        }))
    }

    /// Look up a single overview record by (group, article_number).
    ///
    /// Returns `None` if no record exists for that article number in that group.
    /// Avoids the header-scan + `query_by_msgid` round-trip used by
    /// `lookup_article_content_by_number` when the overview has been indexed.
    pub async fn query_by_number(
        &self,
        group: &str,
        article_number: u64,
    ) -> Result<Option<OverviewRecord>, sqlx::Error> {
        let number = article_number as i64;
        let row: Option<OverviewRow> = sqlx::query_as(
            "SELECT article_number, subject, from_header, date_header, \
             message_id, references_header, byte_count, line_count, did_sig_valid \
             FROM overview \
             WHERE group_name = ? AND article_number = ? \
             LIMIT 1",
        )
        .bind(group)
        .bind(number)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| OverviewRecord {
            article_number: r.article_number as u64,
            subject: r.subject,
            from: r.from_header,
            date: r.date_header,
            message_id: r.message_id,
            references: r.references_header,
            byte_count: r.byte_count as u64,
            line_count: r.line_count as u64,
            did_sig_valid: r.did_sig_valid.map(|v| v != 0),
        }))
    }

    /// Query overview records for a range of article numbers (inclusive).
    ///
    /// Returns records in ascending `article_number` order, capped at
    /// [`MAX_OVER_RESULTS`]. Article numbers within the range that have no
    /// record are silently skipped.
    ///
    /// # DECISION (rbe3.7): bounded materialization, not true wire streaming
    ///
    /// `fetch_all` materializes at most `MAX_OVER_RESULTS` rows before the
    /// caller formats and writes them to the NNTP wire.  True streaming
    /// (writing each row to the wire as it is fetched from SQLite) would
    /// require restructuring the command loop to write incrementally rather
    /// than building a complete `Response` and calling `write_all` once.
    /// The current architecture keeps command handlers as pure functions that
    /// return a `Response` value, which simplifies testing and error handling.
    /// `MAX_OVER_RESULTS = 10_000` bounds peak memory to ≈2 MB per OVER
    /// response, which is acceptable.  If a future benchmark shows this is a
    /// bottleneck for very high-volume groups, the fix is to change the
    /// command loop to accept an `AsyncWrite` sink and pipe rows directly.
    pub async fn query_range(
        &self,
        group: &str,
        low: u64,
        high: u64,
    ) -> Result<Vec<OverviewRecord>, sqlx::Error> {
        let low = low as i64;
        let high = high as i64;

        let rows: Vec<OverviewRow> = sqlx::query_as(
            "SELECT article_number, subject, from_header, date_header, \
              message_id, references_header, byte_count, line_count, did_sig_valid \
             FROM overview \
             WHERE group_name = ? AND article_number >= ? AND article_number <= ? \
             ORDER BY article_number ASC \
             LIMIT ?",
        )
        .bind(group)
        .bind(low)
        .bind(high)
        .bind(MAX_OVER_RESULTS as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| OverviewRecord {
                article_number: row.article_number as u64,
                subject: row.subject,
                from: row.from_header,
                date: row.date_header,
                message_id: row.message_id,
                references: row.references_header,
                byte_count: row.byte_count as u64,
                line_count: row.line_count as u64,
                did_sig_valid: row.did_sig_valid.map(|v| v != 0),
            })
            .collect())
    }
}

/// Replace tab, CR, and LF with a space to prevent corruption of
/// tab-separated OVER/XOVER responses.
fn sanitize_overview_field(s: &str) -> String {
    if !s.contains(['\t', '\r', '\n']) {
        return s.to_owned();
    }
    s.chars()
        .map(|c| if c == '\t' || c == '\r' || c == '\n' { ' ' } else { c })
        .collect()
}

/// Extract the 7 overview fields from raw header bytes and a body.
///
/// Returns an `OverviewRecord` with `article_number` set to 0; the caller is
/// responsible for setting the correct local article number before storing.
///
/// Missing header fields default to an empty string.
/// `byte_count` is `body_bytes.len()`.
/// `line_count` is the count of `\n` bytes in `body_bytes`.
pub fn extract_overview(header_bytes: &[u8], body_bytes: &[u8]) -> OverviewRecord {
    let header_text = String::from_utf8_lossy(header_bytes);

    let mut subject = String::new();
    let mut from = String::new();
    let mut date = String::new();
    let mut message_id = String::new();
    let mut references = String::new();

    // Single-pass scan with RFC 5322 §2.2.3 folding, no intermediate Vec<String>.
    // Track which of the five target fields is being accumulated so that
    // continuation lines (starting with SP or HTAB) can be appended correctly.
    #[derive(Clone, Copy)]
    enum CurField { None, Subject, From, Date, MessageId, References }
    let mut cur = CurField::None;

    for raw in header_text.split('\n') {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            break; // blank line = end of headers
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line: append trimmed content to current field.
            let cont = line.trim_start();
            match cur {
                CurField::Subject => { subject.push(' '); subject.push_str(cont); }
                CurField::From => { from.push(' '); from.push_str(cont); }
                CurField::Date => { date.push(' '); date.push_str(cont); }
                CurField::MessageId => { message_id.push(' '); message_id.push_str(cont); }
                CurField::References => { references.push(' '); references.push_str(cont); }
                CurField::None => {}
            }
            continue;
        }
        cur = CurField::None;
        if let Some(value) = strip_header_name(line, "Subject") {
            subject = value.to_owned();
            cur = CurField::Subject;
        } else if let Some(value) = strip_header_name(line, "From") {
            from = value.to_owned();
            cur = CurField::From;
        } else if let Some(value) = strip_header_name(line, "Date") {
            date = value.to_owned();
            cur = CurField::Date;
        } else if let Some(value) = strip_header_name(line, "Message-ID") {
            message_id = value.to_owned();
            cur = CurField::MessageId;
        } else if let Some(value) = strip_header_name(line, "References") {
            references = value.to_owned();
            cur = CurField::References;
        }
    }

    let byte_count = body_bytes.len() as u64;
    let line_count = body_bytes.iter().filter(|&&b| b == b'\n').count() as u64;

    OverviewRecord {
        article_number: 0,
        subject: sanitize_overview_field(&subject),
        from: sanitize_overview_field(&from),
        date: sanitize_overview_field(&date),
        message_id: sanitize_overview_field(&message_id),
        references: sanitize_overview_field(&references),
        byte_count,
        line_count,
        did_sig_valid: None,
    }
}

/// Return the trimmed value after `Name:` in `line`, case-insensitively.
///
/// Returns `None` if the line does not start with `name` (followed by `:`).
fn strip_header_name<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let prefix = line.get(..name.len())?;
    if !prefix.eq_ignore_ascii_case(name) {
        return None;
    }
    let rest = line.get(name.len()..)?;
    let rest = rest.strip_prefix(':')?;
    Some(rest.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;

    async fn make_store() -> (OverviewStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        (OverviewStore::new(pool), tmp)
    }

    fn sample_record(n: u64) -> OverviewRecord {
        OverviewRecord {
            article_number: n,
            subject: format!("Subject {n}"),
            from: format!("user{n}@example.com"),
            date: "Sat, 01 Jan 2026 00:00:00 +0000".to_owned(),
            message_id: format!("<{n}@example.com>"),
            references: String::new(),
            byte_count: 100,
            line_count: 5,
            did_sig_valid: None,
        }
    }

    #[tokio::test]
    async fn insert_and_query_single() {
        let (store, _tmp) = make_store().await;
        store
            .insert("comp.lang.rust", &sample_record(1))
            .await
            .unwrap();
        let results = store.query_range("comp.lang.rust", 1, 1).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].article_number, 1);
        assert_eq!(results[0].subject, "Subject 1");
    }

    #[tokio::test]
    async fn query_range_returns_ordered() {
        let (store, _tmp) = make_store().await;
        store
            .insert("comp.lang.rust", &sample_record(5))
            .await
            .unwrap();
        store
            .insert("comp.lang.rust", &sample_record(1))
            .await
            .unwrap();
        store
            .insert("comp.lang.rust", &sample_record(3))
            .await
            .unwrap();
        let results = store.query_range("comp.lang.rust", 1, 5).await.unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].article_number, 1);
        assert_eq!(results[1].article_number, 3);
        assert_eq!(results[2].article_number, 5);
    }

    #[tokio::test]
    async fn query_range_skips_missing() {
        let (store, _tmp) = make_store().await;
        store
            .insert("comp.lang.rust", &sample_record(1))
            .await
            .unwrap();
        store
            .insert("comp.lang.rust", &sample_record(3))
            .await
            .unwrap();
        let results = store.query_range("comp.lang.rust", 1, 5).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].article_number, 1);
        assert_eq!(results[1].article_number, 3);
    }

    #[tokio::test]
    async fn insert_idempotent() {
        let (store, _tmp) = make_store().await;
        store
            .insert("comp.lang.rust", &sample_record(1))
            .await
            .unwrap();
        store
            .insert("comp.lang.rust", &sample_record(1))
            .await
            .unwrap();
        let results = store.query_range("comp.lang.rust", 1, 1).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn multi_group_isolation() {
        let (store, _tmp) = make_store().await;
        store
            .insert("comp.lang.rust", &sample_record(1))
            .await
            .unwrap();
        store.insert("alt.test", &sample_record(1)).await.unwrap();

        let rust = store.query_range("comp.lang.rust", 1, 1).await.unwrap();
        let alt = store.query_range("alt.test", 1, 1).await.unwrap();

        assert_eq!(rust.len(), 1);
        assert_eq!(alt.len(), 1);
        assert_eq!(rust[0].subject, "Subject 1");
        assert_eq!(alt[0].subject, "Subject 1");

        // A third group has no records.
        let none = store.query_range("sci.math", 1, 1).await.unwrap();
        assert_eq!(none.len(), 0);
    }

    #[tokio::test]
    async fn extract_overview_parses_headers() {
        let headers = b"Subject: Hello World\r\n\
                        From: Alice <alice@example.com>\r\n\
                        Date: Sat, 01 Jan 2026 00:00:00 +0000\r\n\
                        Message-ID: <abc123@example.com>\r\n\
                        References: <prev@example.com>\r\n";
        let body = b"Line one\nLine two\nLine three\n";

        let rec = extract_overview(headers, body);

        assert_eq!(rec.subject, "Hello World");
        assert_eq!(rec.from, "Alice <alice@example.com>");
        assert_eq!(rec.date, "Sat, 01 Jan 2026 00:00:00 +0000");
        assert_eq!(rec.message_id, "<abc123@example.com>");
        assert_eq!(rec.references, "<prev@example.com>");
        assert_eq!(rec.byte_count, body.len() as u64);
        assert_eq!(rec.line_count, 3);
        assert_eq!(rec.article_number, 0);
    }

    #[tokio::test]
    async fn extract_overview_missing_fields_are_empty() {
        // Only Subject is present; all other fields should be empty.
        let headers = b"Subject: Only Subject\r\n";
        let body = b"";

        let rec = extract_overview(headers, body);

        assert_eq!(rec.subject, "Only Subject");
        assert_eq!(rec.from, "");
        assert_eq!(rec.date, "");
        assert_eq!(rec.message_id, "");
        assert_eq!(rec.references, "");
        assert_eq!(rec.byte_count, 0);
        assert_eq!(rec.line_count, 0);
    }

    #[tokio::test]
    async fn insert_50_articles() {
        let (store, _tmp) = make_store().await;
        for n in 1u64..=50 {
            store
                .insert("comp.lang.rust", &sample_record(n))
                .await
                .unwrap();
        }
        let results = store.query_range("comp.lang.rust", 1, 50).await.unwrap();
        assert_eq!(results.len(), 50);
        for (i, rec) in results.iter().enumerate() {
            assert_eq!(rec.article_number, (i + 1) as u64);
        }
    }

    #[test]
    fn extract_overview_strips_tab_in_subject() {
        let headers = b"Subject: Hello\tWorld\r\nFrom: user@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <test@example.com>\r\n";
        let rec = extract_overview(headers, b"Some body\r\n");
        assert!(
            !rec.subject.contains('\t'),
            "tab in subject must be stripped"
        );
        assert_eq!(rec.subject, "Hello World");
    }

    /// Inserting more than MAX_OVER_RESULTS articles and querying the full
    /// range must return at most MAX_OVER_RESULTS records.
    ///
    /// This test verifies the LIMIT clause in query_range prevents unbounded
    /// result sets when a client requests a very wide article range.
    #[tokio::test]
    async fn query_range_caps_at_max_over_results() {
        let (store, _tmp) = make_store().await;
        let total = MAX_OVER_RESULTS + 5;
        for n in 1u64..=(total as u64) {
            store
                .insert("comp.lang.rust", &sample_record(n))
                .await
                .unwrap();
        }
        let results = store
            .query_range("comp.lang.rust", 1, total as u64)
            .await
            .unwrap();
        assert_eq!(
            results.len(),
            MAX_OVER_RESULTS,
            "query_range must return at most MAX_OVER_RESULTS records"
        );
        assert_eq!(results[0].article_number, 1);
        assert_eq!(
            results[MAX_OVER_RESULTS - 1].article_number,
            MAX_OVER_RESULTS as u64
        );
    }
}
