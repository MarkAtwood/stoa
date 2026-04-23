//! Full-text search subsystem backed by Tantivy.
//! Disabled when `SearchConfig.index_dir` is `None`.
//!
//! ## Index corruption recovery
//!
//! The Tantivy search index is a **rebuildable cache**. If the index is
//! corrupted (power loss during commit, disk full, filesystem errors), the
//! server will log a `TantivyError` on startup or on the first query.
//!
//! Recovery procedure:
//! 1. Stop the server.
//! 2. Delete the entire `search.index_dir` directory.
//! 3. Restart the server. The index will be empty until new articles arrive.
//!
//! To rebuild the index from existing articles, use the admin rebuild command
//! (not yet implemented; tracked in issue 9tz). Until then, the index
//! accumulates from new ingest after restart.
//!
//! The index is never the authoritative record of article existence —
//! that role belongs to the SQLite article_numbers table and the IPFS
//! block store.

pub mod error;
pub use error::SearchError;

use crate::config::SearchConfig;
use std::sync::Arc;
use tantivy::{
    collector::TopDocs,
    doc,
    query::{BooleanQuery, Occur, QueryParser, TermQuery},
    schema::{Field, IndexRecordOption, Schema, Value, FAST, INDEXED, STORED, STRING, TEXT},
    Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term,
};
use tokio::sync::Mutex;

/// Schema field indices (filled in at construction time).
struct Fields {
    message_id: Field,
    newsgroup: Field,
    article_num: Field,
    subject: Field,
    from_header: Field,
    date_ts: Field,
    body_text: Field,
}

struct Inner {
    index: Index,
    reader: IndexReader,
    writer: Mutex<IndexWriter>,
    fields: Fields,
    config: SearchConfig,
}

/// Truncate a byte slice at or before `max_bytes`, always landing on a valid
/// UTF-8 character boundary.
///
/// If the byte at `max_bytes` is a UTF-8 continuation byte (top two bits are
/// `10`), we walk backward until we find a leading byte or reach the start.
/// This prevents `String::from_utf8_lossy` from emitting a U+FFFD replacement
/// character that would corrupt the last word in indexed text.
fn truncate_at_char_boundary(s: &[u8], max_bytes: usize) -> &[u8] {
    if s.len() <= max_bytes {
        return s;
    }
    let mut i = max_bytes;
    // UTF-8 continuation bytes have the form 10xxxxxx.
    while i > 0 && (s[i] & 0xC0) == 0x80 {
        i -= 1;
    }
    &s[..i]
}

/// Full-text search index backed by Tantivy.
///
/// This type is `Send + Sync` and is meant to be shared via `Arc`.
/// Index writes are serialized via an internal `tokio::sync::Mutex`.
pub struct TantivySearchIndex {
    inner: Arc<Inner>,
}

/// All fields required to index a single article.
pub struct ArticleIndexRequest<'a> {
    pub message_id: &'a str,
    pub newsgroup: &'a str,
    pub article_num: u64,
    pub subject: &'a str,
    pub from: &'a str,
    /// RFC 2822 date string (e.g. `"Mon, 01 Jan 2024 00:00:00 +0000"`).
    pub date_str: &'a str,
    /// Raw body bytes; truncated to `SearchConfig.body_index_max_bytes` before indexing.
    pub body_bytes: &'a [u8],
}

fn build_schema() -> (Schema, Fields) {
    let mut b = Schema::builder();
    // STRING = stored as a single token (exact match), not tokenized.
    let message_id = b.add_text_field("message_id", STRING | STORED);
    let newsgroup = b.add_text_field("newsgroup", STRING | STORED);
    let article_num = b.add_u64_field("article_num", FAST | STORED);
    let subject = b.add_text_field("subject", TEXT | STORED);
    let from_header = b.add_text_field("from_header", TEXT | STORED);
    let date_ts = b.add_u64_field("date_ts", INDEXED | FAST | STORED);
    let body_text = b.add_text_field("body_text", TEXT);
    let schema = b.build();
    let fields = Fields {
        message_id,
        newsgroup,
        article_num,
        subject,
        from_header,
        date_ts,
        body_text,
    };
    (schema, fields)
}

/// Parse an RFC 2822 date string into a Unix timestamp.
/// Returns 0 on any parse failure (non-fatal; article is still indexed).
fn parse_date_to_ts(date_str: &str) -> u64 {
    let trimmed = date_str.trim();
    if trimmed.is_empty() {
        return 0;
    }

    // Strip optional day-of-week prefix, e.g. "Mon, 01 Jan 2024 ..."
    let s = if let Some(comma_pos) = trimmed.find(',') {
        trimmed[comma_pos + 1..].trim()
    } else {
        trimmed
    };

    // Try RFC 2822 date-time formats (chrono).
    let formats = [
        "%d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M %z",
        "%d %b %Y %T %z",
    ];

    for fmt in &formats {
        if let Ok(dt) = chrono::DateTime::parse_from_str(s, fmt) {
            let ts = dt.timestamp();
            if ts > 0 {
                return ts as u64;
            }
        }
    }

    0
}

impl TantivySearchIndex {
    /// Open (or create) the search index at the path given in `config`.
    ///
    /// Returns `Ok(None)` if `config.index_dir` is `None` (search disabled).
    /// Returns `Err` if the index cannot be opened.
    pub fn open(config: &SearchConfig) -> Result<Option<Self>, SearchError> {
        let path = match &config.index_dir {
            Some(p) => p.clone(),
            None => return Ok(None),
        };
        std::fs::create_dir_all(&path)
            .map_err(|e| SearchError::Tantivy(tantivy::TantivyError::IoError(Arc::new(e))))?;
        let (schema, fields) = build_schema();
        let dir_path = std::path::Path::new(&path);
        let index = if dir_path.join("meta.json").exists() {
            // `open_in_dir` performs basic structural validation of the index
            // on disk. If the index is corrupt it returns
            // `TantivyError::DataCorruption`, which propagates as `Err` here
            // and causes the server to refuse startup. This is intentional:
            // fail fast rather than silently returning empty search results.
            // See module-level docs for the recovery procedure.
            Index::open_in_dir(dir_path)?
        } else {
            Index::create_in_dir(dir_path, schema)?
        };
        let writer = index.writer(50_000_000)?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;
        Ok(Some(Self {
            inner: Arc::new(Inner {
                index,
                reader,
                writer: Mutex::new(writer),
                fields,
                config: config.clone(),
            }),
        }))
    }

    /// Create an in-memory index for testing.
    pub fn open_in_memory(config: &SearchConfig) -> Result<Self, SearchError> {
        let (schema, fields) = build_schema();
        let index = Index::create_in_ram(schema);
        let writer = index.writer(15_000_000)?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;
        Ok(Self {
            inner: Arc::new(Inner {
                index,
                reader,
                writer: Mutex::new(writer),
                fields,
                config: config.clone(),
            }),
        })
    }

    /// Index a single article.
    ///
    /// Body bytes are truncated to `config.body_index_max_bytes` before indexing.
    /// Date is parsed from RFC 2822 string; failures fall back to timestamp 0.
    ///
    /// Errors are returned to the caller; callers in the POST pipeline should
    /// log and continue — never reject an article due to indexing failure.
    pub async fn index_article(&self, req: &ArticleIndexRequest<'_>) -> Result<(), SearchError> {
        let f = &self.inner.fields;
        let date_ts = parse_date_to_ts(req.date_str);
        let max_body = self.inner.config.body_index_max_bytes;
        let body_slice = truncate_at_char_boundary(req.body_bytes, max_body);
        let body_str = String::from_utf8_lossy(body_slice).to_string();

        let document = doc!(
            f.message_id => req.message_id,
            f.newsgroup => req.newsgroup,
            f.article_num => req.article_num,
            f.subject => req.subject,
            f.from_header => req.from,
            f.date_ts => date_ts,
            f.body_text => body_str,
        );

        let writer = self.inner.writer.lock().await;
        writer.add_document(document)?;
        Ok(())
    }

    /// Commit pending documents to the index and make them visible to searchers.
    ///
    /// Should be called after a batch of `index_article` calls.
    pub async fn commit(&self) -> Result<(), SearchError> {
        let mut writer = self.inner.writer.lock().await;
        writer.commit()?;
        // With ReloadPolicy::Manual the reader does not auto-reload.
        // Reload explicitly so searchers see the newly committed segments.
        self.inner.reader.reload()?;
        Ok(())
    }

    /// Search within a specific newsgroup and return matching article numbers.
    ///
    /// Returns up to `max_results` article numbers ordered by relevance score.
    pub async fn search_in_group(
        &self,
        group: &str,
        query_str: &str,
        max_results: usize,
    ) -> Result<Vec<u64>, SearchError> {
        let max_query_len = self.inner.config.max_query_len;
        if query_str.len() > max_query_len {
            return Err(SearchError::QueryTooLong {
                len: query_str.len(),
                max: max_query_len,
            });
        }
        let f = &self.inner.fields;
        let searcher = self.inner.reader.searcher();

        // Build newsgroup filter term (exact match — newsgroup field is STRING).
        let group_term = Term::from_field_text(f.newsgroup, group);
        let group_query = Box::new(TermQuery::new(group_term, IndexRecordOption::Basic));

        // Build the user's free-text query over indexed text fields.
        let parser = QueryParser::for_index(
            &self.inner.index,
            vec![f.subject, f.from_header, f.body_text],
        );
        let (user_query, _errors) = parser.parse_query_lenient(query_str);

        // Combine: newsgroup:group AND user_query
        let combined =
            BooleanQuery::new(vec![(Occur::Must, group_query), (Occur::Must, user_query)]);

        let top_docs = searcher
            .search(&combined, &TopDocs::with_limit(max_results))
            .map_err(SearchError::Tantivy)?;

        let mut nums = Vec::with_capacity(top_docs.len());
        for (_score, addr) in top_docs {
            let doc: TantivyDocument = searcher.doc(addr).map_err(SearchError::Tantivy)?;
            if let Some(v) = doc.get_first(f.article_num) {
                if let Some(n) = v.as_u64() {
                    nums.push(n);
                }
            }
        }
        Ok(nums)
    }

    /// Search across all groups and return matching message-IDs.
    ///
    /// Used by JMAP Email/query text filter.
    pub async fn search_all(
        &self,
        query_str: &str,
        max_results: usize,
    ) -> Result<Vec<String>, SearchError> {
        let max_query_len = self.inner.config.max_query_len;
        if query_str.len() > max_query_len {
            return Err(SearchError::QueryTooLong {
                len: query_str.len(),
                max: max_query_len,
            });
        }
        let f = &self.inner.fields;
        let searcher = self.inner.reader.searcher();

        let parser = QueryParser::for_index(
            &self.inner.index,
            vec![f.subject, f.from_header, f.body_text],
        );
        let (user_query, _errors) = parser.parse_query_lenient(query_str);

        let top_docs = searcher
            .search(&user_query, &TopDocs::with_limit(max_results))
            .map_err(SearchError::Tantivy)?;

        let mut ids = Vec::with_capacity(top_docs.len());
        for (_score, addr) in top_docs {
            let doc: TantivyDocument = searcher.doc(addr).map_err(SearchError::Tantivy)?;
            if let Some(v) = doc.get_first(f.message_id) {
                if let Some(s) = Value::as_str(&v) {
                    ids.push(s.to_owned());
                }
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SearchConfig {
        SearchConfig {
            index_dir: None,
            max_index_bytes: 10_737_418_240,
            body_index_max_bytes: 102_400,
            max_query_len: 4096,
        }
    }

    #[test]
    fn open_returns_none_when_disabled() {
        let cfg = test_config();
        let result = TantivySearchIndex::open(&cfg).expect("should succeed");
        assert!(result.is_none(), "disabled config must return None");
    }

    #[test]
    fn open_in_memory_succeeds() {
        let cfg = test_config();
        TantivySearchIndex::open_in_memory(&cfg).expect("in-memory index must open");
    }

    #[test]
    fn parse_date_to_ts_valid_date() {
        // RFC 2822: "Mon, 01 Jan 2024 00:00:00 +0000" => 2024-01-01 00:00:00 UTC
        // Reference: https://www.unixtimestamp.com/ confirms 1704067200
        let ts = parse_date_to_ts("Mon, 01 Jan 2024 00:00:00 +0000");
        assert_eq!(ts, 1_704_067_200, "known Unix timestamp for 2024-01-01");
    }

    #[test]
    fn parse_date_to_ts_empty_returns_zero() {
        assert_eq!(parse_date_to_ts(""), 0);
        assert_eq!(parse_date_to_ts("   "), 0);
    }

    #[test]
    fn parse_date_to_ts_garbage_returns_zero() {
        assert_eq!(parse_date_to_ts("not a date"), 0);
    }

    #[tokio::test]
    async fn index_and_search_in_group() {
        let cfg = test_config();
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<abc@example.com>",
            newsgroup: "comp.lang.rust",
            article_num: 42,
            subject: "Rust async patterns",
            from: "Alice <alice@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"Tokio is great for async Rust code.",
        })
        .await
        .expect("index_article");

        idx.commit().await.expect("commit");

        let results = idx
            .search_in_group("comp.lang.rust", "async", 10)
            .await
            .expect("search");

        assert!(
            results.contains(&42),
            "article 42 must appear in search results; got: {results:?}"
        );
    }

    #[tokio::test]
    async fn search_in_wrong_group_returns_empty() {
        let cfg = test_config();
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<def@example.com>",
            newsgroup: "comp.lang.rust",
            article_num: 99,
            subject: "Rust async patterns",
            from: "Bob <bob@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"Tokio is great.",
        })
        .await
        .expect("index_article");

        idx.commit().await.expect("commit");

        let results = idx
            .search_in_group("sci.physics", "async", 10)
            .await
            .expect("search");

        assert!(
            results.is_empty(),
            "wrong group must return empty; got: {results:?}"
        );
    }

    #[tokio::test]
    async fn search_all_returns_message_id() {
        let cfg = test_config();
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<xyz@example.com>",
            newsgroup: "misc.test",
            article_num: 1,
            subject: "Hello from Rust",
            from: "Carol <carol@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"This is a test article body.",
        })
        .await
        .expect("index_article");

        idx.commit().await.expect("commit");

        let results = idx.search_all("Hello Rust", 10).await.expect("search_all");

        assert!(
            results.contains(&"<xyz@example.com>".to_owned()),
            "message-id must appear in search_all results; got: {results:?}"
        );
    }

    #[tokio::test]
    async fn query_too_long_returns_error() {
        let cfg = SearchConfig {
            index_dir: None,
            max_index_bytes: 10_737_418_240,
            body_index_max_bytes: 102_400,
            max_query_len: 10,
        };
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        let long_query = "a".repeat(11);
        let err = idx
            .search_in_group("comp.lang.rust", &long_query, 10)
            .await
            .expect_err("must fail for long query");
        assert!(
            matches!(err, SearchError::QueryTooLong { .. }),
            "expected QueryTooLong, got: {err:?}"
        );

        let err2 = idx
            .search_all(&long_query, 10)
            .await
            .expect_err("must fail for long query");
        assert!(
            matches!(err2, SearchError::QueryTooLong { .. }),
            "expected QueryTooLong, got: {err2:?}"
        );
    }

    #[tokio::test]
    async fn body_truncation_applied_before_indexing() {
        // Config with very small body_index_max_bytes.
        let cfg = SearchConfig {
            index_dir: None,
            max_index_bytes: 10_737_418_240,
            body_index_max_bytes: 5,
            max_query_len: 4096,
        };
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        // Body is "hello world" — only "hello" fits within 5 bytes.
        // "world" must NOT be indexed.
        idx.index_article(&ArticleIndexRequest {
            message_id: "<trunc@example.com>",
            newsgroup: "misc.test",
            article_num: 7,
            subject: "truncation test",
            from: "Dave <dave@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"hello world",
        })
        .await
        .expect("index_article");

        idx.commit().await.expect("commit");

        // "world" should NOT be found (it was truncated from the body).
        let results = idx
            .search_in_group("misc.test", "world", 10)
            .await
            .expect("search");
        assert!(
            results.is_empty(),
            "truncated body word must not be found; got: {results:?}"
        );
    }

    // ── Required tests for bead 9tz.6 ──────────────────────────────────────

    #[tokio::test]
    async fn index_then_search_body() {
        // Oracle: manually crafted. Searching "rust" must find the article;
        // "python" must return empty because the word never appears.
        let cfg = test_config();
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<body-test@example.com>",
            newsgroup: "comp.lang.rust",
            article_num: 100,
            subject: "Body search test",
            from: "Eve <eve@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"hello rust world",
        })
        .await
        .expect("index_article");

        idx.commit().await.expect("commit");

        let found = idx
            .search_in_group("comp.lang.rust", "rust", 10)
            .await
            .expect("search rust");
        assert!(
            found.contains(&100),
            "article 100 must be found when searching 'rust'; got: {found:?}"
        );

        let not_found = idx
            .search_in_group("comp.lang.rust", "python", 10)
            .await
            .expect("search python");
        assert!(
            not_found.is_empty(),
            "'python' must return empty (word not in article); got: {not_found:?}"
        );
    }

    #[tokio::test]
    async fn index_then_search_subject() {
        // Oracle: manually crafted. Tantivy uses a standard English tokenizer;
        // lowercasing means "tantivy" matches subject "Tantivy test".
        let cfg = test_config();
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<subj-test@example.com>",
            newsgroup: "comp.test",
            article_num: 200,
            subject: "Tantivy test",
            from: "Frank <frank@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"see subject",
        })
        .await
        .expect("index_article");

        idx.commit().await.expect("commit");

        // Search is case-insensitive because Tantivy's TEXT field uses a
        // lowercasing tokenizer; "tantivy" must match subject "Tantivy test".
        let results = idx
            .search_in_group("comp.test", "tantivy", 10)
            .await
            .expect("search");
        assert!(
            results.contains(&200),
            "article 200 must be found with lowercase 'tantivy'; got: {results:?}"
        );
    }

    #[tokio::test]
    async fn search_respects_newsgroup() {
        // Oracle: manually crafted. Two articles in different groups; each
        // search is scoped to one group and must not bleed into the other.
        let cfg = test_config();
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<grp-a@example.com>",
            newsgroup: "comp.lang.rust",
            article_num: 11,
            subject: "Rust concurrency",
            from: "Grace <grace@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"concurrency in rust is great",
        })
        .await
        .expect("index group A");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<grp-b@example.com>",
            newsgroup: "sci.physics",
            article_num: 22,
            subject: "Quantum concurrency",
            from: "Heidi <heidi@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"concurrency in quantum systems",
        })
        .await
        .expect("index group B");

        idx.commit().await.expect("commit");

        // Searching comp.lang.rust for "concurrency" must find article 11 only.
        let rust_results = idx
            .search_in_group("comp.lang.rust", "concurrency", 10)
            .await
            .expect("search rust group");
        assert!(
            rust_results.contains(&11),
            "article 11 must appear in comp.lang.rust results; got: {rust_results:?}"
        );
        assert!(
            !rust_results.contains(&22),
            "article 22 (sci.physics) must NOT appear in comp.lang.rust results; got: {rust_results:?}"
        );

        // Searching sci.physics for "concurrency" must find article 22 only.
        let phys_results = idx
            .search_in_group("sci.physics", "concurrency", 10)
            .await
            .expect("search physics group");
        assert!(
            phys_results.contains(&22),
            "article 22 must appear in sci.physics results; got: {phys_results:?}"
        );
        assert!(
            !phys_results.contains(&11),
            "article 11 (comp.lang.rust) must NOT appear in sci.physics results; got: {phys_results:?}"
        );
    }

    #[tokio::test]
    async fn commit_is_needed() {
        // Oracle: manually crafted. Before commit, Tantivy's in-memory index
        // exposes no segments to the reader; search must return empty. After
        // commit (and manual reader reload), the article is visible.
        let cfg = test_config();
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<commit-test@example.com>",
            newsgroup: "misc.test",
            article_num: 300,
            subject: "Commit visibility test",
            from: "Ivan <ivan@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"visibility before and after commit",
        })
        .await
        .expect("index_article");

        // No commit yet — must find nothing.
        let before = idx
            .search_in_group("misc.test", "visibility", 10)
            .await
            .expect("search before commit");
        assert!(
            before.is_empty(),
            "before commit search must return empty; got: {before:?}"
        );

        idx.commit().await.expect("commit");

        // After commit — article must be visible.
        let after = idx
            .search_in_group("misc.test", "visibility", 10)
            .await
            .expect("search after commit");
        assert!(
            after.contains(&300),
            "article 300 must be visible after commit; got: {after:?}"
        );
    }

    // ── ld7.11: UTF-8 boundary truncation ────────────────────────────────

    #[test]
    fn truncate_at_char_boundary_ascii_unchanged() {
        // Oracle: ASCII-only input; truncation at any byte is a valid boundary.
        let data = b"hello world";
        assert_eq!(truncate_at_char_boundary(data, 5), b"hello");
    }

    #[test]
    fn truncate_at_char_boundary_multibyte_walks_back() {
        // Oracle: "é" is 0xC3 0xA9 (2 bytes). A string of 3 é chars = 6 bytes.
        // Truncating at byte 5 falls inside the third é (index 4 = 0xC3 leading
        // byte, index 5 = 0xA9 continuation byte). The helper must walk back to
        // byte 4 (the leading byte of the third é) and return only the first two
        // é characters (4 bytes).
        let input = "ééé".as_bytes(); // [0xC3,0xA9, 0xC3,0xA9, 0xC3,0xA9]
        assert_eq!(input.len(), 6);
        let sliced = truncate_at_char_boundary(input, 5);
        let s = std::str::from_utf8(sliced).expect("must be valid UTF-8 after boundary truncation");
        assert_eq!(
            s, "éé",
            "truncation must include exactly the first two é chars"
        );
    }

    #[test]
    fn truncate_at_char_boundary_exactly_on_boundary() {
        // Oracle: truncating at exactly the end of a 2-byte sequence includes it.
        let input = "éx".as_bytes(); // [0xC3, 0xA9, 0x78]
        let sliced = truncate_at_char_boundary(input, 2);
        assert_eq!(sliced, "é".as_bytes());
    }

    #[tokio::test]
    async fn index_article_multibyte_truncation_no_corruption() {
        // Oracle: body is 51 é characters (102 bytes, 2 bytes each).
        // body_index_max_bytes = 101 — one byte short of a complete character.
        // The old code passed 101 bytes to from_utf8_lossy, which emitted
        // U+FFFD for the dangling 0xC3 leading byte. The fixed code truncates
        // at byte 100 (50 complete é chars) and produces valid UTF-8 with no
        // replacement character. Verified by constructing the expected slice
        // independently and comparing.
        let cfg = SearchConfig {
            index_dir: None,
            max_index_bytes: 10_737_418_240,
            body_index_max_bytes: 101,
            max_query_len: 4096,
        };
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        // 51 é chars = 102 bytes. The first 50 fit within the 101-byte limit.
        let body: Vec<u8> = "é".repeat(51).into_bytes();
        assert_eq!(body.len(), 102);

        idx.index_article(&ArticleIndexRequest {
            message_id: "<utf8-trunc@example.com>",
            newsgroup: "misc.test",
            article_num: 5,
            subject: "UTF-8 truncation test",
            from: "Tester <t@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: &body,
        })
        .await
        .expect("index_article must not fail on multibyte truncation boundary");

        // Verify the helper itself returns valid UTF-8 (independent oracle).
        let sliced = truncate_at_char_boundary(&body, 101);
        let as_str =
            std::str::from_utf8(sliced).expect("truncated slice must be valid UTF-8, not U+FFFD");
        assert_eq!(
            as_str,
            "é".repeat(50),
            "truncated slice must contain exactly 50 é chars"
        );

        idx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn body_truncation_huge_body_no_panic() {
        // Oracle: a 5 MiB body with body_index_max_bytes = 102_400 must not
        // panic. Only the first 100 KiB is indexed. Words at byte offset
        // 200_000 must not appear in results.
        let cfg = test_config(); // body_index_max_bytes = 102_400
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        // Build a 5 MiB body: first 100 KiB is spaces + "earlykeyword",
        // then a unique "latekeyword" past the truncation boundary.
        let mut body = vec![b' '; 102_400];
        body[0..12].copy_from_slice(b"earlykeyword");
        body.extend_from_slice(&vec![b' '; 102_400]); // push "latekeyword" beyond limit
        body.extend_from_slice(b"latekeyword");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<huge@example.com>",
            newsgroup: "misc.test",
            article_num: 400,
            subject: "huge body test",
            from: "Judy <judy@example.com>",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: &body,
        })
        .await
        .expect("index_article must not panic on large body");

        idx.commit().await.expect("commit");

        // "latekeyword" is past the truncation boundary — must not be found.
        let late_results = idx
            .search_in_group("misc.test", "latekeyword", 10)
            .await
            .expect("search latekeyword");
        assert!(
            late_results.is_empty(),
            "'latekeyword' beyond truncation must not be found; got: {late_results:?}"
        );
    }

    #[tokio::test]
    async fn search_all_returns_message_ids() {
        // Oracle: manually crafted. "frobnicator" appears in both subject and
        // body; search_all must return the exact message-id string indexed.
        let cfg = test_config();
        let idx = TantivySearchIndex::open_in_memory(&cfg).expect("open");

        idx.index_article(&ArticleIndexRequest {
            message_id: "<msg@test>",
            newsgroup: "comp.test",
            article_num: 1,
            subject: "Frobnicator hypothesis",
            from: "alice@test",
            date_str: "Mon, 01 Jan 2024 00:00:00 +0000",
            body_bytes: b"unique frobnicator content",
        })
        .await
        .expect("index_article");

        idx.commit().await.expect("commit");

        let ids = idx.search_all("frobnicator", 10).await.expect("search_all");
        assert_eq!(
            ids,
            vec!["<msg@test>".to_owned()],
            "search_all must return exactly the indexed message-id"
        );
    }
}
