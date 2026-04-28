//! RSS 2.0 and Atom 1.0 feed endpoints.
//!
//! Serves one feed per newsgroup at:
//!   GET /feed/<group-name>.rss  → RSS 2.0 (application/rss+xml)
//!   GET /feed/<group-name>.atom → Atom 1.0 (application/atom+xml)
//!
//! The group name may contain dots (e.g. `comp.lang.rust`); the `.rss` or
//! `.atom` suffix is stripped from the last path component.
//!
//! No authentication is required — feeds are public in v1.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use stoa_reader::store::overview::OverviewRecord;

use crate::server::AppState;

/// Feed format selected by URL suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    Rss,
    Atom,
}

/// Query parameters accepted by the feed endpoints.
#[derive(Debug, Deserialize)]
pub struct FeedQuery {
    /// Maximum number of items to return (default 100, cap 500).
    pub limit: Option<u64>,
    /// Pagination cursor: return items published before this Message-ID.
    pub before: Option<String>,
}

/// Parse the trailing path segment into (group_name, FeedFormat).
///
/// The path is the portion after `/feed/`, e.g. `comp.lang.rust.rss`.
/// Returns `None` if the path does not end in `.rss` or `.atom`, or if the
/// group name portion (before the format suffix) would be empty.
pub fn parse_feed_path(path: &str) -> Option<(String, FeedFormat)> {
    if let Some(group) = path.strip_suffix(".rss") {
        if group.is_empty() {
            return None;
        }
        Some((group.to_owned(), FeedFormat::Rss))
    } else if let Some(group) = path.strip_suffix(".atom") {
        if group.is_empty() {
            return None;
        }
        Some((group.to_owned(), FeedFormat::Atom))
    } else {
        None
    }
}

/// XML-escape a string for safe embedding in XML text content or attribute values.
///
/// Escapes `&` first (to avoid double-escaping), then `<`, `>`, `"`, `'`.
pub fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Validate an RFC 3977 newsgroup name.
///
/// Delegates to [`stoa_core::article::GroupName::new`] so validation rules
/// are defined in one place.
pub fn validate_group_name(name: &str) -> bool {
    stoa_core::article::GroupName::new(name).is_ok()
}

/// Strip angle brackets from a Message-ID: `<foo@bar>` → `foo@bar`.
fn strip_angles(msgid: &str) -> &str {
    msgid.trim_matches(|c| c == '<' || c == '>')
}

/// Parse an RFC 2822 date string to RFC 3339 (for Atom).
///
/// Returns empty string on parse failure.
fn to_rfc3339(date: &str) -> String {
    chrono::DateTime::parse_from_rfc2822(date)
        .map(|dt| dt.with_timezone(&chrono::Utc).to_rfc3339())
        .unwrap_or_default()
}

/// Generate RSS 2.0 XML for a newsgroup feed.
pub fn generate_rss(base_url: &str, group: &str, articles: &[OverviewRecord]) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<rss version=\"2.0\">\n<channel>\n");
    xml.push_str(&format!("  <title>{}</title>\n", escape_xml(group)));
    xml.push_str(&format!(
        "  <link>{}/feed/{}.rss</link>\n",
        escape_xml(base_url),
        escape_xml(group)
    ));
    xml.push_str(&format!(
        "  <description>Usenet newsgroup {}</description>\n",
        escape_xml(group)
    ));
    if let Some(first) = articles.first() {
        xml.push_str(&format!(
            "  <lastBuildDate>{}</lastBuildDate>\n",
            escape_xml(&first.date)
        ));
    }
    for art in articles {
        xml.push_str("  <item>\n");
        xml.push_str(&format!(
            "    <title>{}</title>\n",
            escape_xml(&art.subject)
        ));
        xml.push_str(&format!(
            "    <guid isPermaLink=\"false\">{}</guid>\n",
            escape_xml(strip_angles(&art.message_id))
        ));
        xml.push_str(&format!(
            "    <pubDate>{}</pubDate>\n",
            escape_xml(&art.date)
        ));
        xml.push_str(&format!("    <author>{}</author>\n", escape_xml(&art.from)));
        xml.push_str("  </item>\n");
    }
    xml.push_str("</channel>\n</rss>\n");
    xml
}

/// Generate Atom 1.0 XML for a newsgroup feed.
pub fn generate_atom(base_url: &str, group: &str, articles: &[OverviewRecord]) -> String {
    let updated = articles
        .first()
        .map(|a| to_rfc3339(&a.date))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<feed xmlns=\"http://www.w3.org/2005/Atom\">\n");
    xml.push_str(&format!(
        "  <id>urn:usenet:group:{}</id>\n",
        escape_xml(group)
    ));
    xml.push_str(&format!("  <title>{}</title>\n", escape_xml(group)));
    xml.push_str(&format!("  <updated>{}</updated>\n", escape_xml(&updated)));
    xml.push_str(&format!(
        "  <link rel=\"self\" href=\"{}/feed/{}.atom\"/>\n",
        escape_xml(base_url),
        escape_xml(group)
    ));
    xml.push_str(&format!(
        "  <link rel=\"alternate\" href=\"{}/\"/>\n",
        escape_xml(base_url)
    ));
    for art in articles {
        let art_updated = to_rfc3339(&art.date);
        let art_updated = if art_updated.is_empty() {
            updated.clone()
        } else {
            art_updated
        };
        xml.push_str("  <entry>\n");
        xml.push_str(&format!(
            "    <id>urn:usenet:msgid:{}</id>\n",
            escape_xml(strip_angles(&art.message_id))
        ));
        xml.push_str(&format!(
            "    <title>{}</title>\n",
            escape_xml(&art.subject)
        ));
        xml.push_str(&format!(
            "    <updated>{}</updated>\n",
            escape_xml(&art_updated)
        ));
        xml.push_str(&format!(
            "    <author><name>{}</name></author>\n",
            escape_xml(&art.from)
        ));
        xml.push_str("  </entry>\n");
    }
    xml.push_str("</feed>\n");
    xml
}

/// Handler for `GET /feed/*path`.
///
/// Dispatches to RSS or Atom generation based on the `.rss` / `.atom` suffix.
pub async fn feed_handler(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<FeedQuery>,
) -> impl IntoResponse {
    let (group, format) = match parse_feed_path(&path) {
        Some(v) => v,
        None => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    if !validate_group_name(&group) {
        return (StatusCode::BAD_REQUEST, "Invalid group name").into_response();
    }

    let jmap = match &state.jmap {
        Some(j) => Arc::clone(j),
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Feed unavailable").into_response(),
    };

    let limit = query.limit.unwrap_or(100).min(500);

    let (low, high) = match jmap.article_numbers.group_range(&group).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Store error").into_response(),
    };

    // Empty feed for nonexistent or empty group.
    if low > high {
        let (content_type, xml) = match format {
            FeedFormat::Rss => (
                "application/rss+xml",
                generate_rss(&state.base_url, &group, &[]),
            ),
            FeedFormat::Atom => (
                "application/atom+xml",
                generate_atom(&state.base_url, &group, &[]),
            ),
        };
        return ([(header::CONTENT_TYPE, content_type)], xml).into_response();
    }

    // Pagination: if `before` cursor provided, look up its article_number.
    let effective_high = if let Some(ref before_msgid) = query.before {
        match jmap.overview_store.query_by_msgid(before_msgid).await {
            Ok(Some(rec)) => rec.article_number.saturating_sub(1),
            Ok(None) => high,
            Err(_) => high,
        }
    } else {
        high
    };

    // Query the N most recent articles.
    let effective_low = effective_high
        .saturating_sub(limit.saturating_sub(1))
        .max(low);

    let articles = match jmap
        .overview_store
        .query_range(&group, effective_low, effective_high)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Store error").into_response(),
    };

    // Sort newest first (query_range returns ascending).
    let mut articles = articles;
    articles.reverse();

    let (content_type, xml) = match format {
        FeedFormat::Rss => (
            "application/rss+xml",
            generate_rss(&state.base_url, &group, &articles),
        ),
        FeedFormat::Atom => (
            "application/atom+xml",
            generate_atom(&state.base_url, &group, &articles),
        ),
    };

    // ETag from last article message_id + count.
    // Strip '"' and '\' from the opaque-tag — both are invalid inside an ETag
    // quoted-string per RFC 7232 §2.3.
    let etag = if let Some(last) = articles.first() {
        let safe_id: String = strip_angles(&last.message_id)
            .chars()
            .filter(|&c| c != '"' && c != '\\')
            .collect();
        format!("W/\"{safe_id}-{}\"", articles.len())
    } else {
        format!("W/\"{group}-0\"")
    };

    // Last-Modified from most recent article date.
    let last_modified = articles
        .first()
        .and_then(|r| chrono::DateTime::parse_from_rfc2822(&r.date).ok())
        .map(|dt| dt.to_rfc2822())
        .unwrap_or_default();

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(
        header::ETAG,
        etag.parse()
            .unwrap_or_else(|_| "W/\"feed\"".parse().unwrap()),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=300".parse().unwrap(),
    );
    if !last_modified.is_empty() {
        if let Ok(v) = last_modified.parse() {
            headers.insert(header::LAST_MODIFIED, v);
        }
    }

    (headers, xml).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_feed_path_rss() {
        let (group, fmt) = parse_feed_path("comp.lang.rust.rss").unwrap();
        assert_eq!(group, "comp.lang.rust");
        assert_eq!(fmt, FeedFormat::Rss);
    }

    #[test]
    fn parse_feed_path_atom() {
        let (group, fmt) = parse_feed_path("alt.test.atom").unwrap();
        assert_eq!(group, "alt.test");
        assert_eq!(fmt, FeedFormat::Atom);
    }

    #[test]
    fn parse_feed_path_no_extension() {
        assert!(parse_feed_path("comp.lang.rust").is_none());
    }

    #[test]
    fn parse_feed_path_empty_group() {
        assert!(parse_feed_path(".rss").is_none());
        assert!(parse_feed_path(".atom").is_none());
    }

    #[test]
    fn escape_xml_ampersand_first() {
        // & must be escaped first; &amp; must NOT be double-escaped to &amp;amp;
        assert_eq!(escape_xml("a&b"), "a&amp;b");
        assert_eq!(escape_xml("<>&\"'"), "&lt;&gt;&amp;&quot;&apos;");
    }

    #[test]
    fn escape_xml_no_change_for_safe_chars() {
        let s = "Hello, world! 123";
        assert_eq!(escape_xml(s), s);
    }

    #[test]
    fn validate_group_name_valid() {
        assert!(validate_group_name("comp.lang.rust"));
        assert!(validate_group_name("alt.test"));
        assert!(validate_group_name("a"));
    }

    #[test]
    fn validate_group_name_invalid() {
        assert!(!validate_group_name(""));
        assert!(!validate_group_name(".comp.test")); // leading dot
        assert!(!validate_group_name("comp.test.")); // trailing dot
        assert!(!validate_group_name("comp..test")); // empty component
        assert!(!validate_group_name("1comp.test")); // starts with digit
        assert!(!validate_group_name("comp/test")); // invalid char
    }
}
