use crate::{session::response::Response, store::overview::OverviewRecord};

/// HDR response record for a single article.
pub struct HdrRecord {
    pub article_number: u64,
    pub value: String,
}

/// Build the shared body lines for HDR and XHDR responses.
///
/// Returns one `"{number} {value}"` string per record.
fn hdr_body(records: &[HdrRecord]) -> Vec<String> {
    records
        .iter()
        .map(|r| format!("{} {}", r.article_number, r.value))
        .collect()
}

/// Format HDR response per RFC 3977 §8.5.
///
/// Returns 225 with one line per article `{number} {value}`, dot-terminated.
pub fn hdr_response(records: &[HdrRecord]) -> Response {
    Response::hdr_follows(hdr_body(records))
}

/// Format XHDR response (RFC 2980 legacy predecessor to HDR).
///
/// Identical to HDR but returns code 221. Not advertised in CAPABILITIES.
pub fn xhdr_response(records: &[HdrRecord]) -> Response {
    Response::xhdr_follows(hdr_body(records))
}

/// Extract a named field from an `OverviewRecord`.
///
/// Field names are matched case-insensitively. Supported fields:
/// `Subject`, `From`, `Date`, `Message-ID`, `References`, `:bytes`, `:lines`.
/// Returns `None` for unknown field names.
pub fn extract_field(record: &OverviewRecord, field: &str) -> Option<String> {
    match field.to_ascii_lowercase().as_str() {
        "subject" => Some(record.subject.clone()),
        "from" => Some(record.from.clone()),
        "date" => Some(record.date.clone()),
        "message-id" => Some(record.message_id.clone()),
        "references" => Some(record.references.clone()),
        ":bytes" => Some(record.byte_count.to_string()),
        ":lines" => Some(record.line_count.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> OverviewRecord {
        OverviewRecord {
            article_number: 42,
            subject: "Test Subject".to_string(),
            from: "alice@example.com".to_string(),
            date: "Mon, 01 Jan 2026 00:00:00 +0000".to_string(),
            message_id: "<42@example.com>".to_string(),
            references: "<41@example.com>".to_string(),
            byte_count: 512,
            line_count: 10,
        }
    }

    #[test]
    fn hdr_response_code() {
        let records = vec![HdrRecord {
            article_number: 1,
            value: "hello".to_string(),
        }];
        assert_eq!(hdr_response(&records).code, 225);
    }

    #[test]
    fn hdr_response_lines_format() {
        let records = vec![HdrRecord {
            article_number: 42,
            value: "Test Subject".to_string(),
        }];
        let resp = hdr_response(&records);
        assert_eq!(resp.body.len(), 1);
        assert_eq!(resp.body[0], "42 Test Subject");
    }

    #[test]
    fn hdr_response_empty() {
        let resp = hdr_response(&[]);
        assert_eq!(resp.code, 225);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn extract_subject_field() {
        let rec = sample_record();
        assert_eq!(
            extract_field(&rec, "Subject"),
            Some("Test Subject".to_string())
        );
    }

    #[test]
    fn extract_from_field() {
        let rec = sample_record();
        assert_eq!(
            extract_field(&rec, "From"),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn extract_bytes_field() {
        let rec = sample_record();
        assert_eq!(extract_field(&rec, ":bytes"), Some("512".to_string()));
    }

    #[test]
    fn extract_unknown_field_returns_none() {
        let rec = sample_record();
        assert_eq!(extract_field(&rec, "X-Foo"), None);
    }

    #[test]
    fn xhdr_response_code_is_221() {
        let records = vec![HdrRecord {
            article_number: 1,
            value: "hello".to_string(),
        }];
        assert_eq!(xhdr_response(&records).code, 221);
    }

    #[test]
    fn xhdr_response_has_same_body_as_hdr() {
        let records = vec![
            HdrRecord {
                article_number: 10,
                value: "foo".to_string(),
            },
            HdrRecord {
                article_number: 11,
                value: "bar".to_string(),
            },
        ];
        let hdr = hdr_response(&records);
        let xhdr = xhdr_response(&records);
        assert_eq!(hdr.body, xhdr.body);
        assert_ne!(hdr.code, xhdr.code);
    }

    #[test]
    fn xhdr_empty_records() {
        let resp = xhdr_response(&[]);
        assert_eq!(resp.code, 221);
        assert!(resp.body.is_empty());
    }
}
