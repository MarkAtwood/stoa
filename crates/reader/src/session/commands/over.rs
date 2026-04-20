use crate::session::response::Response;
use crate::store::overview::OverviewRecord;

/// Format one OVER/XOVER result line from an OverviewRecord.
///
/// Tab-separated per RFC 3977 §8.3.2:
/// `number\tsubject\tfrom\tdate\tmessage-id\treferences\t:bytes\t:lines`
pub fn format_overview_line(record: &OverviewRecord) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        record.article_number,
        record.subject,
        record.from,
        record.date,
        record.message_id,
        record.references,
        record.byte_count,
        record.line_count,
    )
}

/// OVER [range]: return overview for the given pre-fetched records.
///
/// Responds with code 224 and one tab-separated line per article.
/// An empty slice produces a 224 response with no body lines.
pub fn over_response(records: &[OverviewRecord]) -> Response {
    let body = records.iter().map(format_overview_line).collect();
    Response {
        code: 224,
        text: "Overview information follows".to_string(),
        body,
    }
}

/// XOVER [range]: legacy alias for OVER; identical response format and code.
pub fn xover_response(records: &[OverviewRecord]) -> Response {
    over_response(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(num: u64, subject: &str) -> OverviewRecord {
        OverviewRecord {
            article_number: num,
            subject: subject.into(),
            from: "user@example.com".into(),
            date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
            message_id: format!("<{num}@example.com>"),
            references: "".into(),
            byte_count: 100,
            line_count: 5,
        }
    }

    #[test]
    fn format_line_tab_separated() {
        let rec = make_record(1, "Test Subject");
        let line = format_overview_line(&rec);
        assert_eq!(line.chars().filter(|&c| c == '\t').count(), 7);
    }

    #[test]
    fn format_line_article_number() {
        let rec = make_record(42, "Some Subject");
        let line = format_overview_line(&rec);
        assert!(line.starts_with("42\t"));
    }

    #[test]
    fn over_response_code_224() {
        let records = vec![make_record(1, "Hello")];
        let resp = over_response(&records);
        assert_eq!(resp.code, 224);
    }

    #[test]
    fn xover_response_code_224() {
        let records = vec![make_record(1, "Hello")];
        let resp = xover_response(&records);
        assert_eq!(resp.code, 224);
    }

    #[test]
    fn over_response_empty() {
        let resp = over_response(&[]);
        assert_eq!(resp.code, 224);
        assert!(resp.body.is_empty());
        let rendered = resp.to_string();
        assert!(rendered.starts_with("224 "));
        // No body lines; Display does not emit ".\r\n" for empty body.
        assert!(!rendered.contains(".\r\n"));
    }

    #[test]
    fn over_response_three_records() {
        let records = vec![
            make_record(1, "First"),
            make_record(2, "Second"),
            make_record(3, "Third"),
        ];
        let resp = over_response(&records);
        assert_eq!(resp.code, 224);
        assert_eq!(resp.body.len(), 3);
        let rendered = resp.to_string();
        assert!(rendered.ends_with(".\r\n"));
    }

    #[test]
    fn xover_same_as_over() {
        let records = vec![make_record(7, "Same"), make_record(8, "Output")];
        assert_eq!(over_response(&records), xover_response(&records));
    }
}
