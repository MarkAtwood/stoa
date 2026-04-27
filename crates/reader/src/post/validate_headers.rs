use crate::session::response::Response;
use mailparse::parse_headers;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use stoa_core::article::GroupName;

/// Maximum header line length per RFC 5322 §2.1.1.
const MAX_HEADER_LINE_BYTES: usize = 998;

/// Window for Date header acceptance: ±24 hours in seconds.
const DATE_WINDOW_SECS: i64 = 86_400;

/// Validate that raw article header bytes contain all required RFC 5536 headers
/// and that their values are well-formed.
///
/// Returns `Ok(())` if all checks pass, or `Err(Response)` with a 441 response
/// and specific error text if any check fails. Checks run in the order specified
/// by the function documentation and the first failure is returned.
pub fn validate_post_headers(header_bytes: &[u8]) -> Result<(), Response> {
    check_line_lengths(header_bytes)?;

    let headers = parse_header_map(header_bytes)?;

    check_mandatory_headers(&headers)?;
    check_newsgroups(&headers)?;
    check_date(&headers)?;
    check_message_id(&headers)?;

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Check that no raw header line exceeds 998 bytes (RFC 5322 §2.1.1).
///
/// Splits on `\n` (handles both CRLF and bare LF). The terminating `\r` is
/// included in the length measurement, which is conservative but correct.
fn check_line_lengths(header_bytes: &[u8]) -> Result<(), Response> {
    for line in header_bytes.split(|&b| b == b'\n') {
        if line.len() > MAX_HEADER_LINE_BYTES {
            // Recover a header name for the error message.
            let name = line
                .iter()
                .position(|&b| b == b':')
                .map(|pos| String::from_utf8_lossy(&line[..pos]).into_owned())
                .unwrap_or_else(|| "(unknown)".to_string());
            return Err(Response::new(441, format!("Header field too long: {name}")));
        }
    }
    Ok(())
}

/// Parse the raw header block into a case-folded map of name → list of values.
fn parse_header_map(header_bytes: &[u8]) -> Result<HashMap<String, Vec<String>>, Response> {
    let (parsed, _) = parse_headers(header_bytes)
        .map_err(|_| Response::new(441, "Could not parse article headers"))?;

    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for hdr in &parsed {
        let key = hdr.get_key().to_ascii_lowercase();
        let value = hdr.get_value();
        map.entry(key).or_default().push(value);
    }
    Ok(map)
}

/// Check that all five mandatory RFC 5536 headers are present.
fn check_mandatory_headers(headers: &HashMap<String, Vec<String>>) -> Result<(), Response> {
    for name in &["From", "Date", "Message-ID", "Newsgroups", "Subject"] {
        if !headers.contains_key(&name.to_ascii_lowercase()) {
            return Err(Response::new(
                441,
                format!("Missing required header: {name}"),
            ));
        }
    }
    Ok(())
}

/// Validate every group name in the `Newsgroups` header.
///
/// Group names must be lowercase (POST path is stricter than internal storage).
fn check_newsgroups(headers: &HashMap<String, Vec<String>>) -> Result<(), Response> {
    let values = headers.get("newsgroups").expect("presence checked above");
    for value in values {
        for raw_name in value.split(',') {
            let name = raw_name.trim();
            if name.is_empty() {
                continue;
            }
            // Require all-lowercase: POST ingress is stricter than GroupName::new().
            if name.chars().any(|c| c.is_ascii_uppercase()) {
                return Err(Response::new(
                    441,
                    format!("Invalid group name in Newsgroups: {name}"),
                ));
            }
            if GroupName::new(name).is_err() {
                return Err(Response::new(
                    441,
                    format!("Invalid group name in Newsgroups: {name}"),
                ));
            }
        }
    }
    Ok(())
}

/// Validate the `Date` header: must parse as RFC 2822 and be within ±24 h of now.
///
/// # DECISION (rbe3.67): window check is intentional, not just a parse check
///
/// The 24-hour window is a hard requirement, not just defensive validation.
/// Out-of-range dates corrupt `NEWNEWS` queries (which filter by date) and
/// enable replay injection of old articles.  Relaxing this to parse-only would
/// accept arbitrary-dated articles and break time-based queries.  Do NOT
/// simplify `check_date` to just call `mailparse::dateparse` without the range check.
fn check_date(headers: &HashMap<String, Vec<String>>) -> Result<(), Response> {
    let value = headers
        .get("date")
        .and_then(|v| v.first())
        .expect("presence checked above");

    let ts = mailparse::dateparse(value)
        .map_err(|_| Response::new(441, "Invalid Date header format"))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;

    let delta = (ts - now).abs();
    if delta > DATE_WINDOW_SECS {
        return Err(Response::new(441, "Date header out of acceptable range"));
    }
    Ok(())
}

/// Validate the `Message-ID` header: must be `<local@domain>` with no whitespace.
fn check_message_id(headers: &HashMap<String, Vec<String>>) -> Result<(), Response> {
    let value = headers
        .get("message-id")
        .and_then(|v| v.first())
        .expect("presence checked above");

    if !is_valid_message_id(value) {
        return Err(Response::new(441, "Invalid Message-ID format"));
    }
    Ok(())
}

/// Returns `true` if `id` matches `<local@domain>` with non-empty `local` and
/// `domain`, angle brackets required, no whitespace or additional `<`/`>`.
fn is_valid_message_id(id: &str) -> bool {
    let id = id.trim();
    if !id.starts_with('<') || !id.ends_with('>') {
        return false;
    }
    let inner = &id[1..id.len() - 1];
    // Must not contain further angle brackets.
    if inner.contains('<') || inner.contains('>') {
        return false;
    }
    // Must not contain whitespace or NUL bytes.
    if inner.chars().any(|c| c.is_ascii_whitespace() || c == '\0') {
        return false;
    }
    // Must contain exactly one '@' with non-empty local and domain parts.
    let at_count = inner.chars().filter(|&c| c == '@').count();
    if at_count != 1 {
        return false;
    }
    // split_once is safe: we just confirmed exactly one '@'.
    let (local, domain) = inner.split_once('@').expect("one '@' confirmed above");
    !local.is_empty() && !domain.is_empty()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stoa_core::util::epoch_to_rfc2822;

    /// Build a CRLF-terminated header block from `(name, value)` pairs.
    /// The block ends with a blank line (`\r\n`).
    fn make_headers(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, value) in fields {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// A set of valid mandatory headers with a current-ish Date.
    fn valid_fields() -> Vec<(&'static str, String)> {
        // Build a Date string that is definitely within ±24 h of now.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Format as RFC 2822; httpdate gives us RFC 7231, which mailparse also accepts.
        // Use a fixed-format string relative to now=0 that mailparse can parse.
        // Simplest portable approach: use the actual epoch offset via httpdate.
        let date_str = epoch_to_rfc2822(now);
        vec![
            ("From", "user@example.com".to_string()),
            ("Date", date_str),
            ("Message-ID", "<test@example.com>".to_string()),
            ("Newsgroups", "comp.lang.rust".to_string()),
            ("Subject", "Test subject".to_string()),
        ]
    }

    // ── 1. Valid headers ──────────────────────────────────────────────────────

    #[test]
    fn valid_all_mandatory_fields() {
        let fields: Vec<(&str, String)> = valid_fields();
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let bytes = make_headers(&refs);
        assert_eq!(validate_post_headers(&bytes), Ok(()));
    }

    // ── 2. Missing From ───────────────────────────────────────────────────────

    #[test]
    fn missing_from() {
        let fields: Vec<(&str, String)> = valid_fields()
            .into_iter()
            .filter(|(k, _)| *k != "From")
            .collect();
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let bytes = make_headers(&refs);
        let err = validate_post_headers(&bytes).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("From"),
            "expected 'From' in: {}",
            err.text
        );
    }

    // ── 3. Missing Newsgroups ─────────────────────────────────────────────────

    #[test]
    fn missing_newsgroups() {
        let fields: Vec<(&str, String)> = valid_fields()
            .into_iter()
            .filter(|(k, _)| *k != "Newsgroups")
            .collect();
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let bytes = make_headers(&refs);
        let err = validate_post_headers(&bytes).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("Newsgroups"),
            "expected 'Newsgroups' in: {}",
            err.text
        );
    }

    // ── 4. Invalid group name (uppercase) ─────────────────────────────────────

    #[test]
    fn invalid_group_name_uppercase() {
        let mut fields = valid_fields();
        for (k, v) in &mut fields {
            if *k == "Newsgroups" {
                *v = "Comp.Lang.Rust".to_string();
            }
        }
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let bytes = make_headers(&refs);
        let err = validate_post_headers(&bytes).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("Invalid group name"),
            "expected 'Invalid group name' in: {}",
            err.text
        );
    }

    // ── 5. Invalid Message-ID (no angle brackets) ──────────────────────────────

    #[test]
    fn invalid_message_id_no_brackets() {
        let mut fields = valid_fields();
        for (k, v) in &mut fields {
            if *k == "Message-ID" {
                *v = "test@example.com".to_string();
            }
        }
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let bytes = make_headers(&refs);
        let err = validate_post_headers(&bytes).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("Message-ID"),
            "expected 'Message-ID' in: {}",
            err.text
        );
    }

    // ── 6. Header field over 998 bytes ────────────────────────────────────────

    #[test]
    fn header_field_too_long() {
        let mut fields = valid_fields();
        // Replace Subject with one that is 999 bytes long after "Subject: ".
        // The raw line "Subject: " + value + "\r\n" — value must make total > 998.
        // "Subject: " = 9 bytes, "\r\n" = 2 bytes, so value must be > 998 - 9 - 2 = 987 bytes.
        let long_value = "x".repeat(990);
        for (k, v) in &mut fields {
            if *k == "Subject" {
                *v = long_value.clone();
            }
        }
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let bytes = make_headers(&refs);
        let err = validate_post_headers(&bytes).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("Header field too long"),
            "expected 'Header field too long' in: {}",
            err.text
        );
    }

    // ── 7. Date out of range ──────────────────────────────────────────────────

    #[test]
    fn date_out_of_range() {
        let mut fields = valid_fields();
        for (k, v) in &mut fields {
            if *k == "Date" {
                // Year 2000 is far in the past.
                *v = "Sat, 01 Jan 2000 00:00:00 +0000".to_string();
            }
        }
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let bytes = make_headers(&refs);
        let err = validate_post_headers(&bytes).unwrap_err();
        assert_eq!(err.code, 441);
        assert!(
            err.text.contains("Date header out of acceptable range"),
            "expected date-range error in: {}",
            err.text
        );
    }

    // ── 8. Valid Message-ID with angle brackets ───────────────────────────────

    #[test]
    fn valid_message_id_with_angle_brackets() {
        let fields = valid_fields();
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let bytes = make_headers(&refs);
        // The valid_fields() already uses "<test@example.com>", so this just
        // confirms the happy path for that specific Message-ID.
        assert_eq!(validate_post_headers(&bytes), Ok(()));
    }

    // ── is_valid_message_id unit tests ────────────────────────────────────────

    #[test]
    fn message_id_missing_at() {
        assert!(!is_valid_message_id("<nodomain>"));
    }

    #[test]
    fn message_id_empty_local() {
        assert!(!is_valid_message_id("<@domain>"));
    }

    #[test]
    fn message_id_empty_domain() {
        assert!(!is_valid_message_id("<local@>"));
    }

    #[test]
    fn message_id_whitespace_inside() {
        assert!(!is_valid_message_id("<lo cal@domain>"));
    }

    #[test]
    fn message_id_valid() {
        assert!(is_valid_message_id("<test@example.com>"));
    }

    /// Regression test for 3vye.6: NUL bytes inside the angle brackets must
    /// be rejected.  NUL is not ASCII whitespace so the old whitespace check
    /// alone did not catch it.
    #[test]
    fn message_id_nul_byte_rejected() {
        assert!(!is_valid_message_id("<local\0part@domain>"));
        assert!(!is_valid_message_id("<local@dom\0ain>"));
    }

    /// Regression test for rbe3.30: multiple '@' signs must be rejected.
    ///
    /// Before the fix, `splitn(2, '@')` returned `["local", "dom@extra"]`,
    /// both non-empty, so `<local@dom@extra>` was accepted.
    #[test]
    fn message_id_multiple_at_signs_rejected() {
        // Two '@' signs — must be rejected.
        assert!(!is_valid_message_id("<local@domain@extra>"));
        // Three '@' signs — must be rejected.
        assert!(!is_valid_message_id("<a@b@c>"));
    }
}
