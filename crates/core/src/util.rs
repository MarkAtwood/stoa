//! Shared utility functions used across crates.

/// Format a Unix timestamp (seconds since epoch) as an RFC 2822 date string.
///
/// Output format: `Www, DD Mon YYYY HH:MM:SS +0000`
///
/// Uses the Rata Die civil-calendar algorithm; no external date library required.
pub fn epoch_to_rfc2822(secs: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let s = secs;
    let days_since_epoch = s.div_euclid(86400);
    let day_secs = s.rem_euclid(86400) as u32;
    let sec = day_secs % 60;
    let min = (day_secs / 60) % 60;
    let hour = day_secs / 3600;
    // Jan 1 1970 was a Thursday (index 0).
    let wday = ((days_since_epoch % 7 + 7) % 7) as usize;

    // Civil date from days since epoch (Rata Die algorithm).
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

/// Split raw article bytes at the blank-line header/body separator.
///
/// Returns `Some((header_bytes, body_bytes))` where neither slice includes the
/// separator itself.  Searches for `\r\n\r\n` first (canonical NNTP CRLF), then
/// falls back to `\n\n`.  Returns `None` if no separator is found.
pub fn split_headers_body(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    for i in 0..bytes.len().saturating_sub(3) {
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return Some((&bytes[..i], &bytes[i + 4..]));
        }
    }
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i..].starts_with(b"\n\n") {
            return Some((&bytes[..i], &bytes[i + 2..]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── epoch_to_rfc2822 ──────────────────────────────────────────────────────

    #[test]
    fn epoch_zero_is_thu_01_jan_1970() {
        // Unix epoch (0) is Thursday, 1 January 1970 00:00:00 UTC.
        assert_eq!(epoch_to_rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    #[test]
    fn known_timestamp_formats_correctly() {
        // 2024-04-22 12:34:56 UTC, verified against an independent reference:
        // Python: datetime.utcfromtimestamp(1713789296).strftime('%a, %d %b %Y %H:%M:%S +0000')
        // → 'Mon, 22 Apr 2024 12:34:56 +0000'
        assert_eq!(
            epoch_to_rfc2822(1_713_789_296),
            "Mon, 22 Apr 2024 12:34:56 +0000"
        );
    }

    #[test]
    fn negative_one_second_is_23_59_59() {
        // secs = -1 → 1969-12-31 23:59:59 UTC
        // Oracle: Python datetime.utcfromtimestamp(-1).strftime('%a, %d %b %Y %H:%M:%S +0000')
        // → 'Wed, 31 Dec 1969 23:59:59 +0000'
        assert_eq!(epoch_to_rfc2822(-1), "Wed, 31 Dec 1969 23:59:59 +0000");
    }

    #[test]
    fn negative_3661_seconds_is_22_58_59() {
        // secs = -3661 → 1969-12-31 22:58:59 UTC
        // Oracle: Python datetime.utcfromtimestamp(-3661).strftime('%a, %d %b %Y %H:%M:%S +0000')
        // → 'Wed, 31 Dec 1969 22:58:59 +0000'
        assert_eq!(epoch_to_rfc2822(-3661), "Wed, 31 Dec 1969 22:58:59 +0000");
    }

    #[test]
    fn zero_seconds_regression() {
        // Regression: rem_euclid must not break the epoch itself.
        assert_eq!(epoch_to_rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    // ── split_headers_body ────────────────────────────────────────────────────

    #[test]
    fn crlf_separator_splits_correctly() {
        let bytes = b"From: a@b.com\r\nSubject: Hi\r\n\r\nBody text.\r\n";
        let (headers, body) = split_headers_body(bytes).expect("must find separator");
        assert_eq!(headers, b"From: a@b.com\r\nSubject: Hi");
        assert_eq!(body, b"Body text.\r\n");
    }

    #[test]
    fn lf_separator_splits_correctly() {
        let bytes = b"From: a@b.com\nSubject: Hi\n\nBody text.\n";
        let (headers, body) = split_headers_body(bytes).expect("must find separator");
        assert_eq!(headers, b"From: a@b.com\nSubject: Hi");
        assert_eq!(body, b"Body text.\n");
    }

    #[test]
    fn crlf_takes_priority_over_lf() {
        // Article with \r\n\r\n: must not split on any embedded \n\n.
        let bytes = b"X: y\r\n\r\nbody\n\nnot a sep";
        let (headers, body) = split_headers_body(bytes).expect("must find separator");
        assert_eq!(headers, b"X: y");
        assert_eq!(body, b"body\n\nnot a sep");
    }

    #[test]
    fn no_separator_returns_none() {
        let bytes = b"From: a@b.com\r\nSubject: Hi\r\n";
        assert!(split_headers_body(bytes).is_none());
    }

    #[test]
    fn empty_body_after_separator() {
        let bytes = b"From: a@b.com\r\n\r\n";
        let (headers, body) = split_headers_body(bytes).expect("must find separator");
        assert_eq!(headers, b"From: a@b.com");
        assert_eq!(body, b"");
    }
}
