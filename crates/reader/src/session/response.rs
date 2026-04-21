use std::fmt;

/// An NNTP response with a numeric code, a text message, and an optional
/// multi-line body.
///
/// `Display` formats as `"NNN text\r\n"` for single-line responses, or
/// `"NNN text\r\n<body lines>\r\n.\r\n"` for multi-line responses, per
/// RFC 3977 §3.2.
///
/// `multiline` must be `true` whenever the RFC requires a dot-terminated
/// body, including when that body is empty (e.g. LIST ACTIVE on a server
/// with no groups). Single-line responses leave it `false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub code: u16,
    pub text: String,
    /// Multi-line body lines (without CRLF).
    pub body: Vec<String>,
    /// True iff the response uses dot-termination per RFC 3977 §3.2.
    pub multiline: bool,
}

impl Response {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self { code, text: text.into(), body: vec![], multiline: false }
    }

    fn new_multiline(code: u16, text: impl Into<String>, body: Vec<String>) -> Self {
        Self { code, text: text.into(), body, multiline: true }
    }

    // --- RFC 3977 standard responses ---

    pub fn service_available_posting() -> Self {
        Self::new(200, "Service available, posting allowed")
    }
    pub fn service_available_posting_allowed() -> Self {
        Self::service_available_posting()
    }
    pub fn service_available_no_posting() -> Self {
        Self::new(201, "Service available, posting prohibited")
    }
    pub fn service_available_posting_prohibited() -> Self {
        Self::service_available_no_posting()
    }
    /// Returns a CAPABILITIES response with only the VERSION 2 line.
    /// Use `capabilities_with_ctx` to build the full list from session state.
    pub fn capabilities() -> Self {
        Self::new(101, "Capability list follows")
    }

    /// Returns a fully-populated CAPABILITIES response per RFC 3977 §5.2.
    ///
    /// `posting_allowed`: include `POST` capability.
    /// `auth_required`: include `AUTHINFO USER` capability.
    /// `starttls_available`: include `STARTTLS` capability (plain-text connection with TLS configured).
    pub fn capabilities_with_ctx(
        posting_allowed: bool,
        auth_required: bool,
        starttls_available: bool,
    ) -> Self {
        let mut caps = vec![
            "VERSION 2".to_string(),
            "READER".to_string(),
            "OVER".to_string(),
            "HDR".to_string(),
            "LIST ACTIVE NEWSGROUPS".to_string(),
            // CID extension capabilities (ADR-0007)
            "XCID".to_string(),
            "XVERIFY".to_string(),
            "X-CID-LOCATOR".to_string(),
        ];
        if starttls_available {
            caps.push("STARTTLS".to_string());
        }
        if posting_allowed {
            caps.push("POST".to_string());
        }
        if auth_required {
            caps.push("AUTHINFO USER".to_string());
        }
        Self::new_multiline(101, "Capability list follows", caps)
    }
    pub fn tls_proceed() -> Self {
        Self::new(382, "Continue with TLS negotiation")
    }
    pub fn tls_not_available() -> Self {
        Self::new(580, "Can not initiate TLS negotiation")
    }
    /// Build a Response by parsing a static `"NNN text\r\n"` string.
    ///
    /// Used to convert the `&'static str` returned by `authinfo_response`
    /// into a `Response` without duplicating the response text.
    ///
    /// # Panics
    /// Panics in debug builds if the string does not start with a 3-digit code.
    /// Only call with known-good static strings from the `auth` module.
    pub fn from_static_str(s: &'static str) -> Self {
        let code: u16 = s[..3].parse().expect("authinfo_response must start with 3-digit code");
        let text = s[4..].trim_end_matches(['\r', '\n']).to_string();
        Self::new(code, text)
    }
    pub fn no_group_selected() -> Self {
        Self::no_newsgroup_selected()
    }
    pub fn closing_connection() -> Self {
        Self::new(205, "Closing connection")
    }
    pub fn group_selected(group: &str, count: u64, low: u64, high: u64) -> Self {
        Self::new(211, format!("{count} {low} {high} {group}"))
    }
    pub fn information_follows() -> Self {
        Self::new(215, "Information follows")
    }
    pub fn list_active(body: Vec<String>) -> Self {
        Self::new_multiline(215, "list of newsgroups follows", body)
    }
    pub fn list_newsgroups(body: Vec<String>) -> Self {
        Self::new_multiline(215, "descriptions of newsgroups follow", body)
    }
    pub fn newgroups(body: Vec<String>) -> Self {
        Self::new_multiline(231, "list of new newsgroups follows", body)
    }
    pub fn newnews(body: Vec<String>) -> Self {
        Self::new_multiline(230, "list of new articles follows", body)
    }
    pub fn article_exists(number: u64, msgid: &str) -> Self {
        Self::new(223, format!("{number} {msgid} Article exists"))
    }
    pub fn article_follows() -> Self {
        Self::new(220, "Article follows")
    }
    pub fn headers_follow() -> Self {
        Self::new(221, "Headers follow")
    }
    pub fn body_follows() -> Self {
        Self::new(222, "Body follows")
    }
    pub fn overview_follows() -> Self {
        Self::new(224, "Overview info follows")
    }
    pub fn hdr_follows(body: Vec<String>) -> Self {
        Self::new_multiline(225, "headers follow", body)
    }
    pub fn xhdr_follows(body: Vec<String>) -> Self {
        Self::new_multiline(221, "Headers follow", body)
    }
    pub fn list_overview_fmt(body: Vec<String>) -> Self {
        Self::new_multiline(215, "Order of fields in overview database.", body)
    }
    pub fn authentication_accepted() -> Self {
        Self::new(281, "Authentication accepted")
    }
    pub fn send_article() -> Self {
        Self::new(340, "Send article to be posted")
    }
    pub fn enter_password() -> Self {
        Self::new(381, "Enter password")
    }
    pub fn service_unavailable() -> Self {
        Self::new(400, "Service temporarily unavailable")
    }
    pub fn no_such_newsgroup() -> Self {
        Self::new(411, "No such newsgroup")
    }
    pub fn no_newsgroup_selected() -> Self {
        Self::new(412, "No newsgroup selected")
    }
    pub fn current_article_invalid() -> Self {
        Self::new(420, "Current article number is invalid")
    }
    pub fn no_next_article() -> Self {
        Self::new(421, "No next article")
    }
    pub fn no_previous_article() -> Self {
        Self::new(422, "No previous article")
    }
    pub fn no_article_with_number() -> Self {
        Self::new(423, "No article with that number")
    }
    pub fn no_article_with_message_id() -> Self {
        Self::new(430, "No article with that message-ID")
    }
    pub fn article_not_wanted() -> Self {
        Self::new(435, "Article not wanted")
    }
    pub fn transfer_not_possible() -> Self {
        Self::new(436, "Transfer not possible")
    }
    pub fn posting_not_permitted() -> Self {
        Self::new(440, "Posting not permitted")
    }
    pub fn posting_failed() -> Self {
        Self::new(441, "Posting failed")
    }
    pub fn authentication_required() -> Self {
        Self::new(480, "Authentication required")
    }
    pub fn authentication_failed() -> Self {
        Self::new(481, "Authentication failed")
    }
    pub fn authentication_out_of_sequence() -> Self {
        Self::new(482, "Authentication commands issued out of sequence")
    }
    pub fn unknown_command() -> Self {
        Self::new(500, "Unknown command")
    }
    pub fn syntax_error() -> Self {
        Self::new(501, "Syntax error in command")
    }
    pub fn command_unavailable() -> Self {
        Self::new(502, "Command unavailable")
    }
    pub fn program_fault() -> Self {
        Self::new(503, "Program fault")
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}\r\n", self.code, self.text)?;
        for line in &self.body {
            write!(f, "{line}\r\n")?;
        }
        if self.multiline {
            write!(f, ".\r\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_with_crlf() {
        let r = Response::new(200, "Service available, posting allowed");
        assert_eq!(r.to_string(), "200 Service available, posting allowed\r\n");
    }

    #[test]
    fn group_selected_format() {
        let r = Response::group_selected("comp.lang.rust", 42, 1, 42);
        assert_eq!(r.to_string(), "211 42 1 42 comp.lang.rust\r\n");
    }

    #[test]
    fn capabilities_with_ctx_code_is_101() {
        assert_eq!(Response::capabilities_with_ctx(true, false, false).code, 101);
        assert_eq!(Response::capabilities_with_ctx(false, true, false).code, 101);
    }

    #[test]
    fn capabilities_with_ctx_multiline_display() {
        let r = Response::capabilities_with_ctx(false, false, false);
        let s = r.to_string();
        assert!(s.starts_with("101 Capability list follows\r\n"));
        assert!(s.contains("VERSION 2\r\n"));
        assert!(s.ends_with(".\r\n"));
    }

    #[test]
    fn capabilities_with_ctx_starttls_included_when_available() {
        let r = Response::capabilities_with_ctx(false, false, true);
        assert!(r.body.iter().any(|l| l == "STARTTLS"), "should include STARTTLS");
    }

    #[test]
    fn capabilities_with_ctx_starttls_excluded_when_not_available() {
        let r = Response::capabilities_with_ctx(false, false, false);
        assert!(!r.body.iter().any(|l| l == "STARTTLS"), "should not include STARTTLS");
    }

    #[test]
    fn all_constructor_codes() {
        assert_eq!(Response::service_available_posting().code, 200);
        assert_eq!(Response::service_available_no_posting().code, 201);
        assert_eq!(Response::closing_connection().code, 205);
        assert_eq!(Response::information_follows().code, 215);
        assert_eq!(Response::article_exists(1, "<x@y>").code, 223);
        assert_eq!(Response::article_follows().code, 220);
        assert_eq!(Response::headers_follow().code, 221);
        assert_eq!(Response::body_follows().code, 222);
        assert_eq!(Response::overview_follows().code, 224);
        assert_eq!(Response::authentication_accepted().code, 281);
        assert_eq!(Response::send_article().code, 340);
        assert_eq!(Response::enter_password().code, 381);
        assert_eq!(Response::service_unavailable().code, 400);
        assert_eq!(Response::no_such_newsgroup().code, 411);
        assert_eq!(Response::no_newsgroup_selected().code, 412);
        assert_eq!(Response::current_article_invalid().code, 420);
        assert_eq!(Response::no_next_article().code, 421);
        assert_eq!(Response::no_previous_article().code, 422);
        assert_eq!(Response::no_article_with_number().code, 423);
        assert_eq!(Response::no_article_with_message_id().code, 430);
        assert_eq!(Response::article_not_wanted().code, 435);
        assert_eq!(Response::transfer_not_possible().code, 436);
        assert_eq!(Response::posting_not_permitted().code, 440);
        assert_eq!(Response::posting_failed().code, 441);
        assert_eq!(Response::authentication_required().code, 480);
        assert_eq!(Response::authentication_failed().code, 481);
        assert_eq!(Response::authentication_out_of_sequence().code, 482);
        assert_eq!(Response::tls_not_available().code, 580);
        assert_eq!(Response::unknown_command().code, 500);
        assert_eq!(Response::syntax_error().code, 501);
        assert_eq!(Response::command_unavailable().code, 502);
        assert_eq!(Response::program_fault().code, 503);
    }
}
