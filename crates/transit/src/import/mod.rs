pub mod ihave_push;
pub mod mbox;
pub mod reindex;
pub mod suck_pull;

/// Parse the 3-digit NNTP response code from the start of a response line.
///
/// Returns 0 if the line is too short or the first three characters are not digits.
pub(crate) fn parse_nntp_response_code(line: &str) -> u16 {
    line.get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}
