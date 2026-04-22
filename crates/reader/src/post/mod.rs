pub mod did_passthrough;
pub mod ipfs_write;
pub mod log_append;
pub mod pipeline;
pub mod sign;
pub mod validate_headers;

/// Find the byte offset of the first byte of the body in an RFC 5322 article.
///
/// Scans `bytes` for the blank-line separator between headers and body.
/// Returns the index of the first byte **after** the separator (i.e. the first
/// byte of the body), or `None` if no blank line is found.
///
/// Both `\r\n\r\n` (canonical NNTP/CRLF) and `\n\n` (bare-LF) are recognised.
/// `\r\n\r\n` is tried first so that well-formed NNTP articles always use the
/// correct offset.
pub fn find_header_boundary(bytes: &[u8]) -> Option<usize> {
    for i in 0..bytes.len().saturating_sub(3) {
        if bytes[i..].starts_with(b"\r\n\r\n") {
            return Some(i + 4);
        }
    }
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i..].starts_with(b"\n\n") {
            return Some(i + 2);
        }
    }
    None
}
