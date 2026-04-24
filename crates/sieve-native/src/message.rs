// SPDX-License-Identifier: MIT

//! RFC 5322 message header extraction utilities.

/// Extract all headers from raw RFC 5322 message bytes.
///
/// Returns `Vec<(lowercase_name, value)>`.  Folds continuation lines
/// (lines whose first character is whitespace) into the preceding header's
/// value.  Stops at the first blank line (the header/body separator).
///
/// Non-UTF-8 bytes are replaced with the Unicode replacement character so
/// that the function never fails on a structurally legal but non-ASCII
/// message.
pub fn extract_headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let mut headers: Vec<(String, String)> = Vec::new();

    for line in text.split('\n') {
        // Strip a trailing CR so we handle both CRLF and LF line endings.
        let line = line.strip_suffix('\r').unwrap_or(line);

        // Blank line = end of headers.
        if line.is_empty() {
            break;
        }

        // Continuation line: starts with whitespace.
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }

        // New header: must contain ':'.
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_ascii_lowercase();
            let value = line[colon + 1..].trim().to_string();
            if !name.is_empty() {
                headers.push((name, value));
            }
        }
        // Lines with no ':' and no leading whitespace are malformed; skip.
    }

    headers
}

/// Extract one part of an RFC 5322 address string.
///
/// `part`:
/// - `"localpart"` — the text before `@`
/// - `"domain"`    — the text after `@`
/// - anything else (including `"all"`) — the full address string
///
/// The address is first stripped of angle-bracket delimiters and any
/// display-name prefix before extracting the part.  Returns `""` on a
/// malformed address when `localpart` or `domain` was requested.
pub fn address_part(addr: &str, part: &str) -> String {
    // Normalise: strip display name and angle brackets.
    let bare = bare_address(addr);

    match part {
        "localpart" => {
            if let Some(at) = bare.rfind('@') {
                bare[..at].to_string()
            } else {
                String::new()
            }
        }
        "domain" => {
            if let Some(at) = bare.rfind('@') {
                bare[at + 1..].to_string()
            } else {
                String::new()
            }
        }
        _ => bare,
    }
}

/// Return the bare `local@domain` address from an RFC 5322 address string,
/// stripping any display name and angle brackets.
fn bare_address(addr: &str) -> String {
    let addr = addr.trim();
    // If there is a `<...>` section, use what is inside it.
    if let Some(start) = addr.rfind('<') {
        if let Some(end) = addr[start..].find('>') {
            return addr[start + 1..start + end].trim().to_string();
        }
    }
    addr.to_string()
}
