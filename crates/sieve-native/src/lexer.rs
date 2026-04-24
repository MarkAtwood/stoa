// SPDX-License-Identifier: MIT

//! Tokenizer for the Sieve scripting language (RFC 5228).

use crate::parse_error::ParseError;

/// Tokens produced by the Sieve lexer.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// An identifier: `[a-zA-Z_][a-zA-Z0-9_]*`
    Word(String),
    /// A tagged argument with the leading `:` stripped: `:is` → `Tag("is")`
    Tag(String),
    /// A string literal with escape sequences resolved.
    StringLit(String),
    /// A numeric literal, with optional size multiplier already applied.
    Number(u64),
    LBracket,
    RBracket,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Semicolon,
    Comma,
}

/// Tokenize a Sieve script source string into a flat token list.
///
/// # Errors
///
/// Returns a [`ParseError`] on any unrecognised character or malformed token.
pub fn tokenize(src: &str) -> Result<Vec<Token>, ParseError> {
    let chars: Vec<char> = src.chars().collect();
    let len = chars.len();
    let mut pos = 0usize;
    // 1-based line/col tracking for error messages.
    let mut line = 1usize;
    let mut col = 1usize;

    // Advance pos by one character, updating line/col.
    macro_rules! advance {
        () => {{
            let ch = chars[pos];
            pos += 1;
            if ch == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            ch
        }};
    }

    macro_rules! err {
        ($msg:expr) => {
            return Err(ParseError {
                message: $msg.to_string(),
                line,
                col,
            })
        };
    }

    let mut tokens: Vec<Token> = Vec::new();

    while pos < len {
        let ch = chars[pos];

        // --- Whitespace ---
        if ch.is_ascii_whitespace() {
            advance!();
            continue;
        }

        // --- Line comment ---
        if ch == '#' {
            while pos < len && chars[pos] != '\n' {
                advance!();
            }
            continue;
        }

        // --- Block comment ---
        if ch == '/' && pos + 1 < len && chars[pos + 1] == '*' {
            let err_line = line;
            let err_col = col;
            advance!(); // '/'
            advance!(); // '*'
            loop {
                if pos >= len {
                    return Err(ParseError {
                        message: "unterminated block comment".to_string(),
                        line: err_line,
                        col: err_col,
                    });
                }
                if chars[pos] == '*' && pos + 1 < len && chars[pos + 1] == '/' {
                    advance!(); // '*'
                    advance!(); // '/'
                    break;
                }
                advance!();
            }
            continue;
        }

        // --- Punctuation ---
        match ch {
            '[' => {
                advance!();
                tokens.push(Token::LBracket);
                continue;
            }
            ']' => {
                advance!();
                tokens.push(Token::RBracket);
                continue;
            }
            '(' => {
                advance!();
                tokens.push(Token::LParen);
                continue;
            }
            ')' => {
                advance!();
                tokens.push(Token::RParen);
                continue;
            }
            '{' => {
                advance!();
                tokens.push(Token::LBrace);
                continue;
            }
            '}' => {
                advance!();
                tokens.push(Token::RBrace);
                continue;
            }
            ';' => {
                advance!();
                tokens.push(Token::Semicolon);
                continue;
            }
            ',' => {
                advance!();
                tokens.push(Token::Comma);
                continue;
            }
            _ => {}
        }

        // --- Tag: colon followed by identifier ---
        if ch == ':' {
            let err_line = line;
            let err_col = col;
            advance!(); // consume ':'
            if pos >= len || !(chars[pos].is_ascii_alphabetic() || chars[pos] == '_') {
                return Err(ParseError {
                    message: "expected identifier after ':'".to_string(),
                    line: err_line,
                    col: err_col,
                });
            }
            let mut ident = String::new();
            while pos < len && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_') {
                ident.push(chars[pos]);
                advance!();
            }
            tokens.push(Token::Tag(ident));
            continue;
        }

        // --- Number ---
        if ch.is_ascii_digit() {
            let mut num_str = String::new();
            while pos < len && chars[pos].is_ascii_digit() {
                num_str.push(chars[pos]);
                advance!();
            }
            let base: u64 = num_str.parse().map_err(|_| ParseError {
                message: format!("number overflow: {num_str}"),
                line,
                col,
            })?;
            let multiplier: u64 = if pos < len {
                match chars[pos] {
                    'K' | 'k' => {
                        advance!();
                        1024
                    }
                    'M' | 'm' => {
                        advance!();
                        1024 * 1024
                    }
                    'G' | 'g' => {
                        advance!();
                        1024 * 1024 * 1024
                    }
                    _ => 1,
                }
            } else {
                1
            };
            let value = base.checked_mul(multiplier).ok_or_else(|| ParseError {
                message: format!("number overflow applying multiplier to {base}"),
                line,
                col,
            })?;
            tokens.push(Token::Number(value));
            continue;
        }

        // --- Word: identifier ---
        if ch.is_ascii_alphabetic() || ch == '_' {
            let mut word = String::new();
            while pos < len && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_') {
                word.push(chars[pos]);
                advance!();
            }
            // Check for multiline string: word "text" followed immediately by ':'
            if word == "text" && pos < len && chars[pos] == ':' {
                let err_line = line;
                let err_col = col;
                advance!(); // consume ':'
                            // Consume optional CR/LF or CRLF to end the `text:` header line.
                if pos < len && chars[pos] == '\r' {
                    advance!();
                }
                if pos < len && chars[pos] == '\n' {
                    advance!();
                } else {
                    return Err(ParseError {
                        message: "expected newline after 'text:'".to_string(),
                        line: err_line,
                        col: err_col,
                    });
                }
                // Collect lines until a line that is exactly "." (RFC 5228 §2.3.1).
                let mut content = String::new();
                loop {
                    if pos >= len {
                        return Err(ParseError {
                            message: "unterminated multiline string (missing '.' terminator)"
                                .to_string(),
                            line: err_line,
                            col: err_col,
                        });
                    }
                    // Read a full line.
                    let mut line_buf = String::new();
                    while pos < len && chars[pos] != '\n' {
                        line_buf.push(chars[pos]);
                        advance!();
                    }
                    // Consume the newline.
                    if pos < len {
                        advance!(); // '\n'
                    }
                    // Strip trailing CR if present (CRLF line ending).
                    let line_trimmed = line_buf.strip_suffix('\r').unwrap_or(&line_buf);
                    // Terminator line.
                    if line_trimmed == "." {
                        break;
                    }
                    // Dot-stuffing: a leading ".." becomes ".".
                    let stored = if let Some(rest) = line_trimmed.strip_prefix("..") {
                        format!(".{rest}")
                    } else {
                        line_trimmed.to_string()
                    };
                    if !content.is_empty() {
                        content.push('\n');
                    }
                    content.push_str(&stored);
                }
                tokens.push(Token::StringLit(content));
                continue;
            }
            tokens.push(Token::Word(word));
            continue;
        }

        // --- Quoted string ---
        if ch == '"' {
            let err_line = line;
            let err_col = col;
            advance!(); // consume opening '"'
            let mut s = String::new();
            loop {
                if pos >= len {
                    return Err(ParseError {
                        message: "unterminated string literal".to_string(),
                        line: err_line,
                        col: err_col,
                    });
                }
                let c = chars[pos];
                if c == '"' {
                    advance!();
                    break;
                }
                if c == '\\' {
                    advance!(); // consume '\'
                    if pos >= len {
                        return Err(ParseError {
                            message: "unexpected end of input after backslash".to_string(),
                            line: err_line,
                            col: err_col,
                        });
                    }
                    let escaped = chars[pos];
                    advance!();
                    match escaped {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        // RFC 5228 §2.3.1: only \" and \\ are defined escape sequences;
                        // other backslash sequences pass through unchanged.
                        other => {
                            s.push('\\');
                            s.push(other);
                        }
                    }
                    continue;
                }
                s.push(c);
                advance!();
            }
            tokens.push(Token::StringLit(s));
            continue;
        }

        err!(format!("unexpected character '{ch}'"));
    }

    Ok(tokens)
}
