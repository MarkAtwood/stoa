/// Errors from the Tantivy full-text search subsystem.
#[derive(Debug)]
pub enum SearchError {
    /// Underlying Tantivy engine error.
    Tantivy(tantivy::TantivyError),
    /// Query string failed to parse.
    QueryParse(String),
    /// Query string exceeds maximum allowed length.
    QueryTooLong { len: usize, max: usize },
    /// Search index is not available (disabled or not yet initialized).
    Unavailable,
}

impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchError::Tantivy(e) => write!(f, "tantivy error: {e}"),
            SearchError::QueryParse(msg) => write!(f, "query parse error: {msg}"),
            SearchError::QueryTooLong { len, max } => {
                write!(f, "query too long: {len} bytes, max {max}")
            }
            SearchError::Unavailable => write!(f, "search index not available"),
        }
    }
}

impl std::error::Error for SearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SearchError::Tantivy(e) => Some(e),
            _ => None,
        }
    }
}

impl From<tantivy::TantivyError> for SearchError {
    fn from(e: tantivy::TantivyError) -> Self {
        SearchError::Tantivy(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages_are_nonempty() {
        let errors = [
            SearchError::Tantivy(tantivy::TantivyError::SystemError("test".to_owned())),
            SearchError::QueryParse("bad syntax".to_owned()),
            SearchError::QueryTooLong {
                len: 5000,
                max: 4096,
            },
            SearchError::Unavailable,
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "Display for {e:?} must not be empty");
        }
    }
}
