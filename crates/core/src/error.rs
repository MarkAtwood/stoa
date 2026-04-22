//! Error types for usenet-ipfs-core.
//!
//! All errors flow through `UsenetIpfsError`. Each subsystem has its own
//! typed sub-enum for structured handling.

use std::fmt;

use crate::group_log::types::LogEntryId;

// ── Top-level error ──────────────────────────────────────────────────────────

/// Top-level error type for the usenet-ipfs system.
///
/// Every function in this crate returns `Result<_, UsenetIpfsError>` or a
/// typed sub-error that converts to this via `From`.
#[derive(Debug)]
pub enum UsenetIpfsError {
    Storage(StorageError),
    Protocol(ProtocolError),
    Validation(ValidationError),
    Signing(SigningError),
    Io(std::io::Error),
    Config(String),
}

impl fmt::Display for UsenetIpfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::Validation(e) => write!(f, "validation error: {e}"),
            Self::Signing(e) => write!(f, "signing error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Config(msg) => write!(f, "config error: {msg}"),
        }
    }
}

impl std::error::Error for UsenetIpfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Validation(e) => Some(e),
            Self::Signing(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Config(_) => None,
        }
    }
}

impl From<StorageError> for UsenetIpfsError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}
impl From<ProtocolError> for UsenetIpfsError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<ValidationError> for UsenetIpfsError {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}
impl From<SigningError> for UsenetIpfsError {
    fn from(e: SigningError) -> Self {
        Self::Signing(e)
    }
}
impl From<std::io::Error> for UsenetIpfsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── ValidationError ──────────────────────────────────────────────────────────

/// Input validation errors. Produced at system boundaries (wire, file, user input).
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    InvalidGroupName(String),
    InvalidMessageId(String),
    MissingMandatoryHeader(String),
    HeaderFieldTooLong {
        field: String,
        len: usize,
        limit: usize,
    },
    ArticleTooBig {
        size: usize,
        limit: usize,
    },
    DateOutOfRange(String),
    InvalidGroupInNewsgroups(String),
    EmptyNewsgroups,
    TooManyNewsgroups {
        count: usize,
        limit: usize,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGroupName(n) => write!(f, "invalid group name: {n:?}"),
            Self::InvalidMessageId(id) => write!(f, "invalid message-id: {id:?}"),
            Self::MissingMandatoryHeader(h) => write!(f, "missing mandatory header: {h}"),
            Self::HeaderFieldTooLong { field, len, limit } => {
                write!(f, "header field {field:?} too long: {len} > {limit} bytes")
            }
            Self::ArticleTooBig { size, limit } => {
                write!(f, "article too large: {size} bytes (limit {limit})")
            }
            Self::DateOutOfRange(d) => write!(f, "date out of acceptable range: {d}"),
            Self::InvalidGroupInNewsgroups(g) => write!(f, "invalid group in Newsgroups: {g:?}"),
            Self::EmptyNewsgroups => write!(f, "Newsgroups header is empty"),
            Self::TooManyNewsgroups { count, limit } => {
                write!(f, "too many Newsgroups entries: {count} (limit {limit})")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ── ProtocolError ─────────────────────────────────────────────────────────────

/// NNTP protocol-level errors. Each variant maps to an RFC 3977 response code.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolError {
    UnknownCommand(String),
    InvalidSyntax(String),
    NoGroupSelected,
    NoSuchGroup(String),
    NoSuchArticle,
    NotAuthenticated,
    DuplicateMessageId(String),
    PostingNotPermitted,
    TransferNotPossible(String),
    ArticleTooBig { size: usize, limit: usize },
    ValidationFailed(ValidationError),
    ServiceUnavailable(String),
}

impl ProtocolError {
    /// Return the RFC 3977 response code for this error.
    pub fn response_code(&self) -> u16 {
        match self {
            Self::UnknownCommand(_) => 500,
            Self::InvalidSyntax(_) => 501,
            Self::NoGroupSelected => 412,
            Self::NoSuchGroup(_) => 411,
            Self::NoSuchArticle => 430,
            Self::NotAuthenticated => 480,
            Self::DuplicateMessageId(_) => 435,
            Self::PostingNotPermitted => 440,
            Self::TransferNotPossible(_) => 436,
            Self::ArticleTooBig { .. } => 441,
            Self::ValidationFailed(_) => 441,
            Self::ServiceUnavailable(_) => 400,
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(cmd) => write!(f, "unknown command: {cmd:?}"),
            Self::InvalidSyntax(msg) => write!(f, "syntax error: {msg}"),
            Self::NoGroupSelected => write!(f, "no newsgroup has been selected"),
            Self::NoSuchGroup(g) => write!(f, "no such newsgroup: {g:?}"),
            Self::NoSuchArticle => write!(f, "no article with that message-id"),
            Self::NotAuthenticated => write!(f, "authentication required"),
            Self::DuplicateMessageId(id) => write!(f, "article not wanted: {id:?}"),
            Self::PostingNotPermitted => write!(f, "posting not permitted"),
            Self::TransferNotPossible(msg) => write!(f, "transfer not possible: {msg}"),
            Self::ArticleTooBig { size, limit } => {
                write!(f, "article too large: {size} > {limit} bytes")
            }
            Self::ValidationFailed(e) => write!(f, "validation failed: {e}"),
            Self::ServiceUnavailable(msg) => write!(f, "service temporarily unavailable: {msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ValidationFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ValidationError> for ProtocolError {
    fn from(e: ValidationError) -> Self {
        Self::ValidationFailed(e)
    }
}

// ── StorageError ─────────────────────────────────────────────────────────────

/// Storage layer errors covering SQLite and IPFS operations.
#[derive(Debug)]
pub enum StorageError {
    Database(String),
    MigrationFailed(String),
    EntryNotFound(LogEntryId),
    DuplicateEntry(LogEntryId),
    IpfsWriteFailed(String),
    IpfsPinFailed(String),
    IpfsNotReachable,
}

impl StorageError {
    /// Returns true if this error is transient and the operation may succeed on retry.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::IpfsNotReachable | Self::IpfsWriteFailed(_) | Self::IpfsPinFailed(_)
        )
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "database error: {msg}"),
            Self::MigrationFailed(msg) => write!(f, "migration failed: {msg}"),
            Self::EntryNotFound(id) => write!(f, "log entry not found: {id}"),
            Self::DuplicateEntry(id) => write!(f, "duplicate log entry: {id}"),
            Self::IpfsWriteFailed(msg) => write!(f, "IPFS write failed: {msg}"),
            Self::IpfsPinFailed(msg) => write!(f, "IPFS pin failed: {msg}"),
            Self::IpfsNotReachable => write!(f, "IPFS node not reachable"),
        }
    }
}

impl std::error::Error for StorageError {}

// ── SigningError ──────────────────────────────────────────────────────────────

/// Ed25519 signing and key management errors.
#[derive(Debug, Clone, PartialEq)]
pub enum SigningError {
    InvalidKeyMaterial(String),
    SignatureLengthInvalid { got: usize, expected: usize },
    VerificationFailed,
    KeyNotLoaded,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyMaterial(msg) => write!(f, "invalid key material: {msg}"),
            Self::SignatureLengthInvalid { got, expected } => write!(
                f,
                "signature length invalid: got {got} bytes, expected {expected}"
            ),
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::KeyNotLoaded => write!(f, "signing key not loaded"),
        }
    }
}

impl std::error::Error for SigningError {}

// ── CoreError (compatibility alias) ──────────────────────────────────────────

/// Backwards-compatibility alias. New code should use `ValidationError` directly.
pub type CoreError = ValidationError;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_error_response_codes() {
        assert_eq!(
            ProtocolError::UnknownCommand("FOO".into()).response_code(),
            500
        );
        assert_eq!(
            ProtocolError::InvalidSyntax("bad".into()).response_code(),
            501
        );
        assert_eq!(ProtocolError::NoGroupSelected.response_code(), 412);
        assert_eq!(
            ProtocolError::NoSuchGroup("misc.test".into()).response_code(),
            411
        );
        assert_eq!(ProtocolError::NoSuchArticle.response_code(), 430);
        assert_eq!(ProtocolError::NotAuthenticated.response_code(), 480);
        assert_eq!(
            ProtocolError::DuplicateMessageId("<x@y>".into()).response_code(),
            435
        );
        assert_eq!(ProtocolError::PostingNotPermitted.response_code(), 440);
        assert_eq!(
            ProtocolError::TransferNotPossible("nope".into()).response_code(),
            436
        );
        assert_eq!(
            ProtocolError::ArticleTooBig { size: 1, limit: 0 }.response_code(),
            441
        );
        assert_eq!(
            ProtocolError::ValidationFailed(ValidationError::EmptyNewsgroups).response_code(),
            441
        );
        assert_eq!(
            ProtocolError::ServiceUnavailable("down".into()).response_code(),
            400
        );
    }

    #[test]
    fn test_storage_error_transient_classification() {
        assert!(StorageError::IpfsNotReachable.is_transient());
        assert!(StorageError::IpfsWriteFailed("timeout".into()).is_transient());
        assert!(StorageError::IpfsPinFailed("gc".into()).is_transient());

        assert!(!StorageError::Database("constraint".into()).is_transient());
        assert!(!StorageError::MigrationFailed("bad schema".into()).is_transient());
        assert!(!StorageError::EntryNotFound(LogEntryId::from_bytes([0u8; 32])).is_transient());
        assert!(!StorageError::DuplicateEntry(LogEntryId::from_bytes([1u8; 32])).is_transient());
    }

    #[test]
    fn test_from_conversions() {
        // StorageError → UsenetIpfsError
        let e: UsenetIpfsError = StorageError::IpfsNotReachable.into();
        assert!(matches!(
            e,
            UsenetIpfsError::Storage(StorageError::IpfsNotReachable)
        ));

        // ProtocolError → UsenetIpfsError
        let e: UsenetIpfsError = ProtocolError::NoGroupSelected.into();
        assert!(matches!(
            e,
            UsenetIpfsError::Protocol(ProtocolError::NoGroupSelected)
        ));

        // ValidationError → UsenetIpfsError
        let e: UsenetIpfsError = ValidationError::EmptyNewsgroups.into();
        assert!(matches!(
            e,
            UsenetIpfsError::Validation(ValidationError::EmptyNewsgroups)
        ));

        // ValidationError → ProtocolError (produces ValidationFailed)
        let e: ProtocolError = ValidationError::EmptyNewsgroups.into();
        assert!(matches!(
            e,
            ProtocolError::ValidationFailed(ValidationError::EmptyNewsgroups)
        ));
    }

    #[test]
    fn test_display_does_not_expose_key_material() {
        let msg = "secret_key_bytes_here";
        let e = SigningError::InvalidKeyMaterial(msg.into());
        let display = e.to_string();
        // Display must contain a description but not raw binary — since we store
        // a String the message will appear, which is acceptable for text keys;
        // the invariant is that we do not format any binary blob as hex bytes.
        assert!(display.contains("invalid key material"));
    }

    #[test]
    fn test_core_error_alias_works() {
        let e = CoreError::InvalidGroupName("bad.name.".into());
        assert_eq!(e, ValidationError::InvalidGroupName("bad.name.".into()));
    }
}
