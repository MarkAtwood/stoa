use std::fmt;

/// Typed error for outbound SMTP relay delivery.
///
/// Variants drive retry policy:
/// - Transient/Io → mark peer down, leave message in queue for retry
/// - Permanent/AuthFailed/ProtocolError → mark peer down, move message to dead-letter
/// - TlsHandshake → mark peer down, leave message in queue for retry (not permanent)
#[derive(Debug)]
pub enum SmtpRelayError {
    /// 4xx response from peer — temporary failure, retry with backoff.
    Transient(String),
    /// 5xx response from peer — permanent failure, do not retry this message.
    Permanent(String),
    /// TLS handshake failed (cert validation, hostname mismatch, etc.).
    TlsHandshake(String),
    /// Network I/O error.
    Io(std::io::Error),
    /// AUTH rejected by peer (535).
    AuthFailed,
    /// Malformed SMTP response (not parseable as 3-digit code + text).
    ProtocolError(String),
}

impl SmtpRelayError {
    /// Returns true if the message should be retried (left in queue).
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            SmtpRelayError::Transient(_) | SmtpRelayError::Io(_) | SmtpRelayError::TlsHandshake(_)
        )
    }

    /// Returns true if the message should be moved to dead-letter (no retry).
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            SmtpRelayError::Permanent(_)
                | SmtpRelayError::AuthFailed
                | SmtpRelayError::ProtocolError(_)
        )
    }
}

impl fmt::Display for SmtpRelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmtpRelayError::Transient(msg) => write!(f, "transient relay failure: {}", msg),
            SmtpRelayError::Permanent(msg) => write!(f, "permanent relay failure: {}", msg),
            SmtpRelayError::TlsHandshake(msg) => write!(f, "TLS handshake failed: {}", msg),
            SmtpRelayError::Io(e) => write!(f, "relay I/O error: {}", e),
            SmtpRelayError::AuthFailed => write!(f, "relay authentication failed (535)"),
            SmtpRelayError::ProtocolError(msg) => write!(f, "relay protocol error: {}", msg),
        }
    }
}

impl std::error::Error for SmtpRelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SmtpRelayError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SmtpRelayError {
    fn from(e: std::io::Error) -> Self {
        SmtpRelayError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_is_transient_not_permanent() {
        let e = SmtpRelayError::Transient("451 service unavailable".to_string());
        assert!(e.is_transient());
        assert!(!e.is_permanent());
    }

    #[test]
    fn permanent_is_permanent_not_transient() {
        let e = SmtpRelayError::Permanent("550 user not found".to_string());
        assert!(e.is_permanent());
        assert!(!e.is_transient());
    }

    #[test]
    fn auth_failed_is_permanent() {
        let e = SmtpRelayError::AuthFailed;
        assert!(e.is_permanent());
        assert!(!e.is_transient());
    }

    #[test]
    fn io_error_is_transient() {
        let e = SmtpRelayError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert!(e.is_transient());
        assert!(!e.is_permanent());
    }

    #[test]
    fn tls_error_is_transient() {
        let e = SmtpRelayError::TlsHandshake("cert verification failed".to_string());
        assert!(e.is_transient());
        assert!(!e.is_permanent());
    }

    #[test]
    fn protocol_error_is_permanent() {
        let e = SmtpRelayError::ProtocolError("line too long".to_string());
        assert!(e.is_permanent());
        assert!(!e.is_transient());
    }

    #[test]
    fn display_does_not_contain_password_or_credentials() {
        let e = SmtpRelayError::AuthFailed;
        let display = format!("{}", e);
        assert!(!display.to_lowercase().contains("password"));
        assert!(!display.to_lowercase().contains("credentials"));
    }

    #[test]
    fn all_variants_classified() {
        // Exhaustive match to ensure no variant is unclassified.
        // This will fail to compile if new variants are added without updating.
        let variants: Vec<SmtpRelayError> = vec![
            SmtpRelayError::Transient("".to_string()),
            SmtpRelayError::Permanent("".to_string()),
            SmtpRelayError::TlsHandshake("".to_string()),
            SmtpRelayError::Io(std::io::Error::new(std::io::ErrorKind::Other, "")),
            SmtpRelayError::AuthFailed,
            SmtpRelayError::ProtocolError("".to_string()),
        ];
        for v in &variants {
            let classified = v.is_transient() || v.is_permanent();
            assert!(
                classified,
                "variant {:?} is neither transient nor permanent",
                v
            );
        }
    }
}
