/// Per-connection peering mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeeringMode {
    /// Traditional IHAVE round-trip mode (RFC 977)
    Ihave,
    /// Pipelined CHECK/TAKETHIS mode (RFC 4644)
    Streaming,
}

/// Handle MODE STREAM command.
///
/// Returns the response line and the new mode. The transit daemon always
/// permits streaming; there is no configuration knob to disable it.
pub fn handle_mode_stream(_current_mode: PeeringMode) -> (String, PeeringMode) {
    (
        "203 Streaming permitted\r\n".to_string(),
        PeeringMode::Streaming,
    )
}

/// Build the CAPABILITIES response for the transit daemon.
///
/// Always includes VERSION 2, IHAVE, and STREAMING (RFC 4644).
pub fn capabilities_response() -> String {
    "101 Capability list:\r\nVERSION 2\r\nIHAVE\r\nSTREAMING\r\n.\r\n".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_stream_returns_203() {
        let (response, _) = handle_mode_stream(PeeringMode::Ihave);
        assert!(
            response.starts_with("203 Streaming permitted"),
            "unexpected response: {response:?}"
        );
    }

    #[test]
    fn mode_stream_sets_streaming_mode() {
        let (_, new_mode) = handle_mode_stream(PeeringMode::Ihave);
        assert_eq!(new_mode, PeeringMode::Streaming);
    }

    #[test]
    fn capabilities_includes_streaming() {
        let resp = capabilities_response();
        assert!(
            resp.contains("STREAMING"),
            "CAPABILITIES response missing STREAMING: {resp:?}"
        );
    }
}
