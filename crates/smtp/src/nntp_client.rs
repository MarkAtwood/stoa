use std::time::Duration;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tracing::warn;

const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Typed error for NNTP client operations.
///
/// Callers can match on the variant to distinguish permanent failures
/// (which must not be retried) from transient ones and I/O errors.
#[derive(Debug)]
pub enum NntpClientError {
    /// A network I/O error.
    Io(std::io::Error),
    /// The operation exceeded the 30-second timeout.
    Timeout,
    /// AUTHINFO USER/PASS was rejected by the server.
    AuthFailed(String),
    /// The server returned a 437 permanent rejection; do not retry this article.
    PermanentRejection(String),
    /// The server returned 436 and all retry attempts were exhausted.
    TransientExhausted(String),
    /// An unexpected or malformed server response.
    Protocol(String),
}

impl std::fmt::Display for NntpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NntpClientError::Io(e) => write!(f, "I/O error: {e}"),
            NntpClientError::Timeout => write!(f, "operation timed out after 30 seconds"),
            NntpClientError::AuthFailed(r) => write!(f, "NNTP authentication failed: {r}"),
            NntpClientError::PermanentRejection(r) => {
                write!(f, "NNTP 437 permanent rejection: {r}")
            }
            NntpClientError::TransientExhausted(r) => {
                write!(f, "NNTP 436 transient failure, retries exhausted: {r}")
            }
            NntpClientError::Protocol(r) => write!(f, "NNTP protocol error: {r}"),
        }
    }
}

impl std::error::Error for NntpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let NntpClientError::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

/// Configuration for NNTP client connections.
#[derive(Debug, Clone)]
pub struct NntpClientConfig {
    /// TCP address of the NNTP server (e.g. `"127.0.0.1:119"`).
    pub addr: String,
    /// Optional AUTHINFO USER credential.
    pub username: Option<String>,
    /// Optional AUTHINFO PASS credential.
    pub password: Option<String>,
    /// Maximum retry attempts on transient 436 failures.
    pub max_retries: u32,
}

/// Post an article to an NNTP server via TCP.
///
/// Protocol sequence:
/// 1. Read `200` greeting
/// 2. Optionally authenticate with AUTHINFO USER/PASS (if credentials configured)
/// 3. Send `POST\r\n`, read `340`
/// 4. Write dot-stuffed article bytes followed by `\r\n.\r\n`
/// 5. Read final response:
///    - `240`: success → verify with ARTICLE command
///    - `436`: transient failure → retry with exponential backoff (up to max_retries)
///    - `437`: permanent rejection → return `Err` immediately
///    - other: return `Err`
/// 6. Verify with `ARTICLE <message_id>`, expect `220` (non-fatal warning on failure)
/// 7. Send `QUIT`
///
/// Returns `Ok(())` on success. Returns `Err(NntpClientError)` on any
/// protocol deviation, I/O error, or timeout.
pub async fn post_article(
    config: &NntpClientConfig,
    article_bytes: &[u8],
    message_id: &str,
) -> Result<(), NntpClientError> {
    timeout(
        OPERATION_TIMEOUT,
        do_post(config, article_bytes, message_id),
    )
    .await
    .map_err(|_| NntpClientError::Timeout)?
}

async fn do_post(
    config: &NntpClientConfig,
    article_bytes: &[u8],
    message_id: &str,
) -> Result<(), NntpClientError> {
    let stream = TcpStream::connect(&config.addr)
        .await
        .map_err(NntpClientError::Io)?;

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read greeting: expect 200
    reader
        .read_line(&mut line)
        .await
        .map_err(NntpClientError::Io)?;
    if !line.starts_with("200") {
        return Err(NntpClientError::Protocol(line.trim_end().to_string()));
    }
    line.clear();

    // AUTHINFO USER/PASS (if credentials configured)
    if let (Some(username), Some(password)) = (&config.username, &config.password) {
        writer
            .write_all(format!("AUTHINFO USER {username}\r\n").as_bytes())
            .await
            .map_err(NntpClientError::Io)?;

        reader
            .read_line(&mut line)
            .await
            .map_err(NntpClientError::Io)?;
        if !line.starts_with("381") {
            return Err(NntpClientError::AuthFailed(line.trim_end().to_string()));
        }
        line.clear();

        // Write AUTHINFO PASS in three separate writes to avoid constructing a
        // String that contains the password (which could be captured in error
        // messages or logs).
        writer
            .write_all(b"AUTHINFO PASS ")
            .await
            .map_err(NntpClientError::Io)?;
        writer
            .write_all(password.as_bytes())
            .await
            .map_err(|_| NntpClientError::Io(std::io::Error::other("AUTHINFO PASS write error")))?;
        writer
            .write_all(b"\r\n")
            .await
            .map_err(NntpClientError::Io)?;

        reader
            .read_line(&mut line)
            .await
            .map_err(NntpClientError::Io)?;
        if !line.starts_with("281") {
            // Include the server's response (does not contain the password) but
            // never interpolate the password itself into this error.
            return Err(NntpClientError::AuthFailed(line.trim_end().to_string()));
        }
        line.clear();
    }

    // POST with retry loop on 436
    let stuffed = dot_stuff(article_bytes);
    let mut attempt = 0u32;
    loop {
        // Send POST command
        writer
            .write_all(b"POST\r\n")
            .await
            .map_err(NntpClientError::Io)?;

        // Read 340 (go ahead, send article)
        reader
            .read_line(&mut line)
            .await
            .map_err(NntpClientError::Io)?;
        if !line.starts_with("340") {
            return Err(NntpClientError::Protocol(line.trim_end().to_string()));
        }
        line.clear();

        // Write dot-stuffed article
        writer
            .write_all(&stuffed)
            .await
            .map_err(NntpClientError::Io)?;

        // End-of-article marker
        writer
            .write_all(b"\r\n.\r\n")
            .await
            .map_err(NntpClientError::Io)?;

        writer.flush().await.map_err(NntpClientError::Io)?;

        // Read final response
        reader
            .read_line(&mut line)
            .await
            .map_err(NntpClientError::Io)?;

        let code = line.get(..3).unwrap_or("");
        if code == "240" || code == "250" {
            break;
        } else if code == "437" {
            return Err(NntpClientError::PermanentRejection(
                line.trim_end().to_string(),
            ));
        } else if code == "436" {
            attempt += 1;
            if attempt >= config.max_retries {
                return Err(NntpClientError::TransientExhausted(
                    line.trim_end().to_string(),
                ));
            }
            let shift = attempt.min(63);
            let backoff = Duration::from_millis(500u64.saturating_mul(1u64 << shift));
            warn!(
                attempt,
                backoff_ms = backoff.as_millis(),
                "NNTP 436 transient failure, retrying"
            );
            line.clear();
            tokio::time::sleep(backoff).await;
            continue;
        } else {
            return Err(NntpClientError::Protocol(line.trim_end().to_string()));
        }
    }

    // Verify with ARTICLE command (non-fatal on failure)
    writer
        .write_all(format!("ARTICLE <{message_id}>\r\n").as_bytes())
        .await
        .map_err(NntpClientError::Io)?;

    line.clear();
    reader
        .read_line(&mut line)
        .await
        .map_err(NntpClientError::Io)?;
    if !line.starts_with("220") {
        warn!(
            message_id,
            response = line.trim_end(),
            "NNTP ARTICLE verify did not return 220 — article may still be accepted"
        );
    }

    // QUIT
    let _ = writer.write_all(b"QUIT\r\n").await;

    Ok(())
}

/// Perform dot-stuffing on article bytes per RFC 3977 §3.1.1.
///
/// Any line beginning with "." has an additional "." prepended.
/// The trailing `\r\n.\r\n` terminator is added by the caller.
fn dot_stuff(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len() + 16);
    let mut line_start = true;
    for &b in bytes {
        if line_start && b == b'.' {
            result.push(b'.');
        }
        result.push(b);
        line_start = b == b'\n';
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn no_auth_config(addr: String) -> NntpClientConfig {
        NntpClientConfig {
            addr,
            username: None,
            password: None,
            max_retries: 3,
        }
    }

    // --- dot_stuff ---

    #[test]
    fn dot_stuff_no_leading_dots() {
        let input = b"From: a@b.com\r\nSubject: test\r\n\r\nbody line\r\n";
        assert_eq!(dot_stuff(input), input.to_vec());
    }

    #[test]
    fn dot_stuff_leading_dot_on_first_line() {
        let input = b".hidden\r\nFrom: a@b.com\r\n";
        let expected = b"..hidden\r\nFrom: a@b.com\r\n";
        assert_eq!(dot_stuff(input), expected.to_vec());
    }

    #[test]
    fn dot_stuff_leading_dot_mid_message() {
        let input = b"From: a@b.com\r\n\r\n.signature line\r\n";
        let expected = b"From: a@b.com\r\n\r\n..signature line\r\n";
        assert_eq!(dot_stuff(input), expected.to_vec());
    }

    #[test]
    fn dot_stuff_dot_not_at_line_start() {
        let input = b"From: a@b.com\r\nSubject: foo.bar\r\n";
        assert_eq!(dot_stuff(input), input.to_vec());
    }

    #[test]
    fn dot_stuff_empty() {
        assert_eq!(dot_stuff(b""), b"".to_vec());
    }

    // --- mock server helper ---

    /// Read from `reader` until the NNTP end-of-article marker `\r\n.\r\n`.
    async fn read_until_eoa(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1];
        loop {
            reader.read_exact(&mut tmp).await.expect("read body byte");
            buf.push(tmp[0]);
            if buf.len() >= 5 {
                let tail = &buf[buf.len() - 5..];
                if tail == b"\r\n.\r\n" {
                    break;
                }
            }
        }
    }

    /// Minimal mock NNTP server: sends `greeting`, expects POST, sends `post_response`,
    /// reads article body, sends `final_response`, reads ARTICLE verify, sends `article_response`,
    /// reads QUIT.
    async fn run_mock_server(
        listener: TcpListener,
        greeting: &'static str,
        post_response: &'static str,
        final_response: &'static str,
        article_response: &'static str,
    ) {
        let (stream, _) = listener.accept().await.expect("accept");
        let (reader_half, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader_half);

        writer
            .write_all(greeting.as_bytes())
            .await
            .expect("write greeting");

        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read POST");
        assert_eq!(line.trim_end(), "POST");

        writer
            .write_all(post_response.as_bytes())
            .await
            .expect("write 340");

        read_until_eoa(&mut reader).await;

        writer
            .write_all(final_response.as_bytes())
            .await
            .expect("write final");

        // Read ARTICLE verify command
        line.clear();
        reader.read_line(&mut line).await.expect("read ARTICLE");

        writer
            .write_all(article_response.as_bytes())
            .await
            .expect("write article response");

        // Read QUIT
        line.clear();
        let _ = reader.read_line(&mut line).await;
    }

    // --- post_article (mock server tests) ---

    #[tokio::test]
    async fn post_article_success_240() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(run_mock_server(
            listener,
            "200 NNTP Service Ready\r\n",
            "340 Send article\r\n",
            "240 Article received ok\r\n",
            "220 0 <test@example.com> article\r\n",
        ));

        let config = no_auth_config(addr);
        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[tokio::test]
    async fn post_article_success_250() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(run_mock_server(
            listener,
            "200 NNTP Service Ready\r\n",
            "340 Send article\r\n",
            "250 Article accepted\r\n",
            "220 0 <test@example.com> article\r\n",
        ));

        let config = no_auth_config(addr);
        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[tokio::test]
    async fn post_article_rejected_posting_not_permitted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (_r, mut writer) = stream.into_split();
            writer
                .write_all(b"200 NNTP Service Ready\r\n")
                .await
                .expect("write");
            // Read POST command
            let mut r = BufReader::new(_r);
            let mut line = String::new();
            r.read_line(&mut line).await.expect("read");
            writer
                .write_all(b"440 Posting not permitted\r\n")
                .await
                .expect("write 440");
        });

        let config = no_auth_config(addr);
        let msg = b"From: a@b.com\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(
            matches!(result, Err(NntpClientError::Protocol(ref s)) if s.starts_with("440")),
            "expected Protocol(440...), got: {result:?}"
        );
    }

    #[tokio::test]
    async fn post_article_bad_greeting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (_r, mut writer) = stream.into_split();
            writer
                .write_all(b"502 Permission denied\r\n")
                .await
                .expect("write");
        });

        let config = no_auth_config(addr);
        let msg = b"From: a@b.com\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(
            matches!(result, Err(NntpClientError::Protocol(ref s)) if s.starts_with("502")),
            "expected Protocol(502...), got: {result:?}"
        );
    }

    #[tokio::test]
    async fn post_article_441_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(run_mock_server(
            listener,
            "200 NNTP Service Ready\r\n",
            "340 Send article\r\n",
            "441 Posting failed\r\n",
            "",
        ));

        let config = no_auth_config(addr);
        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(
            matches!(result, Err(NntpClientError::Protocol(ref s)) if s.starts_with("441")),
            "expected Protocol(441...), got: {result:?}"
        );
    }

    #[tokio::test]
    async fn post_article_connection_refused() {
        // Port 1 is reserved/unlikely to be listening
        let config = no_auth_config("127.0.0.1:1".to_string());
        let result = post_article(&config, b"test\r\n", "test@example.com").await;
        assert!(result.is_err());
    }

    // --- 437 permanent rejection ---

    #[tokio::test]
    async fn post_article_437_permanent_rejection_no_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader_half, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader_half);
            let mut line = String::new();

            writer
                .write_all(b"200 NNTP Service Ready\r\n")
                .await
                .expect("write greeting");

            reader.read_line(&mut line).await.expect("read POST");
            assert_eq!(line.trim_end(), "POST");
            writer
                .write_all(b"340 Send article\r\n")
                .await
                .expect("write 340");

            read_until_eoa(&mut reader).await;

            writer
                .write_all(b"437 Article permanently rejected\r\n")
                .await
                .expect("write 437");
        });

        let config = no_auth_config(addr);
        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(
            matches!(result, Err(NntpClientError::PermanentRejection(_))),
            "expected PermanentRejection, got: {result:?}"
        );
    }

    // --- 436 transient retry ---

    #[tokio::test]
    async fn post_article_436_retries_then_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader_half, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader_half);
            let mut line = String::new();

            writer
                .write_all(b"200 NNTP Service Ready\r\n")
                .await
                .expect("write greeting");

            // Attempt 1: 436
            line.clear();
            reader.read_line(&mut line).await.expect("read POST 1");
            assert_eq!(line.trim_end(), "POST");
            writer
                .write_all(b"340 Send article\r\n")
                .await
                .expect("write 340");
            read_until_eoa(&mut reader).await;
            writer
                .write_all(b"436 Try again later\r\n")
                .await
                .expect("write 436");

            // Attempt 2: 240
            line.clear();
            reader.read_line(&mut line).await.expect("read POST 2");
            assert_eq!(line.trim_end(), "POST");
            writer
                .write_all(b"340 Send article\r\n")
                .await
                .expect("write 340");
            read_until_eoa(&mut reader).await;
            writer
                .write_all(b"240 Article received ok\r\n")
                .await
                .expect("write 240");

            // ARTICLE verify
            line.clear();
            reader.read_line(&mut line).await.expect("read ARTICLE");
            writer
                .write_all(b"220 0 <test@example.com> article\r\n")
                .await
                .expect("write 220");

            // QUIT
            line.clear();
            let _ = reader.read_line(&mut line).await;
        });

        let config = NntpClientConfig {
            addr,
            username: None,
            password: None,
            max_retries: 3,
        };
        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(result.is_ok(), "expected Ok after retry, got: {result:?}");
    }

    #[tokio::test]
    async fn post_article_436_exhausts_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        // max_retries = 2; server always returns 436
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader_half, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader_half);
            let mut line = String::new();

            writer
                .write_all(b"200 NNTP Service Ready\r\n")
                .await
                .expect("write greeting");

            for _ in 0..2 {
                line.clear();
                reader.read_line(&mut line).await.expect("read POST");
                assert_eq!(line.trim_end(), "POST");
                writer
                    .write_all(b"340 Send article\r\n")
                    .await
                    .expect("write 340");
                read_until_eoa(&mut reader).await;
                writer
                    .write_all(b"436 Deferred\r\n")
                    .await
                    .expect("write 436");
            }
        });

        let config = NntpClientConfig {
            addr,
            username: None,
            password: None,
            max_retries: 2,
        };
        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(
            matches!(result, Err(NntpClientError::TransientExhausted(_))),
            "expected TransientExhausted, got: {result:?}"
        );
    }

    // --- AUTHINFO ---

    #[tokio::test]
    async fn post_article_authinfo_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader_half, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader_half);
            let mut line = String::new();

            writer
                .write_all(b"200 NNTP Service Ready\r\n")
                .await
                .expect("write greeting");

            // AUTHINFO USER
            reader
                .read_line(&mut line)
                .await
                .expect("read authinfo user");
            assert_eq!(line.trim_end(), "AUTHINFO USER testuser");
            writer
                .write_all(b"381 Enter password\r\n")
                .await
                .expect("write 381");

            // AUTHINFO PASS
            line.clear();
            reader
                .read_line(&mut line)
                .await
                .expect("read authinfo pass");
            assert_eq!(line.trim_end(), "AUTHINFO PASS secret");
            writer
                .write_all(b"281 Authentication accepted\r\n")
                .await
                .expect("write 281");

            // POST
            line.clear();
            reader.read_line(&mut line).await.expect("read POST");
            assert_eq!(line.trim_end(), "POST");
            writer
                .write_all(b"340 Send article\r\n")
                .await
                .expect("write 340");
            read_until_eoa(&mut reader).await;
            writer
                .write_all(b"240 Article received ok\r\n")
                .await
                .expect("write 240");

            // ARTICLE verify
            line.clear();
            reader.read_line(&mut line).await.expect("read ARTICLE");
            writer
                .write_all(b"220 0 <mid@example.com> article\r\n")
                .await
                .expect("write 220");

            // QUIT
            line.clear();
            let _ = reader.read_line(&mut line).await;
        });

        let config = NntpClientConfig {
            addr,
            username: Some("testuser".to_string()),
            password: Some("secret".to_string()),
            max_retries: 3,
        };
        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "mid@example.com").await;
        assert!(result.is_ok(), "expected Ok with auth, got: {result:?}");
    }

    #[tokio::test]
    async fn post_article_authinfo_wrong_password() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader_half, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader_half);
            let mut line = String::new();

            writer
                .write_all(b"200 NNTP Service Ready\r\n")
                .await
                .expect("write greeting");

            // AUTHINFO USER
            reader
                .read_line(&mut line)
                .await
                .expect("read authinfo user");
            writer
                .write_all(b"381 Enter password\r\n")
                .await
                .expect("write 381");

            // AUTHINFO PASS — reject
            line.clear();
            reader
                .read_line(&mut line)
                .await
                .expect("read authinfo pass");
            writer
                .write_all(b"482 Authentication failed\r\n")
                .await
                .expect("write 482");
        });

        let config = NntpClientConfig {
            addr,
            username: Some("testuser".to_string()),
            password: Some("wrong".to_string()),
            max_retries: 3,
        };
        let msg = b"From: a@b.com\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "mid@example.com").await;
        assert!(
            matches!(result, Err(NntpClientError::AuthFailed(_))),
            "expected AuthFailed, got: {result:?}"
        );
    }

    // --- ARTICLE verify non-fatal ---

    #[tokio::test]
    async fn post_article_article_verify_non_fatal() {
        // Server returns 240 but ARTICLE verify returns 430 (not found); should still succeed.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader_half, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader_half);
            let mut line = String::new();

            writer
                .write_all(b"200 NNTP Service Ready\r\n")
                .await
                .expect("write greeting");

            reader.read_line(&mut line).await.expect("read POST");
            writer
                .write_all(b"340 Send article\r\n")
                .await
                .expect("write 340");
            read_until_eoa(&mut reader).await;
            writer
                .write_all(b"240 Article received ok\r\n")
                .await
                .expect("write 240");

            // ARTICLE verify: return 430
            line.clear();
            reader.read_line(&mut line).await.expect("read ARTICLE");
            writer
                .write_all(b"430 No such article\r\n")
                .await
                .expect("write 430");

            // QUIT
            line.clear();
            let _ = reader.read_line(&mut line).await;
        });

        let config = no_auth_config(addr);
        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&config, msg, "test@example.com").await;
        assert!(
            result.is_ok(),
            "ARTICLE verify failure should be non-fatal, got: {result:?}"
        );
    }
}
