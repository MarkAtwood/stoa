use std::time::Duration;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Post an article to an NNTP server via TCP.
///
/// Protocol sequence:
/// 1. Read `200` greeting
/// 2. Send `POST\r\n`
/// 3. Read `340` (send article)
/// 4. Write dot-stuffed article bytes followed by `\r\n.\r\n`
/// 5. Read `240` or `250` (article received)
///
/// Returns `Ok(())` on 240/250. Returns `Err(String)` on any protocol
/// deviation, I/O error, or timeout.
pub async fn post_article(addr: &str, article_bytes: &[u8]) -> Result<(), String> {
    timeout(OPERATION_TIMEOUT, do_post(addr, article_bytes))
        .await
        .map_err(|_| "NNTP POST timed out after 30 seconds".to_string())?
}

async fn do_post(addr: &str, article_bytes: &[u8]) -> Result<(), String> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("failed to connect to NNTP server {addr}: {e}"))?;

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read greeting: expect 200
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("failed to read NNTP greeting: {e}"))?;
    if !line.starts_with("200") {
        return Err(format!("unexpected NNTP greeting: {}", line.trim_end()));
    }
    line.clear();

    // Send POST command
    writer
        .write_all(b"POST\r\n")
        .await
        .map_err(|e| format!("failed to send POST command: {e}"))?;

    // Read 340 (go ahead, send article)
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("failed to read POST response: {e}"))?;
    if !line.starts_with("340") {
        return Err(format!("NNTP server rejected POST: {}", line.trim_end()));
    }
    line.clear();

    // Write dot-stuffed article
    let stuffed = dot_stuff(article_bytes);
    writer
        .write_all(&stuffed)
        .await
        .map_err(|e| format!("failed to write article body: {e}"))?;

    // End-of-article marker
    writer
        .write_all(b"\r\n.\r\n")
        .await
        .map_err(|e| format!("failed to write article terminator: {e}"))?;

    writer
        .flush()
        .await
        .map_err(|e| format!("failed to flush NNTP stream: {e}"))?;

    // Read final response: 240 or 250 = success
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("failed to read article-received response: {e}"))?;

    let code = line.get(..3).unwrap_or("");
    if code == "240" || code == "250" {
        Ok(())
    } else {
        Err(format!(
            "NNTP article not accepted: {}",
            line.trim_end()
        ))
    }
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

    // --- post_article (mock server tests) ---

    async fn run_mock_server(
        listener: TcpListener,
        greeting: &'static str,
        post_response: &'static str,
        final_response: &'static str,
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

        // Read until end-of-article marker
        let mut buf = Vec::new();
        let mut prev = [0u8; 4];
        let mut tmp = [0u8; 1];
        loop {
            reader.read_exact(&mut tmp).await.expect("read body byte");
            buf.push(tmp[0]);
            prev = [prev[1], prev[2], prev[3], tmp[0]];
            // Look for \r\n.\r\n
            if buf.len() >= 5 {
                let tail = &buf[buf.len() - 5..];
                if tail == b"\r\n.\r\n" {
                    break;
                }
            }
            let _ = prev;
        }

        writer
            .write_all(final_response.as_bytes())
            .await
            .expect("write final");
    }

    #[tokio::test]
    async fn post_article_success_240() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();

        tokio::spawn(run_mock_server(
            listener,
            "200 NNTP Service Ready\r\n",
            "340 Send article\r\n",
            "240 Article received ok\r\n",
        ));

        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&addr, msg).await;
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
        ));

        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&addr, msg).await;
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

        let msg = b"From: a@b.com\r\n\r\nbody\r\n";
        let result = post_article(&addr, msg).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("440"),
            "expected 440 in error"
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

        let msg = b"From: a@b.com\r\n\r\nbody\r\n";
        let result = post_article(&addr, msg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("502"));
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
        ));

        let msg = b"From: a@b.com\r\nSubject: test\r\n\r\nbody\r\n";
        let result = post_article(&addr, msg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("441"));
    }

    #[tokio::test]
    async fn post_article_connection_refused() {
        // Port 1 is reserved/unlikely to be listening
        let result = post_article("127.0.0.1:1", b"test\r\n").await;
        assert!(result.is_err());
    }
}
