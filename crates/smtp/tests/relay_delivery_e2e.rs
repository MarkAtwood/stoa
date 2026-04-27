use std::time::Duration;
use stoa_smtp::config::SmtpRelayPeerConfig;
use stoa_smtp::SmtpRelayQueue;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

fn test_peer(port: u16) -> SmtpRelayPeerConfig {
    SmtpRelayPeerConfig {
        host: "127.0.0.1".to_string(),
        port,
        tls: false,
        username: None,
        password: None,
    }
}

/// Bind a port and spawn a mock SMTP server that accepts one connection,
/// responds 250 OK to everything, and returns the list of commands received.
///
/// Write errors are ignored: the SMTP client sends QUIT as best-effort and
/// immediately drops the TCP connection, so the server's reply write may race
/// with the client-side teardown.
async fn mock_smtp_ok() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (rd, mut wr) = tokio::io::split(stream);
        let mut reader = BufReader::new(rd);
        let mut commands: Vec<String> = Vec::new();

        // Greeting — must succeed or the test is broken.
        wr.write_all(b"220 mock.smtp.test ESMTP\r\n").await.unwrap();

        let mut line = String::new();
        loop {
            line.clear();
            // EOF or read error ends the session; either is fine.
            let n = match reader.read_line(&mut line).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end().to_string();
            commands.push(trimmed.clone());

            // QUIT: write best-effort (client may already have closed the connection).
            if trimmed.starts_with("QUIT") {
                let _ = wr.write_all(b"221 Bye\r\n").await;
                break;
            }

            let reply = if trimmed.starts_with("EHLO") {
                "250-mock.smtp.test\r\n250 OK\r\n"
            } else if trimmed == "DATA" {
                "354 Start mail input\r\n"
            } else if trimmed == "." {
                "250 OK\r\n"
            } else {
                "250 OK\r\n"
            };
            // Write errors after DATA acceptance are also best-effort.
            if wr.write_all(reply.as_bytes()).await.is_err() {
                break;
            }
        }
        commands
    });
    (port, handle)
}

/// Mock that returns 451 (transient) to MAIL FROM, then closes.
///
/// Write errors are ignored for the same reason as `mock_smtp_ok`.
async fn mock_smtp_transient() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (rd, mut wr) = tokio::io::split(stream);
        let mut reader = BufReader::new(rd);
        let mut commands: Vec<String> = Vec::new();

        wr.write_all(b"220 mock.smtp.test ESMTP\r\n").await.unwrap();

        let mut line = String::new();
        loop {
            line.clear();
            let n = match reader.read_line(&mut line).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end().to_string();
            commands.push(trimmed.clone());

            if trimmed.starts_with("QUIT") {
                let _ = wr.write_all(b"221 Bye\r\n").await;
                break;
            }

            let reply = if trimmed.starts_with("EHLO") {
                "250-mock.smtp.test\r\n250 OK\r\n"
            } else if trimmed.starts_with("MAIL FROM") {
                "451 Service unavailable\r\n"
            } else {
                "250 OK\r\n"
            };
            if wr.write_all(reply.as_bytes()).await.is_err() {
                break;
            }
        }
        commands
    });
    (port, handle)
}

/// Mock that returns 550 (permanent) to MAIL FROM, then closes.
///
/// Write errors are ignored for the same reason as `mock_smtp_ok`.
async fn mock_smtp_permanent() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (rd, mut wr) = tokio::io::split(stream);
        let mut reader = BufReader::new(rd);
        let mut commands: Vec<String> = Vec::new();

        wr.write_all(b"220 mock.smtp.test ESMTP\r\n").await.unwrap();

        let mut line = String::new();
        loop {
            line.clear();
            let n = match reader.read_line(&mut line).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end().to_string();
            commands.push(trimmed.clone());

            if trimmed.starts_with("QUIT") {
                let _ = wr.write_all(b"221 Bye\r\n").await;
                break;
            }

            let reply = if trimmed.starts_with("EHLO") {
                "250-mock.smtp.test\r\n250 OK\r\n"
            } else if trimmed.starts_with("MAIL FROM") {
                "550 User not found\r\n"
            } else {
                "250 OK\r\n"
            };
            if wr.write_all(reply.as_bytes()).await.is_err() {
                break;
            }
        }
        commands
    });
    (port, handle)
}

// ---- test cases ----

/// Happy path: article is delivered and queue is empty afterwards.
///
/// The mock server records the SMTP command sequence. We verify that the
/// canonical EHLO/MAIL FROM/RCPT TO/DATA sequence was issued and that both
/// queue files are gone after drain.
#[tokio::test]
async fn happy_path_article_delivered_queue_empty() {
    let (port, server_handle) = mock_smtp_ok().await;
    let dir = tempfile::TempDir::new().unwrap();

    let queue = SmtpRelayQueue::new(
        dir.path().to_path_buf(),
        vec![test_peer(port)],
        Duration::from_secs(300),
    )
    .unwrap();

    let article =
        b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello\r\n";
    queue
        .enqueue(article, "alice@example.com", &["bob@example.com"])
        .await
        .unwrap();

    queue.drain_once_for_test().await;

    // Queue root must have no .env or .msg files.
    let leftover: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.ends_with(".env") || n.ends_with(".msg")
        })
        .collect();
    assert!(
        leftover.is_empty(),
        "queue should be empty after successful delivery, found: {:?}",
        leftover
    );

    // Verify the server saw the expected SMTP command sequence.
    // Oracle: RFC 5321 §3.3 — envelope is EHLO, MAIL FROM, RCPT TO, DATA, body, QUIT.
    let cmds = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(
        cmds.iter().any(|c| c.starts_with("EHLO")),
        "missing EHLO in: {:?}",
        cmds
    );
    assert!(
        cmds.iter().any(|c| c.starts_with("MAIL FROM")),
        "missing MAIL FROM in: {:?}",
        cmds
    );
    assert!(
        cmds.iter().any(|c| c.starts_with("RCPT TO")),
        "missing RCPT TO in: {:?}",
        cmds
    );
    assert!(
        cmds.iter().any(|c| c == "DATA"),
        "missing DATA in: {:?}",
        cmds
    );
}

/// Transient failure: 451 response leaves the message in the queue for retry.
///
/// A 4xx response to MAIL FROM is mapped to SmtpRelayError::Transient, which
/// must leave both queue files in place so the next drain cycle retries.
#[tokio::test]
async fn transient_failure_leaves_message_in_queue() {
    let (port, _server_handle) = mock_smtp_transient().await;
    let dir = tempfile::TempDir::new().unwrap();

    let queue = SmtpRelayQueue::new(
        dir.path().to_path_buf(),
        vec![test_peer(port)],
        Duration::from_secs(300),
    )
    .unwrap();

    let article = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: T\r\n\r\nBody\r\n";
    queue
        .enqueue(article, "a@example.com", &["b@example.com"])
        .await
        .unwrap();

    queue.drain_once_for_test().await;

    // The .env file must still be present — transient errors do not discard the message.
    let env_count = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".env"))
        .count();
    assert_eq!(
        env_count, 1,
        "transient failure should leave message in queue"
    );
}

/// Permanent failure: 550 response moves message to dead/ subdirectory.
///
/// A 5xx response to MAIL FROM is mapped to SmtpRelayError::Permanent. The
/// queue removes both files from the queue root and moves them to dead/ to
/// prevent infinite retry loops.
#[tokio::test]
async fn permanent_failure_moves_to_dead() {
    let (port, _server_handle) = mock_smtp_permanent().await;
    let dir = tempfile::TempDir::new().unwrap();

    let queue = SmtpRelayQueue::new(
        dir.path().to_path_buf(),
        vec![test_peer(port)],
        Duration::from_secs(300),
    )
    .unwrap();

    let article = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: T\r\n\r\nBody\r\n";
    queue
        .enqueue(article, "a@example.com", &["b@example.com"])
        .await
        .unwrap();

    queue.drain_once_for_test().await;

    // No .env in queue root.
    let root_env = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".env"))
        .count();
    assert_eq!(
        root_env, 0,
        "permanent failure should remove .env from queue root"
    );

    // .env present in dead/.
    let dead_env = std::fs::read_dir(dir.path().join("dead"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".env"))
        .count();
    assert_eq!(
        dead_env, 1,
        "permanent failure should move .env to dead/ subdirectory"
    );
}

/// Round-robin: with two peers and two messages each peer receives exactly one.
///
/// PeerHealthState advances rr_index after each select_peer call, so the first
/// message goes to peer 0 and the second to peer 1. Both mock servers must
/// accept one connection each.
#[tokio::test]
async fn round_robin_two_peers_each_gets_one() {
    let (port1, handle1) = mock_smtp_ok().await;
    let (port2, handle2) = mock_smtp_ok().await;
    let dir = tempfile::TempDir::new().unwrap();

    let queue = SmtpRelayQueue::new(
        dir.path().to_path_buf(),
        vec![test_peer(port1), test_peer(port2)],
        Duration::from_secs(300),
    )
    .unwrap();

    let article = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: T\r\n\r\nBody\r\n";
    queue
        .enqueue(article, "a@example.com", &["b@example.com"])
        .await
        .unwrap();
    queue
        .enqueue(article, "a@example.com", &["b@example.com"])
        .await
        .unwrap();

    queue.drain_once_for_test().await;

    // Both queued messages delivered → queue empty.
    let leftover: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.ends_with(".env") || n.ends_with(".msg")
        })
        .collect();
    assert!(
        leftover.is_empty(),
        "both messages should be delivered, found: {:?}",
        leftover
    );

    // Each server received exactly one MAIL FROM, confirming round-robin distribution.
    let cmds1 = tokio::time::timeout(Duration::from_secs(5), handle1)
        .await
        .unwrap()
        .unwrap();
    let cmds2 = tokio::time::timeout(Duration::from_secs(5), handle2)
        .await
        .unwrap()
        .unwrap();

    let mail_count1 = cmds1.iter().filter(|c| c.starts_with("MAIL FROM")).count();
    let mail_count2 = cmds2.iter().filter(|c| c.starts_with("MAIL FROM")).count();
    assert_eq!(
        mail_count1, 1,
        "peer 1 should receive exactly one delivery, got: {:?}",
        cmds1
    );
    assert_eq!(
        mail_count2, 1,
        "peer 2 should receive exactly one delivery, got: {:?}",
        cmds2
    );
}
