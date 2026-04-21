//! End-to-end data flow integration test for the reader server.
//!
//! Starts a real TCP listener, spawns a session task, POSTs an article, then
//! verifies GROUP, OVER, and ARTICLE all return the expected data.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use usenet_ipfs_reader::{session::lifecycle::run_session, store::server_stores::ServerStores};

fn test_config(addr: &str) -> usenet_ipfs_reader::config::Config {
    let toml = format!(
        "[listen]\naddr = \"{addr}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [tls]\n"
    );
    toml::from_str(&toml).expect("minimal config must parse")
}

fn test_article(newsgroup: &str, subject: &str, msgid: &str) -> String {
    format!(
        "Newsgroups: {newsgroup}\r\n\
         From: tester@example.com\r\n\
         Subject: {subject}\r\n\
         Date: Mon, 20 Apr 2026 12:00:00 +0000\r\n\
         Message-ID: {msgid}\r\n\
         \r\n\
         Article body line one.\r\n\
         Article body line two.\r\n"
    )
}

/// Send a command and return the first response line.
async fn send_cmd(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    command: &str,
) -> String {
    writer
        .write_all(format!("{command}\r\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// Consume a dot-terminated multi-line response body. Returns all data lines.
async fn read_dot_body(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "." {
            break;
        }
        lines.push(trimmed.to_string());
    }
    lines
}

#[tokio::test]
async fn e2e_post_group_over_article() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(test_config(&addr.to_string()));
    let stores = Arc::new(ServerStores::new_mem().await);

    // Spawn the server session in the background.
    let config2 = config.clone();
    let stores2 = stores.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        run_session(stream, &config2, stores2).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Read greeting.
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(
        greeting.starts_with("200"),
        "expected 200 greeting, got: {greeting}"
    );

    // POST phase 1: announce POST.
    let post_start = send_cmd(&mut write_half, &mut reader, "POST").await;
    assert!(
        post_start.starts_with("340"),
        "expected 340, got: {post_start}"
    );

    // POST phase 2: send article body then dot-terminator.
    let body = test_article("comp.test", "E2E Test Subject", "<e2e@test.example>");
    write_half.write_all(body.as_bytes()).await.unwrap();
    write_half.write_all(b".\r\n").await.unwrap();

    let mut post_result = String::new();
    reader.read_line(&mut post_result).await.unwrap();
    assert!(
        post_result.starts_with("240"),
        "expected 240 after article body, got: {post_result}"
    );

    // GROUP comp.test — must report 1 article.
    let group_resp = send_cmd(&mut write_half, &mut reader, "GROUP comp.test").await;
    assert!(
        group_resp.starts_with("211"),
        "expected 211, got: {group_resp}"
    );
    let parts: Vec<&str> = group_resp.split_whitespace().collect();
    assert_eq!(
        parts[1], "1",
        "GROUP count must be 1; full response: {group_resp}"
    );

    // OVER 1 — must return the overview record for article 1.
    let over_resp = send_cmd(&mut write_half, &mut reader, "OVER 1").await;
    assert!(
        over_resp.starts_with("224"),
        "expected 224, got: {over_resp}"
    );
    let over_lines = read_dot_body(&mut reader).await;
    assert_eq!(over_lines.len(), 1, "OVER must return exactly one record");
    assert!(
        over_lines[0].contains("E2E Test Subject"),
        "OVER record must include the subject; got: {}",
        over_lines[0]
    );

    // ARTICLE <e2e@test.example> — must return the stored article.
    let article_resp = send_cmd(&mut write_half, &mut reader, "ARTICLE <e2e@test.example>").await;
    assert!(
        article_resp.starts_with("220"),
        "expected 220, got: {article_resp}"
    );
    let article_lines = read_dot_body(&mut reader).await;
    assert!(
        article_lines.iter().any(|l| l.contains("E2E Test Subject")),
        "ARTICLE response must include the Subject header"
    );
    assert!(
        article_lines
            .iter()
            .any(|l| l.contains("Article body line one")),
        "ARTICLE response must include body text"
    );

    // Clean shutdown.
    let quit_resp = send_cmd(&mut write_half, &mut reader, "QUIT").await;
    assert!(
        quit_resp.starts_with("205"),
        "expected 205, got: {quit_resp}"
    );
}
