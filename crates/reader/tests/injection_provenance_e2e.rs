//! End-to-end injection-provenance tests for the reader POST pipeline.
//!
//! Verifies that `X-Stoa-Injection-Source` routing is enforced
//! end-to-end through a real NNTP session:
//!
//! - `SmtpListId`: article is readable (GROUP/OVER work), but the group log
//!   receives **no** entry — the article is local-only and will not be
//!   replicated to peers via IHAVE.
//! - `SmtpSieve`: article is readable **and** the group log receives an entry.
//! - `SmtpNewsgroups`: same as SmtpSieve — peerable, so a log entry is written.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use stoa_core::{article::GroupName, group_log::LogStorage};
use stoa_reader::{session::lifecycle::run_session, store::server_stores::ServerStores};

// ── Config ────────────────────────────────────────────────────────────────────

fn test_config(addr: &str) -> stoa_reader::config::Config {
    let toml = format!(
        "[listen]\naddr = \"{addr}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [tls]\n"
    );
    toml::from_str(&toml).expect("minimal config must parse")
}

// ── NNTP helpers ──────────────────────────────────────────────────────────────

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

// ── Article fixture ───────────────────────────────────────────────────────────

/// Build a raw article ready to send after the NNTP `340` response.
///
/// `injection_source` is prepended as the first header line, exactly as the
/// SMTP queue drain does.  Pass `None` to omit the header (normal NNTP POST).
fn make_article(injection_source: Option<&str>, newsgroup: &str, msgid: &str) -> String {
    let mut s = String::new();
    if let Some(src) = injection_source {
        s.push_str(&format!("X-Stoa-Injection-Source: {src}\r\n"));
    }
    s.push_str(&format!("Newsgroups: {newsgroup}\r\n"));
    s.push_str("From: provenance-test@example.com\r\n");
    s.push_str(&format!("Subject: Provenance test {msgid}\r\n"));
    s.push_str("Date: Thu, 23 Apr 2026 12:00:00 +0000\r\n");
    s.push_str(&format!("Message-ID: {msgid}\r\n"));
    s.push_str("\r\n");
    s.push_str("Provenance test body.\r\n");
    s
}

// ── Harness ───────────────────────────────────────────────────────────────────

/// Spin up a reader session, POST one article, verify it is readable via GROUP
/// and OVER, QUIT, then return the stores so the caller can inspect the log.
///
/// Returns `(group_article_count, stores)`.
async fn post_article_and_quit(
    injection_source: Option<&str>,
    newsgroup: &str,
    msgid: &str,
) -> Arc<ServerStores> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(test_config(&addr.to_string()));
    let stores = Arc::new(ServerStores::new_mem().await);

    let config2 = config.clone();
    let stores2 = stores.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        run_session(stream, false, &config2, stores2, None).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(
        greeting.starts_with("200"),
        "expected 200 greeting, got: {greeting}"
    );

    let post_start = send_cmd(&mut write_half, &mut reader, "POST").await;
    assert!(
        post_start.starts_with("340"),
        "expected 340 after POST, got: {post_start}"
    );

    let body = make_article(injection_source, newsgroup, msgid);
    write_half.write_all(body.as_bytes()).await.unwrap();
    write_half.write_all(b".\r\n").await.unwrap();

    let mut post_result = String::new();
    reader.read_line(&mut post_result).await.unwrap();
    assert!(
        post_result.starts_with("240"),
        "expected 240 after article body, got: {post_result}"
    );

    let group_resp = send_cmd(&mut write_half, &mut reader, &format!("GROUP {newsgroup}")).await;
    assert!(
        group_resp.starts_with("211"),
        "expected 211 from GROUP, got: {group_resp}"
    );
    let parts: Vec<&str> = group_resp.split_whitespace().collect();
    assert_eq!(
        parts[1], "1",
        "GROUP count must be 1; full response: {group_resp}"
    );

    let over_resp = send_cmd(&mut write_half, &mut reader, "OVER 1").await;
    assert!(
        over_resp.starts_with("224"),
        "expected 224 from OVER, got: {over_resp}"
    );
    let over_lines = read_dot_body(&mut reader).await;
    assert_eq!(over_lines.len(), 1, "OVER must return exactly one record");

    let quit_resp = send_cmd(&mut write_half, &mut reader, "QUIT").await;
    assert!(
        quit_resp.starts_with("205"),
        "expected 205 from QUIT, got: {quit_resp}"
    );

    stores
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// SmtpListId articles must be readable locally (GROUP/OVER work) but must
/// produce **no** group log entry — they are not replicated to peers.
#[tokio::test]
async fn listid_stays_local() {
    let newsgroup = "comp.test.listid";
    let msgid = "<listid-stays-local@provenance-test.example>";

    let stores = post_article_and_quit(Some("SmtpListId"), newsgroup, msgid).await;

    let group_name = GroupName::new(newsgroup).expect("group name must be valid");
    let tips = stores
        .log_storage
        .list_tips(&group_name)
        .await
        .expect("list_tips must not fail");

    assert!(
        tips.is_empty(),
        "SmtpListId article must not write a group log entry (local-only); tips: {tips:?}"
    );
}

/// SmtpSieve articles must be readable **and** produce a group log entry
/// (they are peerable — the sieve script explicitly routed them to a newsgroup).
#[tokio::test]
async fn sieve_route_peers() {
    let newsgroup = "comp.test.sieve";
    let msgid = "<sieve-route-peers@provenance-test.example>";

    let stores = post_article_and_quit(Some("SmtpSieve"), newsgroup, msgid).await;

    let group_name = GroupName::new(newsgroup).expect("group name must be valid");
    let tips = stores
        .log_storage
        .list_tips(&group_name)
        .await
        .expect("list_tips must not fail");

    assert!(
        !tips.is_empty(),
        "SmtpSieve article must write a group log entry (peerable); tips were empty"
    );
}

/// SmtpNewsgroups articles (Newsgroups: header present in the SMTP message)
/// must also produce a group log entry — they are peerable.
#[tokio::test]
async fn newsgroups_header_peers() {
    let newsgroup = "comp.test.newsgroups";
    let msgid = "<newsgroups-header-peers@provenance-test.example>";

    let stores = post_article_and_quit(Some("SmtpNewsgroups"), newsgroup, msgid).await;

    let group_name = GroupName::new(newsgroup).expect("group name must be valid");
    let tips = stores
        .log_storage
        .list_tips(&group_name)
        .await
        .expect("list_tips must not fail");

    assert!(
        !tips.is_empty(),
        "SmtpNewsgroups article must write a group log entry (peerable); tips were empty"
    );
}
