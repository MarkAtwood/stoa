//! E2E: POST article, verify X-Stoa-Sig via operator key, check NNTP and JMAP surfaces.
//!
//! NNTP surface: after POST, ARTICLE response must include `X-Stoa-Verified: pass`.
//! JMAP surface: after POST, the verification store holds a Pass result for the article CID,
//!   which the JMAP handler would project into `Email.x-stoa-verifications`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use stoa_reader::{
    session::lifecycle::{run_session, ListenerKind},
    store::server_stores::ServerStores,
};
use stoa_verify::VerifResult;

// ── Config helper ─────────────────────────────────────────────────────────────

fn reader_config(addr: &str) -> stoa_reader::config::Config {
    let toml = format!(
        "[listen]\naddr = \"{addr}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [tls]\n"
    );
    toml::from_str(&toml).expect("reader config must parse")
}

// ── NNTP wire helpers ─────────────────────────────────────────────────────────

async fn read_line(r: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> String {
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    line.trim_end_matches(['\r', '\n']).to_string()
}

async fn send_cmd(
    w: &mut tokio::io::WriteHalf<TcpStream>,
    r: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    cmd: &str,
) -> String {
    w.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
    read_line(r).await
}

async fn read_multiline(r: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(r).await;
        if line == "." {
            break;
        }
        if let Some(stripped) = line.strip_prefix("..") {
            lines.push(stripped.to_owned());
        } else {
            lines.push(line);
        }
    }
    lines
}

// ── Server setup ──────────────────────────────────────────────────────────────

/// Spin up a reader server and return (addr, config, shared stores Arc).
///
/// The stores Arc lets tests inspect the verification store after article ingestion.
async fn start_server() -> (
    std::net::SocketAddr,
    Arc<stoa_reader::config::Config>,
    Arc<ServerStores>,
) {
    let stores = Arc::new(ServerStores::new_mem().await);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(reader_config(&addr.to_string()));

    {
        let stores = Arc::clone(&stores);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let s = Arc::clone(&stores);
                let c = Arc::clone(&config);
                tokio::spawn(
                    async move { run_session(stream, ListenerKind::Plain, &c, s, None).await },
                );
            }
        });
    }

    (addr, config, stores)
}

/// Connect to `addr`, consume the greeting, and return (write_half, buf_reader).
async fn connect(
    addr: std::net::SocketAddr,
) -> (
    tokio::io::WriteHalf<TcpStream>,
    BufReader<tokio::io::ReadHalf<TcpStream>>,
) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (r_half, w_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(r_half);
    let greeting = read_line(&mut reader).await;
    assert!(
        greeting.starts_with("200"),
        "expected 200 greeting, got: {greeting}"
    );
    (w_half, reader)
}

/// POST a raw article and assert 240 response.
async fn post_article(
    w: &mut tokio::io::WriteHalf<TcpStream>,
    r: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    article: &str,
) {
    let post_start = send_cmd(w, r, "POST").await;
    assert!(
        post_start.starts_with("340"),
        "expected 340 after POST, got: {post_start}"
    );
    w.write_all(article.as_bytes()).await.unwrap();
    w.write_all(b".\r\n").await.unwrap();
    let mut result = String::new();
    r.read_line(&mut result).await.unwrap();
    assert!(
        result.starts_with("240"),
        "expected 240 after article, got: {result}"
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// NNTP surface: posted article gets operator-signed and X-Stoa-Verified: pass
/// injected in the ARTICLE response.
#[tokio::test]
async fn posted_article_nntp_verified_pass() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (addr, _config, _stores) = start_server().await;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let msgid = format!("<verify-e2e-nntp-{ts}@e2e.example>");
        let newsgroup = "test.verify.e2e";
        let date = common::now_rfc2822();

        let article = format!(
            "Newsgroups: {newsgroup}\r\n\
             From: alice@example.com\r\n\
             Subject: Verify E2E NNTP test\r\n\
             Date: {date}\r\n\
             Message-ID: {msgid}\r\n\
             \r\n\
             Article body for verify E2E NNTP test.\r\n"
        );

        let (mut w, mut r) = connect(addr).await;
        post_article(&mut w, &mut r, &article).await;

        let article_resp = send_cmd(&mut w, &mut r, &format!("ARTICLE {msgid}")).await;
        assert!(
            article_resp.starts_with("220"),
            "expected 220 for ARTICLE, got: {article_resp}"
        );
        let lines = read_multiline(&mut r).await;

        assert!(
            lines
                .iter()
                .any(|h| h.eq_ignore_ascii_case("X-Stoa-Verified: pass")),
            "expected X-Stoa-Verified: pass in ARTICLE headers; got:\n{}",
            lines.join("\n")
        );

        let _ = send_cmd(&mut w, &mut r, "QUIT").await;
    })
    .await
    .expect("test must complete within 30 s");
}

/// JMAP surface: verification store holds a Pass result for the article after POST.
///
/// The JMAP handler queries the verify store and projects results into
/// `Email.x-stoa-verifications`.  This test validates the store data
/// that the JMAP surface consumes.
#[tokio::test]
async fn posted_article_jmap_verify_store_has_pass() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (addr, _config, stores) = start_server().await;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let msgid = format!("<verify-e2e-jmap-{ts}@e2e.example>");
        let newsgroup = "test.verify.e2e";
        let date = common::now_rfc2822();

        let article = format!(
            "Newsgroups: {newsgroup}\r\n\
             From: bob@example.com\r\n\
             Subject: Verify E2E JMAP test\r\n\
             Date: {date}\r\n\
             Message-ID: {msgid}\r\n\
             \r\n\
             Article body for verify E2E JMAP test.\r\n"
        );

        let (mut w, mut r) = connect(addr).await;
        post_article(&mut w, &mut r, &article).await;

        // Retrieve the CID for the article via XCID — response: "290 <cid>"
        let xcid_resp = send_cmd(&mut w, &mut r, &format!("XCID {msgid}")).await;
        assert!(
            xcid_resp.starts_with("290"),
            "expected 290 for XCID, got: {xcid_resp}"
        );
        let cid_str = xcid_resp
            .split_whitespace()
            .nth(1)
            .expect("XCID response must have CID field");
        let cid: cid::Cid = cid_str.parse().expect("XCID response CID must parse");

        // Query the verification store directly (simulating what the JMAP handler does)
        let verifications = stores
            .verification_store
            .get_verifications(&cid)
            .await
            .expect("get_verifications must not fail");

        // The operator signed the article; we should have at least one Pass result
        assert!(
            !verifications.is_empty(),
            "verification store must have results for a posted article"
        );
        assert!(
            verifications.iter().any(|v| v.result == VerifResult::Pass),
            "expected at least one Pass result; got: {:?}",
            verifications
        );

        let _ = send_cmd(&mut w, &mut r, "QUIT").await;
    })
    .await
    .expect("test must complete within 30 s");
}
