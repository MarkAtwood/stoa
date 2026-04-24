//! E2E: POST article with X-Stoa-DID-Sig, verify X-Stoa-DID-Verified in ARTICLE response.

mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::Signer;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use stoa_reader::{session::lifecycle::run_session, store::server_stores::ServerStores};

// ── Config helper (same pattern as nntp_conformance.rs) ───────────────────────

fn reader_config(addr: &str) -> stoa_reader::config::Config {
    let toml = format!(
        "[listen]\naddr = \"{addr}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [tls]\n"
    );
    toml::from_str(&toml).expect("reader config must parse")
}

// ── NNTP wire helpers ──────────────────────────────────────────────────────────

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

/// Read all lines of a multiline NNTP response (up to and including ".\r\n"),
/// returning every line that is NOT the terminating dot.
async fn read_multiline(r: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(r).await;
        if line == "." {
            break;
        }
        // Undo dot-stuffing: a line starting with ".." becomes "."
        if let Some(stripped) = line.strip_prefix("..") {
            lines.push(stripped.to_owned());
        } else {
            lines.push(line);
        }
    }
    lines
}

// ── Shared setup ───────────────────────────────────────────────────────────────

/// Spin up an in-process reader and return (write_half, reader, addr).
///
/// The server loop runs in a background task and accepts connections for the
/// lifetime of the test (dropped when the test exits).
async fn start_server() -> (
    std::net::SocketAddr,
    Arc<stoa_reader::config::Config>,
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
                tokio::spawn(async move { run_session(stream, false, &c, s, None).await });
            }
        });
    }

    (addr, config)
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

/// Build a `did:key` URI and the corresponding signing key from a 32-byte seed.
fn make_did_key(seed: [u8; 32]) -> (ed25519_dalek::SigningKey, String) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.as_bytes();
    let mut multicodec = vec![0xed_u8, 0x01]; // Ed25519 multicodec varint
    multicodec.extend_from_slice(pub_bytes);
    let b58 = bs58::encode(&multicodec).into_string();
    let did_key = format!("did:key:z{b58}");
    (signing_key, did_key)
}

/// POST a raw article over NNTP; assert 240 response.
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

// ── Tests ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn did_sig_valid_article_gets_verified_true() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (addr, _config) = start_server().await;

        // Key material
        let (signing_key, did_key) = make_did_key([0x42u8; 32]);

        // Unique message-id to avoid duplicate rejection across test runs
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let msgid = format!("<did-valid-{ts}@e2e.example>");
        let newsgroup = "test.did.verify";
        let date = common::now_rfc2822();

        // Article base bytes — what the author signs BEFORE adding the DID-Sig header.
        let article_base = format!(
            "Newsgroups: {newsgroup}\r\n\
             From: alice@example.com\r\n\
             Subject: DID E2E valid test\r\n\
             Date: {date}\r\n\
             Message-ID: {msgid}\r\n\
             \r\n\
             DID signature E2E test body — valid.\r\n"
        );

        // Sign the base article bytes
        let sig = signing_key.sign(article_base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

        // Build full article: insert DID-Sig header before the blank line
        let header_line = format!("X-Stoa-DID-Sig: {did_key} {sig_b64}\r\n");
        let blank_pos = article_base.find("\r\n\r\n").unwrap();
        let mut full_article = article_base[..blank_pos + 2].to_string();
        full_article.push_str(&header_line);
        full_article.push_str(&article_base[blank_pos + 2..]);

        // POST
        let (mut w, mut r) = connect(addr).await;
        post_article(&mut w, &mut r, &full_article).await;

        // ARTICLE <msgid>
        let article_resp = send_cmd(&mut w, &mut r, &format!("ARTICLE {msgid}")).await;
        assert!(
            article_resp.starts_with("220"),
            "expected 220 for ARTICLE, got: {article_resp}"
        );
        let lines = read_multiline(&mut r).await;

        // Assert X-Stoa-DID-Verified: true is present in the returned headers
        assert!(
            lines
                .iter()
                .any(|h| h.eq_ignore_ascii_case("X-Stoa-DID-Verified: true")),
            "expected X-Stoa-DID-Verified: true in ARTICLE response headers; got:\n{}",
            lines.join("\n")
        );

        let _ = send_cmd(&mut w, &mut r, "QUIT").await;
    })
    .await
    .expect("test must complete within 30 s");
}

#[tokio::test]
async fn did_sig_wrong_sig_gets_verified_false() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (addr, _config) = start_server().await;

        let (signing_key, did_key) = make_did_key([0x43u8; 32]);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let msgid = format!("<did-wrong-{ts}@e2e.example>");
        let newsgroup = "test.did.verify";
        let date = common::now_rfc2822();

        let article_base = format!(
            "Newsgroups: {newsgroup}\r\n\
             From: mallory@example.com\r\n\
             Subject: DID E2E wrong-sig test\r\n\
             Date: {date}\r\n\
             Message-ID: {msgid}\r\n\
             \r\n\
             DID signature E2E test body — wrong sig.\r\n"
        );

        // Sign, then corrupt the signature by flipping the last byte
        let sig = signing_key.sign(article_base.as_bytes());
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[63] ^= 0xff;
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes);

        let header_line = format!("X-Stoa-DID-Sig: {did_key} {sig_b64}\r\n");
        let blank_pos = article_base.find("\r\n\r\n").unwrap();
        let mut full_article = article_base[..blank_pos + 2].to_string();
        full_article.push_str(&header_line);
        full_article.push_str(&article_base[blank_pos + 2..]);

        let (mut w, mut r) = connect(addr).await;
        post_article(&mut w, &mut r, &full_article).await;

        let article_resp = send_cmd(&mut w, &mut r, &format!("ARTICLE {msgid}")).await;
        assert!(
            article_resp.starts_with("220"),
            "expected 220 for ARTICLE, got: {article_resp}"
        );
        let lines = read_multiline(&mut r).await;

        assert!(
            lines
                .iter()
                .any(|h| h.eq_ignore_ascii_case("X-Stoa-DID-Verified: false")),
            "expected X-Stoa-DID-Verified: false in ARTICLE response headers; got:\n{}",
            lines.join("\n")
        );

        let _ = send_cmd(&mut w, &mut r, "QUIT").await;
    })
    .await
    .expect("test must complete within 30 s");
}
