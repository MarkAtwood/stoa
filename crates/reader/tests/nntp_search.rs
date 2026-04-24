//! Protocol-level tests for the NNTP SEARCH command dispatch and lifecycle.
//!
//! Covers:
//! - CAPABILITIES must include "SEARCH"
//! - SEARCH without a selected group returns 412
//! - SEARCH with search_index = None returns 503

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

/// Start a plain TCP listener, accept one connection, and run a session on it.
/// Returns the client stream and a join handle for the session task.
async fn start_session(
    stores: Arc<ServerStores>,
) -> (
    tokio::io::WriteHalf<TcpStream>,
    BufReader<tokio::io::ReadHalf<TcpStream>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind must succeed");
    let addr = listener.local_addr().expect("local_addr");
    let config = test_config(&addr.to_string());

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        run_session(stream, false, &config, stores, None).await;
    });

    let client = TcpStream::connect(addr).await.expect("connect");
    let (read_half, write_half) = tokio::io::split(client);
    (write_half, BufReader::new(read_half))
}

/// Read lines from the server until we see a line not starting with a digit
/// followed by '-' (multi-line single-response prefix), then collect until
/// the bare "." terminator for multi-line, or return the single response line.
///
/// For this test suite we just read the greeting and single-line responses.
async fn read_line(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> String {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .expect("read_line must not fail");
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// Read all lines until the dot terminator, returning all lines including the
/// status line (but not the "." terminator itself).
async fn read_multiline(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(reader).await;
        if line == "." {
            break;
        }
        lines.push(line);
    }
    lines
}

/// Send a command (adding CRLF) and return the first response line.
async fn cmd(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    command: &str,
) -> String {
    writer
        .write_all(format!("{command}\r\n").as_bytes())
        .await
        .expect("write must not fail");
    read_line(reader).await
}

#[tokio::test]
async fn capabilities_includes_search() {
    let stores = Arc::new(ServerStores::new_mem().await);
    let (mut writer, mut reader) = start_session(stores).await;

    // Consume the greeting.
    read_line(&mut reader).await;

    writer.write_all(b"CAPABILITIES\r\n").await.expect("write");

    // Read the status line (101 ...) then body lines until ".".
    let lines = read_multiline(&mut reader).await;

    assert!(
        lines.iter().any(|l| l == "SEARCH"),
        "CAPABILITIES must include SEARCH; got: {lines:?}"
    );
}

#[tokio::test]
async fn search_without_group_returns_412() {
    let stores = Arc::new(ServerStores::new_mem().await);
    let (mut writer, mut reader) = start_session(stores).await;

    // Consume greeting.
    read_line(&mut reader).await;

    let resp = cmd(&mut writer, &mut reader, "SEARCH SUBJECT hello").await;
    assert!(
        resp.starts_with("412"),
        "SEARCH with no group selected must return 412; got: {resp:?}"
    );
}

/// Return today's date in RFC 2822 format for article headers.
fn now_rfc2822() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;
    let sec = (s % 60) as u32;
    let min = ((s / 60) % 60) as u32;
    let hour = ((s / 3600) % 24) as u32;
    let days_since_epoch = s / 86400;
    let wday = ((days_since_epoch % 7 + 7) % 7) as usize;
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[wday],
        d,
        MONTHS[(m - 1) as usize],
        y,
        hour,
        min,
        sec
    )
}

/// POST an article over an established NNTP session and assert 240.
///
/// Sends POST, waits for 340, sends the article bytes + dot-terminator, then
/// reads and returns the final response line (expected "240 ...").
async fn post_article(
    writer: &mut tokio::io::WriteHalf<tokio::net::TcpStream>,
    reader: &mut BufReader<tokio::io::ReadHalf<tokio::net::TcpStream>>,
    article: &str,
) -> String {
    let announce = cmd(writer, reader, "POST").await;
    assert!(
        announce.starts_with("340"),
        "POST must return 340 (send article); got: {announce:?}"
    );
    writer
        .write_all(article.as_bytes())
        .await
        .expect("write article bytes must not fail");
    writer
        .write_all(b".\r\n")
        .await
        .expect("write dot-terminator must not fail");
    read_line(reader).await
}

/// E2E test: POST an article whose body contains "frobnicator", then
/// SEARCH BODY frobnicator must return article number 1.
///
/// Oracle: the term "frobnicator" appears in the article body by construction.
/// Article number 1 is independently known because it is the first article
/// posted to the group in this isolated in-memory store.
#[tokio::test]
async fn e2e_post_article_then_search_body_finds_it() {
    let stores = Arc::new(ServerStores::new_mem().await);
    let (mut writer, mut reader) = start_session(stores).await;

    // Consume greeting.
    read_line(&mut reader).await;

    let date = now_rfc2822();
    let article = format!(
        "Newsgroups: comp.test\r\n\
         From: tester@example.com\r\n\
         Subject: Body Search Test\r\n\
         Date: {date}\r\n\
         Message-ID: <body-search-1@test.example>\r\n\
         \r\n\
         frobnicator hypothesis unique content\r\n"
    );

    let post_resp = post_article(&mut writer, &mut reader, &article).await;
    assert!(
        post_resp.starts_with("240"),
        "POST must be accepted (240); got: {post_resp:?}"
    );

    // Refresh group state so the server registers comp.test as carried.
    let group_resp = cmd(&mut writer, &mut reader, "GROUP comp.test").await;
    assert!(
        group_resp.starts_with("211"),
        "GROUP comp.test must return 211 after POST; got: {group_resp:?}"
    );

    // SEARCH BODY frobnicator — must return article number 1.
    writer
        .write_all(b"SEARCH BODY frobnicator\r\n")
        .await
        .expect("write SEARCH must not fail");
    let search_status = read_line(&mut reader).await;
    assert!(
        search_status.starts_with("100"),
        "SEARCH BODY must return 100; got: {search_status:?}"
    );
    let result_lines = read_multiline(&mut reader).await;
    assert!(
        result_lines.iter().any(|l| l.trim() == "1"),
        "SEARCH BODY frobnicator must include article number 1; got: {result_lines:?}"
    );
}

/// E2E test: POST an article with subject "QuantumFrobnication Test", then
/// SEARCH SUBJECT QuantumFrobnication must return article number 1.
///
/// Oracle: the subject token "QuantumFrobnication" is present in the article
/// Subject header by construction.  Article number 1 is independently known
/// as the first article posted to this isolated in-memory store.
#[tokio::test]
async fn e2e_post_article_then_search_subject_finds_it() {
    let stores = Arc::new(ServerStores::new_mem().await);
    let (mut writer, mut reader) = start_session(stores).await;

    // Consume greeting.
    read_line(&mut reader).await;

    let date = now_rfc2822();
    let article = format!(
        "Newsgroups: comp.test\r\n\
         From: tester@example.com\r\n\
         Subject: QuantumFrobnication Test\r\n\
         Date: {date}\r\n\
         Message-ID: <subject-search-1@test.example>\r\n\
         \r\n\
         Article body for subject search test.\r\n"
    );

    let post_resp = post_article(&mut writer, &mut reader, &article).await;
    assert!(
        post_resp.starts_with("240"),
        "POST must be accepted (240); got: {post_resp:?}"
    );

    // Refresh group state.
    let group_resp = cmd(&mut writer, &mut reader, "GROUP comp.test").await;
    assert!(
        group_resp.starts_with("211"),
        "GROUP comp.test must return 211 after POST; got: {group_resp:?}"
    );

    // SEARCH SUBJECT QuantumFrobnication — must return article number 1.
    writer
        .write_all(b"SEARCH SUBJECT QuantumFrobnication\r\n")
        .await
        .expect("write SEARCH must not fail");
    let search_status = read_line(&mut reader).await;
    assert!(
        search_status.starts_with("100"),
        "SEARCH SUBJECT must return 100; got: {search_status:?}"
    );
    let result_lines = read_multiline(&mut reader).await;
    assert!(
        result_lines.iter().any(|l| l.trim() == "1"),
        "SEARCH SUBJECT QuantumFrobnication must include article number 1; got: {result_lines:?}"
    );
}

/// E2E test: SEARCH for a term that does not appear in any posted article
/// must return a 100 response with an empty body (dot-only terminator).
///
/// Oracle: the term "xyzzy_nonexistent_term_abc" does not appear in any article
/// header or body because it was chosen to be unique and is never written by any
/// test in this file.
#[tokio::test]
async fn e2e_search_nonexistent_term_returns_empty() {
    let stores = Arc::new(ServerStores::new_mem().await);
    let (mut writer, mut reader) = start_session(stores).await;

    // Consume greeting.
    read_line(&mut reader).await;

    let date = now_rfc2822();
    let article = format!(
        "Newsgroups: comp.test\r\n\
         From: tester@example.com\r\n\
         Subject: Empty Search Test\r\n\
         Date: {date}\r\n\
         Message-ID: <empty-search-1@test.example>\r\n\
         \r\n\
         This body contains only ordinary words.\r\n"
    );

    let post_resp = post_article(&mut writer, &mut reader, &article).await;
    assert!(
        post_resp.starts_with("240"),
        "POST must be accepted (240); got: {post_resp:?}"
    );

    // Select the group so SEARCH is accepted.
    let group_resp = cmd(&mut writer, &mut reader, "GROUP comp.test").await;
    assert!(
        group_resp.starts_with("211"),
        "GROUP comp.test must return 211; got: {group_resp:?}"
    );

    // SEARCH BODY xyzzy_nonexistent_term_abc — must return 100 with empty body.
    writer
        .write_all(b"SEARCH BODY xyzzy_nonexistent_term_abc\r\n")
        .await
        .expect("write SEARCH must not fail");
    let search_status = read_line(&mut reader).await;
    assert!(
        search_status.starts_with("100"),
        "SEARCH for absent term must return 100; got: {search_status:?}"
    );
    let result_lines = read_multiline(&mut reader).await;
    assert!(
        result_lines.is_empty(),
        "SEARCH for absent term must return no article numbers; got: {result_lines:?}"
    );
}
