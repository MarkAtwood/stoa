//! End-to-end data flow integration test for the reader server.
//!
//! Starts a real TCP listener, spawns a session task, POSTs an article, then
//! verifies GROUP, OVER, and ARTICLE all return the expected data.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use usenet_ipfs_reader::{
    config::UserCredential,
    session::lifecycle::run_session,
    store::{credentials::CredentialStore, server_stores::ServerStores},
};

fn test_config(addr: &str) -> usenet_ipfs_reader::config::Config {
    let toml = format!(
        "[listen]\naddr = \"{addr}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [tls]\n"
    );
    toml::from_str(&toml).expect("minimal config must parse")
}

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

fn test_article(newsgroup: &str, subject: &str, msgid: &str) -> String {
    let date = now_rfc2822();
    format!(
        "Newsgroups: {newsgroup}\r\n\
         From: tester@example.com\r\n\
         Subject: {subject}\r\n\
         Date: {date}\r\n\
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
        run_session(stream, false, &config2, stores2).await;
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

/// After `MAX_AUTH_FAILURES` (5) consecutive AUTHINFO PASS failures the server
/// must close the connection with a 400 response, not accept further commands.
///
/// Uses bcrypt cost 4 (minimum, ~5ms/verify) to keep the test fast while still
/// exercising the real credential path.
#[tokio::test]
async fn authinfo_rate_limiter_closes_after_max_failures() {
    use usenet_ipfs_reader::session::context::MAX_AUTH_FAILURES;

    // Precompute a hash at cost 4 for speed (DEFAULT_COST≈100ms × 5 is too slow).
    let hash = bcrypt::hash("right-password", 4).expect("bcrypt::hash must not fail");
    let mut stores = ServerStores::new_mem().await;
    // Replace the empty store with one that has a known user — all wrong-password
    // checks will run real bcrypt verify (returning false) at low cost.
    stores.credential_store =
        std::sync::Arc::new(CredentialStore::from_credentials(&[UserCredential {
            username: "alice".to_string(),
            password: hash,
        }]));
    let stores = std::sync::Arc::new(stores);

    // Config with auth.required=false but users=[alice] — disables dev mode so
    // credential checks actually run.
    let addr_str = "127.0.0.1:0";
    let toml = format!(
        "[listen]\naddr = \"{addr_str}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [[auth.users]]\nusername = \"alice\"\npassword = \"placeholder\"\n\
         [tls]\n"
    );
    let config: usenet_ipfs_reader::config::Config =
        toml::from_str(&toml).expect("config must parse");
    let config = std::sync::Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config2 = config.clone();
    let stores2 = stores.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        run_session(stream, false, &config2, stores2).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Consume the greeting.
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(
        greeting.starts_with("200") || greeting.starts_with("201"),
        "greeting: {greeting}"
    );

    // Send MAX_AUTH_FAILURES wrong passwords.  Each one should return 481.
    // The (MAX_AUTH_FAILURES)th failure should close the connection with 400.
    for attempt in 1..=MAX_AUTH_FAILURES {
        let user_resp = send_cmd(&mut write_half, &mut reader, "AUTHINFO USER alice").await;
        assert!(
            user_resp.starts_with("381"),
            "attempt {attempt}: expected 381, got: {user_resp}"
        );

        let pass_resp = send_cmd(&mut write_half, &mut reader, "AUTHINFO PASS wrong").await;
        if attempt < MAX_AUTH_FAILURES {
            assert!(
                pass_resp.starts_with("481"),
                "attempt {attempt}: expected 481, got: {pass_resp}"
            );
        } else {
            assert!(
                pass_resp.starts_with("400"),
                "final attempt: expected 400 (close), got: {pass_resp}"
            );
        }
    }
}
