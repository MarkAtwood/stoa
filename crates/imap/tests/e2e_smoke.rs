//! End-to-end smoke test: raw TCP client connects to the session loop.
//!
//! Uses the in-process session runner (`run_session_plain`) bound on a random
//! loopback port.  No TLS — so only CAPABILITY/NOOP/LOGOUT are exercised
//! (AUTH requires TLS; LOGINDISABLED is advertised on plain connections).

use std::sync::Arc;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use usenet_ipfs_imap::{
    config::{
        AdminConfig, AuthConfig, DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, TlsConfig,
        UserCredential,
    },
    session::run_session_plain,
};

/// Build an in-memory pool with the IMAP schema applied.
async fn test_pool() -> Arc<sqlx::SqlitePool> {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.expect("in-memory pool");
    sqlx::query(
        "CREATE TABLE imap_uid_validity (
            mailbox     TEXT    NOT NULL PRIMARY KEY,
            uidvalidity INTEGER NOT NULL,
            next_uid    INTEGER NOT NULL DEFAULT 1
        )",
    )
    .execute(&pool)
    .await
    .expect("create table");
    sqlx::query(
        "CREATE TABLE imap_flags (
            username TEXT    NOT NULL,
            mailbox  TEXT    NOT NULL,
            uid      INTEGER NOT NULL,
            flags    TEXT    NOT NULL DEFAULT '',
            PRIMARY KEY (username, mailbox, uid)
        )",
    )
    .execute(&pool)
    .await
    .expect("create flags table");
    Arc::new(pool)
}

fn test_config() -> Arc<usenet_ipfs_imap::config::Config> {
    Arc::new(usenet_ipfs_imap::config::Config {
        listen: ListenConfig { addr: "127.0.0.1:0".into(), tls_addr: None },
        database: DatabaseConfig { path: ":memory:".into() },
        limits: LimitsConfig::default(),
        auth: AuthConfig {
            mechanisms: vec!["PLAIN".into(), "LOGIN".into()],
            users: vec![UserCredential {
                username: "testuser".into(),
                password: "testpass".into(),
            }],
        },
        tls: TlsConfig { cert_path: None, key_path: None },
        admin: AdminConfig::default(),
        log: LogConfig::default(),
    })
}

/// Read one IMAP line, stripping CRLF.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read line");
    line.trim_end_matches(['\r', '\n']).to_owned()
}

#[tokio::test]
async fn smoke_greeting_capability_noop_logout() {
    let pool = test_pool().await;
    let config = test_config();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    // Spawn the server session; it handles exactly one connection.
    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        run_session_plain(stream, peer, srv_config, srv_pool).await;
    });

    // Connect a raw client.
    let stream = TcpStream::connect(addr).await.expect("connect");
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // Greeting.
    let greeting = read_line(&mut rd).await;
    assert!(greeting.starts_with("* OK"), "expected greeting, got: {greeting}");

    // CAPABILITY.
    wr.write_all(b"T01 CAPABILITY\r\n").await.expect("write");
    let cap_data = read_line(&mut rd).await;
    assert!(cap_data.starts_with("* CAPABILITY"), "got: {cap_data}");
    assert!(
        cap_data.contains("LOGINDISABLED"),
        "plain session must advertise LOGINDISABLED, got: {cap_data}"
    );
    assert!(
        !cap_data.contains("AUTH=PLAIN"),
        "plain session must not advertise AUTH=PLAIN, got: {cap_data}"
    );
    let cap_ok = read_line(&mut rd).await;
    assert!(cap_ok.starts_with("T01 OK"), "got: {cap_ok}");

    // NOOP.
    wr.write_all(b"T02 NOOP\r\n").await.expect("write");
    let noop_ok = read_line(&mut rd).await;
    assert!(noop_ok.starts_with("T02 OK"), "got: {noop_ok}");

    // LOGOUT.
    wr.write_all(b"T03 LOGOUT\r\n").await.expect("write");
    let bye = read_line(&mut rd).await;
    assert!(bye.starts_with("* BYE"), "got: {bye}");
    let logout_ok = read_line(&mut rd).await;
    assert!(logout_ok.starts_with("T03 OK"), "got: {logout_ok}");
}

#[tokio::test]
async fn smoke_unknown_command_returns_bad() {
    let pool = test_pool().await;
    let config = test_config();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let srv_pool = Arc::clone(&pool);
    let srv_config = Arc::clone(&config);
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        run_session_plain(stream, peer, srv_config, srv_pool).await;
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // Consume greeting.
    let _ = read_line(&mut rd).await;

    // COPY (unimplemented) → BAD.
    wr.write_all(b"U01 COPY 1:* INBOX\r\n").await.expect("write");
    let bad = read_line(&mut rd).await;
    assert!(bad.starts_with("U01 BAD"), "expected BAD for unimplemented command, got: {bad}");

    // Clean shutdown.
    wr.write_all(b"U02 LOGOUT\r\n").await.expect("write");
    let _ = read_line(&mut rd).await; // BYE
    let _ = read_line(&mut rd).await; // OK
}
