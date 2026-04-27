//! RFC 3977 conformance test: Python nntplib client against a live reader.
//!
//! Starts the reader in-process on a random port, posts one article via raw
//! TCP, then drives Python's `nntplib.NNTP` client to verify that
//! CAPABILITIES, LIST, GROUP, OVER, and ARTICLE all return RFC-conformant
//! responses.
//!
//! The test is skipped automatically if `python3` is not found in PATH.
//! On Python 3.12 `nntplib` raises a DeprecationWarning; this test
//! suppresses it with `-W ignore::DeprecationWarning`.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use stoa_core::{hlc::HlcClock, msgid_map::MsgIdMap};
use stoa_reader::{
    post::ipfs_write::{IpfsBlockStore, IpfsWriteError},
    session::lifecycle::run_session,
    store::{
        article_numbers::ArticleNumberStore, client_cert_store::ClientCertStore,
        credentials::CredentialStore, overview::OverviewStore, server_stores::ServerStores,
    },
};

// ── Minimal in-memory IPFS store ──────────────────────────────────────────────

struct MemIpfs {
    blocks: tokio::sync::RwLock<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemIpfs {
    fn new() -> Self {
        Self {
            blocks: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl IpfsBlockStore for MemIpfs {
    async fn put_raw(&self, data: &[u8]) -> Result<Cid, IpfsWriteError> {
        let digest = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, digest);
        self.blocks
            .write()
            .await
            .insert(cid.to_bytes(), data.to_vec());
        Ok(cid)
    }

    async fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), IpfsWriteError> {
        self.blocks.write().await.insert(cid.to_bytes(), data);
        Ok(())
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsWriteError> {
        self.blocks
            .read()
            .await
            .get(&cid.to_bytes())
            .cloned()
            .ok_or_else(|| IpfsWriteError::NotFound(cid.to_string()))
    }
}

// ── Pool helpers ──────────────────────────────────────────────────────────────
//
// Tests use on-disk SQLite backed by a tempdir so they exercise the same
// code path as production deployments (disk + WAL mode).

async fn make_core_pool(dir: &tempfile::TempDir) -> sqlx::SqlitePool {
    let path = dir.path().join("core.db");
    let url = format!("sqlite://{}", path.display());
    let opts = <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str(&url)
        .unwrap()
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .expect("core pool");
    stoa_core::migrations::run_migrations(&pool)
        .await
        .expect("core migrations");
    pool
}

async fn make_reader_pool(dir: &tempfile::TempDir) -> sqlx::SqlitePool {
    let path = dir.path().join("reader.db");
    let url = format!("sqlite://{}", path.display());
    let opts = <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str(&url)
        .unwrap()
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .expect("reader pool");
    stoa_reader::migrations::run_migrations(&pool)
        .await
        .expect("reader migrations");
    pool
}

async fn make_verify_pool(dir: &tempfile::TempDir) -> sqlx::SqlitePool {
    let path = dir.path().join("verify.db");
    let url = format!("sqlite://{}", path.display());
    let opts = <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str(&url)
        .unwrap()
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .expect("verify pool");
    stoa_verify::run_migrations(&pool)
        .await
        .expect("verify migrations");
    pool
}

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

// ── NNTP helpers ──────────────────────────────────────────────────────────────

async fn read_line(r: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> String {
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    line.trim_end_matches(['\r', '\n']).to_string()
}

async fn cmd(
    w: &mut tokio::io::WriteHalf<TcpStream>,
    r: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    c: &str,
) -> String {
    w.write_all(format!("{c}\r\n").as_bytes()).await.unwrap();
    read_line(r).await
}

// ── Python nntplib conformance script ────────────────────────────────────────

fn nntplib_script(port: u16, msgid: &str, newsgroup: &str, subject: &str) -> String {
    format!(
        r#"
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
import sys, nntplib

PORT    = {port}
MSGID   = '{msgid}'
GROUP   = '{newsgroup}'
SUBJECT = '{subject}'

conn = nntplib.NNTP('127.0.0.1', port=PORT)

# CAPABILITIES
resp, caps = conn.capabilities()
assert '101' in resp or resp.startswith('1'), f'CAPABILITIES bad resp: {{resp}}'
print(f'CAPABILITIES: {{resp.strip()}}')

# LIST — group must appear
resp, groups = conn.list()
assert any(g.group == GROUP for g in groups), \
    f'{{GROUP}} not in LIST; got: {{[g.group for g in groups]}}'
print(f'LIST: {{GROUP}} present')

# GROUP
resp, count, first, last, name = conn.group(GROUP)
assert resp.startswith('211'), f'GROUP bad resp: {{resp}}'
assert count >= 1, f'GROUP count must be >= 1; got {{count}}'
print(f'GROUP {{GROUP}}: count={{count}} first={{first}} last={{last}}')

# OVER
resp, overviews = conn.over((first, last))
assert resp.startswith('224'), f'OVER bad resp: {{resp}}'
assert len(overviews) >= 1, f'OVER returned no overviews'
subj_found = any(
    SUBJECT in str(ov[1].get('subject', ''))
    for ov in overviews
)
assert subj_found, f'Subject {{SUBJECT!r}} not found in OVER; got: {{overviews}}'
print(f'OVER: {{len(overviews)}} row(s), subject found')

# ARTICLE
resp, info = conn.article(MSGID)
assert resp.startswith('220'), f'ARTICLE bad resp: {{resp}}'
text = b'\n'.join(info.lines).decode()
assert SUBJECT in text, f'Subject not in article; got: {{text[:200]}}'
assert 'Conformance test body' in text, f'Body not in article; got: {{text[:200]}}'
print(f'ARTICLE {{MSGID}}: ok')

conn.quit()
print('PASS')
"#,
        port = port,
        msgid = msgid,
        newsgroup = newsgroup,
        subject = subject,
    )
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn nntp_conformance_via_nntplib() {
    // Skip if python3 is not available.
    if tokio::process::Command::new("python3")
        .arg("--version")
        .output()
        .await
        .is_err()
    {
        eprintln!("SKIP: python3 not found");
        return;
    }

    let msgid = "<d63@test.example>";
    let newsgroup = "comp.test";
    let subject = "Conformance Subject";

    // ── Set up in-process reader ───────────────────────────────────────────

    let db_dir = tempfile::TempDir::new().expect("tempdir");
    let core_pool = make_core_pool(&db_dir).await;
    let reader_pool = make_reader_pool(&db_dir).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let stores = Arc::new(ServerStores {
        ipfs_store: Arc::new(MemIpfs::new()) as Arc<dyn IpfsBlockStore>,
        msgid_map: Arc::new(MsgIdMap::new(core_pool)),
        log_storage: Arc::new(stoa_core::group_log::MemLogStorage::new()),
        article_numbers: Arc::new(ArticleNumberStore::new(reader_pool.clone())),
        overview_store: Arc::new(OverviewStore::new(reader_pool)),
        credential_store: Arc::new(CredentialStore::empty()),
        client_cert_store: Arc::new(ClientCertStore::empty()),
        trusted_issuer_store: Arc::new(stoa_auth::TrustedIssuerStore::empty()),
        clock: Arc::new(Mutex::new(HlcClock::new([0x03u8; 8], now_ms))),
        signing_key: Arc::new(stoa_core::signing::SigningKey::from_bytes(&[0x44u8; 32])),
        search_index: None,
        smtp_relay_queue: None,
        verification_store: Arc::new(stoa_verify::VerificationStore::new(
            make_verify_pool(&db_dir).await,
        )),
        dkim_authenticator: Arc::new(
            mail_auth::MessageAuthenticator::new_cloudflare_tls().unwrap(),
        ),
        path_hostname: "localhost".to_string(),
        audit_logger: None,
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
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

    // ── POST one article via raw TCP ───────────────────────────────────────

    let stream = TcpStream::connect(addr).await.unwrap();
    let (r_half, mut w_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(r_half);

    let greeting = read_line(&mut reader).await;
    assert!(
        greeting.starts_with("200"),
        "expected 200 greeting, got: {greeting}"
    );

    let post_start = cmd(&mut w_half, &mut reader, "POST").await;
    assert!(
        post_start.starts_with("340"),
        "expected 340 after POST, got: {post_start}"
    );

    let date = common::now_rfc2822();
    let article = format!(
        "Newsgroups: {newsgroup}\r\n\
         From: conform@test.example\r\n\
         Subject: {subject}\r\n\
         Date: {date}\r\n\
         Message-ID: {msgid}\r\n\
         \r\n\
         Conformance test body.\r\n"
    );
    w_half.write_all(article.as_bytes()).await.unwrap();
    w_half.write_all(b".\r\n").await.unwrap();

    let mut post_result = String::new();
    reader.read_line(&mut post_result).await.unwrap();
    assert!(
        post_result.starts_with("240"),
        "expected 240, got: {post_result}"
    );

    let quit = cmd(&mut w_half, &mut reader, "QUIT").await;
    assert!(quit.starts_with("205"), "expected 205, got: {quit}");

    // ── Run Python nntplib conformance check ───────────────────────────────

    let script = nntplib_script(port, msgid, newsgroup, subject);

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::process::Command::new("python3")
            .args(["-W", "ignore::DeprecationWarning", "-c", &script])
            .output(),
    )
    .await
    .expect("nntplib conformance script must complete within 30 s")
    .expect("python3 must be runnable");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Print transcript for record-keeping (visible with `cargo test -- --nocapture`).
    println!("=== nntplib session transcript ===");
    println!("{stdout}");
    if !stderr.is_empty() {
        println!("stderr: {stderr}");
    }
    println!("==================================");

    assert!(
        output.status.success(),
        "nntplib conformance script failed (exit {:?}):\n  stdout: {stdout}\n  stderr: {stderr}",
        output.status.code()
    );

    assert!(
        stdout.contains("PASS"),
        "nntplib script did not print PASS:\n{stdout}"
    );
}
