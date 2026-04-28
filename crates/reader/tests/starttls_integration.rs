//! Integration tests for the STARTTLS upgrade path in the NNTP reader server.
//!
//! These tests verify:
//! 1. STARTTLS appears in CAPABILITIES when TLS cert/key are configured.
//! 2. STARTTLS upgrade succeeds: the client receives 382, performs a TLS
//!    handshake on the same TCP connection, and can then issue commands.
//! 3. STARTTLS does NOT appear in CAPABILITIES after the upgrade.
//! 4. A second STARTTLS on an already-TLS session returns 502.
//! 5. AUTHINFO USER works after STARTTLS (session accepts commands over TLS).
//!
//! Architecture: each test binds a TCP listener on 127.0.0.1:0, spawns
//! `run_session(stream, ListenerKind::Plain, ...)` in a background task, then drives a
//! `TcpStream` client manually.  After sending STARTTLS and reading the 382
//! response, the client performs a TLS handshake using `tokio_rustls::TlsConnector`
//! with a custom `ServerCertVerifier` that accepts the self-signed test cert.
//!
//! No IPFS daemon is required.  All storage uses `ServerStores::new_mem()`.

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;

use stoa_reader::{
    session::lifecycle::{run_session, ListenerKind},
    store::server_stores::ServerStores,
    tls::load_tls_acceptor,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Install the aws-lc-rs CryptoProvider as the process-level default.
///
/// rustls 0.23 requires an explicit provider selection when both `ring` and
/// `aws-lc-rs` are present in the dependency tree.  Uses `OnceLock` so the
/// call is idempotent when multiple tests run in the same process.
///
/// We use aws-lc-rs because that is the provider enabled by `tokio-rustls`
/// in this workspace's dependency tree.
fn install_crypto_provider() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap_or(());
    });
}

/// Write a self-signed certificate and private key to a temp directory.
///
/// Returns the `TempDir` (keep alive to prevent premature deletion), and the
/// paths to `cert.pem` and `key.pem` within it.
fn write_test_tls_files() -> (TempDir, String, String) {
    let cert = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("rcgen must generate a self-signed cert");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let dir = TempDir::new().expect("tempdir must be created");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert_pem).expect("cert.pem write must succeed");
    std::fs::write(&key_path, key_pem).expect("key.pem write must succeed");

    let cert_str = cert_path
        .to_str()
        .expect("cert path must be UTF-8")
        .to_owned();
    let key_str = key_path
        .to_str()
        .expect("key path must be UTF-8")
        .to_owned();
    (dir, cert_str, key_str)
}

/// Construct a minimal `Config` with TLS paths pointing to the given files.
fn test_config_with_tls(
    addr: &str,
    cert_path: &str,
    key_path: &str,
) -> stoa_reader::config::Config {
    let toml = format!(
        "[listen]\naddr = \"{addr}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [tls]\ncert_path = \"{cert_path}\"\nkey_path = \"{key_path}\"\n"
    );
    toml::from_str(&toml).expect("test config with TLS must parse")
}

/// Construct a minimal `Config` with no TLS configured.
fn test_config_no_tls(addr: &str) -> stoa_reader::config::Config {
    let toml = format!(
        "[listen]\naddr = \"{addr}\"\n\
         [limits]\nmax_connections = 10\ncommand_timeout_secs = 30\n\
         [auth]\nrequired = false\n\
         [tls]\n"
    );
    toml::from_str(&toml).expect("test config without TLS must parse")
}

/// Bind a TCP listener and spawn a single-connection `run_session` server.
///
/// Returns the bound address.  The server task accepts one connection and runs
/// it to completion (QUIT or EOF).
async fn spawn_server(
    config: Arc<stoa_reader::config::Config>,
    stores: Arc<ServerStores>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TCP listener must bind");
    let addr = listener
        .local_addr()
        .expect("listener must have local addr");

    // Load the TLS acceptor from config paths (if configured) and wrap in Arc
    // so it can be shared across connections.
    let tls_acceptor: Option<Arc<stoa_reader::tls::TlsAcceptor>> = match (
        config.tls.cert_path.as_deref(),
        config.tls.key_path.as_deref(),
    ) {
        (Some(cert), Some(key)) => Some(Arc::new(
            load_tls_acceptor(cert, key).expect("test TLS acceptor must load"),
        )),
        _ => None,
    };

    tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("server accept must succeed");
        run_session(stream, ListenerKind::Plain, &config, stores, tls_acceptor).await;
    });

    addr
}

/// Read one response line from the reader, with a 5-second timeout.
async fn read_line(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> String {
    let mut line = String::new();
    timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("read_line must not time out")
        .expect("read_line must not error");
    line.trim_end_matches(['\r', '\n']).to_owned()
}

/// Send a command (appends CRLF) and return the first response line.
async fn send_cmd(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    cmd: &str,
) -> String {
    timeout(
        Duration::from_secs(5),
        writer.write_all(format!("{cmd}\r\n").as_bytes()),
    )
    .await
    .expect("write must not time out")
    .expect("write must not error");
    read_line(reader).await
}

/// Read a dot-terminated multi-line body.  Returns the lines (excluding the
/// bare `.` terminator).
async fn read_dot_body(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Vec<String> {
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

/// A `ServerCertVerifier` that accepts any certificate without validation.
///
/// Used on the test client side to connect to a server presenting a self-signed
/// test certificate.  This verifier must never appear in production code.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Build a `TlsConnector` that accepts any server certificate.
fn danger_tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

// ── Test 1: STARTTLS in CAPABILITIES ─────────────────────────────────────────

/// STARTTLS must appear in the CAPABILITIES list when TLS cert/key are
/// configured.
///
/// Oracle: the CAPABILITIES response (multi-line, dot-terminated) contains a
/// line equal to "STARTTLS".  This is the prerequisite for all upgrade tests.
#[tokio::test]
async fn starttls_advertised_in_capabilities_when_tls_configured() {
    install_crypto_provider();
    let (_dir, cert_path, key_path) = write_test_tls_files();
    let config = Arc::new(test_config_with_tls("127.0.0.1:0", &cert_path, &key_path));
    let stores = Arc::new(ServerStores::new_mem().await);

    let addr = spawn_server(config, stores).await;

    let stream = TcpStream::connect(addr).await.expect("client must connect");
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Consume the greeting.
    let greeting = read_line(&mut reader).await;
    assert!(
        greeting.starts_with("200"),
        "expected 200 greeting, got: {greeting}"
    );

    // Send CAPABILITIES and collect the dot-terminated body.
    let caps_first = send_cmd(&mut write_half, &mut reader, "CAPABILITIES").await;
    assert!(
        caps_first.starts_with("101"),
        "expected 101 Capabilities list, got: {caps_first}"
    );
    let caps = read_dot_body(&mut reader).await;

    assert!(
        caps.iter().any(|l| l == "STARTTLS"),
        "STARTTLS must appear in CAPABILITIES when TLS is configured; got: {caps:?}"
    );

    let quit = send_cmd(&mut write_half, &mut reader, "QUIT").await;
    assert!(quit.starts_with("205"), "expected 205 quit, got: {quit}");
}

// ── Test 2: STARTTLS upgrade succeeds ────────────────────────────────────────

/// Sending STARTTLS on a plain connection returns 382, after which the client
/// performs a TLS handshake and can issue commands over the encrypted channel.
///
/// The post-upgrade CAPABILITIES response must NOT contain STARTTLS (RFC 4642:
/// a second STARTTLS is unavailable once already running over TLS).
///
/// Oracle:
/// - 382 response to STARTTLS command.
/// - TLS handshake completes without error.
/// - Post-upgrade CAPABILITIES does not list STARTTLS.
/// - QUIT returns 205 over the TLS channel.
#[tokio::test]
async fn starttls_upgrade_succeeds_and_removes_starttls_from_capabilities() {
    install_crypto_provider();
    let (_dir, cert_path, key_path) = write_test_tls_files();
    let config = Arc::new(test_config_with_tls("127.0.0.1:0", &cert_path, &key_path));
    let stores = Arc::new(ServerStores::new_mem().await);

    let addr = spawn_server(config, stores).await;

    let stream = TcpStream::connect(addr).await.expect("client must connect");
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Consume greeting.
    let greeting = read_line(&mut reader).await;
    assert!(greeting.starts_with("200"), "greeting: {greeting}");

    // Issue STARTTLS — expect 382.
    let starttls_resp = send_cmd(&mut write_half, &mut reader, "STARTTLS").await;
    assert!(
        starttls_resp.starts_with("382"),
        "expected 382 Continue with TLS negotiation, got: {starttls_resp}"
    );

    // Reunite the TCP stream and perform the TLS handshake.
    let plain_stream = reader.into_inner().unsplit(write_half);
    let connector = danger_tls_connector();
    let server_name =
        ServerName::try_from("localhost").expect("'localhost' is a valid server name");
    let tls_stream = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, plain_stream),
    )
    .await
    .expect("TLS connect must not time out")
    .expect("TLS handshake must succeed");

    // Drive the post-upgrade session over the TLS stream.
    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_reader = BufReader::new(tls_read);

    // RFC 4642 §2.2: no greeting is re-sent after the handshake.
    // The first command the client sends after the handshake should be answered.
    timeout(
        Duration::from_secs(5),
        tls_write.write_all(b"CAPABILITIES\r\n"),
    )
    .await
    .expect("write must not time out")
    .expect("write must not error");

    let caps_first = {
        let mut line = String::new();
        timeout(Duration::from_secs(5), tls_reader.read_line(&mut line))
            .await
            .expect("read must not time out")
            .expect("read must not error");
        line.trim_end_matches(['\r', '\n']).to_owned()
    };
    assert!(
        caps_first.starts_with("101"),
        "post-upgrade CAPABILITIES must start with 101, got: {caps_first}"
    );

    // Read the dot-terminated capabilities list.
    let mut post_caps = Vec::new();
    loop {
        let mut line = String::new();
        timeout(Duration::from_secs(5), tls_reader.read_line(&mut line))
            .await
            .expect("read must not time out")
            .expect("read must not error");
        let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
        if trimmed == "." {
            break;
        }
        post_caps.push(trimmed);
    }

    assert!(
        !post_caps.iter().any(|l| l == "STARTTLS"),
        "STARTTLS must NOT appear in post-upgrade CAPABILITIES; got: {post_caps:?}"
    );

    // Clean shutdown over TLS.
    timeout(Duration::from_secs(5), tls_write.write_all(b"QUIT\r\n"))
        .await
        .expect("write must not time out")
        .expect("write must not error");

    let mut quit_line = String::new();
    timeout(Duration::from_secs(5), tls_reader.read_line(&mut quit_line))
        .await
        .expect("read must not time out")
        .expect("read must not error");
    assert!(
        quit_line.starts_with("205"),
        "expected 205 after QUIT over TLS, got: {quit_line}"
    );
}

// ── Test 3: Second STARTTLS returns 502 ──────────────────────────────────────

/// After a successful STARTTLS upgrade, sending STARTTLS again must return 502
/// (Command unavailable — already running over TLS).
///
/// Oracle: the server responds 502 to the second STARTTLS command on the
/// post-upgrade TLS channel.
#[tokio::test]
async fn second_starttls_on_tls_session_returns_502() {
    install_crypto_provider();
    let (_dir, cert_path, key_path) = write_test_tls_files();
    let config = Arc::new(test_config_with_tls("127.0.0.1:0", &cert_path, &key_path));
    let stores = Arc::new(ServerStores::new_mem().await);

    let addr = spawn_server(config, stores).await;

    let stream = TcpStream::connect(addr).await.expect("client must connect");
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.starts_with("200"), "greeting: {greeting}");

    let starttls_resp = send_cmd(&mut write_half, &mut reader, "STARTTLS").await;
    assert!(
        starttls_resp.starts_with("382"),
        "expected 382, got: {starttls_resp}"
    );

    let plain_stream = reader.into_inner().unsplit(write_half);
    let connector = danger_tls_connector();
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls_stream = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, plain_stream),
    )
    .await
    .expect("TLS connect must not time out")
    .expect("TLS handshake must succeed");

    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_reader = BufReader::new(tls_read);

    // Second STARTTLS must return 502.
    timeout(Duration::from_secs(5), tls_write.write_all(b"STARTTLS\r\n"))
        .await
        .expect("write must not time out")
        .expect("write must not error");

    let mut second_resp = String::new();
    timeout(
        Duration::from_secs(5),
        tls_reader.read_line(&mut second_resp),
    )
    .await
    .expect("read must not time out")
    .expect("read must not error");

    assert!(
        second_resp.starts_with("502"),
        "second STARTTLS on TLS session must return 502, got: {second_resp}"
    );

    // Clean shutdown.
    timeout(Duration::from_secs(5), tls_write.write_all(b"QUIT\r\n"))
        .await
        .expect("write must not time out")
        .expect("write must not error");
}

// ── Test 4: STARTTLS absent in CAPABILITIES when TLS not configured ───────────

/// When no cert/key are configured, STARTTLS must NOT appear in CAPABILITIES.
///
/// Oracle: the CAPABILITIES dot-terminated body does not contain a "STARTTLS"
/// line.  This is the complementary test to test 1.
#[tokio::test]
async fn starttls_not_advertised_in_capabilities_when_tls_not_configured() {
    install_crypto_provider();
    let config = Arc::new(test_config_no_tls("127.0.0.1:0"));
    let stores = Arc::new(ServerStores::new_mem().await);

    let addr = spawn_server(config, stores).await;

    let stream = TcpStream::connect(addr).await.expect("client must connect");
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.starts_with("200"), "greeting: {greeting}");

    let caps_first = send_cmd(&mut write_half, &mut reader, "CAPABILITIES").await;
    assert!(
        caps_first.starts_with("101"),
        "expected 101, got: {caps_first}"
    );
    let caps = read_dot_body(&mut reader).await;

    assert!(
        !caps.iter().any(|l| l == "STARTTLS"),
        "STARTTLS must NOT appear in CAPABILITIES when TLS is not configured; got: {caps:?}"
    );

    let quit = send_cmd(&mut write_half, &mut reader, "QUIT").await;
    assert!(quit.starts_with("205"), "expected 205, got: {quit}");
}

// ── Test 5: AUTHINFO USER works after STARTTLS upgrade ───────────────────────

/// After a successful STARTTLS upgrade, the session accepts AUTHINFO USER/PASS.
///
/// The server is in dev mode (auth.required = false, no users configured) so
/// any credentials are accepted (returns 281 to AUTHINFO PASS).  The point of
/// this test is that the post-STARTTLS session handles the AUTHINFO command at
/// all — the session is not broken after the upgrade.
///
/// Oracle: AUTHINFO USER returns 381, AUTHINFO PASS returns 281.
#[tokio::test]
async fn authinfo_user_works_after_starttls_upgrade() {
    install_crypto_provider();
    let (_dir, cert_path, key_path) = write_test_tls_files();
    let config = Arc::new(test_config_with_tls("127.0.0.1:0", &cert_path, &key_path));
    let stores = Arc::new(ServerStores::new_mem().await);

    let addr = spawn_server(config, stores).await;

    let stream = TcpStream::connect(addr).await.expect("client must connect");
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.starts_with("200"), "greeting: {greeting}");

    let starttls_resp = send_cmd(&mut write_half, &mut reader, "STARTTLS").await;
    assert!(
        starttls_resp.starts_with("382"),
        "expected 382, got: {starttls_resp}"
    );

    let plain_stream = reader.into_inner().unsplit(write_half);
    let connector = danger_tls_connector();
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls_stream = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, plain_stream),
    )
    .await
    .expect("TLS connect must not time out")
    .expect("TLS handshake must succeed");

    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_reader = BufReader::new(tls_read);

    // AUTHINFO USER: expect 381 (send password).
    timeout(
        Duration::from_secs(5),
        tls_write.write_all(b"AUTHINFO USER alice\r\n"),
    )
    .await
    .expect("write must not time out")
    .expect("write must not error");

    let mut user_resp = String::new();
    timeout(Duration::from_secs(5), tls_reader.read_line(&mut user_resp))
        .await
        .expect("read must not time out")
        .expect("read must not error");
    assert!(
        user_resp.starts_with("381"),
        "AUTHINFO USER after STARTTLS must return 381, got: {user_resp}"
    );

    // AUTHINFO PASS: in dev mode (no users configured), any password is accepted.
    timeout(
        Duration::from_secs(5),
        tls_write.write_all(b"AUTHINFO PASS secret\r\n"),
    )
    .await
    .expect("write must not time out")
    .expect("write must not error");

    let mut pass_resp = String::new();
    timeout(Duration::from_secs(5), tls_reader.read_line(&mut pass_resp))
        .await
        .expect("read must not time out")
        .expect("read must not error");
    assert!(
        pass_resp.starts_with("281"),
        "AUTHINFO PASS after STARTTLS must return 281 (dev mode), got: {pass_resp}"
    );

    // Clean shutdown.
    timeout(Duration::from_secs(5), tls_write.write_all(b"QUIT\r\n"))
        .await
        .expect("write must not time out")
        .expect("write must not error");
}
