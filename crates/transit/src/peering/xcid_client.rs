//! XCID client: fetches `LogEntry` structs from remote transit peers.
//!
//! The XCID protocol is a stoa extension over the existing NNTP peering
//! TCP channel.  A requester sends `XCID <cid>\r\n` and receives either:
//! - `224 Block follows (<cid>)\r\n<base64_lines>\r\n.\r\n` — entry found, or
//! - `430 No such block\r\n` — entry not present on that peer.
//!
//! The CID encodes a `LogEntryId` as a CIDv1 with codec 0x71 (DAG-CBOR) and a
//! SHA-256 multihash whose digest is the raw 32-byte `LogEntryId`.
//!
//! This client opens ephemeral TCP connections per fetch attempt; it does not
//! reuse the inbound peering session because the session handler runs in a
//! separate task with its own ownership of the stream.
//!
//! ## Outbound TLS
//!
//! When `PeerInfo::tls` is true the client wraps the TCP stream in TLS.
//! Because transit peers often use self-signed certificates, standard CA
//! verification is bypassed and replaced with a SHA-256 certificate
//! fingerprint check (`PeerInfo::cert_sha256`).  A peer entry with `tls =
//! true` must supply a `cert_sha256` fingerprint — the config validator
//! rejects `tls = true` without it.

use std::sync::Arc;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use tokio_rustls::TlsConnector;

use stoa_core::group_log::{
    types::{LogEntry, LogEntryId},
    verify::{verify_signature, VerifiedEntry},
};

/// How long to wait for any single blocking operation on a peer connection.
const PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Per-peer connection configuration for the XCID client.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Socket address in `"host:port"` form.
    pub addr: String,
    /// Connect with TLS.  Requires `cert_sha256` to be set.
    pub tls: bool,
    /// SHA-256 fingerprint of the peer's DER-encoded leaf certificate.
    ///
    /// Format: colon-separated lowercase hex bytes, e.g. `"aa:bb:cc:..."`.
    /// Required when `tls = true`; ignored when `tls = false`.
    pub cert_sha256: Option<String>,
}

/// Client for fetching log entries from remote transit peers via the XCID command.
pub struct XcidClient {
    peers: Arc<Vec<PeerInfo>>,
    /// Pre-built TLS client configs, one entry per peer (aligned by index).
    /// `None` for plaintext peers.
    tls_configs: Arc<Vec<Option<Arc<rustls::ClientConfig>>>>,
    trusted_keys: Arc<Vec<ed25519_dalek::VerifyingKey>>,
}

impl XcidClient {
    /// Create a new client that will try `peers` in order.
    ///
    /// `trusted_keys` is the set of operator public keys whose signatures are
    /// accepted.  A fetched entry must be signed by at least one of these keys.
    pub fn new(peers: Vec<PeerInfo>, trusted_keys: Vec<ed25519_dalek::VerifyingKey>) -> Self {
        let tls_configs: Vec<Option<Arc<rustls::ClientConfig>>> = peers
            .iter()
            .map(|peer| {
                if !peer.tls {
                    return None;
                }
                let cert_sha256 = peer.cert_sha256.as_deref()?;
                let fingerprint = parse_cert_sha256(cert_sha256).ok()?;
                let verifier = Arc::new(PinnedCertVerifier {
                    expected_fingerprint: fingerprint,
                });
                let config = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth();
                Some(Arc::new(config))
            })
            .collect();

        Self {
            peers: Arc::new(peers),
            tls_configs: Arc::new(tls_configs),
            trusted_keys: Arc::new(trusted_keys),
        }
    }

    /// Fetch and verify a log entry by its ID, trying each configured peer in turn.
    ///
    /// Returns the first successfully fetched and signature-verified entry.
    /// Returns `Err` if all peers are exhausted or no trusted key validates the
    /// fetched entry.
    pub async fn fetch_entry(&self, entry_id: &LogEntryId) -> Result<VerifiedEntry, String> {
        if self.peers.is_empty() {
            return Err("no peer addresses configured for XCID fetch".to_string());
        }

        let cid_str = entry_id.to_cid().to_string();

        for (i, peer) in self.peers.iter().enumerate() {
            let tls_config = self.tls_configs[i].clone();
            match self
                .try_fetch_from_peer(peer, tls_config, &cid_str, entry_id)
                .await
            {
                Ok(verified) => return Ok(verified),
                Err(e) => {
                    tracing::debug!(
                        peer = %peer.addr,
                        cid = %cid_str,
                        "xcid: peer fetch failed: {e}"
                    );
                }
            }
        }

        Err(format!("xcid: all peers exhausted for {cid_str}"))
    }

    async fn try_fetch_from_peer(
        &self,
        peer: &PeerInfo,
        tls_config: Option<Arc<rustls::ClientConfig>>,
        cid_str: &str,
        expected_id: &LogEntryId,
    ) -> Result<VerifiedEntry, String> {
        let addr = &peer.addr;

        // Open TCP connection with timeout, then optionally wrap in TLS.
        let tcp = time::timeout(PEER_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("connect timeout to {addr}"))?
            .map_err(|e| format!("connect to {addr}: {e}"))?;

        if peer.tls {
            let config = tls_config
                .ok_or_else(|| format!("peer {addr}: tls=true but no cert_sha256 pin"))?;
            let tls_stream = connect_tls(tcp, addr, config).await?;
            self.run_xcid_protocol(tls_stream, addr, cid_str, expected_id)
                .await
        } else {
            self.run_xcid_protocol(tcp, addr, cid_str, expected_id)
                .await
        }
    }

    async fn run_xcid_protocol<S>(
        &self,
        stream: S,
        addr: &str,
        cid_str: &str,
        expected_id: &LogEntryId,
    ) -> Result<VerifiedEntry, String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();

        // Read the server greeting (200 or 201).
        time::timeout(PEER_TIMEOUT, reader.read_line(&mut line))
            .await
            .map_err(|_| format!("read timeout from {addr}"))?
            .map_err(|e| format!("read error: {e}"))?;
        if !line.starts_with("200 ") && !line.starts_with("201 ") {
            return Err(format!("unexpected greeting: {}", line.trim()));
        }

        // Send the XCID command.
        write_half
            .write_all(format!("XCID {cid_str}\r\n").as_bytes())
            .await
            .map_err(|e| format!("write XCID: {e}"))?;

        // Read the first response line.
        line.clear();
        time::timeout(PEER_TIMEOUT, reader.read_line(&mut line))
            .await
            .map_err(|_| format!("read timeout from {addr}"))?
            .map_err(|e| format!("read error: {e}"))?;
        let response_line = line.trim().to_owned();

        if response_line.starts_with("430 ") || response_line.starts_with("500 ") {
            return Err(format!("peer responded: {response_line}"));
        }
        if !response_line.starts_with("224 ") {
            return Err(format!("unexpected response: {response_line}"));
        }

        // Read base64 body lines until a standalone ".".
        let mut b64_accumulator = String::new();
        loop {
            line.clear();
            time::timeout(PEER_TIMEOUT, reader.read_line(&mut line))
                .await
                .map_err(|_| format!("read timeout from {addr}"))?
                .map_err(|e| format!("read error: {e}"))?;
            let t = line.trim();
            if t == "." {
                break;
            }
            if line.is_empty() {
                return Err("unexpected EOF in XCID response body".to_string());
            }
            b64_accumulator.push_str(t);
        }

        // Best-effort QUIT before closing the connection.
        let _ = write_half.write_all(b"QUIT\r\n").await;

        // Decode base64 → DAG-CBOR bytes.
        let cbor_bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64_accumulator)
            .map_err(|e| format!("base64 decode: {e}"))?;

        // Deserialize LogEntry from DAG-CBOR.
        let entry: LogEntry = serde_ipld_dagcbor::from_slice(&cbor_bytes)
            .map_err(|e| format!("dagcbor deserialize: {e}"))?;

        // Verify integrity: recompute the LogEntryId from the entry fields and
        // compare to what was requested.  This guards against a peer serving a
        // different entry under the same CID.
        let computed_id = LogEntryId::from_entry(&entry);
        if computed_id != *expected_id {
            return Err(format!(
                "entry ID mismatch: expected {expected_id}, computed {computed_id}"
            ));
        }

        // Verify the operator signature with any trusted key.
        // Avoid cloning on the last key check by splitting the key list.
        if let Some((last_key, prefix_keys)) = self.trusted_keys.split_last() {
            for key in prefix_keys {
                if let Ok(verified) = verify_signature(entry.clone(), key) {
                    return Ok(verified);
                }
            }
            if let Ok(verified) = verify_signature(entry, last_key) {
                return Ok(verified);
            }
        }

        Err(format!(
            "no trusted key (tried {}) could verify entry {expected_id} from {addr}",
            self.trusted_keys.len()
        ))
    }
}

/// Parse a colon-separated hex fingerprint string into a 32-byte array.
fn parse_cert_sha256(s: &str) -> Result<[u8; 32], String> {
    let bytes: Result<Vec<u8>, _> = s
        .split(':')
        .map(|hex| u8::from_str_radix(hex, 16).map_err(|_| ()))
        .collect();
    let bytes = bytes.map_err(|_| format!("invalid cert_sha256 hex: {s}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("cert_sha256 must be 32 bytes, got {}", s.split(':').count()))
}

/// Establish a TLS connection to a transit peer, verifying the certificate
/// against the provided SHA-256 fingerprint.
///
/// The peer's certificate need not be signed by a trusted CA; only the
/// fingerprint is checked.  This is the standard pattern for private peering
/// networks that use self-signed certificates.
async fn connect_tls(
    tcp: TcpStream,
    addr: &str,
    client_config: Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let connector = TlsConnector::from(client_config);

    // Extract hostname for SNI (bypassed by our verifier but required by the API).
    let hostname = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|e| format!("invalid SNI hostname {hostname}: {e}"))?;

    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS connect to {addr}: {e}"))
}

/// Compute the SHA-256 fingerprint of DER certificate bytes, formatted as
/// colon-separated lowercase hex (e.g. `"aa:bb:cc:..."`).
fn cert_sha256_colon(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hash.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A rustls `ServerCertVerifier` that accepts any certificate whose SHA-256
/// fingerprint matches a configured pin.
///
/// Used for transit-to-transit peering where peers may use self-signed
/// certificates.  The TLS handshake still provides channel encryption and
/// proves the server holds the private key matching the pinned certificate.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected_fingerprint: [u8; 32],
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let actual = Sha256::digest(end_entity.as_ref());
        if actual.as_slice() != self.expected_fingerprint {
            return Err(RustlsError::General(format!(
                "cert pin mismatch: expected {}, got {}",
                cert_sha256_colon(&self.expected_fingerprint),
                cert_sha256_colon(actual.as_slice()),
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| RustlsError::General("no crypto provider installed".into()))?;
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| RustlsError::General("no crypto provider installed".into()))?;
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}
