//! TLS acceptor for the NNTP listener.
//!
//! When TLS is configured, wraps the TCP stream in a rustls ServerConnection.
//! The `NntpStream` enum unifies plain and TLS streams so the session handler
//! does not need to know which variant is active.

use std::{fs::File, io::BufReader, sync::Arc};

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use rustls_pemfile::{certs, private_key};
use sha2::Digest as _;

/// Errors produced during TLS setup or handshake.
#[derive(Debug)]
pub enum TlsError {
    /// Failed to read or parse the certificate file.
    CertLoad(String, std::io::Error),
    /// Failed to read or parse the private key file.
    KeyLoad(String, std::io::Error),
    /// Failed to build the rustls `ServerConfig`.
    Config(rustls::Error),
    /// TLS handshake with the client failed.
    Handshake(std::io::Error),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::CertLoad(path, e) => {
                write!(f, "failed to load TLS certificate from '{path}': {e}")
            }
            TlsError::KeyLoad(path, e) => {
                write!(f, "failed to load TLS private key from '{path}': {e}")
            }
            TlsError::Config(e) => write!(f, "TLS server config error: {e}"),
            TlsError::Handshake(e) => write!(f, "TLS handshake failed: {e}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::CertLoad(_, e) | TlsError::KeyLoad(_, e) | TlsError::Handshake(e) => Some(e),
            TlsError::Config(e) => Some(e),
        }
    }
}

/// A rustls-backed TLS acceptor for incoming TCP connections.
pub struct TlsAcceptor {
    inner: tokio_rustls::TlsAcceptor,
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

/// A permissive `ClientCertVerifier` that requests but never rejects a client
/// certificate.
///
/// All certificate validation (including fingerprint-to-username binding)
/// happens at the application layer in the session context after the handshake.
/// This verifier's sole job is to tell rustls "offer client auth, accept
/// anything, never fail the handshake because of the cert".
#[derive(Debug)]
struct PermissiveClientAuth;

impl ClientCertVerifier for PermissiveClientAuth {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
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

/// Extract the SHA-256 fingerprint and raw DER bytes of the client's TLS leaf
/// certificate.
///
/// Returns `(fingerprint, raw_der)` where:
/// - `fingerprint` is `Some("sha256:<64-lowercase-hex-chars>")`.
/// - `raw_der` is `Some(<leaf cert DER bytes>)`.
///
/// Both fields are `None` if no client certificate was presented.
pub fn extract_client_cert_data(
    tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> (Option<String>, Option<Vec<u8>>) {
    let certs = match tls_stream.get_ref().1.peer_certificates() {
        Some(c) => c,
        None => return (None, None),
    };
    let leaf = match certs.first() {
        Some(l) => l,
        None => return (None, None),
    };
    let der = leaf.as_ref().to_vec();
    let digest = sha2::Sha256::digest(&der);
    let fingerprint = format!("sha256:{}", hex::encode(digest));
    (Some(fingerprint), Some(der))
}

/// Build a `TlsAcceptor` from PEM certificate and private-key files.
///
/// The resulting `ServerConfig` requires TLS 1.2 or higher; TLS 1.0 and 1.1
/// are not offered. Client certificates are requested but not required —
/// fingerprint validation happens at the application layer.
pub fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, TlsError> {
    // --- Load certificate chain ---
    let cert_file =
        File::open(cert_path).map_err(|e| TlsError::CertLoad(cert_path.to_string(), e))?;
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::CertLoad(cert_path.to_string(), e))?;

    // --- Load private key ---
    let key_file = File::open(key_path).map_err(|e| TlsError::KeyLoad(key_path.to_string(), e))?;
    let private_key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| TlsError::KeyLoad(key_path.to_string(), e))?
        .ok_or_else(|| {
            TlsError::KeyLoad(
                key_path.to_string(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no private key found in PEM",
                ),
            )
        })?;

    // --- Build ServerConfig with minimum TLS 1.2 ---
    // Request but do not require a client certificate.  Fingerprint validation
    // is performed at the application layer after the handshake.
    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_client_cert_verifier(Arc::new(PermissiveClientAuth))
    .with_single_cert(cert_chain, private_key)
    .map_err(TlsError::Config)?;

    Ok(TlsAcceptor {
        inner: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
    })
}

/// Perform the TLS handshake on an already-accepted TCP stream.
pub async fn accept_tls(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, TlsError> {
    acceptor
        .inner
        .accept(stream)
        .await
        .map_err(TlsError::Handshake)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_tls_acceptor_missing_cert_returns_error() {
        let result = load_tls_acceptor("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertLoad(path, _) => assert!(path.contains("cert.pem")),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn tls_error_display_is_informative() {
        let e = TlsError::CertLoad(
            "/foo/cert.pem".into(),
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        );
        let msg = e.to_string();
        assert!(msg.contains("/foo/cert.pem"), "display: {msg}");
    }
}
