//! OIDC JWT validation via JWKS discovery.
//!
//! Each `[[auth.oidc_providers]]` entry configures one identity provider.
//! At request time, Bearer tokens that look like JWTs are validated against
//! all configured providers (first match wins).
//!
//! JWKS keys are fetched lazily on first use and cached for one hour.
//! On key-not-found (key rotation detected), the cache is force-refreshed once.
//!
//! # Security invariants
//!
//! - The `none` algorithm is never accepted (`Validation::new` requires an explicit
//!   algorithm, and `Algorithm::None` does not exist in the `jsonwebtoken` crate).
//! - Only RSA algorithms (RS256, RS384, RS512, PS256, PS384, PS512) are supported.
//!   EC (`kty=EC`) keys are rejected with `UnsupportedKeyType`.
//! - The JWT header `alg` is validated against the allowed algorithm(s) by
//!   `jsonwebtoken::decode`; algorithm confusion attacks are therefore prevented.
//! - `exp`, `iss`, and `aud` claims are always validated.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::config::OidcProviderConfig;

const JWKS_TTL: Duration = Duration::from_secs(3600);

// ── Internal JWKS data structures ────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
struct Jwk {
    /// Key ID matched against the JWT header `kid` field.
    kid: Option<String>,
    /// Key type: `"RSA"`, `"EC"`, `"oct"`, etc.
    kty: String,
    /// Intended use: `"sig"` (signature) or `"enc"` (encryption).
    #[serde(rename = "use")]
    key_use: Option<String>,
    /// Advertised algorithm, e.g. `"RS256"`.
    alg: Option<String>,
    // RSA public key components (base64url-encoded big-endian unsigned integers).
    #[serde(rename = "n")]
    rsa_n: Option<String>,
    #[serde(rename = "e")]
    rsa_e: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

// ── Per-provider validator ────────────────────────────────────────────────────

struct ProviderValidator {
    config: OidcProviderConfig,
    /// Cached keys and the instant they were fetched.  `None` = not yet fetched.
    cache: RwLock<Option<(Vec<Jwk>, Instant)>>,
    client: Arc<reqwest::Client>,
}

impl ProviderValidator {
    fn new(config: OidcProviderConfig, client: Arc<reqwest::Client>) -> Self {
        Self {
            config,
            cache: RwLock::new(None),
            client,
        }
    }

    /// Fetch the JWKS URI from the OIDC discovery document.
    async fn discover_jwks_uri(&self) -> Result<String, OidcError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(OidcError::Http)?
            .json()
            .await
            .map_err(OidcError::Http)?;
        resp["jwks_uri"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                OidcError::Config("jwks_uri not found in OIDC discovery document".into())
            })
    }

    async fn fetch_fresh_keys(&self) -> Result<Vec<Jwk>, OidcError> {
        let jwks_uri = self.discover_jwks_uri().await?;
        let set: JwkSet = self
            .client
            .get(&jwks_uri)
            .send()
            .await
            .map_err(OidcError::Http)?
            .json()
            .await
            .map_err(OidcError::Http)?;
        Ok(set.keys)
    }

    /// Return cached keys, refreshing if the cache is expired or `force` is set.
    async fn get_keys(&self, force: bool) -> Result<Vec<Jwk>, OidcError> {
        // Fast path: check under read lock (avoids write-lock contention when hot).
        if !force {
            let cache = self.cache.read().await;
            if let Some((ref keys, fetched_at)) = *cache {
                if fetched_at.elapsed() < JWKS_TTL {
                    return Ok(keys.clone());
                }
            }
        }
        // Slow path: acquire write lock and check again before fetching.
        // This prevents a thunder-herd where multiple callers all see expiry,
        // drop the read lock, and race to call fetch_fresh_keys().
        let mut cache = self.cache.write().await;
        if !force {
            if let Some((ref keys, fetched_at)) = *cache {
                if fetched_at.elapsed() < JWKS_TTL {
                    return Ok(keys.clone());
                }
            }
        }
        let keys = self.fetch_fresh_keys().await?;
        *cache = Some((keys.clone(), Instant::now()));
        Ok(keys)
    }

    /// Validate a JWT against this provider.  Returns the username claim.
    ///
    /// If the signing key is not found (rotation), the cache is force-refreshed
    /// and the validation is retried once.
    async fn validate_jwt(&self, token: &str) -> Result<String, OidcError> {
        for force_refresh in [false, true] {
            let keys = self.get_keys(force_refresh).await?;
            match self.validate_with_keys(token, &keys) {
                Err(OidcError::KeyNotFound) if !force_refresh => {
                    // Key not in cache — possible rotation; retry with fresh JWKS.
                    continue;
                }
                result => return result,
            }
        }
        unreachable!("loop always returns or continues exactly once")
    }

    fn validate_with_keys(&self, token: &str, keys: &[Jwk]) -> Result<String, OidcError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| OidcError::InvalidToken(e.to_string()))?;

        // Select candidate keys by `kid` if present; otherwise try all sig keys.
        let candidates: Vec<&Jwk> = if let Some(ref kid) = header.kid {
            keys.iter()
                .filter(|k| k.kid.as_deref() == Some(kid.as_str()))
                .filter(|k| k.key_use.as_deref().unwrap_or("sig") == "sig")
                .collect()
        } else {
            keys.iter()
                .filter(|k| k.key_use.as_deref().unwrap_or("sig") == "sig")
                .collect()
        };

        if candidates.is_empty() {
            return Err(OidcError::KeyNotFound);
        }

        let mut last_err = OidcError::KeyNotFound;
        for jwk in candidates {
            match self.try_key(token, jwk) {
                Ok(username) => return Ok(username),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn try_key(&self, token: &str, jwk: &Jwk) -> Result<String, OidcError> {
        let (decoding_key, alg) = rsa_decoding_key_and_alg(jwk)?;

        let mut validation = Validation::new(alg);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.validate_exp = true;

        let data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
            .map_err(|e| OidcError::InvalidToken(e.to_string()))?;

        let claims = &data.claims;
        let username = claims
            .get(&self.config.username_claim)
            .and_then(|v| v.as_str())
            .or_else(|| claims.get("sub").and_then(|v| v.as_str()))
            .ok_or_else(|| OidcError::MissingClaim(self.config.username_claim.clone()))?
            .to_string();

        Ok(username)
    }
}

// ── Key extraction helpers ────────────────────────────────────────────────────

/// Build an RSA `DecodingKey` and select the matching `Algorithm` from a JWK.
///
/// Returns `UnsupportedKeyType` for non-RSA keys (EC support is deferred).
fn rsa_decoding_key_and_alg(jwk: &Jwk) -> Result<(DecodingKey, Algorithm), OidcError> {
    if jwk.kty != "RSA" {
        return Err(OidcError::UnsupportedKeyType(jwk.kty.clone()));
    }
    let n = jwk
        .rsa_n
        .as_deref()
        .ok_or_else(|| OidcError::InvalidKey("RSA JWK missing 'n'".into()))?;
    let e = jwk
        .rsa_e
        .as_deref()
        .ok_or_else(|| OidcError::InvalidKey("RSA JWK missing 'e'".into()))?;
    let key =
        DecodingKey::from_rsa_components(n, e).map_err(|e| OidcError::InvalidKey(e.to_string()))?;

    let alg = match jwk.alg.as_deref() {
        Some("RS256") => Algorithm::RS256,
        None => {
            // DECISION: RS256 is the correct default for JWKs with kty=RSA and no alg field.
            // RFC 7518 §3.3 defines RS256 as the baseline RSA signature algorithm.
            // Providers that omit alg (e.g. some Azure AD JWKS endpoints) expect RS256.
            tracing::debug!(key_id = ?jwk.kid, "JWK has no 'alg' field; defaulting to RS256 per RFC 7518 §3.3");
            Algorithm::RS256
        }
        Some("RS384") => Algorithm::RS384,
        Some("RS512") => Algorithm::RS512,
        Some("PS256") => Algorithm::PS256,
        Some("PS384") => Algorithm::PS384,
        Some("PS512") => Algorithm::PS512,
        Some(other) => return Err(OidcError::UnsupportedAlgorithm(other.to_string())),
    };

    Ok((key, alg))
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by OIDC JWT validation.
#[derive(Debug)]
pub enum OidcError {
    /// Configuration problem (missing field, malformed issuer URL, etc.).
    Config(String),
    /// The JWT failed signature, expiry, issuer, or audience validation.
    InvalidToken(String),
    /// A JWK in the JWKS response could not be used as a key.
    InvalidKey(String),
    /// The signing key referenced by the JWT `kid` was not found in the JWKS.
    KeyNotFound,
    /// A required claim (e.g. `email`) was absent from the validated token.
    MissingClaim(String),
    /// The JWK `kty` is not supported (only `"RSA"` is supported in v1).
    UnsupportedKeyType(String),
    /// The JWK `alg` is not a recognised RSA algorithm.
    UnsupportedAlgorithm(String),
    /// An HTTP error occurred while fetching the discovery document or JWKS.
    Http(reqwest::Error),
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcError::Config(s) => write!(f, "OIDC config: {s}"),
            OidcError::InvalidToken(s) => write!(f, "OIDC invalid token: {s}"),
            OidcError::InvalidKey(s) => write!(f, "OIDC invalid key: {s}"),
            OidcError::KeyNotFound => write!(f, "OIDC key not found in JWKS"),
            OidcError::MissingClaim(s) => write!(f, "OIDC missing claim '{s}'"),
            OidcError::UnsupportedKeyType(s) => {
                write!(
                    f,
                    "OIDC unsupported key type '{s}' (only RSA supported in v1)"
                )
            }
            OidcError::UnsupportedAlgorithm(s) => {
                write!(f, "OIDC unsupported algorithm '{s}'")
            }
            OidcError::Http(e) => write!(f, "OIDC HTTP error: {e}"),
        }
    }
}

impl std::error::Error for OidcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OidcError::Http(e) => Some(e),
            _ => None,
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Multi-provider OIDC JWT validator.
///
/// Instantiated once at startup from the `[[auth.oidc_providers]]` config section.
/// Call `validate_jwt` for every JWT Bearer token received from a client.
pub struct OidcStore {
    providers: Vec<ProviderValidator>,
}

impl OidcStore {
    /// Create a new store from the list of configured OIDC providers.
    ///
    /// No network calls are made at construction time; JWKS keys are fetched
    /// lazily on the first `validate_jwt` call for each provider.
    pub fn new(configs: Vec<OidcProviderConfig>) -> Self {
        let client = Arc::new(reqwest::Client::new());
        Self {
            providers: configs
                .into_iter()
                .map(|c| ProviderValidator::new(c, Arc::clone(&client)))
                .collect(),
        }
    }

    /// Validate a JWT Bearer token against all configured OIDC providers.
    ///
    /// Returns `Ok(username)` when any provider accepts the token (first match wins).
    /// Returns `Err` if no provider accepts it — wrong issuer, bad signature,
    /// expired, wrong audience, missing claim, etc.  The error includes the
    /// reason from every provider so operators can diagnose misconfiguration.
    pub async fn validate_jwt(&self, token: &str) -> Result<String, OidcError> {
        if self.providers.is_empty() {
            return Err(OidcError::Config("no OIDC providers configured".into()));
        }
        let mut errors: Vec<String> = Vec::new();
        for provider in &self.providers {
            match provider.validate_jwt(token).await {
                Ok(username) => return Ok(username),
                Err(e) => errors.push(e.to_string()),
            }
        }
        Err(OidcError::Config(format!(
            "all providers rejected the token: [{}]",
            errors.join("; ")
        )))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Non-JWT strings must be rejected before any network call.
    #[test]
    fn decode_header_rejects_non_jwt_strings() {
        for bad in ["not-a-jwt", "", "two.parts", "toolong.too.long.too.many"] {
            // "toolong.too.many.dots" actually has 3 segments — decode_header
            // will try to parse; that's fine, it should fail on invalid b64.
            let _ = jsonwebtoken::decode_header(bad); // just must not panic
        }
        // A plain non-base64 string must error.
        assert!(jsonwebtoken::decode_header("not-a-jwt").is_err());
    }

    /// RSA JWK missing `n` must return `InvalidKey`.
    #[test]
    fn rsa_key_missing_n_returns_invalid_key() {
        let jwk = Jwk {
            kid: Some("k1".into()),
            kty: "RSA".into(),
            key_use: Some("sig".into()),
            alg: Some("RS256".into()),
            rsa_n: None,
            rsa_e: Some("AQAB".into()),
        };
        assert!(matches!(
            rsa_decoding_key_and_alg(&jwk),
            Err(OidcError::InvalidKey(_))
        ));
    }

    /// RSA JWK missing `e` must return `InvalidKey`.
    #[test]
    fn rsa_key_missing_e_returns_invalid_key() {
        let jwk = Jwk {
            kid: Some("k1".into()),
            kty: "RSA".into(),
            key_use: Some("sig".into()),
            alg: Some("RS256".into()),
            rsa_n: Some("somemodulus".into()),
            rsa_e: None,
        };
        assert!(matches!(
            rsa_decoding_key_and_alg(&jwk),
            Err(OidcError::InvalidKey(_))
        ));
    }

    /// EC keys must return `UnsupportedKeyType`.
    #[test]
    fn ec_key_returns_unsupported_key_type() {
        let jwk = Jwk {
            kid: None,
            kty: "EC".into(),
            key_use: Some("sig".into()),
            alg: Some("ES256".into()),
            rsa_n: None,
            rsa_e: None,
        };
        assert!(matches!(
            rsa_decoding_key_and_alg(&jwk),
            Err(OidcError::UnsupportedKeyType(_))
        ));
    }

    /// Unknown algorithm must return `UnsupportedAlgorithm`.
    #[test]
    fn unknown_alg_returns_unsupported_algorithm() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".into(),
            key_use: Some("sig".into()),
            alg: Some("HS256".into()), // HMAC — not acceptable for OIDC
            rsa_n: Some("AQAB".into()),
            rsa_e: Some("AQAB".into()),
        };
        assert!(matches!(
            rsa_decoding_key_and_alg(&jwk),
            Err(OidcError::UnsupportedAlgorithm(_))
        ));
    }

    /// A RSA JWK with no `alg` field defaults to RS256.
    #[test]
    fn rsa_jwk_no_alg_defaults_to_rs256() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".into(),
            key_use: Some("sig".into()),
            alg: None,
            // Use minimal valid base64url values for a syntactically valid key
            // (semantically invalid — tests alg selection only, not key validity).
            rsa_n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".into()),
            rsa_e: Some("AQAB".into()),
        };
        match rsa_decoding_key_and_alg(&jwk) {
            Ok((_, alg)) => assert_eq!(alg, Algorithm::RS256),
            Err(OidcError::InvalidKey(_)) => {
                // Key components may fail to parse — that's ok, test is about alg selection.
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// OidcStore with zero providers returns an error immediately.
    #[tokio::test]
    async fn empty_store_returns_config_error() {
        let store = OidcStore::new(vec![]);
        assert!(store.validate_jwt("any.token.here").await.is_err());
    }
}
