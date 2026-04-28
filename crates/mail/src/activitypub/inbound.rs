//! ActivityPub inbound — `Create{Note}` to RFC 5322 article injection.
//!
//! Translates an ActivityPub `Create{Note}` activity into a raw RFC 5322
//! article and injects it via the same IPFS write pipeline used by NNTP POST
//! and JMAP upload.
//!
//! # Deduplication
//!
//! Each activity's `id` field is stored in `activitypub_received`.  If the
//! same `id` is received again, the activity is silently discarded.
//!
//! # HTTP Signature Verification
//!
//! When `ActivityPubConfig.verify_http_signatures` is `true` (default), inbound
//! POST requests must carry a valid `Signature:` header.  The referenced public
//! key is fetched from the `keyId` URL and the signature is verified against
//! the signed components.  If verification fails, the request is rejected with
//! 401.  Set `verify_http_signatures = false` to skip verification (dev mode).

use axum::http::HeaderMap;
use chrono::Utc;
use serde_json::Value;
use sqlx::AnyPool;
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

// ── Deduplication store ────────────────────────────────────────────────────────

/// Records received activity IDs to prevent duplicate injection.
pub struct ReceivedActivityStore {
    pool: AnyPool,
}

impl ReceivedActivityStore {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Returns `true` and records the `activity_id` if it is new.
    /// Returns `false` if it was already received.
    pub async fn record_if_new(&self, activity_id: &str) -> Result<bool, sqlx::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let rows_affected = sqlx::query(
            "INSERT OR IGNORE INTO activitypub_received (activity_id, received_at) VALUES (?, ?)",
        )
        .bind(activity_id)
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(rows_affected > 0)
    }
}

// ── Note → RFC 5322 translation ───────────────────────────────────────────────

/// Build a raw RFC 5322 article from a `Note` object.
///
/// Returns `(message_id, newsgroups, article_bytes)` or an error string.
pub fn note_to_article(
    note: &Value,
    group_name: &str,
    base_url: &str,
) -> Result<(String, Vec<String>, Vec<u8>), String> {
    let content = note["content"]
        .as_str()
        .or_else(|| {
            note["contentMap"]
                .as_object()
                .and_then(|m| m.values().next()?.as_str())
        })
        .unwrap_or("")
        .to_string();

    let from = note["attributedTo"]
        .as_str()
        .map(attributed_to_email)
        .unwrap_or_else(|| "unknown@activitypub.invalid".to_string());

    let subject = note["summary"]
        .as_str()
        .or_else(|| note["name"].as_str())
        .unwrap_or("(no subject)")
        .to_string();

    let published = note["published"].as_str().unwrap_or("").to_string();

    let in_reply_to = note["inReplyTo"]
        .as_str()
        .map(|u| decode_msgid_from_url(u, base_url, group_name));

    // Generate a stable Message-ID from the Note id, or fabricate one.
    let note_id = note["id"].as_str().unwrap_or("").to_string();
    let message_id = if note_id.is_empty() {
        format!("<{}@activitypub.invalid>", Uuid::new_v4())
    } else {
        // Derive from note_id: replace non-RFC5321 chars.
        let sanitized = note_id
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .replace('/', "-")
            .replace(['<', '>', ' ', '\n', '\r'], "_");
        format!("<ap.{sanitized}>")
    };

    // Strip HTML tags from content for plaintext body.
    let body = strip_html(&content);

    let mut article = String::new();
    article.push_str(&format!("From: {from}\r\n"));
    article.push_str(&format!("Newsgroups: {group_name}\r\n"));
    article.push_str(&format!("Subject: {subject}\r\n"));
    article.push_str(&format!("Message-ID: {message_id}\r\n"));
    let date = if published.is_empty() {
        Utc::now().format("%a, %d %b %Y %H:%M:%S +0000").to_string()
    } else {
        published.clone()
    };
    article.push_str(&format!("Date: {date}\r\n"));
    if let Some(ref irt) = in_reply_to {
        article.push_str(&format!("In-Reply-To: {irt}\r\n"));
    }
    article.push_str("X-ActivityPub: inbound\r\n");
    article.push_str("\r\n");
    article.push_str(&body);

    Ok((
        message_id,
        vec![group_name.to_string()],
        article.into_bytes(),
    ))
}

/// Attempt to reconstruct a Message-ID from a Note URL.
///
/// Inverts the encoding in `outbound::percent_encode_msgid`.
fn decode_msgid_from_url(url: &str, base_url: &str, group_name: &str) -> String {
    let prefix = format!("{base_url}/ap/groups/{group_name}/articles/");
    if let Some(encoded) = url.strip_prefix(&prefix) {
        encoded
            .replace("%3C", "<")
            .replace("%3c", "<")
            .replace("%3E", ">")
            .replace("%3e", ">")
            .replace("%40", "@")
            .replace("%2F", "/")
            .replace("%20", " ")
    } else {
        // Unknown URL format — use as-is wrapped in angle brackets.
        format!("<{url}>")
    }
}

/// Convert an `attributedTo` URL to a synthetic RFC 5322 mailbox address.
///
/// For `https://host/path/to/user`, produces `user@host`.
/// Falls back to `unknown@activitypub.invalid` if the URL cannot be parsed.
fn attributed_to_email(url: &str) -> String {
    // Strip scheme.
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Split host from path.
    let (host, path) = if let Some(slash) = without_scheme.find('/') {
        (&without_scheme[..slash], &without_scheme[slash..])
    } else {
        // No path component at all.
        return format!("unknown@{}", without_scheme);
    };

    if host.is_empty() {
        return "unknown@activitypub.invalid".to_string();
    }

    // Last non-empty path segment becomes the local part.
    let local = path
        .split('/')
        .rfind(|s| !s.is_empty())
        .unwrap_or("unknown");

    format!("{local}@{host}")
}

// ── HTTP Signature verification ───────────────────────────────────────────────

/// Verify the HTTP Signature on an inbound request.
///
/// Fetches the `keyId` URL to obtain the actor's RSA public key (with
/// TTL-based caching via `pub_key_cache`), then verifies the signature
/// against the reconstructed signed-string.
///
/// Returns `Ok(actor_url)` on success, `Err(reason)` on failure.
pub async fn verify_http_signature(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    http_client: &reqwest::Client,
    pub_key_cache: &RwLock<HashMap<String, (String, Instant)>>,
) -> Result<String, String> {
    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing Signature header".to_string())?;

    let key_id = parse_sig_param(sig_header, "keyId")
        .ok_or_else(|| "Signature header missing keyId".to_string())?;

    let signed_headers_spec =
        parse_sig_param(sig_header, "headers").unwrap_or("(request-target) host date".to_string());

    let sig_b64 = parse_sig_param(sig_header, "signature")
        .ok_or_else(|| "Signature header missing signature".to_string())?;

    // Reconstruct the signed string (needed for both cache-hit and miss paths).
    let signed_string = build_signed_string(method, path, headers, body, &signed_headers_spec)?;

    // Fast path: try cache under read lock.
    {
        let cache = pub_key_cache.read().await;
        if let Some((pem, fetched_at)) = cache.get(&key_id) {
            if fetched_at.elapsed() < crate::activitypub::PUB_KEY_CACHE_TTL {
                verify_rsa_sha256(pem, &signed_string, &sig_b64)?;
                let actor_url = key_id.split('#').next().unwrap_or(&key_id).to_string();
                return Ok(actor_url);
            }
        }
    }

    // Slow path: fetch fresh key and update cache under write lock.
    let pem = fetch_public_key(&key_id, http_client).await?;
    {
        let mut cache = pub_key_cache.write().await;
        cache.insert(key_id.clone(), (pem.clone(), Instant::now()));
    }
    verify_rsa_sha256(&pem, &signed_string, &sig_b64)?;

    // Extract actor URL: the part of keyId before the fragment.
    let actor_url = key_id.split('#').next().unwrap_or(&key_id).to_string();
    Ok(actor_url)
}

/// Parse a named parameter from a `Signature:` header value.
fn parse_sig_param(header: &str, name: &str) -> Option<String> {
    for part in header.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(&format!("{name}=")) {
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

/// Fetch and extract the RSA public key PEM from an ActivityPub actor document.
async fn fetch_public_key(key_id: &str, http_client: &reqwest::Client) -> Result<String, String> {
    let actor_url = key_id.split('#').next().unwrap_or(key_id);
    let resp = http_client
        .get(actor_url)
        .header("Accept", "application/activity+json, application/json")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("failed to fetch actor: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("actor fetch returned {}", resp.status()));
    }

    let actor: Value = resp
        .json()
        .await
        .map_err(|e| format!("failed to parse actor JSON: {e}"))?;

    let pem = actor["publicKey"]["publicKeyPem"]
        .as_str()
        .ok_or_else(|| "actor has no publicKey.publicKeyPem".to_string())?
        .to_string();

    Ok(pem)
}

/// Build the signed string from the request components.
fn build_signed_string(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    signed_headers_spec: &str,
) -> Result<String, String> {
    use data_encoding::BASE64;
    use sha2::{Digest, Sha256};

    let mut parts = Vec::new();
    for header_name in signed_headers_spec.split_whitespace() {
        match header_name {
            "(request-target)" => {
                parts.push(format!(
                    "(request-target): {} {}",
                    method.to_lowercase(),
                    path
                ));
            }
            "digest" => {
                let hash = Sha256::digest(body);
                let computed = format!("SHA-256={}", BASE64.encode(&hash));
                let provided = headers
                    .get("digest")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !provided.is_empty() && provided != computed {
                    return Err(format!(
                        "Digest mismatch: provided={provided}, computed={computed}"
                    ));
                }
                parts.push(format!("digest: {computed}"));
            }
            name => {
                let val = headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                parts.push(format!("{name}: {val}"));
            }
        }
    }
    Ok(parts.join("\n"))
}

/// Verify an RSA-SHA256 signature.
fn verify_rsa_sha256(pub_key_pem: &str, signed_string: &str, sig_b64: &str) -> Result<(), String> {
    use data_encoding::BASE64;
    use rsa::{
        pkcs1::DecodeRsaPublicKey,
        pkcs1v15::{Signature, VerifyingKey},
        signature::Verifier,
        RsaPublicKey,
    };
    use sha2::Sha256;

    let sig_bytes = BASE64
        .decode(sig_b64.as_bytes())
        .map_err(|e| format!("invalid base64 in signature: {e}"))?;

    let pub_key = RsaPublicKey::from_pkcs1_pem(pub_key_pem)
        .map_err(|e| format!("invalid public key: {e}"))?;

    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("invalid signature bytes: {e}"))?;
    verifying_key
        .verify(signed_string.as_bytes(), &sig)
        .map_err(|e| format!("signature verification failed: {e}"))?;
    Ok(())
}

// ── HTML stripping ─────────────────────────────────────────────────────────────

/// Remove HTML tags and decode basic entities to get plaintext.
fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push('\n'); // newline after block elements
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    // Decode basic HTML entities.
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_to_article_basic() {
        let note = serde_json::json!({
            "type": "Note",
            "id": "https://mastodon.social/users/alice/statuses/123",
            "attributedTo": "https://mastodon.social/users/alice",
            "content": "<p>Hello, newsgroups!</p>",
            "summary": "Re: hello",
            "published": "2026-04-27T12:00:00Z"
        });
        let (msgid, newsgroups, bytes) =
            note_to_article(&note, "comp.lang.rust", "https://news.example.com").unwrap();
        let article = String::from_utf8(bytes).unwrap();
        assert!(article.contains("From: alice@mastodon.social"));
        assert!(article.contains("Newsgroups: comp.lang.rust"));
        assert!(article.contains("Subject: Re: hello"));
        assert!(article.contains("Hello, newsgroups!"));
        assert!(!msgid.is_empty());
        assert_eq!(newsgroups, vec!["comp.lang.rust".to_string()]);
    }

    #[test]
    fn note_to_article_strips_html() {
        let note = serde_json::json!({
            "type": "Note",
            "id": "https://mastodon.social/users/alice/statuses/456",
            "attributedTo": "https://mastodon.social/users/alice",
            "content": "<p>Hello <strong>world</strong>!</p>"
        });
        let (_, _, bytes) =
            note_to_article(&note, "comp.test", "https://news.example.com").unwrap();
        let article = String::from_utf8(bytes).unwrap();
        assert!(article.contains("Hello"));
        assert!(article.contains("world"));
        assert!(!article.contains("<p>"), "should strip HTML tags");
    }

    #[test]
    fn strip_html_basic() {
        assert_eq!(strip_html("<p>Hello</p>"), "\nHello\n");
        assert_eq!(strip_html("plain text"), "plain text");
        assert_eq!(strip_html("&amp;&lt;&gt;"), "&<>");
    }

    #[test]
    fn note_to_article_missing_published_generates_date() {
        let note = serde_json::json!({
            "type": "Note",
            "id": "https://mastodon.social/users/bob/statuses/789",
            "attributedTo": "https://mastodon.social/users/bob",
            "content": "No timestamp here"
        });
        let (_, _, bytes) =
            note_to_article(&note, "comp.test", "https://news.example.com").unwrap();
        let article = String::from_utf8(bytes).unwrap();
        assert!(
            article.contains("Date: "),
            "Date header must be present even without published"
        );
    }

    #[test]
    fn decode_msgid_percent20() {
        let base = "https://news.example.com";
        let group = "comp.test";
        let url = format!("{base}/ap/groups/{group}/articles/%3Chello%20world%40example.com%3E");
        let decoded = decode_msgid_from_url(&url, base, group);
        assert_eq!(decoded, "<hello world@example.com>");
    }

    #[test]
    fn attributed_to_email_roundtrip() {
        assert_eq!(
            attributed_to_email("https://mastodon.social/users/alice"),
            "alice@mastodon.social"
        );
        assert_eq!(
            attributed_to_email("https://example.org/users/deeply/nested/bob"),
            "bob@example.org"
        );
        // No path component — host used as domain, local part is "unknown".
        assert_eq!(
            attributed_to_email("https://activitypub.invalid"),
            "unknown@activitypub.invalid"
        );
    }

    #[tokio::test]
    async fn dedup_prevents_double_injection() {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        let store = ReceivedActivityStore::new(pool);
        assert!(store
            .record_if_new("https://mastodon.social/activities/abc")
            .await
            .unwrap());
        assert!(!store
            .record_if_new("https://mastodon.social/activities/abc")
            .await
            .unwrap());
        assert!(store
            .record_if_new("https://mastodon.social/activities/xyz")
            .await
            .unwrap());
    }
}
