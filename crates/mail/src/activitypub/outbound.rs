//! ActivityPub outbound delivery — article to Create{Note} activity.
//!
//! Converts an ingested article into an ActivityPub `Create{Note}` activity
//! and fans it out to all followers of the group via HTTP POST (RFC 7235 /
//! draft-cavage-http-signatures).
//!
//! # Integration point
//!
//! Call `deliver_article` from the article ingestion path after the article
//! has been written to IPFS and the group log.  The call is fire-and-forget —
//! individual delivery failures are logged but do not bubble up.

use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

use super::{follower_store::Follower, http_sign::RsaActorKey, ActivityPubState};

/// Metadata extracted from a newsgroup article.
pub struct ArticleActivity<'a> {
    pub group_name: &'a str,
    /// Message-ID (e.g. `<abc123@example.com>`).
    pub message_id: &'a str,
    /// From header value (author).
    pub from: &'a str,
    /// Subject header value.
    pub subject: &'a str,
    /// Plain-text body.
    pub body: &'a str,
    /// In-Reply-To message-ID, if any.
    pub in_reply_to: Option<&'a str>,
    /// DAG-CBOR CID of the article root block.
    pub cid: &'a str,
    /// ISO 8601 UTC publication timestamp.
    pub published: &'a str,
}

/// Build a `Create{Note}` activity JSON-LD value.
pub fn build_create_note(base_url: &str, article: &ArticleActivity<'_>) -> Value {
    let group_actor_url = format!("{}/ap/groups/{}", base_url, article.group_name);
    let followers_url = format!("{}/followers", group_actor_url);
    let activity_id = format!(
        "{}/ap/groups/{}/activities/{}",
        base_url,
        article.group_name,
        Uuid::new_v4()
    );
    // Note ID derived from message-ID (percent-encode angle brackets).
    let note_id = format!(
        "{}/ap/groups/{}/articles/{}",
        base_url,
        article.group_name,
        percent_encode_msgid(article.message_id)
    );
    let public = "https://www.w3.org/ns/activitystreams#Public";

    let in_reply_to: Value = match article.in_reply_to {
        Some(mid) => json!(format!(
            "{}/ap/groups/{}/articles/{}",
            base_url,
            article.group_name,
            percent_encode_msgid(mid)
        )),
        None => Value::Null,
    };

    json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            {
                "usenet": "https://stoa.example/ns#",
                "x-usenet-ipfs-cid": "usenet:cid"
            }
        ],
        "type": "Create",
        "id": activity_id,
        "actor": group_actor_url,
        "to": [public],
        "cc": [followers_url],
        "object": {
            "type": "Note",
            "id": note_id,
            "attributedTo": group_actor_url,
            "content": article.body,
            "summary": article.subject,
            "published": article.published,
            "to": [public],
            "cc": [followers_url],
            "inReplyTo": in_reply_to,
            "x-usenet-ipfs-cid": article.cid
        }
    })
}

/// Result of a single delivery attempt.
#[derive(Debug)]
pub struct DeliveryResult {
    pub inbox_url: String,
    pub success: bool,
    pub status: Option<u16>,
}

/// Fan out a `Create{Note}` activity to all followers of `group_name`.
///
/// Returns a vec of delivery results for observability.  Failures are also
/// logged with `warn!`.  This function is typically called from a `tokio::spawn`
/// and its return value can be dropped.
pub async fn deliver_article(
    ap_state: &ActivityPubState,
    base_url: &str,
    article: &ArticleActivity<'_>,
) -> Vec<DeliveryResult> {
    let followers = match ap_state.follower_store.list(article.group_name).await {
        Ok(f) => f,
        Err(e) => {
            warn!(group = %article.group_name, error = %e, "failed to list followers for outbound delivery");
            return Vec::new();
        }
    };
    if followers.is_empty() {
        return Vec::new();
    }
    let activity = build_create_note(base_url, article);
    let body = match serde_json::to_vec(&activity) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to serialize Create{{Note}} activity");
            return Vec::new();
        }
    };
    let client = &ap_state.http_client;
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();

    let mut results = Vec::with_capacity(followers.len());
    for follower in &followers {
        let result = deliver_one(client, ap_state.key.as_ref(), &body, follower, &date).await;
        results.push(result);
    }
    results
}

async fn deliver_one(
    client: &reqwest::Client,
    key: Option<&RsaActorKey>,
    body: &[u8],
    follower: &Follower,
    date: &str,
) -> DeliveryResult {
    let (host, path) = super::extract_host_path(&follower.inbox_url);
    let mut req = client
        .post(&follower.inbox_url)
        .header("Content-Type", "application/activity+json")
        .header("Date", date)
        .header("Host", &host);

    if let Some(k) = key {
        match k.sign_post(&host, &path, date, body) {
            Ok(sig) => {
                req = req.header("Signature", sig);
            }
            Err(e) => {
                warn!(inbox = %follower.inbox_url, error = %e, "failed to sign activity delivery");
            }
        }
    }

    match req.body(body.to_vec()).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let success = resp.status().is_success();
            if !success {
                warn!(
                    inbox = %follower.inbox_url,
                    status = status,
                    "outbound activity delivery returned error"
                );
            } else {
                info!(inbox = %follower.inbox_url, "delivered Create{{Note}}");
            }
            DeliveryResult {
                inbox_url: follower.inbox_url.clone(),
                success,
                status: Some(status),
            }
        }
        Err(e) => {
            warn!(inbox = %follower.inbox_url, error = %e, "outbound activity delivery failed");
            DeliveryResult {
                inbox_url: follower.inbox_url.clone(),
                success: false,
                status: None,
            }
        }
    }
}

/// Percent-encode a Message-ID for use in a URL path segment.
///
/// Replaces `<`, `>`, `@`, and space with percent-encoded equivalents.
fn percent_encode_msgid(msgid: &str) -> String {
    msgid
        .chars()
        .flat_map(|c| match c {
            '<' => vec!['%', '3', 'C'],
            '>' => vec!['%', '3', 'E'],
            '@' => vec!['%', '4', '0'],
            ' ' => vec!['%', '2', '0'],
            c => vec![c],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_create_note_fields() {
        let article = ArticleActivity {
            group_name: "comp.lang.rust",
            message_id: "<abc123@example.com>",
            from: "Alice <alice@example.com>",
            subject: "Re: lifetimes",
            body: "Lifetimes are great.",
            in_reply_to: None,
            cid: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            published: "2026-04-27T12:00:00Z",
        };
        let v = build_create_note("https://news.example.com", &article);
        assert_eq!(v["type"], "Create");
        assert_eq!(v["object"]["type"], "Note");
        assert_eq!(v["object"]["content"], "Lifetimes are great.");
        assert_eq!(v["object"]["inReplyTo"], Value::Null);
        assert_eq!(
            v["object"]["x-usenet-ipfs-cid"],
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        );
        let note_id = v["object"]["id"].as_str().unwrap();
        assert!(note_id.contains("comp.lang.rust"), "id: {note_id}");
    }

    #[test]
    fn build_create_note_with_in_reply_to() {
        let article = ArticleActivity {
            group_name: "comp.lang.rust",
            message_id: "<reply@example.com>",
            from: "Bob <bob@example.com>",
            subject: "Re: lifetimes",
            body: "I agree.",
            in_reply_to: Some("<original@example.com>"),
            cid: "bafytest",
            published: "2026-04-27T13:00:00Z",
        };
        let v = build_create_note("https://news.example.com", &article);
        let in_reply_to = v["object"]["inReplyTo"].as_str().unwrap();
        assert!(
            in_reply_to.contains("comp.lang.rust"),
            "inReplyTo: {in_reply_to}"
        );
        assert!(
            in_reply_to.contains("%3Coriginal"),
            "should encode <: {in_reply_to}"
        );
    }

    #[test]
    fn percent_encode_msgid_encodes_brackets() {
        let encoded = percent_encode_msgid("<abc@example.com>");
        assert_eq!(encoded, "%3Cabc%40example.com%3E");
    }
}
