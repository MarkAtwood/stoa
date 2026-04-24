use std::sync::Arc;

use cid::Cid;
use serde_json::{json, Value};

use crate::jmap::types::MethodError;
use crate::state::flags::UserFlagsStore;
use stoa_core::msgid_map::MsgIdMap;
use stoa_reader::post::ipfs_write::{write_article_to_ipfs, IpfsBlockStore};
use stoa_smtp::SmtpRelayQueue;

/// Handle Email/set — route to destroy/update/create sub-handlers.
pub fn handle_email_set(args: Value) -> Result<Value, MethodError> {
    let mut not_destroyed: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut not_updated: serde_json::Map<String, Value> = serde_json::Map::new();

    // destroy: always notPermitted — articles are immutable
    if let Some(destroy_ids) = args.get("destroy").and_then(|v| v.as_array()) {
        for id in destroy_ids {
            if let Some(id_str) = id.as_str() {
                tracing::warn!(email_id = %id_str, "Email/set destroy rejected — articles are immutable");
                not_destroyed.insert(
                    id_str.to_string(),
                    json!({"type": "notPermitted", "description": "Articles are immutable in v1"}),
                );
            }
        }
    }

    // update: notPermitted for mailboxIds; other properties handled in user-state epic
    if let Some(update_map) = args.get("update").and_then(|v| v.as_object()) {
        for (id, patch) in update_map {
            // Check if patch attempts to change mailboxIds
            if patch.get("mailboxIds").is_some()
                || patch
                    .as_object()
                    .is_some_and(|m| m.keys().any(|k| k.starts_with("mailboxIds/")))
            {
                not_updated.insert(
                    id.clone(),
                    json!({"type": "notPermitted", "description": "mailboxIds are derived from Newsgroups header and are read-only"}),
                );
            }
        }
    }

    Ok(json!({
        "accountId": args.get("accountId").cloned().unwrap_or(Value::Null),
        "oldState": "0",
        "newState": "0",
        "created": null,
        "updated": null,
        "destroyed": null,
        "notCreated": null,
        "notUpdated": if not_updated.is_empty() { Value::Null } else { Value::Object(not_updated) },
        "notDestroyed": if not_destroyed.is_empty() { Value::Null } else { Value::Object(not_destroyed) },
    }))
}

/// Handle Email/set update for keywords (\Seen, \Flagged) only.
///
/// For each id, parses CID, extracts keyword patch, calls UserFlagsStore.
/// Ignores entries whose patch does not contain a `keywords` key (those are
/// handled by `handle_email_set`).
pub async fn handle_keyword_update(
    update_map: &serde_json::Map<String, Value>,
    user_id: i64,
    flags_store: &UserFlagsStore,
) -> (
    serde_json::Map<String, Value>,
    serde_json::Map<String, Value>,
) {
    let mut updated: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut not_updated: serde_json::Map<String, Value> = serde_json::Map::new();

    for (id, patch) in update_map {
        let keywords = match patch.get("keywords") {
            Some(k) => k,
            None => continue,
        };

        let cid = match Cid::try_from(id.as_str()) {
            Ok(c) => c,
            Err(_) => {
                not_updated.insert(id.clone(), json!({"type": "notFound"}));
                continue;
            }
        };

        let seen = keywords
            .get("$seen")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let flagged = keywords
            .get("$flagged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        match flags_store.set_flags(user_id, &cid, seen, flagged).await {
            Ok(()) => {
                updated.insert(id.clone(), json!(null));
            }
            Err(e) => {
                tracing::warn!(id = %id, "Email/set keywords update error: {e}");
                not_updated.insert(
                    id.clone(),
                    json!({"type": "serverFail", "description": e.to_string()}),
                );
            }
        }
    }

    (updated, not_updated)
}

/// Handle Email/set create.
///
/// Accepts JMAP Email creation objects, constructs RFC 5322 article bytes,
/// writes to IPFS via `write_article_to_ipfs`, returns created Email ids.
///
/// If `smtp_queue` is `Some` and the created article has `to` or `cc`
/// recipients, the article is enqueued for SMTP relay delivery.  Enqueue
/// failure is non-fatal and does not fail the JMAP response.
pub async fn handle_email_create(
    create_map: &serde_json::Map<String, Value>,
    ipfs: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
    smtp_queue: Option<&Arc<SmtpRelayQueue>>,
) -> (
    serde_json::Map<String, Value>,
    serde_json::Map<String, Value>,
) {
    let mut created: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut not_created: serde_json::Map<String, Value> = serde_json::Map::new();

    for (creation_id, obj) in create_map {
        match create_one_email(obj, ipfs, msgid_map, smtp_queue).await {
            Ok(cid) => {
                created.insert(creation_id.clone(), json!({"id": cid.to_string()}));
            }
            Err(e) => {
                tracing::warn!(creation_id = %creation_id, "Email/set create error: {e}");
                not_created.insert(
                    creation_id.clone(),
                    json!({"type": "invalidArguments", "description": e}),
                );
            }
        }
    }

    (created, not_created)
}

async fn create_one_email(
    obj: &Value,
    ipfs: &dyn IpfsBlockStore,
    msgid_map: &MsgIdMap,
    smtp_queue: Option<&Arc<SmtpRelayQueue>>,
) -> Result<Cid, String> {
    let subject = obj
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("(no subject)");

    let from_email = obj
        .get("from")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|addr| addr.get("email"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown@example.com");

    let newsgroups: Vec<&str> = obj
        .get("mailboxIds")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();

    if newsgroups.is_empty() {
        return Err("mailboxIds must not be empty".to_string());
    }

    let text_body = obj
        .get("textBody")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|part| part.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let message_id = format!("<jmap-{timestamp}@stoa.local>");

    let article = format!(
        "Newsgroups: {}\r\nFrom: {}\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: {}\r\n\r\n{}",
        newsgroups.join(","),
        from_email,
        subject,
        "Mon, 01 Jan 2024 00:00:00 +0000",
        message_id,
        text_body,
    );

    let cid = write_article_to_ipfs(ipfs, msgid_map, article.as_bytes(), &message_id)
        .await
        .map_err(|resp| format!("IPFS write failed: {}", resp.text))?;

    // Enqueue for SMTP relay if a queue is configured and there are recipients.
    if let Some(queue) = smtp_queue {
        let mut rcpt_list = extract_email_addrs(obj.get("to"));
        rcpt_list.extend(extract_email_addrs(obj.get("cc")));
        if !rcpt_list.is_empty() {
            let rcpts: Vec<&str> = rcpt_list.iter().map(String::as_str).collect();
            if let Err(e) = queue.enqueue(article.as_bytes(), from_email, &rcpts).await {
                tracing::warn!("smtp relay enqueue failed: {e}");
                stoa_smtp::metrics::inc_relay_enqueue_failure();
            }
        }
    }

    Ok(cid)
}

/// Extract RFC 8621 §4.1.2 email addresses from a JMAP EmailAddress array field.
///
/// Accepts `None` gracefully (returns empty vec).  Skips entries without a
/// valid `email` string containing `@`.
fn extract_email_addrs(field: Option<&Value>) -> Vec<String> {
    field
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|obj| obj.get("email"))
                .filter_map(|e| e.as_str())
                .filter(|s| s.contains('@'))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destroy_returns_not_permitted() {
        let args = json!({
            "accountId": "acc1",
            "destroy": ["cid1", "cid2"]
        });
        let result = handle_email_set(args).unwrap();
        let not_destroyed = result["notDestroyed"].as_object().unwrap();
        assert!(not_destroyed.contains_key("cid1"));
        assert!(not_destroyed.contains_key("cid2"));
        assert_eq!(not_destroyed["cid1"]["type"], "notPermitted");
    }

    #[test]
    fn update_mailbox_ids_returns_not_permitted() {
        let args = json!({
            "accountId": "acc1",
            "update": {
                "somecid": {
                    "mailboxIds": {"newmailbox": true}
                }
            }
        });
        let result = handle_email_set(args).unwrap();
        let not_updated = result["notUpdated"].as_object().unwrap();
        assert!(not_updated.contains_key("somecid"));
        assert_eq!(not_updated["somecid"]["type"], "notPermitted");
    }

    #[test]
    fn update_without_mailbox_ids_succeeds() {
        let args = json!({
            "accountId": "acc1",
            "update": {
                "somecid": {
                    "keywords": {"$seen": true}
                }
            }
        });
        let result = handle_email_set(args).unwrap();
        // notUpdated should be null since keywords-only is allowed
        assert!(result["notUpdated"].is_null());
    }

    // --- Tests for handle_keyword_update ---

    #[tokio::test]
    async fn keyword_update_sets_seen_flag() {
        use crate::state::flags::UserFlagsStore;
        use multihash_codetable::{Code, MultihashDigest};
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        use std::str::FromStr as _;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static DB_SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let url = format!("file:kw_update_test_{n}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .unwrap();
        let flags_store = UserFlagsStore::new(pool);

        let cid = cid::Cid::new_v1(0x71, Code::Sha2_256.digest(b"test-article"));
        let cid_str = cid.to_string();

        let mut update_map = serde_json::Map::new();
        update_map.insert(cid_str.clone(), json!({"keywords": {"$seen": true}}));

        let (updated, not_updated) = handle_keyword_update(&update_map, 1, &flags_store).await;
        assert!(
            not_updated.is_empty(),
            "should not have errors: {:?}",
            not_updated
        );
        assert!(updated.contains_key(&cid_str));

        let flags = flags_store
            .get_flags(1, &cid)
            .await
            .unwrap()
            .expect("must exist");
        assert!(flags.seen);
    }

    // --- Tests for handle_email_create ---

    #[tokio::test]
    async fn email_create_produces_cid() {
        use stoa_reader::post::ipfs_write::MemIpfsStore;

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        stoa_core::migrations::run_migrations(&pool)
            .await
            .unwrap();
        let msgid_map = stoa_core::msgid_map::MsgIdMap::new(pool);
        let ipfs = MemIpfsStore::new();

        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {"somemailboxid": true},
                "from": [{"email": "alice@example.com"}],
                "subject": "Test Create",
                "textBody": [{"value": "Hello, world!"}]
            }),
        );

        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, None).await;
        assert!(not_created.is_empty(), "should succeed: {:?}", not_created);
        assert!(created.contains_key("c1"));
        assert!(created["c1"]["id"].as_str().is_some());
    }

    /// Helper: build a MsgIdMap on an in-memory SQLite pool with core migrations.
    async fn make_msgid_map() -> stoa_core::msgid_map::MsgIdMap {
        use sqlx::sqlite::SqlitePoolOptions;
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        stoa_core::migrations::run_migrations(&pool)
            .await
            .unwrap();
        stoa_core::msgid_map::MsgIdMap::new(pool)
    }

    /// smtp_queue=None: no .env files written even when To: is present.
    #[tokio::test]
    async fn email_create_no_smtp_queue_no_enqueue() {
        use stoa_reader::post::ipfs_write::MemIpfsStore;

        let dir = tempfile::tempdir().expect("tempdir");
        let msgid_map = make_msgid_map().await;
        let ipfs = MemIpfsStore::new();

        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {"news.test": true},
                "from": [{"email": "alice@example.com"}],
                "to": [{"email": "bob@example.com"}],
                "subject": "No smtp queue test",
                "textBody": [{"value": "body"}]
            }),
        );

        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, None).await;
        assert!(not_created.is_empty());
        assert!(created.contains_key("c1"));

        // Oracle: no .env files in the dir (queue was never created there, but
        // we verify by checking the tmpdir we control).
        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "env"))
            .count();
        assert_eq!(env_count, 0, "no smtp queue: no .env files expected");
    }

    /// smtp_queue=Some with To: field: .env file appears in queue_dir.
    #[tokio::test]
    async fn email_create_with_smtp_queue_and_to_enqueues() {
        use std::time::Duration;
        use stoa_reader::post::ipfs_write::MemIpfsStore;
        use stoa_smtp::config::SmtpRelayPeerConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let peer = SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: false,
            username: None,
            password: None,
        };
        let queue =
            stoa_smtp::SmtpRelayQueue::new(dir.path(), vec![peer], Duration::from_secs(300))
                .expect("queue");

        let msgid_map = make_msgid_map().await;
        let ipfs = MemIpfsStore::new();

        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {"news.test": true},
                "from": [{"email": "alice@example.com"}],
                "to": [{"email": "bob@example.com"}],
                "subject": "Smtp relay test",
                "textBody": [{"value": "relay this"}]
            }),
        );

        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, Some(&queue)).await;
        assert!(not_created.is_empty(), "should succeed: {:?}", not_created);
        assert!(created.contains_key("c1"));

        // Oracle: .env file must exist in queue_dir.
        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "env"))
            .count();
        assert_eq!(env_count, 1, "expected 1 .env file in smtp relay queue");
    }

    /// smtp_queue=Some but no To: or Cc:: no .env file written.
    #[tokio::test]
    async fn email_create_with_smtp_queue_no_recipients_no_enqueue() {
        use std::time::Duration;
        use stoa_reader::post::ipfs_write::MemIpfsStore;
        use stoa_smtp::config::SmtpRelayPeerConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let peer = SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: false,
            username: None,
            password: None,
        };
        let queue =
            stoa_smtp::SmtpRelayQueue::new(dir.path(), vec![peer], Duration::from_secs(300))
                .expect("queue");

        let msgid_map = make_msgid_map().await;
        let ipfs = MemIpfsStore::new();

        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {"news.test": true},
                "from": [{"email": "alice@example.com"}],
                "subject": "No recipients test",
                "textBody": [{"value": "body"}]
            }),
        );

        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, Some(&queue)).await;
        assert!(not_created.is_empty(), "should succeed: {:?}", not_created);
        assert!(created.contains_key("c1"));

        // Oracle: only dead/ subdir; no .env files.
        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |x| x == "env"))
            .count();
        assert_eq!(env_count, 0, "no recipients: no .env files expected");
    }

    /// SMTP enqueue failure (queue dir removed) must NOT cause handle_email_create to fail.
    #[tokio::test]
    async fn email_create_smtp_enqueue_failure_is_nonfatal() {
        use std::time::Duration;
        use stoa_reader::post::ipfs_write::MemIpfsStore;
        use stoa_smtp::config::SmtpRelayPeerConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let peer = SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: false,
            username: None,
            password: None,
        };
        let queue =
            stoa_smtp::SmtpRelayQueue::new(dir.path(), vec![peer], Duration::from_secs(300))
                .expect("queue");

        // Remove the queue directory so enqueue will fail with an I/O error.
        std::fs::remove_dir_all(dir.path()).expect("remove queue dir");

        let msgid_map = make_msgid_map().await;
        let ipfs = MemIpfsStore::new();

        let mut create_map = serde_json::Map::new();
        create_map.insert(
            "c1".to_string(),
            json!({
                "mailboxIds": {"news.test": true},
                "from": [{"email": "alice@example.com"}],
                "to": [{"email": "bob@example.com"}],
                "subject": "Enqueue failure test",
                "textBody": [{"value": "body"}]
            }),
        );

        // Oracle: handle_email_create must succeed (not_created is empty).
        let (created, not_created) =
            handle_email_create(&create_map, &ipfs, &msgid_map, Some(&queue)).await;
        assert!(
            not_created.is_empty(),
            "smtp enqueue failure must be non-fatal: {:?}",
            not_created
        );
        assert!(created.contains_key("c1"), "article must still be created");
    }

    /// extract_email_addrs correctly extracts email strings from JMAP format.
    #[test]
    fn extract_email_addrs_parses_jmap_format() {
        let field = json!([
            {"name": "Alice", "email": "alice@example.com"},
            {"name": "Bob", "email": "bob@example.com"},
            {"email": "no-name@example.com"},
            {"name": "Missing email"},
        ]);
        let addrs = extract_email_addrs(Some(&field));
        assert_eq!(
            addrs,
            vec![
                "alice@example.com",
                "bob@example.com",
                "no-name@example.com"
            ]
        );
    }

    /// extract_email_addrs returns empty vec for None input.
    #[test]
    fn extract_email_addrs_none_returns_empty() {
        let addrs = extract_email_addrs(None);
        assert!(addrs.is_empty());
    }
}
