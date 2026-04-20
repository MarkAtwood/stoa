//! Immutable audit log for security-relevant events.
//!
//! All events are written to the `audit_log` SQLite table as append-only rows.
//! No UPDATE or DELETE ever runs against this table.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::StorageError;

/// A security-relevant event to be recorded in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    /// An article was signed and written to IPFS by this operator.
    ArticleSigned {
        message_id: String,
        cid: String,
        key_fingerprint: String,
    },
    /// An authentication attempt from a peer or client.
    AuthAttempt {
        peer_addr: String,
        user: String,
        success: bool,
    },
    /// A peer was blacklisted due to repeated failures.
    PeerBlacklisted {
        peer_id: String,
        reason: String,
        duration_secs: u64,
    },
    /// A GC run completed.
    GcRun {
        articles_unpinned: u64,
        group_name: String,
    },
    /// An admin endpoint was accessed.
    AdminAccess {
        peer_addr: String,
        path: String,
        method: String,
        status_code: u16,
    },
}

impl AuditEvent {
    /// Returns the event type string used as the `event_type` column value.
    pub fn event_type(&self) -> &'static str {
        match self {
            AuditEvent::ArticleSigned { .. } => "article_signed",
            AuditEvent::AuthAttempt { .. } => "auth_attempt",
            AuditEvent::PeerBlacklisted { .. } => "peer_blacklisted",
            AuditEvent::GcRun { .. } => "gc_run",
            AuditEvent::AdminAccess { .. } => "admin_access",
        }
    }

    /// Serialize the event to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("AuditEvent serialization must not fail")
    }

    /// Deserialize an event from JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// Append an audit event to the `audit_log` table.
pub async fn append_audit_event(
    pool: &SqlitePool,
    timestamp_ms: i64,
    event: &AuditEvent,
) -> Result<(), StorageError> {
    let event_type = event.event_type();
    let event_json = event.to_json();
    sqlx::query(
        "INSERT INTO audit_log (timestamp_ms, event_type, event_json) VALUES (?, ?, ?)",
    )
    .bind(timestamp_ms)
    .bind(event_type)
    .bind(&event_json)
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

/// Read the N most recent audit events (all types).
pub async fn recent_audit_events(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<(i64, AuditEvent)>, StorageError> {
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT timestamp_ms, event_json FROM audit_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    let mut events = Vec::with_capacity(rows.len());
    for (ts, json) in rows {
        match AuditEvent::from_json(&json) {
            Ok(event) => events.push((ts, event)),
            Err(e) => {
                return Err(StorageError::Database(format!(
                    "audit event deserialize: {e}"
                )))
            }
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;

    async fn make_pool() -> (SqlitePool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        let opts = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        crate::migrations::run_migrations(&pool).await.unwrap();
        (pool, tmp)
    }

    #[test]
    fn article_signed_roundtrip() {
        let event = AuditEvent::ArticleSigned {
            message_id: "<test@example.com>".to_string(),
            cid: "bafy123".to_string(),
            key_fingerprint: "ab:cd:ef".to_string(),
        };
        let json = event.to_json();
        let parsed = AuditEvent::from_json(&json).unwrap();
        assert_eq!(event, parsed);
        assert!(json.contains("article_signed"), "event_type in JSON: {json}");
    }

    #[test]
    fn all_event_types_serialize() {
        let events = vec![
            AuditEvent::ArticleSigned {
                message_id: "m".into(),
                cid: "c".into(),
                key_fingerprint: "k".into(),
            },
            AuditEvent::AuthAttempt {
                peer_addr: "127.0.0.1:9000".into(),
                user: "u".into(),
                success: true,
            },
            AuditEvent::PeerBlacklisted {
                peer_id: "p".into(),
                reason: "spam".into(),
                duration_secs: 3600,
            },
            AuditEvent::GcRun {
                articles_unpinned: 5,
                group_name: "comp.test".into(),
            },
            AuditEvent::AdminAccess {
                peer_addr: "127.0.0.1".into(),
                path: "/status".into(),
                method: "GET".into(),
                status_code: 200,
            },
        ];
        for event in &events {
            let json = event.to_json();
            let parsed = AuditEvent::from_json(&json).unwrap();
            assert_eq!(event, &parsed, "roundtrip failed for {json}");
        }
    }

    #[tokio::test]
    async fn append_and_read_events() {
        let (pool, _tmp) = make_pool().await;
        let event = AuditEvent::GcRun {
            articles_unpinned: 3,
            group_name: "alt.test".into(),
        };
        append_audit_event(&pool, 1_700_000_000_000, &event)
            .await
            .unwrap();

        let events = recent_audit_events(&pool, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, 1_700_000_000_000);
        assert_eq!(events[0].1, event);
    }

    #[tokio::test]
    async fn multiple_events_ordered_desc() {
        let (pool, _tmp) = make_pool().await;
        for i in 0..5u64 {
            let e = AuditEvent::GcRun {
                articles_unpinned: i,
                group_name: "alt.test".into(),
            };
            append_audit_event(&pool, i as i64 * 1000, &e)
                .await
                .unwrap();
        }
        let events = recent_audit_events(&pool, 3).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].1,
            AuditEvent::GcRun {
                articles_unpinned: 4,
                group_name: "alt.test".into()
            }
        );
    }
}
