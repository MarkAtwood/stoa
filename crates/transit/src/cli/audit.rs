//! CLI subcommand: audit-export — query and export the audit log.

use sqlx::SqlitePool;
use stoa_core::StorageError;

/// Filters for the audit export command.
pub struct AuditExportFilter {
    /// Only include events after this timestamp (milliseconds since Unix epoch).
    pub since_ms: Option<i64>,
    /// Only include events before this timestamp (milliseconds since Unix epoch).
    pub until_ms: Option<i64>,
    /// Only include events of this type (matches the event_type column).
    pub event_type: Option<String>,
}

impl AuditExportFilter {
    pub fn none() -> Self {
        Self {
            since_ms: None,
            until_ms: None,
            event_type: None,
        }
    }
}

/// Export audit log events as newline-delimited JSON to a String.
///
/// Each line is one JSON object. Empty result produces an empty string.
pub async fn cmd_audit_export(
    pool: &SqlitePool,
    filter: &AuditExportFilter,
) -> Result<String, StorageError> {
    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT timestamp_ms, event_type, event_json FROM audit_log \
         WHERE (? IS NULL OR timestamp_ms >= ?) \
           AND (? IS NULL OR timestamp_ms < ?) \
           AND (? IS NULL OR event_type = ?) \
         ORDER BY id ASC",
    )
    .bind(filter.since_ms)
    .bind(filter.since_ms)
    .bind(filter.until_ms)
    .bind(filter.until_ms)
    .bind(filter.event_type.as_deref())
    .bind(filter.event_type.as_deref())
    .fetch_all(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;

    let mut output = String::new();
    for (ts_ms, _event_type, event_json) in &rows {
        let mut obj: serde_json::Value =
            serde_json::from_str(event_json).map_err(|e| StorageError::Database(e.to_string()))?;
        if let serde_json::Value::Object(ref mut map) = obj {
            map.insert(
                "timestamp_ms".to_owned(),
                serde_json::Value::Number((*ts_ms).into()),
            );
        }
        output.push_str(&serde_json::to_string(&obj).expect("re-serialization must not fail"));
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr as _;
    use stoa_core::audit::{append_audit_event, AuditEvent};

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
        stoa_core::migrations::run_migrations(&pool)
            .await
            .unwrap();
        (pool, tmp)
    }

    #[tokio::test]
    async fn export_empty_log() {
        let (pool, _tmp) = make_pool().await;
        let result = cmd_audit_export(&pool, &AuditExportFilter::none())
            .await
            .unwrap();
        assert!(result.is_empty(), "empty log should produce empty output");
    }

    #[tokio::test]
    async fn export_all_events() {
        let (pool, _tmp) = make_pool().await;
        for i in 0..5i64 {
            let e = AuditEvent::GcRun {
                articles_unpinned: i as u64,
                group_name: "alt.test".into(),
            };
            append_audit_event(&pool, i * 1000, &e).await.unwrap();
        }
        let result = cmd_audit_export(&pool, &AuditExportFilter::none())
            .await
            .unwrap();
        let lines: Vec<&str> = result.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 5, "should have 5 lines");
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("must be valid JSON");
            assert!(
                parsed.get("timestamp_ms").is_some(),
                "must have timestamp_ms: {line}"
            );
        }
    }

    #[tokio::test]
    async fn filter_by_since() {
        let (pool, _tmp) = make_pool().await;
        for i in 0..10i64 {
            let e = AuditEvent::GcRun {
                articles_unpinned: i as u64,
                group_name: "alt.test".into(),
            };
            append_audit_event(&pool, i * 1000, &e).await.unwrap();
        }
        let filter = AuditExportFilter {
            since_ms: Some(5000),
            until_ms: None,
            event_type: None,
        };
        let result = cmd_audit_export(&pool, &filter).await.unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(
            lines.len(),
            5,
            "events at 5000,6000,7000,8000,9000 should be returned"
        );
    }

    #[tokio::test]
    async fn filter_by_type() {
        let (pool, _tmp) = make_pool().await;
        append_audit_event(
            &pool,
            1000,
            &AuditEvent::GcRun {
                articles_unpinned: 1,
                group_name: "alt.test".into(),
            },
        )
        .await
        .unwrap();
        append_audit_event(
            &pool,
            2000,
            &AuditEvent::AdminAccess {
                peer_addr: "127.0.0.1".into(),
                path: "/status".into(),
                method: "GET".into(),
                status_code: 200,
            },
        )
        .await
        .unwrap();

        let filter = AuditExportFilter {
            since_ms: None,
            until_ms: None,
            event_type: Some("gc_run".into()),
        };
        let result = cmd_audit_export(&pool, &filter).await.unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 1, "only gc_run events: {result}");
        assert!(result.contains("gc_run"), "output should contain gc_run");
    }
}
