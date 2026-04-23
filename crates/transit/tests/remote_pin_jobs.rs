//! Integration tests for the remote pinning jobs table and admin endpoint.
//!
//! Tests exercise the DB schema via the public migration runner, then insert
//! and query rows directly using the same sqlx pool — no live HTTP services
//! or background worker tasks are spawned.
//!
//! Oracles:
//!   - DB constraints verified by INSERT UNIQUE constraint violation
//!   - JSON structure verified by serde_json deserialization
//!   - Status counts verified by direct SELECT after INSERT

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::Row;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use usenet_ipfs_transit::admin::build_pinning_remote_json;

static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

async fn make_pool() -> Arc<sqlx::SqlitePool> {
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("file:remote_pin_{n}?mode=memory&cache=shared");
    let opts = SqliteConnectOptions::new()
        .filename(&url)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    usenet_ipfs_transit::migrations::run_migrations(&pool)
        .await
        .unwrap();
    Arc::new(pool)
}

/// INSERT OR IGNORE enqueues a job with default `pending` status.
#[tokio::test]
async fn insert_or_ignore_enqueues_job_as_pending() {
    let pool = make_pool().await;

    sqlx::query("INSERT OR IGNORE INTO remote_pin_jobs (cid, service_name) VALUES (?1, ?2)")
        .bind("QmTest1")
        .bind("pinata")
        .execute(&*pool)
        .await
        .unwrap();

    let row = sqlx::query(
        "SELECT status, attempt_count FROM remote_pin_jobs WHERE cid = ?1 AND service_name = ?2",
    )
    .bind("QmTest1")
    .bind("pinata")
    .fetch_one(&*pool)
    .await
    .unwrap();

    let status: String = row.get("status");
    let attempt_count: i64 = row.get("attempt_count");
    assert_eq!(status, "pending");
    assert_eq!(attempt_count, 0);
}

/// UNIQUE constraint on (cid, service_name) prevents duplicate entries.
/// INSERT OR IGNORE must silently skip the second insert.
#[tokio::test]
async fn unique_constraint_prevents_duplicate_per_service() {
    let pool = make_pool().await;

    // First insert succeeds.
    sqlx::query("INSERT OR IGNORE INTO remote_pin_jobs (cid, service_name) VALUES (?1, ?2)")
        .bind("QmDup1")
        .bind("web3")
        .execute(&*pool)
        .await
        .unwrap();

    // Second insert for same (cid, service_name) must be silently ignored.
    let result =
        sqlx::query("INSERT OR IGNORE INTO remote_pin_jobs (cid, service_name) VALUES (?1, ?2)")
            .bind("QmDup1")
            .bind("web3")
            .execute(&*pool)
            .await;
    assert!(
        result.is_ok(),
        "INSERT OR IGNORE must not error on duplicate"
    );

    // Only one row must exist.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM remote_pin_jobs WHERE cid = 'QmDup1' AND service_name = 'web3'",
    )
    .fetch_one(&*pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "exactly one row expected after duplicate insert");
}

/// Same CID can be submitted to different services (different rows).
#[tokio::test]
async fn same_cid_different_services_creates_two_rows() {
    let pool = make_pool().await;

    sqlx::query("INSERT OR IGNORE INTO remote_pin_jobs (cid, service_name) VALUES (?1, ?2)")
        .bind("QmShared")
        .bind("pinata")
        .execute(&*pool)
        .await
        .unwrap();

    sqlx::query("INSERT OR IGNORE INTO remote_pin_jobs (cid, service_name) VALUES (?1, ?2)")
        .bind("QmShared")
        .bind("filebase")
        .execute(&*pool)
        .await
        .unwrap();

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM remote_pin_jobs WHERE cid = 'QmShared'")
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(count, 2, "expected two rows for two different services");
}

/// Group filter matching: when service groups is empty, all groups match.
/// This is a unit-level check of the pipeline's group_matches_pattern logic.
/// Verified indirectly by checking job count after a pattern match loop.
#[tokio::test]
async fn group_filter_empty_means_pin_all_groups() {
    // A service with empty groups list should pin articles from any group.
    // We simulate the pipeline logic: if svc_groups.is_empty(), always insert.
    let pool = make_pool().await;
    let svc_name = "all-groups-svc";

    let article_groups = ["comp.lang.rust", "alt.test", "sci.math"];
    let svc_groups: Vec<String> = vec![];

    for group in &article_groups {
        let should_pin = svc_groups.is_empty()
            || article_groups
                .iter()
                .any(|g| svc_groups.iter().any(|p| group_matches_pattern(g, p)));
        if should_pin {
            sqlx::query(
                "INSERT OR IGNORE INTO remote_pin_jobs (cid, service_name) VALUES (?1, ?2)",
            )
            .bind(format!("Qm{group}"))
            .bind(svc_name)
            .execute(&*pool)
            .await
            .unwrap();
        }
    }

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM remote_pin_jobs WHERE service_name = ?1")
            .bind(svc_name)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(
        count, 3,
        "all 3 groups should be enqueued when filter is empty"
    );
}

/// Group filter matching: pattern `comp.*` matches comp groups but not alt.
#[tokio::test]
async fn group_filter_pattern_matches_prefix() {
    let pool = make_pool().await;
    let svc_name = "comp-only";

    let all_groups = ["comp.lang.rust", "comp.os.linux", "alt.test", "sci.math"];
    let svc_groups = vec!["comp.*".to_string()];

    for group in &all_groups {
        let should_pin =
            svc_groups.is_empty() || svc_groups.iter().any(|p| group_matches_pattern(group, p));
        if should_pin {
            sqlx::query(
                "INSERT OR IGNORE INTO remote_pin_jobs (cid, service_name) VALUES (?1, ?2)",
            )
            .bind(format!("Qm{group}"))
            .bind(svc_name)
            .execute(&*pool)
            .await
            .unwrap();
        }
    }

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM remote_pin_jobs WHERE service_name = ?1")
            .bind(svc_name)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(count, 2, "only comp.* groups should be enqueued");
}

/// /pinning/remote admin endpoint returns correct per-service JSON stats.
#[tokio::test]
async fn admin_pinning_remote_endpoint_returns_stats() {
    let pool = make_pool().await;

    // Seed mixed statuses for two services.
    let inserts = [
        ("Qm1", "pinata", "pending"),
        ("Qm2", "pinata", "pending"),
        ("Qm3", "pinata", "pinned"),
        ("Qm4", "web3", "queued"),
        ("Qm5", "web3", "failed"),
    ];
    for (cid, svc, status) in inserts {
        sqlx::query("INSERT INTO remote_pin_jobs (cid, service_name, status) VALUES (?1, ?2, ?3)")
            .bind(cid)
            .bind(svc)
            .bind(status)
            .execute(&*pool)
            .await
            .unwrap();
    }

    let json = build_pinning_remote_json(&*pool).await.unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

    assert_eq!(arr.len(), 2, "expected 2 service entries: {json}");

    // BTreeMap ordering guarantees "pinata" comes before "web3".
    let pinata = &arr[0];
    assert_eq!(pinata["service"], "pinata");
    assert_eq!(pinata["pending"], 2);
    assert_eq!(pinata["pinned"], 1);
    assert_eq!(pinata["queued"], 0);
    assert_eq!(pinata["failed"], 0);

    let web3 = &arr[1];
    assert_eq!(web3["service"], "web3");
    assert_eq!(web3["queued"], 1);
    assert_eq!(web3["failed"], 1);
    assert_eq!(web3["pending"], 0);
    assert_eq!(web3["pinned"], 0);
}

/// Reusable group pattern matcher (mirrors main.rs logic).
fn group_matches_pattern(group: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        group.starts_with(prefix)
    } else {
        group == pattern
    }
}
