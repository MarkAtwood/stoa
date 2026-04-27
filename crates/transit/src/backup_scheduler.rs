//! Scheduled SQLite backup task for the transit daemon.
//!
//! When `backup.schedule` is configured, [`run_backup_scheduler`] is spawned at
//! startup.  It computes the next fire time from the cron expression, sleeps until
//! that time, runs a full SQLite backup via [`crate::admin::backup_databases`], and
//! optionally uploads the resulting files to S3 using `aws s3 cp`.
//!
//! The loop runs indefinitely until the process exits.  A failed backup attempt
//! is logged at error level and retried at the next scheduled time.

use std::sync::Arc;

use chrono::Utc;
use cron::Schedule;
use sqlx::SqlitePool;
use std::str::FromStr;
use tracing::{error, info, warn};

/// Normalise a 5- or 6-field cron expression to the 7-field format required by
/// the `cron` crate (`sec min hour dom month dow [year]`).
///
/// Standard 5-field (`min hour dom month dow`): prepend `0 ` (sec=0) and append ` *`.
/// 6-field (`sec min hour dom month dow`): append ` *`.
fn normalize_cron(s: &str) -> String {
    let field_count = s.split_whitespace().count();
    match field_count {
        5 => format!("0 {s} *"),
        6 => format!("{s} *"),
        _ => s.to_owned(),
    }
}

/// Upload backup files to S3 using the `aws` CLI.
///
/// Each path is uploaded to `s3://<bucket>/<prefix><filename>`.  `prefix` may
/// be empty; files land at the bucket root.  Errors are logged at warn level
/// and do not abort the upload of remaining paths.
async fn s3_upload_backup(bucket: &str, prefix: &str, paths: &[String]) {
    for path in paths {
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let s3_dest = format!("s3://{bucket}/{prefix}{filename}");
        match tokio::process::Command::new("aws")
            .args(["s3", "cp", path, &s3_dest])
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                info!(src = %path, dest = %s3_dest, "backup uploaded to S3");
            }
            Ok(out) => {
                warn!(
                    src = %path,
                    dest = %s3_dest,
                    stderr = %String::from_utf8_lossy(&out.stderr),
                    "aws s3 cp failed"
                );
            }
            Err(e) => {
                warn!(src = %path, dest = %s3_dest, "aws s3 cp could not be started: {e}");
            }
        }
    }
}

/// Run the scheduled backup loop indefinitely.
///
/// Parses `schedule`, sleeps until the next fire time, calls
/// [`crate::admin::backup_databases`], and (if `s3_bucket` is set) uploads each
/// backup file to S3.  The loop repeats until the process exits.
pub async fn run_backup_scheduler(
    transit_pool: Arc<SqlitePool>,
    core_pool: Arc<SqlitePool>,
    dest_dir: String,
    s3_bucket: Option<String>,
    s3_prefix: Option<String>,
    schedule: String,
) {
    let normalized = normalize_cron(&schedule);
    let sched = match Schedule::from_str(&normalized) {
        Ok(s) => s,
        Err(e) => {
            error!(schedule = %schedule, "backup scheduler: invalid cron expression: {e}");
            return;
        }
    };

    loop {
        let next = match sched.upcoming(Utc).next() {
            Some(t) => t,
            None => {
                warn!(
                    schedule = %schedule,
                    "backup scheduler: no upcoming fire times; stopping"
                );
                return;
            }
        };

        let delay_secs = (next - Utc::now()).num_seconds().max(0) as u64;
        info!(
            next = %next.format("%Y-%m-%dT%H:%M:%SZ"),
            delay_secs,
            "backup scheduler: next backup scheduled"
        );

        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

        match crate::admin::backup_databases(&transit_pool, &core_pool, &dest_dir).await {
            Ok(paths) => {
                info!(files = ?paths, "scheduled backup completed");
                if let Some(ref bucket) = s3_bucket {
                    let prefix = s3_prefix.as_deref().unwrap_or("");
                    s3_upload_backup(bucket, prefix, &paths).await;
                }
            }
            Err(e) => {
                error!("scheduled backup failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_cron;

    #[test]
    fn normalize_five_field() {
        // "min hour dom month dow" → "0 min hour dom month dow *"
        assert_eq!(normalize_cron("0 3 * * *"), "0 0 3 * * * *");
    }

    #[test]
    fn normalize_six_field() {
        // "sec min hour dom month dow" → same plus " *"
        assert_eq!(normalize_cron("0 0 3 * * *"), "0 0 3 * * * *");
    }

    #[test]
    fn normalize_unknown_field_count_passthrough() {
        assert_eq!(normalize_cron("bad"), "bad");
    }
}
