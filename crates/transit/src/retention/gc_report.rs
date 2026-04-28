//! GC run report: structured JSON written to disk after each GC pass.
//!
//! Each GC run writes a file named `YYYYMMDDTHHMMSSZ-<run_id>.json` to the
//! configured `[gc] report_dir`.  Report files are never deleted by the daemon;
//! retention of the reports themselves is the operator's responsibility.

use serde::{Deserialize, Serialize};

/// A single failed-unpin record in a GC report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GcReportError {
    pub cid: String,
    pub reason: String,
}

/// Structured report emitted after each GC run.
///
/// Written as a JSON file to `[gc] report_dir` (if configured) and stored
/// in-memory as the last-run report for `GET /admin/gc/last-run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcReport {
    /// Random hex-encoded run identifier (16 bytes = 32 hex chars).
    pub run_id: String,
    /// UTC timestamp when the run started.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// UTC timestamp when the run completed.
    pub completed_at: chrono::DateTime<chrono::Utc>,
    /// Human-readable description of the active pin policy.
    pub policy: String,
    /// Number of distinct newsgroups present in the candidate set.
    pub groups_scanned: usize,
    /// Total articles evaluated (passed to `run_once`).
    pub articles_evaluated: usize,
    /// Articles successfully unpinned (deleted) in this run.
    pub articles_deleted: usize,
    /// Approximate bytes reclaimed (sum of `byte_count` for unpinned articles).
    pub bytes_reclaimed: u64,
    /// Unpin failures: articles that were evaluated for deletion but could not be unpinned.
    pub errors: Vec<GcReportError>,
}

impl GcReport {
    /// Write this report to `<report_dir>/<started_at>-<run_id>.json`.
    ///
    /// Creates the directory if it does not exist.  Errors are logged at WARN
    /// but do not abort the GC run.
    pub async fn write_to_dir(&self, report_dir: &str) {
        let dir = std::path::Path::new(report_dir);
        if let Err(e) = tokio::fs::create_dir_all(dir).await {
            tracing::warn!(report_dir, "GC: failed to create report directory: {e}");
            return;
        }
        let ts_safe = self.started_at.format("%Y-%m-%dT%H-%M-%SZ").to_string();
        let filename = format!("{ts_safe}-{}.json", self.run_id);
        let path = dir.join(&filename);
        match serde_json::to_vec_pretty(self) {
            Ok(bytes) => {
                if let Err(e) = tokio::fs::write(&path, &bytes).await {
                    tracing::warn!(path = %path.display(), "GC: failed to write report: {e}");
                } else {
                    tracing::debug!(path = %path.display(), "GC: report written");
                }
            }
            Err(e) => {
                tracing::warn!("GC: failed to serialise report: {e}");
            }
        }
    }
}

/// Generate a random 32-hex-character run ID using `rand_core::OsRng`.
pub fn new_run_id() -> String {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Convert a Unix millisecond timestamp to a `DateTime<Utc>`.
///
/// Returns the Unix epoch on overflow (which cannot happen for any real
/// timestamp value).
pub fn ms_to_datetime(ms: u64) -> chrono::DateTime<chrono::Utc> {
    let secs = (ms / 1000) as i64;
    let nsecs = ((ms % 1000) * 1_000_000) as u32;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nsecs)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_run_id_produces_32_hex_chars() {
        let id = new_run_id();
        assert_eq!(id.len(), 32, "run_id must be 32 hex chars: {id}");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "run_id must be hex: {id}"
        );
    }

    #[test]
    fn ms_to_datetime_formats_correctly() {
        // 2026-04-27T00:00:00Z = 1777248000000 ms
        let ms = 1_777_248_000_000u64;
        let dt = ms_to_datetime(ms);
        let s = dt.to_rfc3339();
        assert!(s.contains("2026-"), "must contain year: {s}");
        assert_eq!(dt.timestamp(), (ms / 1000) as i64);
    }

    #[test]
    fn gc_report_serializes_to_json() {
        let started_at = ms_to_datetime(1_777_248_000_000u64);
        let completed_at = ms_to_datetime(1_777_248_001_000u64);
        let report = GcReport {
            run_id: "abc123".to_string(),
            started_at,
            completed_at,
            policy: "pin-all (max_age=30d)".to_string(),
            groups_scanned: 3,
            articles_evaluated: 100,
            articles_deleted: 5,
            bytes_reclaimed: 51200,
            errors: vec![GcReportError {
                cid: "bafk1".to_string(),
                reason: "connection refused".to_string(),
            }],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"run_id\""));
        assert!(json.contains("\"articles_deleted\":5"));
        assert!(json.contains("\"bytes_reclaimed\":51200"));
        assert!(json.contains("connection refused"));
    }

    #[tokio::test]
    async fn write_to_dir_creates_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let report = GcReport {
            run_id: "testrunid0000000".to_string(),
            started_at: ms_to_datetime(1_777_248_000_000u64),
            completed_at: ms_to_datetime(1_777_248_001_000u64),
            policy: "test".to_string(),
            groups_scanned: 0,
            articles_evaluated: 0,
            articles_deleted: 0,
            bytes_reclaimed: 0,
            errors: vec![],
        };
        report.write_to_dir(tmp.path().to_str().unwrap()).await;
        let mut entries = tokio::fs::read_dir(tmp.path()).await.expect("readdir");
        let entry = entries.next_entry().await.expect("ok").expect("entry");
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            name.ends_with(".json"),
            "report file must end with .json: {name}"
        );
        let content = tokio::fs::read_to_string(entry.path()).await.expect("read");
        assert!(content.contains("\"run_id\""));
    }
}
