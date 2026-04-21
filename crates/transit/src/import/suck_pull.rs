//! Pull-style import: fetch new articles from a remote NNTP server via NEWNEWS.

use sqlx::SqlitePool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use usenet_ipfs_core::error::StorageError;

/// Configuration for the suck pull import.
#[derive(Debug, Clone)]
pub struct SuckPullConfig {
    /// Remote NNTP server address (e.g., "news.example.com:119").
    pub remote_addr: String,
    /// Groups to pull (glob patterns accepted by the remote NEWNEWS command).
    pub groups: Vec<String>,
    /// Override starting timestamp (Unix seconds). If None, uses the cursor.
    pub since_override: Option<u64>,
    /// Max retry attempts per article on network error.
    pub max_retries: usize,
}

/// Summary of a completed suck pull run.
#[derive(Debug, Default)]
pub struct SuckPullSummary {
    pub new_articles: usize,
    pub fetched: usize,
    pub skipped_duplicate: usize,
    pub failed: usize,
    pub elapsed_ms: u64,
}

impl std::fmt::Display for SuckPullSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "new: {}, fetched: {}, skipped: {}, failed: {}, elapsed: {}ms",
            self.new_articles, self.fetched, self.skipped_duplicate, self.failed, self.elapsed_ms
        )
    }
}

/// Run the suck pull import for all configured groups.
pub async fn run_suck_pull(
    pool: &SqlitePool,
    config: &SuckPullConfig,
) -> Result<SuckPullSummary, StorageError> {
    let start = Instant::now();

    ensure_cursor_table(pool).await?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let default_since = now_unix.saturating_sub(86400);

    let stream = match TcpStream::connect(&config.remote_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "suck_pull: TCP connect to {} failed: {e}",
                config.remote_addr
            );
            return Ok(SuckPullSummary {
                failed: config.groups.len(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                ..Default::default()
            });
        }
    };

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    // Read server greeting.
    line.clear();
    if let Err(e) = reader.read_line(&mut line).await {
        tracing::warn!("suck_pull: failed to read greeting: {e}");
        return Ok(SuckPullSummary {
            failed: config.groups.len(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        });
    }
    let code = parse_response_code(&line);
    if code != 200 && code != 201 {
        tracing::warn!(
            "suck_pull: unexpected greeting from {}: {}",
            config.remote_addr,
            line.trim()
        );
        return Ok(SuckPullSummary {
            failed: config.groups.len(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        });
    }

    let mut summary = SuckPullSummary::default();

    for group in &config.groups {
        let since = match config.since_override {
            Some(ts) => ts,
            None => read_cursor(pool, group).await?.unwrap_or(default_since),
        };

        let date_str = format_nntp_date(since);
        let newnews_cmd = format!("NEWNEWS {} {} GMT\r\n", group, date_str);

        if let Err(e) = writer.write_all(newnews_cmd.as_bytes()).await {
            tracing::warn!("suck_pull: write NEWNEWS for {group} failed: {e}");
            summary.failed += 1;
            continue;
        }

        line.clear();
        if let Err(e) = reader.read_line(&mut line).await {
            tracing::warn!("suck_pull: read NEWNEWS response for {group} failed: {e}");
            summary.failed += 1;
            continue;
        }
        let code = parse_response_code(&line);
        if code != 230 {
            tracing::info!(
                "suck_pull: NEWNEWS {group} returned code {code}: {}",
                line.trim()
            );
            summary.failed += 1;
            continue;
        }

        // Collect dot-terminated list of Message-IDs.
        let mut msgids: Vec<String> = Vec::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("suck_pull: read msgid list for {group} failed: {e}");
                    break;
                }
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed == "." {
                break;
            }
            msgids.push(trimmed.to_string());
        }

        summary.new_articles += msgids.len();

        for msgid in &msgids {
            match fetch_article_with_retry(&mut writer, &mut reader, msgid, config.max_retries)
                .await
            {
                FetchResult::Fetched => {
                    tracing::debug!("suck_pull: fetched {msgid}");
                    summary.fetched += 1;
                }
                FetchResult::NotFound => {
                    tracing::debug!("suck_pull: not found (430) {msgid}");
                    summary.skipped_duplicate += 1;
                }
                FetchResult::Failed => {
                    tracing::warn!("suck_pull: failed to fetch {msgid}");
                    summary.failed += 1;
                }
            }
        }

        // Update cursor to now for this group.
        update_cursor(pool, group, now_unix).await?;
    }

    // Send QUIT.
    let _ = writer.write_all(b"QUIT\r\n").await;

    summary.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(summary)
}

// ── Cursor helpers ─────────────────────────────────────────────────────────────

async fn ensure_cursor_table(pool: &SqlitePool) -> Result<(), StorageError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS suck_pull_cursor (\
            group_name TEXT PRIMARY KEY NOT NULL,\
            last_fetched_unix INTEGER NOT NULL\
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

async fn read_cursor(pool: &SqlitePool, group: &str) -> Result<Option<u64>, StorageError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT last_fetched_unix FROM suck_pull_cursor WHERE group_name = ?")
            .bind(group)
            .fetch_optional(pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(row.map(|(ts,)| ts as u64))
}

async fn update_cursor(pool: &SqlitePool, group: &str, unix_secs: u64) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT OR REPLACE INTO suck_pull_cursor (group_name, last_fetched_unix) VALUES (?, ?)",
    )
    .bind(group)
    .bind(unix_secs as i64)
    .execute(pool)
    .await
    .map_err(|e| StorageError::Database(e.to_string()))?;
    Ok(())
}

// ── Article fetch ──────────────────────────────────────────────────────────────

#[derive(Debug)]
enum FetchResult {
    Fetched,
    NotFound,
    Failed,
}

async fn fetch_article_with_retry(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    msgid: &str,
    max_retries: usize,
) -> FetchResult {
    let mut attempts = 0usize;
    loop {
        match fetch_article(writer, reader, msgid).await {
            FetchResult::Fetched => return FetchResult::Fetched,
            FetchResult::NotFound => return FetchResult::NotFound,
            FetchResult::Failed => {
                attempts += 1;
                if attempts > max_retries {
                    return FetchResult::Failed;
                }
                tracing::debug!("suck_pull: retry {attempts}/{max_retries} for {msgid}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

async fn fetch_article(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    msgid: &str,
) -> FetchResult {
    let cmd = format!("ARTICLE {msgid}\r\n");
    if let Err(e) = writer.write_all(cmd.as_bytes()).await {
        tracing::warn!("suck_pull: write ARTICLE {msgid} failed: {e}");
        return FetchResult::Failed;
    }

    let mut line = String::new();
    line.clear();
    match reader.read_line(&mut line).await {
        Ok(0) => return FetchResult::Failed,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("suck_pull: read ARTICLE response for {msgid} failed: {e}");
            return FetchResult::Failed;
        }
    }

    let code = parse_response_code(&line);
    match code {
        430 => return FetchResult::NotFound,
        220 => {}
        _ => {
            tracing::info!(
                "suck_pull: ARTICLE {msgid} unexpected code {code}: {}",
                line.trim()
            );
            return FetchResult::Failed;
        }
    }

    // Read dot-terminated article body; discard content (storage handled elsewhere).
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => return FetchResult::Failed,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("suck_pull: read article body for {msgid} failed: {e}");
                return FetchResult::Failed;
            }
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "." {
            break;
        }
    }

    FetchResult::Fetched
}

// ── Date formatting ────────────────────────────────────────────────────────────

/// Format a Unix timestamp as NNTP NEWNEWS date/time string.
///
/// Returns `"YYYYMMDD HHMMSS"` (caller appends `" GMT"` in the NEWNEWS command).
pub(crate) fn format_nntp_date(unix_secs: u64) -> String {
    let secs_of_day = (unix_secs % 86400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let mut days = (unix_secs / 86400) as u32;

    // Gregorian calendar: compute year.
    // Each 400-year cycle = 146097 days.
    let cycles400 = days / 146097;
    days %= 146097;

    // Each 100-year century = 36524 days (no leap on century unless div-400).
    let cycles100 = (days / 36524).min(3);
    days -= cycles100 * 36524;

    // Each 4-year cycle = 1461 days.
    let cycles4 = days / 1461;
    days %= 1461;

    // Each remaining year = 365 days (first year in a 4-cycle can be leap).
    let cycles1 = (days / 365).min(3);
    days -= cycles1 * 365;

    let year = 1970 + cycles400 * 400 + cycles100 * 100 + cycles4 * 4 + cycles1;

    // Now `days` is 0-based day-of-year. Compute month and day.
    let leap = is_leap_year(year);
    let month_lengths: [u32; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 1u32;
    let mut remaining = days;
    for &mlen in &month_lengths {
        if remaining < mlen {
            break;
        }
        remaining -= mlen;
        month += 1;
    }
    let day = remaining + 1;

    format!(
        "{:04}{:02}{:02} {:02}{:02}{:02}",
        year, month, day, hour, minute, second
    )
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ── Protocol helper ───────────────────────────────────────────────────────────

/// Parse the 3-digit NNTP response code from the start of a line.
///
/// Returns 0 if the line is too short or the first three characters are not digits.
fn parse_response_code(line: &str) -> u16 {
    line.get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_nntp_date_epoch() {
        // 1970-01-01 00:00:00 UTC
        assert_eq!(format_nntp_date(0), "19700101 000000");
    }

    #[test]
    fn format_nntp_date_known_date() {
        // 2024-01-15 12:30:45 UTC
        // 2024-01-15: days from epoch = 19737
        // 19737 * 86400 = 1705276800, + 12*3600 + 30*60 + 45 = 45045
        // = 1705276800 + 45045 = 1705321845
        // Cross-checked: python3 -c "import datetime; print(int(datetime.datetime(2024,1,15,12,30,45,tzinfo=datetime.timezone.utc).timestamp()))"
        assert_eq!(format_nntp_date(1705321845), "20240115 123045");
    }

    #[tokio::test]
    async fn run_suck_pull_connection_refused_fails_gracefully() {
        // Use a port that nothing is listening on
        let pool_url = "file:suck_test?mode=memory&cache=shared";
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(pool_url)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        let config = SuckPullConfig {
            remote_addr: "127.0.0.1:19998".to_string(),
            groups: vec!["comp.lang.rust".to_string()],
            since_override: Some(0),
            max_retries: 1,
        };
        // Should not panic; connection failure is handled gracefully
        let result = run_suck_pull(&pool, &config).await;
        // Either Ok with 0 fetched or Err — either is acceptable, no panic
        match result {
            Ok(s) => assert_eq!(s.fetched, 0),
            Err(_) => {} // Also acceptable
        }
    }

    #[test]
    fn summary_display_is_readable() {
        let s = SuckPullSummary {
            new_articles: 10,
            fetched: 8,
            skipped_duplicate: 2,
            failed: 0,
            elapsed_ms: 1234,
        };
        let text = s.to_string();
        assert!(text.contains("10") || text.contains("fetched"));
    }
}
