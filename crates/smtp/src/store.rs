use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

/// Open (or create) the SQLite database at `path` and run migrations.
/// Pass `":memory:"` for an ephemeral in-process database.
pub async fn open(path: &str) -> Result<SqlitePool, sqlx::Error> {
    let url = if path == ":memory:" {
        "sqlite::memory:".to_string()
    } else {
        format!("sqlite:{}", path)
    };
    let opts = SqliteConnectOptions::from_str(&url)?.create_if_missing(true);
    // In-memory databases use a single connection so all callers share one DB.
    let max_conn = if path == ":memory:" { 1 } else { 5 };
    let pool = SqlitePoolOptions::new()
        .max_connections(max_conn)
        .connect_with(opts)
        .await?;
    run_migrations(&pool).await?;
    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_sieve_scripts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    NOT NULL,
            script_name  TEXT    NOT NULL DEFAULT 'default',
            script_bytes BLOB    NOT NULL,
            active       INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(username, script_name)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mailbox_messages (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    NOT NULL,
            mailbox      TEXT    NOT NULL DEFAULT 'INBOX',
            envelope_from TEXT   NOT NULL,
            envelope_to  TEXT    NOT NULL,
            raw_message  BLOB    NOT NULL,
            received_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Return the raw Sieve script bytes for the active script of `username`, if any.
pub async fn load_active_script(pool: &SqlitePool, username: &str) -> Option<Vec<u8>> {
    sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT script_bytes FROM user_sieve_scripts WHERE username = ? AND active = 1 LIMIT 1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Insert or replace a Sieve script for `username`.
pub async fn save_script(
    pool: &SqlitePool,
    username: &str,
    script_name: &str,
    script_bytes: &[u8],
    active: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO user_sieve_scripts (username, script_name, script_bytes, active)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(username, script_name) DO UPDATE SET
             script_bytes = excluded.script_bytes,
             active       = excluded.active,
             updated_at   = datetime('now')",
    )
    .bind(username)
    .bind(script_name)
    .bind(script_bytes)
    .bind(active as i64)
    .execute(pool)
    .await?;
    Ok(())
}

/// Deliver a raw message to a user's named mailbox.
pub async fn deliver(
    pool: &SqlitePool,
    username: &str,
    mailbox: &str,
    envelope_from: &str,
    envelope_to: &str,
    raw_message: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mailbox_messages
             (username, mailbox, envelope_from, envelope_to, raw_message)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(username)
    .bind(mailbox)
    .bind(envelope_from)
    .bind(envelope_to)
    .bind(raw_message)
    .execute(pool)
    .await?;
    Ok(())
}

/// Count messages in a specific mailbox (used in tests).
pub async fn count_messages(pool: &SqlitePool, username: &str, mailbox: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mailbox_messages WHERE username = ? AND mailbox = ?",
    )
    .bind(username)
    .bind(mailbox)
    .fetch_one(pool)
    .await
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_memory_and_deliver() {
        let pool = open(":memory:").await.expect("open");

        deliver(&pool, "alice", "INBOX", "sender@example.com", "alice@example.com", b"hello")
            .await
            .expect("deliver");

        let count = count_messages(&pool, "alice", "INBOX").await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn save_and_load_script() {
        let pool = open(":memory:").await.expect("open");

        assert!(load_active_script(&pool, "alice").await.is_none());

        save_script(&pool, "alice", "default", b"keep;", true)
            .await
            .expect("save");

        let bytes = load_active_script(&pool, "alice").await.expect("script");
        assert_eq!(bytes, b"keep;");
    }

    #[tokio::test]
    async fn inactive_script_not_returned() {
        let pool = open(":memory:").await.expect("open");
        save_script(&pool, "bob", "default", b"discard;", false)
            .await
            .expect("save");
        assert!(load_active_script(&pool, "bob").await.is_none());
    }
}
