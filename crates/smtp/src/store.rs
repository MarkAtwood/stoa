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

/// List all scripts for `username`, returning `(script_name, is_active)` pairs.
pub async fn list_scripts(
    pool: &SqlitePool,
    username: &str,
) -> Result<Vec<(String, bool)>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT script_name, active FROM user_sieve_scripts WHERE username = ? ORDER BY script_name",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(name, active)| (name, active != 0)).collect())
}

/// Fetch the raw bytes of a named script for `username`, or `None` if not found.
pub async fn get_script(
    pool: &SqlitePool,
    username: &str,
    script_name: &str,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT script_bytes FROM user_sieve_scripts WHERE username = ? AND script_name = ?",
    )
    .bind(username)
    .bind(script_name)
    .fetch_optional(pool)
    .await
}

/// Delete a named script.  Returns `true` if a row was deleted.
pub async fn delete_script(
    pool: &SqlitePool,
    username: &str,
    script_name: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM user_sieve_scripts WHERE username = ? AND script_name = ?",
    )
    .bind(username)
    .bind(script_name)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Set `script_name` as the sole active script for `username`, deactivating
/// all others.  Returns `false` if the named script does not exist.
pub async fn set_active(
    pool: &SqlitePool,
    username: &str,
    script_name: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Verify the target script exists.
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM user_sieve_scripts WHERE username = ? AND script_name = ?",
    )
    .bind(username)
    .bind(script_name)
    .fetch_optional(&mut *tx)
    .await?;

    if exists.is_none() {
        return Ok(false);
    }

    // Deactivate all scripts for this user, then activate the target.
    sqlx::query(
        "UPDATE user_sieve_scripts SET active = 0 WHERE username = ?",
    )
    .bind(username)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE user_sieve_scripts SET active = 1, updated_at = datetime('now')
         WHERE username = ? AND script_name = ?",
    )
    .bind(username)
    .bind(script_name)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
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

/// Fetch raw message bytes of the first message in a mailbox (used in tests).
pub async fn get_first_message_raw(
    pool: &SqlitePool,
    username: &str,
    mailbox: &str,
) -> Option<Vec<u8>> {
    sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT raw_message FROM mailbox_messages WHERE username = ? AND mailbox = ? ORDER BY id LIMIT 1",
    )
    .bind(username)
    .bind(mailbox)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Fetch the envelope_from of the first message in a mailbox (used in tests).
pub async fn get_first_envelope_from(
    pool: &SqlitePool,
    username: &str,
    mailbox: &str,
) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT envelope_from FROM mailbox_messages WHERE username = ? AND mailbox = ? ORDER BY id LIMIT 1",
    )
    .bind(username)
    .bind(mailbox)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
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
