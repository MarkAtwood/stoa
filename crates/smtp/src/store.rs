use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

/// Default global Sieve script installed at first startup.
///
/// Routes messages with a `List-Id:` header to `List/<list-id>` mailboxes
/// using RFC 5229 `:matches` capture groups.  Messages without `List-Id:`
/// fall through to the RFC 5228 implicit keep (INBOX).
pub const DEFAULT_GLOBAL_SIEVE_SCRIPT: &str = "\
require [\"fileinto\", \"variables\"];\n\
\n\
if header :matches \"List-Id\" \"*<*>*\" {\n\
    set \"list_id\" \"${2}\";\n\
    fileinto \"List/${list_id}\";\n\
    stop;\n\
}\n";

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

    // Enforce at most one active script per user at the DB level.
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_sieve_one_active
         ON user_sieve_scripts (username) WHERE active = 1",
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
///
/// When `active` is `true`, all other scripts for the same user are
/// deactivated first inside a single transaction so that at most one
/// script per user is ever marked active.
pub async fn save_script(
    pool: &SqlitePool,
    username: &str,
    script_name: &str,
    script_bytes: &[u8],
    active: bool,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    if active {
        // Deactivate every other script for this user before activating the
        // new one.  This keeps the partial unique index on (username) WHERE
        // active = 1 satisfied throughout the transaction.
        sqlx::query(
            "UPDATE user_sieve_scripts SET active = 0, updated_at = datetime('now')
             WHERE username = ? AND script_name != ? AND active = 1",
        )
        .bind(username)
        .bind(script_name)
        .execute(&mut *tx)
        .await?;
    }

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
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
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
    Ok(rows
        .into_iter()
        .map(|(name, active)| (name, active != 0))
        .collect())
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
    let result =
        sqlx::query("DELETE FROM user_sieve_scripts WHERE username = ? AND script_name = ?")
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
    sqlx::query("UPDATE user_sieve_scripts SET active = 0 WHERE username = ?")
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

/// Install the default global Sieve script if no active script exists yet.
///
/// Idempotent: does nothing when an active script is already stored under
/// `GLOBAL_SCRIPT_KEY`.  An operator who has uploaded a custom script via
/// the admin API will have an active row, so this function will skip
/// installation and preserve their script.
pub async fn provision_global_sieve(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let already_active: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM user_sieve_scripts WHERE username = ? AND active = 1 LIMIT 1",
    )
    .bind(crate::config::GLOBAL_SCRIPT_KEY)
    .fetch_optional(pool)
    .await?;

    if already_active.is_some() {
        return Ok(());
    }

    save_script(
        pool,
        crate::config::GLOBAL_SCRIPT_KEY,
        "default",
        DEFAULT_GLOBAL_SIEVE_SCRIPT.as_bytes(),
        true,
    )
    .await
}

/// Count messages in a specific mailbox.
#[cfg(test)]
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

/// Fetch raw message bytes of the first message in a mailbox.
#[cfg(test)]
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

/// Fetch the envelope_from of the first message in a mailbox.
#[cfg(test)]
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
    async fn provision_global_sieve_installs_default_script() {
        let pool = open(":memory:").await.expect("open");
        provision_global_sieve(&pool).await.expect("provision");

        let script = load_active_script(&pool, crate::config::GLOBAL_SCRIPT_KEY)
            .await
            .expect("active script must exist after provisioning");
        let src = std::str::from_utf8(&script).expect("utf-8");
        assert!(
            src.contains("List-Id"),
            "default script must contain List-Id routing: {src}"
        );
        assert!(
            src.contains("fileinto"),
            "default script must use fileinto: {src}"
        );
    }

    #[tokio::test]
    async fn provision_global_sieve_is_idempotent() {
        let pool = open(":memory:").await.expect("open");
        provision_global_sieve(&pool).await.expect("first provision");
        provision_global_sieve(&pool).await.expect("second provision");

        let scripts = list_scripts(&pool, crate::config::GLOBAL_SCRIPT_KEY)
            .await
            .unwrap();
        let active_count = scripts.iter().filter(|(_, a)| *a).count();
        assert_eq!(active_count, 1, "exactly one script must be active");
    }

    #[tokio::test]
    async fn provision_global_sieve_does_not_overwrite_existing_active_script() {
        let pool = open(":memory:").await.expect("open");
        save_script(
            &pool,
            crate::config::GLOBAL_SCRIPT_KEY,
            "custom",
            b"discard;",
            true,
        )
        .await
        .expect("save custom script");

        provision_global_sieve(&pool).await.expect("provision after custom");

        let script = load_active_script(&pool, crate::config::GLOBAL_SCRIPT_KEY)
            .await
            .expect("active script");
        assert_eq!(
            script,
            b"discard;",
            "provision must not overwrite an existing active script"
        );
    }

    #[tokio::test]
    async fn open_memory_and_deliver() {
        let pool = open(":memory:").await.expect("open");

        deliver(
            &pool,
            "alice",
            "INBOX",
            "sender@example.com",
            "alice@example.com",
            b"hello",
        )
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

    /// Saving a second script with active=true must deactivate the first.
    /// At most one script per user may be active at any time.
    #[tokio::test]
    async fn save_script_active_deactivates_siblings() {
        let pool = open(":memory:").await.expect("open");

        // Save first script as active.
        save_script(&pool, "carol", "script_a", b"keep;", true)
            .await
            .expect("save script_a");

        // Save a second script as active — script_a must become inactive.
        save_script(&pool, "carol", "script_b", b"discard;", true)
            .await
            .expect("save script_b");

        // load_active_script must return exactly script_b's bytes.
        let active = load_active_script(&pool, "carol")
            .await
            .expect("active script");
        assert_eq!(active, b"discard;", "script_b must be the active script");

        // list_scripts must show exactly one active entry.
        let scripts = list_scripts(&pool, "carol").await.expect("list");
        let active_count = scripts.iter().filter(|(_, a)| *a).count();
        assert_eq!(active_count, 1, "exactly one script must be active");

        // Verify script_a is now inactive.
        let a_active = scripts
            .iter()
            .find(|(name, _)| name == "script_a")
            .map(|(_, a)| *a)
            .expect("script_a must still exist");
        assert!(!a_active, "script_a must be deactivated");
    }
}
