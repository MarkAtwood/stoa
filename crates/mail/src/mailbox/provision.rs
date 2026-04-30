use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use sqlx::AnyPool;

use crate::mailbox::types::SpecialMailbox;

/// Derive a stable, user-scoped mailbox ID from (user_id, role).
///
/// Algorithm: SHA-256(user_id as 8 little-endian bytes || role as UTF-8) → first 16 bytes → BASE32_NOPAD.
/// Result is always 26 characters.
///
/// Oracle: Python `hashlib.sha256(uid.to_bytes(8,'little') + role.encode()).digest()[:16]`
///         then `base64.b32encode(h).decode().rstrip('=')`
pub fn mailbox_id_for_user(user_id: i64, role: &str) -> String {
    let mut data = Vec::with_capacity(8 + role.len());
    data.extend_from_slice(&(user_id as u64).to_le_bytes());
    data.extend_from_slice(role.as_bytes());
    let digest = Sha256::digest(&data);
    BASE32_NOPAD.encode(&digest[..16])
}

const SPECIAL_FOLDERS: &[(&str, &str, i32)] = &[
    ("inbox", "INBOX", 1),
    ("sent", "Sent", 2),
    ("drafts", "Drafts", 3),
    ("trash", "Trash", 4),
    ("junk", "Junk", 5),
    ("archive", "Archive", 6),
];

/// Create the six RFC 6154 special-use mailboxes for `user_id` if they don't exist.
/// Idempotent: INSERT OR IGNORE, re-running for an already-provisioned user is a no-op.
/// All six rows are written in a single batched statement.
pub async fn provision_user_mailboxes(pool: &AnyPool, user_id: i64) -> Result<(), sqlx::Error> {
    let mut qb: sqlx::QueryBuilder<sqlx::Any> = sqlx::QueryBuilder::new(
        "INSERT OR IGNORE INTO user_mailboxes (user_id, role, mailbox_id, name, sort_order) ",
    );
    qb.push_values(
        SPECIAL_FOLDERS.iter(),
        |mut b, &(role, name, sort_order)| {
            b.push_bind(user_id)
                .push_bind(role)
                .push_bind(mailbox_id_for_user(user_id, role))
                .push_bind(name)
                .push_bind(sort_order as i64);
        },
    );
    qb.build().execute(pool).await?;
    Ok(())
}

/// Return the provisioned special-use mailboxes for `user_id`, ordered by sort_order.
///
/// Returns an empty vec (never an error) when the user has no rows yet; callers
/// should call `provision_user_mailboxes` first if they need the folders created.
pub async fn list_user_mailboxes(
    pool: &AnyPool,
    user_id: i64,
) -> Result<Vec<SpecialMailbox>, sqlx::Error> {
    let rows: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT mailbox_id, role, name, sort_order FROM user_mailboxes WHERE user_id = ? ORDER BY sort_order ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, role, name, sort_order)| SpecialMailbox {
            id,
            role,
            name,
            sort_order: sort_order as u32,
        })
        .collect())
}

/// Resolve a JMAP canonical_account_id (format: "u_{username}") to the user's row id.
///
/// Returns Err if the prefix is missing or the username is not found.
pub async fn resolve_user_id(
    pool: &AnyPool,
    canonical_account_id: &str,
) -> Result<i64, ResolveError> {
    let username = canonical_account_id
        .strip_prefix("u_")
        .filter(|s| !s.is_empty())
        .ok_or(ResolveError::InvalidAccountId)?;

    let id: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await
        .map_err(ResolveError::Db)?;

    id.ok_or(ResolveError::NotFound)
}

#[derive(Debug)]
pub enum ResolveError {
    InvalidAccountId,
    NotFound,
    Db(sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::{mailbox_id_for_user, provision_user_mailboxes, resolve_user_id};
    use sqlx::AnyPool;

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (pool, tmp)
    }

    // ── mailbox_id_for_user ────────────────────────────────────────────────────
    // Oracle: Python
    //   import hashlib, base64
    //   def mid(uid, role):
    //       h = hashlib.sha256(uid.to_bytes(8,'little') + role.encode()).digest()[:16]
    //       return base64.b32encode(h).decode().rstrip('=')

    #[test]
    fn mailbox_id_user1_inbox() {
        assert_eq!(
            mailbox_id_for_user(1, "inbox"),
            "XHEK6XD6CFURMHQFSXIALKNX6A"
        );
    }

    #[test]
    fn mailbox_id_user1_sent() {
        assert_eq!(mailbox_id_for_user(1, "sent"), "4ZAA5SOFZU7P5STWROOWLLRNOM");
    }

    #[test]
    fn mailbox_id_user2_inbox() {
        assert_eq!(
            mailbox_id_for_user(2, "inbox"),
            "PP6H5PGHSYOYJSE3Y57JTSCY34"
        );
    }

    #[test]
    fn mailbox_id_is_26_chars() {
        for role in &["inbox", "sent", "drafts", "trash", "junk", "archive"] {
            let id = mailbox_id_for_user(1, role);
            assert_eq!(id.len(), 26, "role={role} id={id}");
        }
    }

    #[test]
    fn mailbox_id_different_users_differ() {
        assert_ne!(
            mailbox_id_for_user(1, "inbox"),
            mailbox_id_for_user(2, "inbox")
        );
    }

    #[test]
    fn mailbox_id_different_roles_differ() {
        assert_ne!(
            mailbox_id_for_user(1, "inbox"),
            mailbox_id_for_user(1, "sent")
        );
    }

    // ── resolve_user_id ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_known_user() {
        let (pool, _tmp) = make_pool().await;
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (42, 'bob', 'x')")
            .execute(&pool)
            .await
            .unwrap();
        let id = resolve_user_id(&pool, "u_bob").await.unwrap();
        assert_eq!(id, 42);
    }

    #[tokio::test]
    async fn resolve_unknown_user_returns_not_found() {
        let (pool, _tmp) = make_pool().await;
        let err = resolve_user_id(&pool, "u_nobody").await.unwrap_err();
        assert!(matches!(err, super::ResolveError::NotFound));
    }

    #[tokio::test]
    async fn resolve_missing_prefix_returns_invalid() {
        let (pool, _tmp) = make_pool().await;
        let err = resolve_user_id(&pool, "alice").await.unwrap_err();
        assert!(matches!(err, super::ResolveError::InvalidAccountId));
    }

    #[tokio::test]
    async fn resolve_empty_suffix_returns_invalid() {
        let (pool, _tmp) = make_pool().await;
        let err = resolve_user_id(&pool, "u_").await.unwrap_err();
        assert!(matches!(err, super::ResolveError::InvalidAccountId));
    }

    // ── provision_user_mailboxes ───────────────────────────────────────────────

    #[tokio::test]
    async fn provision_creates_six_folders() {
        let (pool, _tmp) = make_pool().await;
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .unwrap();
        provision_user_mailboxes(&pool, 1).await.unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_mailboxes WHERE user_id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 6);
    }

    #[tokio::test]
    async fn provision_is_idempotent() {
        let (pool, _tmp) = make_pool().await;
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .unwrap();
        provision_user_mailboxes(&pool, 1).await.unwrap();
        provision_user_mailboxes(&pool, 1).await.unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_mailboxes WHERE user_id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 6);
    }

    #[tokio::test]
    async fn provision_inbox_has_correct_id() {
        let (pool, _tmp) = make_pool().await;
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .unwrap();
        provision_user_mailboxes(&pool, 1).await.unwrap();

        let mailbox_id: String = sqlx::query_scalar(
            "SELECT mailbox_id FROM user_mailboxes WHERE user_id = 1 AND role = 'inbox'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(mailbox_id, mailbox_id_for_user(1, "inbox"));
        assert_eq!(mailbox_id, "XHEK6XD6CFURMHQFSXIALKNX6A");
    }

    #[tokio::test]
    async fn provision_inbox_sort_order_is_1() {
        let (pool, _tmp) = make_pool().await;
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x')")
            .execute(&pool)
            .await
            .unwrap();
        provision_user_mailboxes(&pool, 1).await.unwrap();

        let sort_order: i64 = sqlx::query_scalar(
            "SELECT sort_order FROM user_mailboxes WHERE user_id = 1 AND role = 'inbox'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sort_order, 1);
    }

    #[tokio::test]
    async fn provision_two_users_independent() {
        let (pool, _tmp) = make_pool().await;
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (1, 'alice', 'x'), (2, 'bob', 'x')")
            .execute(&pool)
            .await
            .unwrap();
        provision_user_mailboxes(&pool, 1).await.unwrap();
        provision_user_mailboxes(&pool, 2).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_mailboxes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 12);

        let inbox1: String = sqlx::query_scalar(
            "SELECT mailbox_id FROM user_mailboxes WHERE user_id = 1 AND role = 'inbox'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let inbox2: String = sqlx::query_scalar(
            "SELECT mailbox_id FROM user_mailboxes WHERE user_id = 2 AND role = 'inbox'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_ne!(inbox1, inbox2);
    }
}
