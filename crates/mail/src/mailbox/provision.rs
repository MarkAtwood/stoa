use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use sqlx::AnyPool;

use crate::mailbox::types::SpecialMailbox;

/// Derive a stable mailbox ID from a role name.
///
/// Algorithm: SHA-256(role as UTF-8) → first 16 bytes → BASE32_NOPAD.
/// Result is always 26 characters.
///
/// Oracle: Python `hashlib.sha256(role.encode()).digest()[:16]`
///         then `base64.b32encode(h).decode().rstrip('=')`
pub fn mailbox_id_for_role(role: &str) -> String {
    let digest = Sha256::digest(role.as_bytes());
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

/// Create the six RFC 6154 special-use mailboxes if they don't exist.
/// Idempotent: INSERT OR IGNORE, re-running is a no-op.
/// All six rows are written in a single batched statement.
///
/// This is a single-user server: all mailboxes are provisioned globally at
/// startup, not per-user. The mailbox_id scheme uses SHA-256(role) rather
/// than SHA-256(user_id||role).
pub async fn provision_mailboxes(pool: &AnyPool) -> Result<(), sqlx::Error> {
    let mut qb: sqlx::QueryBuilder<sqlx::Any> = sqlx::QueryBuilder::new(
        "INSERT OR IGNORE INTO mailboxes (mailbox_id, role, name, sort_order) ",
    );
    qb.push_values(
        SPECIAL_FOLDERS.iter(),
        |mut b, &(role, name, sort_order)| {
            b.push_bind(mailbox_id_for_role(role))
                .push_bind(role)
                .push_bind(name)
                .push_bind(sort_order as i64);
        },
    );
    qb.build().execute(pool).await?;
    Ok(())
}

/// Return the provisioned special-use mailboxes, ordered by sort_order.
///
/// Returns an empty vec (never an error) when no rows exist yet; callers
/// should call `provision_mailboxes` first if they need the folders created.
pub async fn list_mailboxes(pool: &AnyPool) -> Result<Vec<SpecialMailbox>, sqlx::Error> {
    let rows: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT mailbox_id, role, name, sort_order FROM mailboxes ORDER BY sort_order ASC",
    )
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

#[cfg(test)]
mod tests {
    use super::{mailbox_id_for_role, provision_mailboxes};
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

    // ── mailbox_id_for_role ────────────────────────────────────────────────────
    // Oracle: Python
    //   import hashlib, base64
    //   def mid(role):
    //       h = hashlib.sha256(role.encode()).digest()[:16]
    //       return base64.b32encode(h).decode().rstrip('=')

    #[test]
    fn mailbox_id_inbox() {
        assert_eq!(mailbox_id_for_role("inbox"), "ZKW3Z77MSA4BCKSWIL6BLZNKM4");
    }

    #[test]
    fn mailbox_id_sent() {
        assert_eq!(mailbox_id_for_role("sent"), "PL53GND7W4SS4UZ5LDMZ24WZCA");
    }

    #[test]
    fn mailbox_id_is_26_chars() {
        for role in &["inbox", "sent", "drafts", "trash", "junk", "archive"] {
            let id = mailbox_id_for_role(role);
            assert_eq!(id.len(), 26, "role={role} id={id}");
        }
    }

    #[test]
    fn mailbox_id_different_roles_differ() {
        assert_ne!(mailbox_id_for_role("inbox"), mailbox_id_for_role("sent"));
    }

    // ── provision_mailboxes ────────────────────────────────────────────────────

    #[tokio::test]
    async fn provision_creates_six_folders() {
        let (pool, _tmp) = make_pool().await;
        provision_mailboxes(&pool).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailboxes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 6);
    }

    #[tokio::test]
    async fn provision_is_idempotent() {
        let (pool, _tmp) = make_pool().await;
        provision_mailboxes(&pool).await.unwrap();
        provision_mailboxes(&pool).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailboxes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 6);
    }

    #[tokio::test]
    async fn provision_inbox_has_correct_id() {
        let (pool, _tmp) = make_pool().await;
        provision_mailboxes(&pool).await.unwrap();

        let mailbox_id: String =
            sqlx::query_scalar("SELECT mailbox_id FROM mailboxes WHERE role = 'inbox'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(mailbox_id, mailbox_id_for_role("inbox"));
        assert_eq!(mailbox_id, "ZKW3Z77MSA4BCKSWIL6BLZNKM4");
    }

    #[tokio::test]
    async fn provision_inbox_sort_order_is_1() {
        let (pool, _tmp) = make_pool().await;
        provision_mailboxes(&pool).await.unwrap();

        let sort_order: i64 =
            sqlx::query_scalar("SELECT sort_order FROM mailboxes WHERE role = 'inbox'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sort_order, 1);
    }
}
