/// Manages JMAP opaque state strings per scope (e.g. "Mailbox", "Email").
///
/// State strings are monotonically increasing version numbers encoded as decimal strings.
pub struct StateStore {
    pool: sqlx::AnyPool,
}

impl StateStore {
    pub fn new(pool: sqlx::AnyPool) -> Self {
        Self { pool }
    }

    /// Return the current state string for a scope.
    /// Returns "0" if the scope has never been written.
    pub async fn get_state(&self, scope: &str) -> Result<String, sqlx::Error> {
        let version: Option<i64> =
            sqlx::query_scalar("SELECT version FROM state_version WHERE scope = ?")
                .bind(scope)
                .fetch_optional(&self.pool)
                .await?;
        Ok(version.unwrap_or(0).to_string())
    }

    /// Increment the version for a scope and return the new state string.
    pub async fn bump_state(&self, scope: &str) -> Result<String, sqlx::Error> {
        sqlx::query(
            "INSERT INTO state_version (scope, version) VALUES (?, 1)
             ON CONFLICT(scope) DO UPDATE SET version = version + 1",
        )
        .bind(scope)
        .execute(&self.pool)
        .await?;
        self.get_state(scope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> (StateStore, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url)
            .await
            .expect("migrations");
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .expect("pool");
        (StateStore::new(pool), tmp)
    }

    #[tokio::test]
    async fn initial_state_is_zero() {
        let (store, _tmp) = make_store().await;
        let state = store.get_state("Mailbox").await.unwrap();
        assert_eq!(state, "0");
    }

    #[tokio::test]
    async fn bump_increments_state() {
        let (store, _tmp) = make_store().await;
        let s1 = store.bump_state("Email").await.unwrap();
        let s2 = store.bump_state("Email").await.unwrap();
        assert_ne!(s1, s2, "state must change after bump");
        assert!(!s1.is_empty());
        assert!(!s2.is_empty());
    }

    #[tokio::test]
    async fn different_scopes_are_independent() {
        let (store, _tmp) = make_store().await;
        store.bump_state("Mailbox").await.unwrap();
        let email_state = store.get_state("Email").await.unwrap();
        assert_eq!(email_state, "0", "Email scope must be independent");
    }
}
