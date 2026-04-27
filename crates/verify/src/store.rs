//! SQLite-backed store for article verification results and seen signing keys.

use cid::Cid;
use sqlx::SqlitePool;

use crate::types::{ArticleVerification, SigType, VerifResult};

/// Stores and retrieves verification results from SQLite.
pub struct VerificationStore {
    pool: SqlitePool,
}

impl VerificationStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Persist a list of verification results for an article CID.
    ///
    /// Existing rows for the same `(cid, sig_type, identity)` are replaced.
    pub async fn record_verifications(
        &self,
        cid: &Cid,
        verifications: &[ArticleVerification],
        verified_at_ms: i64,
    ) -> Result<(), sqlx::Error> {
        let cid_bytes = cid.to_bytes();
        for v in verifications {
            let sig_type = v.sig_type.as_str();
            let result_str = v.result.as_str();
            // For DnsError, encode both domain and err separated by NUL so
            // the domain survives the round-trip.  Domain names never contain
            // NUL, so this is unambiguous.  Other variants use reason() as-is.
            let dns_reason_buf: String;
            let reason: Option<&str> = match &v.result {
                crate::types::VerifResult::DnsError { domain, err } => {
                    dns_reason_buf = format!("{domain}\x00{err}");
                    Some(&dns_reason_buf)
                }
                r => r.reason(),
            };
            let identity = v.identity.as_deref();
            sqlx::query(
                "INSERT OR REPLACE INTO article_verifications \
                 (cid, sig_type, result, identity, reason, verified_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&cid_bytes)
            .bind(sig_type)
            .bind(result_str)
            .bind(identity.unwrap_or(""))
            .bind(reason)
            .bind(verified_at_ms)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Retrieve all verification results for an article CID.
    ///
    /// Returns an empty vec when no results have been recorded yet.
    pub async fn get_verifications(
        &self,
        cid: &Cid,
    ) -> Result<Vec<ArticleVerification>, sqlx::Error> {
        let cid_bytes = cid.to_bytes();
        let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT sig_type, result, identity, reason \
             FROM article_verifications \
             WHERE cid = ?",
        )
        .bind(&cid_bytes)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(sig_type_str, result_str, identity, reason)| {
                let sig_type = parse_sig_type(&sig_type_str)?;
                let result = parse_result(&result_str, reason.as_deref(), &sig_type);
                // Empty string means identity was unknown at verification time.
                let identity = if identity.is_empty() {
                    None
                } else {
                    Some(identity)
                };
                Some(ArticleVerification {
                    sig_type,
                    result,
                    identity,
                })
            })
            .collect())
    }

    /// Record a seen Ed25519 public key.
    ///
    /// `key_data` is the 32 raw bytes of the verifying key.
    /// `key_id` is the lowercase hex SHA-256 of `key_data`.
    /// Only inserts the first time; ignores duplicate key_ids.
    pub async fn upsert_seen_ed25519_key(
        &self,
        key_id: &str,
        key_data: &[u8; 32],
        first_seen_cid: &Cid,
        first_seen_at_ms: i64,
    ) -> Result<(), sqlx::Error> {
        let cid_bytes = first_seen_cid.to_bytes();
        sqlx::query(
            "INSERT OR IGNORE INTO seen_keys \
             (key_type, key_id, key_data, first_seen_cid, first_seen_at) \
             VALUES ('ed25519', ?, ?, ?, ?)",
        )
        .bind(key_id)
        .bind(key_data.as_slice())
        .bind(&cid_bytes)
        .bind(first_seen_at_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn parse_sig_type(s: &str) -> Option<SigType> {
    match s {
        "dkim" => Some(SigType::Dkim),
        "x-stoa-sig" => Some(SigType::XUsenetIpfsSig),
        other => {
            tracing::warn!(
                sig_type = other,
                "unrecognised sig_type in article_verifications; skipping row"
            );
            None
        }
    }
}

fn parse_result(result: &str, reason: Option<&str>, _sig_type: &SigType) -> VerifResult {
    match result {
        "pass" => VerifResult::Pass,
        "fail" => VerifResult::Fail {
            reason: reason.unwrap_or("unknown").to_owned(),
        },
        "dns-error" => {
            // reason was stored as "domain\x00err" (NUL-separated).
            // Older rows may lack NUL; treat the whole string as err in that case.
            let raw = reason.unwrap_or("");
            let (domain, err) = match raw.split_once('\x00') {
                Some((d, e)) => (d.to_owned(), e.to_owned()),
                None => (String::new(), raw.to_owned()),
            };
            VerifResult::DnsError { domain, err }
        }
        "no-key" => VerifResult::NoKey,
        _ => VerifResult::ParseError {
            reason: reason.unwrap_or("unknown").to_owned(),
        },
    }
}
