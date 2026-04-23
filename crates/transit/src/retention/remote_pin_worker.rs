//! Background worker: submit and poll remote pinning jobs.
//!
//! The worker runs a periodic sweep:
//! 1. Submit `pending` jobs to their external pinning service.
//! 2. Poll `queued` and `pinning` jobs for status updates.
//! 3. Mark jobs as `pinned` or `failed` based on service responses.

use sqlx::{Row, SqlitePool};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use super::remote_pin_client::{PinningApiKey, RemotePinClient, RemotePinError, RemotePinStatus};

/// Configuration for one service slot in the worker.
pub struct ServiceSlot {
    pub name: String,
    pub client: RemotePinClient,
    pub max_attempts: u32,
}

/// Background worker that submits and polls remote pinning jobs.
pub struct RemotePinWorker {
    pool: SqlitePool,
    services: Vec<ServiceSlot>,
    poll_interval: Duration,
}

impl RemotePinWorker {
    pub fn new(pool: SqlitePool, services: Vec<ServiceSlot>, poll_interval: Duration) -> Self {
        Self {
            pool,
            services,
            poll_interval,
        }
    }

    /// Build a worker from config entries.
    pub fn from_config(
        pool: SqlitePool,
        cfgs: &[crate::config::ExternalPinServiceConfig],
    ) -> Result<Self, RemotePinError> {
        let mut services = Vec::with_capacity(cfgs.len());
        for cfg in cfgs {
            let api_key = PinningApiKey(cfg.api_key.0.clone());
            let client = RemotePinClient::new(
                &cfg.endpoint,
                api_key,
                cfg.connect_timeout_secs,
                cfg.request_timeout_secs,
            )?;
            services.push(ServiceSlot {
                name: cfg.name.clone(),
                client,
                max_attempts: cfg.max_attempts,
            });
        }
        Ok(Self {
            pool,
            services,
            poll_interval: Duration::from_secs(30),
        })
    }

    /// Run the worker loop forever (meant to be spawned as a tokio task).
    pub async fn run(self) {
        loop {
            for slot in &self.services {
                self.sweep(slot).await;
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// One sweep for a single service: submit pending, then poll in-flight.
    async fn sweep(&self, slot: &ServiceSlot) {
        self.submit_pending(slot).await;
        self.poll_inflight(slot).await;
    }

    /// Submit all `pending` jobs for this service (up to 20 per sweep).
    async fn submit_pending(&self, slot: &ServiceSlot) {
        let max_att = slot.max_attempts as i64;
        let rows = sqlx::query(
            "SELECT id, cid FROM remote_pin_jobs \
             WHERE service_name = ?1 AND status = 'pending' AND attempt_count < ?2 \
             LIMIT 20",
        )
        .bind(&slot.name)
        .bind(max_att)
        .fetch_all(&self.pool)
        .await;

        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                warn!(service = %slot.name, "remote_pin_worker: DB error fetching pending: {e}");
                return;
            }
        };

        let now_ms = now_ms();
        for row in rows {
            let id: i64 = row.get("id");
            let cid: String = row.get("cid");
            let name_label = format!("usenet-ipfs:{cid}");

            match slot.client.submit(&cid, &name_label).await {
                Ok(resp) => {
                    let request_id = resp.requestid.clone();
                    let new_status = resp.status.to_string();
                    if let Err(e) = sqlx::query(
                        "UPDATE remote_pin_jobs \
                         SET status = ?1, request_id = ?2, submitted_at_ms = ?3, \
                             last_attempt_ms = ?3, attempt_count = attempt_count + 1, error = NULL \
                         WHERE id = ?4",
                    )
                    .bind(&new_status)
                    .bind(&request_id)
                    .bind(now_ms)
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    {
                        warn!(service = %slot.name, cid, "remote_pin_worker: DB update error after submit: {e}");
                    } else {
                        debug!(service = %slot.name, cid, request_id, status = %new_status, "remote pin submitted");
                    }
                }
                Err(RemotePinError::RateLimited { retry_after_secs }) => {
                    warn!(service = %slot.name, cid, retry_after_secs,
                          "remote pin rate-limited; will retry later");
                }
                Err(e) => {
                    let err_str = e.to_string();
                    let is_fatal = matches!(e, RemotePinError::Unauthorized);
                    let is_fatal_i = if is_fatal { 1i64 } else { 0i64 };
                    let _ = sqlx::query(
                        "UPDATE remote_pin_jobs \
                         SET attempt_count = attempt_count + 1, \
                             last_attempt_ms = ?1, \
                             error = ?2, \
                             status = CASE \
                               WHEN attempt_count + 1 >= ?3 OR ?4 THEN 'failed' \
                               ELSE status \
                             END \
                         WHERE id = ?5",
                    )
                    .bind(now_ms)
                    .bind(&err_str)
                    .bind(max_att)
                    .bind(is_fatal_i)
                    .bind(id)
                    .execute(&self.pool)
                    .await;
                    warn!(service = %slot.name, cid, "remote pin submit error: {e}");
                }
            }
        }
    }

    /// Poll all `queued` and `pinning` jobs for this service (up to 50 per sweep).
    async fn poll_inflight(&self, slot: &ServiceSlot) {
        let rows = sqlx::query(
            "SELECT id, cid, request_id FROM remote_pin_jobs \
             WHERE service_name = ?1 AND (status = 'queued' OR status = 'pinning') \
             LIMIT 50",
        )
        .bind(&slot.name)
        .fetch_all(&self.pool)
        .await;

        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                warn!(service = %slot.name, "remote_pin_worker: DB error fetching inflight: {e}");
                return;
            }
        };

        let now_ms = now_ms();
        for row in rows {
            let id: i64 = row.get("id");
            let cid: String = row.get("cid");
            let request_id: Option<String> = row.get("request_id");
            let request_id = match request_id {
                Some(r) => r,
                None => {
                    warn!(service = %slot.name, cid, "remote_pin_worker: inflight job missing request_id");
                    continue;
                }
            };

            match slot.client.check(&request_id).await {
                Ok(resp) => {
                    let new_status = match resp.status {
                        RemotePinStatus::Pinned => "pinned",
                        RemotePinStatus::Failed => "failed",
                        RemotePinStatus::Queued => "queued",
                        RemotePinStatus::Pinning => "pinning",
                    };
                    if let Err(e) = sqlx::query(
                        "UPDATE remote_pin_jobs SET status = ?1, last_attempt_ms = ?2 WHERE id = ?3",
                    )
                    .bind(new_status)
                    .bind(now_ms)
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    {
                        warn!(service = %slot.name, cid, "remote_pin_worker: DB update error after poll: {e}");
                    } else {
                        debug!(service = %slot.name, cid, request_id, status = new_status, "remote pin polled");
                    }
                }
                Err(RemotePinError::Http { status: 404, .. }) => {
                    // Service lost the request; reset to pending for re-submission.
                    let _ = sqlx::query(
                        "UPDATE remote_pin_jobs SET status = 'pending', request_id = NULL WHERE id = ?1",
                    )
                    .bind(id)
                    .execute(&self.pool)
                    .await;
                    warn!(service = %slot.name, cid, request_id,
                          "remote pin request_id 404; resetting to pending");
                }
                Err(e) => {
                    warn!(service = %slot.name, cid, request_id, "remote pin poll error: {e}");
                }
            }
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
