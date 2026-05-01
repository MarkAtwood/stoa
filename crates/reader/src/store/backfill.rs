//! Startup backfill: populate the overview index from the article_numbers
//! store and IPFS for articles that were not directly POSTed through this
//! reader (e.g. articles received via transit propagation).

use std::collections::HashSet;

use cid::Cid;
use tracing::warn;

use crate::post::ipfs_write::IpfsBlockStore;
use crate::store::{
    article_numbers::ArticleNumberStore,
    overview::{extract_overview, OverviewStore},
};

/// Batch size for the backfill loop.  Each iteration issues one SQL query and
/// up to `BATCH_SIZE` IPFS fetches.  Larger values reduce DB round-trips but
/// increase peak memory during the backfill pass.
const BATCH_SIZE: i64 = 500;

/// Populate the overview index for any `(group, article_number)` pair that
/// exists in `article_numbers` but is absent from `overview_store`.
///
/// Uses a LEFT JOIN to find missing records without loading all articles into
/// memory and without a per-article overview query (fixes stoa-c4zlv.70 and
/// stoa-c4zlv.67).  Both tables live in the same SQLite database (reader_pool).
///
/// Articles that repeatedly fail IPFS fetch are skipped after the first
/// failure to prevent an infinite loop.  Failures are logged as warnings.
/// Returns the count of successfully backfilled records.
pub async fn backfill_overview(
    article_numbers: &ArticleNumberStore,
    overview_store: &OverviewStore,
    ipfs_store: &dyn IpfsBlockStore,
) -> usize {
    let pool = article_numbers.pool();
    // Track permanently-failed (group, article_number) pairs so we don't
    // loop forever if IPFS can't serve a block.
    let mut failed: HashSet<(String, i64)> = HashSet::new();
    let mut total_backfilled = 0usize;

    loop {
        #[derive(sqlx::FromRow)]
        struct Row {
            group_name: String,
            article_number: i64,
            cid: Vec<u8>,
        }

        // One query finds the next batch of articles missing from overview.
        // As records are inserted, they no longer appear here, so OFFSET=0
        // always returns the next unprocessed batch.
        let batch: Vec<Row> = match sqlx::query_as(
            "SELECT an.group_name, an.article_number, an.cid \
             FROM article_numbers an \
             LEFT JOIN overview o \
                 ON o.group_name = an.group_name \
                 AND o.article_number = an.article_number \
             WHERE o.article_number IS NULL \
             ORDER BY an.group_name, an.article_number \
             LIMIT ?",
        )
        .bind(BATCH_SIZE)
        .fetch_all(pool)
        .await
        {
            Ok(b) => b,
            Err(e) => {
                warn!("backfill_overview: failed to query missing articles: {e}");
                break;
            }
        };

        if batch.is_empty() {
            break;
        }

        let mut progress = false;
        for row in &batch {
            let key = (row.group_name.clone(), row.article_number);
            if failed.contains(&key) {
                continue;
            }

            let cid = match Cid::try_from(row.cid.as_slice()) {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        "backfill_overview: invalid CID bytes for {}/{}: {e}",
                        row.group_name, row.article_number
                    );
                    failed.insert(key);
                    continue;
                }
            };

            let raw_bytes = match ipfs_store.get_raw(&cid).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        "backfill_overview: IPFS fetch failed for {}/{} cid={cid}: {e}",
                        row.group_name, row.article_number
                    );
                    failed.insert(key);
                    continue;
                }
            };

            let (header_bytes, body_bytes) = split_at_blank_line(&raw_bytes);
            let mut record = extract_overview(&header_bytes, &body_bytes);
            record.article_number = row.article_number as u64;

            if let Err(e) = overview_store.insert(&row.group_name, &record).await {
                warn!(
                    "backfill_overview: insert failed for {}/{}: {e}",
                    row.group_name, row.article_number
                );
                failed.insert(key);
                continue;
            }

            total_backfilled += 1;
            progress = true;
        }

        // If no progress was made (all articles in this batch have already
        // failed), there is nothing left we can do.
        if !progress {
            break;
        }
    }

    total_backfilled
}

/// Split raw article bytes at the blank-line separator.
///
fn split_at_blank_line(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (h, b) = crate::post::split_header_body(bytes);
    (h.to_vec(), b.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post::ipfs_write::MemIpfsStore;
    use crate::store::server_stores::ServerStores;

    fn test_article(subject: &str, msgid: &str) -> Vec<u8> {
        format!(
            "Newsgroups: comp.test\r\n\
             From: tester@example.com\r\n\
             Subject: {subject}\r\n\
             Date: Mon, 20 Apr 2026 12:00:00 +0000\r\n\
             Message-ID: {msgid}\r\n\
             \r\n\
             Article body.\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn backfill_inserts_missing_overview_records() {
        let stores = ServerStores::new_mem().await;
        let ipfs = MemIpfsStore::new();

        // Put an article in IPFS and assign an article number — bypass the POST
        // pipeline to simulate transit-propagated articles.
        let article = test_article("Backfill Subject", "<backfill-test@example>");
        let cid = ipfs.put_raw(&article).await.unwrap();
        stores
            .article_numbers
            .assign_number("comp.test", &cid)
            .await
            .unwrap();

        // Overview is empty before backfill.
        let before = stores
            .overview_store
            .query_range("comp.test", 1, 1)
            .await
            .unwrap();
        assert_eq!(before.len(), 0, "overview must be empty before backfill");

        let filled =
            backfill_overview(&stores.article_numbers, &stores.overview_store, &ipfs).await;
        assert_eq!(filled, 1, "one record must be backfilled");

        let after = stores
            .overview_store
            .query_range("comp.test", 1, 1)
            .await
            .unwrap();
        assert_eq!(
            after.len(),
            1,
            "overview must have one record after backfill"
        );
        assert_eq!(after[0].subject, "Backfill Subject");
    }

    #[tokio::test]
    async fn backfill_skips_already_present_records() {
        let stores = ServerStores::new_mem().await;
        let ipfs = MemIpfsStore::new();

        let article = test_article("Already Present", "<already@example>");
        let cid = ipfs.put_raw(&article).await.unwrap();
        stores
            .article_numbers
            .assign_number("comp.test", &cid)
            .await
            .unwrap();

        // First backfill: inserts.
        let count1 =
            backfill_overview(&stores.article_numbers, &stores.overview_store, &ipfs).await;
        assert_eq!(count1, 1);

        // Second backfill: must skip (record already present).
        let count2 =
            backfill_overview(&stores.article_numbers, &stores.overview_store, &ipfs).await;
        assert_eq!(count2, 0, "second backfill must insert 0 (already present)");
    }
}
