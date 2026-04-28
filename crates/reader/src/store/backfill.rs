//! Startup backfill: populate the overview index from the article_numbers
//! store and IPFS for articles that were not directly POSTed through this
//! reader (e.g. articles received via transit propagation).

use tracing::warn;

use crate::post::ipfs_write::IpfsBlockStore;
use crate::store::{
    article_numbers::ArticleNumberStore,
    overview::{extract_overview, OverviewStore},
};

/// Populate the overview index for any `(group, article_number)` pair that
/// exists in `article_numbers` but is absent from `overview_store`.
///
/// For each missing pair, the article bytes are fetched from `ipfs_store`,
/// the 7 RFC 3977 overview fields are extracted, and the record is inserted.
///
/// Failures to fetch or extract are logged as warnings; the function
/// continues processing remaining articles and returns the count that were
/// successfully backfilled.
pub async fn backfill_overview(
    article_numbers: &ArticleNumberStore,
    overview_store: &OverviewStore,
    ipfs_store: &dyn IpfsBlockStore,
) -> usize {
    let all_articles = match article_numbers.list_all_articles().await {
        Ok(v) => v,
        Err(e) => {
            warn!("backfill_overview: failed to list articles: {e}");
            return 0;
        }
    };

    let mut count = 0usize;

    for (group, article_number, cid) in &all_articles {
        // Check if overview already has this record.
        let existing = overview_store
            .query_range(group, *article_number, *article_number)
            .await;
        match existing {
            Ok(rows) if !rows.is_empty() => continue,
            Err(e) => {
                warn!("backfill_overview: query_range failed for {group}/{article_number}: {e}");
                continue;
            }
            Ok(_) => {} // empty — needs backfill
        }

        // Fetch raw article bytes from IPFS.
        let raw_bytes = match ipfs_store.get_raw(cid).await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "backfill_overview: IPFS fetch failed for {group}/{article_number} cid={cid}: {e}"
                );
                continue;
            }
        };

        // Split headers from body and extract overview fields.
        let (header_bytes, body_bytes) = split_at_blank_line(&raw_bytes);
        let mut record = extract_overview(&header_bytes, &body_bytes);
        record.article_number = *article_number;

        if let Err(e) = overview_store.insert(group, &record).await {
            warn!("backfill_overview: insert failed for {group}/{article_number}: {e}");
            continue;
        }

        count += 1;
    }

    count
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
