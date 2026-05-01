//! CAR file export: fetch article blocks from IPFS and write as CARv1.

use cid::Cid;
use sqlx::{AnyPool, Row};
use std::str::FromStr as _;
use tracing::warn;

use crate::car_writer;
use crate::peering::pipeline::IpfsStore;

/// Fetch up to `limit` articles for `group` from the DB, retrieve their raw
/// IPFS blocks, and return a CARv1-encoded archive.
///
/// Articles are selected newest-first (`ORDER BY ingested_at_ms DESC`).
/// The most-recent article CID whose block is found becomes the single root.
/// CIDs whose blocks are missing or whose IPFS fetch errors out are skipped
/// with a `warn!` log and do not abort the export.
///
/// Returns an empty-roots CAR (`{"version":1,"roots":[]}` + zero blocks)
/// when no blocks are found.
pub async fn build_export_car(
    pool: &AnyPool,
    ipfs: &(impl IpfsStore + ?Sized),
    group: &str,
    limit: i64,
) -> Result<Vec<u8>, String> {
    let rows = sqlx::query(
        "SELECT cid FROM articles \
         WHERE group_name = ? \
         ORDER BY ingested_at_ms DESC \
         LIMIT ?",
    )
    .bind(group)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("DB error querying articles: {e}"))?;

    let mut roots: Vec<Cid> = Vec::new();
    let mut blocks: Vec<(Cid, Vec<u8>)> = Vec::new();

    for row in rows {
        let cid_str: String = row.get("cid");
        let cid = match Cid::from_str(&cid_str) {
            Ok(c) => c,
            Err(e) => {
                warn!(cid = %cid_str, "export_car: invalid CID in articles table: {e}");
                continue;
            }
        };

        match ipfs.get_raw(&cid).await {
            Ok(Some(data)) => {
                // Articles are exported newest-first so recent content appears
                // early in the CAR stream.  The single CAR root is the
                // most-recently-ingested article whose block is available in
                // IPFS.  This is a v1 simplification — a future version may
                // use an explicit manifest CID as root.
                if roots.is_empty() {
                    roots.push(cid);
                }
                blocks.push((cid, data));
            }
            Ok(None) => {
                warn!(cid = %cid_str, "export_car: block not in IPFS, skipping");
            }
            Err(e) => {
                warn!(cid = %cid_str, "export_car: IPFS fetch error: {e}, skipping");
            }
        }
    }

    Ok(car_writer::build_car(&roots, &blocks))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peering::pipeline::MemIpfsStore;
    use sqlx::AnyPool;

    async fn make_pool() -> (AnyPool, tempfile::TempPath) {
        let tmp = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let url = format!("sqlite://{}", tmp.to_str().unwrap());
        crate::migrations::run_migrations(&url).await.unwrap();
        let pool = stoa_core::db_pool::try_open_any_pool(&url, 1)
            .await
            .unwrap();
        (pool, tmp)
    }

    fn make_cid_for(data: &[u8]) -> Cid {
        use multihash_codetable::{Code, MultihashDigest};
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x55, digest)
    }

    async fn insert_article(pool: &AnyPool, cid: &Cid, group: &str, ingested_at_ms: i64) {
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(cid.to_string())
        .bind(group)
        .bind(ingested_at_ms)
        .bind(0i64)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Empty table returns a valid CAR with no blocks and empty roots.
    ///
    /// Oracle: the CARv1 wire format for an empty-roots header is a known
    /// fixed byte sequence (verified in car_writer tests).
    #[tokio::test]
    async fn no_articles_returns_empty_car() {
        let (pool, _tmp) = make_pool().await;
        let ipfs = MemIpfsStore::new();
        let car = build_export_car(&pool, &ipfs, "comp.test", 100)
            .await
            .unwrap();
        // CARv1 with zero roots and zero blocks: only the header.
        assert!(
            !car.is_empty(),
            "CAR must not be empty (header always present)"
        );
        // Decode varint at start to find header length, confirm no trailing bytes.
        let mut header_len: u64 = 0;
        let mut shift = 0u32;
        let mut header_varint_bytes = 0usize;
        for &byte in &car {
            header_len |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            header_varint_bytes += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        assert_eq!(
            car.len(),
            header_varint_bytes + header_len as usize,
            "empty-group CAR must contain only the header (no block frames)"
        );
    }

    /// One article inserted and its block stored in IPFS → exported in CAR.
    ///
    /// Oracle: CARv1 block frame layout verified via field-by-field parsing
    /// (see car_writer tests for frame structure).
    #[tokio::test]
    async fn single_article_exported() {
        let (pool, _tmp) = make_pool().await;
        let ipfs = MemIpfsStore::new();

        let data = b"article block data";
        let cid = ipfs.put_raw(data).await.unwrap();
        insert_article(&pool, &cid, "comp.test", 1_000).await;

        let car = build_export_car(&pool, &ipfs, "comp.test", 100)
            .await
            .unwrap();

        // Skip header varint + header bytes.
        let mut header_len: u64 = 0;
        let mut shift = 0u32;
        let mut hv = 0usize;
        for &byte in &car {
            header_len |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            hv += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let block_start = hv + header_len as usize;
        assert!(
            block_start < car.len(),
            "CAR must contain at least one block frame"
        );

        // Decode frame varint.
        let mut frame_len: u64 = 0;
        let mut shift2 = 0u32;
        let mut fv = 0usize;
        for &byte in &car[block_start..] {
            frame_len |= ((byte & 0x7f) as u64) << shift2;
            shift2 += 7;
            fv += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let cid_bytes = cid.to_bytes();
        assert_eq!(
            frame_len as usize,
            cid_bytes.len() + data.len(),
            "block frame length must equal cid_len + data_len"
        );
        let payload = &car[block_start + fv..];
        assert_eq!(
            &payload[..cid_bytes.len()],
            cid_bytes.as_slice(),
            "CID bytes must be first in block payload"
        );
        assert_eq!(
            &payload[cid_bytes.len()..cid_bytes.len() + data.len()],
            data,
            "block data must follow CID bytes"
        );
    }

    /// Articles from a different group are excluded from the export.
    #[tokio::test]
    async fn cross_group_isolation() {
        let (pool, _tmp) = make_pool().await;
        let ipfs = MemIpfsStore::new();

        let d1 = b"comp article";
        let d2 = b"alt article";
        let c1 = ipfs.put_raw(d1).await.unwrap();
        let c2 = ipfs.put_raw(d2).await.unwrap();
        insert_article(&pool, &c1, "comp.test", 1_000).await;
        insert_article(&pool, &c2, "alt.test", 2_000).await;

        let car = build_export_car(&pool, &ipfs, "comp.test", 100)
            .await
            .unwrap();

        // Only one block frame should be present.
        let mut hlen: u64 = 0;
        let mut shift = 0u32;
        let mut hv = 0usize;
        for &byte in &car {
            hlen |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            hv += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let block_start = hv + hlen as usize;
        let blocks_bytes = &car[block_start..];

        // Consume exactly one block frame.
        let mut flen: u64 = 0;
        let mut shift2 = 0u32;
        let mut fv = 0usize;
        for &byte in blocks_bytes {
            flen |= ((byte & 0x7f) as u64) << shift2;
            shift2 += 7;
            fv += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        assert_eq!(
            fv + flen as usize,
            blocks_bytes.len(),
            "only one block (comp.test article) must appear in the CAR"
        );
    }

    /// Missing IPFS block is skipped without aborting the export.
    #[tokio::test]
    async fn missing_block_skipped_gracefully() {
        let (pool, _tmp) = make_pool().await;
        let ipfs = MemIpfsStore::new();

        // Insert a CID into the articles table but do NOT store the block in IPFS.
        let phantom_cid = make_cid_for(b"ghost data");
        insert_article(&pool, &phantom_cid, "comp.test", 1_000).await;

        // Store a real block for a second article.
        let real_data = b"real article data";
        let real_cid = ipfs.put_raw(real_data).await.unwrap();
        insert_article(&pool, &real_cid, "comp.test", 2_000).await;

        let car = build_export_car(&pool, &ipfs, "comp.test", 100)
            .await
            .unwrap();

        // CAR must be non-empty (one real block) and must not error.
        assert!(!car.is_empty());
        let mut hlen: u64 = 0;
        let mut shift = 0u32;
        let mut hv = 0usize;
        for &byte in &car {
            hlen |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            hv += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        assert!(
            car.len() > hv + hlen as usize,
            "CAR must contain the real block even after skipping the missing one"
        );
    }

    /// `limit` parameter caps the number of articles returned.
    #[tokio::test]
    async fn limit_caps_block_count() {
        let (pool, _tmp) = make_pool().await;
        let ipfs = MemIpfsStore::new();

        for i in 0..5i64 {
            let data = format!("article {i}");
            let cid = ipfs.put_raw(data.as_bytes()).await.unwrap();
            insert_article(&pool, &cid, "comp.test", i * 1000).await;
        }

        let car2 = build_export_car(&pool, &ipfs, "comp.test", 2)
            .await
            .unwrap();
        let car5 = build_export_car(&pool, &ipfs, "comp.test", 5)
            .await
            .unwrap();

        // The 2-article CAR must be strictly smaller than the 5-article CAR.
        assert!(
            car2.len() < car5.len(),
            "limit=2 CAR ({} bytes) must be smaller than limit=5 CAR ({} bytes)",
            car2.len(),
            car5.len()
        );
    }
}
