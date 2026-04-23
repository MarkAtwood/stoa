//! Integration test: DB + MemIpfsStore → build_export_car → CARv1 bytes.
//!
//! Seeds articles into both the `articles` table and a MemIpfsStore, then
//! calls `build_export_car` and hand-parses the resulting CARv1 bytes to verify:
//!
//!   - The header varint decodes to the correct header byte count.
//!   - The CBOR header contains `"version"` = 1 (spot-checked via byte scan).
//!   - Every seeded block appears in the CAR with the correct CID and data.
//!   - The root is the most-recently-ingested article CID (ORDER BY DESC first).
//!   - Articles from other groups are excluded.
//!
//! Oracles:
//!   - CARv1 block frame format: varint(cid_len+data_len) || CID-bytes || data
//!     (independent reference: <https://ipld.io/specs/transport/car/carv1/>)
//!   - LEB128 varint decoding is the independent inverse of `car_writer::write_varint`
//!     (no round-trip through the same encoder function)

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::sync::atomic::{AtomicUsize, Ordering};
use usenet_ipfs_transit::{
    export::build_export_car,
    peering::pipeline::{IpfsStore as _, MemIpfsStore},
};

static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

async fn make_pool() -> sqlx::SqlitePool {
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let url = format!("file:car_export_integ_{n}?mode=memory&cache=shared");
    let opts = SqliteConnectOptions::new()
        .filename(&url)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    usenet_ipfs_transit::migrations::run_migrations(&pool)
        .await
        .unwrap();
    pool
}

/// Decode one LEB128 varint from the start of `buf`.
/// Returns `(value, bytes_consumed)`.
fn decode_varint(buf: &[u8]) -> (u64, usize) {
    let mut n: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        n |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return (n, i + 1);
        }
        assert!(shift < 64, "varint overflow");
    }
    panic!("unterminated varint");
}

/// Parse all block frames from the CAR body (after the header).
///
/// Returns a `Vec<(cid_bytes, data_bytes)>` in order of appearance.
fn parse_blocks(body: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut blocks = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let (frame_len, vlen) = decode_varint(&body[pos..]);
        pos += vlen;
        let frame_end = pos + frame_len as usize;
        assert!(frame_end <= body.len(), "block frame overflows buffer");

        // Use `Cid::read_bytes` with a Cursor to determine how many bytes the CID occupies.
        let mut cursor = std::io::Cursor::new(&body[pos..frame_end]);
        let cid = cid::Cid::read_bytes(&mut cursor).expect("valid CID in block frame");
        let cid_consumed = cursor.position() as usize;
        let cid_bytes = cid.to_bytes();

        let data = body[pos + cid_consumed..frame_end].to_vec();
        blocks.push((cid_bytes, data));
        pos = frame_end;
    }
    blocks
}

/// End-to-end: 3 articles → build_export_car → verify block count, CIDs, data.
#[tokio::test]
async fn three_articles_all_appear_as_blocks() {
    let pool = make_pool().await;
    let ipfs = MemIpfsStore::new();

    let articles: &[(&[u8], &str, i64)] = &[
        (b"first article body", "comp.test", 1_000),
        (b"second article body", "comp.test", 2_000),
        (b"third article body", "comp.test", 3_000),
    ];

    let mut cids = Vec::new();
    for (data, group, ts) in articles {
        let cid = ipfs.put_raw(data).await.unwrap();
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(cid.to_string())
        .bind(*group)
        .bind(*ts)
        .bind(data.len() as i64)
        .execute(&pool)
        .await
        .unwrap();
        cids.push((cid, *data));
    }

    let car = build_export_car(&pool, &ipfs, "comp.test", 100)
        .await
        .unwrap();

    // ── Parse CAR header ─────────────────────────────────────────────────────
    let (header_len, hv) = decode_varint(&car);
    let header_bytes = &car[hv..hv + header_len as usize];

    // The CBOR-encoded string "version" is text(7) = 0x67 followed by its UTF-8
    // bytes. Spot-check that the header contains the literal "version" text.
    let version_key: &[u8] = &[0x67, b'v', b'e', b'r', b's', b'i', b'o', b'n'];
    assert!(
        header_bytes
            .windows(version_key.len())
            .any(|w| w == version_key),
        "CBOR header must contain text(7)\"version\""
    );
    // uint(1) immediately follows the "version" key in the CBOR header.
    let version_offset = header_bytes
        .windows(version_key.len())
        .position(|w| w == version_key)
        .unwrap();
    assert_eq!(
        header_bytes[version_offset + version_key.len()],
        0x01,
        "version value must be 1 (CBOR uint 0x01)"
    );

    // ── Parse blocks ─────────────────────────────────────────────────────────
    let block_body = &car[hv + header_len as usize..];
    let blocks = parse_blocks(block_body);

    assert_eq!(
        blocks.len(),
        3,
        "must export exactly 3 blocks; got {}",
        blocks.len()
    );

    // Build a lookup map cid_bytes → data for oracle verification.
    let oracle: std::collections::HashMap<Vec<u8>, &[u8]> = cids
        .iter()
        .map(|(cid, data)| (cid.to_bytes(), *data))
        .collect();

    for (cid_bytes, data) in &blocks {
        let expected = oracle
            .get(cid_bytes)
            .unwrap_or_else(|| panic!("unexpected CID in CAR output"));
        assert_eq!(
            data.as_slice(),
            *expected,
            "block data must match what was stored in IPFS"
        );
    }
}

/// Root CID must be the most-recently-ingested article (ORDER BY DESC first).
///
/// Oracle: the CAR spec places roots in the CBOR header array; the CID at
/// root position is encoded as tag(42) + bytes(0x00 || cid_bytes).
#[tokio::test]
async fn root_is_most_recent_article() {
    let pool = make_pool().await;
    let ipfs = MemIpfsStore::new();

    let d_old = b"older article";
    let d_new = b"newer article";
    let cid_old = ipfs.put_raw(d_old).await.unwrap();
    let cid_new = ipfs.put_raw(d_new).await.unwrap();

    for (cid, data, ts) in [(&cid_old, d_old, 1_000i64), (&cid_new, d_new, 2_000i64)] {
        sqlx::query(
            "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
             VALUES (?1, 'comp.test', ?2, ?3)",
        )
        .bind(cid.to_string())
        .bind(ts)
        .bind(data.len() as i64)
        .execute(&pool)
        .await
        .unwrap();
    }

    let car = build_export_car(&pool, &ipfs, "comp.test", 100)
        .await
        .unwrap();

    // The root CID bytes are encoded in the CBOR header as:
    //   tag(42) [D8 2A] + bytes(len) [58 len] + 0x00 + <cid_bytes>
    // Locate 0xD8 0x2A (tag 42) in the header and extract the CID bytes.
    let (header_len, hv) = decode_varint(&car);
    let header_bytes = &car[hv..hv + header_len as usize];

    let tag42_pos = header_bytes
        .windows(2)
        .position(|w| w == [0xd8, 0x2a])
        .expect("header must contain tag(42) for root CID");

    // After tag(42): CBOR bytes major type (0x58 = 1-byte length, or 0x40+n for short).
    let after_tag = &header_bytes[tag42_pos + 2..];
    let (byte_len, bv) = if after_tag[0] == 0x58 {
        (after_tag[1] as usize, 2usize)
    } else {
        // Short form: 0x40 | len
        ((after_tag[0] & 0x1f) as usize, 1usize)
    };
    // Skip the 0x00 multibase prefix.
    let root_cid_bytes = &after_tag[bv + 1..bv + byte_len];
    let expected_root_cid_bytes = cid_new.to_bytes();
    assert_eq!(
        root_cid_bytes,
        expected_root_cid_bytes.as_slice(),
        "root CID must be the most recently ingested article (cid_new)"
    );
}

/// Articles from another group must not appear in the export.
#[tokio::test]
async fn group_isolation_excludes_other_groups() {
    let pool = make_pool().await;
    let ipfs = MemIpfsStore::new();

    let d_comp = b"comp article data";
    let d_alt = b"alt article data";
    let cid_comp = ipfs.put_raw(d_comp).await.unwrap();
    let cid_alt = ipfs.put_raw(d_alt).await.unwrap();

    sqlx::query(
        "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
         VALUES (?1, 'comp.test', 1000, ?2)",
    )
    .bind(cid_comp.to_string())
    .bind(d_comp.len() as i64)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO articles (cid, group_name, ingested_at_ms, byte_count) \
         VALUES (?1, 'alt.test', 2000, ?2)",
    )
    .bind(cid_alt.to_string())
    .bind(d_alt.len() as i64)
    .execute(&pool)
    .await
    .unwrap();

    let car = build_export_car(&pool, &ipfs, "comp.test", 100)
        .await
        .unwrap();

    let (header_len, hv) = decode_varint(&car);
    let blocks = parse_blocks(&car[hv + header_len as usize..]);

    assert_eq!(blocks.len(), 1, "only the comp.test article must appear");
    assert_eq!(
        blocks[0].0,
        cid_comp.to_bytes(),
        "the block must be the comp.test article CID"
    );
    assert_eq!(blocks[0].1, d_comp, "block data must match");
}
