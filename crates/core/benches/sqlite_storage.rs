use cid::Cid;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use multihash_codetable::{Code, MultihashDigest};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::SqlitePool;
use std::str::FromStr;
use stoa_core::group_log::sqlite_storage::SqliteLogStorage;
use stoa_core::group_log::storage::LogStorage;
use stoa_core::group_log::types::{LogEntry, LogEntryId};
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_cid(n: u64) -> Cid {
    let digest = Code::Sha2_256.digest(&n.to_le_bytes());
    Cid::new_v1(0x71, digest)
}

/// Create a deterministic `(LogEntryId, LogEntry)` pair for index `n`.
fn make_log_entry(n: u64) -> (LogEntryId, LogEntry) {
    let mut id_bytes = [0u8; 32];
    id_bytes[..8].copy_from_slice(&n.to_le_bytes());
    let id = LogEntryId::from_bytes(id_bytes);

    let entry = LogEntry {
        hlc_timestamp: 1_700_000_000_000 + n,
        article_cid: make_cid(n),
        operator_signature: vec![0u8; 64],
        parent_cids: vec![],
    };

    (id, entry)
}

/// Create an in-memory `SqliteLogStorage` for a fresh-DB iteration.
async fn setup_memory_storage() -> SqliteLogStorage {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("in-memory pool");
    stoa_core::migrations::run_migrations(&pool)
        .await
        .expect("migrations");
    SqliteLogStorage::new(pool)
}

/// Create a file-backed `SqliteLogStorage`.  Returns `(storage, tmp)` — the
/// `TempPath` must be kept alive for the duration of the storage's use.
async fn setup_storage() -> (SqliteLogStorage, tempfile::TempPath) {
    let tmp = NamedTempFile::new().expect("temp file").into_temp_path();
    let url = format!("sqlite://{}", tmp.to_str().expect("utf-8 path"));
    let opts = SqliteConnectOptions::from_str(&url)
        .expect("parse url")
        .create_if_missing(true);
    let pool = SqlitePool::connect_with(opts).await.expect("file pool");
    stoa_core::migrations::run_migrations(&pool)
        .await
        .expect("migrations");
    (SqliteLogStorage::new(pool), tmp)
}

// ── benchmarks ────────────────────────────────────────────────────────────────

/// Measure sequential insert throughput: 1 000 entries per iteration into a
/// fresh in-memory database.
fn bench_sqlite_insert_1000(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("sqlite_storage");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("insert_1000", |b| {
        b.iter(|| {
            rt.block_on(async {
                let storage = setup_memory_storage().await;
                for i in 0u64..1000 {
                    let (id, entry) = make_log_entry(i);
                    storage.insert_entry(id, entry).await.expect("insert");
                }
            })
        })
    });

    group.finish();
}

/// Measure random get latency against a pre-populated 1 000-entry database.
/// Each iteration fetches 100 entries chosen evenly across the populated set.
fn bench_sqlite_get_random(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    // Pre-populate once outside the benchmark loop.
    let (storage, _tmp) = rt.block_on(setup_storage());
    rt.block_on(async {
        for i in 0u64..1000 {
            let (id, entry) = make_log_entry(i);
            storage
                .insert_entry(id, entry)
                .await
                .expect("pre-populate insert");
        }
    });

    // Build the 100 IDs we will fetch each iteration (evenly spaced).
    let fetch_ids: Vec<LogEntryId> = (0u64..100)
        .map(|i| {
            let (id, _) = make_log_entry(i * 10);
            id
        })
        .collect();

    let mut group = c.benchmark_group("sqlite_storage");
    group.throughput(Throughput::Elements(100));

    group.bench_function("get_100_random", |b| {
        b.iter(|| {
            rt.block_on(async {
                for id in &fetch_ids {
                    let _ = storage.get_entry(id).await.expect("get");
                }
            })
        })
    });

    group.finish();
}

criterion_group!(benches, bench_sqlite_insert_1000, bench_sqlite_get_random);
criterion_main!(benches);
