use cid::Cid;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use multihash_codetable::Multihash;
use stoa_core::article::GroupName;
use stoa_core::group_log::mem_storage::MemLogStorage;
use stoa_core::group_log::storage::LogStorage;
use stoa_core::group_log::types::{LogEntry, LogEntryId};
use tokio::runtime::Runtime;

// ── helpers ───────────────────────────────────────────────────────────────────

const SHARED_COUNT: usize = 9_000;
const UNIQUE_COUNT: usize = 1_000;

/// Build a deterministic `LogEntryId` from a domain tag byte and a counter.
///
/// Layout: `[tag, 0, 0, ..., n_lo, n_hi, 0, ...]` with `n` encoded as
/// little-endian in bytes 24-31 and `tag` in byte 0.
fn make_id(tag: u8, n: usize) -> LogEntryId {
    let mut raw = [0u8; 32];
    raw[0] = tag;
    let n_bytes = (n as u64).to_le_bytes();
    raw[24..32].copy_from_slice(&n_bytes);
    LogEntryId::from_bytes(raw)
}

/// Wrap a `LogEntryId` as a parent CID.
///
/// Uses multihash code `0x12` (raw SHA-256 wrap) + DAG-CBOR codec `0x71`,
/// matching the encoding that `reconcile` decodes via `hash().digest()`.
fn id_to_parent_cid(id: &LogEntryId) -> Cid {
    let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
    Cid::new_v1(0x71, mh)
}

/// Build a minimal `LogEntry` with an optional single parent.
fn make_entry(hlc: u64, n: usize, parent: Option<&LogEntryId>) -> LogEntry {
    // Article CID: deterministic from counter, distinct from entry IDs.
    let mut art_bytes = [0xFFu8; 32];
    art_bytes[0] = 0xAC;
    let n_bytes = (n as u64).to_le_bytes();
    art_bytes[24..32].copy_from_slice(&n_bytes);
    let art_mh = Multihash::wrap(0x12, &art_bytes).expect("valid multihash");
    let article_cid = Cid::new_v1(0x71, art_mh);

    let parent_cids = parent.map(id_to_parent_cid).into_iter().collect();

    LogEntry {
        hlc_timestamp: hlc,
        article_cid,
        operator_signature: vec![],
        parent_cids,
    }
}

/// Populate `storage` with the shared chain (entries 0..SHARED_COUNT) and a
/// node-specific divergent chain (entries SHARED_COUNT..SHARED_COUNT+UNIQUE_COUNT).
///
/// The shared genesis (index 0) has no parent.  Every subsequent entry points
/// to its predecessor.  The final unique entry is set as the tip for `group`.
///
/// `unique_tag` distinguishes node-specific entry IDs (`0xAA` for A, `0xBB`
/// for B).  Shared entries always use tag `0x00`.
async fn populate(storage: &MemLogStorage, group: &GroupName, unique_tag: u8) -> LogEntryId {
    let shared_tag = 0x00u8;

    // ── shared chain ─────────────────────────────────────────────────────────
    let genesis_id = make_id(shared_tag, 0);
    storage
        .insert_entry(genesis_id.clone(), make_entry(1_000_000, 0, None))
        .await
        .expect("insert genesis");

    let mut prev_id = genesis_id;
    for i in 1..SHARED_COUNT {
        let id = make_id(shared_tag, i);
        let entry = make_entry(1_000_000 + i as u64, i, Some(&prev_id));
        storage
            .insert_entry(id.clone(), entry)
            .await
            .expect("insert shared");
        prev_id = id;
    }

    // `prev_id` is now the last shared entry (index SHARED_COUNT - 1).

    // ── unique chain ─────────────────────────────────────────────────────────
    for i in 0..UNIQUE_COUNT {
        let id = make_id(unique_tag, i);
        let entry = make_entry(2_000_000 + i as u64, SHARED_COUNT + i, Some(&prev_id));
        storage
            .insert_entry(id.clone(), entry)
            .await
            .expect("insert unique");
        prev_id = id;
    }

    // `prev_id` is now the tip: last unique entry (index UNIQUE_COUNT - 1).
    let tip = prev_id;
    storage
        .set_tips(group, &[tip.clone()])
        .await
        .expect("set tips");
    tip
}

// ── benchmarks ────────────────────────────────────────────────────────────────

/// Benchmark CRDT log reconciliation: node A computes what it wants from node B
/// and what it has to offer, given two 10 000-entry logs that diverge at entry
/// 9 000.
///
/// Setup (outside `b.iter`): populate both storages and collect B's tips.
/// Measurement: one `reconcile` call per iteration.
fn bench_reconcile_10k_diverge_at_9k(c: &mut Criterion) {
    use stoa_core::group_log::reconcile::reconcile;

    let rt = Runtime::new().expect("tokio runtime");

    let group = GroupName::new("comp.lang.rust").expect("valid group name");

    let storage_a = MemLogStorage::new();
    let storage_b = MemLogStorage::new();

    // Pre-populate both nodes outside the measurement loop.
    let b_tip = rt.block_on(async {
        populate(&storage_a, &group, 0xAA).await;
        populate(&storage_b, &group, 0xBB).await
    });

    let b_tips: Vec<LogEntryId> = vec![b_tip];

    let mut bench_group = c.benchmark_group("reconcile");
    // Each iteration resolves 1 000 unique entries on each side.
    bench_group.throughput(Throughput::Elements(UNIQUE_COUNT as u64));

    bench_group.bench_function("10k_diverge_at_9k", |b| {
        b.iter(|| {
            rt.block_on(async {
                reconcile(&storage_a, &group, &b_tips)
                    .await
                    .expect("reconcile")
            })
        })
    });

    bench_group.finish();
}

criterion_group!(benches, bench_reconcile_10k_diverge_at_9k);
criterion_main!(benches);
