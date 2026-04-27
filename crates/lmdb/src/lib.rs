//! FFI boundary crate wrapping LMDB via the `heed` safe bindings.
//!
//! This crate isolates the single `unsafe` call required to open an LMDB
//! environment.  All callers at higher levels can stay `#![forbid(unsafe_code)]`.
//!
//! # Thread safety
//!
//! `LmdbBlockDb` is `Send + Sync`.  LMDB itself is thread-safe: multiple
//! readers run concurrently without any locking; write transactions are
//! serialised internally by LMDB.  `spawn_blocking` is the caller's
//! responsibility — all methods here are synchronous.
//!
//! # Single-open invariant
//!
//! LMDB requires that each environment path is opened **at most once per
//! process**.  Opening two environments at the same path from the same process
//! is undefined behaviour.  Callers must ensure they create at most one
//! `LmdbBlockDb` per path.

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, MdbError};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

type BlocksDb = Database<Bytes, Bytes>;

// Compile-time assertion that LmdbBlockDb is Send + Sync.
// If a future change adds a !Send or !Sync field (e.g. Rc, RefCell, raw pointer)
// this will fail to compile rather than silently losing the thread-safety guarantee
// that callers rely on when wrapping LmdbBlockDb in Arc.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<LmdbBlockDb>;
};

/// Process-global set of canonicalized paths with open LMDB environments.
///
/// LMDB requires that each environment path is opened **at most once per
/// process**.  Opening two environments at the same path is undefined behaviour.
/// This set enforces the invariant at runtime, converting a prose comment into
/// a checked error.
static OPEN_PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn open_paths() -> &'static Mutex<HashSet<PathBuf>> {
    OPEN_PATHS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Typed errors from LMDB operations.
///
/// Callers can match on `MapFull` or `ReadersFull` to handle those conditions
/// differently (e.g. resize the map or back off and retry) rather than
/// treating all failures as generic strings.
#[derive(Debug)]
pub enum LmdbError {
    /// The LMDB map is full (`MDB_MAP_FULL`).  The environment must be
    /// reopened with a larger `map_size`, or writes must be rejected.
    MapFull,
    /// The LMDB reader lock table is full (`MDB_READERS_FULL`).  Back off
    /// and retry, or increase `max_readers` in the environment options.
    ReadersFull,
    /// Any other LMDB or I/O error.
    Other(String),
}

impl std::fmt::Display for LmdbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MapFull => write!(f, "LMDB map full (MDB_MAP_FULL)"),
            Self::ReadersFull => write!(f, "LMDB reader table full (MDB_READERS_FULL)"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for LmdbError {}

impl From<heed::Error> for LmdbError {
    fn from(e: heed::Error) -> Self {
        match e {
            heed::Error::Mdb(MdbError::MapFull) => Self::MapFull,
            heed::Error::Mdb(MdbError::ReadersFull) => Self::ReadersFull,
            other => Self::Other(other.to_string()),
        }
    }
}

/// A content-addressed block database backed by LMDB.
///
/// Keys are raw CID bytes (`Cid::to_bytes()`); values are raw block bytes.
/// Uses a single named database (`"blocks"`) inside the LMDB environment.
pub struct LmdbBlockDb {
    env: Env,
    db: BlocksDb,
    /// Canonicalized path registered in `OPEN_PATHS`; removed on drop.
    canonical_path: PathBuf,
}

impl Drop for LmdbBlockDb {
    fn drop(&mut self) {
        if let Ok(mut set) = open_paths().lock() {
            set.remove(&self.canonical_path);
        }
    }
}

impl LmdbBlockDb {
    /// Open or create the LMDB environment at `path`.
    ///
    /// `map_size_gb` sets the virtual address space reservation in GiB.
    /// On 64-bit systems this does **not** pre-allocate disk space.
    /// Typical production value: 1024 (1 TiB).  Use a smaller value (e.g. 1)
    /// in tests.
    ///
    /// Returns `Err` if the directory cannot be created or the environment
    /// cannot be opened (e.g. the path is not writable).
    ///
    /// # Panics
    ///
    /// Does not panic.  All error conditions are returned as `Err`.
    pub fn open(path: &Path, map_size_gb: u64) -> Result<Self, LmdbError> {
        std::fs::create_dir_all(path).map_err(|e| {
            LmdbError::Other(format!(
                "cannot create LMDB directory {}: {e}",
                path.display()
            ))
        })?;

        // Enforce the single-open invariant: LMDB's EnvOpenOptions::open is
        // `unsafe` precisely because opening the same environment path twice
        // from the same process is undefined behaviour (mmap aliasing, silent
        // data corruption).  We canonicalize the path (resolving symlinks) and
        // register it in a process-global set so that a second open attempt
        // returns a clear error rather than silently invoking UB.
        let canonical = path.canonicalize().map_err(|e| {
            LmdbError::Other(format!(
                "cannot canonicalize LMDB path {}: {e}",
                path.display()
            ))
        })?;
        {
            let mut set = open_paths()
                .lock()
                .map_err(|_| LmdbError::Other("OPEN_PATHS lock poisoned".into()))?;
            if !set.insert(canonical.clone()) {
                return Err(LmdbError::Other(format!(
                    "LMDB environment at {} is already open in this process; \
                     wrap LmdbBlockDb in Arc to share it across tasks",
                    canonical.display()
                )));
            }
        }

        // Reject map sizes that would overflow usize.  The config validator
        // catches this for production configs; this check defends callers (e.g.
        // tests) that call open() directly with an unchecked value.
        //
        // The cast `map_size_gb as usize` must be checked first: on 32-bit
        // platforms usize is 32 bits and a large u64 would silently truncate
        // before checked_mul runs, defeating the overflow check entirely.
        const GIB: usize = 1024 * 1024 * 1024;
        let map_size_gb_usize: usize = map_size_gb.try_into().map_err(|_| {
            LmdbError::Other(format!(
                "map_size_gb {map_size_gb} overflows usize on this platform"
            ))
        })?;
        let map_size = map_size_gb_usize.checked_mul(GIB).ok_or_else(|| {
            LmdbError::Other(format!(
                "map_size_gb {map_size_gb} overflows usize on this platform"
            ))
        })?;

        // SAFETY: We open this environment exactly once per process at this
        // path.  The `LmdbBlockDb` wrapper type is the only entry point; wrap
        // it in an Arc at the call site to share it across tasks.
        let env: Env = unsafe {
            EnvOpenOptions::new()
                .map_size(map_size)
                .max_dbs(1)
                .open(path)
                .map_err(|e| {
                    LmdbError::Other(format!("LMDB open failed at {}: {e}", path.display()))
                })?
        };

        let mut wtxn = env.write_txn().map_err(LmdbError::from)?;
        let db: BlocksDb = env
            .create_database(&mut wtxn, Some("blocks"))
            .map_err(LmdbError::from)?;
        wtxn.commit().map_err(LmdbError::from)?;

        Ok(Self { env, db, canonical_path: canonical })
    }

    /// Store `value` under `key`.  Idempotent: re-writing the same key with
    /// the same value is a no-op from the caller's perspective (LMDB
    /// overwrites silently).
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), LmdbError> {
        let mut wtxn = self.env.write_txn().map_err(LmdbError::from)?;
        self.db
            .put(&mut wtxn, key, value)
            .map_err(LmdbError::from)?;
        wtxn.commit().map_err(LmdbError::from)
    }

    /// Retrieve the value stored under `key`.
    ///
    /// Returns `Ok(None)` if the key does not exist.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, LmdbError> {
        let rtxn = self.env.read_txn().map_err(LmdbError::from)?;
        let result = self.db.get(&rtxn, key).map_err(LmdbError::from)?;
        Ok(result.map(|v| v.to_vec()))
    }

    /// Write multiple `(key, value)` pairs in a single write transaction.
    ///
    /// More efficient than calling [`put`] repeatedly: each `put` opens and
    /// commits a separate write transaction, incurring a full `fsync` per
    /// call.  This method amortises that overhead across all pairs.
    ///
    /// Idempotent: re-writing the same key with the same value is a no-op.
    /// If any individual write fails, the transaction is aborted and no
    /// pairs are committed.
    ///
    /// Returns `Ok(())` immediately if `pairs` is empty.
    ///
    /// # DECISION (rbe3.5): batch write for multi-block ingestion
    ///
    /// LMDB serialises write transactions at the environment level: each
    /// call to `put` opens a write txn, writes one record, then commits
    /// (fsync).  When ingesting a multi-block article — root block plus
    /// one or more chunk blocks — calling `put` N times costs N fsyncs.
    /// `put_batch` writes all N blocks in one transaction and commits once.
    /// The caller must not hold the result of a previous read transaction
    /// across this call, because LMDB readers and writers do not block each
    /// other but a long-lived read transaction prevents the write from
    /// advancing the free-list.
    pub fn put_batch(&self, pairs: &[(&[u8], &[u8])]) -> Result<(), LmdbError> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut wtxn = self.env.write_txn().map_err(LmdbError::from)?;
        for (key, value) in pairs {
            self.db
                .put(&mut wtxn, key, value)
                .map_err(LmdbError::from)?;
        }
        wtxn.commit().map_err(LmdbError::from)
    }

    /// Delete `key` from the database.
    ///
    /// Idempotent: deleting a key that does not exist returns `Ok(false)`
    /// without error.  Returns `Ok(true)` if the key was found and removed.
    pub fn delete(&self, key: &[u8]) -> Result<bool, LmdbError> {
        let mut wtxn = self.env.write_txn().map_err(LmdbError::from)?;
        let found = self.db.delete(&mut wtxn, key).map_err(LmdbError::from)?;
        wtxn.commit().map_err(LmdbError::from)?;
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> (LmdbBlockDb, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db = LmdbBlockDb::open(tmp.path(), 1).expect("open");
        (db, tmp)
    }

    #[test]
    fn put_get_round_trip() {
        let (db, _tmp) = open_test_db();
        db.put(b"key1", b"value1").unwrap();
        let v = db.get(b"key1").unwrap();
        assert_eq!(v, Some(b"value1".to_vec()));
    }

    #[test]
    fn get_missing_returns_none() {
        let (db, _tmp) = open_test_db();
        assert!(db.get(b"missing").unwrap().is_none());
    }

    #[test]
    fn delete_removes_key() {
        let (db, _tmp) = open_test_db();
        db.put(b"to_del", b"data").unwrap();
        let found = db.delete(b"to_del").unwrap();
        assert!(found, "delete must return true for existing key");
        assert!(db.get(b"to_del").unwrap().is_none());
    }

    #[test]
    fn delete_idempotent() {
        let (db, _tmp) = open_test_db();
        db.put(b"k", b"v").unwrap();
        let first = db.delete(b"k").unwrap();
        let second = db.delete(b"k").unwrap();
        assert!(first);
        assert!(!second, "second delete must return false");
    }

    #[test]
    fn put_batch_writes_all_pairs() {
        let (db, _tmp) = open_test_db();
        let pairs: &[(&[u8], &[u8])] = &[
            (b"block1", b"data1"),
            (b"block2", b"data2"),
            (b"block3", b"data3"),
        ];
        db.put_batch(pairs).unwrap();
        assert_eq!(db.get(b"block1").unwrap(), Some(b"data1".to_vec()));
        assert_eq!(db.get(b"block2").unwrap(), Some(b"data2".to_vec()));
        assert_eq!(db.get(b"block3").unwrap(), Some(b"data3".to_vec()));
    }

    #[test]
    fn put_batch_empty_is_noop() {
        let (db, _tmp) = open_test_db();
        db.put_batch(&[]).unwrap();
        // No error; database is still usable.
        assert!(db.get(b"any").unwrap().is_none());
    }

    #[test]
    fn put_batch_idempotent() {
        let (db, _tmp) = open_test_db();
        let pairs: &[(&[u8], &[u8])] = &[(b"k", b"v")];
        db.put_batch(pairs).unwrap();
        db.put_batch(pairs).unwrap();
        assert_eq!(db.get(b"k").unwrap(), Some(b"v".to_vec()));
    }
}
