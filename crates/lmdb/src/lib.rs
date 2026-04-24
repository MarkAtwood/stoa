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
use heed::{Database, Env, EnvOpenOptions};
use std::path::Path;

type BlocksDb = Database<Bytes, Bytes>;

/// A content-addressed block database backed by LMDB.
///
/// Keys are raw CID bytes (`Cid::to_bytes()`); values are raw block bytes.
/// Uses a single named database (`"blocks"`) inside the LMDB environment.
pub struct LmdbBlockDb {
    env: Env,
    db: BlocksDb,
}

// SAFETY: heed::Env is Send + Sync (it wraps an Arc<EnvInner>).
// heed::Database<Bytes, Bytes> is Copy + Send + Sync (it is a u32 DBI handle).
unsafe impl Send for LmdbBlockDb {}
unsafe impl Sync for LmdbBlockDb {}

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
    pub fn open(path: &Path, map_size_gb: u64) -> Result<Self, String> {
        std::fs::create_dir_all(path)
            .map_err(|e| format!("cannot create LMDB directory {}: {e}", path.display()))?;

        // Reject map sizes that would overflow usize.  The config validator
        // catches this for production configs; this check defends callers (e.g.
        // tests) that call open() directly with an unchecked value.
        const GIB: usize = 1024 * 1024 * 1024;
        let map_size = (map_size_gb as usize)
            .checked_mul(GIB)
            .ok_or_else(|| {
                format!("map_size_gb {map_size_gb} overflows usize on this platform")
            })?;

        // SAFETY: We open this environment exactly once per process at this
        // path.  The `LmdbBlockDb` wrapper type is the only entry point; wrap
        // it in an Arc at the call site to share it across tasks.
        let env: Env = unsafe {
            EnvOpenOptions::new()
                .map_size(map_size)
                .max_dbs(1)
                .open(path)
                .map_err(|e| format!("LMDB open failed at {}: {e}", path.display()))?
        };

        let mut wtxn = env.write_txn().map_err(|e| e.to_string())?;
        let db: BlocksDb = env
            .create_database(&mut wtxn, Some("blocks"))
            .map_err(|e| e.to_string())?;
        wtxn.commit().map_err(|e| e.to_string())?;

        Ok(Self { env, db })
    }

    /// Store `value` under `key`.  Idempotent: re-writing the same key with
    /// the same value is a no-op from the caller's perspective (LMDB
    /// overwrites silently).
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        let mut wtxn = self.env.write_txn().map_err(|e| e.to_string())?;
        self.db
            .put(&mut wtxn, key, value)
            .map_err(|e| e.to_string())?;
        wtxn.commit().map_err(|e| e.to_string())
    }

    /// Retrieve the value stored under `key`.
    ///
    /// Returns `Ok(None)` if the key does not exist.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let rtxn = self.env.read_txn().map_err(|e| e.to_string())?;
        let result = self
            .db
            .get(&rtxn, key)
            .map_err(|e| e.to_string())?;
        Ok(result.map(|v| v.to_vec()))
    }

    /// Delete `key` from the database.
    ///
    /// Idempotent: deleting a key that does not exist returns `Ok(false)`
    /// without error.  Returns `Ok(true)` if the key was found and removed.
    pub fn delete(&self, key: &[u8]) -> Result<bool, String> {
        let mut wtxn = self.env.write_txn().map_err(|e| e.to_string())?;
        let found = self
            .db
            .delete(&mut wtxn, key)
            .map_err(|e| e.to_string())?;
        wtxn.commit().map_err(|e| e.to_string())?;
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
}
