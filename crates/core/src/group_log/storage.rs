use std::future::Future;

use crate::article::GroupName;
use crate::error::StorageError;
use crate::group_log::types::{LogEntry, LogEntryId};

/// Async storage backend for the per-group Merkle-CRDT log.
///
/// All futures returned by this trait are `Send` so implementations can be
/// shared across tokio tasks without wrapping in a mutex. `entry_count`
/// returns the number of current tip entries for the group, which is an
/// approximation of total log depth for DAGs with concurrent branches.
pub trait LogStorage: Send + Sync {
    /// Persist a log entry. Returns `StorageError::DuplicateEntry` if an entry
    /// with the same id already exists.
    fn insert_entry(
        &self,
        id: LogEntryId,
        entry: LogEntry,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Retrieve a log entry by id. Returns `None` if not found.
    fn get_entry(
        &self,
        id: &LogEntryId,
    ) -> impl Future<Output = Result<Option<LogEntry>, StorageError>> + Send;

    /// Return `true` if an entry with the given id exists.
    fn has_entry(
        &self,
        id: &LogEntryId,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Return the current tip ids for a group (empty vec if no tips set).
    fn list_tips(
        &self,
        group: &GroupName,
    ) -> impl Future<Output = Result<Vec<LogEntryId>, StorageError>> + Send;

    /// Replace the tip set for a group atomically.
    fn set_tips(
        &self,
        group: &GroupName,
        tips: &[LogEntryId],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Return the number of tip entries for the group.
    fn entry_count(
        &self,
        group: &GroupName,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
}
