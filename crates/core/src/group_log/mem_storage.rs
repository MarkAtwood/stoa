use std::collections::HashMap;

use tokio::sync::RwLock;

use crate::article::GroupName;
use crate::error::StorageError;
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};

/// In-memory `LogStorage` implementation for testing and ephemeral use.
pub struct MemLogStorage {
    entries: RwLock<HashMap<[u8; 32], LogEntry>>,
    tips: RwLock<HashMap<String, Vec<[u8; 32]>>>,
}

impl MemLogStorage {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            tips: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemLogStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl LogStorage for MemLogStorage {
    async fn insert_entry(&self, id: LogEntryId, entry: LogEntry) -> Result<(), StorageError> {
        let key = *id.as_bytes();
        let mut map = self.entries.write().await;
        if map.contains_key(&key) {
            return Err(StorageError::DuplicateEntry(id));
        }
        map.insert(key, entry);
        Ok(())
    }

    async fn get_entry(&self, id: &LogEntryId) -> Result<Option<LogEntry>, StorageError> {
        let map = self.entries.read().await;
        Ok(map.get(id.as_bytes()).cloned())
    }

    async fn has_entry(&self, id: &LogEntryId) -> Result<bool, StorageError> {
        let map = self.entries.read().await;
        Ok(map.contains_key(id.as_bytes()))
    }

    async fn list_tips(&self, group: &GroupName) -> Result<Vec<LogEntryId>, StorageError> {
        let map = self.tips.read().await;
        let ids = map
            .get(group.as_str())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(LogEntryId::from_bytes)
            .collect();
        Ok(ids)
    }

    async fn set_tips(&self, group: &GroupName, tips: &[LogEntryId]) -> Result<(), StorageError> {
        let mut map = self.tips.write().await;
        let raw: Vec<[u8; 32]> = tips.iter().map(|id| *id.as_bytes()).collect();
        map.insert(group.as_str().to_owned(), raw);
        Ok(())
    }

    async fn entry_count(&self, group: &GroupName) -> Result<u64, StorageError> {
        let map = self.tips.read().await;
        let count = map
            .get(group.as_str())
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_log::storage_tests;

    #[tokio::test]
    async fn mem_insert_and_get() {
        let s = MemLogStorage::new();
        storage_tests::test_insert_and_get(&s).await;
    }

    #[tokio::test]
    async fn mem_has_entry() {
        let s = MemLogStorage::new();
        storage_tests::test_has_entry(&s).await;
    }

    #[tokio::test]
    async fn mem_set_and_list_tips() {
        let s = MemLogStorage::new();
        storage_tests::test_set_and_list_tips(&s).await;
    }

    #[tokio::test]
    async fn mem_entry_count() {
        let s = MemLogStorage::new();
        storage_tests::test_entry_count(&s).await;
    }

    #[tokio::test]
    async fn mem_duplicate_insert_rejected() {
        let s = MemLogStorage::new();
        storage_tests::test_duplicate_insert_rejected(&s).await;
    }
}
