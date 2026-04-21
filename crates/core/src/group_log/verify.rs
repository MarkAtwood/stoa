use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::error::{SigningError, StorageError};
use crate::group_log::storage::LogStorage;
use crate::group_log::types::{LogEntry, LogEntryId};
use crate::signing::{verify, VerifyingKey};

use ed25519_dalek::Signature;

/// Compute a deterministic hash of a tip set.
///
/// Tip CIDs are sorted lexicographically by their raw byte representation,
/// concatenated, then SHA2-256 hashed. An empty tip set produces the
/// SHA2-256 of an empty byte string.
pub fn tip_hash(tips: &[Cid]) -> [u8; 32] {
    let mut tip_bytes: Vec<Vec<u8>> = tips.iter().map(|c| c.to_bytes()).collect();
    tip_bytes.sort();
    let mut combined = Vec::new();
    for tb in &tip_bytes {
        combined.extend_from_slice(tb);
    }
    let digest = Code::Sha2_256.digest(&combined);
    digest
        .digest()
        .try_into()
        .expect("SHA2-256 is always 32 bytes")
}

/// Errors returned by [`verify_entry`].
#[derive(Debug)]
pub enum VerifyError {
    Storage(StorageError),
    InvalidSignature(SigningError),
    MissingParent(String),
    HlcNotMonotonic { entry: u64, parent: u64 },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::MissingParent(cid) => write!(f, "parent entry not found: {cid}"),
            Self::HlcNotMonotonic { entry, parent } => write!(
                f,
                "HLC not monotonic: entry timestamp {entry} <= parent timestamp {parent}"
            ),
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::InvalidSignature(e) => Some(e),
            Self::MissingParent(_) | Self::HlcNotMonotonic { .. } => None,
        }
    }
}

impl From<StorageError> for VerifyError {
    fn from(e: StorageError) -> Self {
        VerifyError::Storage(e)
    }
}

/// Verify a log entry's consistency:
///
/// 1. The Ed25519 signature in `entry.operator_signature` is valid over the
///    canonical bytes: `hlc_timestamp (8 BE bytes) || article_cid bytes ||
///    sorted parent_cid bytes`.  The signature field itself is excluded from
///    the signed content.
/// 2. All parent CIDs listed in `entry.parent_cids` exist in `storage`.
/// 3. `entry.hlc_timestamp` is strictly greater than every parent's
///    `hlc_timestamp`.
///
/// Genesis entries (no parents) pass checks 2 and 3 vacuously.
pub async fn verify_entry<S: LogStorage>(
    entry: &LogEntry,
    _entry_id: &LogEntryId,
    storage: &S,
    pubkey: &VerifyingKey,
) -> Result<(), VerifyError> {
    // ── 1. Signature verification ─────────────────────────────────────────────
    // Canonical bytes are the same fields used in compute_entry_id, but WITHOUT
    // operator_signature — the signature covers the content it protects.
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&entry.hlc_timestamp.to_be_bytes());
    canonical.extend_from_slice(&entry.article_cid.to_bytes());

    let mut parent_bytes: Vec<Vec<u8>> = entry.parent_cids.iter().map(|c| c.to_bytes()).collect();
    parent_bytes.sort();
    for pb in &parent_bytes {
        canonical.extend_from_slice(pb);
    }

    let sig_bytes: [u8; 64] = entry
        .operator_signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            VerifyError::InvalidSignature(SigningError::SignatureTooShort {
                actual: entry.operator_signature.len(),
                expected: 64,
            })
        })?;
    let sig = Signature::from_bytes(&sig_bytes);

    verify(pubkey, &canonical, &sig).map_err(VerifyError::InvalidSignature)?;

    // ── 2 & 3. Parent existence and HLC monotonicity ──────────────────────────
    for parent_cid in &entry.parent_cids {
        let digest_bytes = parent_cid.hash().digest();
        let raw: [u8; 32] = digest_bytes.try_into().map_err(|_| {
            VerifyError::MissingParent(format!(
                "parent CID {} has a non-32-byte digest (length {})",
                parent_cid,
                parent_cid.hash().digest().len()
            ))
        })?;
        let parent_id = LogEntryId::from_bytes(raw);

        if !storage.has_entry(&parent_id).await? {
            return Err(VerifyError::MissingParent(parent_cid.to_string()));
        }

        let parent_entry = storage
            .get_entry(&parent_id)
            .await?
            .ok_or_else(|| VerifyError::MissingParent(parent_cid.to_string()))?;

        if entry.hlc_timestamp <= parent_entry.hlc_timestamp {
            return Err(VerifyError::HlcNotMonotonic {
                entry: entry.hlc_timestamp,
                parent: parent_entry.hlc_timestamp,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_log::mem_storage::MemLogStorage;
    use crate::signing::SigningKey;
    use multihash_codetable::Multihash;

    fn test_cid(data: &[u8]) -> Cid {
        let digest = Code::Sha2_256.digest(data);
        Cid::new_v1(0x71, digest)
    }

    fn entry_id_to_cid(id: &LogEntryId) -> Cid {
        let mh = Multihash::wrap(0x12, id.as_bytes()).expect("valid multihash");
        Cid::new_v1(0x71, mh)
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    /// Build canonical bytes for signing: hlc_timestamp || article_cid || sorted parent_cids.
    fn canonical_bytes(entry: &LogEntry) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&entry.hlc_timestamp.to_be_bytes());
        bytes.extend_from_slice(&entry.article_cid.to_bytes());
        let mut parent_bytes: Vec<Vec<u8>> =
            entry.parent_cids.iter().map(|c| c.to_bytes()).collect();
        parent_bytes.sort();
        for pb in &parent_bytes {
            bytes.extend_from_slice(pb);
        }
        bytes
    }

    fn sign_entry(entry: &mut LogEntry, key: &SigningKey) {
        let canonical = canonical_bytes(entry);
        let sig = crate::signing::sign(key, &canonical);
        entry.operator_signature = sig.to_bytes().to_vec();
    }

    /// Helper: store an entry in MemLogStorage and return its id CID.
    async fn store_entry(storage: &MemLogStorage, id: LogEntryId, entry: LogEntry) -> Cid {
        storage
            .insert_entry(id.clone(), entry)
            .await
            .expect("insert");
        entry_id_to_cid(&id)
    }

    // ── tip_hash_deterministic ────────────────────────────────────────────────

    #[test]
    fn tip_hash_deterministic() {
        let cid_a = test_cid(b"aaa");
        let cid_b = test_cid(b"bbb");
        assert_eq!(
            tip_hash(&[cid_b.clone(), cid_a.clone()]),
            tip_hash(&[cid_a, cid_b]),
            "tip_hash must be order-independent"
        );
    }

    // ── tip_hash_empty ────────────────────────────────────────────────────────

    #[test]
    fn tip_hash_empty() {
        // SHA2-256 of the empty byte string, from an independent reference:
        // $ echo -n "" | sha256sum
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected: [u8; 32] = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855",
        )
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");
        assert_eq!(tip_hash(&[]), expected);
    }

    // ── verify_entry_valid ────────────────────────────────────────────────────

    #[tokio::test]
    async fn verify_entry_valid() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        let mut entry = LogEntry {
            hlc_timestamp: 1_000,
            article_cid: test_cid(b"article-valid"),
            operator_signature: vec![],
            parent_cids: vec![],
        };
        sign_entry(&mut entry, &key);

        // Compute entry id the same way append.rs does (includes sig bytes).
        let entry_id = {
            let mut input = Vec::new();
            input.extend_from_slice(&entry.hlc_timestamp.to_be_bytes());
            input.extend_from_slice(&entry.article_cid.to_bytes());
            input.extend_from_slice(&entry.operator_signature);
            let digest = Code::Sha2_256.digest(&input);
            LogEntryId::from_bytes(digest.digest().try_into().expect("32 bytes"))
        };

        let result = verify_entry(&entry, &entry_id, &storage, &pubkey).await;
        assert!(
            result.is_ok(),
            "valid entry must pass verification: {result:?}"
        );
    }

    // ── verify_entry_bad_signature ────────────────────────────────────────────

    #[tokio::test]
    async fn verify_entry_bad_signature() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        let mut entry = LogEntry {
            hlc_timestamp: 2_000,
            article_cid: test_cid(b"article-tampered"),
            operator_signature: vec![],
            parent_cids: vec![],
        };
        sign_entry(&mut entry, &key);

        // Flip the first byte of the signature to invalidate it.
        entry.operator_signature[0] ^= 0xff;

        let entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&entry, &entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::InvalidSignature(_))),
            "tampered signature must yield InvalidSignature, got {result:?}"
        );
    }

    // ── verify_entry_missing_parent ───────────────────────────────────────────

    #[tokio::test]
    async fn verify_entry_missing_parent() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        // Invent a parent CID whose digest is not in storage.
        let phantom_id = LogEntryId::from_bytes([0xde; 32]);
        let phantom_cid = entry_id_to_cid(&phantom_id);

        let mut entry = LogEntry {
            hlc_timestamp: 3_000,
            article_cid: test_cid(b"article-orphan"),
            operator_signature: vec![],
            parent_cids: vec![phantom_cid],
        };
        sign_entry(&mut entry, &key);

        let entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&entry, &entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::MissingParent(_))),
            "missing parent must yield MissingParent, got {result:?}"
        );
    }

    // ── verify_entry_hlc_not_monotonic ────────────────────────────────────────

    #[tokio::test]
    async fn verify_entry_hlc_not_monotonic() {
        let storage = MemLogStorage::new();
        let key = test_signing_key();
        let pubkey = key.verifying_key();

        // Store a parent entry with hlc_timestamp = 5_000.
        let mut parent_entry = LogEntry {
            hlc_timestamp: 5_000,
            article_cid: test_cid(b"parent-article"),
            operator_signature: vec![],
            parent_cids: vec![],
        };
        sign_entry(&mut parent_entry, &key);
        let parent_id = {
            let mut input = Vec::new();
            input.extend_from_slice(&parent_entry.hlc_timestamp.to_be_bytes());
            input.extend_from_slice(&parent_entry.article_cid.to_bytes());
            input.extend_from_slice(&parent_entry.operator_signature);
            let digest = Code::Sha2_256.digest(&input);
            LogEntryId::from_bytes(digest.digest().try_into().expect("32 bytes"))
        };
        let parent_cid = store_entry(&storage, parent_id, parent_entry).await;

        // Child entry with hlc_timestamp <= parent's (equal — not strictly greater).
        let mut child_entry = LogEntry {
            hlc_timestamp: 4_000,
            article_cid: test_cid(b"child-article"),
            operator_signature: vec![],
            parent_cids: vec![parent_cid],
        };
        sign_entry(&mut child_entry, &key);

        let entry_id = LogEntryId::from_bytes([0u8; 32]);
        let result = verify_entry(&child_entry, &entry_id, &storage, &pubkey).await;
        assert!(
            matches!(result, Err(VerifyError::HlcNotMonotonic { .. })),
            "non-monotonic HLC must yield HlcNotMonotonic, got {result:?}"
        );
    }
}
