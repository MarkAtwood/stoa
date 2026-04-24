//! IPFS/IPLD codec and multihash constants.
//!
//! Single source of truth for the multicodec byte values used throughout
//! stoa.  Centralising them here prevents silent drift if the codec
//! strategy ever changes and makes the multicodec registry relationship
//! explicit to readers.

/// IPFS multicodec code for raw binary content (0x55 in the multicodec table).
///
/// Used for header and body blocks, which are opaque byte strings with no
/// IPLD-structured interpretation.
pub const CODEC_RAW: u64 = 0x55;

/// IPFS multicodec code for DAG-CBOR (0x71 in the multicodec table).
///
/// Used for the article root node and all IPLD-structured sub-nodes
/// (header map, MIME node, metadata).  DAG-CBOR is the selected and final
/// codec for this project (see CLAUDE.md — irreversible once articles are
/// written to IPFS).
pub const CODEC_DAG_CBOR: u64 = 0x71;

/// Multihash function code for SHA-256 (0x12 in the multihash table).
///
/// Used in `Multihash::wrap(MH_SHA2_256, digest)` to construct CIDv1 hashes.
/// SHA-256 is the selected digest function for all CIDs in this project.
pub const MH_SHA2_256: u64 = 0x12;
