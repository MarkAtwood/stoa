//! IPLD schema types for usenet-ipfs article storage.
//!
//! The article root node (DAG-CBOR, codec 0x71) links to separate raw blocks
//! for the verbatim wire bytes and to IPLD sub-nodes for MIME and metadata.
//! All CIDs are CIDv1 SHA-256.

pub mod blocks;
pub mod builder;
pub mod header_map;
pub mod metadata;
pub mod mime;
pub mod mime_parser;
pub mod root_node;
pub mod test_vectors;

pub use blocks::{body_block, header_block};
pub use builder::{build_article, BuildError, BuiltArticle};
pub use header_map::{HeaderMapNode, HeaderValue};
pub use metadata::{compute_byte_count, compute_line_count, compute_metadata, extract_content_type_summary};
pub use mime::MimeNode;
pub use mime_parser::{parse_mime, ParsedMime};
pub use root_node::{ArticleMetadata, ArticleRootNode};
