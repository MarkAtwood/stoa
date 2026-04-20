#![forbid(unsafe_code)]

pub mod article;
pub mod audit;
pub mod canonical;
pub mod cid_util;
pub mod error;
pub mod group_log;
pub mod hlc;
pub mod ipld;
pub mod migrations;
pub mod msgid_map;
pub mod signing;
pub mod validation;

pub use article::{Article, ArticleBody, ArticleHeader, GroupName};
pub use error::{
    CoreError, ProtocolError, SigningError, StorageError, UsenetIpfsError, ValidationError,
};
pub use ipld::{ArticleMetadata, ArticleRootNode, MimeNode};
pub use validation::{check_duplicate, validate_article_ingress, MsgIdStorage, ValidationConfig};
