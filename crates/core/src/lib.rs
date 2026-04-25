#![forbid(unsafe_code)]

pub mod article;
pub mod audit;
pub mod canonical;
pub mod error;
pub mod group_log;
pub mod hlc;
pub mod injection_source;
pub mod ipfs;
pub mod ipld;
pub mod migrations;
pub mod msgid_map;
pub mod rate_limiter;
pub mod signing;
pub mod util;
pub mod validation;

pub use article::{Article, ArticleBody, ArticleHeader, GroupName};
pub use error::{
    CoreError, ProtocolError, SigningError, StorageError, UsenetIpfsError, ValidationError,
};
pub use injection_source::{default_injection_source, InjectionSource};
pub use ipld::{ArticleMetadata, ArticleRootNode, MimeNode};
pub use validation::{check_duplicate, validate_article_ingress, MsgIdStorage, ValidationConfig};
