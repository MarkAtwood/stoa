//! JMAP wire types for stoa-mail — re-exported from `jmap-types`.
//!
//! All internal stoa-mail modules import from here rather than from
//! `jmap_types` directly so this file is the single point of control.

/// Canonical JMAP request envelope (RFC 8620 §3.3).
pub use jmap_types::JmapRequest as Request;

/// Canonical JMAP response envelope (RFC 8620 §3.4).
pub use jmap_types::JmapResponse as Response;

/// A JMAP method invocation: `(method_name, arguments, call_id)`.
pub use jmap_types::wire::Invocation;

/// Method-level JMAP error (RFC 8620 §3.6.2).
///
/// Alias for [`jmap_types::JmapError`].  Handler modules use this alias
/// so they don't need to import `jmap_types` directly.
pub use jmap_types::JmapError as MethodError;
