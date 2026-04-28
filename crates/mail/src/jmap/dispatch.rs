use serde_json::Value;

use super::types::MethodError;

/// Synchronous JMAP method handler.
///
/// Receives the argument object from the method call, returns the response object.
/// Returns `Err(MethodError)` to respond with an error invocation.
pub type HandlerFn = Box<dyn Fn(Value) -> Result<Value, MethodError> + Send + Sync>;
