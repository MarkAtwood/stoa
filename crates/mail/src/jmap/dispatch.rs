use std::collections::HashMap;

use serde_json::{json, Value};

use super::types::{Invocation, MethodError, Request, Response};

/// Synchronous JMAP method handler.
///
/// Receives the argument object from the method call, returns the response object.
/// Returns `Err(MethodError)` to respond with an error invocation.
pub type HandlerFn = Box<dyn Fn(Value) -> Result<Value, MethodError> + Send + Sync>;

/// Dispatches JMAP method calls to registered handlers.
pub struct Dispatcher {
    handlers: HashMap<String, HandlerFn>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a method name.
    pub fn register(&mut self, method: impl Into<String>, handler: HandlerFn) {
        self.handlers.insert(method.into(), handler);
    }

    /// Dispatch a parsed JMAP [`Request`] and return a [`Response`].
    pub fn dispatch(&self, request: Request) -> Response {
        let mut method_responses = Vec::new();

        for Invocation(method_name, args, call_id) in request.method_calls {
            let response_invocation = match self.handlers.get(&method_name) {
                Some(handler) => match handler(args) {
                    Ok(result) => Invocation(method_name, result, call_id),
                    Err(err) => {
                        let err_val = serde_json::to_value(&err).unwrap_or(json!({}));
                        Invocation("error".to_string(), err_val, call_id)
                    }
                },
                None => {
                    let err = MethodError::unknown_method();
                    let err_val = serde_json::to_value(&err).unwrap_or(json!({}));
                    Invocation("error".to_string(), err_val, call_id)
                }
            };
            method_responses.push(response_invocation);
        }

        Response {
            method_responses,
            session_state: "0".to_string(),
            created_ids: None,
        }
    }

    /// Parse a JSON request body and dispatch it.
    ///
    /// Returns `Err(String)` for non-JSON or non-`Request` bodies (caller should return 400).
    pub fn dispatch_bytes(&self, body: &[u8]) -> Result<Response, String> {
        let request: Request = serde_json::from_slice(body).map_err(|e| format!("notJSON: {e}"))?;
        Ok(self.dispatch(request))
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dispatcher() -> Dispatcher {
        let mut d = Dispatcher::new();
        d.register("Core/echo", Box::new(|args| Ok(args)));
        d
    }

    #[test]
    fn unknown_method_returns_error_invocation() {
        let d = make_dispatcher();
        let req = Request {
            using: vec!["urn:ietf:params:jmap:core".to_string()],
            method_calls: vec![Invocation(
                "Nonexistent/method".to_string(),
                serde_json::json!({}),
                "c1".to_string(),
            )],
            created_ids: None,
        };
        let resp = d.dispatch(req);
        assert_eq!(resp.method_responses.len(), 1);
        let Invocation(name, args, call_id) = &resp.method_responses[0];
        assert_eq!(name, "error", "response method must be 'error'");
        assert_eq!(call_id, "c1");
        // MethodError::unknown_method() uses ErrorType::Other (serializes as "other")
        // with description "unknownMethod". Check the description field.
        let description = args
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            description, "unknownMethod",
            "error description must be 'unknownMethod'; got: {args}"
        );
    }

    #[test]
    fn known_method_echoes_args() {
        let d = make_dispatcher();
        let args = serde_json::json!({"key": "value"});
        let req = Request {
            using: vec![],
            method_calls: vec![Invocation(
                "Core/echo".to_string(),
                args.clone(),
                "c2".to_string(),
            )],
            created_ids: None,
        };
        let resp = d.dispatch(req);
        assert_eq!(resp.method_responses.len(), 1);
        let Invocation(name, result, _) = &resp.method_responses[0];
        assert_eq!(name, "Core/echo");
        assert_eq!(result, &args);
    }

    #[test]
    fn dispatch_bytes_invalid_json_returns_err() {
        let d = make_dispatcher();
        let result = d.dispatch_bytes(b"not json at all {{");
        assert!(result.is_err(), "invalid JSON must return Err");
    }

    #[test]
    fn dispatch_bytes_valid_request() {
        let d = make_dispatcher();
        let body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core"],
            "methodCalls": [["Core/echo", {"x": 1}, "c3"]]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let resp = d.dispatch_bytes(&bytes).unwrap();
        assert_eq!(resp.method_responses.len(), 1);
    }

    #[test]
    fn multiple_method_calls_all_dispatched() {
        let d = make_dispatcher();
        let req = Request {
            using: vec![],
            method_calls: vec![
                Invocation(
                    "Core/echo".to_string(),
                    serde_json::json!({}),
                    "c1".to_string(),
                ),
                Invocation(
                    "Unknown/method".to_string(),
                    serde_json::json!({}),
                    "c2".to_string(),
                ),
            ],
            created_ids: None,
        };
        let resp = d.dispatch(req);
        assert_eq!(resp.method_responses.len(), 2);
        assert_eq!(resp.method_responses[0].0, "Core/echo");
        assert_eq!(resp.method_responses[1].0, "error");
    }
}
