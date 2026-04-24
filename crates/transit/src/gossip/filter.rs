//! In-topic group-name filter for gossipsub messages.
//!
//! Gossipsub delivers messages at hierarchy granularity (`stoa.hier.comp`).
//! The `GroupFilter` reads `group_name` from the message JSON payload and
//! dispatches to the handler for that specific group, or drops the message
//! if the local node does not serve the group.

use std::collections::{HashMap, HashSet};

/// A handler function called when a message for a subscribed group arrives.
pub type GroupHandler = Box<dyn Fn(Vec<u8>) + Send + Sync>;

/// Filter and dispatch layer for in-topic group-name routing.
pub struct GroupFilter {
    /// Groups this node subscribes to.
    subscribed: HashSet<String>,
    /// Per-group message handlers.
    handlers: HashMap<String, GroupHandler>,
    /// Counter of messages dispatched.
    dispatched: u64,
    /// Counter of messages dropped (group not subscribed).
    dropped: u64,
}

impl GroupFilter {
    pub fn new() -> Self {
        Self {
            subscribed: HashSet::new(),
            handlers: HashMap::new(),
            dispatched: 0,
            dropped: 0,
        }
    }

    /// Register a handler for a specific group.
    ///
    /// Also marks the group as subscribed. Replaces any existing handler.
    pub fn subscribe(&mut self, group_name: &str, handler: GroupHandler) {
        self.subscribed.insert(group_name.to_owned());
        self.handlers.insert(group_name.to_owned(), handler);
    }

    /// Unsubscribe from a group and remove its handler.
    pub fn unsubscribe(&mut self, group_name: &str) {
        self.subscribed.remove(group_name);
        self.handlers.remove(group_name);
    }

    /// Process an incoming gossipsub message payload.
    ///
    /// Parses `group_name` from the JSON bytes. If the group is subscribed,
    /// calls the registered handler. Otherwise, drops the message silently
    /// (logs at debug level).
    ///
    /// Returns `true` if the message was dispatched, `false` if dropped.
    pub fn handle(&mut self, message_bytes: Vec<u8>) -> bool {
        let group_name = match extract_group_name(&message_bytes) {
            Some(g) => g,
            None => {
                tracing::debug!("gossip filter: message has no group_name field, dropping");
                self.dropped += 1;
                return false;
            }
        };

        if !self.subscribed.contains(&group_name) {
            tracing::debug!(
                group = %group_name,
                "gossip filter: dropping message for unsubscribed group"
            );
            self.dropped += 1;
            return false;
        }

        if let Some(handler) = self.handlers.get(&group_name) {
            handler(message_bytes);
            self.dispatched += 1;
            true
        } else {
            // Subscribed but no handler registered (shouldn't happen).
            tracing::warn!(group = %group_name, "gossip filter: subscribed group has no handler");
            self.dropped += 1;
            false
        }
    }

    /// Number of messages successfully dispatched.
    pub fn dispatched(&self) -> u64 {
        self.dispatched
    }

    /// Number of messages dropped.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl Default for GroupFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the `group_name` field from a JSON message payload.
fn extract_group_name(bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    v.get("group_name")?.as_str().map(|s| s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn make_message(group: &str) -> Vec<u8> {
        serde_json::json!({
            "group_name": group,
            "tip_cids": ["bafytest"],
            "hlc_ms": 1700000000000u64,
            "hlc_logical": 0,
            "hlc_node_id": "0102030405060708",
            "sender_peer_id": "12D3KooWTest",
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn subscribed_message_is_dispatched() {
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let received_clone = Arc::clone(&received);

        let mut filter = GroupFilter::new();
        filter.subscribe(
            "comp.lang.rust",
            Box::new(move |msg| received_clone.lock().unwrap().push(msg)),
        );

        let dispatched = filter.handle(make_message("comp.lang.rust"));
        assert!(dispatched);
        assert_eq!(filter.dispatched(), 1);
        assert_eq!(filter.dropped(), 0);
        assert_eq!(received.lock().unwrap().len(), 1);
    }

    #[test]
    fn unsubscribed_message_is_dropped() {
        let mut filter = GroupFilter::new();
        filter.subscribe("comp.lang.rust", Box::new(|_| {}));

        let dispatched = filter.handle(make_message("sci.math"));
        assert!(!dispatched);
        assert_eq!(filter.dropped(), 1);
        assert_eq!(filter.dispatched(), 0);
    }

    #[test]
    fn malformed_message_is_dropped() {
        let mut filter = GroupFilter::new();
        filter.subscribe("comp.lang.rust", Box::new(|_| {}));

        let dispatched = filter.handle(b"not valid json".to_vec());
        assert!(!dispatched);
        assert_eq!(filter.dropped(), 1);
    }

    #[test]
    fn multiple_groups_dispatch_independently() {
        let comp_msgs = Arc::new(Mutex::new(0u32));
        let sci_msgs = Arc::new(Mutex::new(0u32));

        let comp_clone = Arc::clone(&comp_msgs);
        let sci_clone = Arc::clone(&sci_msgs);

        let mut filter = GroupFilter::new();
        filter.subscribe(
            "comp.lang.rust",
            Box::new(move |_| {
                *comp_clone.lock().unwrap() += 1;
            }),
        );
        filter.subscribe(
            "sci.math",
            Box::new(move |_| {
                *sci_clone.lock().unwrap() += 1;
            }),
        );

        for _ in 0..10 {
            filter.handle(make_message("comp.lang.rust"));
            filter.handle(make_message("sci.math"));
        }

        assert_eq!(*comp_msgs.lock().unwrap(), 10);
        assert_eq!(*sci_msgs.lock().unwrap(), 10);
        assert_eq!(filter.dispatched(), 20);
        assert_eq!(filter.dropped(), 0);
    }

    #[test]
    fn inject_100_messages_for_10_groups_each_handler_receives_only_own() {
        let counters: Vec<Arc<Mutex<u32>>> = (0..10).map(|_| Arc::new(Mutex::new(0u32))).collect();

        let mut filter = GroupFilter::new();
        for i in 0..10 {
            let counter = Arc::clone(&counters[i]);
            let group = format!("comp.group.{i}");
            filter.subscribe(
                &group,
                Box::new(move |_| {
                    *counter.lock().unwrap() += 1;
                }),
            );
        }

        for i in 0..10 {
            for _ in 0..10 {
                filter.handle(make_message(&format!("comp.group.{i}")));
            }
        }

        for (i, counter) in counters.iter().enumerate() {
            assert_eq!(
                *counter.lock().unwrap(),
                10,
                "handler for group {i} should have received exactly 10 messages"
            );
        }
        assert_eq!(filter.dispatched(), 100);
        assert_eq!(filter.dropped(), 0);
    }

    #[test]
    fn unsubscribe_stops_dispatch() {
        let received = Arc::new(Mutex::new(0u32));
        let received_clone = Arc::clone(&received);

        let mut filter = GroupFilter::new();
        filter.subscribe(
            "comp.lang.rust",
            Box::new(move |_| {
                *received_clone.lock().unwrap() += 1;
            }),
        );

        filter.handle(make_message("comp.lang.rust"));
        filter.unsubscribe("comp.lang.rust");
        filter.handle(make_message("comp.lang.rust"));

        assert_eq!(*received.lock().unwrap(), 1);
        assert_eq!(filter.dispatched(), 1);
        assert_eq!(filter.dropped(), 1);
    }
}
