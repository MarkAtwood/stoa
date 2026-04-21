use std::time::SystemTime;
use tokio::sync::mpsc;

/// A complete inbound SMTP message, ready for the auth+routing pipeline.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// SMTP envelope sender (from MAIL FROM command), empty string for null sender.
    pub envelope_from: String,
    /// SMTP envelope recipients (from RCPT TO commands).
    pub envelope_to: Vec<String>,
    /// Raw RFC 5322 message bytes as received (dot-unstuffed).
    pub raw_bytes: Vec<u8>,
    /// Wall-clock time the DATA phase completed.
    pub received_at: SystemTime,
    /// Peer IP:port of the sending client.
    pub peer_addr: String,
}

/// Sender half of the inbound message queue.
#[derive(Clone)]
pub struct MessageQueue(mpsc::UnboundedSender<IncomingMessage>);

impl MessageQueue {
    /// Create a new queue. Returns the sender (MessageQueue) and receiver.
    pub fn new() -> (MessageQueue, mpsc::UnboundedReceiver<IncomingMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (MessageQueue(tx), rx)
    }

    /// Enqueue a message. Logs a warning if the receiver has been dropped.
    pub fn enqueue(&self, msg: IncomingMessage) {
        if self.0.send(msg).is_err() {
            tracing::warn!("smtp: message queue receiver dropped — message lost");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message(envelope_from: &str) -> IncomingMessage {
        IncomingMessage {
            envelope_from: envelope_from.to_string(),
            envelope_to: vec!["recipient@example.com".to_string()],
            raw_bytes: b"From: sender@example.com\r\nSubject: test\r\n\r\nbody\r\n".to_vec(),
            received_at: SystemTime::UNIX_EPOCH,
            peer_addr: "127.0.0.1:12345".to_string(),
        }
    }

    #[tokio::test]
    async fn enqueue_and_receive_message() {
        let (queue, mut rx) = MessageQueue::new();
        queue.enqueue(sample_message("sender@example.com"));
        let received = rx.recv().await.expect("should receive message");
        assert_eq!(received.envelope_from, "sender@example.com");
    }

    #[tokio::test]
    async fn enqueue_after_receiver_dropped_does_not_panic() {
        let (queue, rx) = MessageQueue::new();
        drop(rx);
        // Must not panic; warning is logged but we cannot assert on it without tracing-test.
        queue.enqueue(sample_message("sender@example.com"));
    }
}
