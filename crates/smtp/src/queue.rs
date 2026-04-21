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
pub struct MessageQueue(mpsc::Sender<IncomingMessage>);

impl MessageQueue {
    /// Create a new bounded queue.  Returns the sender (MessageQueue) and receiver.
    ///
    /// `capacity` sets the maximum number of in-flight messages.  When the
    /// queue is full, [`enqueue`](Self::enqueue) returns `false` so the caller
    /// can issue a 452 transient error and let the sending MTA retry.
    pub fn new(capacity: usize) -> (MessageQueue, mpsc::Receiver<IncomingMessage>) {
        let (tx, rx) = mpsc::channel(capacity);
        (MessageQueue(tx), rx)
    }

    /// Try to enqueue a message.
    ///
    /// Returns `true` if the message was accepted, `false` if the queue is
    /// full or the receiver has been dropped.  Logs a warning on failure.
    pub fn enqueue(&self, msg: IncomingMessage) -> bool {
        match self.0.try_send(msg) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("smtp: message queue full — rejecting message with 452");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("smtp: message queue receiver dropped — message lost");
                false
            }
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
        let (queue, mut rx) = MessageQueue::new(10);
        assert!(queue.enqueue(sample_message("sender@example.com")));
        let received = rx.recv().await.expect("should receive message");
        assert_eq!(received.envelope_from, "sender@example.com");
    }

    #[tokio::test]
    async fn enqueue_returns_false_when_full() {
        let (queue, _rx) = MessageQueue::new(2);
        assert!(queue.enqueue(sample_message("a@example.com")));
        assert!(queue.enqueue(sample_message("b@example.com")));
        assert!(!queue.enqueue(sample_message("c@example.com")));
    }

    #[tokio::test]
    async fn enqueue_after_receiver_dropped_returns_false() {
        let (queue, rx) = MessageQueue::new(10);
        drop(rx);
        assert!(!queue.enqueue(sample_message("sender@example.com")));
    }
}
