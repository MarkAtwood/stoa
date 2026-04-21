use std::sync::Arc;

use mail_auth::MessageAuthenticator;
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::queue::MessageQueue;
use crate::session::run_session;

/// Accept connections on both port-25 and port-587 listeners, spawning a
/// `run_session` task for each.  Returns when both listeners close or an
/// unrecoverable error occurs.
pub async fn run_server(
    listener_25: TcpListener,
    listener_587: TcpListener,
    config: Arc<Config>,
    queue: MessageQueue,
    pool: Option<SqlitePool>,
) {
    let auth: Option<Arc<MessageAuthenticator>> =
        match MessageAuthenticator::new_cloudflare() {
            Ok(a) => {
                info!("inbound auth (SPF/DKIM/DMARC/ARC) enabled via Cloudflare DNS");
                Some(Arc::new(a))
            }
            Err(e) => {
                warn!("failed to create DNS resolver — inbound auth disabled: {e}");
                None
            }
        };

    let semaphore = Arc::new(Semaphore::new(config.limits.max_connections));

    loop {
        // Acquire a permit before accepting so we apply back-pressure when
        // the connection limit is reached (same pattern as usenet-ipfs-reader).
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                warn!("connection semaphore closed, stopping accept loop");
                break;
            }
        };

        let (stream, peer_addr) = tokio::select! {
            result = listener_25.accept() => match result {
                Ok(pair) => pair,
                Err(e) => {
                    error!("port_25 accept error: {e}");
                    drop(permit);
                    continue;
                }
            },
            result = listener_587.accept() => match result {
                Ok(pair) => pair,
                Err(e) => {
                    error!("port_587 accept error: {e}");
                    drop(permit);
                    continue;
                }
            },
        };

        let peer_str = peer_addr.to_string();
        info!(%peer_str, "accepted connection");

        let config = config.clone();
        let queue = queue.clone();
        let auth = auth.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when session task ends
            run_session(stream, peer_str, config, queue, auth, pool).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DatabaseConfig, LimitsConfig, ListenConfig, LogConfig, ReaderConfig, TlsConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            hostname: "test.example.com".to_string(),
            listen: ListenConfig {
                port_25: "127.0.0.1:0".to_string(),
                port_587: "127.0.0.1:0".to_string(),
            },
            tls: TlsConfig { cert_path: None, key_path: None },
            limits: LimitsConfig {
                max_message_bytes: 1_048_576,
                max_recipients: 10,
                command_timeout_secs: 300,
                max_connections: 10,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: "text".to_string(),
            },
            reader: ReaderConfig::default(),
            list_routing: vec![],
            users: vec![],
            database: DatabaseConfig::default(),
        })
    }

    /// Spin up run_server on ephemeral ports and verify the greeting arrives.
    #[tokio::test]
    async fn server_sends_greeting_on_connect() {
        let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_25 = listener_25.local_addr().unwrap();

        let config = test_config();
        let (queue, _rx) = MessageQueue::new();

        tokio::spawn(run_server(listener_25, listener_587, config, queue, None));

        let mut client = tokio::net::TcpStream::connect(addr_25).await.unwrap();
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let greeting = std::str::from_utf8(&buf[..n]).unwrap();

        assert!(
            greeting.starts_with("220 "),
            "expected SMTP greeting, got: {greeting:?}"
        );
    }

    /// Two simultaneous connections both get greeted (semaphore not exhausted).
    #[tokio::test]
    async fn server_handles_multiple_connections() {
        let listener_25 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_587 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_25 = listener_25.local_addr().unwrap();
        let addr_587 = listener_587.local_addr().unwrap();

        let config = test_config();
        let (queue, _rx) = MessageQueue::new();

        tokio::spawn(run_server(listener_25, listener_587, config, queue, None));

        // Connect to port_25 and port_587 concurrently.
        let (c1, c2) = tokio::join!(
            tokio::net::TcpStream::connect(addr_25),
            tokio::net::TcpStream::connect(addr_587),
        );
        let mut c1 = c1.unwrap();
        let mut c2 = c2.unwrap();

        let mut buf1 = [0u8; 256];
        let mut buf2 = [0u8; 256];
        let (n1, n2) = tokio::join!(c1.read(&mut buf1), c2.read(&mut buf2));

        let g1 = std::str::from_utf8(&buf1[..n1.unwrap()]).unwrap();
        let g2 = std::str::from_utf8(&buf2[..n2.unwrap()]).unwrap();

        assert!(g1.starts_with("220 "), "conn1 expected 220: {g1:?}");
        assert!(g2.starts_with("220 "), "conn2 expected 220: {g2:?}");

        // Send QUIT on both connections.
        c1.write_all(b"QUIT\r\n").await.unwrap();
        c2.write_all(b"QUIT\r\n").await.unwrap();
    }
}
