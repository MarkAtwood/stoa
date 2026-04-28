//! Prometheus metrics for the transit daemon.

use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram, register_histogram_vec,
    register_int_counter, register_int_gauge,
};

lazy_static::lazy_static! {
    pub static ref ARTICLES_INGESTED_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "articles_ingested_total",
            "Total number of articles ingested by the transit daemon"
        )
        .expect("failed to register articles_ingested_total");

    pub static ref IPFS_WRITE_LATENCY_SECONDS: prometheus::Histogram =
        register_histogram!(
            "ipfs_write_latency_seconds",
            "Latency of IPFS block write operations in seconds",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
        )
        .expect("failed to register ipfs_write_latency_seconds");

    pub static ref GC_ARTICLES_UNPINNED_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "gc_articles_unpinned_total",
            "Total number of articles unpinned by the garbage collector"
        )
        .expect("failed to register gc_articles_unpinned_total");

    pub static ref GC_RUNS_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "gc_runs_total",
            "Total number of GC runs completed (including no-op runs)"
        )
        .expect("failed to register gc_runs_total");

    pub static ref GC_ARTICLES_DELETED_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "gc_articles_deleted_total",
            "Total number of articles deleted (unpinned) by GC runs"
        )
        .expect("failed to register gc_articles_deleted_total");

    pub static ref GC_BYTES_RECLAIMED_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "gc_bytes_reclaimed_total",
            "Total bytes reclaimed by GC runs (sum of deleted article byte_count)"
        )
        .expect("failed to register gc_bytes_reclaimed_total");

    pub static ref GOSSIP_MESSAGES_PUBLISHED_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "gossip_messages_published_total",
            "Total number of gossipsub messages published"
        )
        .expect("failed to register gossip_messages_published_total");

    pub static ref GOSSIP_MESSAGES_DROPPED_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "gossip_messages_dropped_total",
            "Total number of gossipsub messages dropped"
        )
        .expect("failed to register gossip_messages_dropped_total");

    pub static ref PEER_CONNECTIONS_ACTIVE: prometheus::IntGauge =
        register_int_gauge!(
            "peer_connections_active",
            "Number of currently active peer connections"
        )
        .expect("failed to register peer_connections_active");

    pub static ref ARTICLES_SERVED_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "articles_served_total",
            "Total number of articles served by the reader daemon"
        )
        .expect("failed to register articles_served_total");

    pub static ref GROUPS_SERVED: prometheus::IntGauge =
        register_int_gauge!(
            "groups_served",
            "Number of newsgroups currently served"
        )
        .expect("failed to register groups_served");

    pub static ref PINNED_ARTICLES_TOTAL: prometheus::IntGauge =
        register_int_gauge!(
            "pinned_articles_total",
            "Total number of pinned articles"
        )
        .expect("failed to register pinned_articles_total");

    pub static ref INGESTION_QUEUE_DEPTH: prometheus::IntGauge =
        register_int_gauge!(
            "ingestion_queue_depth",
            "Current number of articles waiting in the ingestion queue"
        )
        .expect("failed to register ingestion_queue_depth");

    pub static ref NNTP_COMMAND_DURATION_SECONDS: prometheus::HistogramVec =
        register_histogram_vec!(
            "nntp_command_duration_seconds",
            "Duration of NNTP command handling in seconds",
            &["command"],
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
        )
        .expect("failed to register nntp_command_duration_seconds");

    pub static ref ARTICLES_INGESTED_GROUP_TOTAL: prometheus::CounterVec =
        register_counter_vec!(
            "articles_ingested_group_total",
            "Articles ingested, labeled by newsgroup",
            &["group"]
        )
        .expect("failed to register articles_ingested_group_total");

    pub static ref ARTICLES_REJECTED_TOTAL: prometheus::CounterVec =
        register_counter_vec!(
            "articles_rejected_total",
            "Articles rejected during ingestion, labeled by reason",
            &["reason"]
        )
        .expect("failed to register articles_rejected_total");

    pub static ref INGEST_BACKPRESSURE_TOTAL: prometheus::IntCounter =
        register_int_counter!(
            "ingest_backpressure_total",
            "Total articles rejected due to ingestion queue high-water mark (backpressure)"
        )
        .expect("failed to register ingest_backpressure_total");

    /// Articles rejected at the pipeline stage (after dequeue), labeled by
    /// newsgroup and failure reason.  Only emitted when the group name is known;
    /// pre-parse rejections (malformed, size, duplicate) use
    /// `articles_rejected_total{reason}` instead.
    ///
    /// Reason values: `invalid_group_name`, `log_tip_error`, `log_append_error`,
    /// `signature_error`.
    pub static ref ARTICLES_REJECTED_GROUP_TOTAL: prometheus::CounterVec =
        register_counter_vec!(
            "articles_rejected_group_total",
            "Articles rejected at the pipeline stage, labeled by group and reason",
            &["group", "reason"]
        )
        .expect("failed to register articles_rejected_group_total");

    // ── Per-group sampled gauges (updated by group_metrics::run_group_metrics_sampler) ──

    /// Current number of articles stored for each newsgroup.
    ///
    /// Sampled periodically from the `articles` table.
    /// Absent until the first sample completes.
    /// Not emitted when >500 distinct groups are active (high-cardinality guard).
    pub static ref GROUP_LOG_ENTRIES_TOTAL: prometheus::GaugeVec =
        register_gauge_vec!(
            "group_log_entries_total",
            "Number of articles stored for this newsgroup (sampled)",
            &["group"]
        )
        .expect("failed to register group_log_entries_total");

    /// Total stored bytes for each newsgroup.
    ///
    /// Sampled periodically from the `articles` table.
    pub static ref GROUP_STORAGE_BYTES: prometheus::GaugeVec =
        register_gauge_vec!(
            "group_storage_bytes",
            "Total stored bytes for this newsgroup (sampled)",
            &["group"]
        )
        .expect("failed to register group_storage_bytes");

    /// Unix timestamp (seconds) of the most recently ingested article per group.
    ///
    /// Sampled periodically from the `articles` table.
    pub static ref GROUP_LAST_ACTIVITY_TIMESTAMP: prometheus::GaugeVec =
        register_gauge_vec!(
            "group_last_activity_timestamp",
            "Unix timestamp of the most recently ingested article for this group (sampled)",
            &["group"]
        )
        .expect("failed to register group_last_activity_timestamp");

    /// Unix timestamp of each configured TLS certificate's NotAfter date.
    ///
    /// Labels: `path` — the filesystem path of the certificate file.
    /// Updated at startup (and on config reload when implemented).
    /// Absent from `/metrics` output until at least one cert is configured.
    pub static ref TLS_CERT_EXPIRY_SECONDS: prometheus::GaugeVec =
        register_gauge_vec!(
            "tls_cert_expiry_seconds",
            "Unix timestamp of TLS certificate expiry (NotAfter), labeled by cert path",
            &["path"]
        )
        .expect("failed to register tls_cert_expiry_seconds");

    // ── Kubo circuit breaker ───────────────────────────────────────────────────

    /// Current circuit breaker state for the Kubo IPFS backend.
    ///
    /// Encoding: 0 = closed (normal), 1 = half-open (probing), 2 = open (failing fast).
    /// Absent from `/metrics` output until the first state transition occurs.
    pub static ref KUBO_CIRCUIT_BREAKER_STATE: prometheus::IntGauge =
        register_int_gauge!(
            "kubo_circuit_breaker_state",
            "Current Kubo circuit breaker state: 0=closed, 1=half-open, 2=open"
        )
        .expect("failed to register kubo_circuit_breaker_state");

    /// Total number of Kubo circuit breaker state transitions, labeled by
    /// `from_state` and `to_state` (values: `closed`, `open`, `half-open`).
    pub static ref KUBO_CIRCUIT_BREAKER_TRANSITIONS_TOTAL: prometheus::CounterVec =
        register_counter_vec!(
            "kubo_circuit_breaker_transitions_total",
            "Total Kubo circuit breaker state transitions, labeled by from_state and to_state",
            &["from_state", "to_state"]
        )
        .expect("failed to register kubo_circuit_breaker_transitions_total");
}

/// Returns all metrics in Prometheus text format.
pub fn gather_metrics() -> String {
    // Force initialisation of all statics before gathering.
    lazy_static::initialize(&ARTICLES_INGESTED_TOTAL);
    lazy_static::initialize(&IPFS_WRITE_LATENCY_SECONDS);
    lazy_static::initialize(&GC_ARTICLES_UNPINNED_TOTAL);
    lazy_static::initialize(&GC_RUNS_TOTAL);
    lazy_static::initialize(&GC_ARTICLES_DELETED_TOTAL);
    lazy_static::initialize(&GC_BYTES_RECLAIMED_TOTAL);
    lazy_static::initialize(&GOSSIP_MESSAGES_PUBLISHED_TOTAL);
    lazy_static::initialize(&GOSSIP_MESSAGES_DROPPED_TOTAL);
    lazy_static::initialize(&PEER_CONNECTIONS_ACTIVE);
    lazy_static::initialize(&ARTICLES_SERVED_TOTAL);
    lazy_static::initialize(&GROUPS_SERVED);
    lazy_static::initialize(&PINNED_ARTICLES_TOTAL);
    lazy_static::initialize(&INGESTION_QUEUE_DEPTH);
    lazy_static::initialize(&NNTP_COMMAND_DURATION_SECONDS);
    lazy_static::initialize(&ARTICLES_INGESTED_GROUP_TOTAL);
    lazy_static::initialize(&ARTICLES_REJECTED_TOTAL);
    lazy_static::initialize(&INGEST_BACKPRESSURE_TOTAL);
    lazy_static::initialize(&TLS_CERT_EXPIRY_SECONDS);
    lazy_static::initialize(&ARTICLES_REJECTED_GROUP_TOTAL);
    lazy_static::initialize(&GROUP_LOG_ENTRIES_TOTAL);
    lazy_static::initialize(&GROUP_STORAGE_BYTES);
    lazy_static::initialize(&GROUP_LAST_ACTIVITY_TIMESTAMP);
    lazy_static::initialize(&KUBO_CIRCUIT_BREAKER_STATE);
    lazy_static::initialize(&KUBO_CIRCUIT_BREAKER_TRANSITIONS_TOTAL);

    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::new();
    encoder
        .encode(&metric_families, &mut buf)
        .unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}

/// Start an HTTP server on `addr` that serves GET /metrics.
/// Spawns a tokio task and returns immediately.
pub fn start_metrics_server(addr: std::net::SocketAddr) {
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("metrics server failed to bind {addr}: {e}");
                return;
            }
        };
        tracing::info!("metrics server listening on {addr}");
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    tokio::spawn(async move {
                        if let Err(e) = handle_metrics_connection(stream).await {
                            tracing::warn!("metrics connection error from {peer}: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("metrics server accept error: {e}");
                }
            }
        }
    });
}

async fn handle_metrics_connection(
    mut stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");

    // Extract the request line (first line before \r\n or \n).
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let response = if method == "GET" && path == "/metrics" {
        let body = gather_metrics();
        let body_bytes = body.as_bytes();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
            body_bytes.len(),
            body
        )
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
    };

    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_names_present() {
        // HistogramVec metrics only appear in Prometheus text output after at
        // least one label combination is observed (unlike plain counters/gauges
        // which always appear at 0).  Observe a sentinel value so this test is
        // deterministic regardless of which other tests ran first.
        NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&["__test__"])
            .observe(0.0);
        let output = gather_metrics();
        assert!(
            output.contains("articles_ingested_total"),
            "missing articles_ingested_total in:\n{output}"
        );
        assert!(
            output.contains("ipfs_write_latency_seconds"),
            "missing ipfs_write_latency_seconds in:\n{output}"
        );
        assert!(
            output.contains("gc_articles_unpinned_total"),
            "missing gc_articles_unpinned_total in:\n{output}"
        );
        assert!(
            output.contains("gossip_messages_published_total"),
            "missing gossip_messages_published_total in:\n{output}"
        );
        assert!(
            output.contains("gossip_messages_dropped_total"),
            "missing gossip_messages_dropped_total in:\n{output}"
        );
        assert!(
            output.contains("peer_connections_active"),
            "missing peer_connections_active in:\n{output}"
        );
        assert!(
            output.contains("articles_served_total"),
            "missing articles_served_total in:\n{output}"
        );
        assert!(
            output.contains("groups_served"),
            "missing groups_served in:\n{output}"
        );
        assert!(
            output.contains("pinned_articles_total"),
            "missing pinned_articles_total in:\n{output}"
        );
        assert!(
            output.contains("nntp_command_duration_seconds"),
            "missing nntp_command_duration_seconds in:\n{output}"
        );
        assert!(
            output.contains("ingestion_queue_depth"),
            "missing ingestion_queue_depth in:\n{output}"
        );
        assert!(
            output.contains("kubo_circuit_breaker_state"),
            "missing kubo_circuit_breaker_state in:\n{output}"
        );
    }

    #[test]
    fn counter_increments() {
        ARTICLES_INGESTED_TOTAL.inc();
        let output = gather_metrics();
        assert!(
            output.contains("articles_ingested_total"),
            "missing articles_ingested_total after increment in:\n{output}"
        );
    }

    #[test]
    fn histogram_vec_label_present() {
        // Record one observation for a known command label.
        NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&["GROUP"])
            .observe(0.01);
        let output = gather_metrics();
        assert!(output.contains("nntp_command_duration_seconds"));
    }

    #[test]
    fn group_counter_increments() {
        ARTICLES_INGESTED_GROUP_TOTAL
            .with_label_values(&["comp.lang.rust"])
            .inc();
        let output = gather_metrics();
        assert!(output.contains("articles_ingested_group_total"));
    }

    #[test]
    fn rejected_counter_increments() {
        ARTICLES_REJECTED_TOTAL
            .with_label_values(&["duplicate"])
            .inc();
        let output = gather_metrics();
        assert!(output.contains("articles_rejected_total"));
    }

    #[test]
    fn rejected_group_counter_increments() {
        ARTICLES_REJECTED_GROUP_TOTAL
            .with_label_values(&["comp.test", "log_append_error"])
            .inc();
        let output = gather_metrics();
        assert!(
            output.contains("articles_rejected_group_total"),
            "missing articles_rejected_group_total in:\n{output}"
        );
    }
}
