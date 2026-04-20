//! Prometheus metrics for the transit daemon.

use prometheus::{register_histogram, register_int_counter, register_int_gauge};

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
}

/// Returns all metrics in Prometheus text format.
pub fn gather_metrics() -> String {
    // Force initialisation of all statics before gathering.
    lazy_static::initialize(&ARTICLES_INGESTED_TOTAL);
    lazy_static::initialize(&IPFS_WRITE_LATENCY_SECONDS);
    lazy_static::initialize(&GC_ARTICLES_UNPINNED_TOTAL);
    lazy_static::initialize(&GOSSIP_MESSAGES_PUBLISHED_TOTAL);
    lazy_static::initialize(&GOSSIP_MESSAGES_DROPPED_TOTAL);
    lazy_static::initialize(&PEER_CONNECTIONS_ACTIVE);

    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::new();
    encoder.encode(&metric_families, &mut buf).unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_names_present() {
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
}
