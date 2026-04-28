//! Prometheus metrics for the reader daemon.

use prometheus::{register_gauge_vec, register_histogram_vec, GaugeVec, HistogramVec};

lazy_static::lazy_static! {
    pub static ref NNTP_COMMAND_DURATION_SECONDS: HistogramVec =
        register_histogram_vec!(
            "nntp_command_duration_seconds",
            "Duration of NNTP command handling in seconds, labeled by command name",
            &["command"],
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
        )
        .expect("failed to register nntp_command_duration_seconds");

    /// Unix timestamp of each configured TLS certificate's NotAfter date.
    ///
    /// Labels: `path` — the filesystem path of the certificate file.
    /// Updated at startup and on `/reload`.  Absent until at least one cert
    /// is configured.
    pub static ref TLS_CERT_EXPIRY_SECONDS: GaugeVec =
        register_gauge_vec!(
            "tls_cert_expiry_seconds",
            "Unix timestamp of TLS certificate expiry (NotAfter), labeled by cert path",
            &["path"]
        )
        .expect("failed to register tls_cert_expiry_seconds");
}

/// Returns all reader metrics in Prometheus text format.
pub fn gather_metrics() -> String {
    lazy_static::initialize(&NNTP_COMMAND_DURATION_SECONDS);
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::new();
    encoder
        .encode(&metric_families, &mut buf)
        .unwrap_or_default();
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_name_present() {
        // Prometheus only emits a metric family once at least one label-value
        // combination has been observed; make a zero-duration observation to
        // ensure the family appears in gather() output.
        NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&["CAPABILITIES"])
            .observe(0.0);
        let output = gather_metrics();
        assert!(
            output.contains("nntp_command_duration_seconds"),
            "output: {output}"
        );
    }

    #[test]
    fn histogram_records_observation() {
        NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&["ARTICLE"])
            .observe(0.001);
        NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&["OVER"])
            .observe(0.002);
        NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&["POST"])
            .observe(0.5);
        NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&["GROUP"])
            .observe(0.003);
        NNTP_COMMAND_DURATION_SECONDS
            .with_label_values(&["HEAD"])
            .observe(0.001);
        let output = gather_metrics();
        assert!(output.contains("nntp_command_duration_seconds_count"));
    }
}
