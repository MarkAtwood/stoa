//! Shared OpenTelemetry configuration for transit and reader daemons.
//!
//! This module contains only the configuration structure; actual OTel SDK
//! initialisation lives in each binary crate to avoid pulling heavy OTel
//! dependencies into every consumer of `stoa-core`.

use serde::Deserialize;

fn default_metrics_push_interval() -> u64 {
    60
}

fn default_trace_sample_rate() -> f64 {
    1.0
}

/// OpenTelemetry observability configuration.
///
/// All fields are optional.  OTLP export is disabled when `otlp_endpoint`
/// is absent — the Prometheus `/metrics` scrape endpoint continues to work
/// regardless of this section.
///
/// ```toml
/// [telemetry]
/// otlp_endpoint = "http://otel-collector:4318"
/// otlp_headers = ["Authorization=Bearer <token>"]
/// metrics_push_interval_secs = 60
/// trace_sample_rate = 1.0
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct TelemetryConfig {
    /// OTLP collector endpoint base URL (e.g. `"http://localhost:4318"`).
    ///
    /// The daemon appends `/v1/metrics` and `/v1/traces` to this base.
    /// When absent, OTLP export is disabled entirely and the section may
    /// be omitted from the config file.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,

    /// Extra HTTP headers for every OTLP request, in `"Key=Value"` format.
    ///
    /// Used to supply authentication tokens required by managed collectors
    /// (e.g. Grafana Cloud: `["Authorization=Bearer glc_xxx"]`).
    #[serde(default)]
    pub otlp_headers: Vec<String>,

    /// Interval between OTLP metrics pushes, in seconds.  Default: 60.
    #[serde(default = "default_metrics_push_interval")]
    pub metrics_push_interval_secs: u64,

    /// Fraction of traces to sample (0.0 – 1.0).  Default: 1.0 (all traces).
    ///
    /// For high-volume deployments, set to `0.1` to sample 10 % of traces.
    /// The Prometheus `/metrics` endpoint is unaffected by this value.
    #[serde(default = "default_trace_sample_rate")]
    pub trace_sample_rate: f64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            otlp_headers: Vec::new(),
            metrics_push_interval_secs: default_metrics_push_interval(),
            trace_sample_rate: default_trace_sample_rate(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = TelemetryConfig::default();
        assert!(cfg.otlp_endpoint.is_none(), "OTLP disabled by default");
        assert!(cfg.otlp_headers.is_empty());
        assert_eq!(cfg.metrics_push_interval_secs, 60);
        assert!((cfg.trace_sample_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn deserializes_from_toml() {
        let toml = r#"
            otlp_endpoint = "http://otel:4318"
            otlp_headers = ["Authorization=Bearer tok"]
            metrics_push_interval_secs = 30
            trace_sample_rate = 0.5
        "#;
        let cfg: TelemetryConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.otlp_endpoint.as_deref(), Some("http://otel:4318"));
        assert_eq!(cfg.otlp_headers, ["Authorization=Bearer tok"]);
        assert_eq!(cfg.metrics_push_interval_secs, 30);
        assert!((cfg.trace_sample_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_section_uses_defaults() {
        let cfg: TelemetryConfig = toml::from_str("").expect("parse empty");
        assert!(cfg.otlp_endpoint.is_none());
        assert_eq!(cfg.metrics_push_interval_secs, 60);
    }
}
