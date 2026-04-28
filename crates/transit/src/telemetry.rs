//! OpenTelemetry SDK initialisation for stoa-transit.
//!
//! The `init_telemetry` function is called once in `main` and the returned
//! `OtelGuard` is held for the process lifetime.  On drop, the meter provider
//! is flushed and shut down.
//!
//! When `config.otlp_endpoint` is absent, this is a no-op: the Prometheus
//! scrape endpoint continues to work regardless.

use std::{collections::HashMap, time::Duration};
use stoa_core::telemetry::TelemetryConfig;
use tracing::warn;

/// Holds the active `SdkMeterProvider`; shuts it down cleanly on drop.
pub struct OtelGuard {
    meter_provider: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.meter_provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("OTel metrics shutdown error: {e}");
            }
        }
    }
}

/// Initialise OTLP metrics export.
///
/// Returns a guard that must be held for the process lifetime (assign to a
/// `let _otel_guard` binding in `main`).  When `otlp_endpoint` is absent the
/// guard is a no-op.
pub fn init_telemetry(config: &TelemetryConfig) -> OtelGuard {
    let endpoint = match config.otlp_endpoint.as_deref() {
        Some(ep) => ep,
        None => return OtelGuard { meter_provider: None },
    };

    let headers: HashMap<String, String> = config
        .otlp_headers
        .iter()
        .filter_map(|h| h.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();

    match build_meter_provider(endpoint, headers, config.metrics_push_interval_secs) {
        Ok(provider) => {
            opentelemetry::global::set_meter_provider(provider.clone());
            OtelGuard {
                meter_provider: Some(provider),
            }
        }
        Err(e) => {
            warn!("OTel OTLP init failed: {e}; continuing without OTLP push");
            OtelGuard { meter_provider: None }
        }
    }
}

fn build_meter_provider(
    endpoint: &str,
    headers: HashMap<String, String>,
    interval_secs: u64,
) -> Result<opentelemetry_sdk::metrics::SdkMeterProvider, Box<dyn std::error::Error + Send + Sync>>
{
    use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(format!("{endpoint}/v1/metrics"))
        .with_headers(headers)
        .build()?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(interval_secs))
        .build();

    Ok(SdkMeterProvider::builder().with_reader(reader).build())
}
