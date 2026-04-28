//! OpenTelemetry SDK initialisation for stoa-reader.
//!
//! Call `init_telemetry` once at the start of `main` (after logging setup) and
//! hold the returned `OtelGuard` alive for the process lifetime.  On drop, both
//! the meter provider and the tracer provider are flushed and shut down.
//!
//! When `config.otlp_endpoint` is absent, this is a no-op: the Prometheus
//! scrape endpoint continues to work, and spans created by `#[tracing::instrument]`
//! are processed only by the local fmt subscriber.

use std::{collections::HashMap, time::Duration};
use stoa_core::telemetry::TelemetryConfig;
use tracing::warn;

/// Holds the active OTel providers; shuts them down cleanly on drop.
pub struct OtelGuard {
    meter_provider: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    logger_provider: Option<opentelemetry_sdk::logs::SdkLoggerProvider>,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.meter_provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("OTel metrics shutdown error: {e}");
            }
        }
        if let Some(provider) = self.tracer_provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("OTel tracer shutdown error: {e}");
            }
        }
        if let Some(provider) = self.logger_provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("OTel logger shutdown error: {e}");
            }
        }
    }
}

/// Initialise OTLP metrics, trace, and (optionally) log export.
///
/// Returns `(OtelGuard, Option<SdkLoggerProvider>)`.  The guard must be held
/// for the process lifetime; it flushes and shuts down all providers on drop.
/// The returned `SdkLoggerProvider` (when `logs_endpoint` is configured) must
/// be passed to `opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new`
/// to wire log records into the OTLP log pipeline.
pub fn init_telemetry(
    config: &TelemetryConfig,
) -> (
    OtelGuard,
    Option<opentelemetry_sdk::logs::SdkLoggerProvider>,
) {
    let endpoint = match config.otlp_endpoint.as_deref() {
        Some(ep) => ep,
        None => {
            return (
                OtelGuard {
                    meter_provider: None,
                    tracer_provider: None,
                    logger_provider: None,
                },
                None,
            )
        }
    };

    let headers: HashMap<String, String> = config
        .otlp_headers
        .iter()
        .filter_map(|h| {
            h.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();

    let meter_provider =
        match build_meter_provider(endpoint, headers.clone(), config.metrics_push_interval_secs) {
            Ok(p) => {
                opentelemetry::global::set_meter_provider(p.clone());
                Some(p)
            }
            Err(e) => {
                warn!("OTel metrics OTLP init failed: {e}; continuing without OTLP metrics push");
                None
            }
        };

    let tracer_provider =
        match build_tracer_provider(endpoint, headers.clone(), config.trace_sample_rate) {
            Ok(p) => {
                opentelemetry::global::set_tracer_provider(p.clone());
                Some(p)
            }
            Err(e) => {
                warn!("OTel tracer OTLP init failed: {e}; continuing without OTLP trace export");
                None
            }
        };

    let logger_provider =
        config
            .logs_endpoint
            .as_deref()
            .and_then(|ep| match build_logger_provider(ep, headers) {
                Ok(p) => Some(p),
                Err(e) => {
                    warn!("OTel logger OTLP init failed: {e}; continuing without OTLP log export");
                    None
                }
            });

    let log_bridge_provider = logger_provider.clone();
    (
        OtelGuard {
            meter_provider,
            tracer_provider,
            logger_provider,
        },
        log_bridge_provider,
    )
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

fn build_tracer_provider(
    endpoint: &str,
    headers: HashMap<String, String>,
    sample_rate: f64,
) -> Result<opentelemetry_sdk::trace::SdkTracerProvider, Box<dyn std::error::Error + Send + Sync>> {
    use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{endpoint}/v1/traces"))
        .with_headers(headers)
        .build()?;

    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(sample_rate)));

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .build())
}

fn build_logger_provider(
    endpoint: &str,
    headers: HashMap<String, String>,
) -> Result<opentelemetry_sdk::logs::SdkLoggerProvider, Box<dyn std::error::Error + Send + Sync>> {
    use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
    use opentelemetry_sdk::logs::SdkLoggerProvider;

    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(format!("{endpoint}/v1/logs"))
        .with_headers(headers)
        .build()?;

    Ok(SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .build())
}
