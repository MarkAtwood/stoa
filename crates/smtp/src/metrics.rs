/// Prometheus metrics for the SMTP crate.
///
/// All metrics are registered into the default global `prometheus` registry.
/// The `/metrics` endpoint on the Sieve admin HTTP server gathers them and
/// renders text/plain in Prometheus exposition format.
use std::sync::LazyLock;

use prometheus::{
    register_counter, register_counter_vec, register_int_counter, Counter, CounterVec, IntCounter,
    Opts,
};

/// Total number of inbound TCP connections accepted.
pub static SMTP_CONNECTIONS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "smtp_connections_total",
        "Total number of inbound SMTP connections accepted"
    ))
    .expect("failed to register smtp_connections_total")
});

/// Total number of messages that completed DATA and were accepted (250 OK).
pub static SMTP_MESSAGES_ACCEPTED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "smtp_messages_accepted_total",
        "Total number of messages accepted after DATA"
    ))
    .expect("failed to register smtp_messages_accepted_total")
});

/// Total number of messages rejected during DATA, labelled by rejection reason.
///
/// Label values in use:
/// - `"size"` — message exceeded the configured size limit
/// - `"policy"` — rejected by DMARC policy or Sieve `reject` action
pub static SMTP_MESSAGES_REJECTED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "smtp_messages_rejected_total",
            "Total number of messages rejected during DATA, by reason"
        ),
        &["reason"]
    )
    .expect("failed to register smtp_messages_rejected_total")
});

/// Total number of message body bytes accepted (after dot-unstuffing, before
/// prepending Received: and Authentication-Results: trace headers).
pub static SMTP_DATA_BYTES_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(Opts::new(
        "smtp_data_bytes_total",
        "Total bytes of message body accepted through DATA"
    ))
    .expect("failed to register smtp_data_bytes_total")
});

/// Total number of Sieve evaluations aborted due to exceeding the configured timeout.
pub static SMTP_SIEVE_EVAL_TIMEOUTS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "smtp_sieve_eval_timeouts_total",
        "Number of Sieve evaluations aborted due to timeout"
    )
    .expect("failed to register smtp_sieve_eval_timeouts_total")
});
