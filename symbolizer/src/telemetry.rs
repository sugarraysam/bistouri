//! Centralized metric definitions for the symbolizer.
//!
//! All Prometheus metric names, descriptions, and the `describe_all()` entry
//! point live here. ClickHouse-specific metrics are in the private
//! `bistouri-storage` crate.

/// Cache hits for objects and symbols.
/// Labels: `kind` = "object" | "symbol", `space` = "user" | "kernel".
pub const METRIC_CACHE_HITS: &str = "symbolizer_cache_hits";

/// Cache misses for objects and symbols.
/// Labels: `kind` = "object" | "symbol", `space` = "user" | "kernel".
pub const METRIC_CACHE_MISSES: &str = "symbolizer_cache_misses";

/// Symbolization latency in seconds (histogram).
/// Labels: `phase` = "total" | "user" | "kernel".
pub const METRIC_LATENCY_SECONDS: &str = "symbolizer_latency_seconds";

/// Total resolution requests.
pub const METRIC_RESOLUTIONS_TOTAL: &str = "symbolizer_resolutions_total";

/// Successful resolution requests.
pub const METRIC_RESOLUTIONS_SUCCESS: &str = "symbolizer_resolutions_success";

/// Resolution requests that failed entirely.
pub const METRIC_RESOLUTIONS_ERROR: &str = "symbolizer_resolutions_error";

/// Debuginfod network/fetch errors.
pub const METRIC_DEBUGINFOD_ERRORS: &str = "symbolizer_debuginfod_errors";

/// ELF parse failures.
pub const METRIC_PARSE_FAILURES: &str = "symbolizer_parse_failures";

/// Sessions enqueued by the gRPC handler (fire-and-forget ingestion).
pub const METRIC_SESSIONS_ENQUEUED: &str = "symbolizer_sessions_enqueued";

/// Sessions dropped because the processing queue was full (backpressure shed).
pub const METRIC_SESSIONS_DROPPED: &str = "symbolizer_sessions_dropped";

// ---------------------------------------------------------------------------
// Gauges — runtime observability for dashboards
// ---------------------------------------------------------------------------

/// Current items pending in the receive mpsc channel.
pub const METRIC_RX_QUEUE_DEPTH: &str = "symbolizer_rx_queue_depth";

/// Current sessions being resolved (semaphore permits consumed).
pub const METRIC_INFLIGHT_SESSIONS: &str = "symbolizer_inflight_sessions";

/// Current byte usage of each cache tier.
/// Labels: `tier` = "l1" | "l2", `space` = "user" | "kernel".
pub const METRIC_CACHE_USAGE_BYTES: &str = "symbolizer_cache_usage_bytes";

/// Maximum byte capacity of each cache tier.
/// Labels: `tier` = "l1" | "l2", `space` = "user" | "kernel".
pub const METRIC_CACHE_CAPACITY_BYTES: &str = "symbolizer_cache_capacity_bytes";

/// Negative cache entry count (gauge).
pub const METRIC_NEGATIVE_CACHE_ENTRIES: &str = "symbolizer_negative_cache_entries";

/// Registers metric descriptions for the symbolizer. Call exactly once
/// in `main()` or daemon start before any metric is incremented.
pub fn describe_all() {
    metrics::describe_counter!(METRIC_CACHE_HITS, "Cache hits for objects and symbols");
    metrics::describe_counter!(METRIC_CACHE_MISSES, "Cache misses for objects and symbols");
    metrics::describe_histogram!(
        METRIC_LATENCY_SECONDS,
        "Symbolization latency in seconds (total, user, kernel)"
    );
    metrics::describe_counter!(
        METRIC_RESOLUTIONS_TOTAL,
        "Total resolution requests processed"
    );
    metrics::describe_counter!(METRIC_RESOLUTIONS_SUCCESS, "Successful resolution requests");
    metrics::describe_counter!(
        METRIC_RESOLUTIONS_ERROR,
        "Resolution requests that failed entirely"
    );
    metrics::describe_counter!(METRIC_DEBUGINFOD_ERRORS, "Debuginfod network/fetch errors");
    metrics::describe_counter!(METRIC_PARSE_FAILURES, "ELF parsing failures");
    metrics::describe_counter!(
        METRIC_SESSIONS_ENQUEUED,
        "Sessions enqueued by the gRPC handler (fire-and-forget)"
    );
    metrics::describe_counter!(
        METRIC_SESSIONS_DROPPED,
        "Sessions dropped due to full processing queue"
    );

    // Gauges
    metrics::describe_gauge!(
        METRIC_RX_QUEUE_DEPTH,
        "Current items pending in the gRPC receive queue"
    );
    metrics::describe_gauge!(
        METRIC_INFLIGHT_SESSIONS,
        "Sessions currently being resolved + stored"
    );
    metrics::describe_gauge!(
        METRIC_CACHE_USAGE_BYTES,
        "Current byte usage of each cache tier (L1 object, L2 symbol)"
    );
    metrics::describe_gauge!(
        METRIC_CACHE_CAPACITY_BYTES,
        "Maximum byte capacity of each cache tier"
    );
    metrics::describe_gauge!(
        METRIC_NEGATIVE_CACHE_ENTRIES,
        "Current number of negative cache entries (404'd build IDs)"
    );
}
