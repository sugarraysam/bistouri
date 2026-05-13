//! Centralized metric definitions for the Bistouri symbolizer.
//!
//! All Prometheus metric names, descriptions, and the `describe_all()` entry
//! point live here.

/// Cache hits for objects and symbols.
/// Labels: `kind` = "object" | "symbol", `space` = "user" | "kernel".
pub const METRIC_CACHE_HITS: &str = "bistouri_symbolizer_cache_hits";

/// Cache misses for objects and symbols.
/// Labels: `kind` = "object" | "symbol", `space` = "user" | "kernel".
pub const METRIC_CACHE_MISSES: &str = "bistouri_symbolizer_cache_misses";

/// Symbolization latency in seconds (histogram).
/// Labels: `phase` = "total" | "user" | "kernel".
pub const METRIC_LATENCY_SECONDS: &str = "bistouri_symbolizer_latency_seconds";

/// Total resolution requests.
pub const METRIC_RESOLUTIONS_TOTAL: &str = "bistouri_symbolizer_resolutions_total";

/// Successful resolution requests.
pub const METRIC_RESOLUTIONS_SUCCESS: &str = "bistouri_symbolizer_resolutions_success";

/// Resolution requests that failed entirely.
pub const METRIC_RESOLUTIONS_ERROR: &str = "bistouri_symbolizer_resolutions_error";

/// Debuginfod network/fetch errors.
pub const METRIC_DEBUGINFOD_ERRORS: &str = "bistouri_symbolizer_debuginfod_errors";

/// ELF parse failures.
pub const METRIC_PARSE_FAILURES: &str = "bistouri_symbolizer_parse_failures";

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
}
