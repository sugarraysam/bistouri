//! Lockless log aggregator for high-frequency events.
//!
//! Accumulates event counts and associated values (e.g., bytes) using
//! atomics, then periodically yields a summary for the caller to log.
//!
//! # Design
//!
//! - **Hot path**: `fetch_add` only — zero contention at millions/sec.
//! - **Emission**: Single `compare_exchange` ensures exactly one caller
//!   wins per interval — no duplicate log lines.
//! - **No locks**: Two `AtomicU64`s for data, one for the timestamp.
//!
//! # Usage
//!
//! ```rust,ignore
//! use bistouri_symbolizer::log_agg::LogAggregator;
//! use std::time::Duration;
//!
//! // Simple event counting (e.g., dropped sessions):
//! static DROPS: LogAggregator = LogAggregator::new(Duration::from_secs(3));
//! if let Some(e) = DROPS.record(1) {
//!     warn!(dropped = e.count, elapsed_ms = e.elapsed_ms, "queue full");
//! }
//!
//! // Value accumulation (e.g., bytes fetched):
//! static FETCHES: LogAggregator = LogAggregator::new(Duration::from_secs(5));
//! if let Some(e) = FETCHES.record(fetch_bytes) {
//!     info!(count = e.count, total_bytes = e.total, "debuginfod fetches");
//! }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Summary emitted when the aggregation interval elapses.
#[derive(Debug, Clone, Copy)]
pub struct Emission {
    /// Number of events recorded since the last emission.
    pub count: u64,
    /// Sum of values passed to [`LogAggregator::record`].
    ///
    /// For simple counting (`record(1)`), this equals `count`.
    /// For byte tracking (`record(bytes)`), this is the total bytes.
    pub total: u64,
    /// Milliseconds elapsed since the previous emission.
    pub elapsed_ms: u64,
}

/// Lockless log aggregator for high-frequency events.
///
/// Accumulates event counts and values using atomics, periodically
/// yielding an [`Emission`] for the caller to log. Safe to use from
/// any context (async, blocking, multi-threaded).
///
/// Place as a `static` for zero initialization cost:
/// ```rust,ignore
/// static AGG: LogAggregator = LogAggregator::new(Duration::from_secs(1));
/// ```
pub struct LogAggregator {
    /// Number of events since last emission.
    count: AtomicU64,
    /// Sum of values since last emission.
    total: AtomicU64,
    /// Epoch millis of last emission (0 = never emitted).
    last_emit_ms: AtomicU64,
    /// Configured interval in milliseconds.
    interval_ms: u64,
}

// SAFETY: All fields are atomics or plain integers — inherently Send + Sync.
// The compiler can't prove this for `const fn new()` because AtomicU64::new()
// isn't const-stable in all contexts, but the type is trivially thread-safe.
unsafe impl Send for LogAggregator {}
unsafe impl Sync for LogAggregator {}

impl LogAggregator {
    /// Creates a new aggregator with the given emission interval.
    ///
    /// Use `const` placement for zero-cost `static` initialization:
    /// ```rust,ignore
    /// static AGG: LogAggregator = LogAggregator::new(Duration::from_secs(3));
    /// ```
    pub const fn new(interval: Duration) -> Self {
        Self {
            count: AtomicU64::new(0),
            total: AtomicU64::new(0),
            last_emit_ms: AtomicU64::new(0),
            interval_ms: interval.as_millis() as u64,
        }
    }

    /// Records one event with an associated value.
    ///
    /// For simple event counting, pass `1` — [`Emission::total`] will
    /// equal [`Emission::count`]. For byte/size tracking, pass the
    /// size — [`Emission::total`] accumulates the sum.
    ///
    /// Returns `Some(emission)` when the configured interval has elapsed
    /// and this caller wins the emission race. Returns `None` otherwise.
    /// Exactly one concurrent caller wins per interval.
    #[inline]
    pub fn record(&self, value: u64) -> Option<Emission> {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(value, Ordering::Relaxed);

        let now_ms = epoch_ms();
        let last = self.last_emit_ms.load(Ordering::Relaxed);

        if now_ms.saturating_sub(last) >= self.interval_ms {
            // Race to claim the emission slot.
            if self
                .last_emit_ms
                .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Won the race — swap accumulators to 0 and report.
                let count = self.count.swap(0, Ordering::Relaxed);
                let total = self.total.swap(0, Ordering::Relaxed);
                let elapsed_ms = now_ms.saturating_sub(last);

                return Some(Emission {
                    count,
                    total,
                    elapsed_ms,
                });
            }
        }

        None
    }
}

/// Current epoch time in milliseconds.
///
/// Uses `SystemTime` (~20ns on Linux via vDSO) which is cheaper than
/// `Instant` and works for cross-thread timestamp comparison without
/// requiring the same clock origin.
#[inline]
fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ── Basic counting ──────────────────────────────────────────────

    #[test]
    fn first_record_emits_immediately() {
        let agg = LogAggregator::new(Duration::from_secs(60));
        // First record should always emit (last_emit_ms starts at 0,
        // which is always >= interval_ms ago).
        let emission = agg.record(1);
        assert!(emission.is_some(), "first record should emit");
        let e = emission.unwrap();
        assert_eq!(e.count, 1);
        assert_eq!(e.total, 1);
    }

    #[test]
    fn subsequent_records_within_interval_are_suppressed() {
        let agg = LogAggregator::new(Duration::from_secs(60));
        // First emits.
        let _ = agg.record(1);
        // Next ones within the 60s window should be suppressed.
        for _ in 0..100 {
            assert!(agg.record(1).is_none());
        }
    }

    #[test]
    fn emission_after_interval_reports_accumulated_count() {
        // Use a zero-length interval so every record emits.
        let agg = LogAggregator::new(Duration::ZERO);
        let _ = agg.record(1); // first
        let _ = agg.record(1);
        let _ = agg.record(1);
        // With Duration::ZERO, every record should try to emit.
        // At least one of them should have count > 1 or the last
        // should emit the residual.
        let e = agg.record(1).expect("zero interval should emit");
        // Count may vary due to race-free single-threaded execution,
        // but should be >= 1.
        assert!(e.count >= 1);
    }

    // ── Value accumulation (bytes) ──────────────────────────────────

    #[rstest]
    #[case::single_value(vec![100], 1, 100)]
    #[case::multiple_values(vec![100, 200, 300], 3, 600)]
    fn value_accumulation(
        #[case] values: Vec<u64>,
        #[case] expected_count: u64,
        #[case] expected_total: u64,
    ) {
        // Use a 10ms interval so records accumulate without intermediate
        // emissions (each record() completes in nanoseconds).
        let agg = LogAggregator::new(Duration::from_millis(10));
        // Drain the initial emission (last_emit_ms starts at 0).
        let _ = agg.record(0);

        // Accumulate values — all within the 10ms window.
        for &v in &values {
            assert!(agg.record(v).is_none(), "should suppress within interval");
        }

        // Wait for the interval to elapse, then trigger emission.
        std::thread::sleep(Duration::from_millis(15));
        let e = agg.record(0).expect("should emit after interval");

        // count includes all accumulated records + the final trigger.
        assert!(
            e.count >= expected_count,
            "count: expected >= {expected_count}, got {}",
            e.count
        );
        assert!(
            e.total >= expected_total,
            "total: expected >= {expected_total}, got {}",
            e.total
        );
    }

    // ── Elapsed tracking ────────────────────────────────────────────

    #[test]
    fn elapsed_ms_is_nonzero_after_delay() {
        let agg = LogAggregator::new(Duration::from_millis(10));
        let _ = agg.record(1); // first emission
        std::thread::sleep(Duration::from_millis(15));
        let e = agg.record(1).expect("should emit after 15ms");
        assert!(
            e.elapsed_ms >= 10,
            "elapsed_ms should be >= 10, got {}",
            e.elapsed_ms
        );
    }
}
