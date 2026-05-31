//! User-space frame resolution.
//!
//! Pipeline: build_id → ObjectCache::get_or_fetch (moka-coalesced) →
//! PT_LOAD match → vaddr → addr2line DWARF lookup → SymbolInfo.

use std::sync::Arc;

use std::time::Instant;

use metrics::{counter, histogram};
use tracing::debug;

use crate::telemetry::{METRIC_CACHE_HITS, METRIC_CACHE_MISSES, METRIC_LATENCY_SECONDS};

use super::build_id::{self, BuildId, BUILD_ID_SIZE};
use super::cache::{CachedObject, SymbolCache};
use super::elf::translate_file_offset;
use crate::model::{ResolvedFrame, SymbolInfo};

use std::collections::HashMap;

/// Resolves a single user-space frame (build_id + file_offset) to symbols.
///
/// Must be called from a `spawn_blocking` context (addr2line is CPU-bound).
pub(crate) fn resolve_frame(
    build_id: &[u8; BUILD_ID_SIZE],
    file_offset: u64,
    pinned_user_objects: &HashMap<BuildId, Arc<CachedObject>>,
    symbols: &SymbolCache,
) -> Arc<ResolvedFrame> {
    let start_time = Instant::now();
    let key = (*build_id, file_offset);

    // L2 symbol cache hit — zero-copy Arc return.
    if let Some(cached) = symbols.get(&key) {
        counter!(METRIC_CACHE_HITS, "kind" => "symbol", "space" => "user").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "user")
            .record(start_time.elapsed().as_secs_f64());
        return cached;
    }
    // Don't count L2 miss yet — it's only a real miss if L1 has the
    // object (otherwise L2 can never contain this entry).

    let hex = build_id::to_hex(build_id);

    let Some(obj) = pinned_user_objects.get(build_id) else {
        counter!(METRIC_CACHE_MISSES, "kind" => "object", "space" => "user").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "user")
            .record(start_time.elapsed().as_secs_f64());
        return Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
    };
    counter!(METRIC_CACHE_HITS, "kind" => "object", "space" => "user").increment(1);

    // L1 hit but L2 missed — THIS is a real L2 miss (the entry is resolvable
    // but wasn't cached yet). After warmup this counter should be near-zero.
    counter!(METRIC_CACHE_MISSES, "kind" => "symbol", "space" => "user").increment(1);

    // DWARF walk: pure CPU cost. Per-session aggregate timing is recorded
    // in resolve_session_blocking(); no per-frame histogram here to avoid
    // inaccurate Summary quantile estimates at high observation rates.
    let frame = Arc::new(resolve_from_object(obj, file_offset, &hex));

    // Populate L2 for future lookups.
    symbols.insert(key, frame.clone());
    histogram!(METRIC_LATENCY_SECONDS, "phase" => "user")
        .record(start_time.elapsed().as_secs_f64());
    frame
}

/// Performs the actual symbolization against a cached ELF object.
fn resolve_from_object(obj: &CachedObject, file_offset: u64, build_id_hex: &str) -> ResolvedFrame {
    // file_offset → vaddr via PT_LOAD segment matching.
    let vaddr = match translate_file_offset(&obj.segments, file_offset, build_id_hex) {
        Ok(v) => {
            debug!(
                build_id = build_id_hex,
                file_offset = file_offset,
                vaddr = format!("0x{v:x}"),
                segments = obj.segments.len(),
                "file_offset → vaddr translation succeeded"
            );
            v
        }
        Err(e) => {
            debug!(
                build_id = build_id_hex,
                file_offset = file_offset,
                segments = obj.segments.len(),
                error = %e,
                "file_offset → vaddr translation failed"
            );
            return ResolvedFrame::Symbolized(SymbolInfo::unknown());
        }
    };

    obj.symbolize_vaddr(vaddr)
}
