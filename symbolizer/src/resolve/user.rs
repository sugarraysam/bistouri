//! User-space frame resolution.
//!
//! Pipeline: build_id → ObjectCache::get_or_fetch (moka-coalesced) →
//! PT_LOAD match → vaddr → addr2line DWARF lookup → SymbolInfo.

use std::sync::Arc;

use tracing::debug;

use super::build_id::{self, BuildId, BUILD_ID_SIZE};
use super::cache::{CachedObject, SymbolCache};
use super::FrameStats;
use crate::model::{ResolvedFrame, SymbolInfo};

use super::elf::translate_file_offset;
use std::collections::HashMap;

/// Resolves a single user-space frame (build_id + file_offset) to symbols.
///
/// Must be called from a `spawn_blocking` context (addr2line is CPU-bound).
/// Cache hit/miss counts are accumulated in `stats` and flushed once per
/// session to avoid per-frame metrics registry lookups.
pub(crate) fn resolve_frame(
    build_id: &[u8; BUILD_ID_SIZE],
    file_offset: u64,
    pinned_user_objects: &HashMap<BuildId, Arc<CachedObject>>,
    symbols: &SymbolCache,
    stats: &mut FrameStats,
) -> Arc<ResolvedFrame> {
    let key = (*build_id, file_offset);

    // L2 symbol cache hit — zero-copy Arc return.
    if let Some(cached) = symbols.get(&key) {
        stats.l2_hits += 1;
        return cached;
    }
    // Don't count L2 miss yet — it's only a real miss if L1 has the
    // object (otherwise L2 can never contain this entry).

    let Some(obj) = pinned_user_objects.get(build_id) else {
        stats.l1_misses += 1;
        return Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
    };
    stats.l1_hits += 1;

    // L1 hit but L2 missed — THIS is a real L2 miss (the entry is resolvable
    // but wasn't cached yet). After warmup this counter should be near-zero.
    stats.l2_misses += 1;

    // to_hex is deferred past L2/L1 checks — only needed for DWARF walks.
    let hex = build_id::to_hex(build_id);

    // DWARF walk: pure CPU cost. Per-session aggregate timing is recorded
    // in resolve_session_blocking(); no per-frame histogram here to avoid
    // inaccurate Summary quantile estimates at high observation rates.
    let frame = Arc::new(resolve_from_object(obj, file_offset, &hex));

    // Populate L2 for future lookups.
    symbols.insert(key, frame.clone());
    frame
}

/// Performs the actual symbolization against a cached ELF object.
fn resolve_from_object(obj: &CachedObject, file_offset: u64, build_id_hex: &str) -> ResolvedFrame {
    // file_offset → vaddr via PT_LOAD segment matching.
    // Success path is deliberately silent — it runs for every frame and the
    // previous debug!() with format!("0x{v:x}") was a major source of
    // per-frame allocations + tracing subscriber contention.
    let vaddr = match translate_file_offset(&obj.segments, file_offset, build_id_hex) {
        Ok(v) => v,
        Err(e) => {
            // Only log failures — they are rare and diagnostically important.
            debug!(build_id = build_id_hex, file_offset, error = %e, "vaddr translation failed");
            return ResolvedFrame::Symbolized(SymbolInfo::unknown());
        }
    };

    obj.symbolize_vaddr(vaddr)
}
