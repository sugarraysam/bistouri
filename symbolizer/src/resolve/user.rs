//! User-space frame resolution.
//!
//! Pipeline: build_id → debuginfod fetch → ELF parse → PT_LOAD match →
//! vaddr → addr2line DWARF lookup → SymbolInfo.

use std::sync::Arc;

use std::time::Instant;

use metrics::{counter, histogram};
use tracing::{debug, error};

use crate::telemetry::{
    METRIC_CACHE_HITS, METRIC_CACHE_MISSES, METRIC_DEBUGINFOD_ERRORS, METRIC_LATENCY_SECONDS,
    METRIC_PARSE_FAILURES,
};

use super::build_id::{self, BuildId, BUILD_ID_SIZE};
use super::cache::{CacheEntry, CachedObject, NegativeCache, ObjectCache, SymbolCache};
use super::elf::translate_file_offset;
use crate::debuginfod::{ArtifactKind, DebuginfodClient};
use crate::error::Result;
use crate::model::{ResolvedFrame, SymbolInfo};

/// Ensures a parsed ELF object is available in the cache for the given build ID.
///
/// Fetches from debuginfod if missing. Returns `true` if the object is
/// available, `false` if it couldn't be obtained (negative cached).
///
/// Negative cache policy: 404 and parse errors are negative-cached.
/// Transient network errors are NOT — allowing retry on the next session.
pub(crate) async fn ensure_cached(
    build_id: &BuildId,
    cache: &ObjectCache,
    negative: &NegativeCache,
    client: &dyn DebuginfodClient,
) -> bool {
    if cache.contains(build_id) {
        return true;
    }

    if negative.is_negative(build_id) {
        return false;
    }

    let hex = build_id::to_hex(build_id);

    // Try debuginfo first (has DWARF + symtab), fall back to executable.
    let elf_bytes = match fetch_elf(client, &hex).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            // Definitive 404 — negative cache.
            debug!(build_id = %hex, "build_id not found in debuginfod, negative caching");
            negative.insert(*build_id);
            return false;
        }
        Err(e) => {
            // Transient error — do NOT negative cache, allow retry.
            error!(build_id = %hex, error = %e, "debuginfod fetch failed (transient, will retry)");
            counter!(METRIC_DEBUGINFOD_ERRORS).increment(1);
            return false;
        }
    };

    match CachedObject::from_elf_bytes(&elf_bytes, &hex, None) {
        Ok(parsed) => {
            cache.insert(*build_id, CacheEntry::Parsed(Arc::new(parsed)));
            true
        }
        Err(e) => {
            // Parse failure is definitive — cache as unparseable sentinel.
            error!(build_id = %hex, error = %e, "ELF parse failed, caching as unparseable");
            counter!(METRIC_PARSE_FAILURES).increment(1);
            cache.insert(*build_id, CacheEntry::Unparseable);
            false
        }
    }
}

async fn fetch_elf(client: &dyn DebuginfodClient, build_id_hex: &str) -> Result<Option<Vec<u8>>> {
    // Prefer debuginfo (has DWARF for file+line resolution).
    if let Some(bytes) = client.fetch(build_id_hex, ArtifactKind::Debuginfo).await? {
        return Ok(Some(bytes));
    }
    // Fall back to executable (may have .symtab but no DWARF).
    client.fetch(build_id_hex, ArtifactKind::Executable).await
}

/// Resolves a single user-space frame (build_id + file_offset) to symbols.
///
/// Must be called from a `spawn_blocking` context (addr2line is CPU-bound).
pub(crate) fn resolve_frame(
    build_id: &[u8; BUILD_ID_SIZE],
    file_offset: u64,
    cache: &ObjectCache,
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
    counter!(METRIC_CACHE_MISSES, "kind" => "symbol", "space" => "user").increment(1);

    let hex = build_id::to_hex(build_id);

    let Some(obj) = cache.get_object(build_id) else {
        counter!(METRIC_CACHE_MISSES, "kind" => "object", "space" => "user").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "user")
            .record(start_time.elapsed().as_secs_f64());
        return Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
    };
    counter!(METRIC_CACHE_HITS, "kind" => "object", "space" => "user").increment(1);

    let frame = Arc::new(resolve_from_object(&obj, file_offset, &hex));

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
