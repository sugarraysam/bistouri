//! User-space frame resolution.
//!
//! Pipeline: build_id → debuginfod fetch → ELF parse → PT_LOAD match →
//! vaddr → addr2line DWARF lookup → SymbolInfo.

use tracing::{debug, warn};

use super::build_id::{self, BuildId, BUILD_ID_SIZE};
use super::cache::{CachedObject, ObjectCache};
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
    client: &dyn DebuginfodClient,
) -> bool {
    if cache.contains(build_id) {
        return true;
    }

    if cache.is_negative(build_id) {
        return false;
    }

    let hex = build_id::to_hex(build_id);

    // Try debuginfo first (has DWARF + symtab), fall back to executable.
    let elf_bytes = match fetch_elf(client, &hex).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            // Definitive 404 — negative cache.
            debug!(build_id = %hex, "build_id not found in debuginfod, negative caching");
            cache.insert_negative(*build_id);
            return false;
        }
        Err(e) => {
            // Transient error — do NOT negative cache, allow retry.
            warn!(build_id = %hex, error = %e, "debuginfod fetch failed (transient, will retry)");
            return false;
        }
    };

    match CachedObject::from_elf_bytes(&elf_bytes, &hex, None) {
        Ok(parsed) => {
            cache.insert(*build_id, parsed);
            true
        }
        Err(e) => {
            // Parse failure is definitive — negative cache.
            warn!(build_id = %hex, error = %e, "ELF parse failed, negative caching");
            cache.insert_negative(*build_id);
            false
        }
    }
}

/// Fetches ELF bytes from debuginfod. Tries debuginfo first, then executable.
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
) -> ResolvedFrame {
    let hex = build_id::to_hex(build_id);

    cache
        .with_object(build_id, |obj| resolve_from_object(obj, file_offset, &hex))
        .unwrap_or(ResolvedFrame::Symbolized(SymbolInfo::unknown()))
}

/// Performs the actual symbolization against a cached ELF object.
fn resolve_from_object(obj: &CachedObject, file_offset: u64, build_id_hex: &str) -> ResolvedFrame {
    // file_offset → vaddr via PT_LOAD segment matching.
    let vaddr = match translate_file_offset(&obj.segments, file_offset, build_id_hex) {
        Ok(v) => v,
        Err(_) => return ResolvedFrame::Symbolized(SymbolInfo::unknown()),
    };

    obj.symbolize_vaddr(vaddr)
}
