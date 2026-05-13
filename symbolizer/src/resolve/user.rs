//! User-space frame resolution.
//!
//! Pipeline: build_id → debuginfod fetch → ELF parse → PT_LOAD match →
//! vaddr → addr2line DWARF lookup → SymbolInfo.

use std::sync::Arc;

use tracing::{debug, warn};

use super::build_id::{self, BuildId, BUILD_ID_SIZE};
use super::cache::{CacheEntry, CachedObject, ObjectCache, SymbolCache};
use super::elf::translate_file_offset;
use crate::debuginfod::{ArtifactKind, DebuginfodClient};
use crate::error::Result;
use crate::model::{ResolvedFrame, SymbolInfo};

/// Long-lived user-space frame resolver.
///
/// Owns shared references to the object cache and debuginfod client,
/// mirroring `KernelResolver<C>` for structural symmetry. Generic over
/// the client type to eliminate vtable dispatch on cache-miss fetches.
pub(crate) struct UserResolver<C> {
    cache: Arc<ObjectCache>,
    client: Arc<C>,
}

impl<C: DebuginfodClient> UserResolver<C> {
    pub(crate) fn new(cache: Arc<ObjectCache>, client: Arc<C>) -> Self {
        Self { cache, client }
    }

    /// Returns a clone of the cache Arc for use in `spawn_blocking` closures.
    pub(crate) fn cache_ref(&self) -> Arc<ObjectCache> {
        self.cache.clone()
    }

    /// Returns a reference to the client Arc for spawning sub-resolvers.
    pub(crate) fn client_ref(&self) -> Arc<C> {
        self.client.clone()
    }

    /// Ensures a parsed ELF object is available in the cache for the given build ID.
    ///
    /// Fetches from debuginfod if missing. Returns `true` if the object is
    /// available, `false` if it couldn't be obtained (negative cached).
    ///
    /// Negative cache policy: 404 and parse errors are negative-cached.
    /// Transient network errors are NOT — allowing retry on the next session.
    pub(crate) async fn ensure_cached(&self, build_id: &BuildId) -> bool {
        if self.cache.contains(build_id) {
            return true;
        }

        if self.cache.is_negative(build_id) {
            return false;
        }

        let hex = build_id::to_hex(build_id);

        // Try debuginfo first (has DWARF + symtab), fall back to executable.
        let elf_bytes = match self.fetch_elf(&hex).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // Definitive 404 — negative cache.
                debug!(build_id = %hex, "build_id not found in debuginfod, negative caching");
                self.cache.insert_negative(*build_id);
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
                self.cache.insert(*build_id, CacheEntry::Parsed(parsed));
                true
            }
            Err(e) => {
                // Parse failure is definitive — cache as unparseable sentinel.
                warn!(build_id = %hex, error = %e, "ELF parse failed, caching as unparseable");
                self.cache.insert(*build_id, CacheEntry::Unparseable);
                false
            }
        }
    }

    /// Fetches ELF bytes from debuginfod. Tries debuginfo first, then executable.
    async fn fetch_elf(&self, build_id_hex: &str) -> Result<Option<Vec<u8>>> {
        // Prefer debuginfo (has DWARF for file+line resolution).
        if let Some(bytes) = self
            .client
            .fetch(build_id_hex, ArtifactKind::Debuginfo)
            .await?
        {
            return Ok(Some(bytes));
        }
        // Fall back to executable (may have .symtab but no DWARF).
        self.client
            .fetch(build_id_hex, ArtifactKind::Executable)
            .await
    }
}

/// Resolves a single user-space frame (build_id + file_offset) to symbols.
///
/// Must be called from a `spawn_blocking` context (addr2line is CPU-bound).
pub(crate) fn resolve_frame(
    build_id: &[u8; BUILD_ID_SIZE],
    file_offset: u64,
    cache: &ObjectCache,
    symbols: &SymbolCache,
) -> ResolvedFrame {
    let key = (*build_id, file_offset);

    // L2 symbol cache hit — skip DWARF entirely.
    // Arc::clone is an atomic refcount bump; we deref-clone only at the
    // return boundary to give the caller an owned ResolvedFrame.
    if let Some(cached) = symbols.get(&key) {
        return ResolvedFrame::clone(&cached);
    }

    let hex = build_id::to_hex(build_id);
    let frame = cache
        .with_object(build_id, |obj| resolve_from_object(obj, file_offset, &hex))
        .unwrap_or(ResolvedFrame::Symbolized(SymbolInfo::unknown()));

    // Populate L2 for future lookups.
    symbols.insert(key, frame.clone());
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
