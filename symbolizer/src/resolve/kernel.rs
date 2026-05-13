//! Kernel frame resolution.
//!
//! Algorithm:
//! 1. Fetch vmlinux debuginfo from debuginfod using the kernel build_id.
//! 2. Parse once: extract DWARF context, PT_LOAD segments, and static `_text` addr.
//! 3. For each raw IP: `vmlinux_vaddr = raw_ip - runtime_text_addr + static_text_addr`
//! 4. Look up `vmlinux_vaddr` in the vmlinux DWARF/symtab.
//!
//! The static `_text` address is a property of the vmlinux ELF (identical for
//! a given `build_id`). It is parsed once during cache insertion and stored
//! in `CachedObject::static_text_addr` to avoid re-parsing on every frame.

use std::sync::Arc;

use tracing::{debug, warn};

use super::build_id;
use super::cache::{CacheEntry, CachedObject, ObjectCache};
use crate::debuginfod::{ArtifactKind, DebuginfodClient};
use crate::model::{ResolvedFrame, SymbolInfo};

/// Default static `_text` virtual address for x86_64 vmlinux.
/// Used as a fallback if the ELF symbol table doesn't contain `_text`.
/// This is the standard kernel link-time address on x86_64.
pub(crate) const DEFAULT_STATIC_TEXT_ADDR: u64 = 0xffff_ffff_8100_0000;

/// Long-lived kernel frame resolver.
///
/// Owns shared references to the object cache and debuginfod client,
/// avoiding repeated parameter passing on the hot path. Generic over
/// the client type to eliminate vtable dispatch on cache-miss fetches.
pub(crate) struct KernelResolver<C> {
    cache: Arc<ObjectCache>,
    client: Arc<C>,
}

impl<C: DebuginfodClient> KernelResolver<C> {
    pub(crate) fn new(cache: Arc<ObjectCache>, client: Arc<C>) -> Self {
        Self { cache, client }
    }

    /// Returns a clone of the cache Arc for use in `spawn_blocking` closures.
    pub(crate) fn cache_ref(&self) -> Arc<ObjectCache> {
        self.cache.clone()
    }

    /// Ensures the vmlinux debuginfo is cached for the given kernel build ID.
    ///
    /// Returns `true` if the vmlinux is available for symbolization.
    ///
    /// Negative cache policy: 404 and parse errors are negative-cached.
    /// Transient network errors are NOT — allowing retry on the next session.
    pub(crate) async fn ensure_cached(&self, kernel_build_id: &[u8]) -> bool {
        let Some(bid) = build_id::try_from_slice(kernel_build_id) else {
            warn!(
                len = kernel_build_id.len(),
                "kernel build_id is not 20 bytes, cannot fetch vmlinux"
            );
            return false;
        };

        if self.cache.contains(bid) {
            return true;
        }

        if self.cache.is_negative(bid) {
            return false;
        }

        let hex = build_id::to_hex(bid);

        // vmlinux is always fetched as debuginfo (it contains DWARF + symtab).
        let bytes = match self.client.fetch(&hex, ArtifactKind::Debuginfo).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // Definitive 404 — negative cache.
                debug!(build_id = %hex, "vmlinux not found in debuginfod, negative caching");
                self.cache.insert_negative(*bid);
                return false;
            }
            Err(e) => {
                // Transient error — do NOT negative cache, allow retry.
                warn!(build_id = %hex, error = %e, "vmlinux fetch failed (transient, will retry)");
                return false;
            }
        };

        // Read static _text address before the bytes are consumed by DWARF parsing.
        let static_text_addr = read_static_text_addr(&bytes);

        match CachedObject::from_elf_bytes(&bytes, &hex, static_text_addr) {
            Ok(parsed) => {
                self.cache.insert(*bid, CacheEntry::Parsed(parsed));
                true
            }
            Err(e) => {
                // Parse failure is definitive — cache as unparseable sentinel.
                warn!(build_id = %hex, error = %e, "vmlinux parse failed, caching as unparseable");
                self.cache.insert(*bid, CacheEntry::Unparseable);
                false
            }
        }
    }
}

/// Reads the static `_text` virtual address from raw ELF bytes.
///
/// This is the link-time address of `_text`, NOT the KASLR-randomized runtime
/// address. Typical value: `0xffffffff81000000` on x86_64.
fn read_static_text_addr(data: &[u8]) -> Option<u64> {
    use object::{Object, ObjectSymbol};

    let object = object::read::File::parse(data).ok()?;
    object
        .symbols()
        .find(|sym| sym.name() == Ok("_text"))
        .map(|sym| sym.address())
}

/// Symbolizes a vmlinux virtual address.
pub(crate) fn resolve_kernel_addr(obj: &CachedObject, vaddr: u64) -> ResolvedFrame {
    // Check if the address falls within any of the vmlinux's virtual address segments.
    // Must use contains_vaddr (not contains) because kernel vaddrs are virtual
    // addresses after KASLR correction, not file offsets.
    let in_text = obj.segments.iter().any(|seg| seg.contains_vaddr(vaddr));
    if !in_text {
        // IP is outside vmlinux text — likely a kernel module.
        return ResolvedFrame::Symbolized(SymbolInfo::unresolved_module());
    }

    obj.symbolize_vaddr(vaddr)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    /// Verifies the KASLR-aware vmlinux vaddr computation.
    ///
    /// `vmlinux_vaddr = raw_ip - runtime_text + static_text`
    #[rstest]
    #[case::small_offset(
        0xffffffff9f201234,
        0xffffffff9f200000,
        0xffffffff81000000,
        0xffffffff81001234,
        "small offset from _text"
    )]
    #[case::zero_offset(
        0xffffffff9f200000,
        0xffffffff9f200000,
        0xffffffff81000000,
        0xffffffff81000000,
        "IP exactly at runtime _text maps to static _text"
    )]
    #[case::large_offset(
        0xffffffff9f400000,
        0xffffffff9f200000,
        0xffffffff81000000,
        0xffffffff81200000,
        "2MB into kernel text"
    )]
    fn vmlinux_vaddr_computation(
        #[case] raw_ip: u64,
        #[case] runtime_text: u64,
        #[case] static_text: u64,
        #[case] expected: u64,
        #[case] description: &str,
    ) {
        let vmlinux_vaddr = raw_ip.wrapping_sub(runtime_text).wrapping_add(static_text);
        assert_eq!(vmlinux_vaddr, expected, "{description}");
    }
}
