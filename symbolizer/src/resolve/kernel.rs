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

use super::build_id;
use super::cache::{CachedObject, ObjectCache};
use crate::model::{ResolvedFrame, SymbolInfo};

/// Default static `_text` virtual address for x86_64 vmlinux.
/// Used as a fallback if the ELF symbol table doesn't contain `_text`.
/// This is the standard kernel link-time address on x86_64.
pub(crate) const DEFAULT_STATIC_TEXT_ADDR: u64 = 0xffff_ffff_8100_0000;

/// Long-lived kernel frame resolver.
///
/// Owns cloned cache handles (moka caches are internally `Arc`-wrapped,
/// so cloning is a pointer bump).
pub(crate) struct KernelResolver {
    cache: ObjectCache,
}

impl KernelResolver {
    pub(crate) fn new(cache: ObjectCache) -> Self {
        Self { cache }
    }

    /// Ensures a parsed vmlinux object is cached for the given kernel build ID.
    ///
    /// Delegates to `ObjectCache::get_or_fetch` which handles fetch coalescing,
    /// concurrency bounding, negative caching, and parse-failure sentinels.
    pub(crate) async fn ensure_cached(&self, kernel_build_id: &[u8]) -> Option<Arc<CachedObject>> {
        let bid = build_id::try_from_slice(kernel_build_id)?;
        self.cache.get_or_fetch(bid).await
    }
}

/// Reads the static `_text` virtual address from raw ELF bytes.
///
/// This is the link-time address of `_text`, NOT the KASLR-randomized runtime
/// address. Typical value: `0xffffffff81000000` on x86_64.
pub(crate) fn read_static_text_addr(data: &[u8]) -> Option<u64> {
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
