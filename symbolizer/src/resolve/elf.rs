//! ELF PT_LOAD segment matching and file_offset → vaddr translation.
//!
//! ## Why this works across hosts
//!
//! The BPF stack walker (`BPF_F_USER_BUILD_ID`) gives us a **file offset** —
//! the byte position within the ELF file — not a runtime virtual address.
//! Runtime addresses vary per process per host due to ASLR/PIE, but the
//! file offset is host-independent.
//!
//! `p_vaddr` is a **static property of the ELF binary** baked in by the
//! linker. For the same `build_id` (same binary), `p_vaddr` is always
//! identical regardless of which host loaded it or where in memory the
//! kernel mapped it. The translation:
//!
//! ```text
//! vaddr = file_offset - p_offset + p_vaddr
//! ```
//!
//! produces the **link-time virtual address** that DWARF debug info is
//! indexed by. This is why `build_id + file_offset` works as a
//! host-independent frame identifier for centralized symbolization.

use crate::error::{Result, SymbolizerError};
use object::Object;

/// A loadable ELF segment extracted from a `PT_LOAD` program header.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LoadSegment {
    /// File offset of the segment start (`p_offset`).
    /// Static property of the ELF binary, identical for all copies.
    p_offset: u64,
    /// Link-time virtual address where this segment is mapped (`p_vaddr`).
    /// This is a static ELF property — NOT the runtime load address.
    /// ASLR slides this at runtime, but we never need the runtime value
    /// because we work with file offsets from the BPF stack walker.
    p_vaddr: u64,
    /// Size of the segment in the file (`p_filesz`).
    p_filesz: u64,
}

impl LoadSegment {
    /// Returns `true` if `file_offset` falls within this segment's file range.
    /// Used for user-space frames (BPF gives file offsets).
    pub(crate) fn contains(&self, file_offset: u64) -> bool {
        file_offset >= self.p_offset && file_offset < self.p_offset + self.p_filesz
    }

    /// Returns `true` if `vaddr` falls within this segment's virtual address range.
    /// Used for kernel frames (KASLR-corrected IPs are virtual addresses).
    pub(crate) fn contains_vaddr(&self, vaddr: u64) -> bool {
        vaddr >= self.p_vaddr && vaddr < self.p_vaddr + self.p_filesz
    }

    /// Translates a file offset to a virtual address within this segment.
    ///
    /// # Panics
    /// Debug-asserts that the offset is within range. Callers must check
    /// `contains()` first.
    pub(crate) fn file_offset_to_vaddr(&self, file_offset: u64) -> u64 {
        debug_assert!(self.contains(file_offset));
        file_offset - self.p_offset + self.p_vaddr
    }
}

/// Extracts all loadable segments from a parsed ELF object.
///
/// The `object` crate's `ObjectSegment` trait documents itself as
/// "A loadable segment in an Object" — so `segments()` already
/// filters to PT_LOAD entries. We additionally skip segments with
/// `p_filesz == 0` (BSS-only) since they have no file data to match.
pub(crate) fn extract_load_segments<'data>(object: &object::read::File<'data>) -> Vec<LoadSegment> {
    use object::ObjectSegment;
    use tracing::debug;

    let segments: Vec<LoadSegment> = object
        .segments()
        .filter_map(|seg| {
            let (p_offset, p_filesz) = seg.file_range();
            if p_filesz == 0 {
                return None;
            }
            Some(LoadSegment {
                p_offset,
                p_vaddr: seg.address(),
                p_filesz,
            })
        })
        .collect();

    debug!(count = segments.len(), "extracted load segments");
    for (i, s) in segments.iter().enumerate() {
        debug!(
            idx = i,
            p_offset = format!("0x{:x}", s.p_offset),
            p_vaddr = format!("0x{:x}", s.p_vaddr),
            p_filesz = format!("0x{:x}", s.p_filesz),
            "  segment"
        );
    }

    segments
}

/// Finds the `PT_LOAD` segment containing `file_offset` and translates
/// it to a virtual address suitable for symbol table / DWARF lookup.
///
/// Linear scan is intentional: ELF binaries typically have 2–4 PT_LOAD
/// segments (text, rodata, data, bss). A linear scan over ≤4 elements
/// is faster than any indexed structure due to cache locality and zero
/// overhead.
pub(crate) fn translate_file_offset(
    segments: &[LoadSegment],
    file_offset: u64,
    build_id_hex: &str,
) -> Result<u64> {
    for seg in segments {
        if seg.contains(file_offset) {
            return Ok(seg.file_offset_to_vaddr(file_offset));
        }
    }
    Err(SymbolizerError::SegmentNotFound {
        build_id: build_id_hex.into(),
        file_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn seg(p_offset: u64, p_vaddr: u64, p_filesz: u64) -> LoadSegment {
        LoadSegment {
            p_offset,
            p_vaddr,
            p_filesz,
        }
    }

    // -----------------------------------------------------------------------
    // contains — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::at_start(seg(0x1000, 0x400000, 0x2000), 0x1000, true)]
    #[case::mid_range(seg(0x1000, 0x400000, 0x2000), 0x1FFF, true)]
    #[case::at_end_exclusive(seg(0x1000, 0x400000, 0x2000), 0x3000, false)]
    #[case::before_start(seg(0x1000, 0x400000, 0x2000), 0x0FFF, false)]
    #[case::zero_offset(seg(0, 0x400000, 0x1000), 0x0, true)]
    fn segment_contains(#[case] segment: LoadSegment, #[case] offset: u64, #[case] expected: bool) {
        assert_eq!(segment.contains(offset), expected);
    }

    // -----------------------------------------------------------------------
    // file_offset_to_vaddr — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::identity_bias(
        seg(0, 0x400000, 0x10000),
        0x1234,
        0x401234,
        "zero p_offset: vaddr = file_offset + p_vaddr"
    )]
    #[case::positive_bias(
        seg(0x1000, 0x401000, 0x5000),
        0x2000,
        0x402000,
        "standard PIE layout: bias = p_vaddr - p_offset"
    )]
    #[case::large_offset(
        seg(0x200000, 0x600000, 0x100000),
        0x250000,
        0x650000,
        "data segment with large offset"
    )]
    fn vaddr_translation(
        #[case] segment: LoadSegment,
        #[case] file_offset: u64,
        #[case] expected_vaddr: u64,
        #[case] description: &str,
    ) {
        assert_eq!(
            segment.file_offset_to_vaddr(file_offset),
            expected_vaddr,
            "{description}"
        );
    }

    // -----------------------------------------------------------------------
    // translate_file_offset — multi-segment lookup
    // -----------------------------------------------------------------------

    #[test]
    fn multi_segment_correct_match() {
        let segments = vec![
            seg(0x0000, 0x400000, 0x1000), // .text
            seg(0x2000, 0x602000, 0x500),  // .data
        ];

        // Hit in first segment
        let vaddr = translate_file_offset(&segments, 0x0500, "aabb").unwrap();
        assert_eq!(vaddr, 0x400500);

        // Hit in second segment
        let vaddr = translate_file_offset(&segments, 0x2100, "aabb").unwrap();
        assert_eq!(vaddr, 0x602100);

        // Miss
        let err = translate_file_offset(&segments, 0x1500, "aabb");
        assert!(err.is_err());
    }

    #[test]
    fn file_offset_zero_is_valid_if_in_segment() {
        let segments = vec![seg(0, 0x400000, 0x1000)];
        let vaddr = translate_file_offset(&segments, 0, "aabb").unwrap();
        assert_eq!(vaddr, 0x400000);
    }
}
