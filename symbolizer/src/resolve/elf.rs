//! ELF PT_LOAD segment matching and file_offset → vaddr translation.
//!
//! The BPF stack walker provides file offsets (host-independent), which
//! we translate to link-time virtual addresses via PT_LOAD segments.
//! Formula: `vaddr = file_offset - p_offset + p_vaddr`

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
    /// Returns `true` if `file_offset` falls within this segment.
    #[inline]
    pub(crate) fn contains(&self, file_offset: u64) -> bool {
        file_offset >= self.p_offset && file_offset < self.p_offset + self.p_filesz
    }

    /// Returns `true` if `vaddr` falls within this segment's virtual address range.
    #[inline]
    pub(crate) fn contains_vaddr(&self, vaddr: u64) -> bool {
        vaddr >= self.p_vaddr && vaddr < self.p_vaddr + self.p_filesz
    }

    /// Translates a file offset to a virtual address within this segment.
    #[inline]
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
/// it to a virtual address.
///
/// Linear scan: ELF binaries have 2–4 PT_LOAD segments.
#[inline]
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

    #[rstest]
    #[case::at_start(seg(0x1000, 0x400000, 0x2000), 0x1000, true)]
    #[case::mid_range(seg(0x1000, 0x400000, 0x2000), 0x1FFF, true)]
    #[case::at_end_exclusive(seg(0x1000, 0x400000, 0x2000), 0x3000, false)]
    #[case::before_start(seg(0x1000, 0x400000, 0x2000), 0x0FFF, false)]
    #[case::zero_offset(seg(0, 0x400000, 0x1000), 0x0, true)]
    fn segment_contains(#[case] segment: LoadSegment, #[case] offset: u64, #[case] expected: bool) {
        assert_eq!(segment.contains(offset), expected);
    }

    #[rstest]
    #[case::at_start(seg(0x1000, 0x400000, 0x2000), 0x400000, true)]
    #[case::mid_range(seg(0x1000, 0x400000, 0x2000), 0x401FFF, true)]
    #[case::at_end_exclusive(seg(0x1000, 0x400000, 0x2000), 0x402000, false)]
    #[case::before_start(seg(0x1000, 0x400000, 0x2000), 0x3FFFFF, false)]
    fn segment_contains_vaddr(
        #[case] segment: LoadSegment,
        #[case] vaddr: u64,
        #[case] expected: bool,
    ) {
        assert_eq!(segment.contains_vaddr(vaddr), expected);
    }

    #[rstest]
    #[case::identity_bias(seg(0, 0x400000, 0x10000), 0x1234, 0x401234)]
    #[case::positive_bias(seg(0x1000, 0x401000, 0x5000), 0x2000, 0x402000)]
    #[case::large_offset(seg(0x200000, 0x600000, 0x100000), 0x250000, 0x650000)]
    fn vaddr_translation(
        #[case] segment: LoadSegment,
        #[case] file_offset: u64,
        #[case] expected_vaddr: u64,
    ) {
        assert_eq!(segment.file_offset_to_vaddr(file_offset), expected_vaddr);
    }

    #[rstest]
    #[case::hit_first_segment(0x0500, Some(0x400500))]
    #[case::hit_second_segment(0x2100, Some(0x602100))]
    #[case::miss_gap(0x1500, None)]
    #[case::zero_offset_in_segment(0x0000, Some(0x400000))]
    fn translate_multi_segment(#[case] offset: u64, #[case] expected: Option<u64>) {
        let segments = vec![seg(0x0000, 0x400000, 0x1000), seg(0x2000, 0x602000, 0x500)];
        let result = translate_file_offset(&segments, offset, "test");
        match expected {
            Some(vaddr) => assert_eq!(result.unwrap(), vaddr),
            None => assert!(result.is_err()),
        }
    }
}
