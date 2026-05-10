use lru::LruCache;
use std::num::NonZeroUsize;
use std::path::Path;

/// Default capacity for the VdsoCache LRU. Sized for typical deployments
/// where the agent monitors tens of processes, not thousands.
const DEFAULT_CACHE_CAPACITY: usize = 256;

/// `AT_SYSINFO_EHDR` auxiliary vector entry type — contains the vDSO base address.
const AT_SYSINFO_EHDR: u64 = 33;

/// `AT_PAGESZ` auxiliary vector entry type — system page size in bytes.
const AT_PAGESZ: u64 = 6;

/// Fallback page size when AT_PAGESZ is missing from auxv.
const DEFAULT_PAGE_SIZE: u64 = 4096;

/// Maximum user-space virtual address by architecture.
/// Addresses above this are either kernel-space or non-canonical (garbage).
///
/// - x86_64 (4-level paging, 47-bit VA): `0x0000_7FFF_FFFF_FFFF`
/// - aarch64 (48-bit VA, default config): `0x0000_FFFF_FFFF_FFFF`
///
/// These are conservative lower bounds — some kernels support wider VA
/// (x86_64 5-level = 56-bit, aarch64 LVA = 52-bit), but using the smaller
/// bound means we might misclassify a few legitimate high-VA frames as
/// corrupted. In practice, user code rarely maps above these limits.
#[cfg(target_arch = "x86_64")]
const USER_SPACE_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

#[cfg(target_arch = "aarch64")]
const USER_SPACE_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

// Fallback for other architectures — conservative 48-bit VA.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const USER_SPACE_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Returns true if `ip` is a valid canonical user-space address.
///
/// Non-canonical addresses (like `0xAAAAAAAAAAAAAAAA`) indicate stack walk
/// corruption — the unwinder followed a garbage "return address" into
/// unmapped memory. These frames carry no useful information.
#[inline]
pub(crate) fn is_canonical_user_address(ip: u64) -> bool {
    ip <= USER_SPACE_MAX
}

/// A process's vDSO virtual address range.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VdsoRange {
    base: u64,
    end: u64,
}

impl VdsoRange {
    fn contains(&self, ip: u64) -> bool {
        ip >= self.base && ip < self.end
    }
}

/// Reads the vDSO base address from `/proc/<pid>/auxv`.
///
/// The auxiliary vector is a sequence of `(type: u64, value: u64)` pairs
/// written by the kernel at exec time. We scan for `AT_SYSINFO_EHDR` (33)
/// which holds the vDSO's ELF header address in the process's address space,
/// and `AT_PAGESZ` (6) for the system page size.
///
/// Returns `None` if the process has exited, auxv is unreadable, or the
/// entry is not found (unlikely on Linux).
pub(crate) fn read_vdso_range(pid: u32, proc_path: &Path) -> Option<VdsoRange> {
    let auxv_path = proc_path.join(format!("{}/auxv", pid));
    let data = std::fs::read(auxv_path).ok()?;

    // auxv is a sequence of (u64, u64) pairs in native byte order.
    if data.len() % 16 != 0 {
        return None;
    }

    let mut vdso_base: Option<u64> = None;
    let mut page_size: u64 = DEFAULT_PAGE_SIZE;

    for chunk in data.chunks_exact(16) {
        let entry_type = u64::from_ne_bytes(chunk[..8].try_into().ok()?);
        let entry_value = u64::from_ne_bytes(chunk[8..16].try_into().ok()?);

        match entry_type {
            AT_SYSINFO_EHDR => vdso_base = Some(entry_value),
            AT_PAGESZ => page_size = entry_value,
            0 => break, // AT_NULL terminates the auxiliary vector.
            _ => {}
        }
    }

    let base = vdso_base?;
    // Conservative: vDSO is always 1-2 pages. Using 2 * page_size covers
    // both x86_64 (4KB pages, vDSO ≈ 4-8KB) and aarch64 (64KB pages).
    let vdso_size = 2 * page_size;
    Some(VdsoRange {
        base,
        end: base.saturating_add(vdso_size),
    })
}

/// LRU cache mapping PIDs to their vDSO address ranges.
///
/// Populated by `proc_walk` for active rule-matched PIDs. Read by the
/// profiler's ringbuf callback to classify fallback stack frames.
///
/// Thread-safety: shared between trigger module (writer, via `insert`) and
/// profiler module (reader, via `contains`) through `Arc<Mutex<VdsoCache>>`.
/// Single reader (ringbuf callback) + single writer (proc_walk every 30s)
/// = zero contention. Mutex is simpler than RwLock and preserves true LRU
/// ordering via `get()` (which promotes accessed entries).
pub(crate) struct VdsoCache {
    cache: LruCache<u32, Option<VdsoRange>>,
}

impl VdsoCache {
    pub(crate) fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity).expect("cache capacity must be > 0")),
        }
    }

    /// Inserts a pre-read vDSO range for a PID.
    /// Called from `proc_walk` after reading `/proc/<pid>/auxv` outside the lock.
    pub(crate) fn insert(&mut self, pid: u32, range: Option<VdsoRange>) {
        self.cache.put(pid, range);
    }

    /// Returns true if `ip` falls within the cached vDSO range for `pid`.
    /// Returns false if the PID has no cached entry or the auxv read failed.
    ///
    /// Uses `get()` which promotes the entry to most-recently-used,
    /// giving us true LRU eviction semantics.
    pub(crate) fn contains(&mut self, pid: u32, ip: u64) -> bool {
        self.cache
            .get(&pid)
            .and_then(|opt| opt.as_ref())
            .is_some_and(|range| range.contains(ip))
    }

    /// Number of entries in the cache (for testing).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::fs;
    use std::path::PathBuf;

    // -----------------------------------------------------------------------
    // is_canonical_user_address — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::zero(0x0, true)]
    #[case::low_text(0x401000, true)]
    #[case::typical_heap(0x5555_5555_0000, true)]
    #[case::typical_mmap(0x7f00_0000_0000, true)]
    #[case::user_max(USER_SPACE_MAX, true)]
    #[case::just_above_max(USER_SPACE_MAX + 1, false)]
    #[case::poison_aa(0xAAAA_AAAA_AAAA_AAAA, false)]
    #[case::kernel_range(0xFFFF_8000_0000_0000, false)]
    #[case::non_canonical_mid(0x0001_0000_0000_0000, false)]
    fn canonical_user_address(#[case] ip: u64, #[case] expected: bool) {
        assert_eq!(is_canonical_user_address(ip), expected, "ip={:#x}", ip);
    }

    // -----------------------------------------------------------------------
    // VdsoRange::contains
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::at_base(0x7FFE_0000_0000, true)]
    #[case::inside(0x7FFE_0000_0001, true)]
    #[case::at_end_minus_one(0x7FFE_0000_0000 + 2 * DEFAULT_PAGE_SIZE - 1, true)]
    #[case::at_end(0x7FFE_0000_0000 + 2 * DEFAULT_PAGE_SIZE, false)]
    #[case::before_base(0x7FFE_0000_0000 - 1, false)]
    #[case::way_outside(0x4000_0000, false)]
    fn vdso_range_contains(#[case] ip: u64, #[case] expected: bool) {
        let range = VdsoRange {
            base: 0x7FFE_0000_0000,
            end: 0x7FFE_0000_0000 + 2 * DEFAULT_PAGE_SIZE,
        };
        assert_eq!(range.contains(ip), expected, "ip={:#x}", ip);
    }

    // -----------------------------------------------------------------------
    // read_vdso_range — synthetic auxv
    // -----------------------------------------------------------------------

    fn make_auxv_entry(entry_type: u64, value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&entry_type.to_ne_bytes());
        buf.extend_from_slice(&value.to_ne_bytes());
        buf
    }

    fn make_auxv(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut data = Vec::new();
        for &(t, v) in entries {
            data.extend_from_slice(&make_auxv_entry(t, v));
        }
        // AT_NULL terminator
        data.extend_from_slice(&make_auxv_entry(0, 0));
        data
    }

    #[test]
    fn read_vdso_range_finds_at_sysinfo_ehdr() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test_vdso_auxv");
        let pid_dir = dir.join("123");
        fs::create_dir_all(&pid_dir).unwrap();

        let vdso_base: u64 = 0x7FFE_ABCD_0000;
        let auxv = make_auxv(&[
            (16, 0xBFEB_FBF7), // AT_HWCAP
            (AT_PAGESZ, 4096), // AT_PAGESZ
            (AT_SYSINFO_EHDR, vdso_base),
            (25, 0), // AT_RANDOM
        ]);
        fs::write(pid_dir.join("auxv"), &auxv).unwrap();

        let range = read_vdso_range(123, &dir).expect("should parse auxv");
        assert_eq!(range.base, vdso_base);
        assert_eq!(range.end, vdso_base + 2 * 4096);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_vdso_range_uses_page_size_from_auxv() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test_vdso_pagesz");
        let pid_dir = dir.join("100");
        fs::create_dir_all(&pid_dir).unwrap();

        let vdso_base: u64 = 0x7FFE_0000_0000;
        let page_size: u64 = 65536; // aarch64 64KB pages
        let auxv = make_auxv(&[(AT_PAGESZ, page_size), (AT_SYSINFO_EHDR, vdso_base)]);
        fs::write(pid_dir.join("auxv"), &auxv).unwrap();

        let range = read_vdso_range(100, &dir).expect("should parse auxv");
        assert_eq!(range.base, vdso_base);
        assert_eq!(range.end, vdso_base + 2 * page_size);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_vdso_range_missing_entry() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test_vdso_no_ehdr");
        let pid_dir = dir.join("456");
        fs::create_dir_all(&pid_dir).unwrap();

        let auxv = make_auxv(&[
            (16, 0xBFEB_FBF7), // AT_HWCAP — no AT_SYSINFO_EHDR
        ]);
        fs::write(pid_dir.join("auxv"), &auxv).unwrap();

        assert!(read_vdso_range(456, &dir).is_none());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_vdso_range_nonexistent_pid() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test_vdso_nonexistent");
        let _ = fs::create_dir_all(&dir);
        assert!(read_vdso_range(99999, &dir).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // VdsoCache
    // -----------------------------------------------------------------------

    #[test]
    fn cache_contains_after_insert() {
        let vdso_base: u64 = 0x7FFE_1234_0000;
        let range = VdsoRange {
            base: vdso_base,
            end: vdso_base + 2 * DEFAULT_PAGE_SIZE,
        };

        let mut cache = VdsoCache::with_capacity(8);
        cache.insert(789, Some(range));

        assert!(cache.contains(789, vdso_base));
        assert!(cache.contains(789, vdso_base + 100));
        assert!(!cache.contains(789, vdso_base + 2 * DEFAULT_PAGE_SIZE));
        assert!(!cache.contains(999, vdso_base)); // different PID
    }

    #[test]
    fn cache_lru_eviction() {
        // Capacity 2: inserting 3 entries evicts the oldest.
        let mut cache = VdsoCache::with_capacity(2);

        cache.insert(1, None);
        cache.insert(2, None);
        assert_eq!(cache.len(), 2);

        cache.insert(3, None);
        assert_eq!(cache.len(), 2); // PID 1 evicted

        // PID 1 should be gone (cache miss returns false).
        assert!(!cache.contains(1, 0x7FFE_0000_0000));
    }
}
