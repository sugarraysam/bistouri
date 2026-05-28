//! Concurrent caches for the symbolization pipeline.
//!
//! Three cache tiers, all built on [`moka`]'s lock-free concurrent cache:
//!
//! - **Object cache (L1)**: `BuildId → CachedObject` — byte-weighted LRU,
//!   split into kernel/user pools. DWARF walks are concurrent via a
//!   `Context` pool inside each `CachedObject`.
//! - **Negative cache**: TTL-based cache for 404'd build IDs.
//! - **Symbol cache (L2)**: `(BuildId, address) → Arc<ResolvedFrame>` —
//!   byte-weighted with [`BYTES_PER_L2_ENTRY`] per slot for zero-copy hits.

use object::{Object, ObjectSection};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use moka::sync::Cache as MokaCache;

use super::build_id::BuildId;
use super::elf::{extract_load_segments, LoadSegment};
use crate::error::{Result, SymbolizerError};
use crate::model::{ResolvedFrame, SymbolInfo};

/// Groups all cache handles for the symbolization pipeline.
///
/// All inner types are `Clone`-cheap (moka is internally Arc-wrapped).
#[derive(Clone)]
pub struct CachePool {
    pub user_objects: ObjectCache,
    pub kernel_objects: ObjectCache,
    pub user_symbols: SymbolCache,
    pub kernel_symbols: SymbolCache,
    pub negative: NegativeCache,
}

/// Reader type owning data via `Arc<[u8]>` (makes `addr2line::Context` `Send`).
pub(crate) type ArcReader = gimli::EndianArcSlice<gimli::RunTimeEndian>;

/// What the object cache stores for a given build ID.
#[derive(Clone)]
pub(crate) enum CacheEntry {
    /// Successfully parsed ELF/DWARF.
    Parsed(Arc<CachedObject>),
    /// Permanent parse failure sentinel — prevents re-fetch.
    Unparseable,
}

impl CacheEntry {
    /// Estimated weight in bytes for moka's byte-budget eviction.
    fn weight_bytes(&self) -> usize {
        match self {
            CacheEntry::Parsed(obj) => obj.estimated_bytes,
            CacheEntry::Unparseable => 1,
        }
    }
}

/// The estimated fraction of the raw DWARF size that a single `addr2line::Context`
/// will allocate on the heap for parsed ASTs and interval trees (1/20 = 5%).
const CONTEXT_HEAP_FRACTION_DIVISOR: usize = 20;

/// Estimates the total memory footprint of the `addr2line::Context` pool.
///
/// This accounts for both the base struct size of the contexts and the lazy
/// heap allocations (e.g., parsed compilation units) across an expected
/// number of concurrent threads.
#[inline]
fn estimate_context_pool_bytes(dwarf_bytes: usize, max_pool_size: usize) -> usize {
    let context_stack_bytes = std::mem::size_of::<addr2line::Context<ArcReader>>();
    let context_heap_bytes = dwarf_bytes / CONTEXT_HEAP_FRACTION_DIVISOR;

    (context_stack_bytes + context_heap_bytes) * max_pool_size
}

/// A parsed and cached ELF object, ready for symbolization.
///
/// DWARF walks are concurrent via a `Context` pool — the `Mutex` is
/// held only for nanosecond `Vec::pop`/`Vec::push`, never during parsing.
pub struct CachedObject {
    dwarf: Arc<gimli::Dwarf<ArcReader>>,
    pool: Mutex<Vec<addr2line::Context<ArcReader>>>,
    pub segments: Vec<LoadSegment>,
    /// Static `_text` vaddr from ELF symtab (vmlinux only).
    pub(crate) static_text_addr: Option<u64>,
    /// Approximate heap bytes — used by moka weigher.
    pub(crate) estimated_bytes: usize,
    /// Capped context pool size.
    pub(crate) max_pool_size: usize,
}

impl CachedObject {
    /// Defines the strict set of DWARF sections required for address-to-line
    /// symbolization. Any section not in this list is dropped to save memory.
    const REQUIRED_DWARF_SECTIONS: &'static [&'static str] = &[
        ".debug_abbrev",
        ".debug_addr",        // DWARF 5
        ".debug_aranges",     // Fast address lookup
        ".debug_info",        // Core DIEs (subprograms, inlines)
        ".debug_line",        // Line number programs
        ".debug_line_str",    // DWARF 5 line strings
        ".debug_ranges",      // DWARF 4 address ranges
        ".debug_rnglists",    // DWARF 5 address ranges
        ".debug_str",         // Strings (function names)
        ".debug_str_offsets", // DWARF 5 string offsets
    ];

    fn is_essential_section(name: &str) -> bool {
        Self::REQUIRED_DWARF_SECTIONS.contains(&name)
    }

    /// Parses raw ELF bytes into a `CachedObject`.
    ///
    /// Creates a shared `Arc<gimli::Dwarf>` and seeds the context pool
    /// with one initial `addr2line::Context`. Additional Contexts are
    /// created on demand when concurrent threads need them.
    ///
    /// `static_text_addr` should be set for vmlinux objects (parsed by
    /// the caller from the same `object::File`).
    pub fn from_elf_bytes(
        data: &[u8],
        build_id_hex: &str,
        static_text_addr: Option<u64>,
        max_pool_size: usize,
    ) -> Result<Self> {
        let object = object::read::File::parse(data).map_err(|e| SymbolizerError::ElfParse {
            build_id: build_id_hex.into(),
            reason: e.to_string(),
        })?;

        let segments = extract_load_segments(&object);

        // Track total DWARF section bytes for the weigher.
        let mut dwarf_bytes: usize = 0;

        // Build gimli::Dwarf from the object file's DWARF sections.
        // Each section is loaded into an Arc<[u8]> so the Context owns
        // its data, is Send, and can outlive the raw ELF bytes.
        let dwarf = gimli::Dwarf::load(|section_id| -> std::result::Result<_, gimli::Error> {
            let section_name = section_id.name();

            let data = if Self::is_essential_section(section_name) {
                object
                    .section_by_name(section_name)
                    .and_then(|s| s.uncompressed_data().ok())
                    .unwrap_or(std::borrow::Cow::Borrowed(&[]))
            } else {
                std::borrow::Cow::Borrowed(&[] as &[u8])
            };

            dwarf_bytes += data.len();
            Ok(gimli::EndianArcSlice::new(
                Arc::from(&*data),
                gimli::RunTimeEndian::Little,
            ))
        })
        .map_err(|e| SymbolizerError::ElfParse {
            build_id: build_id_hex.into(),
            reason: format!("DWARF section load failed: {e}"),
        })?;

        // Wrap in Arc — all Context instances share this same byte data.
        let dwarf = Arc::new(dwarf);

        // Create the first Context and seed the pool.
        let initial_context = addr2line::Context::from_arc_dwarf(dwarf.clone()).map_err(|e| {
            SymbolizerError::ElfParse {
                build_id: build_id_hex.into(),
                reason: format!("DWARF context creation failed: {e}"),
            }
        })?;

        let seg_bytes = segments.len() * std::mem::size_of::<LoadSegment>();
        let estimated_bytes =
            dwarf_bytes + seg_bytes + estimate_context_pool_bytes(dwarf_bytes, max_pool_size);

        Ok(Self {
            dwarf,
            pool: Mutex::new(vec![initial_context]),
            segments,
            static_text_addr,
            estimated_bytes,
            max_pool_size,
        })
    }

    /// Borrows a `Context` from the pool, or creates a new one if empty.
    #[inline]
    fn borrow_context(&self) -> addr2line::Context<ArcReader> {
        if let Some(ctx) = self.pool.lock().unwrap().pop() {
            return ctx;
        }
        addr2line::Context::from_arc_dwarf(self.dwarf.clone())
            .expect("Context creation from cached Dwarf must not fail")
    }

    /// Returns a `Context` to the pool for reuse.
    ///
    /// If the pool is already at [`MAX_POOL_SIZE`], the context is dropped
    /// instead of pooled. This bounds memory at `MAX_POOL_SIZE × context_bytes`
    /// per cached object — matching the weigher's estimate.
    #[inline]
    fn return_context(&self, ctx: addr2line::Context<ArcReader>) {
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < self.max_pool_size {
            pool.push(ctx);
        }
        // else: ctx is dropped here, reclaiming its heap memory.
    }

    /// Looks up a virtual address in DWARF and returns resolved symbols.
    #[inline]
    pub fn symbolize_vaddr(&self, vaddr: u64) -> ResolvedFrame {
        let context = self.borrow_context();
        let frame = Self::walk_dwarf(&context, vaddr);
        self.return_context(context);
        frame
    }

    /// Performs the actual DWARF walk against a borrowed `Context`.
    fn walk_dwarf(context: &addr2line::Context<ArcReader>, vaddr: u64) -> ResolvedFrame {
        let lookup = context.find_frames(vaddr);
        let frames_result = lookup.skip_all_loads();

        match frames_result {
            Ok(mut frames) => {
                let mut symbols = Vec::new();
                while let Ok(Some(frame)) = frames.next() {
                    let function = frame
                        .function
                        .as_ref()
                        .and_then(|f| f.demangle().ok())
                        .map(|cow| cow.into_owned())
                        .unwrap_or_else(|| "[unknown]".into());

                    let (file, line) = frame
                        .location
                        .map(|loc| (loc.file.map(|f| f.to_string()), loc.line))
                        .unwrap_or((None, None));

                    symbols.push(SymbolInfo {
                        function,
                        file,
                        line,
                    });
                }

                match symbols.len() {
                    0 => ResolvedFrame::Symbolized(SymbolInfo::unknown()),
                    1 => ResolvedFrame::Symbolized(symbols.into_iter().next().unwrap()),
                    _ => ResolvedFrame::Inlined(symbols),
                }
            }
            Err(_) => ResolvedFrame::Symbolized(SymbolInfo::unknown()),
        }
    }
}

/// Byte-weighted LRU cache for parsed ELF objects.
///
/// `Clone` is cheap (moka is internally `Arc`-wrapped).
#[derive(Clone)]
pub struct ObjectCache {
    objects: MokaCache<BuildId, CacheEntry>,
    max_capacity_bytes: u64,
    max_pool_size: usize,
}

impl ObjectCache {
    pub fn new(max_capacity_bytes: u64, max_pool_size: usize) -> Self {
        let max_capacity_kb = max_capacity_bytes.div_ceil(1024);
        let builder = MokaCache::builder()
            .weigher(|_key: &BuildId, value: &CacheEntry| -> u32 {
                let bytes = value.weight_bytes();
                let kb = bytes.div_ceil(1024);
                kb.try_into().unwrap_or(u32::MAX)
            })
            .max_capacity(max_capacity_kb);

        Self {
            objects: builder.build(),
            max_capacity_bytes,
            max_pool_size,
        }
    }

    #[inline]
    pub fn max_pool_size(&self) -> usize {
        self.max_pool_size
    }

    #[inline]
    pub(crate) fn contains(&self, build_id: &BuildId) -> bool {
        self.objects.contains_key(build_id)
    }

    pub(crate) fn insert(&self, build_id: BuildId, entry: CacheEntry) {
        self.objects.insert(build_id, entry);
    }

    #[cfg(test)]
    pub(crate) fn is_unparseable(&self, build_id: &BuildId) -> bool {
        self.objects
            .get(build_id)
            .is_some_and(|e| matches!(&e, CacheEntry::Unparseable))
    }

    #[inline]
    pub(crate) fn get_object(&self, build_id: &BuildId) -> Option<Arc<CachedObject>> {
        match self.objects.get(build_id)? {
            CacheEntry::Parsed(obj) => Some(obj),
            CacheEntry::Unparseable => None,
        }
    }

    /// Current number of entries in the cache.
    #[inline]
    pub fn entry_count(&self) -> u64 {
        self.objects.entry_count()
    }

    /// Current weighted byte usage of the cache.
    ///
    /// Call [`run_pending_tasks()`](Self::run_pending_tasks) first for
    /// accurate values — moka defers weight tracking to background
    /// maintenance that runs during `get()`/`insert()` calls.
    #[inline]
    pub fn weighted_size(&self) -> u64 {
        self.objects.weighted_size() * 1024
    }

    /// Maximum capacity in bytes.
    #[inline]
    pub fn max_capacity_bytes(&self) -> u64 {
        self.max_capacity_bytes
    }

    /// Forces moka's deferred maintenance (eviction, weight tracking).
    ///
    /// Moka batches internal bookkeeping for performance. This method
    /// flushes all pending operations so that `weighted_size()` and
    /// `entry_count()` return accurate values. Cost is O(pending_ops),
    /// typically microseconds.
    pub fn run_pending_tasks(&self) {
        self.objects.run_pending_tasks();
    }
}

/// TTL-based negative cache for debuginfod 404s.
///
/// `Clone` is cheap (moka is internally `Arc`-wrapped).
#[derive(Clone)]
pub struct NegativeCache {
    entries: MokaCache<BuildId, ()>,
    max_capacity: u64,
}

impl NegativeCache {
    pub fn new(capacity: u64, ttl: Duration) -> Self {
        Self {
            entries: MokaCache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
            max_capacity: capacity,
        }
    }

    pub(crate) fn insert(&self, build_id: BuildId) {
        self.entries.insert(build_id, ());
    }

    #[inline]
    pub(crate) fn is_negative(&self, build_id: &BuildId) -> bool {
        self.entries.contains_key(build_id)
    }

    /// Current number of entries in the negative cache.
    #[inline]
    pub fn entry_count(&self) -> u64 {
        self.entries.entry_count()
    }

    /// Maximum number of entries the negative cache can hold.
    #[inline]
    pub fn max_capacity(&self) -> u64 {
        self.max_capacity
    }
}

pub(crate) type SymbolKey = (BuildId, u64);

/// Approximate cost per L2 symbol cache entry.
///
/// Breakdown:
///   Key:   `(BuildId, u64)` = `([u8; 20], u64)` = 28 bytes
///   Value: `Arc<ResolvedFrame>` pointer = 8 bytes
///          `SymbolInfo` (function ~80B, file ~60B, line 4B) ≈ 144 bytes
///   Moka:  per-entry overhead (hash, pointers, freq sketch) ≈ 64 bytes
///   Total: ~244 bytes → rounded up to 256 (power of 2).
pub const BYTES_PER_L2_ENTRY: u64 = 256;

/// Byte-budget cache for resolved symbols — `Arc<ResolvedFrame>` for zero-copy hits.
///
/// Sized by byte budget, internally divided by [`BYTES_PER_L2_ENTRY`] to
/// compute the entry count. `Clone` is cheap (moka is internally `Arc`-wrapped).
#[derive(Clone)]
pub struct SymbolCache {
    entries: MokaCache<SymbolKey, Arc<ResolvedFrame>>,
    budget_bytes: u64,
}

impl SymbolCache {
    /// Creates a new symbol cache with the given byte budget.
    ///
    /// Uses moka's byte-weighted eviction (matching L1 `ObjectCache`)
    /// with a fixed per-entry weight of [`BYTES_PER_L2_ENTRY`].
    pub fn new_byte_budget(budget_bytes: u64) -> Self {
        let builder = MokaCache::builder()
            .weigher(|_key: &SymbolKey, _value: &Arc<ResolvedFrame>| -> u32 {
                BYTES_PER_L2_ENTRY as u32
            })
            .max_capacity(budget_bytes);

        Self {
            entries: builder.build(),
            budget_bytes,
        }
    }

    /// Creates a new symbol cache with the given entry capacity.
    ///
    /// Converts to byte budget internally for consistent byte-weighted
    /// eviction across all caches.
    pub fn new(capacity: u64) -> Self {
        let budget_bytes = capacity * BYTES_PER_L2_ENTRY;
        Self {
            entries: MokaCache::builder()
                .weigher(|_key: &SymbolKey, _value: &Arc<ResolvedFrame>| -> u32 {
                    BYTES_PER_L2_ENTRY as u32
                })
                .max_capacity(budget_bytes)
                .build(),
            budget_bytes,
        }
    }

    #[inline]
    pub(crate) fn get(&self, key: &SymbolKey) -> Option<Arc<ResolvedFrame>> {
        self.entries.get(key)
    }

    pub(crate) fn insert(&self, key: SymbolKey, frame: Arc<ResolvedFrame>) {
        self.entries.insert(key, frame);
    }

    /// Current number of entries in the cache.
    #[inline]
    pub fn entry_count(&self) -> u64 {
        self.entries.entry_count()
    }

    /// Current byte usage as tracked by moka's byte-weighted eviction.
    ///
    /// Call [`run_pending_tasks()`](Self::run_pending_tasks) first for
    /// accurate values.
    #[inline]
    pub fn weighted_byte_usage(&self) -> u64 {
        self.entries.weighted_size()
    }

    /// Byte budget this cache was created with.
    #[inline]
    pub fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    /// Forces moka's deferred maintenance (eviction, weight tracking).
    ///
    /// See [`ObjectCache::run_pending_tasks()`] for rationale.
    pub fn run_pending_tasks(&self) {
        self.entries.run_pending_tasks();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::build_id::BUILD_ID_SIZE;
    use rstest::rstest;
    use std::sync::{Arc, Barrier};

    const MAX_POOL_SIZE: usize = 4;

    fn dummy_build_id(byte: u8) -> BuildId {
        [byte; BUILD_ID_SIZE]
    }

    /// Creates a `CachedObject` with a synthetic weight for testing moka
    /// weigher behavior without needing a real ELF binary.
    fn make_test_object_with_weight(weight: usize) -> CachedObject {
        CachedObject {
            dwarf: Arc::new(
                gimli::Dwarf::load(|_| -> std::result::Result<ArcReader, gimli::Error> {
                    Ok(gimli::EndianArcSlice::new(
                        Arc::from(&[] as &[u8]),
                        gimli::RunTimeEndian::Little,
                    ))
                })
                .unwrap(),
            ),
            pool: Mutex::new(Vec::new()),
            segments: Vec::new(),
            static_text_addr: None,
            estimated_bytes: weight,
            max_pool_size: 4,
        }
    }

    /// Creates a `CachedObject` from the fixture ELF binary.
    fn make_fixture_cached_object() -> CachedObject {
        let fixture_path = format!(
            "{}/tests/e2e/fixtures/bin/hello",
            env!("CARGO_MANIFEST_DIR")
        );
        let elf_bytes = std::fs::read(&fixture_path)
            .unwrap_or_else(|_| panic!("missing fixture: {fixture_path}"));
        CachedObject::from_elf_bytes(&elf_bytes, "test", None, 4)
            .expect("failed to parse fixture ELF")
    }

    // ── NegativeCache + ObjectCache entry behavior ─────────────────────

    #[rstest]
    #[case::negative_cache_miss(0xAA, false, "negative cache miss before insert")]
    #[case::negative_cache_hit(0xAA, true, "negative cache hit after insert")]
    fn negative_cache_behavior(
        #[case] bid_byte: u8,
        #[case] should_insert: bool,
        #[case] description: &str,
    ) {
        let cache = NegativeCache::new(16, Duration::from_secs(300));
        let bid = dummy_build_id(bid_byte);

        if should_insert {
            cache.insert(bid);
        }
        assert_eq!(cache.is_negative(&bid), should_insert, "{description}");
    }

    #[rstest]
    #[case::missing_key(0xFF, false, false, false, "missing key: no entry")]
    #[case::unparseable(0xBB, true, true, false, "unparseable: contains=true, object=none")]
    fn object_cache_entry_states(
        #[case] bid_byte: u8,
        #[case] insert_unparseable: bool,
        #[case] expect_contains: bool,
        #[case] expect_get_object: bool,
        #[case] description: &str,
    ) {
        let cache = ObjectCache::new(1024 * 1024, 4);
        let bid = dummy_build_id(bid_byte);

        if insert_unparseable {
            cache.insert(bid, CacheEntry::Unparseable);
        }

        assert_eq!(cache.contains(&bid), expect_contains, "{description}");
        assert_eq!(
            cache.get_object(&bid).is_some(),
            expect_get_object,
            "{description}"
        );

        if insert_unparseable {
            assert!(cache.is_unparseable(&bid), "{description}");
        }
    }

    // ── CacheEntry::weight_bytes() saturation ─────────────────────────

    #[rstest]
    #[case::exactly_u32_max_kb((u32::MAX as usize) * 1024, (u32::MAX as u64) * 1024)]
    #[case::one_over_u32_max_kb((u32::MAX as usize) * 1024 + 1, (u32::MAX as u64) * 1024)]
    #[case::very_large(usize::MAX, (u32::MAX as u64) * 1024)]
    #[case::zero(0, 0)]
    #[case::normal(1024 * 1024, 1024 * 1024)]
    fn l1_weighted_size_saturates_on_overflow(
        #[case] estimated_bytes: usize,
        #[case] expected_weight_bytes: u64,
    ) {
        let cache = ObjectCache::new(u64::MAX, 4);
        let obj = make_test_object_with_weight(estimated_bytes);
        cache.insert(dummy_build_id(0x01), CacheEntry::Parsed(Arc::new(obj)));
        cache.run_pending_tasks();
        assert_eq!(cache.weighted_size(), expected_weight_bytes);
    }

    #[test]
    fn weight_bytes_unparseable_is_one() {
        assert_eq!(CacheEntry::Unparseable.weight_bytes(), 1);
    }

    // ── L1 ObjectCache: moka weigher accuracy ─────────────────────────
    //
    // Validates that moka's `weighted_size()` accurately reflects the
    // sum of inserted entry weights AFTER `run_pending_tasks()`.

    #[rstest]
    #[case::small_object(1024, 1024, "1 KiB object")]
    #[case::megabyte_object(1_048_576, 1_048_576, "1 MiB object")]
    #[case::large_object(52_428_800, 52_428_800, "50 MiB object")]
    fn l1_weighted_size_tracks_inserts(
        #[case] estimated_bytes: usize,
        #[case] expected_weight: u64,
        #[case] description: &str,
    ) {
        let cache = ObjectCache::new(104_857_600, 4); // 100 MiB budget
        let obj = make_test_object_with_weight(estimated_bytes);
        cache.insert(dummy_build_id(0x01), CacheEntry::Parsed(Arc::new(obj)));
        cache.run_pending_tasks();
        assert_eq!(cache.weighted_size(), expected_weight, "{description}");
    }

    // ── L1 ObjectCache: eviction under pressure ───────────────────────
    //
    // Validates that moka evicts entries when total weight exceeds the
    // byte budget — the core invariant for memory-bounded caching.

    #[rstest]
    #[case::three_in_two_budget(3, 1_048_576, 2_097_152, 2, "one evicted")]
    #[case::five_in_two_budget(5, 1_048_576, 2_097_152, 2, "three evicted")]
    #[case::exact_fit(2, 524_288, 1_048_576, 2, "exact fit, no eviction")]
    fn l1_eviction_under_pressure(
        #[case] insert_count: usize,
        #[case] weight_per_object: usize,
        #[case] budget: u64,
        #[case] expected_max_entries: u64,
        #[case] description: &str,
    ) {
        let cache = ObjectCache::new(budget, 4);
        for i in 0..insert_count {
            let obj = make_test_object_with_weight(weight_per_object);
            cache.insert(dummy_build_id(i as u8), CacheEntry::Parsed(Arc::new(obj)));
        }
        cache.run_pending_tasks();
        assert!(
            cache.entry_count() <= expected_max_entries,
            "{description}: entry_count={}, expected <={}",
            cache.entry_count(),
            expected_max_entries,
        );
        assert!(
            cache.weighted_size() <= budget,
            "{description}: weighted_size={}, budget={}",
            cache.weighted_size(),
            budget,
        );
    }

    // ── L2 SymbolCache: byte-weighted accuracy ────────────────────────
    //
    // Validates that L2's weigher correctly assigns BYTES_PER_L2_ENTRY
    // per entry and that weighted_size() reflects the sum.

    #[rstest]
    #[case::single_entry(1, BYTES_PER_L2_ENTRY, "one entry")]
    #[case::ten_entries(10, BYTES_PER_L2_ENTRY * 10, "ten entries")]
    #[case::hundred_entries(100, BYTES_PER_L2_ENTRY * 100, "100 entries")]
    fn l2_weighted_size_tracks_entries(
        #[case] insert_count: u64,
        #[case] expected_bytes: u64,
        #[case] description: &str,
    ) {
        let cache = SymbolCache::new_byte_budget(1_000_000);
        let frame = Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
        for i in 0..insert_count {
            cache.insert((dummy_build_id(0x01), i), frame.clone());
        }
        cache.run_pending_tasks();
        assert_eq!(cache.weighted_byte_usage(), expected_bytes, "{description}");
    }

    // ── L2 SymbolCache: eviction under pressure ──────────────────────

    #[rstest]
    #[case::over_budget(5, 3, "evicts to stay within budget")]
    #[case::exact_budget(3, 3, "exact fit, no eviction")]
    #[case::large_excess(20, 5, "heavy eviction")]
    fn l2_eviction_behavior(
        #[case] insert_count: u64,
        #[case] budget_entries: u64,
        #[case] description: &str,
    ) {
        let budget = budget_entries * BYTES_PER_L2_ENTRY;
        let cache = SymbolCache::new_byte_budget(budget);
        let frame = Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
        for i in 0..insert_count {
            cache.insert((dummy_build_id(0x01), i), frame.clone());
        }
        cache.run_pending_tasks();
        assert!(
            cache.entry_count() <= budget_entries,
            "{description}: entry_count={}, expected <={}",
            cache.entry_count(),
            budget_entries,
        );
        assert!(
            cache.weighted_byte_usage() <= budget,
            "{description}: weighted_byte_usage={}, budget={}",
            cache.weighted_byte_usage(),
            budget,
        );
    }

    // ── Context pool capping ──────────────────────────────────────────
    //
    // Validates the memory leak fix: return_context() must drop excess
    // contexts instead of pooling them unboundedly.

    #[rstest]
    #[case::at_cap(MAX_POOL_SIZE, MAX_POOL_SIZE, "pool stays at cap")]
    #[case::over_cap(MAX_POOL_SIZE + 4, MAX_POOL_SIZE, "excess contexts dropped")]
    #[case::double_over(MAX_POOL_SIZE * 2, MAX_POOL_SIZE, "double overflow dropped")]
    #[case::under_cap(2, 2, "pool grows normally below cap")]
    #[case::single(1, 1, "single context returned")]
    fn context_pool_capped(
        #[case] borrow_count: usize,
        #[case] expected_pool_size: usize,
        #[case] description: &str,
    ) {
        let obj = make_fixture_cached_object();
        let mut contexts: Vec<_> = (0..borrow_count).map(|_| obj.borrow_context()).collect();
        for ctx in contexts.drain(..) {
            obj.return_context(ctx);
        }
        assert_eq!(
            obj.pool.lock().unwrap().len(),
            expected_pool_size,
            "{description}"
        );
    }

    // ── run_pending_tasks() accuracy ──────────────────────────────────
    //
    // Validates that weighted_size() is accurate AFTER run_pending_tasks.

    #[test]
    fn l1_weighted_size_accurate_after_run_pending_tasks() {
        let cache = ObjectCache::new(104_857_600, 4);
        let obj = make_test_object_with_weight(1_048_576);
        cache.insert(dummy_build_id(0x01), CacheEntry::Parsed(Arc::new(obj)));

        // After run_pending_tasks: must be accurate.
        cache.run_pending_tasks();
        assert_eq!(
            cache.weighted_size(),
            1_048_576,
            "weighted_size must be accurate after run_pending_tasks"
        );
    }

    #[test]
    fn l2_weighted_size_accurate_after_run_pending_tasks() {
        let cache = SymbolCache::new_byte_budget(1_000_000);
        let frame = Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
        cache.insert((dummy_build_id(0x01), 0x1000), frame);

        // After run_pending_tasks: must reflect one entry.
        cache.run_pending_tasks();
        assert_eq!(
            cache.weighted_byte_usage(),
            BYTES_PER_L2_ENTRY,
            "L2 weighted_byte_usage must equal BYTES_PER_L2_ENTRY for one entry"
        );
    }

    // ── L2 SymbolCache: basic hit/miss behavior ──────────────────────

    #[rstest]
    #[case::miss_on_empty(16, &[], (0xCC, 0x1234), false)]
    #[case::hit_after_insert(16, &[(0xCC, 0x1234)], (0xCC, 0x1234), true)]
    #[case::miss_different_key(16, &[(0xCC, 0x1234)], (0xCC, 0x5678), false)]
    fn symbol_cache_behavior(
        #[case] capacity: u64,
        #[case] keys_to_insert: &[(u8, u64)],
        #[case] lookup_key: (u8, u64),
        #[case] expect_hit: bool,
    ) {
        let cache = SymbolCache::new(capacity);
        let frame = Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));

        for &(bid_byte, offset) in keys_to_insert {
            cache.insert((dummy_build_id(bid_byte), offset), frame.clone());
        }

        let key = (dummy_build_id(lookup_key.0), lookup_key.1);
        assert_eq!(cache.get(&key).is_some(), expect_hit);
    }

    // ── ELF fixture integration tests ────────────────────────────────

    #[test]
    fn fixture_hello_resolves_target_function() {
        let fixture_path = format!(
            "{}/tests/e2e/fixtures/bin/hello",
            env!("CARGO_MANIFEST_DIR")
        );
        let elf_bytes = std::fs::read(&fixture_path)
            .unwrap_or_else(|_| panic!("missing fixture: {fixture_path}"));

        let obj = CachedObject::from_elf_bytes(&elf_bytes, "test", None, 4)
            .expect("failed to parse fixture ELF");

        assert!(!obj.segments.is_empty(), "expected PT_LOAD segments");

        // file_offset 6213 (0x1845) = target_function from manifest.json
        let vaddr = crate::resolve::elf::translate_file_offset(&obj.segments, 6213, "test")
            .expect("segment translation failed for offset 6213");

        let frame = obj.symbolize_vaddr(vaddr);

        match &frame {
            crate::model::ResolvedFrame::Symbolized(info) => {
                assert_eq!(
                    info.function, "target_function",
                    "expected 'target_function' got '{}'",
                    info.function
                );
            }
            crate::model::ResolvedFrame::Inlined(frames) => {
                let names: Vec<&str> = frames.iter().map(|f| f.function.as_str()).collect();
                assert!(
                    names.contains(&"target_function"),
                    "expected 'target_function' in {names:?}"
                );
            }
        }
    }

    /// Verifies concurrent DWARF walks don't panic and pool is capped
    /// at MAX_POOL_SIZE after all threads return their contexts.
    #[test]
    fn concurrent_symbolize_vaddr() {
        let fixture_path = format!(
            "{}/tests/e2e/fixtures/bin/hello",
            env!("CARGO_MANIFEST_DIR")
        );
        let elf_bytes = std::fs::read(&fixture_path)
            .unwrap_or_else(|_| panic!("missing fixture: {fixture_path}"));

        let obj = Arc::new(
            CachedObject::from_elf_bytes(&elf_bytes, "test", None, 4)
                .expect("failed to parse fixture ELF"),
        );

        let vaddr = crate::resolve::elf::translate_file_offset(&obj.segments, 6213, "test")
            .expect("segment translation failed for offset 6213");

        // Spawn 8 threads. Use a barrier after borrowing but before returning
        // to guarantee that all 8 threads hold a context simultaneously.
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let obj = obj.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let ctx = obj.borrow_context();
                    barrier.wait();
                    let frame = CachedObject::walk_dwarf(&ctx, vaddr);
                    obj.return_context(ctx);
                    frame
                })
            })
            .collect();

        for handle in handles {
            let frame = handle.join().expect("thread panicked during DWARF walk");
            match &frame {
                ResolvedFrame::Symbolized(info) => {
                    assert_eq!(info.function, "target_function");
                }
                ResolvedFrame::Inlined(frames) => {
                    let names: Vec<&str> = frames.iter().map(|f| f.function.as_str()).collect();
                    assert!(names.contains(&"target_function"));
                }
            }
        }

        // Pool is capped at MAX_POOL_SIZE — 4 excess contexts were dropped.
        let pool_size = obj.pool.lock().unwrap().len();
        assert_eq!(
            pool_size, MAX_POOL_SIZE,
            "pool should be capped at {MAX_POOL_SIZE}, got {pool_size}"
        );
    }

    /// Verifies pool growth on demand and capping behavior.
    #[test]
    fn pool_growth_on_demand() {
        let obj = make_fixture_cached_object();

        // Seed context is present.
        assert_eq!(obj.pool.lock().unwrap().len(), 1);

        // Borrow the first context (empties the pool).
        let ctx1 = obj.borrow_context();
        assert_eq!(obj.pool.lock().unwrap().len(), 0);

        // Borrow a second context (forces creation of a new one).
        let ctx2 = obj.borrow_context();
        assert_eq!(obj.pool.lock().unwrap().len(), 0);

        // Return both contexts.
        obj.return_context(ctx1);
        assert_eq!(obj.pool.lock().unwrap().len(), 1);

        obj.return_context(ctx2);
        assert_eq!(obj.pool.lock().unwrap().len(), 2);
    }
}
