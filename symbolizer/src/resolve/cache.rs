//! Concurrent caches for the symbolization pipeline.
//!
//! Three cache tiers, all built on [`moka`]'s lock-free concurrent cache:
//!
//! - **Object cache (L1)**: `BuildId → CachedObject` — byte-weighted LRU,
//!   split into kernel/user pools. DWARF walks are concurrent via a
//!   `Context` pool inside each `CachedObject`.
//! - **Negative cache**: TTL-based cache for 404'd build IDs.
//! - **Symbol cache (L2)**: `(BuildId, address) → Arc<ResolvedFrame>` —
//!   zero-copy cache hits.

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
    fn weight_bytes(&self) -> u32 {
        match self {
            CacheEntry::Parsed(obj) => obj
                .estimated_bytes
                .try_into()
                .expect("estimated_bytes exceeds u32::MAX"),
            CacheEntry::Unparseable => 1,
        }
    }
}

/// Expected number of concurrent threads borrowing from the context pool.
const EXPECTED_CONTEXT_POOL_SIZE: usize = 4;

/// The estimated fraction of the raw DWARF size that a single `addr2line::Context`
/// will allocate on the heap for parsed ASTs and interval trees (1/20 = 5%).
const CONTEXT_HEAP_FRACTION_DIVISOR: usize = 20;

/// Estimates the total memory footprint of the `addr2line::Context` pool.
///
/// This accounts for both the base struct size of the contexts and the lazy
/// heap allocations (e.g., parsed compilation units) across an expected
/// number of concurrent threads.
#[inline]
fn estimate_context_pool_bytes(dwarf_bytes: usize) -> usize {
    let context_stack_bytes = std::mem::size_of::<addr2line::Context<ArcReader>>();
    let context_heap_bytes = dwarf_bytes / CONTEXT_HEAP_FRACTION_DIVISOR;

    (context_stack_bytes + context_heap_bytes) * EXPECTED_CONTEXT_POOL_SIZE
}

/// A parsed and cached ELF object, ready for symbolization.
///
/// DWARF walks are concurrent via a `Context` pool — the `Mutex` is
/// held only for nanosecond `Vec::pop`/`Vec::push`, never during parsing.
pub(crate) struct CachedObject {
    dwarf: Arc<gimli::Dwarf<ArcReader>>,
    pool: Mutex<Vec<addr2line::Context<ArcReader>>>,
    pub(crate) segments: Vec<LoadSegment>,
    /// Static `_text` vaddr from ELF symtab (vmlinux only).
    pub(crate) static_text_addr: Option<u64>,
    /// Approximate heap bytes — used by moka weigher.
    pub(crate) estimated_bytes: usize,
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
    pub(crate) fn from_elf_bytes(
        data: &[u8],
        build_id_hex: &str,
        static_text_addr: Option<u64>,
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
        let estimated_bytes = dwarf_bytes + seg_bytes + estimate_context_pool_bytes(dwarf_bytes);

        Ok(Self {
            dwarf,
            pool: Mutex::new(vec![initial_context]),
            segments,
            static_text_addr,
            estimated_bytes,
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
    #[inline]
    fn return_context(&self, ctx: addr2line::Context<ArcReader>) {
        self.pool.lock().unwrap().push(ctx);
    }

    /// Looks up a virtual address in DWARF and returns resolved symbols.
    #[inline]
    pub(crate) fn symbolize_vaddr(&self, vaddr: u64) -> ResolvedFrame {
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
}

impl ObjectCache {
    pub fn new(max_capacity_bytes: u64) -> Self {
        Self {
            objects: MokaCache::builder()
                .weigher(|_key: &BuildId, value: &CacheEntry| -> u32 { value.weight_bytes() })
                .max_capacity(max_capacity_bytes)
                .build(),
        }
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
}

/// TTL-based negative cache for debuginfod 404s.
///
/// `Clone` is cheap (moka is internally `Arc`-wrapped).
#[derive(Clone)]
pub struct NegativeCache {
    entries: MokaCache<BuildId, ()>,
}

impl NegativeCache {
    pub fn new(capacity: u64, ttl: Duration) -> Self {
        Self {
            entries: MokaCache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
        }
    }

    pub(crate) fn insert(&self, build_id: BuildId) {
        self.entries.insert(build_id, ());
    }

    #[inline]
    pub(crate) fn is_negative(&self, build_id: &BuildId) -> bool {
        self.entries.contains_key(build_id)
    }
}

pub(crate) type SymbolKey = (BuildId, u64);

/// Cache for resolved symbols — `Arc<ResolvedFrame>` for zero-copy hits.
///
/// `Clone` is cheap (moka is internally `Arc`-wrapped).
#[derive(Clone)]
pub struct SymbolCache {
    entries: MokaCache<SymbolKey, Arc<ResolvedFrame>>,
}

impl SymbolCache {
    pub fn new(capacity: u64) -> Self {
        Self {
            entries: MokaCache::builder().max_capacity(capacity).build(),
        }
    }

    #[inline]
    pub(crate) fn get(&self, key: &SymbolKey) -> Option<Arc<ResolvedFrame>> {
        self.entries.get(key)
    }

    pub(crate) fn insert(&self, key: SymbolKey, frame: Arc<ResolvedFrame>) {
        self.entries.insert(key, frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::build_id::BUILD_ID_SIZE;
    use rstest::rstest;
    use std::sync::{Arc, Barrier};

    fn dummy_build_id(byte: u8) -> BuildId {
        [byte; BUILD_ID_SIZE]
    }

    /// Tests for NegativeCache and ObjectCache entry behavior.
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
        let cache = ObjectCache::new(1024 * 1024);
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

    #[test]
    fn fixture_hello_resolves_target_function() {
        let fixture_path = format!(
            "{}/tests/e2e/fixtures/bin/hello",
            env!("CARGO_MANIFEST_DIR")
        );
        let elf_bytes = std::fs::read(&fixture_path)
            .unwrap_or_else(|_| panic!("missing fixture: {fixture_path}"));

        let obj = CachedObject::from_elf_bytes(&elf_bytes, "test", None)
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

    /// Verifies that multiple threads can walk the DWARF of the same
    /// `CachedObject` concurrently without panics or incorrect results.
    #[test]
    fn concurrent_symbolize_vaddr() {
        let fixture_path = format!(
            "{}/tests/e2e/fixtures/bin/hello",
            env!("CARGO_MANIFEST_DIR")
        );
        let elf_bytes = std::fs::read(&fixture_path)
            .unwrap_or_else(|_| panic!("missing fixture: {fixture_path}"));

        let obj = Arc::new(
            CachedObject::from_elf_bytes(&elf_bytes, "test", None)
                .expect("failed to parse fixture ELF"),
        );

        let vaddr = crate::resolve::elf::translate_file_offset(&obj.segments, 6213, "test")
            .expect("segment translation failed for offset 6213");

        // Spawn 8 threads all resolving the same vaddr concurrently. Use barrier
        // to ensure concurrency.
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let obj = obj.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    obj.symbolize_vaddr(vaddr)
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

        // Verify pool grew to accommodate concurrency.
        let pool_size = obj.pool.lock().unwrap().len();
        assert!(
            pool_size > 1,
            "pool should have grown beyond the initial seed, got {pool_size}"
        );
    }
}
