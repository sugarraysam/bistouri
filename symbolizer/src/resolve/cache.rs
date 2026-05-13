//! Concurrent caches for the symbolization pipeline.
//!
//! Built on [`moka`]'s lock-free concurrent cache for high-throughput,
//! contention-free access from parallel `spawn_blocking` tasks.
//!
//! ## Object cache (L1)
//!
//! Keyed by build ID (content-addressed SHA-1). Stores parsed ELF/DWARF
//! objects as `Arc<CachedObject>`. Metadata (segments, static_text_addr)
//! is `Sync`-safe and freely accessible. DWARF walks are **fully
//! concurrent** via a pool of `addr2line::Context` instances that share
//! the same `Arc<gimli::Dwarf>` byte data.
//!
//! Split into separate kernel and user-space pools so vmlinux objects
//! are never evicted by user-space churn. Uses a byte-weighted LRU
//! eviction policy.
//!
//! ### Concurrent DWARF walks (Context pool)
//!
//! `addr2line::Context` is `!Sync` (internal `OnceCell` for lazy CU
//! parsing). Instead of serializing all walks behind a Mutex, each
//! `CachedObject` maintains a **pool** of `Context` instances. Threads
//! borrow a Context (nanosecond `Vec::pop`), walk DWARF with **no lock
//! held**, and return it (nanosecond `Vec::push`). New Contexts are
//! created on demand from `Arc<gimli::Dwarf>` when concurrency exceeds
//! pool size — the underlying DWARF bytes are shared, only the per-
//! Context CU index (~100 bytes/CU) is duplicated.
//!
//! ## Negative cache (404 only)
//!
//! TTL-based cache for build IDs not found in debuginfod (HTTP 404).
//! Uses moka's built-in `time_to_live` — no manual `Instant` tracking.
//! Only **not-found** results live here. Parse failures are stored as
//! `CacheEntry::Unparseable` in the object cache, not here.
//!
//! **Transient failures** (network timeout, DNS failure, 500s) are NOT
//! cached at all — the caller should retry on the next session.
//!
//! ## Symbol cache (L2)
//!
//! Keyed by `(BuildId, u64)` — build ID plus either a file offset
//! (user-space) or a vmlinux vaddr (kernel). Caches `Arc<ResolvedFrame>`
//! for zero-clone cache hits — no string allocations on the hot path.
//! Split into kernel and user-space pools.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use moka::sync::Cache as MokaCache;

use super::build_id::BuildId;
use super::elf::{extract_load_segments, LoadSegment};
use crate::error::{Result, SymbolizerError};
use crate::model::{ResolvedFrame, SymbolInfo};

/// A reader type that owns its data via `Arc<[u8]>`.
///
/// Using `Arc` instead of `Rc` makes the `addr2line::Context` `Send`.
/// `addr2line::Context` is still `!Sync` — we handle this via a Context
/// pool pattern (see `CachedObject`).
pub(crate) type ArcReader = gimli::EndianArcSlice<gimli::RunTimeEndian>;

/// What the object cache stores for a given build ID.
///
/// `Clone` is cheap — `Parsed` holds `Arc` (pointer bump),
/// `Unparseable` is zero-cost.
#[derive(Clone)]
pub(crate) enum CacheEntry {
    /// Successfully parsed ELF/DWARF — ready for symbolization.
    Parsed(Arc<CachedObject>),
    /// ELF was fetched but parsing failed definitively.
    /// Stored as a sentinel to prevent re-fetch and re-parse attempts.
    /// Retrying is pointless — same bytes will always fail.
    Unparseable,
}

impl CacheEntry {
    /// Estimated weight in bytes for moka's byte-budget eviction.
    ///
    /// Called at insert time; moka caches the returned weight.
    fn weight_bytes(&self) -> u32 {
        match self {
            CacheEntry::Parsed(obj) => obj
                .estimated_bytes
                .try_into()
                .expect("CachedObject estimated_bytes exceeds u32::MAX (> 4 GiB single object)"),
            CacheEntry::Unparseable => 1,
        }
    }
}

/// A parsed and cached ELF object, ready for symbolization.
///
/// Metadata (segments, static_text_addr) is `Sync`-safe and freely
/// accessible without any lock.
///
/// DWARF walks (`symbolize_vaddr`) are **fully concurrent** — each
/// caller borrows its own `addr2line::Context` from an internal pool,
/// walks DWARF with **no lock held**, and returns the Context when done.
/// The pool `Mutex` is held only for nanosecond `Vec::pop` / `Vec::push`
/// operations, never during DWARF parsing.
///
/// All `Context` instances share the same underlying DWARF byte data
/// via `Arc<gimli::Dwarf>` — only the per-Context compilation unit
/// index (`ResUnits`, ~100 bytes/CU) is duplicated.
///
/// ## Moka eviction safety
///
/// When moka evicts a `CacheEntry::Parsed(Arc<CachedObject>)`, it drops
/// its `Arc` clone. In-flight callers that already hold their own `Arc`
/// keep the `CachedObject` alive until the last reference is dropped.
/// Borrowed `Context` instances also hold `Arc<Dwarf>` internally, so
/// DWARF data survives even if the pool itself is dropped mid-walk.
pub(crate) struct CachedObject {
    /// Shared DWARF sections — used to create new `Context` instances
    /// on demand when the pool is empty. Cloning is cheap: just `Arc`
    /// bumps on the underlying byte buffers, zero byte copies.
    dwarf: Arc<gimli::Dwarf<ArcReader>>,
    /// Pool of reusable `addr2line::Context` instances. Each thread
    /// borrows a Context (pop), walks DWARF without holding the lock,
    /// and returns it (push). The `Mutex` is held only for the
    /// nanosecond `Vec` operation — never during DWARF parsing.
    pool: Mutex<Vec<addr2line::Context<ArcReader>>>,
    /// PT_LOAD segments for file_offset → vaddr translation.
    /// `Sync`-safe — freely accessible without locking.
    pub(crate) segments: Vec<LoadSegment>,
    /// Static `_text` virtual address from the ELF symbol table.
    /// Only populated for vmlinux objects.
    /// `Sync`-safe — freely accessible without locking.
    pub(crate) static_text_addr: Option<u64>,
    /// Approximate heap memory consumed by this object (DWARF sections
    /// + segments). Used by the moka weigher for byte-budget eviction.
    pub(crate) estimated_bytes: usize,
}

impl CachedObject {
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
            use object::{Object, ObjectSection};
            let data = object
                .section_by_name(section_id.name())
                .and_then(|s| s.uncompressed_data().ok())
                .unwrap_or(std::borrow::Cow::Borrowed(&[]));
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
        let estimated_bytes = dwarf_bytes + seg_bytes;

        Ok(Self {
            dwarf,
            pool: Mutex::new(vec![initial_context]),
            segments,
            static_text_addr,
            estimated_bytes,
        })
    }

    /// Borrows a `Context` from the pool, or creates a new one if empty.
    ///
    /// The pool `Mutex` is held only for `Vec::pop` — nanoseconds.
    /// Creating a new Context from `Arc<Dwarf>` parses compilation unit
    /// headers (not full DWARF), typically < 1 ms for user-space binaries.
    fn borrow_context(&self) -> addr2line::Context<ArcReader> {
        if let Some(ctx) = self.pool.lock().unwrap().pop() {
            return ctx;
        }
        // Pool empty — create a new Context sharing the same DWARF bytes.
        addr2line::Context::from_arc_dwarf(self.dwarf.clone())
            .expect("Context creation from cached Dwarf must not fail")
    }

    /// Returns a `Context` to the pool for reuse by other threads.
    ///
    /// The pool `Mutex` is held only for `Vec::push` — nanoseconds.
    fn return_context(&self, ctx: addr2line::Context<ArcReader>) {
        self.pool.lock().unwrap().push(ctx);
    }

    /// Looks up a virtual address in the DWARF context and returns
    /// resolved symbols (including inlined frames).
    ///
    /// **Fully concurrent** — multiple threads can call this on the
    /// same `CachedObject` simultaneously. Each thread borrows its own
    /// `Context` from the pool; no lock is held during the DWARF walk.
    pub(crate) fn symbolize_vaddr(&self, vaddr: u64) -> ResolvedFrame {
        let context = self.borrow_context();
        let frame = Self::walk_dwarf(&context, vaddr);
        self.return_context(context);
        frame
    }

    /// Performs the actual DWARF walk against a borrowed `Context`.
    ///
    /// Extracted as a static method to make the zero-lock guarantee
    /// structurally visible — no `&self` state is accessed during the
    /// walk, only the borrowed Context.
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

/// Concurrent, byte-weighted cache for parsed ELF objects.
///
/// Built on `moka::sync::Cache`. Metadata (segments, static_text_addr)
/// is freely accessible via `Arc<CachedObject>`. DWARF walks are fully
/// concurrent via the Context pool inside each `CachedObject`.
///
/// `Clone` is cheap (internally `Arc`-wrapped by moka).
#[derive(Clone)]
pub struct ObjectCache {
    objects: MokaCache<BuildId, CacheEntry>,
}

impl ObjectCache {
    /// Creates a new byte-weighted object cache.
    ///
    /// `max_capacity_bytes`: maximum total weight (estimated DWARF bytes)
    /// before moka starts evicting entries.
    pub fn new(max_capacity_bytes: u64) -> Self {
        Self {
            objects: MokaCache::builder()
                .weigher(|_key: &BuildId, value: &CacheEntry| -> u32 { value.weight_bytes() })
                .max_capacity(max_capacity_bytes)
                .build(),
        }
    }

    /// Returns `true` if the build ID has an entry in the object cache
    /// (either `Parsed` or `Unparseable`).
    pub(crate) fn contains(&self, build_id: &BuildId) -> bool {
        self.objects.contains_key(build_id)
    }

    /// Inserts a cache entry (parsed object or unparseable sentinel).
    pub(crate) fn insert(&self, build_id: BuildId, entry: CacheEntry) {
        self.objects.insert(build_id, entry);
    }

    /// Returns `true` if the build ID is cached as `Unparseable`.
    #[cfg(test)]
    pub(crate) fn is_unparseable(&self, build_id: &BuildId) -> bool {
        self.objects
            .get(build_id)
            .is_some_and(|e| matches!(&e, CacheEntry::Unparseable))
    }

    /// Returns an `Arc<CachedObject>` if the build ID is cached and parsed.
    ///
    /// The caller receives a cheap `Arc` clone — metadata (segments,
    /// static_text_addr) is accessible without any lock. DWARF walks
    /// via `symbolize_vaddr()` are fully concurrent.
    pub(crate) fn get_object(&self, build_id: &BuildId) -> Option<Arc<CachedObject>> {
        match self.objects.get(build_id)? {
            CacheEntry::Parsed(obj) => Some(obj),
            CacheEntry::Unparseable => None,
        }
    }
}

/// Concurrent TTL-based negative cache for debuginfod 404s.
///
/// Uses moka's built-in `time_to_live` for automatic expiration —
/// no manual `Instant` tracking required.
///
/// `Clone` is cheap (internally `Arc`-wrapped by moka).
#[derive(Clone)]
pub struct NegativeCache {
    entries: MokaCache<BuildId, ()>,
}

impl NegativeCache {
    /// Creates a new negative cache.
    ///
    /// `capacity`: maximum number of negative entries.
    /// `ttl`: how long a negative entry stays valid before allowing retry.
    pub fn new(capacity: u64, ttl: Duration) -> Self {
        Self {
            entries: MokaCache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// Records a negative cache entry for a build ID not found in debuginfod
    /// (HTTP 404). Do NOT call for parse failures — use
    /// `ObjectCache::insert(bid, CacheEntry::Unparseable)` instead.
    ///
    /// Do NOT call for transient errors (network timeout, 500s) — those
    /// should be retried on the next session.
    pub(crate) fn insert(&self, build_id: BuildId) {
        self.entries.insert(build_id, ());
    }

    /// Returns `true` if the build ID is in the negative cache and hasn't expired.
    pub(crate) fn is_negative(&self, build_id: &BuildId) -> bool {
        self.entries.contains_key(build_id)
    }
}

/// Key for the symbol cache: `(build_id, address)`.
///
/// For user-space frames, `address` is the raw file offset from BPF.
/// For kernel frames, `address` is the computed vmlinux vaddr.
/// 28 bytes, `Copy`, no heap allocation.
pub(crate) type SymbolKey = (BuildId, u64);

/// Concurrent cache for resolved symbols, keyed by `(build_id, address)`.
///
/// Stores `Arc<ResolvedFrame>` — cache hits are a pointer bump, zero
/// string allocations on the hot path. Built on `moka::sync::Cache`
/// for lock-free concurrent access.
///
/// `Clone` is cheap (internally `Arc`-wrapped by moka).
#[derive(Clone)]
pub struct SymbolCache {
    entries: MokaCache<SymbolKey, Arc<ResolvedFrame>>,
}

impl SymbolCache {
    /// Creates a new symbol cache bounded by entry count.
    pub fn new(capacity: u64) -> Self {
        Self {
            entries: MokaCache::builder().max_capacity(capacity).build(),
        }
    }

    /// Returns a cached frame if present. Zero-clone — returns `Arc`.
    pub(crate) fn get(&self, key: &SymbolKey) -> Option<Arc<ResolvedFrame>> {
        self.entries.get(key)
    }

    /// Inserts a resolved frame into the cache.
    pub(crate) fn insert(&self, key: SymbolKey, frame: Arc<ResolvedFrame>) {
        self.entries.insert(key, frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::build_id::BUILD_ID_SIZE;
    use rstest::rstest;

    fn dummy_build_id(byte: u8) -> BuildId {
        [byte; BUILD_ID_SIZE]
    }

    #[test]
    fn negative_cache_blocks_lookup() {
        let cache = NegativeCache::new(16, Duration::from_secs(300));
        let bid = dummy_build_id(0xAA);

        assert!(!cache.is_negative(&bid));
        cache.insert(bid);
        assert!(cache.is_negative(&bid));
    }

    #[test]
    fn contains_returns_false_for_missing() {
        let cache = ObjectCache::new(1024 * 1024);
        assert!(!cache.contains(&dummy_build_id(0xFF)));
    }

    #[test]
    fn unparseable_sentinel_blocks_resolve() {
        let cache = ObjectCache::new(1024 * 1024);
        let bid = dummy_build_id(0xBB);

        cache.insert(bid, CacheEntry::Unparseable);

        // contains() returns true for Unparseable entries.
        assert!(cache.contains(&bid));
        // is_unparseable() returns true.
        assert!(cache.is_unparseable(&bid));
        // get_object() returns None — no parsed object available.
        assert!(cache.get_object(&bid).is_none());
    }

    /// Symbol cache behavior across capacity and access patterns.
    ///
    /// Each case inserts `keys_to_insert` into a cache of `capacity`,
    /// then checks whether `lookup_key` is a hit or miss.
    #[rstest]
    #[case::miss_on_empty(16, &[], (0xCC, 0x1234), false, "empty cache always misses")]
    #[case::hit_after_insert(16, &[(0xCC, 0x1234)], (0xCC, 0x1234), true, "inserted key is found")]
    #[case::miss_different_key(16, &[(0xCC, 0x1234)], (0xCC, 0x5678), false, "different offset misses")]
    fn symbol_cache_behavior(
        #[case] capacity: u64,
        #[case] keys_to_insert: &[(u8, u64)],
        #[case] lookup_key: (u8, u64),
        #[case] expect_hit: bool,
        #[case] description: &str,
    ) {
        let cache = SymbolCache::new(capacity);
        let frame = Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));

        for &(bid_byte, offset) in keys_to_insert {
            cache.insert((dummy_build_id(bid_byte), offset), frame.clone());
        }

        let key = (dummy_build_id(lookup_key.0), lookup_key.1);
        assert_eq!(cache.get(&key).is_some(), expect_hit, "{description}");
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

        eprintln!("vaddr: 0x{vaddr:x}");

        let frame = obj.symbolize_vaddr(vaddr);
        eprintln!("frame: {:?}", frame);

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

        // Spawn 8 threads all resolving the same vaddr concurrently.
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let obj = obj.clone();
                std::thread::spawn(move || obj.symbolize_vaddr(vaddr))
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
