//! LRU caches for the symbolization pipeline.
//!
//! ## Object cache (L1)
//!
//! Keyed by build ID (content-addressed SHA-1). Stores parsed ELF/DWARF
//! contexts or `Unparseable` sentinels for ELFs that were fetched
//! successfully but failed to parse (definitive failure — retrying the
//! same bytes is pointless).
//!
//! ## Negative cache (404 only)
//!
//! TTL-based cache for build IDs not found in debuginfod (HTTP 404).
//! Only **not-found** results live here. Parse failures are stored as
//! `CacheEntry::Unparseable` in the object cache, not here.
//!
//! **Transient failures** (network timeout, DNS failure, 500s) are NOT
//! cached at all — the caller should retry on the next session.
//!
//! ## Symbol cache (L2)
//!
//! Keyed by `(BuildId, u64)` — build ID plus either a file offset
//! (user-space) or a vmlinux vaddr (kernel). Caches the resolved
//! `ResolvedFrame` to skip DWARF walks on repeated lookups.

use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use lru::LruCache;

use super::build_id::BuildId;
use super::elf::{extract_load_segments, LoadSegment};
use crate::error::{Result, SymbolizerError};
use crate::model::{ResolvedFrame, SymbolInfo};

/// A reader type that owns its data via `Rc<[u8]>`.
/// This allows the `addr2line::Context` to outlive the raw ELF bytes.
pub(crate) type RcReader = gimli::EndianRcSlice<gimli::RunTimeEndian>;

/// What the object cache stores for a given build ID.
pub(crate) enum CacheEntry {
    /// Successfully parsed ELF/DWARF — ready for symbolization.
    Parsed(CachedObject),
    /// ELF was fetched but parsing failed definitively.
    /// Stored as a sentinel to prevent re-fetch and re-parse attempts.
    /// Retrying is pointless — same bytes will always fail.
    Unparseable,
}

/// A parsed and cached ELF object, ready for symbolization.
///
/// The `addr2line::Context` uses `Rc<[u8]>` internally via `EndianRcSlice`,
/// so it owns its DWARF data and can outlive the raw ELF bytes.
pub(crate) struct CachedObject {
    /// addr2line context for DWARF symbolization.
    pub(crate) context: addr2line::Context<RcReader>,
    /// PT_LOAD segments for file_offset → vaddr translation.
    pub(crate) segments: Vec<LoadSegment>,
    /// Static `_text` virtual address from the ELF symbol table.
    /// Only populated for vmlinux objects — used to avoid re-parsing
    /// the ELF on every kernel frame resolution.
    pub(crate) static_text_addr: Option<u64>,
}

impl CachedObject {
    /// Parses raw ELF bytes into a `CachedObject`.
    ///
    /// This is the single entry point for ELF/DWARF parsing — both
    /// user-space and kernel resolvers use this to avoid duplicating
    /// the gimli/addr2line boilerplate.
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

        // Build gimli::Dwarf from the object file's DWARF sections.
        // Each section is loaded into an Rc<[u8]> so the Context owns
        // its data and can outlive the raw ELF bytes.
        let dwarf = gimli::Dwarf::load(|section_id| -> std::result::Result<_, gimli::Error> {
            use object::{Object, ObjectSection};
            let data = object
                .section_by_name(section_id.name())
                .and_then(|s| s.uncompressed_data().ok())
                .unwrap_or(std::borrow::Cow::Borrowed(&[]));
            Ok(gimli::EndianRcSlice::new(
                Rc::from(&*data),
                gimli::RunTimeEndian::Little,
            ))
        })
        .map_err(|e| SymbolizerError::ElfParse {
            build_id: build_id_hex.into(),
            reason: format!("DWARF section load failed: {e}"),
        })?;

        let context =
            addr2line::Context::from_dwarf(dwarf).map_err(|e| SymbolizerError::ElfParse {
                build_id: build_id_hex.into(),
                reason: format!("DWARF context creation failed: {e}"),
            })?;

        Ok(Self {
            context,
            segments,
            static_text_addr,
        })
    }

    /// Looks up a virtual address in the DWARF context and returns
    /// resolved symbols (including inlined frames).
    ///
    /// This is the single DWARF lookup entry point — both kernel and
    /// user-space resolvers call this after translating their
    /// domain-specific address (KASLR'd IP or file_offset) to a vaddr.
    pub(crate) fn symbolize_vaddr(&self, vaddr: u64) -> ResolvedFrame {
        let lookup = self.context.find_frames(vaddr);
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

// addr2line::Context is not Send due to Rc internals. We access it only
// from spawn_blocking tasks (single-threaded per task), but the cache
// itself needs Send for Arc<Mutex<_>>. We enforce single-threaded access
// at the architectural level (cache.get() returns data, caller uses it
// within the same spawn_blocking closure).
//
// SAFETY: CachedObject is only accessed within spawn_blocking tasks.
// The Mutex<ObjectCache> ensures exclusive access. No CachedObject
// is ever shared across threads simultaneously.
unsafe impl Send for CachedObject {}
unsafe impl Send for CacheEntry {}

/// Thread-safe LRU cache for parsed ELF objects.
///
/// Wraps `LruCache` in a `Mutex` for concurrent access from multiple
/// `spawn_blocking` tasks. The cache is append-only (modulo LRU eviction)
/// since build IDs are content-addressed.
pub struct ObjectCache {
    objects: Mutex<LruCache<BuildId, CacheEntry>>,
    /// Negative cache: build IDs where debuginfod returned HTTP 404.
    /// Only not-found results live here — parse failures are stored
    /// as `CacheEntry::Unparseable` in the object cache.
    negative: Mutex<LruCache<BuildId, Instant>>,
    /// How long a negative cache entry stays valid.
    negative_ttl: std::time::Duration,
}

impl ObjectCache {
    /// Creates a new cache with the given capacity.
    ///
    /// `capacity`: maximum number of parsed ELF objects to keep.
    /// `negative_capacity`: maximum number of negative (404) entries.
    pub fn new(capacity: usize, negative_capacity: usize) -> Self {
        use std::num::NonZeroUsize;
        Self {
            objects: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("cache capacity must be > 0"),
            )),
            negative: Mutex::new(LruCache::new(
                NonZeroUsize::new(negative_capacity).expect("negative capacity must be > 0"),
            )),
            negative_ttl: std::time::Duration::from_secs(300), // 5 minutes
        }
    }

    /// Returns `true` if the build ID has an entry in the object cache
    /// (either `Parsed` or `Unparseable`).
    pub(crate) fn contains(&self, build_id: &BuildId) -> bool {
        self.objects.lock().unwrap().contains(build_id)
    }

    /// Inserts a cache entry (parsed object or unparseable sentinel).
    pub(crate) fn insert(&self, build_id: BuildId, entry: CacheEntry) {
        self.objects.lock().unwrap().put(build_id, entry);
    }

    /// Returns `true` if the build ID is cached as `Unparseable`.
    #[cfg(test)]
    pub(crate) fn is_unparseable(&self, build_id: &BuildId) -> bool {
        let mut cache = self.objects.lock().unwrap();
        matches!(cache.get(build_id), Some(CacheEntry::Unparseable))
    }

    /// Retrieves a parsed object and applies a closure to it.
    ///
    /// Uses a closure pattern to avoid returning a reference through the Mutex.
    /// Returns `None` if the build ID is missing or `Unparseable`.
    pub(crate) fn with_object<F, R>(&self, build_id: &BuildId, f: F) -> Option<R>
    where
        F: FnOnce(&CachedObject) -> R,
    {
        let mut cache = self.objects.lock().unwrap();
        match cache.get(build_id) {
            Some(CacheEntry::Parsed(obj)) => Some(f(obj)),
            _ => None,
        }
    }

    /// Records a negative cache entry for a build ID not found in debuginfod
    /// (HTTP 404). Do NOT call for parse failures — use
    /// `insert(bid, CacheEntry::Unparseable)` instead.
    ///
    /// Do NOT call for transient errors (network timeout, 500s) — those
    /// should be retried on the next session.
    pub(crate) fn insert_negative(&self, build_id: BuildId) {
        self.negative.lock().unwrap().put(build_id, Instant::now());
    }

    /// Returns `true` if the build ID is in the negative cache and hasn't expired.
    pub(crate) fn is_negative(&self, build_id: &BuildId) -> bool {
        let mut cache = self.negative.lock().unwrap();
        match cache.get(build_id) {
            Some(inserted_at) => {
                if inserted_at.elapsed() < self.negative_ttl {
                    true
                } else {
                    // Expired — remove and allow retry.
                    cache.pop(build_id);
                    false
                }
            }
            None => false,
        }
    }
}

/// Key for the symbol cache: `(build_id, address)`.
///
/// For user-space frames, `address` is the raw file offset from BPF.
/// For kernel frames, `address` is the computed vmlinux vaddr.
/// 28 bytes, `Copy`, no heap allocation.
pub(crate) type SymbolKey = (BuildId, u64);

/// LRU cache for resolved symbols, keyed by `(build_id, address)`.
///
/// Sits in front of the DWARF walk — if a `(build_id, offset)` pair has
/// been resolved before, we return the cached `ResolvedFrame` without
/// touching addr2line.
///
/// Stores `Arc<ResolvedFrame>` internally so cache hits are atomic
/// refcount bumps instead of deep-cloning every `String` field.
pub struct SymbolCache {
    entries: Mutex<LruCache<SymbolKey, Arc<ResolvedFrame>>>,
}

impl SymbolCache {
    /// Creates a new symbol cache with the given capacity.
    pub fn new(capacity: usize) -> Self {
        use std::num::NonZeroUsize;
        Self {
            entries: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("symbol cache capacity must be > 0"),
            )),
        }
    }

    /// Returns a cached frame if present.
    ///
    /// Returns `Arc<ResolvedFrame>` — an atomic refcount bump with
    /// zero heap allocation. Callers dereference to use the frame.
    pub(crate) fn get(&self, key: &SymbolKey) -> Option<Arc<ResolvedFrame>> {
        self.entries.lock().unwrap().get(key).cloned()
    }

    /// Inserts a resolved frame into the cache.
    pub(crate) fn insert(&self, key: SymbolKey, frame: ResolvedFrame) {
        self.entries.lock().unwrap().put(key, Arc::new(frame));
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
        let cache = ObjectCache::new(16, 16);
        let bid = dummy_build_id(0xAA);

        assert!(!cache.is_negative(&bid));
        cache.insert_negative(bid);
        assert!(cache.is_negative(&bid));
    }

    #[test]
    fn contains_returns_false_for_missing() {
        let cache = ObjectCache::new(16, 16);
        assert!(!cache.contains(&dummy_build_id(0xFF)));
    }

    #[test]
    fn unparseable_sentinel_blocks_resolve() {
        let cache = ObjectCache::new(16, 16);
        let bid = dummy_build_id(0xBB);

        cache.insert(bid, CacheEntry::Unparseable);

        // contains() returns true for Unparseable entries.
        assert!(cache.contains(&bid));
        // is_unparseable() returns true.
        assert!(cache.is_unparseable(&bid));
        // with_object() returns None — no parsed object available.
        assert!(cache.with_object(&bid, |_| ()).is_none());
    }

    /// Symbol cache behavior across capacity and access patterns.
    ///
    /// Each case inserts `keys_to_insert` into a cache of `capacity`,
    /// then checks whether `lookup_key` is a hit or miss.
    #[rstest]
    #[case::miss_on_empty(16, &[], (0xCC, 0x1234), false, "empty cache always misses")]
    #[case::hit_after_insert(16, &[(0xCC, 0x1234)], (0xCC, 0x1234), true, "inserted key is found")]
    #[case::miss_different_key(16, &[(0xCC, 0x1234)], (0xCC, 0x5678), false, "different offset misses")]
    #[case::eviction_oldest(2, &[(0xDD, 1), (0xDD, 2), (0xDD, 3)], (0xDD, 1), false, "oldest key evicted at capacity")]
    #[case::eviction_keeps_recent(2, &[(0xDD, 1), (0xDD, 2), (0xDD, 3)], (0xDD, 3), true, "newest key survives eviction")]
    fn symbol_cache_behavior(
        #[case] capacity: usize,
        #[case] keys_to_insert: &[(u8, u64)],
        #[case] lookup_key: (u8, u64),
        #[case] expect_hit: bool,
        #[case] description: &str,
    ) {
        let cache = SymbolCache::new(capacity);
        let frame = ResolvedFrame::Symbolized(SymbolInfo::unknown());

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
}
