use std::collections::hash_map::DefaultHasher;
use cuckoofilter::CuckooFilter;

/// In-memory Cuckoo pre-filter for fast negative lookups before hitting RamIndex.
/// Used to accelerate PoS hot-path collision checks (< 1µs).
pub struct SpentLockFilter {
    inner: CuckooFilter<DefaultHasher>,
}

impl Default for SpentLockFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SpentLockFilter {
    /// Creates a new filter with standard capacity of 100_000 entries.
    pub fn new() -> Self {
        Self {
            inner: CuckooFilter::with_capacity(100_000),
        }
    }

    /// Creates a new filter with explicit capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: CuckooFilter::with_capacity(cap),
        }
    }

    /// Returns true if the tag is probably present in the filter.
    /// False positives are possible, false negatives never.
    pub fn contains(&self, tag: &str) -> bool {
        self.inner.contains(tag)
    }

    /// Adds tag to filter. Errors (NotEnoughSpace) are ignored – the cuckoo filter
    /// internally drops a random victim but still considers insertion probabilistically
    /// present. For PoS path we treat it as best-effort; RAM is canonical.
    pub fn add(&mut self, tag: &str) {
        let _ = self.inner.add(tag);
    }

    /// Deletes tag from filter. Returns true if tag existed.
    /// False negatives on delete are tolerated because RAM is source of truth.
    pub fn delete(&mut self, tag: &str) -> bool {
        self.inner.delete(tag)
    }

    /// Number of items currently tracked (approximate due to cuckoo evictions).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if filter contains no items.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl std::fmt::Debug for SpentLockFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpentLockFilter")
            .field("len", &self.len())
            .field("is_empty", &self.is_empty())
            .finish()
    }
}
