//! Spec 12 & 14: RAM Index, Ingress Window, TTL Eviction, Dual-Tier Persistence
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Instant;

use crate::types::{Hash256, LockRecord, SimTime};

/// Maximum voucher and lock validity duration: 11 years (10 years standard range max + 1 year buffer)
/// Reconciles with L1 voucher standard max issuance (10Y) + rounding & grace periods.
/// Protects L2 RAM index against permanent state bloat and eternal griefing attacks.
pub const MAX_LOCK_TTL_YEARS: u64 = 11;
pub const MAX_LOCK_TTL_SECONDS: u64 = MAX_LOCK_TTL_YEARS * crate::quota::SECONDS_PER_YEAR; // 346_896_000 seconds
pub const MAX_LOCK_TTL_MS: u64 = MAX_LOCK_TTL_SECONDS * 1_000; // 346_896_000_000 ms

/// Ingress time window: now+30s < valid_until <= root.valid_until <= now + MAX_LOCK_TTL_MS (INV-1202)
pub fn ingress_time_window_valid(now: SimTime, valid_until: SimTime, root_valid_until: SimTime) -> bool {
    // valid_until must be strictly > now + 30s, <= root_valid_until, and root_valid_until <= now + 11 years
    let min_valid = now.0.saturating_add(30_000);
    let max_valid = now.0.saturating_add(MAX_LOCK_TTL_MS);
    valid_until.0 > min_valid && valid_until.0 <= root_valid_until.0 && root_valid_until.0 <= max_valid
}

/// Should prune if now > root.valid_until + 30s grace (INV-1203)
pub fn should_prune(now: SimTime, root_valid_until: SimTime) -> bool {
    let prune_threshold = root_valid_until.0.saturating_add(30_000);
    now.0 > prune_threshold
}

/// Hot-path RAM Index with O(1) First-Seen CAS (INV-1201/1202)
pub struct RamIndex {
    /// parent_lock -> StoredLock (224B concept, stored as LockRecord)
    map: HashMap<Hash256, LockRecord>,
    /// root valid_until per parent for TTL enforcement
    root_valid: HashMap<Hash256, SimTime>,
    /// Bucket index: valid_until_seconds / 60 -> Vec<parent_lock> for O(1) bucket pruning (INV-1203)
    ttl_buckets: BTreeMap<u64, Vec<Hash256>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IngressVerdictLow {
    AcceptedNew,
    IdempotentReplay,
    RejectedWindow,
    RejectedCollision,
    RejectedCapacity,
}

impl RamIndex {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            root_valid: HashMap::new(),
            ttl_buckets: BTreeMap::new(),
        }
    }
    /// Insert with First-Seen semantics and ingress window check
    /// Returns IdempotentReplay if same lock id, RejectedCollision if parent already locked with different lock
    pub fn try_insert(
        &mut self,
        record: LockRecord,
        now: SimTime,
        root_valid_until: SimTime,
    ) -> Result<IngressVerdictLow, IngressVerdictLow> {
        if !ingress_time_window_valid(now, record.valid_until, root_valid_until) {
            return Err(IngressVerdictLow::RejectedWindow);
        }
        let parent = record.parent_lock;
        if let Some(existing) = self.map.get(&parent) {
            if existing.id == record.id {
                return Ok(IngressVerdictLow::IdempotentReplay);
            } else {
                return Err(IngressVerdictLow::RejectedCollision);
            }
        }
        let prune_threshold_ms = root_valid_until.0.saturating_add(30_000);
        let bucket_sec = prune_threshold_ms / 1_000; // 1-second prune buckets
        self.ttl_buckets.entry(bucket_sec).or_default().push(parent);
        self.root_valid.insert(parent, root_valid_until);
        self.map.insert(parent, record);
        Ok(IngressVerdictLow::AcceptedNew)
    }
    pub fn get(&self, parent: &Hash256) -> Option<&LockRecord> {
        self.map.get(parent)
    }
    pub fn get_mut(&mut self, parent: &Hash256) -> Option<&mut LockRecord> {
        self.map.get_mut(parent)
    }
    pub fn replace_lock(&mut self, record: LockRecord, root_valid_until: SimTime) {
        let parent = record.parent_lock;
        let prune_threshold_ms = root_valid_until.0.saturating_add(30_000);
        let bucket_sec = prune_threshold_ms / 1_000;
        self.ttl_buckets.entry(bucket_sec).or_default().push(parent);
        self.root_valid.insert(parent, root_valid_until);
        self.map.insert(parent, record);
    }
    /// Cold-start recovery from disk persistence: bypasses ingress window check (INV-1202 only applies to new ingress)
    pub fn insert_recovered(&mut self, record: LockRecord, root_valid_until: SimTime) {
        let parent = record.parent_lock;
        let prune_threshold_ms = root_valid_until.0.saturating_add(30_000);
        let bucket_sec = prune_threshold_ms / 1_000;
        self.ttl_buckets.entry(bucket_sec).or_default().push(parent);
        self.root_valid.insert(parent, root_valid_until);
        self.map.insert(parent, record);
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Returns a list of all currently stored locks in the RAM index with their root valid times.
    pub fn all_locks(&self) -> Vec<(LockRecord, SimTime)> {
        self.map
            .values()
            .map(|r| {
                let rv = self.root_valid.get(&r.parent_lock).copied().unwrap_or(SimTime(0));
                (r.clone(), rv)
            })
            .collect()
    }
    /// Zero-cost TTL eviction: prune all bucket entries where now > root_valid + 30s
    /// Returns number pruned
    pub fn prune_expired(&mut self, now: SimTime) -> usize {
        let before = self.map.len();
        // All buckets with prune_threshold_ms < now.0 can be safely purged
        let max_expired_sec = if now.0 > 0 { (now.0 - 1) / 1_000 } else { 0 };

        let expired_bucket_keys: Vec<u64> = self
            .ttl_buckets
            .range(..=max_expired_sec)
            .map(|(b, _)| *b)
            .collect();

        for bucket in expired_bucket_keys {
            if let Some(parents) = self.ttl_buckets.remove(&bucket) {
                for p in parents {
                    if let Some(rv) = self.root_valid.get(&p) {
                        if should_prune(now, *rv) {
                            self.map.remove(&p);
                            self.root_valid.remove(&p);
                        }
                    }
                }
            }
        }

        before - self.map.len()
    }
    /// Measure First-Seen latency (<1ms for test, actual <1us)
    pub fn bench_first_seen_latency(&mut self, samples: usize) -> std::time::Duration {
        let start = Instant::now();
        for i in 0..samples {
            let mut parent = [0xAB; 32];
            parent[0] = (i & 0xFF) as u8;
            parent[1] = ((i>>8)&0xFF) as u8;
            parent[2] = ((i>>16)&0xFF) as u8;
            let rec = LockRecord::new(parent, [0xCC;32], vec![i as u8], SimTime(0), SimTime(60_000));
            let _ = self.try_insert(rec, SimTime(0), SimTime(600_000));
        }
        start.elapsed()
    }
}

impl Default for RamIndex {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Dual-Tier Persistence (INV-1401) : WAL + async redb-like + crash recovery
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct WalEntry {
    pub lock: LockRecord,
    pub root_valid_until: SimTime,
    pub seq: u64,
}

pub struct DualTierStorage {
    pub ram: RamIndex,
    pub wal: VecDeque<WalEntry>,
    /// Simulated persistent disk table (TABLE_ACTIVE_LOCKS)
    pub disk: BTreeMap<Hash256, (LockRecord, SimTime)>, // parent -> (record, root_valid)
    next_seq: u64,
}

impl DualTierStorage {
    pub fn new() -> Self {
        Self { ram: RamIndex::new(), wal: VecDeque::new(), disk: BTreeMap::new(), next_seq: 0 }
    }
    /// Hot-path insert: RAM immediately, WAL queued (async)
    pub fn ingress(&mut self, record: LockRecord, now: SimTime, root_valid_until: SimTime) -> Result<IngressVerdictLow, IngressVerdictLow> {
        let res = self.ram.try_insert(record.clone(), now, root_valid_until)?;
        // async WAL enqueue (non-blocking)
        self.wal.push_back(WalEntry { lock: record, root_valid_until, seq: self.next_seq });
        self.next_seq += 1;
        Ok(res)
    }
    /// Simulate async persistence worker draining WAL to disk (ACID)
    pub fn persist_flush(&mut self) -> usize {
        let mut n = 0;
        while let Some(entry) = self.wal.pop_front() {
            // Zero-I/O blocking simulation: just insert into disk map
            self.disk.insert(entry.lock.parent_lock, (entry.lock, entry.root_valid_until));
            n += 1;
        }
        n
    }
    /// Crash: drop RAM, keep disk+wal (wal may be partially persisted, but on real redb WAL is durable)
    /// For simulation, we keep wal as durable as well.
    pub fn crash(&mut self) {
        // RAM lost
        self.ram = RamIndex::new();
    }
    /// Recovery: reload all non-expired locks from disk + replay WAL
    pub fn recover(&mut self, now: SimTime) {
        // First flush any remaining WAL to disk before reload (simulate WAL replay)
        self.persist_flush();
        self.ram = RamIndex::new();
        for (_parent, (rec, root_valid)) in self.disk.clone() {
            if !should_prune(now, root_valid) && rec.valid_until > now {
                let _ = self.ram.try_insert(rec, now, root_valid);
            }
        }
        // Also replay wal entries that were not yet flushed (already flushed above, but keep logic)
        for entry in self.wal.clone() {
            if !should_prune(now, entry.root_valid_until) {
                let _ = self.ram.try_insert(entry.lock, now, entry.root_valid_until);
            }
        }
    }
    pub fn ram_len(&self) -> usize { self.ram.len() }
    pub fn disk_len(&self) -> usize { self.disk.len() }
    pub fn wal_len(&self) -> usize { self.wal.len() }
}

impl Default for DualTierStorage {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SimTime;
    #[test]
    fn test_window_and_prune() {
        let now = SimTime(1000);
        let rv = SimTime(60000);
        assert!(!ingress_time_window_valid(now, SimTime(31000), rv)); // need > now+30s = 31000 -> > not >=, so 31000 fails
        assert!(ingress_time_window_valid(now, SimTime(31001), rv));
        assert!(!ingress_time_window_valid(now, SimTime(61000), rv)); // > rv fails

        assert!(!should_prune(SimTime(90000), rv)); // 90000 == 60000+30000 not >, so false
        assert!(should_prune(SimTime(90001), rv));
    }
}
