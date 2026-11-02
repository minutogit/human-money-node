//! Spec 12 & 14: RAM Index, Ingress Window, TTL Eviction, Dual-Tier Persistence
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use crate::types::{Hash256, LockRecord, SimTime};

/// Maximum voucher and lock validity duration: 11 years (10 years standard range max + 1 year buffer)
/// Reconciles with L1 voucher standard max issuance (10Y) + rounding & grace periods.
/// Protects L2 RAM index against permanent state bloat and eternal griefing attacks.
pub const MAX_LOCK_TTL_YEARS: u64 = 11;
pub const MAX_LOCK_TTL_SECONDS: u64 = MAX_LOCK_TTL_YEARS * crate::quota::SECONDS_PER_YEAR; // 346_896_000 seconds
pub const MAX_LOCK_TTL_MS: u64 = MAX_LOCK_TTL_SECONDS * 1_000; // 346_896_000_000 ms

/// Ingress time window: now+30s < valid_until <= root.valid_until <= now + MAX_LOCK_TTL_MS (INV-1202)
pub fn ingress_time_window_valid(
    now: SimTime,
    valid_until: SimTime,
    root_valid_until: SimTime,
) -> bool {
    // valid_until must be strictly > now + 30s, <= root_valid_until, and root_valid_until <= now + 11 years
    let min_valid = now.0.saturating_add(30_000);
    let max_valid = now.0.saturating_add(MAX_LOCK_TTL_MS);
    valid_until.0 > min_valid
        && valid_until.0 <= root_valid_until.0
        && root_valid_until.0 <= max_valid
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
    /// Output ID reference count: record.id -> count of active records with this id
    output_counts: HashMap<Hash256, usize>,
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
            output_counts: HashMap::new(),
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
        *self.output_counts.entry(record.id).or_default() += 1;
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
        if let Some(old) = self.map.insert(parent, record.clone()) {
            if old.id != record.id {
                if let std::collections::hash_map::Entry::Occupied(mut e) =
                    self.output_counts.entry(old.id)
                {
                    if *e.get() <= 1 {
                        e.remove();
                    } else {
                        *e.get_mut() -= 1;
                    }
                }
                *self.output_counts.entry(record.id).or_default() += 1;
            }
        } else {
            *self.output_counts.entry(record.id).or_default() += 1;
        }
    }
    /// Cold-start recovery from disk persistence: bypasses ingress window check (INV-1202 only applies to new ingress)
    pub fn insert_recovered(&mut self, record: LockRecord, root_valid_until: SimTime) {
        let parent = record.parent_lock;
        let prune_threshold_ms = root_valid_until.0.saturating_add(30_000);
        let bucket_sec = prune_threshold_ms / 1_000;
        self.ttl_buckets.entry(bucket_sec).or_default().push(parent);
        self.root_valid.insert(parent, root_valid_until);
        if let Some(old) = self.map.insert(parent, record.clone()) {
            if old.id != record.id {
                if let std::collections::hash_map::Entry::Occupied(mut e) =
                    self.output_counts.entry(old.id)
                {
                    if *e.get() <= 1 {
                        e.remove();
                    } else {
                        *e.get_mut() -= 1;
                    }
                }
                *self.output_counts.entry(record.id).or_default() += 1;
            }
        } else {
            *self.output_counts.entry(record.id).or_default() += 1;
        }
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Returns an iterator over all lock records stored in the RAM index.
    pub fn iter(&self) -> impl Iterator<Item = &LockRecord> {
        self.map.values()
    }
    /// Returns a list of all currently stored locks in the RAM index with their root valid times.
    pub fn all_locks(&self) -> Vec<(LockRecord, SimTime)> {
        self.map
            .values()
            .map(|r| {
                let rv = self
                    .root_valid
                    .get(&r.parent_lock)
                    .copied()
                    .unwrap_or(SimTime(0));
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
                let mut remaining = Vec::new();
                for p in parents {
                    if let Some(rv) = self.root_valid.get(&p) {
                        if should_prune(now, *rv) {
                            if let Some(rec) = self.map.remove(&p) {
                                if let std::collections::hash_map::Entry::Occupied(mut e) =
                                    self.output_counts.entry(rec.id)
                                {
                                    if *e.get() <= 1 {
                                        e.remove();
                                    } else {
                                        *e.get_mut() -= 1;
                                    }
                                }
                            }
                            self.root_valid.remove(&p);
                        } else {
                            let actual_bucket = rv.0.saturating_add(30_000) / 1_000;
                            if actual_bucket > bucket {
                                let vec = self.ttl_buckets.entry(actual_bucket).or_default();
                                if !vec.contains(&p) {
                                    vec.push(p);
                                }
                            } else {
                                remaining.push(p);
                            }
                        }
                    }
                }
                if !remaining.is_empty() {
                    self.ttl_buckets.insert(bucket, remaining);
                }
            }
        }

        before - self.map.len()
    }
    /// Examines at most `limit` expiry-index entries per pass.
    /// The current second remains pending until every entry in it is certainly expired.
    pub fn prune_expired_bounded(&mut self, now: SimTime, limit: usize) -> usize {
        let mut pruned = 0;
        for _ in 0..limit {
            let Some((&bucket, _)) = self.ttl_buckets.first_key_value() else {
                break;
            };
            if now.0 <= bucket.saturating_add(1).saturating_mul(1000) {
                break;
            }
            let parent = self.ttl_buckets.get_mut(&bucket).and_then(Vec::pop);
            if self.ttl_buckets.get(&bucket).is_some_and(Vec::is_empty) {
                self.ttl_buckets.remove(&bucket);
            }
            if let Some(parent) = parent {
                if let Some(rv) = self.root_valid.get(&parent) {
                    if should_prune(now, *rv) {
                        if let Some(rec) = self.map.remove(&parent) {
                            if let std::collections::hash_map::Entry::Occupied(mut e) =
                                self.output_counts.entry(rec.id)
                            {
                                if *e.get() <= 1 {
                                    e.remove();
                                } else {
                                    *e.get_mut() -= 1;
                                }
                            }
                        }
                        self.root_valid.remove(&parent);
                        pruned += 1;
                    } else {
                        let actual_bucket = rv.0.saturating_add(30_000) / 1_000;
                        if actual_bucket > bucket {
                            let vec = self.ttl_buckets.entry(actual_bucket).or_default();
                            if !vec.contains(&parent) {
                                vec.push(parent);
                            }
                        }
                    }
                }
            }
        }
        pruned
    }
    /// Measure First-Seen latency (<1ms for test, actual <1us)
    pub fn bench_first_seen_latency(&mut self, samples: usize) -> std::time::Duration {
        let start = Instant::now();
        for i in 0..samples {
            let mut parent = [0xAB; 32];
            parent[0] = (i & 0xFF) as u8;
            parent[1] = ((i >> 8) & 0xFF) as u8;
            parent[2] = ((i >> 16) & 0xFF) as u8;
            let rec = LockRecord::new(
                parent,
                [0xCC; 32],
                vec![i as u8],
                SimTime(0),
                SimTime(60_000),
            );
            let _ = self.try_insert(rec, SimTime(0), SimTime(600_000));
        }
        start.elapsed()
    }
    pub fn remove(&mut self, parent: &Hash256) -> Option<LockRecord> {
        let rec = self.map.remove(parent)?;
        self.root_valid.remove(parent);
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.output_counts.entry(rec.id)
        {
            if *e.get() <= 1 {
                e.remove();
            } else {
                *e.get_mut() -= 1;
            }
        }
        Some(rec)
    }
    /// Checks in O(1) time whether any stored lock record produced `id` as its output lock ID.
    pub fn has_output_id(&self, id: &Hash256) -> bool {
        self.output_counts.get(id).copied().unwrap_or(0) > 0
    }
    /// Clears all stored records, TTL tracking, and output indices.
    pub fn clear(&mut self) {
        self.map.clear();
        self.root_valid.clear();
        self.ttl_buckets.clear();
        self.output_counts.clear();
    }
}

impl Default for RamIndex {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn test_ram_index_output_counts() {
        let mut ram = RamIndex::new();
        let parent = [0x11; 32];
        let receiver = [0x22; 32];
        let now = SimTime(1000);
        let valid_until = SimTime(60_000);
        let root_valid = SimTime(120_000);

        let rec = LockRecord::new(parent, receiver, vec![1], now, valid_until);
        let rec_id = rec.id;

        assert!(!ram.has_output_id(&rec_id));
        assert_eq!(
            ram.try_insert(rec.clone(), now, root_valid),
            Ok(IngressVerdictLow::AcceptedNew)
        );
        assert!(ram.has_output_id(&rec_id));

        // Removal from ram
        assert!(ram.remove(&parent).is_some());
        assert!(!ram.has_output_id(&rec_id));
    }

    #[test]
    fn test_prune_expired_bucket_migration_on_extension() {
        let mut ram = RamIndex::new();
        let parent = [0x33; 32];
        let receiver = [0x44; 32];
        let now = SimTime(1000);
        let valid_until = SimTime(40_000);
        let root_valid_short = SimTime(50_000);

        let rec = LockRecord::new(parent, receiver, vec![2], now, valid_until);
        assert_eq!(
            ram.try_insert(rec.clone(), now, root_valid_short),
            Ok(IngressVerdictLow::AcceptedNew)
        );

        // Extend lock via replace_lock before short prune threshold
        let root_valid_extended = SimTime(200_000);
        let extended_rec = LockRecord::new(parent, receiver, vec![2], now, SimTime(150_000));
        let extended_id = extended_rec.id;
        ram.replace_lock(extended_rec, root_valid_extended);

        // Prune at time past short threshold (50_000 + 30_000 = 80_000)
        let prune_time = SimTime(85_000);
        let pruned = ram.prune_expired(prune_time);
        assert_eq!(pruned, 0, "Extended lock must not be pruned");
        assert!(ram.get(&parent).is_some(), "Lock still present");
        assert!(
            ram.has_output_id(&extended_id),
            "Extended output ID still present"
        );
        assert!(
            !ram.has_output_id(&rec.id),
            "Superseded output ID must be removed"
        );

        // Old bucket should not be lingering in ttl_buckets as stale
        let old_bucket_sec = 80_000 / 1_000;
        assert!(
            !ram.ttl_buckets.contains_key(&old_bucket_sec),
            "Expired bucket key must be purged, not kept indefinitely"
        );
    }
}
