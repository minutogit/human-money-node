#![forbid(unsafe_code)]

//! CEH State Snapshotting & `closed_state_root` Aggregation.
//!
//! Provides deterministic state closure across epoch transitions:
//! - Collects unexpired, active locks for a shard.
//! - Canonical sorting by `(parent_lock, child_lock)` ensures replica-independent determinism.
//! - Computes cryptographic `closed_state_root` via length-prefixed BLAKE3 domain tags.
//! - Merges / reconciles active lock state across honest predecessor replicas (Set-Union).

use std::collections::BTreeSet;

/// Represents an active collision lock record within a shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct ActiveLockEntry {
    pub parent_lock: [u8; 32],
    pub child_lock: [u8; 32],
    pub valid_until: u64,
}

impl ActiveLockEntry {
    pub fn new(parent_lock: [u8; 32], child_lock: [u8; 32], valid_until: u64) -> Self {
        Self {
            parent_lock,
            child_lock,
            valid_until,
        }
    }
}

/// Shard State Snapshot frozen during `FENCE_LOCKED`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ShardStateSnapshot {
    pub shard_id: u16,
    pub epoch: u64,
    /// Canonical ordered set of active locks.
    pub active_locks: BTreeSet<ActiveLockEntry>,
    /// Cryptographic state root calculated over active locks.
    pub closed_state_root: [u8; 32],
}

impl ShardStateSnapshot {
    /// Builds a new snapshot from a set of active locks and computes the deterministic `closed_state_root`.
    pub fn build(shard_id: u16, epoch: u64, locks: BTreeSet<ActiveLockEntry>) -> Self {
        let root = compute_closed_state_root(shard_id, epoch, &locks);
        Self {
            shard_id,
            epoch,
            active_locks: locks,
            closed_state_root: root,
        }
    }

    /// Checks if a given `parent_lock` is committed in this snapshot.
    pub fn contains_parent(&self, parent_lock: &[u8; 32]) -> bool {
        self.active_locks.iter().any(|entry| entry.parent_lock == *parent_lock)
    }

    /// Checks if a specific `(parent_lock, child_lock)` pair is present in this snapshot.
    pub fn contains_lock(&self, parent_lock: &[u8; 32], child_lock: &[u8; 32]) -> bool {
        self.active_locks
            .iter()
            .any(|entry| entry.parent_lock == *parent_lock && entry.child_lock == *child_lock)
    }

    /// Merges another honest replica's active locks into this snapshot (Set-Union),
    /// discarding any locks whose `valid_until <= current_time`.
    pub fn reconcile_union(
        &mut self,
        other_locks: impl IntoIterator<Item = ActiveLockEntry>,
        current_time: u64,
    ) {
        for lock in other_locks {
            if lock.valid_until > current_time {
                self.active_locks.insert(lock);
            }
        }
        // Recompute root after union reconciliation
        self.closed_state_root = compute_closed_state_root(self.shard_id, self.epoch, &self.active_locks);
    }
}

/// Computes the canonical BLAKE3 `closed_state_root` for a shard epoch snapshot.
///
/// ClosedStateRoot = BLAKE3(len || "HUMOCO_V1_CEH_STATE_ROOT" || shard_id_LE || epoch_LE || num_locks_LE || (parent || child || valid_until)*)
pub fn compute_closed_state_root(
    shard_id: u16,
    epoch: u64,
    locks: &BTreeSet<ActiveLockEntry>,
) -> [u8; 32] {
    const DOMAIN_CEH_STATE_ROOT: &[u8] = b"HUMOCO_V1_CEH_STATE_ROOT";
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_CEH_STATE_ROOT.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_CEH_STATE_ROOT);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    let num_locks = locks.len() as u64;
    hasher.update(&num_locks.to_le_bytes());

    for entry in locks {
        hasher.update(&entry.parent_lock);
        hasher.update(&entry.child_lock);
        hasher.update(&entry.valid_until.to_le_bytes());
    }

    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_root_determinism_and_sorting() {
        let lock1 = ActiveLockEntry::new([1u8; 32], [2u8; 32], 1000);
        let lock2 = ActiveLockEntry::new([3u8; 32], [4u8; 32], 2000);

        let mut set1 = BTreeSet::new();
        set1.insert(lock1);
        set1.insert(lock2);

        let mut set2 = BTreeSet::new();
        set2.insert(lock2);
        set2.insert(lock1);

        let snap1 = ShardStateSnapshot::build(42, 1, set1);
        let snap2 = ShardStateSnapshot::build(42, 1, set2);

        assert_eq!(snap1.closed_state_root, snap2.closed_state_root);
        assert!(snap1.contains_parent(&[1u8; 32]));
        assert!(snap1.contains_lock(&[1u8; 32], &[2u8; 32]));
        assert!(!snap1.contains_lock(&[1u8; 32], &[9u8; 32]));
    }

    #[test]
    fn test_snapshot_union_reconciliation() {
        let lock1 = ActiveLockEntry::new([1u8; 32], [2u8; 32], 1000);
        let lock2 = ActiveLockEntry::new([3u8; 32], [4u8; 32], 500); // Expired at t=600

        let mut snap = ShardStateSnapshot::build(42, 1, BTreeSet::from([lock1]));
        let initial_root = snap.closed_state_root;

        // Reconcile with lock2 at current_time = 600 -> lock2 must be pruned as expired
        snap.reconcile_union(vec![lock2], 600);
        assert_eq!(snap.active_locks.len(), 1);
        assert_eq!(snap.closed_state_root, initial_root);

        // Reconcile with valid unexpired lock3
        let lock3 = ActiveLockEntry::new([5u8; 32], [6u8; 32], 2000);
        snap.reconcile_union(vec![lock3], 600);
        assert_eq!(snap.active_locks.len(), 2);
        assert_ne!(snap.closed_state_root, initial_root);
    }
}
