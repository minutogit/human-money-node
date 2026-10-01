use std::collections::VecDeque;
use serde::{Deserialize, Serialize};

pub const DEFAULT_RECENT_LOCKS_CAPACITY: usize = 32;

/// Maturity / verification status for the lightweight lock ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecentLockStatus {
    Verified,
    Provisional,
    Conflict,
}

/// Lightweight summary of a recently processed lock (< 1µs RAM footprint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentLockSummary {
    pub parent_lock_hex: String,
    pub child_lock_hex: String,
    pub timestamp_ms: u64,
    pub status: RecentLockStatus,
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub byte_years: u64,
    #[serde(default)]
    pub voucher_id: Option<String>,
}

/// Detailed live inspection of a lock from the RAM index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockInspection {
    pub parent_lock_hex: String,
    pub lock_id_hex: String,
    pub receiver_pub_hex: String,
    pub created_at_ms: u64,
    pub valid_until_ms: u64,
    pub status: String,
    pub signers_count: usize,
}

/// Lightweight summary of an active voucher in the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoucherSummaryDto {
    pub voucher_id: String,
    pub root_valid_until_ms: u64,
    pub root_valid_until_formatted: String,
    pub created_at_ms: u64,
    pub locks_count: usize,
    pub genesis_tag: Option<String>,
    pub status: String,
}

/// Detailed voucher inspection including all hops in the lock chain and raw entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoucherDetailDto {
    pub voucher_id: String,
    pub root_valid_until_ms: u64,
    pub root_valid_until_formatted: String,
    pub created_at_ms: u64,
    pub genesis_tag: Option<String>,
    pub total_byte_years: u64,
    pub locks: Vec<VoucherLockHopDto>,
}

/// Alias for VoucherDetailDto representing the full voucher lineage.
pub type VoucherLineageDto = VoucherDetailDto;

/// Single hop in a voucher lock lineage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoucherLockHopDto {
    pub lookup_tag: String,
    pub is_genesis: bool,
    pub t_id_hex: String,
    pub sender_pub_hex: String,
    pub receiver_pub_hex: Option<String>,
    pub encrypted_timestamp: u128,
    pub deletable_at: Option<String>,
    pub status: String,
    pub raw_json: serde_json::Value,
}

/// Zero-contention FIFO ring buffer for the latest max 32 locks (Spec 06 & Spec 12).
#[derive(Debug, Clone)]
pub struct RecentLockBuffer {
    buffer: VecDeque<RecentLockSummary>,
    capacity: usize,
}

impl Default for RecentLockBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_RECENT_LOCKS_CAPACITY)
    }
}

impl RecentLockBuffer {
    /// Creates a new ring buffer with fixed maximum capacity (default: 32).
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Pushes a new lock entry into the buffer.
    /// Upon reaching maximum capacity, the oldest entry is evicted (FIFO).
    pub fn push(&mut self, summary: RecentLockSummary) {
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(summary);
    }

    /// Returns the most recent locks up to the limit (newest first).
    pub fn get_recent(&self, limit: usize) -> Vec<RecentLockSummary> {
        let count = limit.min(self.buffer.len());
        self.buffer.iter().rev().take(count).cloned().collect()
    }

    /// Returns the number of entries currently in the ring buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Checks if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns the maximum capacity of the buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fifo_eviction_at_32_items() {
        let mut ring = RecentLockBuffer::new(32);
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
        assert_eq!(ring.capacity(), 32);

        for i in 0..40 {
            ring.push(RecentLockSummary {
                parent_lock_hex: format!("parent_{:02}", i),
                child_lock_hex: format!("child_{:02}", i),
                timestamp_ms: 1000 + i,
                status: if i % 2 == 0 {
                    RecentLockStatus::Verified
                } else {
                    RecentLockStatus::Conflict
                },
                tier: if i % 2 == 0 { "VIP".to_string() } else { "Free".to_string() },
                byte_years: if i % 2 == 0 { 120 } else { 0 },
                voucher_id: Some(format!("voucher_{}", i)),
            });
        }

        assert_eq!(ring.len(), 32);
        assert!(!ring.is_empty());

        // Limit 10: newest 10 (39 down to 30)
        let recent10 = ring.get_recent(10);
        assert_eq!(recent10.len(), 10);
        assert_eq!(recent10[0].parent_lock_hex, "parent_39");
        assert_eq!(recent10[9].parent_lock_hex, "parent_30");

        // Limit 50: all 32 items (39 down to 8)
        let all = ring.get_recent(50);
        assert_eq!(all.len(), 32);
        assert_eq!(all[0].parent_lock_hex, "parent_39");
        assert_eq!(all[31].parent_lock_hex, "parent_08");
    }

    #[test]
    fn test_thread_safety_concurrent_pushes_and_reads() {
        use std::sync::Arc;
        use parking_lot::RwLock;

        let buffer = Arc::new(RwLock::new(RecentLockBuffer::new(32)));
        let mut handles = Vec::new();

        for t in 0..4 {
            let b = Arc::clone(&buffer);
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    b.write().push(RecentLockSummary {
                        parent_lock_hex: format!("p_{}_{}", t, i),
                        child_lock_hex: format!("c_{}_{}", t, i),
                        timestamp_ms: (t * 100 + i) as u64,
                        status: RecentLockStatus::Verified,
                        tier: "P2P-Sync".to_string(),
                        byte_years: 0,
                        voucher_id: None,
                    });
                    let _ = b.read().get_recent(5);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(buffer.read().len(), 32);
    }
}
