//! # Node Security & Audit Event Log (Phase 2)
//!
//! Stores a fixed-capacity ring buffer of 1000 items in RAM.
//! Thread-safe with `RwLock` and monotonic sequence IDs.
//!
//! ## Architectural Invariants:
//! - INV-1701: Telemetry & security audit logs are purely diagnostic and operator-facing.
//! - Fixed RAM ceiling: 1000 items * ~200 bytes ≈ 200 KB in memory.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::api::health::HealthLevel;

/// Maximum number of audit events retained in memory before FIFO eviction.
pub const EVENT_LOG_CAPACITY: usize = 1000;

/// Category of node audit or security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    PeerConnect,
    PeerDisconnect,
    EquivocationFraud,
    PeerBan,
    QuotaTopup,
    ClientRegistered,
    ClientRemoved,
    HealthWarning,
    System,
}

/// A single recorded audit or security event entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventItem {
    pub id: u64,
    pub timestamp_sec: u64,
    pub kind: EventKind,
    pub severity: HealthLevel,
    pub message: String,
}

/// In-memory ring buffer for audit and security events.
#[derive(Debug)]
pub struct EventLog {
    buffer: Arc<RwLock<VecDeque<EventItem>>>,
    next_id: AtomicU64,
    capacity: usize,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new(EVENT_LOG_CAPACITY)
    }
}

impl EventLog {
    /// Creates a new `EventLog` with specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(capacity.min(EVENT_LOG_CAPACITY)))),
            next_id: AtomicU64::new(1),
            capacity,
        }
    }

    /// Records an event with the current timestamp.
    pub fn record(&self, kind: EventKind, severity: HealthLevel, msg: impl Into<String>) -> u64 {
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.record_at(now_sec, kind, severity, msg)
    }

    /// Records an event with an explicit timestamp (e.g. synchronized network time or testing).
    pub fn record_at(&self, timestamp_sec: u64, kind: EventKind, severity: HealthLevel, msg: impl Into<String>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let item = EventItem {
            id,
            timestamp_sec,
            kind,
            severity,
            message: msg.into(),
        };

        let mut guard = self.buffer.write();
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(item);
        id
    }

    /// Returns the number of events currently in the log.
    pub fn len(&self) -> usize {
        self.buffer.read().len()
    }

    /// True if no events have been recorded.
    pub fn is_empty(&self) -> bool {
        self.buffer.read().is_empty()
    }

    /// Maximum capacity of the ring buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Queries events, optionally filtered to those with `id > since_id` and capped by `limit`.
    ///
    /// Results are returned in chronological order (oldest to newest among matching).
    pub fn query(&self, since_id: Option<u64>, limit: Option<usize>) -> Vec<EventItem> {
        let guard = self.buffer.read();
        let iter = guard.iter().filter(|item| {
            if let Some(min_id) = since_id {
                item.id > min_id
            } else {
                true
            }
        });

        match limit {
            Some(l) => {
                // If limit is specified and there are more items, return the most recent `l` items
                let items: Vec<EventItem> = iter.cloned().collect();
                if items.len() > l {
                    items[items.len() - l..].to_vec()
                } else {
                    items
                }
            }
            None => iter.cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_log_overflow_eviction() {
        let log = EventLog::new(3);
        assert_eq!(log.capacity(), 3);
        assert!(log.is_empty());

        let _id1 = log.record_at(100, EventKind::System, HealthLevel::Ok, "Event 1");
        let id2 = log.record_at(101, EventKind::PeerConnect, HealthLevel::Ok, "Event 2");
        let id3 = log.record_at(102, EventKind::QuotaTopup, HealthLevel::Ok, "Event 3");
        assert_eq!(log.len(), 3);

        // Fourth event should evict event 1
        let id4 = log.record_at(103, EventKind::PeerBan, HealthLevel::Crit, "Event 4");
        assert_eq!(log.len(), 3);

        let items = log.query(None, None);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].id, id2);
        assert_eq!(items[1].id, id3);
        assert_eq!(items[2].id, id4);
        assert_eq!(items[2].severity, HealthLevel::Crit);
        assert_eq!(items[2].kind, EventKind::PeerBan);
    }

    #[test]
    fn test_event_log_since_id_and_limit() {
        let log = EventLog::new(100);
        for i in 1..=10 {
            log.record_at(
                1000 + i,
                EventKind::HealthWarning,
                HealthLevel::Warn,
                format!("Warning {}", i),
            );
        }

        assert_eq!(log.len(), 10);

        // Query since id 6 -> should yield items 7..=10
        let since_6 = log.query(Some(6), None);
        assert_eq!(since_6.len(), 4);
        assert_eq!(since_6[0].id, 7);
        assert_eq!(since_6[3].id, 10);

        // Query with limit 2 -> last 2 items (9, 10)
        let limited = log.query(None, Some(2));
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].id, 9);
        assert_eq!(limited[1].id, 10);

        // Query since id 8 with limit 1 -> item 10
        let since_and_limit = log.query(Some(8), Some(1));
        assert_eq!(since_and_limit.len(), 1);
        assert_eq!(since_and_limit[0].id, 10);
    }

    #[test]
    fn test_event_serialization() {
        let item = EventItem {
            id: 42,
            timestamp_sec: 1728000000,
            kind: EventKind::EquivocationFraud,
            severity: HealthLevel::Crit,
            message: "Double sign detected".into(),
        };

        let json = serde_json::to_string(&item).expect("serialize");
        let deserialized: EventItem = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(item, deserialized);
    }
}
