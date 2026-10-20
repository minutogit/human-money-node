//! # Node Historical Metrics Sampling Engine (Phase 2)
//!
//! Stores a fixed-capacity ring buffer of 1440 points (24 hours at 1-minute resolution)
//! in RAM (< 200 KB).
//!
//! ## Architectural Invariants:
//! - Rule 1 (No I/O & No Mutex on the Hot Path): Sampler reads atomic counters and
//!   lock-free / cheap accessors without locking `RamIndex` during hot-path transactions.
//! - Fixed RAM ceiling: 1440 entries * ~72 bytes ≈ 104 KB maximum memory usage.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// Maximum number of historical sample points retained (24 hours at 1 min resolution).
pub const HISTORY_CAPACITY: usize = 1440;

/// Snapshot of node telemetry at a single point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryPoint {
    pub timestamp_sec: u64,
    pub write_count: u64,
    pub read_count: u64,
    pub free_writes: u64,
    pub f2f_writes: u64,
    pub vip_writes: u64,
    pub connected_peers: usize,
    pub active_locks: usize,
    pub queue_depth: usize,
    pub pow_diff: u8,
}

/// In-memory ring buffer holding historical node metrics.
#[derive(Debug, Clone)]
pub struct HistorySampler {
    buffer: Arc<RwLock<VecDeque<HistoryPoint>>>,
    capacity: usize,
    pub hourly: Arc<super::history_retention::HourlyHistory>,
}

impl Default for HistorySampler {
    fn default() -> Self {
        Self::new(HISTORY_CAPACITY)
    }
}

impl HistorySampler {
    /// Creates a new `HistorySampler` with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(capacity.min(HISTORY_CAPACITY)))),
            capacity: capacity.min(HISTORY_CAPACITY),
            hourly: Arc::new(super::history_retention::HourlyHistory::default()),
        }
    }

    /// Records a new sample point into the ring buffer.
    /// If capacity is exceeded, the oldest point is dropped.
    pub fn record(&self, point: HistoryPoint) {
        if self.capacity == 0 { return; }
        let mut guard = self.buffer.write();
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(point);
    }

    /// Current number of stored sample points.
    pub fn len(&self) -> usize {
        self.buffer.read().len()
    }

    /// True if no sample points are stored.
    pub fn is_empty(&self) -> bool {
        self.buffer.read().is_empty()
    }

    /// Maximum capacity of the sampler.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Queries historical points within a specified time window string.
    ///
    /// Supported formats:
    /// - `"1h"` / `"60m"`: last 60 minutes
    /// - `"6h"`: last 6 hours (360 points)
    /// - `"24h"` / `"1d"` / `""` / `"all"`: all available points (up to 24h)
    /// - `<N>m` / `<N>h`: arbitrary minutes or hours
    pub fn query(&self, window: &str) -> Vec<HistoryPoint> {
        let guard = self.buffer.read();
        if guard.is_empty() {
            return Vec::new();
        }

        let max_points = parse_window_to_points(window);
        let len = guard.len();
        if len <= max_points {
            guard.iter().cloned().collect()
        } else {
            let start = len - max_points;
            guard.iter().skip(start).cloned().collect()
        }
    }

    /// Spawns a background sampling task bound to the node's `AppState` and shutdown token.
    ///
    /// The sampling interval defaults to 60 seconds (or custom for testing/simulation).
    pub fn spawn_sampling_task(
        self: Arc<Self>,
        state: crate::api::routes::AppState,
        interval_dur: Duration,
        cancel_token: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval_dur);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    _ = ticker.tick() => {
                        let now_sec = state.net_time_ms() / 1000;
                        let write_count = state.metrics.total_writes();
                        let read_count = state.metrics.total_reads();
                        let (vip_writes, f2f_writes, free_writes) = state.tier_controller.tier_counters();

                        let connected_peers = if let Some(ref pm) = state.peer_manager {
                            pm.connected_peer_count().await
                        } else {
                            0
                        };

                        // Atomic / non-locking reads:
                        // RamIndex.len() uses read lock briefly, but never blocks hot-path.
                        let active_locks = state.engine.ram.read().await.len() + state.engine.hmc_ram.read().await.locks.len();
                        let queue_depth = state.engine.flush_sender_len();

                        let load_factor = (state.tier_controller.rolling_24h_average() as f64
                            / state.tier_controller.effective_ncb().max(1) as f64)
                            .clamp(0.0, 1.0);
                        let pow_diff = state.pow_engine.required_difficulty_for_load(load_factor) as u8;

                        let point = HistoryPoint {
                            timestamp_sec: now_sec,
                            write_count,
                            read_count,
                            free_writes,
                            f2f_writes,
                            vip_writes,
                            connected_peers,
                            active_locks,
                            queue_depth,
                            pow_diff,
                        };

                        let persist = self.hourly.record(point.clone());
                        self.record(point);
                        if persist { self.persist_hourly().await; }
                    }
                }
            }
            self.persist_hourly().await;
        })
    }

    async fn persist_hourly(&self) {
        let hourly = self.hourly.clone();
        match tokio::task::spawn_blocking(move || hourly.persist()).await {
            Ok(Ok(())) => {},
            other => tracing::warn!(?other, "Private hourly history could not be persisted"),
        }
    }
}

/// Parses window query parameter into maximum point count (assuming 1 point / min).
fn parse_window_to_points(window: &str) -> usize {
    let s = window.trim().to_lowercase();
    if s.is_empty() || s == "all" || s == "24h" || s == "1d" {
        return HISTORY_CAPACITY;
    }
    if let Some(m_str) = s.strip_suffix('m') {
        if let Ok(m) = m_str.parse::<usize>() {
            return m.min(HISTORY_CAPACITY);
        }
    }
    if let Some(h_str) = s.strip_suffix('h') {
        if let Ok(h) = h_str.parse::<usize>() {
            return (h * 60).min(HISTORY_CAPACITY);
        }
    }
    // Default fallback to 60 points (1h)
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_capacity_overflow() {
        let sampler = HistorySampler::new(5);
        assert_eq!(sampler.capacity(), 5);
        assert!(sampler.is_empty());

        for i in 1..=10 {
            sampler.record(HistoryPoint {
                timestamp_sec: i,
                write_count: i * 10,
                read_count: i * 5,
                free_writes: i,
                f2f_writes: i,
                vip_writes: i,
                connected_peers: 2,
                active_locks: 10,
                queue_depth: 0,
                pow_diff: 8,
            });
        }

        assert_eq!(sampler.len(), 5);
        let points = sampler.query("all");
        assert_eq!(points.len(), 5);
        // Oldest 1..=5 dropped, only 6..=10 remaining
        assert_eq!(points[0].timestamp_sec, 6);
        assert_eq!(points[4].timestamp_sec, 10);
    }

    #[test]
    fn test_history_query_windows() {
        let sampler = HistorySampler::new(1440);
        for i in 0..120 {
            sampler.record(HistoryPoint {
                timestamp_sec: 1000 + i as u64,
                write_count: i as u64,
                read_count: 0,
                free_writes: 0,
                f2f_writes: 0,
                vip_writes: 0,
                connected_peers: 1,
                active_locks: 5,
                queue_depth: 0,
                pow_diff: 8,
            });
        }

        assert_eq!(sampler.len(), 120);

        // 30m window -> 30 points
        let p30 = sampler.query("30m");
        assert_eq!(p30.len(), 30);
        assert_eq!(p30[0].write_count, 90);
        assert_eq!(p30[29].write_count, 119);

        // 1h window -> 60 points
        let p60 = sampler.query("1h");
        assert_eq!(p60.len(), 60);
        assert_eq!(p60[0].write_count, 60);

        // 2h / all -> all 120 points
        let p_all = sampler.query("all");
        assert_eq!(p_all.len(), 120);
        assert_eq!(p_all[0].write_count, 0);

        let p_empty = sampler.query("");
        assert_eq!(p_empty.len(), 120);
    }

    #[test]
    fn test_history_serialization() {
        let pt = HistoryPoint {
            timestamp_sec: 1728000000,
            write_count: 100,
            read_count: 200,
            free_writes: 50,
            f2f_writes: 30,
            vip_writes: 20,
            connected_peers: 5,
            active_locks: 42,
            queue_depth: 3,
            pow_diff: 12,
        };

        let json = serde_json::to_string(&pt).expect("serialize");
        let deserialized: HistoryPoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pt, deserialized);
    }
}
