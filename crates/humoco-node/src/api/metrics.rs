use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use parking_lot::RwLock;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::api::routes::AppState;

/// Rolling latency ring buffer for the last N samples (default 100).
#[derive(Debug)]
pub struct RollingLatencyBuffer<const N: usize = 100> {
    samples: RwLock<VecDeque<u64>>, // in microseconds
}

impl<const N: usize> Default for RollingLatencyBuffer<N> {
    fn default() -> Self {
        Self {
            samples: RwLock::new(VecDeque::with_capacity(N)),
        }
    }
}

impl<const N: usize> RollingLatencyBuffer<N> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, duration: Duration) {
        let micros = duration.as_micros() as u64;
        let mut guard = self.samples.write();
        if guard.len() >= N {
            guard.pop_front();
        }
        guard.push_back(micros);
    }

    pub fn count(&self) -> usize {
        self.samples.read().len()
    }

    pub fn avg_ms(&self) -> f64 {
        let guard = self.samples.read();
        if guard.is_empty() {
            0.0
        } else {
            let sum: u64 = guard.iter().copied().sum();
            (sum as f64) / (guard.len() as f64 * 1000.0)
        }
    }

    pub fn min_ms(&self) -> f64 {
        let guard = self.samples.read();
        guard.iter().copied().min().map(|m| (m as f64) / 1000.0).unwrap_or(0.0)
    }

    pub fn max_ms(&self) -> f64 {
        let guard = self.samples.read();
        guard.iter().copied().max().map(|m| (m as f64) / 1000.0).unwrap_or(0.0)
    }

    pub fn p95_ms(&self) -> f64 {
        let guard = self.samples.read();
        if guard.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<u64> = guard.iter().copied().collect();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64) * 0.95).ceil() as usize;
        let p95_idx = idx.saturating_sub(1).min(sorted.len() - 1);
        (sorted[p95_idx] as f64) / 1000.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyTierStats {
    pub avg_ms: f64,
    pub p95_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub sample_count: usize,
    pub sla_compliant: bool,
}

/// Lock operation metrics tracker with separated 3-tier latencies (Rolling 100).
#[derive(Debug, Default)]
pub struct NodeMetrics {
    pub local_latency: RollingLatencyBuffer<100>,
    pub quorum_latency: RollingLatencyBuffer<100>,
    pub e2e_latency: RollingLatencyBuffer<100>,
    pub pos_latency_count: AtomicU64,
    pub pos_latency_sum_micros: AtomicU64,
    pub locks_rejected: AtomicU64,
    pub rejected_conflict_409: AtomicU64,
    pub rejected_capacity_429: AtomicU64,
    pub rejected_quota_429: AtomicU64,
    pub rejected_bad_pow_400: AtomicU64,
    pub last_rejection_unix_sec: AtomicU64,
    pub total_writes: AtomicU64,
    pub total_reads: AtomicU64,
    pub ttl_purged_count: AtomicU64,
}

impl NodeMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    fn touch_last_rejection(&self) {
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_rejection_unix_sec.store(now_sec, Ordering::Relaxed);
    }

    /// Returns how many seconds ago the last rejection occurred, or `None` if no rejection has been recorded.
    pub fn last_rejection_ago_sec(&self) -> Option<u64> {
        let ts = self.last_rejection_unix_sec.load(Ordering::Relaxed);
        if ts == 0 {
            None
        } else {
            let now_sec = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Some(now_sec.saturating_sub(ts))
        }
    }

    /// Records local collision check & durable commit latency (< 20ms durable SLA).
    pub fn record_local_latency(&self, duration: Duration) {
        self.local_latency.record(duration);
    }

    /// Records P2P mesh quorum roundtrip latency (Gateway <-> Shards, < 500ms SLA).
    pub fn record_quorum_latency(&self, duration: Duration) {
        self.quorum_latency.record(duration);
    }

    /// Records end-to-end HTTP request processing latency.
    pub fn record_e2e_latency(&self, duration: Duration) {
        self.e2e_latency.record(duration);
        self.pos_latency_count.fetch_add(1, Ordering::Relaxed);
        self.pos_latency_sum_micros.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Legacy helper: records to e2e latency.
    pub fn record_pos_latency(&self, duration: Duration) {
        self.record_e2e_latency(duration);
    }

    /// Records a rejected lock due to conflict (409) or backpressure/quota (429).
    pub fn record_lock_rejected(&self) {
        self.locks_rejected.fetch_add(1, Ordering::Relaxed);
        self.touch_last_rejection();
    }

    /// Records a rejected lock specifically due to double-spend conflict (409 Conflict).
    pub fn record_rejected_conflict_409(&self) {
        self.rejected_conflict_409.fetch_add(1, Ordering::Relaxed);
        self.locks_rejected.fetch_add(1, Ordering::Relaxed);
        self.touch_last_rejection();
    }

    /// Records a rejected lock due to storage backpressure / queue full (429 Too Many Requests).
    pub fn record_rejected_capacity_429(&self) {
        self.rejected_capacity_429.fetch_add(1, Ordering::Relaxed);
        self.locks_rejected.fetch_add(1, Ordering::Relaxed);
        self.touch_last_rejection();
    }

    /// Records a rejected lock due to VIP/F2F quota exhaustion (429 Too Many Requests).
    pub fn record_rejected_quota_429(&self) {
        self.rejected_quota_429.fetch_add(1, Ordering::Relaxed);
        self.locks_rejected.fetch_add(1, Ordering::Relaxed);
        self.touch_last_rejection();
    }

    /// Records a rejected lock due to invalid, missing or weak Proof of Work (400 / 429).
    pub fn record_rejected_bad_pow_400(&self) {
        self.rejected_bad_pow_400.fetch_add(1, Ordering::Relaxed);
        self.locks_rejected.fetch_add(1, Ordering::Relaxed);
        self.touch_last_rejection();
    }

    pub fn rejected_conflict_409(&self) -> u64 {
        self.rejected_conflict_409.load(Ordering::Relaxed)
    }

    pub fn rejected_capacity_429(&self) -> u64 {
        self.rejected_capacity_429.load(Ordering::Relaxed)
    }

    pub fn rejected_quota_429(&self) -> u64 {
        self.rejected_quota_429.load(Ordering::Relaxed)
    }

    pub fn rejected_bad_pow_400(&self) -> u64 {
        self.rejected_bad_pow_400.load(Ordering::Relaxed)
    }

    pub fn last_rejection_unix_sec(&self) -> u64 {
        self.last_rejection_unix_sec.load(Ordering::Relaxed)
    }

    /// Increments the total write transactions counter.
    pub fn record_write(&self) {
        self.total_writes.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the total read queries counter.
    pub fn record_read(&self) {
        self.total_reads.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the number of purged expired TTL locks.
    pub fn record_ttl_purged(&self, count: u64) {
        self.ttl_purged_count.fetch_add(count, Ordering::Relaxed);
    }

    pub fn total_writes(&self) -> u64 {
        self.total_writes.load(Ordering::Relaxed)
    }

    pub fn total_reads(&self) -> u64 {
        self.total_reads.load(Ordering::Relaxed)
    }

    pub fn ttl_purged_count(&self) -> u64 {
        self.ttl_purged_count.load(Ordering::Relaxed)
    }

    pub fn pos_latency_count(&self) -> u64 {
        self.pos_latency_count.load(Ordering::Relaxed)
    }

    pub fn pos_latency_sum_seconds(&self) -> f64 {
        (self.pos_latency_sum_micros.load(Ordering::Relaxed) as f64) / 1_000_000.0
    }

    pub fn pos_latency_avg_ms(&self) -> f64 {
        let count = self.pos_latency_count();
        if count == 0 {
            0.0
        } else {
            (self.pos_latency_sum_micros.load(Ordering::Relaxed) as f64) / (count as f64 * 1000.0)
        }
    }

    pub fn local_stats(&self) -> LatencyTierStats {
        let count = self.local_latency.count();
        let avg = self.local_latency.avg_ms();
        LatencyTierStats {
            avg_ms: avg,
            p95_ms: self.local_latency.p95_ms(),
            min_ms: self.local_latency.min_ms(),
            max_ms: self.local_latency.max_ms(),
            sample_count: count,
            sla_compliant: count == 0 || avg < 20.0,
        }
    }

    pub fn quorum_stats(&self) -> LatencyTierStats {
        let count = self.quorum_latency.count();
        let avg = self.quorum_latency.avg_ms();
        LatencyTierStats {
            avg_ms: avg,
            p95_ms: self.quorum_latency.p95_ms(),
            min_ms: self.quorum_latency.min_ms(),
            max_ms: self.quorum_latency.max_ms(),
            sample_count: count,
            sla_compliant: count == 0 || avg < 500.0,
        }
    }

    pub fn e2e_stats(&self) -> LatencyTierStats {
        let count = self.e2e_latency.count();
        let avg = self.e2e_latency.avg_ms();
        LatencyTierStats {
            avg_ms: avg,
            p95_ms: self.e2e_latency.p95_ms(),
            min_ms: self.e2e_latency.min_ms(),
            max_ms: self.e2e_latency.max_ms(),
            sample_count: count,
            sla_compliant: count == 0 || avg < 1500.0,
        }
    }

    pub fn locks_rejected(&self) -> u64 {
        self.locks_rejected.load(Ordering::Relaxed)
    }
}

/// Handler for GET /metrics rendering Prometheus / OpenMetrics format.
pub async fn prometheus_metrics(State(state): State<AppState>) -> Response {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let (active_byte_years, _) = state.engine.get_active_footprint_byte_years(now_ms).await;
    let active_locks = state.engine.ram.read().await.len() + state.engine.hmc_ram.read().await.locks.len();
    let daily_write_quota_byte_years = state.tier_controller.calculate_daily_quota(1.0, 1.0);
    let (peers_connected, gateway_concentration_ratio, shard_subnet_dominance_max) =
        if let Some(ref pm) = state.peer_manager {
            let conn = pm.connected_peer_count().await;
            let active_nodes = pm.active_known_nodes().await;
            let diversity_data = pm.get_ingress_diversity_data().await;
            let mut ingress_counts: std::collections::HashMap<std::net::SocketAddr, usize> =
                std::collections::HashMap::new();
            for (best_ingress_peer, _) in diversity_data {
                if let Some(peer) = best_ingress_peer {
                    *ingress_counts.entry(peer).or_insert(0) += 1;
                }
            }
            let source_counts: Vec<usize> = ingress_counts.values().copied().collect();
            let conc_ratio =
                humoco_sim_core::telemetry::evaluate_gateway_concentration_ratio(&source_counts);

            let mut subnet_map: std::collections::HashMap<[u8; 3], usize> =
                std::collections::HashMap::new();
            for (_, addr) in &active_nodes {
                match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        let oct = ipv4.octets();
                        *subnet_map.entry([oct[0], oct[1], oct[2]]).or_insert(0) += 1;
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        let seg = ipv6.segments();
                        *subnet_map
                            .entry([(seg[0] >> 8) as u8, seg[0] as u8, (seg[1] >> 8) as u8])
                            .or_insert(0) += 1;
                    }
                }
            }
            let subnet_counts: Vec<usize> = subnet_map.values().copied().collect();
            let sub_dom_max =
                humoco_sim_core::telemetry::evaluate_subnet_dominance_max(&subnet_counts);
            (conn, conc_ratio, sub_dom_max)
        } else {
            (0, 0.0, 0.0)
        };
    let free_tier_enabled = 1; // Default true for standard nodes
    let uptime_sec = state.start_time.elapsed().as_secs();
    let flush_queue_depth = state.engine.flush_sender_len();

    let pos_latency_count = state.metrics.pos_latency_count();
    let pos_latency_sum = state.metrics.pos_latency_sum_seconds();
    let locks_rejected = state.metrics.locks_rejected();

    let mut body = String::new();
    body.push_str("# HELP humoco_locks_active_total Total number of active locks in memory\n");
    body.push_str("# TYPE humoco_locks_active_total gauge\n");
    body.push_str(&format!("humoco_locks_active_total {}\n", active_locks));

    body.push_str("# HELP humoco_active_byte_years Total active storage-time footprint in Byte-Years\n");
    body.push_str("# TYPE humoco_active_byte_years gauge\n");
    body.push_str(&format!("humoco_active_byte_years {}\n", active_byte_years));

    body.push_str("# HELP humoco_daily_write_quota_byte_years Daily write quota in Byte-Years\n");
    body.push_str("# TYPE humoco_daily_write_quota_byte_years gauge\n");
    body.push_str(&format!("humoco_daily_write_quota_byte_years {}\n", daily_write_quota_byte_years));

    body.push_str("# HELP humoco_p2p_connected_peers Number of active connected peers\n");
    body.push_str("# TYPE humoco_p2p_connected_peers gauge\n");
    body.push_str(&format!("humoco_p2p_connected_peers {}\n", peers_connected));

    body.push_str("# HELP humoco_node_uptime_seconds Total uptime of the node\n");
    body.push_str("# TYPE humoco_node_uptime_seconds counter\n");
    body.push_str(&format!("humoco_node_uptime_seconds {}\n", uptime_sec));

    body.push_str("# HELP humoco_flush_queue_depth Current depth of the async disk flush queue\n");
    body.push_str("# TYPE humoco_flush_queue_depth gauge\n");
    body.push_str(&format!("humoco_flush_queue_depth {}\n", flush_queue_depth));

    body.push_str("# HELP humoco_pos_latency_seconds Latency of PoS lock verification operations\n");
    body.push_str("# TYPE humoco_pos_latency_seconds summary\n");
    body.push_str(&format!("humoco_pos_latency_seconds_count {}\n", pos_latency_count));
    body.push_str(&format!("humoco_pos_latency_seconds_sum {:.6}\n", pos_latency_sum));

    body.push_str("# HELP humoco_locks_rejected_total Total number of locks rejected due to conflicts or backpressure\n");
    body.push_str("# TYPE humoco_locks_rejected_total counter\n");
    body.push_str(&format!("humoco_locks_rejected_total {}\n", locks_rejected));

    body.push_str("# HELP humoco_gateway_concentration_ratio Ratio of locks from top 2 ingress gateways\n");
    body.push_str("# TYPE humoco_gateway_concentration_ratio gauge\n");
    body.push_str(&format!("humoco_gateway_concentration_ratio {:.4}\n", gateway_concentration_ratio));

    body.push_str("# HELP humoco_shard_subnet_dominance_max Maximum percentage of shard nodes in single subnet\n");
    body.push_str("# TYPE humoco_shard_subnet_dominance_max gauge\n");
    body.push_str(&format!("humoco_shard_subnet_dominance_max {:.4}\n", shard_subnet_dominance_max));

    body.push_str("# HELP humoco_free_tier_enabled Whether free tier PoW ingress is enabled on this node (1 = true, 0 = false)\n");
    body.push_str("# TYPE humoco_free_tier_enabled gauge\n");
    body.push_str(&format!("humoco_free_tier_enabled {}\n", free_tier_enabled));

    // Rejections breakdown
    body.push_str("# HELP humoco_rejections_total Total number of rejected requests by reason\n");
    body.push_str("# TYPE humoco_rejections_total counter\n");
    body.push_str(&format!("humoco_rejections_total{{reason=\"conflict_409\"}} {}\n", state.metrics.rejected_conflict_409.load(Ordering::Relaxed)));
    body.push_str(&format!("humoco_rejections_total{{reason=\"capacity_429\"}} {}\n", state.metrics.rejected_capacity_429.load(Ordering::Relaxed)));
    body.push_str(&format!("humoco_rejections_total{{reason=\"quota_429\"}} {}\n", state.metrics.rejected_quota_429.load(Ordering::Relaxed)));
    body.push_str(&format!("humoco_rejections_total{{reason=\"bad_pow_400\"}} {}\n", state.metrics.rejected_bad_pow_400.load(Ordering::Relaxed)));

    // Persistence stats
    body.push_str("# HELP humoco_persistence_flush_batches_total Total successful persistence flush batches\n");
    body.push_str("# TYPE humoco_persistence_flush_batches_total counter\n");
    body.push_str(&format!("humoco_persistence_flush_batches_total {}\n", state.engine.stats.flush_batches_total.load(Ordering::Relaxed)));

    body.push_str("# HELP humoco_persistence_flush_ops_total Total persistence flush operations\n");
    body.push_str("# TYPE humoco_persistence_flush_ops_total counter\n");
    body.push_str(&format!("humoco_persistence_flush_ops_total {}\n", state.engine.stats.flush_ops_total.load(Ordering::Relaxed)));

    body.push_str("# HELP humoco_persistence_flush_errors_total Total persistence flush errors\n");
    body.push_str("# TYPE humoco_persistence_flush_errors_total counter\n");
    body.push_str(&format!("humoco_persistence_flush_errors_total {}\n", state.engine.stats.flush_errors_total.load(Ordering::Relaxed)));

    // Health status gauge: 0 = Ok, 1 = Warn, 2 = Crit
    let health_level = if peers_connected == 0 && !state.is_simulation {
        2 // Crit
    } else if flush_queue_depth > 1000 || !state.metrics.local_stats().sla_compliant {
        1 // Warn
    } else {
        0 // Ok
    };
    body.push_str("# HELP humoco_health_status Node health evaluation level (0=Ok, 1=Warn, 2=Crit)\n");
    body.push_str("# TYPE humoco_health_status gauge\n");
    body.push_str(&format!("humoco_health_status {}\n", health_level));

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejection_metrics_tracking() {
        let metrics = NodeMetrics::new();
        assert_eq!(metrics.last_rejection_ago_sec(), None);
        assert_eq!(metrics.locks_rejected(), 0);

        metrics.record_rejected_conflict_409();
        assert_eq!(metrics.locks_rejected(), 1);
        assert_eq!(metrics.rejected_conflict_409(), 1);
        assert!(metrics.last_rejection_ago_sec().is_some());
        assert!(metrics.last_rejection_unix_sec() > 0);

        metrics.record_rejected_capacity_429();
        assert_eq!(metrics.locks_rejected(), 2);
        assert_eq!(metrics.rejected_capacity_429(), 1);

        metrics.record_rejected_quota_429();
        assert_eq!(metrics.locks_rejected(), 3);
        assert_eq!(metrics.rejected_quota_429(), 1);

        metrics.record_rejected_bad_pow_400();
        assert_eq!(metrics.locks_rejected(), 4);
        assert_eq!(metrics.rejected_bad_pow_400(), 1);

        metrics.record_lock_rejected();
        assert_eq!(metrics.locks_rejected(), 5);
    }
}
