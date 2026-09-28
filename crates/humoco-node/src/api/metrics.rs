use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use crate::api::routes::AppState;

/// Lock operation metrics tracker for Prometheus exposition.
#[derive(Debug, Default)]
pub struct NodeMetrics {
    pub pos_latency_count: AtomicU64,
    pub pos_latency_sum_micros: AtomicU64,
    pub locks_rejected: AtomicU64,
}

impl NodeMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a successful PoS lock verification duration.
    pub fn record_pos_latency(&self, duration: Duration) {
        self.pos_latency_count.fetch_add(1, Ordering::Relaxed);
        self.pos_latency_sum_micros.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Records a rejected lock due to conflict (409) or backpressure/quota (429).
    pub fn record_lock_rejected(&self) {
        self.locks_rejected.fetch_add(1, Ordering::Relaxed);
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

    pub fn locks_rejected(&self) -> u64 {
        self.locks_rejected.load(Ordering::Relaxed)
    }
}

/// Handler for GET /metrics rendering Prometheus / OpenMetrics format.
pub async fn prometheus_metrics(State(state): State<AppState>) -> Response {
    let active_locks = state.engine.ram.read().await.len() + state.engine.hmc_ram.read().await.locks.len();
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
