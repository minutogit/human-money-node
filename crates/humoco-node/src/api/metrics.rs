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
    let peers_connected = if let Some(ref pm) = state.peer_manager {
        pm.connected_peer_count().await
    } else {
        0
    };
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
