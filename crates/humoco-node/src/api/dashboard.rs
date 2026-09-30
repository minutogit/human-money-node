use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::api::metrics::LatencyTierStats;
use crate::api::qr::generate_qr_svg;
use crate::api::routes::AppState;
use crate::api::system_stats::{SparklinesDto, SystemStatsDto};
use crate::network::manager::NetworkNodeDto;
use crate::network::peer::PeerConnectionType;
use crate::storage::recent::{
    RecentLockStatus, RecentLockSummary, VoucherSummaryDto,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermometerStatsDto {
    pub gossip_write_load: f64,
    pub gossip_read_load: f64,
    pub ncb_eff: f64,
    pub ncb_read_eff: f64,
    pub daily_write_quota: u64,
    pub daily_read_quota: u64,
    pub today_write_used: u64,
    pub today_read_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VipAccountDto {
    pub account_tag: String,
    pub balance_byte_years: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierOverviewDto {
    pub free_pow_diff: u32,
    pub free_req_sec: f64,
    pub friends_reserved_pct: f64,
    pub friends_used_pct: f64,
    pub vip_reserved_pct: f64,
    pub vip_used_pct: f64,
    pub vip_accounts: Vec<VipAccountDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct F2fFriendDto {
    pub node_id: String,
    pub public_key: String,
    pub address: String,
    pub is_connected: bool,
    pub last_seen_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct F2fOverviewDto {
    pub my_pubkey: String,
    pub friends: Vec<F2fFriendDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddFriendRequest {
    pub pubkey: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddFriendResponse {
    pub status: String,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveFriendResponse {
    pub status: String,
    pub removed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopupQuotaRequest {
    pub account_tag: String,
    pub byte_years: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopupQuotaResponse {
    pub status: String,
    pub account_tag: String,
    pub new_balance: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecentLockDto {
    pub parent_lock_hex: String,
    pub child_lock_hex: String,
    pub timestamp_ms: u64,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShardScoreSampleDto {
    pub shard_id: u16,
    pub score: f64,
    pub is_responsible: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardData {
    pub status: String,
    pub status_badge: String,
    pub node_id: String,
    pub public_key: String,
    pub hrw_routing_id: String,
    pub peering_string: String,
    pub uptime_seconds: u64,
    pub uptime_formatted: String,
    pub active_locks: usize,
    pub flush_queue_depth: usize,
    pub connected_peers: usize,
    pub configured_peers: usize,
    pub active_nodes_count: usize,

    // 3-Tier Latencies (Rolling 100)
    pub local_latency: LatencyTierStats,
    pub quorum_latency: LatencyTierStats,
    pub e2e_latency: LatencyTierStats,
    pub pos_latency_count: u64,
    pub pos_latency_avg_ms: f64,
    pub pos_sla_compliant: bool,

    // Telemetry & Security
    pub broom_patterns_detected: usize,
    pub gateway_concentration_ratio: f64,
    pub shard_subnet_dominance_max: f64,
    pub free_tier_enabled: bool,
    pub warnings: Vec<String>,

    // Shard Topology
    pub total_shards: usize,
    pub shard_mode: String,
    pub shard_responsibility_ratio: f64,
    pub sample_shard_scores: Vec<ShardScoreSampleDto>,

    // Network & Peer Explorer
    pub network_nodes: Vec<NetworkNodeDto>,

    // Vouchers
    pub active_vouchers: Vec<VoucherSummaryDto>,

    // Recent Locks
    pub recent_locks: Vec<RecentLockDto>,

    // Dashboard v2 New Observatory Extensions
    pub system: SystemStatsDto,
    pub thermometer: ThermometerStatsDto,
    pub sparklines: SparklinesDto,
    pub tiers: TierOverviewDto,
    pub f2f: F2fOverviewDto,
}

/// Type alias for DashboardData DTO
pub type DashboardDataDto = DashboardData;

/// Computes the node's peering string `<pubkey>@<ip>:9090`
pub fn determine_peering_string(state: &AppState) -> String {
    let pubkey = state.identity.public_key_hex();
    let addr = if let Some(ref t) = state.transport {
        t.local_addr().ok().map(|a| {
            if a.ip().is_unspecified() {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), a.port())
            } else {
                a
            }
        })
    } else {
        None
    };
    let addr_str = addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());
    format!("{}@{}", pubkey, addr_str)
}

fn format_uptime(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, mins, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, secs)
    } else {
        format!("{}m {}s", mins, secs)
    }
}

pub async fn collect_dashboard_data(state: &AppState) -> DashboardData {
    let uptime = state.start_time.elapsed();
    let uptime_formatted = format_uptime(uptime);
    let peering_string = determine_peering_string(state);
    let local_pubkey_bytes = *state.identity.public_key().as_bytes();
    let local_hrw = state.identity.hrw_routing_id();
    let local_addr = state.transport.as_ref().and_then(|t| t.local_addr().ok());

    let (
        connected_peers,
        configured_peers,
        active_nodes_count,
        broom_patterns_detected,
        gateway_concentration_ratio,
        shard_subnet_dominance_max,
        warnings,
        network_nodes,
    ): (
        usize,
        usize,
        usize,
        usize,
        f64,
        f64,
        Vec<String>,
        Vec<NetworkNodeDto>,
    ) = if let Some(ref pm) = state.peer_manager {
        let conn = pm.connected_peer_count().await;
        let conf = pm.all_peer_addrs().await.len();
        let active_nodes = pm.active_known_nodes().await;
        let act = active_nodes.len();

        let diversity_data = pm.get_ingress_diversity_data().await;
        let mut ingress_counts: std::collections::HashMap<SocketAddr, (usize, u32)> =
            std::collections::HashMap::new();
        for (best_ingress_peer, ingress_diversity_mask) in diversity_data {
            if let Some(peer) = best_ingress_peer {
                let entry = ingress_counts
                    .entry(peer)
                    .or_insert((0, ingress_diversity_mask));
                entry.0 += 1;
                entry.1 |= ingress_diversity_mask;
            }
        }
        let mut brooms = 0;
        let mut source_counts = Vec::new();
        for (count, mask) in ingress_counts.values() {
            source_counts.push(*count);
            if *count >= 10 && mask.count_ones() <= 1 {
                brooms += 1;
            }
        }
        let conc_ratio =
            humoco_sim_core::telemetry::evaluate_gateway_concentration_ratio(&source_counts);

        // Subnet dominance
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

        let mut warns = Vec::new();
        if let Some(w) =
            humoco_sim_core::telemetry::detect_gateway_concentration(&source_counts)
        {
            warns.push(w.message);
        }
        if let Some(w) =
            humoco_sim_core::telemetry::detect_shard_operator_dominance(0, &subnet_counts)
        {
            warns.push(w.message);
        }

        let nodes = pm
            .get_network_nodes_explorer(&local_pubkey_bytes, local_addr, *local_hrw)
            .await;

        (
            conn,
            conf,
            act,
            brooms,
            conc_ratio,
            sub_dom_max,
            warns,
            nodes,
        )
    } else {
        (
            0,
            0,
            0,
            0,
            0.0,
            0.0,
            Vec::new(),
            vec![NetworkNodeDto {
                node_id: hex::encode(local_pubkey_bytes),
                public_key: hex::encode(local_pubkey_bytes),
                address: local_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "127.0.0.1:9090".to_string()),
                is_f2f: false,
                is_local: true,
                connection_status: "Standalone (Village Mode)".to_string(),
                min_hops: 0,
                hrw_routing_id: hex::encode(local_hrw),
                work_score: 1,
                is_immature: false,
                pending_ticket: None,
                incubation_remaining_sec: None,
            }],
        )
    };

    let free_tier_enabled = true;

    let (status, status_badge) = if state.peer_manager.is_none() || configured_peers == 0 {
        ("VILLAGE MODE".to_string(), "VILLAGE MODE (N=1)".to_string())
    } else if connected_peers > 0 {
        ("ONLINE".to_string(), "ONLINE".to_string())
    } else {
        ("DEGRADED".to_string(), "DEGRADED (0 Peers)".to_string())
    };

    let active_locks =
        state.engine.ram.read().await.len() + state.engine.hmc_ram.read().await.locks.len();
    let flush_queue_depth = state.engine.flush_sender_len();

    // 3-Tier Latencies (Rolling 100)
    let local_latency = state.metrics.local_stats();
    let quorum_latency = state.metrics.quorum_stats();
    let e2e_latency = state.metrics.e2e_stats();

    let pos_latency_count = state.metrics.pos_latency_count();
    let pos_latency_avg_ms = state.metrics.pos_latency_avg_ms();
    let pos_sla_compliant = local_latency.sla_compliant;

    // Shard Topology
    let total_nodes = network_nodes.len().max(1);
    let (shard_mode, shard_responsibility_ratio) = if total_nodes < 20 {
        ("Global Mesh (N < 20)".to_string(), 1.0f64)
    } else {
        ("HRW Top-20 Sharding (N >= 20)".to_string(), (20.0f64 / total_nodes as f64).min(1.0f64))
    };

    let sample_shards = [0, 64, 128, 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960];
    let sample_shard_scores = sample_shards
        .into_iter()
        .map(|sid| {
            let score = humoco_sim_core::client_flow::compute_hrw_score_f64(&local_hrw, sid);
            let is_responsible = total_nodes < 20 || score > 0.05;
            ShardScoreSampleDto {
                shard_id: sid,
                score,
                is_responsible,
            }
        })
        .collect();

    // Active Vouchers
    let active_vouchers = state.engine.get_all_active_vouchers().await;

    // Recent Locks
    let recent_raw = state.engine.get_recent_locks(15);
    let recent_locks: Vec<RecentLockDto> = recent_raw
        .into_iter()
        .map(|r: RecentLockSummary| {
            let status_str = match r.status {
                RecentLockStatus::Verified => "Verified".to_string(),
                RecentLockStatus::Provisional => "Provisional".to_string(),
                RecentLockStatus::Conflict => "Conflict".to_string(),
            };
            RecentLockDto {
                parent_lock_hex: r.parent_lock_hex,
                child_lock_hex: r.child_lock_hex,
                timestamp_ms: r.timestamp_ms,
                status: status_str,
            }
        })
        .collect();

    // 1. System stats
    let system = state.system_stats.get_system_stats(
        active_locks,
        local_latency.avg_ms,
        state.metrics.ttl_purged_count(),
    );

    // 2. Thermometer stats
    let ncb_eff = state.tier_controller.effective_ncb() as f64;
    let ncb_read_eff = state.tier_controller.effective_read_ncb() as f64;
    let gossip_write_load = state.tier_controller.rolling_24h_average() as f64;
    let gossip_read_load = 0.0;
    let daily_write_quota = state.tier_controller.calculate_daily_quota(1.0, 1.0);
    let daily_read_quota = state.tier_controller.calculate_daily_read_quota(1.0, 1.0);
    let local_node_id_u16 = state.identity.node_id_u16();
    let today_write_used = state
        .tier_controller
        .thermometer()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get_node_usage(local_node_id_u16);
    let today_read_used = state
        .tier_controller
        .thermometer()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get_node_read_usage(local_node_id_u16);

    let thermometer = ThermometerStatsDto {
        gossip_write_load,
        gossip_read_load,
        ncb_eff,
        ncb_read_eff,
        daily_write_quota,
        daily_read_quota,
        today_write_used,
        today_read_used,
    };

    // 3. Sparklines
    let sparklines = state.system_stats.get_sparklines();

    // 4. Tiers Overview
    let free_pow_diff = state.pow_engine.default_difficulty();
    let free_req_sec = sparklines.writes.last().copied().unwrap_or(0.0) as f64;
    let friends_reserved_pct = 30.0;
    let friends_used_pct = if daily_write_quota > 0 {
        ((today_write_used as f64 / daily_write_quota as f64) * 100.0).min(100.0)
    } else {
        0.0
    };
    let vip_reserved_pct = 50.0;
    let vip_used_pct = 0.0;
    let vip_accounts = state
        .tier_controller
        .list_cached_vip_quotas()
        .into_iter()
        .map(|(tag, bal)| VipAccountDto {
            account_tag: hex::encode(tag),
            balance_byte_years: bal,
        })
        .collect();

    let tiers = TierOverviewDto {
        free_pow_diff,
        free_req_sec,
        friends_reserved_pct,
        friends_used_pct,
        vip_reserved_pct,
        vip_used_pct,
        vip_accounts,
    };

    // 5. F2F Overview
    let friends_list = if let Some(ref pm) = state.peer_manager {
        let peers = pm.list_peers().await;
        let mut f_list = Vec::new();
        for p in peers {
            if p.conn_type == PeerConnectionType::FriendToFriend {
                let nid_hex = p.node_id.map(hex::encode).unwrap_or_else(|| "".to_string());
                let last_seen_sec = p.last_seen.map(|t| t.elapsed().as_secs());
                f_list.push(F2fFriendDto {
                    node_id: nid_hex.clone(),
                    public_key: nid_hex,
                    address: p.addr.to_string(),
                    is_connected: p.is_connected(),
                    last_seen_sec,
                });
            }
        }
        f_list
    } else {
        Vec::new()
    };

    let f2f = F2fOverviewDto {
        my_pubkey: state.identity.public_key_hex(),
        friends: friends_list,
    };

    DashboardData {
        status,
        status_badge,
        node_id: state.identity.node_id_hex(),
        public_key: state.identity.public_key_hex(),
        hrw_routing_id: hex::encode(local_hrw),
        peering_string,
        uptime_seconds: uptime.as_secs(),
        uptime_formatted,
        active_locks,
        flush_queue_depth,
        connected_peers,
        configured_peers,
        active_nodes_count,
        local_latency,
        quorum_latency,
        e2e_latency,
        pos_latency_count,
        pos_latency_avg_ms,
        pos_sla_compliant,
        broom_patterns_detected,
        gateway_concentration_ratio,
        shard_subnet_dominance_max,
        free_tier_enabled,
        warnings,
        total_shards: 1024,
        shard_mode,
        shard_responsibility_ratio,
        sample_shard_scores,
        network_nodes,
        active_vouchers,
        recent_locks,
        system,
        thermometer,
        sparklines,
        tiers,
        f2f,
    }
}

/// Helper to verify admin authorization header.
fn verify_admin_auth(state: &AppState, headers: &axum::http::HeaderMap) -> Result<(), Response> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if !state.auth.verify_token(auth_header) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Invalid or missing admin authorization token"
            })),
        )
            .into_response());
    }
    Ok(())
}

/// Handler for POST /dashboard/admin/verify-token
pub async fn admin_verify_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(unauth) = verify_admin_auth(&state, &headers) {
        return unauth;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": "Admin token valid"
        })),
    )
        .into_response()
}

/// Handler for POST /dashboard/admin/friends
pub async fn admin_add_friend(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<AddFriendRequest>,
) -> Response {
    if let Err(unauth) = verify_admin_auth(&state, &headers) {
        return unauth;
    }

    let trimmed = payload.pubkey.trim();
    let key_bytes = match hex::decode(trimmed) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "BadRequest",
                    "message": "Invalid hex Ed25519 public key (must be 64 hex characters / 32 bytes)"
                })),
            )
                .into_response();
        }
    };

    if let Some(ref pm) = state.peer_manager {
        pm.add_trusted_f2f_peer(key_bytes).await;
        (
            StatusCode::OK,
            Json(AddFriendResponse {
                status: "ok".into(),
                pubkey: hex::encode(key_bytes),
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "PeerManagerUnavailable",
                "message": "P2P peer manager is not initialized"
            })),
        )
            .into_response()
    }
}

/// Handler for DELETE /dashboard/admin/friends/:key
pub async fn admin_remove_friend(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if let Err(unauth) = verify_admin_auth(&state, &headers) {
        return unauth;
    }

    let trimmed = key.trim();
    let key_bytes = match hex::decode(trimmed) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "BadRequest",
                    "message": "Invalid hex Ed25519 public key (must be 64 hex characters / 32 bytes)"
                })),
            )
                .into_response();
        }
    };

    if let Some(ref pm) = state.peer_manager {
        pm.remove_trusted_f2f_peer(&key_bytes).await;
        (
            StatusCode::OK,
            Json(RemoveFriendResponse {
                status: "ok".into(),
                removed: hex::encode(key_bytes),
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "PeerManagerUnavailable",
                "message": "P2P peer manager is not initialized"
            })),
        )
            .into_response()
    }
}

/// Handler for POST /dashboard/admin/quota
pub async fn admin_topup_quota(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<TopupQuotaRequest>,
) -> Response {
    if let Err(unauth) = verify_admin_auth(&state, &headers) {
        return unauth;
    }

    let trimmed = payload.account_tag.trim();
    let tag_bytes = match hex::decode(trimmed) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "BadRequest",
                    "message": "Invalid hex account tag (must be 64 hex characters / 32 bytes)"
                })),
            )
                .into_response();
        }
    };

    match state.tier_controller.topup_vip_quota(tag_bytes, payload.byte_years) {
        Ok(new_balance) => (
            StatusCode::OK,
            Json(TopupQuotaResponse {
                status: "ok".into(),
                account_tag: hex::encode(tag_bytes),
                new_balance,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "QuotaError",
                "message": e.to_string()
            })),
        )
            .into_response(),
    }
}

/// Handler for GET /dashboard/data
pub async fn dashboard_data(State(state): State<AppState>) -> (StatusCode, Json<DashboardData>) {
    let data = collect_dashboard_data(&state).await;
    (StatusCode::OK, Json(data))
}

/// Handler for GET /dashboard/vouchers
pub async fn dashboard_vouchers(
    State(state): State<AppState>,
) -> (StatusCode, Json<Vec<VoucherSummaryDto>>) {
    let vouchers = state.engine.get_all_active_vouchers().await;
    (StatusCode::OK, Json(vouchers))
}

/// Handler for GET /dashboard/voucher/:voucher_id
pub async fn dashboard_voucher_detail(
    State(state): State<AppState>,
    Path(voucher_id): Path<String>,
) -> Response {
    if let Some(detail) = state.engine.get_voucher_lineage(&voucher_id).await {
        (StatusCode::OK, Json(detail)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "VoucherNotFound", "voucher_id": voucher_id})),
        )
            .into_response()
    }
}

/// Handler for GET /dashboard/lock/:lookup_tag
pub async fn dashboard_lock_raw(
    State(state): State<AppState>,
    Path(lookup_tag): Path<String>,
) -> Response {
    if let Some(raw) = state.engine.get_raw_lock_data(&lookup_tag).await {
        (StatusCode::OK, Json(raw)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "LockNotFound", "lookup_tag": lookup_tag})),
        )
            .into_response()
    }
}

/// Handler for GET /dashboard rendering pure standalone HTML5 Dashboard v2.
pub async fn render_dashboard(State(state): State<AppState>) -> Response {
    let data = collect_dashboard_data(&state).await;
    let qr_svg = generate_qr_svg(&data.peering_string);

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HuMoCo Layer-2 Node Control Center</title>
<style>
:root {{
  --bg: #090d16;
  --surface: #111827;
  --surface-alt: #1a2234;
  --surface-hover: #232d42;
  --border: #2e384d;
  --text: #f3f4f6;
  --text-muted: #94a3b8;
  --green: #10b981;
  --green-bg: rgba(16,185,129,0.15);
  --amber: #f59e0b;
  --amber-bg: rgba(245,158,11,0.15);
  --red: #ef4444;
  --red-bg: rgba(239,68,68,0.15);
  --blue: #3b82f6;
  --blue-bg: rgba(59,130,246,0.15);
  --purple: #a855f7;
  --purple-bg: rgba(168,85,247,0.15);
  --cyan: #06b6d4;
  --cyan-bg: rgba(6,182,212,0.15);
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.5;
  padding: 1.5rem;
}}
.container {{ max-width: 1280px; margin: 0 auto; }}
header {{
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 1.25rem;
  margin-bottom: 1.25rem;
  border-bottom: 1px solid var(--border);
}}
.header-title {{ display: flex; align-items: center; gap: 0.75rem; }}
.header-title h1 {{ font-size: 1.5rem; font-weight: 700; letter-spacing: -0.025em; }}
.header-meta {{ display: flex; align-items: center; gap: 0.75rem; }}
.badge {{
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.25rem 0.75rem;
  border-radius: 9999px;
  font-size: 0.8125rem;
  font-weight: 600;
  white-space: nowrap;
}}
.badge-green {{ background: var(--green-bg); color: var(--green); border: 1px solid rgba(16,185,129,0.3); }}
.badge-amber {{ background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(245,158,11,0.3); }}
.badge-red {{ background: var(--red-bg); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }}
.badge-blue {{ background: var(--blue-bg); color: var(--blue); border: 1px solid rgba(59,130,246,0.3); }}
.badge-purple {{ background: var(--purple-bg); color: var(--purple); border: 1px solid rgba(168,85,247,0.3); }}
.badge-cyan {{ background: var(--cyan-bg); color: var(--cyan); border: 1px solid rgba(6,182,212,0.3); }}

/* Navigation Tabs */
.tabs-nav {{
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
  overflow-x: auto;
  padding-bottom: 0.5rem;
}}
.tab-btn {{
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-muted);
  padding: 0.5rem 1rem;
  border-radius: 0.5rem;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transition: all 0.2s;
  white-space: nowrap;
}}
.tab-btn:hover {{ background: var(--surface-alt); color: var(--text); }}
.tab-btn.active {{
  background: var(--blue-bg);
  color: var(--blue);
  border-color: rgba(59,130,246,0.4);
}}

.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}

.grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.25rem;
  margin-bottom: 1.5rem;
}}
.card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 0.75rem;
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
}}
.card-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
  color: var(--text-muted);
  font-size: 0.85rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}}
.card-value {{
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 0.35rem;
}}
.card-sub {{ font-size: 0.8125rem; color: var(--text-muted); }}

.identity-card {{
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 1.5rem;
  align-items: center;
}}
@media (max-width: 640px) {{
  .identity-card {{ grid-template-columns: 1fr; }}
}}
.qr-box {{
  width: 140px;
  height: 140px;
  background: #ffffff;
  border-radius: 0.5rem;
  padding: 0.35rem;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.qr-svg {{ width: 100%; height: 100%; display: block; }}
.code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.8125rem;
  background: var(--surface-alt);
  padding: 0.4rem 0.6rem;
  border-radius: 0.375rem;
  border: 1px solid var(--border);
  word-break: break-all;
}}
.peering-row {{
  display: flex;
  gap: 0.5rem;
  align-items: center;
  margin-top: 0.5rem;
}}
.btn {{
  background: var(--blue);
  color: #ffffff;
  border: none;
  border-radius: 0.375rem;
  padding: 0.4rem 0.75rem;
  font-size: 0.8125rem;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
  white-space: nowrap;
}}
.btn:hover {{ opacity: 0.9; }}
.btn-secondary {{
  background: var(--surface-alt);
  border: 1px solid var(--border);
  color: var(--text);
}}
.btn-secondary:hover {{ background: var(--surface-hover); }}

.table-card {{ grid-column: 1 / -1; margin-top: 1rem; }}
table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 0.5rem;
  font-size: 0.875rem;
}}
th {{
  text-align: left;
  padding: 0.75rem;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  font-weight: 600;
}}
td {{
  padding: 0.75rem;
  border-bottom: 1px solid var(--border);
  color: var(--text);
}}
tr:hover td {{ background: var(--surface-alt); }}
.empty-cell {{ text-align: center; color: var(--text-muted); padding: 2.5rem 0; }}

/* Shard Bar */
.shard-bar {{
  display: flex;
  width: 100%;
  height: 24px;
  background: var(--surface-alt);
  border-radius: 6px;
  overflow: hidden;
  border: 1px solid var(--border);
  margin: 1rem 0;
}}
.shard-seg {{
  height: 100%;
  transition: width 0.3s;
}}

/* Modal Overlay */
.modal-overlay {{
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.75);
  backdrop-filter: blur(4px);
  z-index: 1000;
  align-items: center;
  justify-content: center;
  padding: 1rem;
}}
.modal-overlay.active {{ display: flex; }}
.modal-box {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 0.75rem;
  max-width: 850px;
  width: 100%;
  max-height: 88vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
}}
.modal-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 1.25rem;
  border-bottom: 1px solid var(--border);
}}
.modal-header h3 {{ font-size: 1.1rem; font-weight: 700; }}
.modal-body {{
  padding: 1.25rem;
  overflow-y: auto;
  font-size: 0.875rem;
}}
.modal-footer {{
  padding: 0.75rem 1.25rem;
  border-top: 1px solid var(--border);
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}}
pre.json-viewer {{
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 1rem;
  overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 0.8125rem;
  color: #38bdf8;
}}

footer {{
  margin-top: 2rem;
  text-align: center;
  font-size: 0.75rem;
  color: var(--text-muted);
}}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-title">
      <h1>HuMoCo Layer-2 Node Control Center</h1>
      <span id="status-badge" class="badge badge-green">{status_badge}</span>
    </div>
    <div class="header-meta">
      <span class="card-sub">Uptime: <strong id="uptime-text">{uptime}</strong></span>
      <span class="badge badge-blue">v{version}</span>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <div class="tabs-nav">
    <button class="tab-btn active" onclick="switchTab('tab-performance')">📊 Performance &amp; Latenzen</button>
    <button class="tab-btn" onclick="switchTab('tab-network')">🌐 Knoten-Explorer</button>
    <button class="tab-btn" onclick="switchTab('tab-shards')">🧩 Shard-Topologie</button>
    <button class="tab-btn" onclick="switchTab('tab-vouchers')">🎟️ Gutscheine &amp; Rohdaten</button>
    <button class="tab-btn" onclick="switchTab('tab-locks')">⏱️ Live-Locks</button>
  </div>

  <!-- TAB 1: PERFORMANCE & LATENZ -->
  <div id="tab-performance" class="tab-content active">
    <div class="grid">
      <!-- 1. Lokale Shard-Verarbeitung (< 5ms SLA) -->
      <div class="card">
        <div class="card-header">
          <span>⚡ Lokale In-RAM Shard-Latenz (PoS)</span>
          <span id="sla-local-badge" class="badge badge-green">🟢 &lt; 5ms SLA Met</span>
        </div>
        <div class="card-value" id="lat-local-val">{local_avg:.2} ms</div>
        <div class="card-sub" id="lat-local-sub">Ø Rolling 100: {local_avg:.2}ms | P95: {local_p95:.2}ms (SLA &lt; 5ms)</div>
      </div>

      <!-- 2. P2P Shard-Quorum (Gateway-Roundtrip < 500ms) -->
      <div class="card">
        <div class="card-header">
          <span>🌐 P2P Quorum-Konsens (Gateway)</span>
          <span id="sla-quorum-badge" class="badge badge-green">🟢 &lt; 500ms SLA</span>
        </div>
        <div class="card-value" id="lat-quorum-val">{quorum_avg:.2} ms</div>
        <div class="card-sub" id="lat-quorum-sub">QUIC Shard-Roundtrip (14/20 Quorum) | P95: {quorum_p95:.2}ms</div>
      </div>

      <!-- 3. End-to-End Kassenpfad -->
      <div class="card">
        <div class="card-header">
          <span>🛒 End-to-End Kassen-Latenz</span>
          <span class="badge badge-blue">PoS Kassenpfad</span>
        </div>
        <div class="card-value" id="lat-e2e-val">{e2e_avg:.2} ms</div>
        <div class="card-sub" id="lat-e2e-sub">Client HTTP &rarr; 200 OK | Stichproben: <span id="sample-count-text">{sample_count}</span></div>
      </div>

      <!-- 4. Peering & Mesh Status -->
      <div class="card">
        <div class="card-header">
          <span>🛡️ Peering &amp; Mesh</span>
          <span class="badge badge-blue">{mesh_mode}</span>
        </div>
        <div class="card-value" id="peers-val">{connected_peers} <span style="font-size: 1rem; font-weight: normal; color: var(--text-muted);">/ {configured_peers} Peers</span></div>
        <div class="card-sub" id="active-nodes-sub">Aktive Netzwerkknoten (F2F): {active_nodes}</div>
      </div>

      <!-- 5. Storage & redb Flush -->
      <div class="card">
        <div class="card-header">
          <span>📊 Storage &amp; Locks</span>
          <span class="badge badge-green">redb ACID</span>
        </div>
        <div class="card-value" id="locks-val">{active_locks}</div>
        <div class="card-sub" id="flush-depth-sub">Flush-Queue Tiefe: {flush_depth} / 10000</div>
      </div>

      <!-- 6. Ingress & Telemetrie -->
      <div class="card">
        <div class="card-header">
          <span>🌐 Ingress &amp; Telemetrie</span>
          <span class="badge badge-green" id="free-tier-badge">Free Tier PoW: Aktiv</span>
        </div>
        <div class="card-value" id="conc-val">{conc_percent:.1}% <span style="font-size: 1rem; font-weight: normal; color: var(--text-muted);">Top-2 Konzentration</span></div>
        <div class="card-sub" id="subnet-dom-sub">Max Subnetz-Dominanz: {dom_percent:.1}%</div>
        <div id="warnings-box"></div>
      </div>
    </div>

    <!-- Node Identity Box -->
    <div class="card identity-card">
      <div class="qr-box">{qr_svg}</div>
      <div>
        <div class="card-header"><span>📱 Lokale Knoten-Identität &amp; Peering-String</span></div>
        <div style="font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 0.25rem;">NodePubKey: <span class="code" id="node-id-text">{node_id}</span></div>
        <div style="font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 0.25rem;">Argon2d Ticket: <span class="code">{hrw_id}</span></div>
        <div class="peering-row">
          <span class="code" id="peering-text" style="flex: 1;">{peering_str}</span>
          <button class="btn" id="copy-btn" onclick="copyPeering()">Copy</button>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: KNOTEN-EXPLORER -->
  <div id="tab-network" class="tab-content">
    <div class="card table-card">
      <div class="card-header">
        <span>🌐 Bekannte Netzwerkknoten &amp; Peers</span>
        <span class="card-sub" id="network-count-sub">{active_nodes} Knoten registriert</span>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Knoten (NodePubKey)</th>
              <th>IP-Adresse / Port</th>
              <th>Beziehung</th>
              <th>Status</th>
              <th>Hops</th>
              <th>Shard-Ticket (Argon2d)</th>
            </tr>
          </thead>
          <tbody id="nodes-tbody">
            <!-- Dynamically populated -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 3: SHARD-TOPOLOGIE -->
  <div id="tab-shards" class="tab-content">
    <div class="card">
      <div class="card-header">
        <span>🧩 1.024-Shard Topologie &amp; HRW-Zuständigkeit</span>
        <span class="badge badge-purple" id="shard-mode-badge">{shard_mode}</span>
      </div>
      <div style="margin: 0.5rem 0;">
        <div style="font-size: 0.9rem; margin-bottom: 0.25rem;">Zuständigkeitsabdeckung: <strong id="shard-ratio-text">{shard_ratio:.1}%</strong> (1.024 Shards gesamt)</div>
        <div class="shard-bar">
          <div class="shard-seg" style="width: 100%; background: linear-gradient(90deg, #10b981, #3b82f6, #a855f7);"></div>
        </div>
      </div>
      <div class="card-sub" style="margin-bottom: 1rem;">
        In Netzwerken mit N &lt; 20 Knoten (Global Mesh) ist jeder Knoten für alle 1.024 Shards verantwortlich (Q = ⌊2/3 N⌋ + 1). Ab N &ge; 20 greift die deterministische Top-20 HRW-Partitionierung (14/20 Finalität).
      </div>

      <div class="card-header" style="margin-top: 1rem;"><span>Stichproben-Shard-Scores (Lokaler Knoten)</span></div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Shard ID</th>
              <th>HRW Score (BLAKE3)</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="shards-tbody">
            <!-- Dynamically populated -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 4: GUTSCHEINE & ROHDATEN -->
  <div id="tab-vouchers" class="tab-content">
    <div class="card table-card">
      <div class="card-header">
        <span>🎟️ Aktive Gutschein-Wurzeln &amp; Lock-Lineage</span>
        <span class="card-sub">Client-Side Custody &bull; Double-Spend Prävention</span>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Gutschein-ID</th>
              <th>Wurzel-Gültigkeit (Root valid_until)</th>
              <th>Genesis-Lock Tag</th>
              <th>Sperren</th>
              <th>Status</th>
              <th>Aktion</th>
            </tr>
          </thead>
          <tbody id="vouchers-tbody">
            <!-- Dynamically populated -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 5: LIVE-LOCKS -->
  <div id="tab-locks" class="tab-content">
    <div class="card table-card">
      <div class="card-header">
        <span>⏱️ Recent Locks Ring Buffer (&lt; 1µs In-RAM)</span>
        <span class="card-sub">Neueste Sperr-Ereignisse</span>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Timestamp (ms)</th>
              <th>Parent Lock / Lookup Tag</th>
              <th>Child Lock (t_id)</th>
              <th>Status</th>
              <th>Rohdaten</th>
            </tr>
          </thead>
          <tbody id="locks-tbody">
            <!-- Dynamically populated -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <footer>
    HuMoCo Layer-2 Daemon &bull; Offline Air-Gap Dashboard v2 &bull; Auto-Refresh 3s
  </footer>
</div>

<!-- Modal: Raw JSON Inspector -->
<div id="json-modal" class="modal-overlay" onclick="closeModalOnOverlay(event)">
  <div class="modal-box">
    <div class="modal-header">
      <h3 id="modal-title">📄 Rohdaten-Inspector</h3>
      <button class="btn btn-secondary" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body">
      <div id="modal-details" style="margin-bottom: 0.75rem;"></div>
      <pre id="modal-json" class="json-viewer"></pre>
    </div>
    <div class="modal-footer">
      <button class="btn" id="modal-copy-btn" onclick="copyModalJson()">JSON Kopieren</button>
      <button class="btn btn-secondary" onclick="closeModal()">Schließen</button>
    </div>
  </div>
</div>

<script>
let currentDashboardData = null;

function switchTab(tabId) {{
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  
  event.currentTarget.classList.add('active');
  const target = document.getElementById(tabId);
  if (target) target.classList.add('active');
}}

function copyPeering() {{
  const text = document.getElementById('peering-text').innerText;
  navigator.clipboard.writeText(text).then(() => {{
    const btn = document.getElementById('copy-btn');
    const orig = btn.innerText;
    btn.innerText = 'Kopiert!';
    setTimeout(() => {{ btn.innerText = orig; }}, 1500);
  }}).catch(() => {{}});
}}

function closeModal() {{
  document.getElementById('json-modal').classList.remove('active');
}}

function closeModalOnOverlay(e) {{
  if (e.target.id === 'json-modal') closeModal();
}}

document.addEventListener('keydown', (e) => {{
  if (e.key === 'Escape') closeModal();
}});

function copyModalJson() {{
  const text = document.getElementById('modal-json').innerText;
  navigator.clipboard.writeText(text).then(() => {{
    const btn = document.getElementById('modal-copy-btn');
    const orig = btn.innerText;
    btn.innerText = 'Kopiert!';
    setTimeout(() => {{ btn.innerText = orig; }}, 1500);
  }}).catch(() => {{}});
}}

function truncateHash(hex) {{
  if (!hex || hex.length <= 16) return hex || '';
  return hex.slice(0, 8) + '…' + hex.slice(-8);
}}

async function openLockInspector(lookupTag) {{
  try {{
    const res = await fetch('/dashboard/lock/' + encodeURIComponent(lookupTag));
    if (!res.ok) return;
    const json = await res.json();
    document.getElementById('modal-title').innerText = '🔒 Sperr-Rohdaten: ' + truncateHash(lookupTag);
    document.getElementById('modal-details').innerHTML = '<strong>Lookup Tag:</strong> <span class="code">' + lookupTag + '</span>';
    document.getElementById('modal-json').innerText = JSON.stringify(json, null, 2);
    document.getElementById('json-modal').classList.add('active');
  }} catch (e) {{}}
}}

async function openVoucherInspector(voucherId) {{
  try {{
    const res = await fetch('/dashboard/voucher/' + encodeURIComponent(voucherId));
    if (!res.ok) return;
    const detail = await res.json();
    document.getElementById('modal-title').innerText = '🎟️ Gutschein-Lineage: ' + voucherId;
    
    let html = '<div style="margin-bottom: 0.75rem;">';
    html += '<div><strong>Wurzel-Anker (valid_until):</strong> ' + detail.root_valid_until_formatted + '</div>';
    html += '<div><strong>Genesis Tag:</strong> <span class="code">' + (detail.genesis_tag || 'N/A') + '</span></div>';
    html += '<div><strong>Gesamt-Sperren in Kette:</strong> ' + detail.locks.length + ' (' + detail.total_byte_years + ' Byte-Jahre Budget)</div>';
    html += '</div>';

    html += '<h4 style="margin: 0.75rem 0 0.25rem 0;">Ketten-Historie (Lock-Hops):</h4>';
    html += '<table><thead><tr><th>Typ</th><th>Lookup Tag</th><th>Child Lock (t_id)</th><th>Sender PubKey</th></tr></thead><tbody>';
    for (const h of detail.locks) {{
      const typeBadge = h.is_genesis ? '<span class="badge badge-amber">GENESIS</span>' : '<span class="badge badge-blue">SPEND</span>';
      html += '<tr><td>' + typeBadge + '</td><td class="code" title="' + h.lookup_tag + '">' + truncateHash(h.lookup_tag) + '</td><td class="code">' + truncateHash(h.t_id_hex) + '</td><td class="code">' + truncateHash(h.sender_pub_hex) + '</td></tr>';
    }}
    html += '</tbody></table>';

    document.getElementById('modal-details').innerHTML = html;
    document.getElementById('modal-json').innerText = JSON.stringify(detail, null, 2);
    document.getElementById('json-modal').classList.add('active');
  }} catch (e) {{}}
}}

async function refreshDashboard() {{
  try {{
    const res = await fetch('/dashboard/data');
    if (!res.ok) return;
    const d = await res.json();
    currentDashboardData = d;
    
    // Status
    const badge = document.getElementById('status-badge');
    badge.innerText = d.status_badge;
    badge.className = 'badge ' + (d.status === 'ONLINE' ? 'badge-green' : (d.status === 'VILLAGE MODE' ? 'badge-amber' : 'badge-red'));

    // Uptime
    document.getElementById('uptime-text').innerText = d.uptime_formatted;

    // 1. Lokale Shard-Latenz
    document.getElementById('lat-local-val').innerText = d.local_latency.avg_ms.toFixed(2) + ' ms';
    document.getElementById('lat-local-sub').innerText = 'Ø Rolling 100: ' + d.local_latency.avg_ms.toFixed(2) + 'ms | P95: ' + d.local_latency.p95_ms.toFixed(2) + 'ms (SLA < 5ms)';
    const slaLocal = document.getElementById('sla-local-badge');
    if (d.local_latency.sla_compliant) {{
      slaLocal.className = 'badge badge-green';
      slaLocal.innerHTML = '🟢 &lt; 5ms SLA Eingehalten';
    }} else {{
      slaLocal.className = 'badge badge-red';
      slaLocal.innerHTML = '🔴 &gt; 5ms SLA Warnung';
    }}

    // 2. Quorum-Latenz
    document.getElementById('lat-quorum-val').innerText = d.quorum_latency.avg_ms.toFixed(2) + ' ms';
    document.getElementById('lat-quorum-sub').innerText = 'QUIC Shard-Roundtrip (14/20 Quorum) | P95: ' + d.quorum_latency.p95_ms.toFixed(2) + 'ms';
    const slaQuorum = document.getElementById('sla-quorum-badge');
    if (d.quorum_latency.sla_compliant) {{
      slaQuorum.className = 'badge badge-green';
      slaQuorum.innerHTML = '🟢 &lt; 500ms SLA';
    }} else {{
      slaQuorum.className = 'badge badge-amber';
      slaQuorum.innerHTML = '⚠️ Hohe Quorum-Latenz';
    }}

    // 3. E2E Kassen-Latenz
    document.getElementById('lat-e2e-val').innerText = d.e2e_latency.avg_ms.toFixed(2) + ' ms';
    document.getElementById('lat-e2e-sub').innerText = 'Client HTTP → 200 OK | P95: ' + d.e2e_latency.p95_ms.toFixed(2) + 'ms (Rolling 100)';
    document.getElementById('sample-count-text').innerText = d.e2e_latency.sample_count;

    // Peers & Mesh
    document.getElementById('peers-val').innerHTML = d.connected_peers + ' <span style="font-size: 1rem; font-weight: normal; color: var(--text-muted);">/ ' + d.configured_peers + ' Peers</span>';
    document.getElementById('active-nodes-sub').innerText = 'Aktive Netzwerkknoten (F2F): ' + d.active_nodes_count;

    // Storage
    document.getElementById('locks-val').innerText = d.active_locks;
    document.getElementById('flush-depth-sub').innerText = 'Flush-Queue Tiefe: ' + d.flush_queue_depth + ' / 10000';

    // Telemetrie
    document.getElementById('conc-val').innerHTML = (d.gateway_concentration_ratio * 100).toFixed(1) + '% <span style="font-size: 1rem; font-weight: normal; color: var(--text-muted);">Top-2</span>';
    document.getElementById('subnet-dom-sub').innerText = 'Max Subnetz-Dominanz: ' + (d.shard_subnet_dominance_max * 100).toFixed(1) + '%';

    // Network Explorer Table
    const nodesTbody = document.getElementById('nodes-tbody');
    if (d.network_nodes && d.network_nodes.length > 0) {{
      let html = '';
      for (const n of d.network_nodes) {{
        const roleBadge = n.is_local ? '<span class="badge badge-purple">LOCAL (Self)</span>' : (n.is_f2f ? '<span class="badge badge-blue">F2F Friend</span>' : '<span class="badge badge-cyan">Gossip Shard</span>');
        const statusBadge = n.connection_status.includes('Connected') ? '<span class="badge badge-green">' + n.connection_status + '</span>' : '<span class="badge badge-amber">' + n.connection_status + '</span>';
        const pShort = truncateHash(n.public_key);
        const hrwShort = truncateHash(n.hrw_routing_id);
        html += '<tr><td><span class="code" title="' + n.public_key + '">' + pShort + '</span></td><td>' + n.address + '</td><td>' + roleBadge + '</td><td>' + statusBadge + '</td><td>' + n.min_hops + '</td><td><span class="code" title="' + n.hrw_routing_id + '">' + hrwShort + '</span> (Work: ' + n.work_score + ')</td></tr>';
      }}
      nodesTbody.innerHTML = html;
      document.getElementById('network-count-sub').innerText = d.network_nodes.length + ' Knoten registriert';
    }}

    // Shard Topology Table
    document.getElementById('shard-mode-badge').innerText = d.shard_mode;
    document.getElementById('shard-ratio-text').innerText = (d.shard_responsibility_ratio * 100).toFixed(1) + '%';
    const shardsTbody = document.getElementById('shards-tbody');
    if (d.sample_shard_scores && d.sample_shard_scores.length > 0) {{
      let html = '';
      for (const s of d.sample_shard_scores) {{
        const statusBadge = s.is_responsible ? '<span class="badge badge-green">Aktiv (Zuständig)</span>' : '<span class="badge badge-amber">Standby</span>';
        html += '<tr><td><strong>Shard #' + s.shard_id + '</strong></td><td><code>' + s.score.toFixed(6) + '</code></td><td>' + statusBadge + '</td></tr>';
      }}
      shardsTbody.innerHTML = html;
    }}

    // Vouchers Table
    const vouchersTbody = document.getElementById('vouchers-tbody');
    if (d.active_vouchers && d.active_vouchers.length > 0) {{
      let html = '';
      for (const v of d.active_vouchers) {{
        const genShort = v.genesis_tag ? truncateHash(v.genesis_tag) : 'N/A';
        const statusBadge = v.status === 'Active' ? '<span class="badge badge-green">Aktiv</span>' : '<span class="badge badge-amber">' + v.status + '</span>';
        html += '<tr><td><strong>' + v.voucher_id + '</strong></td><td>' + v.root_valid_until_formatted + '</td><td class="code">' + genShort + '</td><td>' + v.locks_count + ' Sperren</td><td>' + statusBadge + '</td><td><button class="btn btn-secondary" onclick="openVoucherInspector(\'' + v.voucher_id + '\')">🔍 Details &amp; JSON</button></td></tr>';
      }}
      vouchersTbody.innerHTML = html;
    }} else {{
      vouchersTbody.innerHTML = '<tr><td colspan="6" class="empty-cell">Keine aktiven Gutscheine im Speicher</td></tr>';
    }}

    // Live Locks Table
    const locksTbody = document.getElementById('locks-tbody');
    if (d.recent_locks && d.recent_locks.length > 0) {{
      let html = '';
      for (const l of d.recent_locks) {{
        const b = l.status === 'Verified' ? '<span class="badge badge-green">Verified</span>' : (l.status === 'Provisional' ? '<span class="badge badge-amber">Provisional</span>' : '<span class="badge badge-red">Conflict</span>');
        const pShort = truncateHash(l.parent_lock_hex);
        const cShort = truncateHash(l.child_lock_hex);
        html += '<tr><td>' + l.timestamp_ms + '</td><td class="code" title="' + l.parent_lock_hex + '">' + pShort + '</td><td class="code" title="' + l.child_lock_hex + '">' + cShort + '</td><td>' + b + '</td><td><button class="btn btn-secondary" style="padding: 0.2rem 0.5rem;" onclick="openLockInspector(\'' + l.parent_lock_hex + '\')">📄 JSON</button></td></tr>';
      }}
      locksTbody.innerHTML = html;
    }} else {{
      locksTbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Keine Sperren im Ringbuffer</td></tr>';
    }}

  }} catch (e) {{}}
}}

// Initial load & periodic refresh
refreshDashboard();
setInterval(refreshDashboard, 3000);
</script>
</body>
</html>"#,
        status_badge = data.status_badge,
        uptime = data.uptime_formatted,
        version = env!("CARGO_PKG_VERSION"),
        local_avg = data.local_latency.avg_ms,
        local_p95 = data.local_latency.p95_ms,
        quorum_avg = data.quorum_latency.avg_ms,
        quorum_p95 = data.quorum_latency.p95_ms,
        e2e_avg = data.e2e_latency.avg_ms,
        sample_count = data.e2e_latency.sample_count,
        mesh_mode = if data.configured_peers == 0 { "Village" } else { "Cluster" },
        connected_peers = data.connected_peers,
        configured_peers = data.configured_peers,
        active_nodes = data.active_nodes_count,
        active_locks = data.active_locks,
        flush_depth = data.flush_queue_depth,
        conc_percent = data.gateway_concentration_ratio * 100.0,
        dom_percent = data.shard_subnet_dominance_max * 100.0,
        qr_svg = qr_svg,
        node_id = data.node_id,
        hrw_id = data.hrw_routing_id,
        peering_str = data.peering_string,
        shard_mode = data.shard_mode,
        shard_ratio = data.shard_responsibility_ratio * 100.0
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}
