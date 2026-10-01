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
    #[serde(default)]
    pub total_write_used: u64,
    #[serde(default)]
    pub total_read_used: u64,
    #[serde(default)]
    pub vip_writes_today: u64,
    #[serde(default)]
    pub f2f_writes_today: u64,
    #[serde(default)]
    pub free_writes_today: u64,
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
    #[serde(default)]
    pub missing_count: u32,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default)]
    pub last_failure_sec: Option<u64>,
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
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub byte_years: u64,
    #[serde(default)]
    pub voucher_id: Option<String>,
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
    pub total_writes: u64,
    pub total_reads: u64,

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
    pub total_active_vouchers_count: usize,
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
    let pubkey = state.identity.public_key_bs58();
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
                node_id: bs58::encode(local_pubkey_bytes).into_string(),
                public_key: bs58::encode(local_pubkey_bytes).into_string(),
                address: local_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "127.0.0.1:9090".to_string()),
                is_f2f: false,
                is_local: true,
                connection_status: "Standalone (Village Mode)".to_string(),
                min_hops: 0,
                hrw_routing_id: bs58::encode(local_hrw).into_string(),
                work_score: 1,
                is_immature: false,
                pending_ticket: None,
                incubation_remaining_sec: None,
                missing_count: 0,
                last_failure_sec: None,
                rtt_ms: Some(0),
                best_ingress_peer: None,
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

    let total_writes = state.metrics.total_writes();
    let total_reads = state.metrics.total_reads();

    // Active Vouchers
    let total_active_vouchers_count = state.engine.get_total_active_vouchers_count().await;
    let active_vouchers = state.engine.get_recent_active_vouchers(15).await;

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
                tier: r.tier,
                byte_years: r.byte_years,
                voucher_id: r.voucher_id,
            }
        })
        .collect();

    // 1. System stats
    let system = state.system_stats.get_system_stats(
        active_locks,
        local_latency.avg_ms,
        state.metrics.ttl_purged_count(),
    );

    // 2. Sparklines
    let sparklines = state.system_stats.get_sparklines();

    // 3. Thermometer stats
    let ncb_eff = state.tier_controller.effective_ncb() as f64;
    let ncb_read_eff = state.tier_controller.effective_read_ncb() as f64;
    let gossip_write_load = state.tier_controller.rolling_24h_average() as f64;
    let gossip_read_load = sparklines.reads.last().copied().unwrap_or(0.0) as f64;
    let daily_write_quota = state.tier_controller.calculate_daily_quota(1.0, 1.0);
    let daily_read_quota = state.tier_controller.calculate_daily_read_quota(1.0, 1.0);
    let local_node_id_u16 = state.identity.node_id_u16();
    let (today_write_used, today_read_used, total_write_used, total_read_used) = {
        let thermo_arc = state.tier_controller.thermometer();
        let thermo = thermo_arc
            .read()
            .unwrap_or_else(|e| e.into_inner());
        (
            thermo.get_node_usage(local_node_id_u16),
            thermo.get_node_read_usage(local_node_id_u16),
            thermo.total_daily_write_usage(),
            thermo.total_daily_read_usage(),
        )
    };
    let (vip_writes_today, f2f_writes_today, free_writes_today) = state.tier_controller.tier_counters();

    let thermometer = ThermometerStatsDto {
        gossip_write_load,
        gossip_read_load,
        ncb_eff,
        ncb_read_eff,
        daily_write_quota,
        daily_read_quota,
        today_write_used,
        today_read_used,
        total_write_used,
        total_read_used,
        vip_writes_today,
        f2f_writes_today,
        free_writes_today,
    };

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
                let nid_bs58 = p
                    .node_id
                    .map(|bytes| bs58::encode(bytes).into_string())
                    .unwrap_or_default();
                let last_seen_sec = p.last_seen.map(|t| t.elapsed().as_secs());
                let missing_count = p.missing_count;
                let rtt_ms = p.connection.as_ref().map(|c| c.rtt().as_millis() as u32);
                let last_failure_sec = p.last_failure.map(|t| t.elapsed().as_secs());
                f_list.push(F2fFriendDto {
                    node_id: nid_bs58.clone(),
                    public_key: nid_bs58,
                    address: p.addr.to_string(),
                    is_connected: p.is_connected(),
                    last_seen_sec,
                    missing_count,
                    rtt_ms,
                    last_failure_sec,
                });
            }
        }
        f_list
    } else {
        Vec::new()
    };

    let f2f = F2fOverviewDto {
        my_pubkey: state.identity.public_key_bs58(),
        friends: friends_list,
    };

    DashboardData {
        status,
        status_badge,
        node_id: state.identity.node_id_bs58(),
        public_key: state.identity.public_key_bs58(),
        hrw_routing_id: state.identity.hrw_routing_id_bs58(),
        peering_string,
        uptime_seconds: uptime.as_secs(),
        uptime_formatted,
        active_locks,
        flush_queue_depth,
        connected_peers,
        configured_peers,
        active_nodes_count,
        total_writes,
        total_reads,
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
        total_active_vouchers_count,
        active_vouchers,
        recent_locks,
        system,
        thermometer,
        sparklines,
        tiers,
        f2f,
    }
}

/// Convenience alias for collect_dashboard_data
pub async fn get_dashboard_data(state: &AppState) -> DashboardData {
    collect_dashboard_data(state).await
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
<title>HuMoCo Node Control Center (v2.0)</title>
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
  padding: 1.25rem;
}}
.container {{ max-width: 1360px; margin: 0 auto; }}
header {{
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  padding-bottom: 1.25rem;
  margin-bottom: 1.25rem;
  border-bottom: 1px solid var(--border);
}}
.header-left {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }}
.header-title {{ font-size: 1.35rem; font-weight: 700; letter-spacing: -0.02em; display: flex; align-items: center; gap: 0.5rem; }}
.header-pills {{ display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }}
.header-right {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }}

.badge {{
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.25rem 0.7rem;
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

.pill {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 0.3rem 0.65rem;
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--text-muted);
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
}}
.pill strong {{ color: var(--text); font-weight: 600; }}

/* Navigation Tabs */
.tabs-nav {{
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.25rem;
  border-bottom: 1px solid var(--border);
  overflow-x: auto;
  padding-bottom: 0.5rem;
}}
.tab-btn {{
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-muted);
  padding: 0.6rem 1.1rem;
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
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1.25rem;
  margin-bottom: 1.25rem;
}}
.grid-2 {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
  gap: 1.25rem;
  margin-bottom: 1.25rem;
}}
@media (max-width: 640px) {{
  .grid-2 {{ grid-template-columns: 1fr; }}
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
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
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
  padding: 0.35rem 0.55rem;
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
  border: 1px solid transparent;
  border-radius: 0.375rem;
  padding: 0.45rem 0.85rem;
  font-size: 0.8125rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  white-space: nowrap;
}}
.btn:hover {{ opacity: 0.9; }}
.btn-secondary {{
  background: var(--surface-alt);
  border: 1px solid var(--border);
  color: var(--text);
}}
.btn-secondary:hover {{ background: var(--surface-hover); }}
.btn-danger {{
  background: var(--red-bg);
  color: var(--red);
  border: 1px solid rgba(239,68,68,0.3);
}}
.btn-danger:hover {{ background: rgba(239,68,68,0.25); }}

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
  font-size: 0.8125rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}}
td {{
  padding: 0.75rem;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  vertical-align: middle;
}}
tr:hover td {{ background: var(--surface-alt); }}
.empty-cell {{ text-align: center; color: var(--text-muted); padding: 2.5rem 0; }}

.progress-bar {{
  width: 100%;
  height: 8px;
  background: var(--surface-alt);
  border-radius: 9999px;
  overflow: hidden;
  margin: 0.5rem 0;
}}
.progress-fill {{
  height: 100%;
  background: linear-gradient(90deg, var(--blue), var(--cyan));
  border-radius: 9999px;
  transition: width 0.3s ease;
}}

.sparkline-box {{
  margin-top: 0.75rem;
  height: 40px;
  width: 100%;
}}

.input-text {{
  background: var(--surface-alt);
  border: 1px solid var(--border);
  border-radius: 0.375rem;
  padding: 0.45rem 0.75rem;
  color: var(--text);
  font-size: 0.875rem;
  outline: none;
}}
.input-text:focus {{ border-color: var(--blue); }}

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
  border-top: 1px solid var(--border);
  padding-top: 1rem;
}}
</style>
</head>
<body>
<div class="container">
  <!-- Top Header -->
  <header>
    <div class="header-left">
      <div class="header-title">
        <span>🟢</span>
        <span>HuMoCo Node Control Center (v2.0)</span>
      </div>
      <span id="status-badge" class="badge badge-green">{status_badge}</span>
    </div>

    <!-- 3-Tier Latencies Pills -->
    <div class="header-pills">
      <div class="pill">⚡ In-RAM: <strong id="hdr-lat-local">{local_avg:.2} ms</strong> (&lt; 5ms SLA)</div>
      <div class="pill">🌐 Quorum: <strong id="hdr-lat-quorum">{quorum_avg:.2} ms</strong> (&lt; 500ms SLA)</div>
      <div class="pill">🛒 Kasse: <strong id="hdr-lat-e2e">{e2e_avg:.2} ms</strong></div>
    </div>

    <!-- Fast Stats & Admin Button -->
    <div class="header-right">
      <div class="pill">Peers: <strong id="hdr-peers">{connected_peers}/{configured_peers}</strong></div>
      <div class="pill">Port: <strong>8080/9090</strong></div>
      <div class="pill">Shard: <strong id="hdr-shard">{shard_mode}</strong></div>
      <button id="admin-btn" class="btn btn-secondary" onclick="handleAdminBtnClick()">🔒 Admin-Modus</button>
    </div>
  </header>

  <!-- 4-Tab Navigation -->
  <div class="tabs-nav">
    <button id="tab-btn-cockpit" class="tab-btn active" onclick="switchTab('tab-cockpit')">⚡ Cockpit &amp; System</button>
    <button id="tab-btn-network" class="tab-btn" onclick="switchTab('tab-network')">🌐 Netzwerk &amp; F2F</button>
    <button id="tab-btn-tiers" class="tab-btn" onclick="switchTab('tab-tiers')">🎛️ Tiers &amp; Quoten</button>
    <button id="tab-btn-vouchers" class="tab-btn" onclick="switchTab('tab-vouchers')">🎟️ Gutscheine &amp; Logs</button>
  </div>

  <!-- TAB 1: COCKPIT & SYSTEM -->
  <div id="tab-cockpit" class="tab-content active">
    <div class="grid">
      <!-- 1. Schreib-Durchsatz -->
      <div class="card">
        <div class="card-header">
          <span>✍️ Schreib-Durchsatz</span>
          <span class="badge badge-green">Hot-Path</span>
        </div>
        <div class="card-value">
          <span id="writes-rate">{free_req_sec:.1}</span>
          <span style="font-size: 1rem; color: var(--text-muted); font-weight: normal;">TX/s (EMA)</span>
        </div>
        <div class="card-sub">Heute: <strong id="writes-today">{total_writes}</strong> Schreiboperationen</div>
        <div id="writes-sparkline" class="sparkline-box"></div>
      </div>

      <!-- 2. Lese-Durchsatz -->
      <div class="card">
        <div class="card-header">
          <span>🔍 Lese-Durchsatz</span>
          <span class="badge badge-blue">RAM-Index</span>
        </div>
        <div class="card-value">
          <span id="reads-rate">{reads_rate:.1}</span>
          <span style="font-size: 1rem; color: var(--text-muted); font-weight: normal;">Req/s</span>
        </div>
        <div class="card-sub">Heute: <strong id="reads-today">{total_reads}</strong> Leseabfragen</div>
        <div id="reads-sparkline" class="sparkline-box"></div>
      </div>

      <!-- 3. Hardware & Ressourcen -->
      <div class="card">
        <div class="card-header">
          <span>💻 Hardware &amp; Ressourcen</span>
          <span class="badge badge-purple">Node Stats</span>
        </div>
        <div style="margin-bottom: 0.5rem;">
          <div style="display: flex; justify-content: space-between; font-size: 0.8125rem;">
            <span>CPU-Auslastung:</span>
            <strong id="sys-cpu-val">{cpu_percent:.1}%</strong>
          </div>
          <div class="progress-bar">
            <div id="sys-cpu-bar" class="progress-fill" style="width: {cpu_percent}%;"></div>
          </div>
        </div>
        <div class="card-sub" style="line-height: 1.6;">
          <div>RSS RAM: <strong id="sys-rss-val">{rss_mb:.1} MB</strong></div>
          <div>redb Disk-Datei: <strong id="sys-redb-val">{redb_kb} KB</strong></div>
          <div>Netto Lock Footprint: <strong id="sys-netto-val">{netto_locks} B</strong> (144 B * N)</div>
          <div>TTL-Pruning: <strong id="sys-purged-val">{ttl_purged}</strong> gelöschte Sperren</div>
        </div>
      </div>

      <!-- 4. Knoten-Kapazitätsrechner & Skalierung -->
      <div class="card">
        <div class="card-header">
          <span>🚀 Knoten-Kapazität &amp; Skalierung</span>
          <span class="badge badge-cyan">Projektion</span>
        </div>
        <div class="card-sub" style="line-height: 1.7; font-size: 0.85rem; margin-top: 0.25rem;">
          <div>Single-Core Peak: <strong id="cap-single-val" style="color: var(--text);">{peak_tps_single}</strong> TPS</div>
          <div>Multi-Core Peak: <strong id="cap-multi-val" style="color: var(--text);">{peak_tps_multi}</strong> TPS</div>
          <div>Storage Ceiling: <strong id="cap-storage-val" style="color: var(--text);">{max_storage_locks}</strong> Sperren</div>
          <div>Byte-Years Kapazität: <strong id="cap-byte-years-val" style="color: var(--text);">{byte_years_capacity}</strong> Byte-Jahre</div>
        </div>
      </div>
    </div>

    <!-- Node Identity & Peering Box -->
    <div class="card identity-card">
      <div class="qr-box">{qr_svg}</div>
      <div>
        <div class="card-header"><span>📱 Lokale Knoten-Identität &amp; Peering-String</span></div>
        <div style="font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 0.25rem;">NodePubKey: <span class="code" id="node-id-text">{node_id}</span></div>
        <div style="font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 0.25rem;">Argon2d Ticket: <span class="code" id="hrw-ticket-text">{hrw_id}</span></div>
        <div class="peering-row">
          <span class="code" id="peering-text" style="flex: 1;">{peering_str}</span>
          <button class="btn" id="copy-btn" onclick="copyPeering()">Kopieren</button>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: NETZWERK & F2F -->
  <div id="tab-network" class="tab-content">
    <div class="grid-2">
      <!-- Network Thermometer Card (Spec 09) -->
      <div class="card">
        <div class="card-header">
          <span>🌡️ Netzwerk-Thermometer (Spec 09)</span>
          <span class="badge badge-cyan">Dynamische Last</span>
        </div>
        <div class="card-sub" style="line-height: 1.8; font-size: 0.875rem;">
          <div>Gossip Write Load: <strong id="thermo-write-load" style="color: var(--text);">{gossip_write_load:.2}</strong></div>
          <div>Gossip Read Load: <strong id="thermo-read-load" style="color: var(--text);">{gossip_read_load:.2}</strong></div>
          <div>28-Tage Median NCB_eff (min 10k): <strong id="thermo-ncb-eff" style="color: var(--text);">{ncb_eff:.0}</strong></div>
          <div>28-Tage Read Median NCB_read_eff (min 50k): <strong id="thermo-ncb-read-eff" style="color: var(--text);">{ncb_read_eff:.0}</strong></div>
          <div>24h Rolling Avg: <strong id="thermo-rolling-avg" style="color: var(--text);">{gossip_write_load:.2}</strong></div>
          <div>Top-2 Konzentration: <strong id="conc-val" style="color: var(--text);">{conc_percent:.1}%</strong> | Max Subnetz-Dominanz: <strong id="subnet-dom-sub" style="color: var(--text);">{dom_percent:.1}%</strong></div>
        </div>
      </div>

      <!-- F2F Web-of-Trust Card -->
      <div class="card">
        <div class="card-header">
          <span>🤝 F2F Web-of-Trust Freunde</span>
          <span class="badge badge-green">Gossip-Barriere</span>
        </div>
        <div style="font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 0.75rem;">
          Eigener PubKey: <span class="code" id="my-pubkey-text">{node_id}</span>
          <button class="btn btn-secondary" style="padding: 0.2rem 0.5rem; margin-left: 0.35rem;" onclick="copyMyPubkey()">Kopieren</button>
        </div>

        <!-- Admin Only: Add Friend Form -->
        <div class="admin-only" style="display: none; background: var(--surface-alt); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border); margin-bottom: 0.75rem;">
          <div style="font-weight: 600; font-size: 0.8125rem; margin-bottom: 0.5rem;">🤝 Freund hinzufügen (Admin)</div>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <input id="friend-pubkey-input" class="input-text" placeholder="Ed25519 PubKey (64 Hex-Zeichen)" style="flex: 2; min-width: 200px;">
            <input id="friend-label-input" class="input-text" placeholder="Label (z.B. Bob)" style="flex: 1; min-width: 100px;">
            <button class="btn" onclick="adminAddFriend()">Hinzufügen</button>
          </div>
        </div>

        <div style="overflow-x: auto; max-height: 250px;">
          <table>
            <thead>
              <tr>
                <th>NodePubKey</th>
                <th>Adresse</th>
                <th>Status &amp; Zuverlässigkeit</th>
                <th>Latenz (RTT)</th>
                <th>Aktion</th>
              </tr>
            </thead>
            <tbody id="friends-tbody">
              <!-- Dynamically populated -->
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Peer Explorer Table ("Nerd-Mode") -->
    <div class="card table-card">
      <div class="card-header" style="flex-wrap: wrap; gap: 0.5rem;">
        <span>🌐 Peer Explorer ("Nerd-Mode" &bull; Bekannte Netzwerkknoten)</span>
        <span class="card-sub" id="network-count-sub">{active_nodes} Knoten registriert</span>
      </div>
      <div style="padding: 0.5rem 1rem 0 1rem;">
        <input id="node-search-input" class="input-text" placeholder="🔍 Suche nach PubKey, IP, Beziehung oder Status..." oninput="filterNodesTable()" style="width: 100%; max-width: 450px;">
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>NodePubKey</th>
              <th>IP-Adresse / Port</th>
              <th>Beziehung</th>
              <th>Status &amp; Zuverlässigkeit</th>
              <th>Latenz (RTT)</th>
              <th>Hops &amp; Route</th>
              <th>Shard-Ticket (Argon2d)</th>
              <th>Inkubation (24h)</th>
              <th>Aktion</th>
            </tr>
          </thead>
          <tbody id="nodes-tbody">
            <!-- Dynamically populated -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 3: TIERS & QUOTEN -->
  <div id="tab-tiers" class="tab-content">
    <div class="grid">
      <!-- Tier 1: Free Tier -->
      <div class="card">
        <div class="card-header">
          <span>🌍 Free Tier</span>
          <span class="badge badge-green">Stateless PoW</span>
        </div>
        <div class="card-value">
          <span id="tier-free-pow-val">{free_pow_diff}</span>
          <span style="font-size: 1rem; color: var(--text-muted); font-weight: normal;">Bits PoW</span>
        </div>
        <div class="card-sub">Aktuelle Last: <strong id="tier-free-req-val">{free_req_sec:.1}</strong> req/s</div>
      </div>

      <!-- Tier 2: Friends Tier -->
      <div class="card">
        <div class="card-header">
          <span>🤝 Friends Tier</span>
          <span class="badge badge-blue">30% Reserviert</span>
        </div>
        <div class="card-value">
          <span id="tier-friends-used-val">{friends_used_pct:.1}%</span>
          <span style="font-size: 1rem; color: var(--text-muted); font-weight: normal;">genutzt</span>
        </div>
        <div class="card-sub">Gossip-gesichert &bull; Prioritätswarteschlange</div>
      </div>

      <!-- Tier 3: VIP Tier -->
      <div class="card">
        <div class="card-header">
          <span>💳 VIP Tier</span>
          <span class="badge badge-purple">50% Reserviert</span>
        </div>
        <div class="card-value">
          <span id="tier-vip-used-val">{vip_used_pct:.1}%</span>
          <span style="font-size: 1rem; color: var(--text-muted); font-weight: normal;">genutzt</span>
        </div>
        <div class="card-sub">Byte-Years Quoten &bull; SLA-Garantie</div>
      </div>
    </div>

    <!-- Daily Quota Card -->
    <div class="card" style="margin-bottom: 1.25rem;">
      <div class="card-header">
        <span>📊 Tägliches Quotenlimit &amp; Byte-Jahre Verbrauch</span>
        <span class="badge badge-cyan">24h Fenster</span>
      </div>
      <div style="margin: 0.5rem 0;">
        <div style="display: flex; justify-content: space-between; font-size: 0.9rem; margin-bottom: 0.35rem;">
          <span>Heute verbraucht: <strong id="quota-used-val">{today_write_used}</strong> / <span id="quota-limit-val">{daily_write_quota}</span> Byte-Jahre</span>
          <strong id="quota-pct-text">{friends_used_pct:.1}%</strong>
        </div>
        <div class="progress-bar">
          <div id="quota-bar" class="progress-fill" style="width: {friends_used_pct:.1}%;"></div>
        </div>
      </div>
    </div>

    <!-- VIP Accounts Card -->
    <div class="card table-card">
      <div class="card-header">
        <span>💳 Registrierte VIP-Accounts &amp; Quoten-Guthaben</span>
        <span class="card-sub">Byte-Years Balance</span>
      </div>

      <!-- Admin Only: Topup VIP Quota Form -->
      <div class="admin-only" style="display: none; background: var(--surface-alt); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border); margin-bottom: 1rem;">
        <div style="font-weight: 600; font-size: 0.8125rem; margin-bottom: 0.5rem;">💳 VIP Guthaben aufladen (Admin)</div>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
          <input id="vip-tag-input" class="input-text" placeholder="Account Tag (64 Hex-Zeichen)" style="flex: 2; min-width: 200px;">
          <input id="vip-amount-input" class="input-text" type="number" placeholder="Byte-Jahre (z.B. 5000)" style="flex: 1; min-width: 120px;">
          <button class="btn" onclick="adminTopupQuota()">Aufladen</button>
        </div>
      </div>

      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Account Tag (Hex)</th>
              <th>Byte-Jahre Guthaben</th>
            </tr>
          </thead>
          <tbody id="vip-accounts-tbody">
            <!-- Dynamically populated -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 4: GUTSCHEINE & LOGS -->
  <div id="tab-vouchers" class="tab-content">
    <!-- Recent Locks Table -->
    <div class="card table-card" style="margin-top: 0; margin-bottom: 1.25rem;">
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
              <th>Tier &amp; Quota</th>
              <th>Gutschein-ID</th>
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

    <!-- Active Vouchers Table -->
    <div class="card table-card">
      <div class="card-header">
        <span>🎟️ Aktive Gutschein-Wurzeln &amp; Lock-Lineage</span>
        <span class="card-sub" id="vouchers-count-sub">{total_active_vouchers} Gutscheine aktiv (Top 15 angezeigt)</span>
      </div>
      <div style="display: flex; gap: 0.5rem; margin-bottom: 0.75rem;">
        <input id="voucher-search-input" class="input-text" placeholder="🎟️ Gutschein-ID oder Lock-Tag eingeben..." style="flex: 1;" onkeydown="if (event.key === 'Enter') searchVoucher()">
        <button class="btn" onclick="searchVoucher()">🔍 Suchen &amp; Prüfen</button>
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

  <footer>
    HuMoCo Layer-2 Daemon &bull; Offline Air-Gap Dashboard v2 &bull; Auto-Refresh 2s
  </footer>
</div>

<!-- Modal 1: Voucher Root Inspector -->
<div id="voucher-modal" class="modal-overlay" onclick="closeModalOnOverlay(event, 'voucher-modal')">
  <div class="modal-box">
    <div class="modal-header">
      <h3 id="voucher-modal-title">🎟️ Gutschein-Lineage Wurzel-Inspektor</h3>
      <button class="btn btn-secondary" onclick="closeModal('voucher-modal')">✕</button>
    </div>
    <div class="modal-body">
      <div id="voucher-modal-details" style="margin-bottom: 0.75rem;"></div>
      <div id="voucher-modal-table-container"></div>
      <div style="margin-top: 1rem;">
        <button class="btn btn-secondary" onclick="toggleVoucherRawJson()">📄 Raw JSON anzeigen / verbergen</button>
        <pre id="voucher-modal-json" class="json-viewer" style="display: none; margin-top: 0.5rem;"></pre>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" id="voucher-copy-btn" onclick="copyVoucherJson()">JSON Kopieren</button>
      <button class="btn btn-secondary" onclick="closeModal('voucher-modal')">Schließen</button>
    </div>
  </div>
</div>

<!-- Modal 2: Raw JSON Inspector -->
<div id="json-modal" class="modal-overlay" onclick="closeModalOnOverlay(event, 'json-modal')">
  <div class="modal-box">
    <div class="modal-header">
      <h3 id="modal-title">📄 Rohdaten-Inspector</h3>
      <button class="btn btn-secondary" onclick="closeModal('json-modal')">✕</button>
    </div>
    <div class="modal-body">
      <div id="modal-details" style="margin-bottom: 0.75rem;"></div>
      <pre id="modal-json" class="json-viewer"></pre>
    </div>
    <div class="modal-footer">
      <button class="btn" id="modal-copy-btn" onclick="copyModalJson()">JSON Kopieren</button>
      <button class="btn btn-secondary" onclick="closeModal('json-modal')">Schließen</button>
    </div>
  </div>
</div>

<!-- Modal 3: Admin Auth Modal -->
<div id="admin-modal" class="modal-overlay" onclick="closeModalOnOverlay(event, 'admin-modal')">
  <div class="modal-box" style="max-width: 480px;">
    <div class="modal-header">
      <h3>🔒 Admin-Modus freischalten</h3>
      <button class="btn btn-secondary" onclick="closeModal('admin-modal')">✕</button>
    </div>
    <div class="modal-body">
      <p style="margin-bottom: 0.75rem; color: var(--text-muted); font-size: 0.85rem;">
        Geben Sie das Admin-Token des HuMoCo Daemons ein, um F2F-Freunde zu verwalten und VIP-Quoten aufzuladen.
      </p>
      <input id="admin-token-input" type="password" class="input-text" placeholder="Admin Bearer Token" style="width: 100%;">
      <div id="admin-auth-error" style="color: var(--red); font-size: 0.8125rem; margin-top: 0.5rem; display: none;"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="closeModal('admin-modal')">Abbrechen</button>
      <button class="btn" onclick="submitAdminToken()">Aktivieren</button>
    </div>
  </div>
</div>

<!-- Modal 4: Node Inspector / Peer-Diagnose -->
<div id="node-modal" class="modal-overlay" onclick="closeModalOnOverlay(event, 'node-modal')">
  <div class="modal-box" style="max-width: 680px;">
    <div class="modal-header">
      <h3 id="node-modal-title">🔍 Knoten-Diagnose</h3>
      <button class="btn btn-secondary" onclick="closeModal('node-modal')">✕</button>
    </div>
    <div class="modal-body">
      <div id="node-modal-details"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="closeModal('node-modal')">Schließen</button>
    </div>
  </div>
</div>

<script>
let currentDashboardData = null;
let currentVoucherDetail = null;
let adminToken = localStorage.getItem('humoco_admin_token') || '';

function updateAdminUI() {{
  const btn = document.getElementById('admin-btn');
  const adminEls = document.querySelectorAll('.admin-only');
  if (adminToken) {{
    btn.innerHTML = '🔓 Admin aktiv (Logout)';
    btn.className = 'btn btn-danger';
    adminEls.forEach(el => el.style.display = 'block');
  }} else {{
    btn.innerHTML = '🔒 Admin-Modus';
    btn.className = 'btn btn-secondary';
    adminEls.forEach(el => el.style.display = 'none');
  }}
}}

function handleAdminBtnClick() {{
  if (adminToken) {{
    localStorage.removeItem('humoco_admin_token');
    adminToken = '';
    updateAdminUI();
    refreshDashboard();
  }} else {{
    document.getElementById('admin-auth-error').style.display = 'none';
    document.getElementById('admin-token-input').value = '';
    document.getElementById('admin-modal').classList.add('active');
  }}
}}

async function submitAdminToken() {{
  const val = document.getElementById('admin-token-input').value.trim();
  if (!val) return;
  try {{
    const res = await fetch('/dashboard/admin/verify-token', {{
      method: 'POST',
      headers: {{ 'Authorization': 'Bearer ' + val }}
    }});
    if (res.ok) {{
      adminToken = val;
      localStorage.setItem('humoco_admin_token', val);
      closeModal('admin-modal');
      updateAdminUI();
      refreshDashboard();
    }} else {{
      const errEl = document.getElementById('admin-auth-error');
      errEl.innerText = 'Ungültiges Admin-Token.';
      errEl.style.display = 'block';
    }}
  }} catch (e) {{
    const errEl = document.getElementById('admin-auth-error');
    errEl.innerText = 'Verbindungsfehler: ' + e.message;
    errEl.style.display = 'block';
  }}
}}

async function adminAddFriend() {{
  const pubkey = document.getElementById('friend-pubkey-input').value.trim();
  const label = document.getElementById('friend-label-input').value.trim();
  if (!pubkey) return;
  try {{
    const res = await fetch('/dashboard/admin/friends', {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + adminToken
      }},
      body: JSON.stringify({{ pubkey, label: label || null }})
    }});
    if (res.ok) {{
      document.getElementById('friend-pubkey-input').value = '';
      document.getElementById('friend-label-input').value = '';
      refreshDashboard();
    }} else {{
      const err = await res.json();
      alert('Fehler: ' + (err.message || res.statusText));
    }}
  }} catch (e) {{ alert('Fehler: ' + e.message); }}
}}

async function adminRemoveFriend(pubkey) {{
  if (!confirm('Freund ' + truncateHash(pubkey) + ' wirklich entfernen?')) return;
  try {{
    const res = await fetch('/dashboard/admin/friends/' + encodeURIComponent(pubkey), {{
      method: 'DELETE',
      headers: {{ 'Authorization': 'Bearer ' + adminToken }}
    }});
    if (res.ok) {{
      refreshDashboard();
    }} else {{
      const err = await res.json();
      alert('Fehler: ' + (err.message || res.statusText));
    }}
  }} catch (e) {{ alert('Fehler: ' + e.message); }}
}}

async function adminTopupQuota() {{
  const tag = document.getElementById('vip-tag-input').value.trim();
  const amount = parseInt(document.getElementById('vip-amount-input').value, 10);
  if (!tag || isNaN(amount) || amount <= 0) return;
  try {{
    const res = await fetch('/dashboard/admin/quota', {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + adminToken
      }},
      body: JSON.stringify({{ account_tag: tag, byte_years: amount }})
    }});
    if (res.ok) {{
      document.getElementById('vip-tag-input').value = '';
      document.getElementById('vip-amount-input').value = '';
      refreshDashboard();
    }} else {{
      const err = await res.json();
      alert('Fehler: ' + (err.message || res.statusText));
    }}
  }} catch (e) {{ alert('Fehler: ' + e.message); }}
}}

function switchTab(tabId) {{
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  
  const btn = document.querySelector('[onclick="switchTab(\'' + tabId + '\')"]');
  if (btn) btn.classList.add('active');
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

function copyMyPubkey() {{
  const text = document.getElementById('my-pubkey-text').innerText;
  navigator.clipboard.writeText(text).catch(() => {{}});
}}

function closeModal(modalId) {{
  document.getElementById(modalId).classList.remove('active');
}}

function closeModalOnOverlay(e, modalId) {{
  if (e.target.id === modalId) closeModal(modalId);
}}

document.addEventListener('keydown', (e) => {{
  if (e.key === 'Escape') {{
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
  }}
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

function copyVoucherJson() {{
  if (!currentVoucherDetail) return;
  navigator.clipboard.writeText(JSON.stringify(currentVoucherDetail, null, 2)).then(() => {{
    const btn = document.getElementById('voucher-copy-btn');
    const orig = btn.innerText;
    btn.innerText = 'Kopiert!';
    setTimeout(() => {{ btn.innerText = orig; }}, 1500);
  }}).catch(() => {{}});
}}

function toggleVoucherRawJson() {{
  const pre = document.getElementById('voucher-modal-json');
  pre.style.display = pre.style.display === 'none' ? 'block' : 'none';
}}

function truncateHash(hex) {{
  if (!hex || hex.length <= 16) return hex || '';
  return hex.slice(0, 8) + '…' + hex.slice(-8);
}}

function renderSparklineSvg(arr, color) {{
  if (!arr || arr.length === 0) return '';
  const max = Math.max(...arr, 1.0);
  const width = 280;
  const height = 40;
  const pts = arr.map((val, i) => {{
    const x = (i / (arr.length - 1 || 1)) * width;
    const y = height - ((val / max) * (height - 6)) - 3;
    return x.toFixed(1) + ',' + y.toFixed(1);
  }});
  const polyline = pts.join(' ');
  const polyArea = '0,' + height + ' ' + polyline + ' ' + width + ',' + height;
  return '<svg viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none" style="width: 100%; height: 40px; display: block;">' +
    '<polygon points="' + polyArea + '" fill="' + color + '" fill-opacity="0.15" />' +
    '<polyline points="' + polyline + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />' +
    '</svg>';
}}

function openNodeInspector(pubkey) {{
  if (!currentDashboardData || !currentDashboardData.network_nodes) return;
  const node = currentDashboardData.network_nodes.find(n => n.public_key === pubkey || n.node_id === pubkey);
  if (!node) {{
    alert('Knoten nicht gefunden: ' + pubkey);
    return;
  }}
  document.getElementById('node-modal-title').innerText = '🔍 Knoten-Diagnose: ' + truncateHash(node.public_key);
  
  const statusBadge = node.connection_status.includes('Connected')
    ? (node.missing_count === 0 ? '<span class="badge badge-green">Connected (0 Ausfälle)</span>' : '<span class="badge badge-amber">' + node.connection_status + '</span>')
    : (node.connection_status.includes('Suspended') ? '<span class="badge badge-red">' + node.connection_status + '</span>' : '<span class="badge badge-amber">' + node.connection_status + '</span>');
  
  const rttText = node.rtt_ms != null ? node.rtt_ms + ' ms' : '<span style="color: var(--text-muted);">-</span>';
  const failText = node.last_failure_sec != null ? 'vor ' + node.last_failure_sec + ' Sekunden' : '<span style="color: var(--green);">Kein Ausfall registriert</span>';
  const ingressText = node.best_ingress_peer ? 'Gelernt über F2F-Freund ' + node.best_ingress_peer : (node.is_local ? 'Lokaler Knoten (Self)' : (node.is_f2f ? 'Direkte F2F-Freundschaft' : 'Direkte Verbindung / Standby'));
  const incubText = node.is_immature ? '<span class="badge badge-amber">24h Schonfrist (noch ' + (node.incubation_remaining_sec || 0) + 's)</span>' : '<span class="badge badge-green">Voll Aktiviert</span>';
  
  let html = '<div style="line-height: 1.6; font-size: 0.875rem;">';
  
  // 1. Identity
  html += '<div style="background: var(--surface-alt); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border); margin-bottom: 0.75rem;">';
  html += '<h4 style="margin: 0 0 0.5rem 0; font-size: 0.85rem; color: var(--purple);">🔑 Identität &amp; Kryptographie</h4>';
  html += '<div><strong>NodePubKey (Ed25519):</strong> <span class="code" id="node-modal-pubkey">' + node.public_key + '</span> <button class="btn btn-secondary" style="padding: 0.15rem 0.4rem; font-size: 0.75rem;" onclick="copyNodePubkey()">Kopieren</button></div>';
  html += '<div><strong>IP-Adresse / Port:</strong> <span class="code">' + node.address + '</span></div>';
  html += '<div><strong>Shard-Ticket (Argon2d):</strong> <span class="code">' + node.hrw_routing_id + '</span> (Work-Score: <strong>' + node.work_score + '</strong>)</div>';
  html += '</div>';

  // 2. Health & Reliability
  html += '<div style="background: var(--surface-alt); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border); margin-bottom: 0.75rem;">';
  html += '<h4 style="margin: 0 0 0.5rem 0; font-size: 0.85rem; color: var(--green);">💓 Verbindungs-Gesundheit &amp; Zuverlässigkeit (Spec 15 &amp; 19)</h4>';
  html += '<div><strong>Status:</strong> ' + statusBadge + '</div>';
  html += '<div><strong>Ausfallzähler (missing_count):</strong> <strong>' + node.missing_count + '</strong> von 3 <span style="font-size: 0.75rem; color: var(--text-muted);">(Debounced Tit-for-Tat; heilt -1/h)</span></div>';
  html += '<div><strong>Live-Latenz (QUIC RTT):</strong> ' + rttText + '</div>';
  html += '<div><strong>Letzter Fehler:</strong> ' + failText + '</div>';
  html += '</div>';

  // 3. Routing & Topology
  html += '<div style="background: var(--surface-alt); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border);">';
  html += '<h4 style="margin: 0 0 0.5rem 0; font-size: 0.85rem; color: var(--blue);">📡 Mesh-Routing &amp; Topologie (Spec 11)</h4>';
  html += '<div><strong>Hop-Distanz:</strong> ' + node.min_hops + ' Hops</div>';
  html += '<div><strong>Ingress-Pfad (via):</strong> ' + ingressText + '</div>';
  html += '<div><strong>Inkubations-Status:</strong> ' + incubText + '</div>';
  html += '</div>';

  html += '</div>';

  document.getElementById('node-modal-details').innerHTML = html;
  document.getElementById('node-modal').classList.add('active');
}}

function copyNodePubkey() {{
  const el = document.getElementById('node-modal-pubkey');
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {{
    alert('NodePubKey kopiert!');
  }}).catch(() => {{}});
}}

function filterNodesTable() {{
  const input = document.getElementById('node-search-input');
  if (!input || !currentDashboardData) return;
  const term = input.value.trim().toLowerCase();
  const nodesTbody = document.getElementById('nodes-tbody');
  if (!currentDashboardData.network_nodes || currentDashboardData.network_nodes.length === 0) return;
  
  let html = '';
  let count = 0;
  for (const n of currentDashboardData.network_nodes) {{
    if (term) {{
      const match = n.public_key.toLowerCase().includes(term)
        || n.address.toLowerCase().includes(term)
        || n.connection_status.toLowerCase().includes(term)
        || n.hrw_routing_id.toLowerCase().includes(term);
      if (!match) continue;
    }}
    count++;
    const roleBadge = n.is_local ? '<span class="badge badge-purple">LOCAL (Self)</span>' : (n.is_f2f ? '<span class="badge badge-blue">F2F Friend</span>' : '<span class="badge badge-cyan">Gossip Shard</span>');
    const statusBadge = n.connection_status.includes('Connected')
      ? (n.missing_count === 0 ? '<span class="badge badge-green">Connected (0 Ausfälle)</span>' : '<span class="badge badge-amber">' + n.connection_status + '</span>')
      : (n.connection_status.includes('Suspended') ? '<span class="badge badge-red">' + n.connection_status + '</span>' : '<span class="badge badge-amber">' + n.connection_status + '</span>');
    const rttText = n.rtt_ms != null ? n.rtt_ms + ' ms' : '<span style="color: var(--text-muted);">-</span>';
    const routeText = n.min_hops + ' Hop' + (n.min_hops === 1 ? '' : 's') + (n.best_ingress_peer ? ' via ' + truncateHash(n.best_ingress_peer) : (n.is_local ? ' (Self)' : (n.is_f2f ? ' (Direkt)' : '')));
    const incubText = n.is_immature ? '<span class="badge badge-amber">24h (' + (n.incubation_remaining_sec || 0) + 's)</span>' : '<span class="badge badge-green">Aktiv</span>';
    html += '<tr><td><span class="code" title="' + n.public_key + '">' + truncateHash(n.public_key) + '</span></td><td>' + n.address + '</td><td>' + roleBadge + '</td><td>' + statusBadge + '</td><td>' + rttText + '</td><td>' + routeText + '</td><td><span class="code" title="' + n.hrw_routing_id + '">' + truncateHash(n.hrw_routing_id) + '</span></td><td>' + incubText + '</td><td><button class="btn btn-secondary" style="padding: 0.2rem 0.5rem;" onclick="openNodeInspector(\'' + n.public_key + '\')">🔍 Info</button></td></tr>';
  }}
  nodesTbody.innerHTML = html || '<tr><td colspan="9" class="empty-cell">Keine Knoten gefunden</td></tr>';
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
  const input = document.getElementById('voucher-search-input');
  if (input) input.value = voucherId;
  searchVoucher();
}}

async function searchVoucher() {{
  const input = document.getElementById('voucher-search-input');
  const term = input ? input.value.trim() : '';
  if (!term) return;
  try {{
    const res = await fetch('/dashboard/voucher/' + encodeURIComponent(term));
    if (res.ok) {{
      const detail = await res.json();
      currentVoucherDetail = detail;
      document.getElementById('voucher-modal-title').innerText = '🎟️ Gutschein-Lineage: ' + detail.voucher_id;
      
      let html = '<div style="margin-bottom: 0.75rem; line-height: 1.6;">';
      html += '<div><strong>Gutschein-ID:</strong> <span class="code">' + detail.voucher_id + '</span></div>';
      html += '<div><strong>Wurzel-Anker (valid_until):</strong> ' + detail.root_valid_until_formatted + '</div>';
      html += '<div><strong>Genesis Tag:</strong> <span class="code">' + (detail.genesis_tag || 'N/A') + '</span></div>';
      html += '<div><strong>Gesamt-Sperren in Kette:</strong> ' + detail.locks.length + ' (' + detail.total_byte_years + ' Byte-Jahre Budget)</div>';
      html += '</div>';

      let tableHtml = '<h4 style="margin: 0.75rem 0 0.25rem 0; font-size: 0.9rem;">Ketten-Historie (Lock-Hops):</h4>';
      tableHtml += '<div style="overflow-x: auto;"><table><thead><tr><th>Typ</th><th>Lookup Tag</th><th>Child Lock (t_id)</th><th>Sender PubKey</th></tr></thead><tbody>';
      for (const h of detail.locks) {{
        const typeBadge = h.is_genesis ? '<span class="badge badge-amber">GENESIS</span>' : '<span class="badge badge-blue">SPEND</span>';
        tableHtml += '<tr><td>' + typeBadge + '</td><td class="code" title="' + h.lookup_tag + '">' + truncateHash(h.lookup_tag) + '</td><td class="code">' + truncateHash(h.t_id_hex) + '</td><td class="code">' + truncateHash(h.sender_pub_hex) + '</td></tr>';
      }}
      tableHtml += '</tbody></table></div>';

      document.getElementById('voucher-modal-details').innerHTML = html;
      document.getElementById('voucher-modal-table-container').innerHTML = tableHtml;
      document.getElementById('voucher-modal-json').innerText = JSON.stringify(detail, null, 2);
      document.getElementById('voucher-modal').classList.add('active');
    }} else {{
      alert('Gutschein oder Lookup-Tag "' + term + '" nicht gefunden.');
    }}
  }} catch (e) {{
    alert('Fehler bei der Gutschein-Suche: ' + e.message);
  }}
}}

async function refreshDashboard() {{
  try {{
    const res = await fetch('/dashboard/data');
    if (!res.ok) return;
    const d = await res.json();
    currentDashboardData = d;
    
    // Header Status & Latency Pills
    const badge = document.getElementById('status-badge');
    badge.innerText = d.status_badge;
    badge.className = 'badge ' + (d.status === 'ONLINE' ? 'badge-green' : (d.status === 'VILLAGE MODE' ? 'badge-amber' : 'badge-red'));

    document.getElementById('hdr-lat-local').innerText = d.local_latency.avg_ms.toFixed(2) + ' ms';
    document.getElementById('hdr-lat-quorum').innerText = d.quorum_latency.avg_ms.toFixed(2) + ' ms';
    document.getElementById('hdr-lat-e2e').innerText = d.e2e_latency.avg_ms.toFixed(2) + ' ms';
    document.getElementById('hdr-peers').innerText = d.connected_peers + '/' + d.configured_peers;
    document.getElementById('hdr-shard').innerText = d.shard_mode;

    // Cockpit & System
    const latestWrite = (d.sparklines && d.sparklines.writes) ? (d.sparklines.writes[d.sparklines.writes.length - 1] || 0) : 0;
    const latestRead = (d.sparklines && d.sparklines.reads) ? (d.sparklines.reads[d.sparklines.reads.length - 1] || 0) : 0;
    document.getElementById('writes-rate').innerText = latestWrite.toFixed(1);
    document.getElementById('writes-today').innerText = d.total_writes;
    document.getElementById('reads-rate').innerText = latestRead.toFixed(1);
    document.getElementById('reads-today').innerText = d.total_reads;

    if (d.sparklines) {{
      document.getElementById('writes-sparkline').innerHTML = renderSparklineSvg(d.sparklines.writes, '#10b981');
      document.getElementById('reads-sparkline').innerHTML = renderSparklineSvg(d.sparklines.reads, '#3b82f6');
    }}

    // Hardware
    document.getElementById('sys-cpu-val').innerText = d.system.cpu_percent.toFixed(1) + '%';
    document.getElementById('sys-cpu-bar').style.width = Math.min(100, Math.max(0, d.system.cpu_percent)) + '%';
    document.getElementById('sys-rss-val').innerText = d.system.rss_mb.toFixed(1) + ' MB';
    document.getElementById('sys-redb-val').innerText = Math.round(d.system.redb_bytes / 1024) + ' KB';
    document.getElementById('sys-netto-val').innerText = d.system.netto_locks_bytes + ' B';
    document.getElementById('sys-purged-val').innerText = d.system.ttl_purged_count;

    // Scaling
    document.getElementById('cap-single-val').innerText = d.system.peak_tps_single_core;
    document.getElementById('cap-multi-val').innerText = d.system.peak_tps_multi_core;
    document.getElementById('cap-storage-val').innerText = d.system.max_storage_locks;
    document.getElementById('cap-byte-years-val').innerText = d.system.byte_years_capacity;

    // Thermometer
    document.getElementById('thermo-write-load').innerText = d.thermometer.gossip_write_load.toFixed(2);
    document.getElementById('thermo-read-load').innerText = d.thermometer.gossip_read_load.toFixed(2);
    document.getElementById('thermo-ncb-eff').innerText = Math.round(d.thermometer.ncb_eff);
    document.getElementById('thermo-ncb-read-eff').innerText = Math.round(d.thermometer.ncb_read_eff);
    document.getElementById('thermo-rolling-avg').innerText = d.thermometer.gossip_write_load.toFixed(2);
    document.getElementById('conc-val').innerText = (d.gateway_concentration_ratio * 100).toFixed(1) + '%';
    document.getElementById('subnet-dom-sub').innerText = (d.shard_subnet_dominance_max * 100).toFixed(1) + '%';

    // F2F Friends Table
    const friendsTbody = document.getElementById('friends-tbody');
    if (d.f2f && d.f2f.friends && d.f2f.friends.length > 0) {{
      let html = '';
      for (const f of d.f2f.friends) {{
        let statusBadge = '<span class="badge badge-green">Verbunden (0 Ausfälle)</span>';
        if (!f.is_connected) {{
          statusBadge = '<span class="badge badge-amber">Getrennt</span>';
        }} else if (f.missing_count >= 3) {{
          statusBadge = '<span class="badge badge-red">Suspended (3/3)</span>';
        }} else if (f.missing_count > 0) {{
          statusBadge = '<span class="badge badge-amber">Degrading (' + f.missing_count + '/3)</span>';
        }}
        const rttText = f.rtt_ms != null ? f.rtt_ms + ' ms' : '<span style="color: var(--text-muted);">-</span>';
        let actionBtn = '<button class="btn btn-secondary" style="padding: 0.2rem 0.5rem;" onclick="openNodeInspector(\'' + f.public_key + '\')">🔍 Info</button>';
        if (adminToken) {{
          actionBtn += ' <button class="btn btn-danger" style="padding: 0.2rem 0.5rem; margin-left: 0.25rem;" onclick="adminRemoveFriend(\'' + f.public_key + '\')">🗑️</button>';
        }}
        html += '<tr><td><span class="code" title="' + f.public_key + '">' + truncateHash(f.public_key) + '</span></td><td>' + f.address + '</td><td>' + statusBadge + '</td><td>' + rttText + '</td><td>' + actionBtn + '</td></tr>';
      }}
      friendsTbody.innerHTML = html;
    }} else {{
      friendsTbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Keine F2F Freunde konfiguriert</td></tr>';
    }}

    // Network Nodes Explorer Table
    const searchInput = document.getElementById('node-search-input');
    if (searchInput && searchInput.value.trim()) {{
      filterNodesTable();
    }} else {{
      const nodesTbody = document.getElementById('nodes-tbody');
      if (d.network_nodes && d.network_nodes.length > 0) {{
        let html = '';
        for (const n of d.network_nodes) {{
          const roleBadge = n.is_local ? '<span class="badge badge-purple">LOCAL (Self)</span>' : (n.is_f2f ? '<span class="badge badge-blue">F2F Friend</span>' : '<span class="badge badge-cyan">Gossip Shard</span>');
          const statusBadge = n.connection_status.includes('Connected')
            ? (n.missing_count === 0 ? '<span class="badge badge-green">Connected (0 Ausfälle)</span>' : '<span class="badge badge-amber">' + n.connection_status + '</span>')
            : (n.connection_status.includes('Suspended') ? '<span class="badge badge-red">' + n.connection_status + '</span>' : '<span class="badge badge-amber">' + n.connection_status + '</span>');
          const rttText = n.rtt_ms != null ? n.rtt_ms + ' ms' : '<span style="color: var(--text-muted);">-</span>';
          const routeText = n.min_hops + ' Hop' + (n.min_hops === 1 ? '' : 's') + (n.best_ingress_peer ? ' via ' + truncateHash(n.best_ingress_peer) : (n.is_local ? ' (Self)' : (n.is_f2f ? ' (Direkt)' : '')));
          const incubText = n.is_immature ? '<span class="badge badge-amber">24h (' + (n.incubation_remaining_sec || 0) + 's)</span>' : '<span class="badge badge-green">Aktiv</span>';
          html += '<tr><td><span class="code" title="' + n.public_key + '">' + truncateHash(n.public_key) + '</span></td><td>' + n.address + '</td><td>' + roleBadge + '</td><td>' + statusBadge + '</td><td>' + rttText + '</td><td>' + routeText + '</td><td><span class="code" title="' + n.hrw_routing_id + '">' + truncateHash(n.hrw_routing_id) + '</span></td><td>' + incubText + '</td><td><button class="btn btn-secondary" style="padding: 0.2rem 0.5rem;" onclick="openNodeInspector(\'' + n.public_key + '\')">🔍 Info</button></td></tr>';
        }}
        nodesTbody.innerHTML = html;
        document.getElementById('network-count-sub').innerText = d.network_nodes.length + ' Knoten registriert';
      }}
    }}

    // Tiers & Quotas
    document.getElementById('tier-free-pow-val').innerText = d.tiers.free_pow_diff;
    document.getElementById('tier-free-req-val').innerText = d.tiers.free_req_sec.toFixed(1);
    document.getElementById('tier-friends-used-val').innerText = d.tiers.friends_used_pct.toFixed(1) + '%';
    document.getElementById('tier-vip-used-val').innerText = d.tiers.vip_used_pct.toFixed(1) + '%';
    document.getElementById('quota-used-val').innerText = d.thermometer.today_write_used;
    document.getElementById('quota-limit-val').innerText = d.thermometer.daily_write_quota;
    document.getElementById('quota-pct-text').innerText = d.tiers.friends_used_pct.toFixed(1) + '%';
    document.getElementById('quota-bar').style.width = Math.min(100, Math.max(0, d.tiers.friends_used_pct)) + '%';

    // VIP Accounts Table
    const vipTbody = document.getElementById('vip-accounts-tbody');
    if (d.tiers && d.tiers.vip_accounts && d.tiers.vip_accounts.length > 0) {{
      let html = '';
      for (const a of d.tiers.vip_accounts) {{
        html += '<tr><td><span class="code" title="' + a.account_tag + '">' + a.account_tag + '</span></td><td><strong style="color: var(--purple);">' + a.balance_byte_years.toLocaleString() + '</strong> Byte-Jahre</td></tr>';
      }}
      vipTbody.innerHTML = html;
    }} else {{
      vipTbody.innerHTML = '<tr><td colspan="2" class="empty-cell">Keine VIP Accounts hinterlegt</td></tr>';
    }}

    // Vouchers Table
    const vouchersTbody = document.getElementById('vouchers-tbody');
    const vouchersCountSub = document.getElementById('vouchers-count-sub');
    if (vouchersCountSub) {{
      vouchersCountSub.innerText = (d.total_active_vouchers_count || 0) + ' Gutscheine aktiv (Top 15 angezeigt)';
    }}
    if (d.active_vouchers && d.active_vouchers.length > 0) {{
      let html = '';
      for (const v of d.active_vouchers) {{
        const genShort = v.genesis_tag ? truncateHash(v.genesis_tag) : 'N/A';
        const statusBadge = v.status === 'Active' ? '<span class="badge badge-green">Aktiv</span>' : '<span class="badge badge-amber">' + v.status + '</span>';
        html += '<tr><td><strong>' + v.voucher_id + '</strong></td><td>' + v.root_valid_until_formatted + '</td><td class="code">' + genShort + '</td><td>' + v.locks_count + ' Sperren</td><td>' + statusBadge + '</td><td><button class="btn btn-secondary" onclick="openVoucherInspector(\'' + v.voucher_id + '\')">🔍 Wurzel-Inspektor</button></td></tr>';
      }}
      vouchersTbody.innerHTML = html;
    }} else {{
      vouchersTbody.innerHTML = '<tr><td colspan="6" class="empty-cell">Keine aktiven Gutscheine im Speicher</td></tr>';
    }}

    // Recent Locks Table
    const locksTbody = document.getElementById('locks-tbody');
    if (d.recent_locks && d.recent_locks.length > 0) {{
      let html = '';
      for (const l of d.recent_locks) {{
        const b = l.status === 'Verified' ? '<span class="badge badge-green">Verified</span>' : (l.status === 'Provisional' ? '<span class="badge badge-amber">Provisional</span>' : '<span class="badge badge-red">Conflict</span>');
        const pShort = truncateHash(l.parent_lock_hex);
        const cShort = truncateHash(l.child_lock_hex);
        let tierBadge = '<span class="badge badge-cyan">P2P Sync</span>';
        if (l.tier === 'VIP') {{
          tierBadge = '<span class="badge badge-purple">VIP (' + (l.byte_years || 0) + ' BY)</span>';
        }} else if (l.tier === 'F2F') {{
          tierBadge = '<span class="badge badge-blue">F2F (' + (l.byte_years || 0) + ' BY)</span>';
        }} else if (l.tier === 'Free') {{
          tierBadge = '<span class="badge badge-green">Free (PoW)</span>';
        }} else if (l.tier) {{
          tierBadge = '<span class="badge badge-cyan">' + l.tier + '</span>';
        }}
        const vLink = l.voucher_id ? '<button class="btn btn-secondary" style="padding: 0.15rem 0.4rem; font-size: 0.75rem;" onclick="openVoucherInspector(\'' + l.voucher_id + '\')">🎟️ ' + truncateHash(l.voucher_id) + '</button>' : '<span style="color: var(--text-muted);">-</span>';
        html += '<tr><td>' + l.timestamp_ms + '</td><td class="code" title="' + l.parent_lock_hex + '">' + pShort + '</td><td class="code" title="' + l.child_lock_hex + '">' + cShort + '</td><td>' + tierBadge + '</td><td>' + vLink + '</td><td>' + b + '</td><td><button class="btn btn-secondary" style="padding: 0.2rem 0.5rem;" onclick="openLockInspector(\'' + l.parent_lock_hex + '\')">📄 JSON</button></td></tr>';
      }}
      locksTbody.innerHTML = html;
    }} else {{
      locksTbody.innerHTML = '<tr><td colspan="7" class="empty-cell">Keine Sperren im Ringbuffer</td></tr>';
    }}

  }} catch (e) {{}}
}}

// Initial load & periodic refresh
updateAdminUI();
refreshDashboard();
setInterval(refreshDashboard, 2000);
</script>
</body>
</html>"#,
        status_badge = data.status_badge,
        local_avg = data.local_latency.avg_ms,
        quorum_avg = data.quorum_latency.avg_ms,
        e2e_avg = data.e2e_latency.avg_ms,
        connected_peers = data.connected_peers,
        configured_peers = data.configured_peers,
        shard_mode = data.shard_mode,
        free_req_sec = data.tiers.free_req_sec,
        total_writes = data.total_writes,
        total_reads = data.total_reads,
        reads_rate = data.sparklines.reads.last().copied().unwrap_or(0.0),
        total_active_vouchers = data.total_active_vouchers_count,
        cpu_percent = data.system.cpu_percent,
        rss_mb = data.system.rss_mb,
        redb_kb = data.system.redb_bytes / 1024,
        netto_locks = data.system.netto_locks_bytes,
        ttl_purged = data.system.ttl_purged_count,
        peak_tps_single = data.system.peak_tps_single_core,
        peak_tps_multi = data.system.peak_tps_multi_core,
        max_storage_locks = data.system.max_storage_locks,
        byte_years_capacity = data.system.byte_years_capacity,
        qr_svg = qr_svg,
        node_id = data.node_id,
        hrw_id = data.hrw_routing_id,
        peering_str = data.peering_string,
        gossip_write_load = data.thermometer.gossip_write_load,
        gossip_read_load = data.thermometer.gossip_read_load,
        ncb_eff = data.thermometer.ncb_eff,
        ncb_read_eff = data.thermometer.ncb_read_eff,
        conc_percent = data.gateway_concentration_ratio * 100.0,
        dom_percent = data.shard_subnet_dominance_max * 100.0,
        active_nodes = data.active_nodes_count,
        free_pow_diff = data.tiers.free_pow_diff,
        friends_used_pct = data.tiers.friends_used_pct,
        vip_used_pct = data.tiers.vip_used_pct,
        today_write_used = data.thermometer.today_write_used,
        daily_write_quota = data.thermometer.daily_write_quota
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}
