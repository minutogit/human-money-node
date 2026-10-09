use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::api::events::EventKind;
use crate::api::health::{evaluate_health, HealthLevel, HealthSummary};
pub use crate::ingress::F2fClientDto;
use crate::api::metrics::LatencyTierStats;
use crate::api::qr::generate_qr_svg;
use crate::api::routes::AppState;
use crate::api::system_stats::{SparklinesDto, SystemStatsDto};
use crate::network::manager::NetworkNodeDto;
use crate::network::peer::PeerConnectionType;
use crate::storage::recent::{
    RecentLockStatus, RecentLockSummary, VoucherSummaryDto,
};

/// Quota reservation percentages across the three ingress tiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TierSharesDto {
    pub free: u8,
    pub f2f: u8,
    pub vip: u8,
}

impl Default for TierSharesDto {
    fn default() -> Self {
        Self {
            free: 20,
            f2f: 30,
            vip: 50,
        }
    }
}

/// Runtime configuration view exported to dashboard clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigViewDto {
    pub api_port: u16,
    pub p2p_port: u16,
    pub bind_addr: String,
    pub footprint_bytes: u64,
    pub tier_shares: TierSharesDto,
    pub loopback_only: bool,
}

impl Default for ConfigViewDto {
    fn default() -> Self {
        Self {
            api_port: 8080,
            p2p_port: 9090,
            bind_addr: "127.0.0.1".to_string(),
            footprint_bytes: 144,
            tier_shares: TierSharesDto::default(),
            loopback_only: true,
        }
    }
}

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
    pub free_pow_hashes: u64,
    pub free_pow_time_est: String,
    pub free_req_sec: f64,
    pub free_reserved_pct: f64,
    pub free_used_pct: f64,
    pub free_writes_today: u64,
    pub friends_reserved_pct: f64,
    pub friends_used_pct: f64,
    pub friends_writes_today: u64,
    pub active_friends_count: usize,
    pub vip_reserved_pct: f64,
    pub vip_used_pct: f64,
    pub vip_writes_today: u64,
    pub vip_accounts_count: usize,
    pub vip_total_balance: u64,
    pub vip_accounts: Vec<VipAccountDto>,
    pub total_writes_today: u64,
    pub total_quota_used_pct: f64,
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
pub struct AddMeshPeerRequest {
    pub pubkey: String,
    #[serde(default)]
    pub label: Option<String>,
    #[deprecated(note = "dual_role_ingress is deprecated and ignored; server peering and client ingress are strictly decoupled")]
    #[serde(default)]
    pub dual_role_ingress: Option<bool>,
}

pub type AddFriendRequest = AddMeshPeerRequest;

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
pub struct AddClientFriendRequest {
    pub label: String,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddClientFriendResponse {
    pub status: String,
    pub token: String,
    pub label: String,
    pub wallet_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveClientFriendResponse {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardScoreSampleDto {
    pub shard_id: u16,
    pub score: f64,
    pub is_responsible: bool,
    #[serde(default)]
    pub rank: usize,
}

/// Status of the asynchronous ACID redb persistence worker.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistenceDto {
    pub last_successful_flush_ms: u64,
    pub last_flush_ago_sec: Option<u64>,
    pub flush_queue_depth: usize,
    pub flush_batches_total: u64,
    pub flush_errors_total: u64,
    pub flush_ops_total: u64,
    pub redb_file_bytes: u64,
}

/// Breakdown of rejected requests across specific failure causes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RejectionsDto {
    pub total_rejected: u64,
    pub conflict_409: u64,
    pub capacity_429: u64,
    pub quota_429: u64,
    pub bad_pow_400: u64,
    pub last_rejection_ago_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    // Sysadmin & Quorum Observability
    #[serde(default)]
    pub disk_free_gb: f64,
    #[serde(default)]
    pub quorum_display: String,

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

    // Network Time & Mode
    pub network_time_ms: u64,
    pub is_simulation: bool,

    /// Registered F2F client API credentials (Tier 2 client ingress via HTTP port 8080).
    /// Note: Distinct from internal P2P mesh topology edges in `f2f.friends` (QUIC port 9090).
    #[serde(default)]
    pub f2f_clients: Vec<F2fClientDto>,

    /// Diagnostic health assessment (INV-1701: non-authoritative, diagnostic only, triggers no auto-ban).
    #[serde(default)]
    pub health: HealthSummary,

    /// Runtime configuration view.
    #[serde(default)]
    pub config_view: ConfigViewDto,

    /// Clock drift relative to F2F median in milliseconds.
    #[serde(default)]
    pub clock_drift_ms: i64,

    /// Persistence and asynchronous disk flush telemetry.
    #[serde(default)]
    pub persistence: PersistenceDto,

    /// Granular breakdown of rejected lock requests.
    #[serde(default)]
    pub rejections: RejectionsDto,
}

/// Formats epoch milliseconds as German civil date/time (DD.MM.YYYY, HH:mm:ss)
pub fn format_epoch_millis(ms: u64) -> String {
    let secs = ms / 1000;
    let s = secs % 60;
    let mins = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days_since_epoch = (secs / 86400) as i64;
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{:02}.{:02}.{}, {:02}:{:02}:{:02}", d, month, year, h, mins, s)
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

struct PeerExplorerSnapshot {
    connected_peers: usize,
    configured_peers: usize,
    active_nodes_count: usize,
    broom_patterns_detected: usize,
    gateway_concentration_ratio: f64,
    shard_subnet_dominance_max: f64,
    warnings: Vec<String>,
    network_nodes: Vec<NetworkNodeDto>,
    active_hrw_nodes: Vec<([u8; 32], SocketAddr)>,
}

pub async fn collect_dashboard_data(state: &AppState) -> DashboardData {
    let uptime = state.start_time.elapsed();
    let uptime_formatted = format_uptime(uptime);
    let peering_string = determine_peering_string(state);
    let local_pubkey_bytes = *state.identity.public_key().as_bytes();
    let local_hrw = state.identity.hrw_routing_id();
    let local_addr = state.transport.as_ref().and_then(|t| t.local_addr().ok());

    let peer_snapshot = if let Some(ref pm) = state.peer_manager {
        let conn = pm.connected_peer_count().await;
        let conf = pm.all_peer_addrs().await.len();
        let active_nodes = pm.active_known_nodes().await;
        let act = active_nodes.len();
        let hrw_nodes = pm.active_hrw_nodes().await;

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

        PeerExplorerSnapshot {
            connected_peers: conn,
            configured_peers: conf,
            active_nodes_count: act,
            broom_patterns_detected: brooms,
            gateway_concentration_ratio: conc_ratio,
            shard_subnet_dominance_max: sub_dom_max,
            warnings: warns,
            network_nodes: nodes,
            active_hrw_nodes: hrw_nodes,
        }
    } else {
        PeerExplorerSnapshot {
            connected_peers: 0,
            configured_peers: 0,
            active_nodes_count: 0,
            broom_patterns_detected: 0,
            gateway_concentration_ratio: 0.0,
            shard_subnet_dominance_max: 0.0,
            warnings: Vec::new(),
            network_nodes: vec![NetworkNodeDto {
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
            active_hrw_nodes: Vec::new(),
        }
    };

    let PeerExplorerSnapshot {
        connected_peers,
        configured_peers,
        active_nodes_count,
        broom_patterns_detected,
        gateway_concentration_ratio,
        shard_subnet_dominance_max,
        warnings,
        network_nodes,
        active_hrw_nodes,
    } = peer_snapshot;

    let free_tier_enabled = true;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let total_active = active_nodes_count + 1; // including self
    let (required_q, _is_final) = humoco_sim_core::types::required_quorum(total_active);
    let is_stable_24h = if let Some(ref pm) = state.peer_manager {
        pm.is_network_stable_ge20_for_24h(now_ms)
    } else {
        false
    };

    let (status, status_badge) = if connected_peers == 0 && configured_peers > 0 {
        ("DEGRADED".to_string(), "DEGRADED (0 Peers)".to_string())
    } else if total_active == 1 || configured_peers == 0 {
        ("STANDALONE".to_string(), "STANDALONE (N=1, PROVISIONAL)".to_string())
    } else if total_active < 20 {
        ("COMMUNITY MESH".to_string(), format!("COMMUNITY-MESH (N={}, PROVISIONAL)", total_active))
    } else if !is_stable_24h {
        ("STABILIZING".to_string(), "WELTNETZ (24h-Stabilisierung)".to_string())
    } else {
        ("ONLINE".to_string(), "WELTNETZ (FINAL)".to_string())
    };

    let quorum_display = if total_active < 20 {
        format!("{}/{} (Prov)", required_q, total_active)
    } else {
        "14/20 (Final)".to_string()
    };

    let (active_byte_years, active_locks) = state.engine.get_active_footprint_byte_years(now_ms).await;
    let flush_queue_depth = state.engine.flush_sender_len();

    // 3-Tier Latencies (Rolling 100)
    let local_latency = state.metrics.local_stats();
    let quorum_latency = state.metrics.quorum_stats();
    let e2e_latency = state.metrics.e2e_stats();

    let pos_latency_count = state.metrics.pos_latency_count();
    let pos_latency_avg_ms = state.metrics.pos_latency_avg_ms();
    let pos_sla_compliant = local_latency.sla_compliant;

    // Shard Topology
    let (shard_mode, shard_responsibility_ratio) = if total_active < 20 {
        ("Community-Mesh (N < 20)".to_string(), 1.0f64)
    } else {
        ("HRW Top-20 Sharding (N >= 20)".to_string(), (20.0f64 / total_active as f64).min(1.0f64))
    };

    let sample_shards = [0, 64, 128, 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960];
    let sample_shard_scores = sample_shards
        .into_iter()
        .map(|sid| {
            let self_score = humoco_sim_core::client_flow::compute_hrw_score_f64(local_hrw, sid);
            let higher_nodes_count = active_hrw_nodes
                .iter()
                .filter(|(hrw_id, _)| {
                    if hrw_id == local_hrw {
                        return false;
                    }
                    let score = humoco_sim_core::client_flow::compute_hrw_score_f64(hrw_id, sid);
                    score > self_score || (score == self_score && hrw_id > local_hrw)
                })
                .count();
            let self_rank = higher_nodes_count + 1;
            let is_responsible = total_active < 20 || self_rank <= 20;
            ShardScoreSampleDto {
                shard_id: sid,
                score: self_score,
                is_responsible,
                rank: self_rank,
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
    let disk_free_gb = system.disk_free_bytes as f64 / (1024.0 * 1024.0 * 1024.0);

    // 2. Sparklines
    let sparklines = state.system_stats.get_sparklines();

    // 3. Thermometer stats
    let ncb_eff = state.tier_controller.effective_ncb() as f64;
    let ncb_read_eff = state.tier_controller.effective_read_ncb() as f64;
    let gossip_write_load = state.tier_controller.rolling_24h_average() as f64;
    let gossip_read_load = sparklines.reads.last().copied().unwrap_or(0.0) as f64;
    let daily_write_quota = state.tier_controller.calculate_daily_quota(1.0, 1.0);
    let daily_read_quota = state.tier_controller.calculate_daily_read_quota(1.0, 1.0);
    let (total_write_used, total_read_used) = {
        let thermo_arc = state.tier_controller.thermometer();
        let thermo = thermo_arc
            .read()
            .unwrap_or_else(|e| e.into_inner());
        (
            thermo.total_daily_write_usage(),
            thermo.total_daily_read_usage(),
        )
    };
    let today_write_used = active_byte_years;
    let today_read_used = state.metrics.total_reads();
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

    // 4. F2F Overview
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
    let active_friends_count = friends_list.iter().filter(|f| f.is_connected).count();

    let f2f = F2fOverviewDto {
        my_pubkey: state.identity.public_key_bs58(),
        friends: friends_list,
    };

    // 5. Tiers Overview
    let free_pow_diff = state.pow_engine.default_difficulty();
    let free_pow_hashes = if free_pow_diff > 0 { 1u64 << free_pow_diff } else { 1 };
    let free_pow_time_est = match free_pow_diff {
        0 => "< 0.1 ms (Instant)",
        1..=8 => "< 0.1 ms",
        9..=12 => "~ 1 ms",
        13..=16 => "~ 15 ms",
        17..=20 => "~ 250 ms",
        21..=24 => "~ 4 s",
        _ => "> 10 s",
    }.to_string();
    let free_req_sec = sparklines.writes.last().copied().unwrap_or(0.0) as f64;

    let free_reserved_pct = 20.0;
    let friends_reserved_pct = 30.0;
    let vip_reserved_pct = 50.0;

    let total_writes_today = vip_writes_today + f2f_writes_today + free_writes_today;
    let total_quota_used_pct = ((today_write_used as f64 / daily_write_quota.max(1) as f64) * 100.0).clamp(0.0, 100.0);

    let free_quota = (daily_write_quota as f64 * 0.20).max(1.0);
    let friends_quota = (daily_write_quota as f64 * 0.30).max(1.0);
    let vip_quota = (daily_write_quota as f64 * 0.50).max(1.0);

    let free_used_by = if total_writes_today > 0 {
        (free_writes_today as f64 / total_writes_today as f64) * today_write_used as f64
    } else {
        0.0
    };
    let friends_used_by = if total_writes_today > 0 {
        (f2f_writes_today as f64 / total_writes_today as f64) * today_write_used as f64
    } else {
        0.0
    };
    let vip_used_by = if total_writes_today > 0 {
        (vip_writes_today as f64 / total_writes_today as f64) * today_write_used as f64
    } else {
        0.0
    };

    let free_used_pct = ((free_used_by / free_quota) * 100.0).clamp(0.0, 100.0);
    let friends_used_pct = ((friends_used_by / friends_quota) * 100.0).clamp(0.0, 100.0);
    let vip_used_pct = ((vip_used_by / vip_quota) * 100.0).clamp(0.0, 100.0);

    let vip_accounts: Vec<VipAccountDto> = state
        .tier_controller
        .list_vip_accounts()
        .into_iter()
        .map(|(account_tag, balance_byte_years)| VipAccountDto {
            account_tag,
            balance_byte_years,
        })
        .collect();
    let vip_accounts_count = vip_accounts.len();
    let vip_total_balance: u64 = vip_accounts.iter().map(|a| a.balance_byte_years).sum();

    let tiers = TierOverviewDto {
        free_pow_diff,
        free_pow_hashes,
        free_pow_time_est,
        free_req_sec,
        free_reserved_pct,
        free_used_pct,
        free_writes_today,
        friends_reserved_pct,
        friends_used_pct,
        friends_writes_today: f2f_writes_today,
        active_friends_count,
        vip_reserved_pct,
        vip_used_pct,
        vip_writes_today,
        vip_accounts_count,
        vip_total_balance,
        vip_accounts,
        total_writes_today,
        total_quota_used_pct,
    };

    let epoch_day = state.tier_controller.current_epoch_day_at(now_ms);
    let f2f_clients = state.tier_controller.list_f2f_clients(now_ms, epoch_day);

    let api_port = state.config.network.rpc_listen_addr.port();
    let p2p_port = state.config.network.p2p_listen_addr.port();
    let bind_addr = state.config.network.rpc_listen_addr.ip().to_string();
    let loopback_only = state.config.network.rpc_listen_addr.ip().is_loopback();
    let tier_shares = state
        .config
        .ingress
        .tier_shares
        .as_ref()
        .map(|s| TierSharesDto {
            free: s.free,
            f2f: s.f2f,
            vip: s.vip,
        })
        .unwrap_or_default();
    let config_view = ConfigViewDto {
        api_port,
        p2p_port,
        bind_addr,
        footprint_bytes: 144,
        tier_shares,
        loopback_only,
    };

    let clock_drift_ms = state
        .peer_manager
        .as_ref()
        .map(|pm| pm.clock().logical_offset_ms())
        .unwrap_or(0);

    let last_flush_ms = state.engine.stats.last_successful_flush_ms.load(std::sync::atomic::Ordering::Relaxed);
    let last_flush_ago_sec = if last_flush_ms > 0 {
        Some(now_ms.saturating_sub(last_flush_ms) / 1000)
    } else {
        None
    };

    let persistence = PersistenceDto {
        last_successful_flush_ms: last_flush_ms,
        last_flush_ago_sec,
        flush_queue_depth,
        flush_batches_total: state.engine.stats.flush_batches_total.load(std::sync::atomic::Ordering::Relaxed),
        flush_errors_total: state.engine.stats.flush_errors_total.load(std::sync::atomic::Ordering::Relaxed),
        flush_ops_total: state.engine.stats.flush_ops_total.load(std::sync::atomic::Ordering::Relaxed),
        redb_file_bytes: system.redb_bytes,
    };

    let rejections = RejectionsDto {
        total_rejected: state.metrics.locks_rejected(),
        conflict_409: state.metrics.rejected_conflict_409(),
        capacity_429: state.metrics.rejected_capacity_429(),
        quota_429: state.metrics.rejected_quota_429(),
        bad_pow_400: state.metrics.rejected_bad_pow_400(),
        last_rejection_ago_sec: state.metrics.last_rejection_ago_sec(),
    };

    let mut data = DashboardData {
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
        total_shards: 65536,
        shard_mode,
        shard_responsibility_ratio,
        sample_shard_scores,
        disk_free_gb,
        quorum_display,
        network_nodes,
        total_active_vouchers_count,
        active_vouchers,
        recent_locks,
        system,
        thermometer,
        sparklines,
        tiers,
        f2f,
        network_time_ms: state.net_time_ms(),
        is_simulation: state.is_simulation,
        f2f_clients,
        health: HealthSummary::default(),
        config_view,
        clock_drift_ms,
        persistence,
        rejections,
    };
    data.health = evaluate_health(&data);
    data
}

/// Convenience alias for collect_dashboard_data
pub async fn get_dashboard_data(state: &AppState) -> DashboardData {
    collect_dashboard_data(state).await
}

fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = forwarded.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "127.0.0.1".to_string()
}

/// Helper to verify admin authorization header.
#[allow(clippy::result_large_err)]
fn verify_admin_auth(state: &AppState, headers: &axum::http::HeaderMap) -> Result<(), Response> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if !state.auth.verify_token(auth_header) {
        state.event_log.record(
            EventKind::System,
            HealthLevel::Warn,
            "Fehlgeschlagene Admin-Authentifizierung".to_string(),
        );
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
    let client_ip = extract_client_ip(&headers);
    if !state.auth.check_rate_limit(&client_ip) {
        state.event_log.record(
            EventKind::System,
            HealthLevel::Warn,
            format!("Rate-Limit für Admin-Authentifizierung erreicht ({})", client_ip),
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "TooManyRequests",
                "message": "Too many failed authentication attempts. Please try again later."
            })),
        )
            .into_response();
    }

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if !state.auth.verify_token(auth_header) {
        state.auth.record_failure(&client_ip);
        state.event_log.record(
            EventKind::System,
            HealthLevel::Warn,
            "Fehlgeschlagene Admin-Authentifizierung".to_string(),
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Invalid or missing admin authorization token"
            })),
        )
            .into_response();
    }

    state.auth.record_success(&client_ip);
    state.event_log.record(
        EventKind::System,
        HealthLevel::Ok,
        "Erfolgreiche Admin-Authentifizierung".to_string(),
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": "Admin token valid"
        })),
    )
        .into_response()
}

/// Handler for POST /dashboard/admin/mesh/peers (and alias POST /dashboard/admin/friends)
pub async fn admin_add_mesh_peer(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<AddMeshPeerRequest>,
) -> Response {
    if let Err(unauth) = verify_admin_auth(&state, &headers) {
        return unauth;
    }

    let key_bytes = match crate::api::keys::parse_pubkey(&payload.pubkey) {
        Ok(arr) => arr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "BadRequest",
                    "message": format!("Invalid public key: {}", e)
                })),
            )
                .into_response();
        }
    };

    let hex_key = hex::encode(key_bytes);

    if let Some(ref pm) = state.peer_manager {
        pm.add_trusted_f2f_peer(key_bytes).await;

        state.event_log.record(
            EventKind::PeerConnect,
            HealthLevel::Ok,
            format!("Added trusted F2F mesh peer {}", hex_key),
        );

        (
            StatusCode::OK,
            Json(AddFriendResponse {
                status: "ok".into(),
                pubkey: hex_key,
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

/// Alias handler for POST /dashboard/admin/friends
pub async fn admin_add_friend(
    state: State<AppState>,
    headers: axum::http::HeaderMap,
    payload: Json<AddFriendRequest>,
) -> Response {
    admin_add_mesh_peer(state, headers, payload).await
}

/// Handler for DELETE /dashboard/admin/mesh/peers/:key (and alias DELETE /dashboard/admin/friends/:key)
pub async fn admin_remove_mesh_peer(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if let Err(unauth) = verify_admin_auth(&state, &headers) {
        return unauth;
    }

    let key_bytes = match crate::api::keys::parse_pubkey(&key) {
        Ok(arr) => arr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "BadRequest",
                    "message": format!("Invalid public key: {}", e)
                })),
            )
                .into_response();
        }
    };

    let hex_key = hex::encode(key_bytes);

    if let Some(ref pm) = state.peer_manager {
        pm.remove_trusted_f2f_peer(&key_bytes).await;

        state.event_log.record(
            EventKind::PeerDisconnect,
            HealthLevel::Ok,
            format!("Removed trusted F2F mesh peer {}", hex_key),
        );

        (
            StatusCode::OK,
            Json(RemoveFriendResponse {
                status: "ok".into(),
                removed: hex_key,
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

/// Alias handler for DELETE /dashboard/admin/friends/:key
pub async fn admin_remove_friend(
    state: State<AppState>,
    headers: axum::http::HeaderMap,
    key: Path<String>,
) -> Response {
    admin_remove_mesh_peer(state, headers, key).await
}

/// Handler for POST /dashboard/admin/ingress/clients
pub async fn admin_add_ingress_client(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<AddClientFriendRequest>,
) -> Response {
    if let Err(unauth) = verify_admin_auth(&state, &headers) {
        return unauth;
    }

    let token = match payload.token {
        Some(ref t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => {
            let mut bytes = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
            format!("f2f_{}", hex::encode(bytes))
        }
    };

    let label = if payload.label.trim().is_empty() {
        format!("Client-{}", &token[..token.len().min(8)])
    } else {
        payload.label.trim().to_string()
    };

    state.tier_controller.register_f2f_client(&token, Some(&label));

    let rpc_addr = state.config.network.rpc_listen_addr;
    let host = if rpc_addr.ip().is_unspecified() {
        "127.0.0.1".to_string()
    } else {
        rpc_addr.ip().to_string()
    };
    let api_addr = format!("{}:{}", host, rpc_addr.port());
    let wallet_uri = format!("humoco://{}?token={}", api_addr, token);

    state.event_log.record(
        EventKind::ClientRegistered,
        HealthLevel::Ok,
        format!("Registered F2F ingress client '{}'", label),
    );

    (
        StatusCode::OK,
        Json(AddClientFriendResponse {
            status: "ok".into(),
            token,
            label,
            wallet_uri,
        }),
    )
        .into_response()
}

/// Handler for DELETE /dashboard/admin/ingress/clients/:token_hash
pub async fn admin_remove_ingress_client(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(token_hash): Path<String>,
) -> Response {
    if let Err(unauth) = verify_admin_auth(&state, &headers) {
        return unauth;
    }

    let removed = state.tier_controller.remove_f2f_client(&token_hash);
    if removed {
        state.event_log.record(
            EventKind::ClientRemoved,
            HealthLevel::Ok,
            format!("Removed F2F ingress client {}", token_hash),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "removed": token_hash,
        })),
    )
        .into_response()
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
    let tag_bytes = crate::control::parse_account_tag(trimmed);
    state.tier_controller.register_vip_token(trimmed, tag_bytes);
    state.tier_controller.register_vip_tag(tag_bytes);

    match state.tier_controller.topup_vip_quota(tag_bytes, payload.byte_years) {
        Ok(new_balance) => {
            state.event_log.record(
                EventKind::QuotaTopup,
                HealthLevel::Ok,
                format!(
                    "VIP Quota aufgeladen für '{}' (+{} BY, Saldo: {})",
                    trimmed, payload.byte_years, new_balance
                ),
            );
            (
                StatusCode::OK,
                Json(TopupQuotaResponse {
                    status: "ok".into(),
                    account_tag: trimmed.to_string(),
                    new_balance,
                }),
            )
                .into_response()
        }
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
    let net_time_formatted = format_epoch_millis(data.network_time_ms);
    let sim_badge_style = if data.is_simulation { "display: inline-block; " } else { "display: none; " };

    let html = format!(
        include_str!("assets/dashboard.html"),
        css = include_str!("assets/dashboard.css"),
        js = include_str!("assets/dashboard.js"),
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
        uptime_formatted = data.uptime_formatted,
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
        active_nodes = data.active_nodes_count + 1,
        free_pow_diff = data.tiers.free_pow_diff,
        free_pow_hashes = data.tiers.free_pow_hashes,
        free_pow_time_est = data.tiers.free_pow_time_est,
        free_used_pct = data.tiers.free_used_pct,
        free_writes_today = data.tiers.free_writes_today,
        friends_used_pct = data.tiers.friends_used_pct,
        friends_writes_today = data.tiers.friends_writes_today,
        active_friends_count = data.tiers.active_friends_count,
        vip_used_pct = data.tiers.vip_used_pct,
        vip_writes_today = data.tiers.vip_writes_today,
        vip_accounts_count = data.tiers.vip_accounts_count,
        vip_total_balance = data.tiers.vip_total_balance,
        total_writes_today = data.tiers.total_writes_today,
        total_quota_used_pct = data.tiers.total_quota_used_pct,
        today_write_used = data.thermometer.today_write_used,
        daily_write_quota = data.thermometer.daily_write_quota,
        net_time_formatted = net_time_formatted,
        sim_badge_style = sim_badge_style,
        disk_free_gb = data.disk_free_gb,
        quorum_display = data.quorum_display
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}
