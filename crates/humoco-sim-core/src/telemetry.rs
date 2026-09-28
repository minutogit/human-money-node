//! # Spec 17: Topologie-Telemetrie & Social-Defense-Layer
//!
//! Zero-I/O, deterministic in-memory telemetry for humoco-sim-core.
//! No syscalls, no external I/O, only blake3 for deterministic hashes.

use std::collections::HashMap;

use crate::types::{NodeId, SimTime};

// ---------------------------------------------------------------------------
// WarningLevel
// ---------------------------------------------------------------------------

pub const WARN_SINGLE_BRIDGE_BOTNET: &str = "WARN_SINGLE_BRIDGE_BOTNET";
pub const WARN_SINGLE_EDGE_CENSORSHIP_RISK: &str = "WARN_SINGLE_EDGE_CENSORSHIP_RISK";
pub const WARN_LOCAL_CLOCK_SKEW: &str = "WARN_LOCAL_CLOCK_SKEW";
pub const WARN_LOCAL_SHARD_PERFORMANCE_DEGRADED: &str = "WARN_LOCAL_SHARD_PERFORMANCE_DEGRADED";
pub const WARN_GATEWAY_CONCENTRATION: &str = "WARN_GATEWAY_CONCENTRATION";
pub const WARN_GATEWAY_NO_FREE_TIER: &str = "WARN_GATEWAY_NO_FREE_TIER";
pub const INFO_NEIGHBOR_SHARD_ACTIVITY: &str = "INFO_NEIGHBOR_SHARD_ACTIVITY";
pub const INFO_AUDIT_INGRESS_HIGH: &str = "INFO_AUDIT_INGRESS_HIGH";
pub const INFO_SHARD_OPERATOR_DOMINANCE: &str = "INFO_SHARD_OPERATOR_DOMINANCE";

/// Diagnostic level for dashboard warnings.
/// Corresponds to the JSON level strings from docs/17 §4.2-4.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WarningLevel {
    /// Peer tunnels massive numbers of unverified identities over a single edge (botnet broom).
    WarnSingleBridgeBotnet,
    /// Local node has only 1 verified F2F edge – high partition / censorship risk.
    WarnSingleEdgeCensorshipRisk,
    /// Local clock drifts >45s from neighbor median – gossip drops imminent.
    WarnLocalClockSkew,
    /// Local shard validation rate <80% – ingress rights at risk of expiry.
    WarnLocalShardPerformanceDegraded,
    /// High percentage of locks originate from <= 2 ingress sources.
    WarnGatewayConcentration,
    /// Configured fallback gateway has free_tier_enabled == false.
    WarnGatewayNoFreeTier,
    /// Neighbor co-signed 0/150 locks in the assigned shard over 24h (optional, informational only).
    InfoNeighborShardActivity,
    /// Neighbor consumes >=80% of its daily ingress on day 1 – plausibility check.
    InfoAuditIngressHigh,
    /// Many shard nodes reside in the same IP subnet.
    InfoShardOperatorDominance,
}

impl WarningLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WarnSingleBridgeBotnet => WARN_SINGLE_BRIDGE_BOTNET,
            Self::WarnSingleEdgeCensorshipRisk => WARN_SINGLE_EDGE_CENSORSHIP_RISK,
            Self::WarnLocalClockSkew => WARN_LOCAL_CLOCK_SKEW,
            Self::WarnLocalShardPerformanceDegraded => WARN_LOCAL_SHARD_PERFORMANCE_DEGRADED,
            Self::WarnGatewayConcentration => WARN_GATEWAY_CONCENTRATION,
            Self::WarnGatewayNoFreeTier => WARN_GATEWAY_NO_FREE_TIER,
            Self::InfoNeighborShardActivity => INFO_NEIGHBOR_SHARD_ACTIVITY,
            Self::InfoAuditIngressHigh => INFO_AUDIT_INGRESS_HIGH,
            Self::InfoShardOperatorDominance => INFO_SHARD_OPERATOR_DOMINANCE,
        }
    }

    /// Telemetry is never authoritative – no level triggers an automatic ban.
    /// INV-1701: always returns false to guarantee non-authoritative behavior.
    pub fn triggers_auto_ban(&self) -> bool {
        false
    }

    pub fn is_warn(&self) -> bool {
        matches!(
            self,
            Self::WarnSingleBridgeBotnet
                | Self::WarnSingleEdgeCensorshipRisk
                | Self::WarnLocalClockSkew
                | Self::WarnLocalShardPerformanceDegraded
                | Self::WarnGatewayConcentration
                | Self::WarnGatewayNoFreeTier
        )
    }

    pub fn is_info(&self) -> bool {
        matches!(
            self,
            Self::InfoNeighborShardActivity
                | Self::InfoAuditIngressHigh
                | Self::InfoShardOperatorDominance
        )
    }
}

impl std::fmt::Display for WarningLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DiagnosticWarning
// ---------------------------------------------------------------------------

/// Single dashboard warning. Peer = None means local warning (own node).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticWarning {
    /// Affected peer; None = local node.
    pub peer: Option<NodeId>,
    pub level: WarningLevel,
    pub message: String,
}

impl DiagnosticWarning {
    pub fn new(peer: Option<NodeId>, level: WarningLevel, message: impl Into<String>) -> Self {
        Self {
            peer,
            level,
            message: message.into(),
        }
    }

    pub fn local(level: WarningLevel, message: impl Into<String>) -> Self {
        Self::new(None, level, message)
    }

    pub fn for_peer(peer: NodeId, level: WarningLevel, message: impl Into<String>) -> Self {
        Self::new(Some(peer), level, message)
    }

    /// Serializes deterministically via blake3 for gossip deduplication (zero-I/O proof).
    pub fn deterministic_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"HUMOCO_V1_TELEMETRY_WARN");
        if let Some(p) = self.peer {
            h.update(&p.to_le_bytes());
        } else {
            h.update(b"LOCAL");
        }
        h.update(self.level.as_str().as_bytes());
        h.update(self.message.as_bytes());
        *h.finalize().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// TopologyReport
// ---------------------------------------------------------------------------

/// Diagnostic report for the `/api/v1/topology.json` endpoint (docs/17 §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopologyReport {
    pub local_node: NodeId,
    pub active_peers_count: usize,
    pub warnings: Vec<DiagnosticWarning>,
}

impl TopologyReport {
    pub fn new(local_node: NodeId, active_peers_count: usize) -> Self {
        Self {
            local_node,
            active_peers_count,
            warnings: Vec::new(),
        }
    }

    pub fn add_warning(&mut self, w: DiagnosticWarning) {
        self.warnings.push(w);
    }

    pub fn is_healthy(&self) -> bool {
        self.warnings.is_empty()
    }

    pub fn has_level(&self, level: WarningLevel) -> bool {
        self.warnings.iter().any(|w| w.level == level)
    }

    pub fn warnings_for_peer(&self, peer: NodeId) -> Vec<&DiagnosticWarning> {
        self.warnings
            .iter()
            .filter(|w| w.peer == Some(peer))
            .collect()
    }

    /// Non-authoritative: report never mutates ban lists. Read-only view.
    /// INV-1701 guarantee – always returns true and mutates nothing.
    pub fn is_non_authoritative(&self) -> bool {
        true
    }

    /// Deterministic blake3 hash over the report (for tests, no I/O).
    pub fn deterministic_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"HUMOCO_V1_TOPOLOGY_REPORT");
        h.update(&self.local_node.to_le_bytes());
        h.update(&(self.active_peers_count as u64).to_le_bytes());
        for w in &self.warnings {
            h.update(&w.deterministic_hash());
        }
        *h.finalize().as_bytes()
    }

    /// Creates Prometheus metrics from the report (zero-I/O conversion).
    pub fn to_prometheus(&self, immature_nodes: usize) -> PrometheusMetrics {
        let mut m = PrometheusMetrics::new();
        m.active_nodes_total = self.active_peers_count + 1; // inkl. lokal
        m.peer_connections = self.active_peers_count;
        m.immature_nodes = immature_nodes;
        m
    }
}

// ---------------------------------------------------------------------------
// PrometheusMetrics
// ---------------------------------------------------------------------------

/// Lightweight Prometheus metrics `/metrics` (docs/17 §4.1), zero-I/O.
#[derive(Clone, Debug, Default)]
pub struct PrometheusMetrics {
    pub active_nodes_total: usize,
    pub peer_connections: usize,
    pub immature_nodes: usize,
    /// Counter: inbound heartbeats per minute per neighbor edge.
    pub inbound_rate: HashMap<NodeId, u64>,
    /// Counter: packets dropped by Dunbar-RED per edge.
    pub red_drop_rate: HashMap<NodeId, u64>,
}

impl PrometheusMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_active_nodes(&mut self, n: usize) {
        self.active_nodes_total = n;
    }

    pub fn set_peer_connections(&mut self, n: usize) {
        self.peer_connections = n;
    }

    pub fn set_immature_nodes(&mut self, n: usize) {
        self.immature_nodes = n;
    }

    pub fn inc_inbound(&mut self, peer: NodeId, delta: u64) {
        *self.inbound_rate.entry(peer).or_insert(0) += delta;
    }

    pub fn inc_red_drop(&mut self, peer: NodeId, delta: u64) {
        *self.red_drop_rate.entry(peer).or_insert(0) += delta;
    }

    pub fn get_inbound(&self, peer: NodeId) -> u64 {
        self.inbound_rate.get(&peer).copied().unwrap_or(0)
    }

    pub fn get_red_drop(&self, peer: NodeId) -> u64 {
        self.red_drop_rate.get(&peer).copied().unwrap_or(0)
    }

    /// Renders in Prometheus exposition format (deterministic, zero-I/O).
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# HELP humoco_active_nodes_total Currently known active nodes in HRW pool\n# TYPE humoco_active_nodes_total gauge\nhumoco_active_nodes_total {}\n",
            self.active_nodes_total
        ));
        out.push_str(&format!(
            "# HELP humoco_peer_connections Number of active direct F2F and co-shard QUIC sessions\n# TYPE humoco_peer_connections gauge\nhumoco_peer_connections {}\n",
            self.peer_connections
        ));
        out.push_str(&format!(
            "# HELP humoco_immature_nodes Newly seen identities in 24h incubation phase\n# TYPE humoco_immature_nodes gauge\nhumoco_immature_nodes {}\n",
            self.immature_nodes
        ));
        // per-peer counters sorted deterministically by NodeId
        let mut peers: Vec<NodeId> = self.inbound_rate.keys().copied().collect();
        peers.sort_unstable();
        for p in &peers {
            out.push_str(&format!(
                "humoco_edge_inbound_rate{{peer=\"{}\"}} {}\n",
                p,
                self.inbound_rate[p]
            ));
        }
        let mut rpeers: Vec<NodeId> = self.red_drop_rate.keys().copied().collect();
        rpeers.sort_unstable();
        for p in &rpeers {
            out.push_str(&format!(
                "humoco_edge_red_drop_rate{{peer=\"{}\"}} {}\n",
                p,
                self.red_drop_rate[p]
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// IngressAuditTracker  (INV-1704)
// ---------------------------------------------------------------------------

/// Monitors ingress volume of directly connected neighbors.
/// Plausibility threshold >=80% daily limit on day 1 (docs/17 §4.3).
#[derive(Clone, Debug)]
pub struct IngressAuditTracker {
    /// Daily quota in Byte-Years (e.g. 960,000 hard floor = 1000×960).
    daily_quota: u64,
    /// peer -> (epoch_day, used_byte_years)
    usage: HashMap<NodeId, (u64, u64)>,
    /// first day the peer was seen
    first_seen_day: HashMap<NodeId, u64>,
}

impl IngressAuditTracker {
    pub fn new(daily_quota: u64) -> Self {
        Self {
            daily_quota,
            usage: HashMap::new(),
            first_seen_day: HashMap::new(),
        }
    }

    pub fn daily_quota(&self) -> u64 {
        self.daily_quota
    }

    pub fn set_daily_quota(&mut self, quota: u64) {
        self.daily_quota = quota;
    }

    /// Records ingress from peer on epoch_day. Returns an optional warning if
    /// the >=80% threshold on day 1 is reached. Deterministic, zero-I/O.
    pub fn record_ingress(
        &mut self,
        peer: NodeId,
        epoch_day: u64,
        byte_years: u64,
    ) -> Option<DiagnosticWarning> {
        let first = self.first_seen_day.entry(peer).or_insert(epoch_day);
        let first_day = *first;

        let entry = self.usage.entry(peer).or_insert((epoch_day, 0));
        if entry.0 != epoch_day {
            // Day change -> reset
            entry.0 = epoch_day;
            entry.1 = 0;
        }
        entry.1 = entry.1.saturating_add(byte_years);

        let ratio = if self.daily_quota == 0 {
            0.0
        } else {
            entry.1 as f64 / self.daily_quota as f64
        };

        // Only on the first day (epoch_day == first_day) and >=80% -> audit hint
        if epoch_day == first_day && ratio >= 0.8 {
            Some(DiagnosticWarning::for_peer(
                peer,
                WarningLevel::InfoAuditIngressHigh,
                format!(
                    "Peer '{}' claims {:.0}% of its daily ingress ({} Byte-Years, quota {}). Please check plausibility.",
                    peer,
                    ratio * 100.0,
                    entry.1,
                    self.daily_quota
                ),
            ))
        } else {
            None
        }
    }

    pub fn usage_for(&self, peer: NodeId) -> u64 {
        self.usage.get(&peer).map(|(_, u)| *u).unwrap_or(0)
    }

    pub fn usage_ratio(&self, peer: NodeId) -> f64 {
        if self.daily_quota == 0 {
            return 0.0;
        }
        self.usage_for(peer) as f64 / self.daily_quota as f64
    }

    /// True if audit threshold exceeded on day 1.
    pub fn is_audit_threshold_exceeded(&self, peer: NodeId) -> bool {
        if let Some(first) = self.first_seen_day.get(&peer) {
            if let Some((day, _)) = self.usage.get(&peer) {
                if *day != *first {
                    return false;
                }
                return self.usage_ratio(peer) >= 0.8;
            }
        }
        false
    }

    /// Day change without ingress – resets usage (deterministic).
    pub fn advance_day(&mut self, peer: NodeId, epoch_day: u64) {
        if let Some(entry) = self.usage.get_mut(&peer) {
            if entry.0 != epoch_day {
                entry.0 = epoch_day;
                entry.1 = 0;
            }
        }
    }
}

impl Default for IngressAuditTracker {
    fn default() -> Self {
        Self::new(960_000)
    }
}

// ---------------------------------------------------------------------------
// ShardPerformanceTracker  (INV-1705)
// ---------------------------------------------------------------------------

/// Tracks shard validation performance for self-diagnosis and neighborhood audit (docs/17 §4.4).
#[derive(Clone, Debug)]
pub struct ShardPerformanceTracker {
    pub local_node: NodeId,
    pub shard_id: u16,
    total_locks: usize,
    signed_locks: usize,
}

impl ShardPerformanceTracker {
    pub fn new(local_node: NodeId, shard_id: u16) -> Self {
        Self {
            local_node,
            shard_id,
            total_locks: 0,
            signed_locks: 0,
        }
    }

    /// Sets shard performance: total locks in shard, of which co-signed.
    pub fn record(&mut self, total_locks: usize, signed_locks: usize) {
        self.total_locks = total_locks;
        self.signed_locks = signed_locks.min(total_locks);
    }

    pub fn total_locks(&self) -> usize {
        self.total_locks
    }

    pub fn signed_locks(&self) -> usize {
        self.signed_locks
    }

    /// Participation ratio 0.0..1.0 – 1.0 when total is 0 (no obligation).
    pub fn participation_ratio(&self) -> f64 {
        if self.total_locks == 0 {
            return 1.0;
        }
        self.signed_locks as f64 / self.total_locks as f64
    }

    /// Checks local warning WARN_LOCAL_SHARD_PERFORMANCE_DEGRADED if <80%.
    pub fn check_local_warning(&self) -> Option<DiagnosticWarning> {
        let ratio = self.participation_ratio();
        if ratio < 0.8 {
            Some(DiagnosticWarning::local(
                WarningLevel::WarnLocalShardPerformanceDegraded,
                format!(
                    "Local shard validation rate is only {:.0}% ({}/{} locks co-signed). Ingress rights at risk of expiry!",
                    ratio * 100.0,
                    self.signed_locks,
                    self.total_locks
                ),
            ))
        } else {
            None
        }
    }

    /// Optional neighborhood audit for F2F friends.
    /// Returns INFO_NEIGHBOR_SHARD_ACTIVITY if the neighbor barely participates.
    pub fn check_neighbor(
        &self,
        peer: NodeId,
        participated: usize,
        total: usize,
    ) -> Option<DiagnosticWarning> {
        if total == 0 {
            return None;
        }
        let ratio = participated as f64 / total as f64;
        // Show info if peer <50% or 0/150 in 24h window – analogous to spec example
        if participated == 0 || ratio < 0.5 {
            Some(DiagnosticWarning::for_peer(
                peer,
                WarningLevel::InfoNeighborShardActivity,
                format!(
                    "Peer participated in {}/{} locks in assigned Shard {} over the last 24h.",
                    participated, total, self.shard_id
                ),
            ))
        } else {
            None
        }
    }

    /// Convenience: is_degraded == true if <80%
    pub fn is_degraded(&self) -> bool {
        self.participation_ratio() < 0.8
    }
}

// ---------------------------------------------------------------------------
// Topologie-Analyse Helfer (INV-1702)
// ---------------------------------------------------------------------------

/// Detects botnet broom: many unverified identities via a single bridge
/// without cross-connections. Threshold: >=50 unverified + 0 cross-connections -> warning.
pub fn detect_single_bridge_botnet(
    peer: NodeId,
    tunneled_unverified: usize,
    cross_connections: usize,
) -> Option<DiagnosticWarning> {
    if tunneled_unverified >= 50 && cross_connections == 0 {
        Some(DiagnosticWarning::for_peer(
            peer,
            WarningLevel::WarnSingleBridgeBotnet,
            format!(
                "Peer tunnels {} unverified identities via single edge. Ingress throttled via Dunbar-RED.",
                tunneled_unverified
            ),
        ))
    } else {
        None
    }
}

/// Single-edge censorship risk: local node has only 1 verified F2F edge.
pub fn detect_single_edge_censorship_risk(
    local_node: NodeId,
    verified_degree: usize,
) -> Option<DiagnosticWarning> {
    if verified_degree <= 1 {
        Some(DiagnosticWarning::new(
            Some(local_node),
            WarningLevel::WarnSingleEdgeCensorshipRisk,
            format!(
                "Node has only {} verified F2F edge(s) (deg={}). High risk of partition and single-edge censorship. Please peer with >= 2-3 nodes.",
                verified_degree, verified_degree
            ),
        ))
    } else {
        None
    }
}

/// Clock-skew warning if local clock deviates >45s from neighbor median.
pub fn detect_clock_skew(local_node: NodeId, skew_ms: i64) -> Option<DiagnosticWarning> {
    if skew_ms.abs() > 45_000 {
        Some(DiagnosticWarning::new(
            Some(local_node),
            WarningLevel::WarnLocalClockSkew,
            format!(
                "Local system clock diverges by {}s from neighbor median. High risk of gossip dropping. Triggers auto NTP resync.",
                skew_ms / 1000
            ),
        ))
    } else {
        None
    }
}

/// Evaluates a meshed multi-node cluster.
/// Returns warnings; legitimate clusters (PoW ok + degree >=3) remain warning-free.
/// INV-1702 guarantee.
pub fn evaluate_multi_node_cluster(
    node_degrees: &[(NodeId, usize)],
    pow_valid: &HashMap<NodeId, bool>,
) -> Vec<DiagnosticWarning> {
    let mut warnings = Vec::new();
    for (nid, deg) in node_degrees {
        let valid = pow_valid.get(nid).copied().unwrap_or(false);
        if !valid {
            warnings.push(DiagnosticWarning::for_peer(
                *nid,
                WarningLevel::WarnSingleEdgeCensorshipRisk,
                format!("Node {} has invalid PoW.", nid),
            ));
            continue;
        }
        if *deg < 3 {
            // Still unmeshed – legitimate reserve but with censorship hint
            if let Some(w) = detect_single_edge_censorship_risk(*nid, *deg) {
                warnings.push(w);
            }
        }
        // deg >=3 && pow valid => no warning (protected)
    }
    warnings
}

// ---------------------------------------------------------------------------
// Starvation-Deterministik (INV-1703)
// ---------------------------------------------------------------------------

/// Result of the starvation cascade after REVOKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StarvationStage {
    /// Still active (under 21h)
    Active,
    /// Deactivated via hysteresis (21-48h)
    Deactivated,
    /// Physically purged from RAM (>=48h)
    Purged,
}

/// Deterministically evaluates the starvation status by hours since REVOKE.
/// Zero-I/O, purely time-based, no central coordination.
pub fn evaluate_starvation(hours_since_revoke: u64) -> StarvationStage {
    if hours_since_revoke >= 48 {
        StarvationStage::Purged
    } else if hours_since_revoke >= 21 {
        StarvationStage::Deactivated
    } else {
        StarvationStage::Active
    }
}

pub fn is_deactivated_by_starvation(hours_since_revoke: u64) -> bool {
    matches!(
        evaluate_starvation(hours_since_revoke),
        StarvationStage::Deactivated | StarvationStage::Purged
    )
}

pub fn is_purged_by_starvation(hours_since_revoke: u64) -> bool {
    evaluate_starvation(hours_since_revoke) == StarvationStage::Purged
}

/// Deterministically simulates the starvation cascade for tests:
/// Returns (is_active, is_purged) based on SimTime.
pub fn starvation_at_time(revoke_at: SimTime, now: SimTime) -> StarvationStage {
    let elapsed_ms = now.0.saturating_sub(revoke_at.0);
    let hours = elapsed_ms / (3600 * 1000);
    evaluate_starvation(hours)
}

/// Evaluates gateway concentration ratio: the fraction of locks/traffic originating
/// from the top <= 2 ingress sources (0.0 to 1.0).
pub fn evaluate_gateway_concentration_ratio(source_counts: &[usize]) -> f64 {
    let total: usize = source_counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let mut sorted = source_counts.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let top_2_sum: usize = sorted.iter().take(2).sum();
    top_2_sum as f64 / total as f64
}

/// Detects gateway concentration: if >= 20 total locks and >= 80% originate from <= 2 ingress sources.
/// INV-1701: non-authoritative warning only.
pub fn detect_gateway_concentration(source_counts: &[usize]) -> Option<DiagnosticWarning> {
    let total: usize = source_counts.iter().sum();
    if total >= 20 {
        let ratio = evaluate_gateway_concentration_ratio(source_counts);
        if ratio >= 0.8 {
            return Some(DiagnosticWarning::local(
                WarningLevel::WarnGatewayConcentration,
                format!(
                    "High gateway concentration: top ingress sources provide {:.1}% of {} total locks (>= 80% threshold). Consider diversifying ingress endpoints.",
                    ratio * 100.0,
                    total
                ),
            ));
        }
    }
    None
}

/// Evaluates maximum shard subnet dominance ratio (0.0 to 1.0).
pub fn evaluate_subnet_dominance_max(subnet_node_counts: &[usize]) -> f64 {
    let total: usize = subnet_node_counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let max_in_subnet = subnet_node_counts.iter().copied().max().unwrap_or(0);
    max_in_subnet as f64 / total as f64
}

/// Detects shard operator dominance: when a single subnet hosts > 50% of nodes in a shard (N >= 3).
/// INV-1701: non-authoritative informational notice only.
pub fn detect_shard_operator_dominance(
    shard_id: u16,
    subnet_node_counts: &[usize],
) -> Option<DiagnosticWarning> {
    let total: usize = subnet_node_counts.iter().sum();
    if total >= 3 {
        let max_ratio = evaluate_subnet_dominance_max(subnet_node_counts);
        if max_ratio > 0.5 {
            return Some(DiagnosticWarning::local(
                WarningLevel::InfoShardOperatorDominance,
                format!(
                    "Shard {} operator dominance: single subnet contains {:.1}% of shard nodes ({} of {}).",
                    shard_id,
                    max_ratio * 100.0,
                    subnet_node_counts.iter().copied().max().unwrap_or(0),
                    total
                ),
            ));
        }
    }
    None
}

/// Detects if a configured fallback gateway has disabled free tier PoW ingress.
/// INV-1701: non-authoritative warning only.
pub fn detect_gateway_no_free_tier(
    gateway_endpoint: &str,
    free_tier_enabled: bool,
) -> Option<DiagnosticWarning> {
    if !free_tier_enabled {
        Some(DiagnosticWarning::local(
            WarningLevel::WarnGatewayNoFreeTier,
            format!(
                "Configured gateway '{}' has disabled free tier ingress (free_tier_enabled = false).",
                gateway_endpoint
            ),
        ))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Deterministische Hash-Helfer
// ---------------------------------------------------------------------------

/// Hash over topology degree distribution (blake3) – for deterministic comparisons.
pub fn hash_degree_map(degrees: &[(NodeId, usize)]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"HUMOCO_V1_DEGREE_MAP");
    let mut sorted = degrees.to_vec();
    sorted.sort_by_key(|(id, _)| *id);
    for (id, deg) in sorted {
        h.update(&id.to_le_bytes());
        h.update(&(deg as u64).to_le_bytes());
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warning_level_non_authoritative() {
        for lvl in [
            WarningLevel::WarnSingleBridgeBotnet,
            WarningLevel::WarnSingleEdgeCensorshipRisk,
            WarningLevel::WarnLocalClockSkew,
            WarningLevel::WarnLocalShardPerformanceDegraded,
            WarningLevel::WarnGatewayConcentration,
            WarningLevel::WarnGatewayNoFreeTier,
            WarningLevel::InfoNeighborShardActivity,
            WarningLevel::InfoAuditIngressHigh,
            WarningLevel::InfoShardOperatorDominance,
        ] {
            assert!(!lvl.triggers_auto_ban(), "Level {:?} must never auto-ban", lvl);
        }
    }

    #[test]
    fn test_starvation_stages() {
        assert_eq!(evaluate_starvation(0), StarvationStage::Active);
        assert_eq!(evaluate_starvation(20), StarvationStage::Active);
        assert_eq!(evaluate_starvation(21), StarvationStage::Deactivated);
        assert_eq!(evaluate_starvation(24), StarvationStage::Deactivated);
        assert_eq!(evaluate_starvation(47), StarvationStage::Deactivated);
        assert_eq!(evaluate_starvation(48), StarvationStage::Purged);
        assert_eq!(evaluate_starvation(100), StarvationStage::Purged);
    }
}
