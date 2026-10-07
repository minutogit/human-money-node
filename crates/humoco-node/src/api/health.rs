//! # Node Health Assessment Engine (Phase 1 Backend & Spec 17 Diagnostic Telemetry)
//!
//! Evaluates the health status of a HuMoCo node deterministically based on [`DashboardData`].
//!
//! ## Architectural Invariant: INV-1701 (Non-Authoritative Telemetry)
//! Health evaluations and status warnings are purely diagnostic and operator-facing.
//! A degraded or critical health level MUST NEVER trigger an automated peer ban,
//! network slashing, or ingress denial (`triggers_auto_ban() == false`).

use serde::{Deserialize, Serialize};

use crate::api::dashboard::DashboardData;

/// Tri-state health severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum HealthLevel {
    #[default]
    Ok,
    Warn,
    Crit,
}

/// A specific diagnostic health finding or evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthItem {
    pub code: String,
    pub severity: HealthLevel,
    pub message_de: String,
    pub hint_de: String,
}

/// Summary of all evaluated diagnostic health checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSummary {
    pub level: HealthLevel,
    pub items: Vec<HealthItem>,
}

impl Default for HealthSummary {
    fn default() -> Self {
        Self {
            level: HealthLevel::Ok,
            items: Vec::new(),
        }
    }
}

/// Flush queue warning threshold (1,000 items)
pub const QUEUE_WARN_THRESHOLD: usize = 1_000;
/// Flush queue critical threshold (9,000 items or 90% of default capacity)
pub const QUEUE_CRIT_THRESHOLD: usize = 9_000;

/// Gateway concentration ratio warning threshold (50%)
pub const GATEWAY_CONCENTRATION_WARN_RATIO: f64 = 0.5;

/// Shard subnet dominance warning threshold (50%)
pub const SUBNET_DOMINANCE_WARN_RATIO: f64 = 0.5;

/// Clock drift warning threshold in milliseconds (5,000 ms = 5 s)
pub const CLOCK_DRIFT_WARN_MS: i64 = 5_000;
/// Clock drift critical threshold in milliseconds (30,000 ms = 30 s)
pub const CLOCK_DRIFT_CRIT_MS: i64 = 30_000;

/// Argon2d shard ticket 24h incubation period in seconds
pub const TICKET_INCUBATION_SEC: u64 = 86_400;

/// Evaluates the node's operational health from `DashboardData`.
///
/// Pure, deterministic function without side-effects or network I/O.
/// Respects architectural invariant INV-1701: diagnostic only, triggers no auto-ban.
pub fn evaluate_health(data: &DashboardData) -> HealthSummary {
    let mut items = Vec::new();

    // 1. NO_PEERS: connected_peers == 0 and configured_peers > 0 -> crit
    if data.connected_peers == 0 && data.configured_peers > 0 {
        items.push(HealthItem {
            code: "NO_PEERS".to_string(),
            severity: HealthLevel::Crit,
            message_de: "Keine P2P-Peers verbunden trotz konfigurierter Gegenstellen.".to_string(),
            hint_de: "Netzwerkverbindung, Firewall und P2P-Port (Standard 9090) prüfen.".to_string(),
        });
    }

    // 2. QUEUE_HIGH: flush_queue_depth > 1000 -> warn, if extreme (> 90%) -> crit
    if data.flush_queue_depth >= QUEUE_CRIT_THRESHOLD {
        items.push(HealthItem {
            code: "QUEUE_HIGH".to_string(),
            severity: HealthLevel::Crit,
            message_de: format!(
                "Flush-Warteschlange extrem voll ({} Einträge, >90% Kapazität).",
                data.flush_queue_depth
            ),
            hint_de: "I/O-Leistung des Speichermediums (redb) und Systemauslastung prüfen.".to_string(),
        });
    } else if data.flush_queue_depth > QUEUE_WARN_THRESHOLD {
        items.push(HealthItem {
            code: "QUEUE_HIGH".to_string(),
            severity: HealthLevel::Warn,
            message_de: format!(
                "Erhöhte Flush-Warteschlangentiefe ({} Einträge).",
                data.flush_queue_depth
            ),
            hint_de: "Disk-I/O beobachten; asynchroner Flush hinkt eventuell hinterher.".to_string(),
        });
    }

    // 3. SLA_VIOLATED: !pos_sla_compliant -> warn
    if !data.pos_sla_compliant {
        items.push(HealthItem {
            code: "SLA_VIOLATED".to_string(),
            severity: HealthLevel::Warn,
            message_de: "PoS-Checkout Hot-Path SLA (<5 ms) verletzt.".to_string(),
            hint_de: "RAM-Index-Latenzen analysieren und I/O-Überlastung reduzieren.".to_string(),
        });
    }

    // 4. BROOM: broom_patterns_detected > 0 -> warn
    if data.broom_patterns_detected > 0 {
        items.push(HealthItem {
            code: "BROOM".to_string(),
            severity: HealthLevel::Warn,
            message_de: format!(
                "Besen-Muster (Broom Attack) im Ingress erkannt ({} Vorfälle).",
                data.broom_patterns_detected
            ),
            hint_de: "Ingress-Diversität und Gateway-Traffic auf aggregierte Sybil-Angriffe prüfen.".to_string(),
        });
    }

    // 5. GATEWAY_CONC: gateway_concentration_ratio > 0.5 -> warn
    if data.gateway_concentration_ratio > GATEWAY_CONCENTRATION_WARN_RATIO {
        items.push(HealthItem {
            code: "GATEWAY_CONC".to_string(),
            severity: HealthLevel::Warn,
            message_de: format!(
                "Hohe Gateway-Konzentration ({:.1}% > 50%).",
                data.gateway_concentration_ratio * 100.0
            ),
            hint_de: "Ingress über mehrere Gateways streuen, um Single-Points-of-Failure zu vermeiden.".to_string(),
        });
    }

    // 6. SUBNET_DOM: shard_subnet_dominance_max > 0.5 -> warn
    if data.shard_subnet_dominance_max > SUBNET_DOMINANCE_WARN_RATIO {
        items.push(HealthItem {
            code: "SUBNET_DOM".to_string(),
            severity: HealthLevel::Warn,
            message_de: format!(
                "Shard-Subnetz-Dominanz überschreitet 50% ({:.1}%).",
                data.shard_subnet_dominance_max * 100.0
            ),
            hint_de: "Peers in unterschiedlichen IP-Subnetzen betreiben zur Erhöhung der Resilienz.".to_string(),
        });
    }

    // 7. CLOCK_DRIFT: if drift > 5_000 ms -> warn, > 30_000 ms -> crit
    let drift = data.clock_drift_ms.abs();
    if drift > CLOCK_DRIFT_CRIT_MS {
        items.push(HealthItem {
            code: "CLOCK_DRIFT".to_string(),
            severity: HealthLevel::Crit,
            message_de: format!(
                "Kritische Uhrenabweichung zur P2P-Netzwerkzeit: {} ms (>30 s).",
                drift
            ),
            hint_de: "Systemzeitsynchronisation (NTP / chrony) prüfen. Große Abweichungen gefährden Konsensvalidität.".to_string(),
        });
    } else if drift > CLOCK_DRIFT_WARN_MS {
        items.push(HealthItem {
            code: "CLOCK_DRIFT".to_string(),
            severity: HealthLevel::Warn,
            message_de: format!(
                "Erhöhte Uhrenabweichung zur P2P-Netzwerkzeit: {} ms (>5 s).",
                drift
            ),
            hint_de: "Lokale Systemzeit weicht vom Median der F2F-Nachbarn ab. NTP-Status überprüfen.".to_string(),
        });
    }

    // 8. TICKET_INCUBATING: if ticket incubation < 86_400 s (when incubating) -> info/ok
    let incubating_node = data.network_nodes.iter().find(|n| {
        n.is_immature
            || n.incubation_remaining_sec
                .map(|s| s > 0 && s <= TICKET_INCUBATION_SEC)
                .unwrap_or(false)
    });
    if let Some(node) = incubating_node {
        let remaining_sec = node.incubation_remaining_sec.unwrap_or(TICKET_INCUBATION_SEC);
        if remaining_sec <= TICKET_INCUBATION_SEC {
            items.push(HealthItem {
                code: "TICKET_INCUBATING".to_string(),
                severity: HealthLevel::Ok,
                message_de: format!(
                    "Argon2d-Shard-Ticket befindet sich in 24h-Reifung (noch {} s verbleibend).",
                    remaining_sec
                ),
                hint_de: "Ticket reift 24 Stunden, bevor es im HRW-Scoring aktiv wird (Schutz vor Shard-Hopping).".to_string(),
            });
        }
    }

    // 9. DASHBOARD_EXPOSED: if bind address is not loopback (0.0.0.0 or public IP) -> crit
    let is_exposed = if !data.config_view.bind_addr.is_empty() {
        !data.config_view.loopback_only
    } else {
        false
    };
    if is_exposed {
        items.push(HealthItem {
            code: "DASHBOARD_EXPOSED".to_string(),
            severity: HealthLevel::Crit,
            message_de: format!(
                "Dashboard-REST-API lauscht auf externer/öffentlicher Adresse '{}'.",
                data.config_view.bind_addr
            ),
            hint_de: "Dashboard sollte nur auf Loopback (127.0.0.1) lauschen oder per Firewall/VPN geschützt werden.".to_string(),
        });
    }

    let level = items.iter().map(|item| item.severity).max().unwrap_or(HealthLevel::Ok);

    HealthSummary { level, items }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::dashboard::{ConfigViewDto, TierSharesDto};
    use crate::api::metrics::LatencyTierStats;
    use crate::api::system_stats::{SparklinesDto, SystemStatsDto};
    use crate::api::dashboard::{F2fOverviewDto, ThermometerStatsDto, TierOverviewDto};
    use crate::network::manager::NetworkNodeDto;

    fn mock_healthy_dashboard_data() -> DashboardData {
        DashboardData {
            status: "ONLINE".to_string(),
            status_badge: "ONLINE".to_string(),
            node_id: "test_node_id".to_string(),
            public_key: "test_pubkey".to_string(),
            hrw_routing_id: "test_hrw".to_string(),
            peering_string: "test_pubkey@127.0.0.1:9090".to_string(),
            uptime_seconds: 3600,
            uptime_formatted: "1h 0m 0s".to_string(),
            active_locks: 10,
            flush_queue_depth: 50,
            connected_peers: 3,
            configured_peers: 3,
            active_nodes_count: 4,
            total_writes: 100,
            total_reads: 500,
            local_latency: LatencyTierStats {
                avg_ms: 1.2,
                p95_ms: 2.0,
                min_ms: 0.5,
                max_ms: 4.0,
                sample_count: 100,
                sla_compliant: true,
            },
            quorum_latency: LatencyTierStats {
                avg_ms: 25.0,
                p95_ms: 45.0,
                min_ms: 10.0,
                max_ms: 60.0,
                sample_count: 100,
                sla_compliant: true,
            },
            e2e_latency: LatencyTierStats {
                avg_ms: 28.0,
                p95_ms: 50.0,
                min_ms: 12.0,
                max_ms: 70.0,
                sample_count: 100,
                sla_compliant: true,
            },
            pos_latency_count: 100,
            pos_latency_avg_ms: 1.2,
            pos_sla_compliant: true,
            broom_patterns_detected: 0,
            gateway_concentration_ratio: 0.2,
            shard_subnet_dominance_max: 0.3,
            free_tier_enabled: true,
            warnings: Vec::new(),
            total_shards: 1024,
            shard_mode: "Global Mesh".to_string(),
            shard_responsibility_ratio: 1.0,
            sample_shard_scores: Vec::new(),
            network_nodes: vec![NetworkNodeDto {
                node_id: "local".to_string(),
                public_key: "local_pk".to_string(),
                address: "127.0.0.1:9090".to_string(),
                is_f2f: false,
                is_local: true,
                connection_status: "Active".to_string(),
                min_hops: 0,
                hrw_routing_id: "local_hrw".to_string(),
                work_score: 10,
                is_immature: false,
                pending_ticket: None,
                incubation_remaining_sec: None,
                missing_count: 0,
                last_failure_sec: None,
                rtt_ms: Some(0),
                best_ingress_peer: None,
            }],
            total_active_vouchers_count: 1,
            active_vouchers: Vec::new(),
            recent_locks: Vec::new(),
            system: SystemStatsDto::default(),
            thermometer: ThermometerStatsDto {
                gossip_write_load: 0.0,
                gossip_read_load: 0.0,
                ncb_eff: 960_000.0,
                ncb_read_eff: 960_000.0,
                daily_write_quota: 960_000,
                daily_read_quota: 960_000,
                today_write_used: 100,
                today_read_used: 500,
                total_write_used: 100,
                total_read_used: 500,
                vip_writes_today: 10,
                f2f_writes_today: 20,
                free_writes_today: 70,
            },
            sparklines: SparklinesDto::default(),
            tiers: TierOverviewDto {
                free_pow_diff: 8,
                free_pow_hashes: 256,
                free_pow_time_est: "< 0.1 ms".to_string(),
                free_req_sec: 0.0,
                free_reserved_pct: 20.0,
                free_used_pct: 1.0,
                free_writes_today: 70,
                friends_reserved_pct: 30.0,
                friends_used_pct: 2.0,
                friends_writes_today: 20,
                active_friends_count: 2,
                vip_reserved_pct: 50.0,
                vip_used_pct: 1.0,
                vip_writes_today: 10,
                vip_accounts_count: 1,
                vip_total_balance: 1000,
                vip_accounts: Vec::new(),
                total_writes_today: 100,
                total_quota_used_pct: 0.1,
            },
            f2f: F2fOverviewDto {
                my_pubkey: "local_pk".to_string(),
                friends: Vec::new(),
            },
            network_time_ms: 1_700_000_000_000,
            is_simulation: false,
            clock_drift_ms: 0,
            health: HealthSummary::default(),
            config_view: ConfigViewDto {
                api_port: 8080,
                p2p_port: 9090,
                bind_addr: "127.0.0.1".to_string(),
                footprint_bytes: 144,
                tier_shares: TierSharesDto { free: 20, f2f: 30, vip: 50 },
                loopback_only: true,
            },
            f2f_clients: Vec::new(),
            persistence: crate::api::dashboard::PersistenceDto::default(),
            rejections: crate::api::dashboard::RejectionsDto::default(),
        }
    }

    #[test]
    fn test_health_all_ok() {
        let data = mock_healthy_dashboard_data();
        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Ok);
        assert!(summary.items.is_empty());
    }

    #[test]
    fn test_health_no_peers_crit() {
        let mut data = mock_healthy_dashboard_data();
        data.connected_peers = 0;
        data.configured_peers = 3;

        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Crit);
        assert!(summary.items.iter().any(|i| i.code == "NO_PEERS" && i.severity == HealthLevel::Crit));
    }

    #[test]
    fn test_health_village_mode_configured_zero_is_ok() {
        let mut data = mock_healthy_dashboard_data();
        data.connected_peers = 0;
        data.configured_peers = 0;

        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Ok);
        assert!(!summary.items.iter().any(|i| i.code == "NO_PEERS"));
    }

    #[test]
    fn test_health_queue_warn_and_crit() {
        let mut data = mock_healthy_dashboard_data();

        // Under 1000 -> Ok
        data.flush_queue_depth = 1_000;
        assert_eq!(evaluate_health(&data).level, HealthLevel::Ok);

        // > 1000 -> Warn
        data.flush_queue_depth = 1_001;
        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Warn);
        assert!(summary.items.iter().any(|i| i.code == "QUEUE_HIGH" && i.severity == HealthLevel::Warn));

        // >= 9000 -> Crit
        data.flush_queue_depth = 9_000;
        let summary_crit = evaluate_health(&data);
        assert_eq!(summary_crit.level, HealthLevel::Crit);
        assert!(summary_crit.items.iter().any(|i| i.code == "QUEUE_HIGH" && i.severity == HealthLevel::Crit));
    }

    #[test]
    fn test_health_sla_violated() {
        let mut data = mock_healthy_dashboard_data();
        data.pos_sla_compliant = false;

        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Warn);
        assert!(summary.items.iter().any(|i| i.code == "SLA_VIOLATED" && i.severity == HealthLevel::Warn));
    }

    #[test]
    fn test_health_broom_detected() {
        let mut data = mock_healthy_dashboard_data();
        data.broom_patterns_detected = 2;

        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Warn);
        assert!(summary.items.iter().any(|i| i.code == "BROOM" && i.severity == HealthLevel::Warn));
    }

    #[test]
    fn test_health_gateway_concentration() {
        let mut data = mock_healthy_dashboard_data();
        data.gateway_concentration_ratio = 0.50;
        assert_eq!(evaluate_health(&data).level, HealthLevel::Ok);

        data.gateway_concentration_ratio = 0.51;
        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Warn);
        assert!(summary.items.iter().any(|i| i.code == "GATEWAY_CONC"));
    }

    #[test]
    fn test_health_subnet_dominance() {
        let mut data = mock_healthy_dashboard_data();
        data.shard_subnet_dominance_max = 0.50;
        assert_eq!(evaluate_health(&data).level, HealthLevel::Ok);

        data.shard_subnet_dominance_max = 0.51;
        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Warn);
        assert!(summary.items.iter().any(|i| i.code == "SUBNET_DOM"));
    }

    #[test]
    fn test_health_clock_drift_warn_and_crit() {
        let mut data = mock_healthy_dashboard_data();

        // 5000 ms -> Ok
        data.clock_drift_ms = 5_000;
        assert_eq!(evaluate_health(&data).level, HealthLevel::Ok);

        // 5001 ms -> Warn
        data.clock_drift_ms = 5_001;
        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Warn);
        assert!(summary.items.iter().any(|i| i.code == "CLOCK_DRIFT" && i.severity == HealthLevel::Warn));

        // -5001 ms -> Warn (negative drift)
        data.clock_drift_ms = -5_001;
        let summary_neg = evaluate_health(&data);
        assert_eq!(summary_neg.level, HealthLevel::Warn);

        // 30001 ms -> Crit
        data.clock_drift_ms = 30_001;
        let summary_crit = evaluate_health(&data);
        assert_eq!(summary_crit.level, HealthLevel::Crit);
        assert!(summary_crit.items.iter().any(|i| i.code == "CLOCK_DRIFT" && i.severity == HealthLevel::Crit));

        // -30001 ms -> Crit
        data.clock_drift_ms = -30_001;
        let summary_crit_neg = evaluate_health(&data);
        assert_eq!(summary_crit_neg.level, HealthLevel::Crit);
    }

    #[test]
    fn test_health_ticket_incubating() {
        let mut data = mock_healthy_dashboard_data();
        data.network_nodes[0].is_immature = true;
        data.network_nodes[0].incubation_remaining_sec = Some(43_200);

        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Ok);
        assert!(summary.items.iter().any(|i| i.code == "TICKET_INCUBATING" && i.severity == HealthLevel::Ok));
    }

    #[test]
    fn test_health_dashboard_exposed() {
        let mut data = mock_healthy_dashboard_data();
        data.config_view.bind_addr = "0.0.0.0".to_string();
        data.config_view.loopback_only = false;

        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Crit);
        assert!(summary.items.iter().any(|i| i.code == "DASHBOARD_EXPOSED" && i.severity == HealthLevel::Crit));
    }

    #[test]
    fn test_health_highest_severity_wins() {
        let mut data = mock_healthy_dashboard_data();
        // One Warn
        data.pos_sla_compliant = false;
        // One Crit
        data.connected_peers = 0;
        data.configured_peers = 2;

        let summary = evaluate_health(&data);
        assert_eq!(summary.level, HealthLevel::Crit);
        assert_eq!(summary.items.len(), 2);
    }
}
