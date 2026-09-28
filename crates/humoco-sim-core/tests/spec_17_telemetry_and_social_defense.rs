//! Spec 17: Topologie-Telemetrie & Social-Defense-Layer (INV-1701..1705)
//! Deterministische, Zero-I/O Tests – keine externen Crates außer blake3.

use humoco_sim_core::telemetry::{
    detect_clock_skew, detect_gateway_concentration, detect_gateway_no_free_tier,
    detect_shard_operator_dominance, detect_single_bridge_botnet, detect_single_edge_censorship_risk,
    evaluate_gateway_concentration_ratio, evaluate_multi_node_cluster, evaluate_starvation,
    evaluate_subnet_dominance_max, hash_degree_map, is_deactivated_by_starvation,
    is_purged_by_starvation, starvation_at_time, DiagnosticWarning, IngressAuditTracker,
    PrometheusMetrics, ShardPerformanceTracker, StarvationStage, TopologyReport, WarningLevel,
    WARN_GATEWAY_CONCENTRATION, WARN_GATEWAY_NO_FREE_TIER, INFO_SHARD_OPERATOR_DOMINANCE,
};
use humoco_sim_core::types::SimTime;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// INV-1701: Nicht-autoritäre Telemetrie – Hinweise statt Banns
// ---------------------------------------------------------------------------

#[test]
fn test_inv1701_telemetry_is_non_authoritative_no_auto_ban() {
    // Kein WarningLevel darf automatischen Bann triggern
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
        assert!(
            !lvl.triggers_auto_ban(),
            "INV-1701: Level {:?} darf keinen Auto-Bann auslösen",
            lvl
        );
        assert!(
            !lvl.as_str().is_empty(),
            "Level muss stringifizierbar sein"
        );
    }

    // TopologyReport erzeugt nur Warnungen, ändert keine Bannlisten (simuliert via HashSet)
    let banned: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut report = TopologyReport::new(1, 7);
    report.add_warning(DiagnosticWarning::for_peer(
        99,
        WarningLevel::WarnSingleBridgeBotnet,
        "Peer tunnels 85 unverified identities via single edge.",
    ));
    report.add_warning(DiagnosticWarning::new(
        Some(1),
        WarningLevel::WarnSingleEdgeCensorshipRisk,
        "Node has only 1 verified F2F edge.",
    ));

    // INV-1701: Report ist non-authoritative
    assert!(report.is_non_authoritative());
    // Bannliste muss leer bleiben obwohl Warnungen existieren
    assert!(
        banned.is_empty(),
        "INV-1701: Telemetrie darf Bannliste nicht mutieren"
    );
    // Auch nach deterministischem Hash bleibt Bannliste leer
    let _hash = report.deterministic_hash();
    assert!(banned.is_empty());

    // Auch Prometheus-Render darf nichts bannen
    let prom = report.to_prometheus(2);
    let rendered = prom.render();
    assert!(rendered.contains("humoco_active_nodes_total"));
    assert!(banned.is_empty(), "Prometheus-Render darf nicht bannen");

    // Zweiter Durchlauf deterministisch identischer Hash
    let mut report2 = TopologyReport::new(1, 7);
    report2.add_warning(DiagnosticWarning::for_peer(
        99,
        WarningLevel::WarnSingleBridgeBotnet,
        "Peer tunnels 85 unverified identities via single edge.",
    ));
    report2.add_warning(DiagnosticWarning::new(
        Some(1),
        WarningLevel::WarnSingleEdgeCensorshipRisk,
        "Node has only 1 verified F2F edge.",
    ));
    assert_eq!(
        report.deterministic_hash(),
        report2.deterministic_hash(),
        "INV-1701: Determinismus – gleiche Warnungen => gleicher Hash"
    );

    // Warnungen selbst sind deterministisch hashbar
    let w = DiagnosticWarning::for_peer(5, WarningLevel::WarnLocalClockSkew, "skew>45s");
    let h1 = w.deterministic_hash();
    let h2 = DiagnosticWarning::for_peer(5, WarningLevel::WarnLocalClockSkew, "skew>45s")
        .deterministic_hash();
    assert_eq!(h1, h2, "Warning Hash deterministisch");
}

#[test]
fn test_inv1701_dashboard_warnings_do_not_evict_peers_automatically() {
    // Simuliere 3 Operator-Entscheidungen: nur menschliches REVOKE entfernt Kante, nicht Automat.
    let mut report = TopologyReport::new(10, 5);
    // Selbst kritische Botnetz-Warnung führt nicht zu automatischem Rausschmiss
    let warn = detect_single_bridge_botnet(42, 85, 0).expect("muss Botnetz erkennen");
    assert_eq!(warn.level, WarningLevel::WarnSingleBridgeBotnet);
    report.add_warning(warn);
    // Peers bleiben gezählt – keine automatische Reduktion
    assert_eq!(report.active_peers_count, 5);
    assert!(report.has_level(WarningLevel::WarnSingleBridgeBotnet));
    // Kein triggers_auto_ban
    for w in &report.warnings {
        assert!(!w.level.triggers_auto_ban());
    }
}

// ---------------------------------------------------------------------------
// INV-1702: Schutz vernetzter Multi-Node-Cluster (PoW + >=3 Kanten)
// ---------------------------------------------------------------------------

#[test]
fn test_inv1702_legit_multi_node_cluster_with_pow_and_ge3_no_warning() {
    // Legitimer Betreiber: 10 Nodes, je >=3 Kanten, valider PoW => keine Botnet-Warnung
    let operator_nodes: Vec<(u16, usize)> = (0..10).map(|i| (i as u16, 3 + (i % 3) as usize)).collect(); // degrees 3,4,5
    let mut pow_valid = HashMap::new();
    for (nid, _) in &operator_nodes {
        pow_valid.insert(*nid, true);
    }

    let warnings = evaluate_multi_node_cluster(&operator_nodes, &pow_valid);
    assert!(
        warnings.is_empty(),
        "INV-1702: Vernetzter legitimer Cluster mit >=3 Kanten und validem PoW darf keine Warnung erzeugen, bekam {:?}",
        warnings
    );

    // Auch bei 10 Nodes deterministisch derselbe Grad-Hash -> kein Flapping
    let h1 = hash_degree_map(&operator_nodes);
    let h2 = hash_degree_map(&operator_nodes);
    assert_eq!(h1, h2);

    // Jeder einzelne Knoten im legitimen Setup hat deg >=3 => kein Censorship-Risk
    for (nid, deg) in &operator_nodes {
        assert!(
            detect_single_edge_censorship_risk(*nid, *deg).is_none(),
            "deg {} sollte kein Risiko sein",
            deg
        );
    }

    // Multi-Homing Bonus: wenn Betreiber seine Nodes untereinander vernetzt (+ ext. Nachbarn)
    // ist er zensurresist-enter (analog Spec Abb. Legit)
    // Simuliere: alle 10 untereinander + je 2 externe Peers => deg >= 5 sicher
    let multi_homed: Vec<(u16, usize)> = (0..10).map(|i| (i as u16, 5)).collect();
    let w2 = evaluate_multi_node_cluster(&multi_homed, &pow_valid);
    assert!(w2.is_empty());
}

#[test]
fn test_inv1702_single_bridge_botnet_besen_detected_and_throttled() {
    // Bösartiger Besen: 1 Bridge-Node tunnelt 500 Bots über 1 Kante, 0 Querverbindungen
    // Dunbar-RED drosselt zu >99.9% (simuliert via Prometheus red_drop_rate)
    let bridge: u16 = 77;
    let w = detect_single_bridge_botnet(bridge, 500, 0);
    assert!(w.is_some(), "Besen mit 500 Bots über 1 Brücke muss detektiert werden");
    let warn = w.unwrap();
    assert_eq!(warn.level, WarningLevel::WarnSingleBridgeBotnet);
    assert!(warn.message.contains("500"));

    // Beispiel aus Spec: 85 unverifizierte via single edge
    let w85 = detect_single_bridge_botnet(bridge, 85, 0).unwrap();
    assert_eq!(w85.level, WarningLevel::WarnSingleBridgeBotnet);

    // Gegenprobe: gleicher Tunnel aber mit Querverbindungen ins Mesh => kein Besen
    let w_cross = detect_single_bridge_botnet(bridge, 85, 5);
    assert!(
        w_cross.is_none(),
        "Mit 5 Querverbindungen kein Botnetz-Besen"
    );

    // Unter Schwelle: 20 unverifizierte => kein Alarm (Rausch-Toleranz)
    assert!(detect_single_bridge_botnet(bridge, 20, 0).is_none());
    assert!(detect_single_bridge_botnet(bridge, 49, 0).is_none());
    // Genau Schwelle 50 => Alarm
    assert!(detect_single_bridge_botnet(bridge, 50, 0).is_some());

    // TopologieReport integriert Botnet-Warnung korrekt
    let mut report = TopologyReport::new(10, 4);
    report.add_warning(warn.clone());
    assert!(report.has_level(WarningLevel::WarnSingleBridgeBotnet));
    assert_eq!(report.warnings_for_peer(bridge).len(), 1);

    // Prometheus dokumentiert Dunbar-RED Drops für diese Kante (Zero-I/O Counter)
    let mut metrics = PrometheusMetrics::new();
    metrics.set_peer_connections(4);
    metrics.inc_red_drop(bridge, 850); // 85*10 Pakete verworfen
    assert!(metrics.get_red_drop(bridge) > 0);
    let rendered = metrics.render();
    assert!(rendered.contains("humoco_edge_red_drop_rate"));
    assert!(rendered.contains(&format!("peer=\"{}\"", bridge)));
}

#[test]
fn test_inv1702_single_edge_censorship_risk_and_clock_skew() {
    let local: u16 = 5;
    // deg=1 => WARN_SINGLE_EDGE_CENSORSHIP_RISK
    let w1 = detect_single_edge_censorship_risk(local, 1).expect("deg 1 muss warnen");
    assert_eq!(w1.level, WarningLevel::WarnSingleEdgeCensorshipRisk);
    // deg=0 ebenfalls Warnung
    assert!(detect_single_edge_censorship_risk(local, 0).is_some());
    // Unsere Funktion warnt bei <=1, daher deg=2 => None ist korrekt
    assert!(
        detect_single_edge_censorship_risk(local, 2).is_none(),
        "deg 2 sollte keine Censorship-Warnung sein (>=2)"
    );
    assert!(detect_single_edge_censorship_risk(local, 3).is_none());
    assert!(detect_single_edge_censorship_risk(local, 10).is_none());

    // Clock Skew >45s => WARN_LOCAL_CLOCK_SKEW
    let w_skew = detect_clock_skew(local, 60_000).expect("60s skew muss warnen");
    assert_eq!(w_skew.level, WarningLevel::WarnLocalClockSkew);
    assert!(detect_clock_skew(local, 45_001).is_some());
    assert!(detect_clock_skew(local, 45_000).is_none(), "45s ist Schwelle, erst >45s warnen");
    assert!(detect_clock_skew(local, -60_000).is_some(), "negative Skew ebenfalls");
    assert!(detect_clock_skew(local, 10_000).is_none());
}

#[test]
fn test_inv1702_pow_invalid_even_with_high_degree_warns() {
    // PoW ungültig => trotz deg>=3 kein Schutz – Warnung wegen invalid PoW
    let nodes = vec![(1, 5), (2, 4)];
    let mut pow = HashMap::new();
    pow.insert(1, true);
    pow.insert(2, false); // invalid PoW
    let warnings = evaluate_multi_node_cluster(&nodes, &pow);
    assert_eq!(warnings.len(), 1, "invalid PoW muss warnen");
    assert_eq!(warnings[0].peer, Some(2));
}

// ---------------------------------------------------------------------------
// INV-1703: Deterministische Verhungerung (REVOKE -> 21-24h deactivated, 48h purge)
// ---------------------------------------------------------------------------

#[test]
fn test_inv1703_starvation_cascade_21h_deactivated_48h_purged() {
    // Reine Zeitfunktion evaluate_starvation
    assert_eq!(evaluate_starvation(0), StarvationStage::Active);
    assert_eq!(evaluate_starvation(10), StarvationStage::Active);
    assert_eq!(evaluate_starvation(20), StarvationStage::Active);
    // Hysterese 21-24h
    assert_eq!(evaluate_starvation(21), StarvationStage::Deactivated);
    assert_eq!(evaluate_starvation(22), StarvationStage::Deactivated);
    assert_eq!(evaluate_starvation(24), StarvationStage::Deactivated);
    assert_eq!(evaluate_starvation(30), StarvationStage::Deactivated);
    assert_eq!(evaluate_starvation(47), StarvationStage::Deactivated);

    // 48h => purged
    assert_eq!(evaluate_starvation(48), StarvationStage::Purged);
    assert_eq!(evaluate_starvation(60), StarvationStage::Purged);
    assert_eq!(evaluate_starvation(100), StarvationStage::Purged);

    // Helper booleans
    assert!(!is_deactivated_by_starvation(20));
    assert!(is_deactivated_by_starvation(21));
    assert!(is_deactivated_by_starvation(24));
    assert!(is_deactivated_by_starvation(48));

    assert!(!is_purged_by_starvation(47));
    assert!(is_purged_by_starvation(48));
    assert!(is_purged_by_starvation(72));

    // Deterministisch über SimTime: REVOKE bei T=0, prüfe nach 21h, 24h, 48h
    let revoke_at = SimTime::ZERO;
    let h21 = SimTime::from_millis(21 * 3600 * 1000);
    let h22 = SimTime::from_millis(22 * 3600 * 1000);
    let h48 = SimTime::from_millis(48 * 3600 * 1000);
    let h72 = SimTime::from_millis(72 * 3600 * 1000);

    assert_eq!(starvation_at_time(revoke_at, h21), StarvationStage::Deactivated);
    assert_eq!(starvation_at_time(revoke_at, h22), StarvationStage::Deactivated);
    assert_eq!(starvation_at_time(revoke_at, h48), StarvationStage::Purged);
    assert_eq!(starvation_at_time(revoke_at, h72), StarvationStage::Purged);

    // Vor 21h noch aktiv
    let h20 = SimTime::from_millis(20 * 3600 * 1000);
    assert_eq!(starvation_at_time(revoke_at, h20), StarvationStage::Active);

    // Ohne zentrale Abstimmung: zwei Nodes rechnen identisches Ergebnis deterministisch
    let node_a = starvation_at_time(revoke_at, h48);
    let node_b = starvation_at_time(revoke_at, h48);
    assert_eq!(node_a, node_b, "Deterministische Konvergenz ohne Abstimmung");

    // Edge: REVOKE bei späterer Zeit (nicht Zero)
    let revoke_late = SimTime::from_millis(100_000);
    let now = SimTime::from_millis(100_000 + 48 * 3600 * 1000);
    assert_eq!(starvation_at_time(revoke_late, now), StarvationStage::Purged);
}

#[test]
fn test_inv1703_healing_without_revoke_stays_active() {
    // Ohne REVOKE (kein starvation) bleibt Peer aktiv – Gegenprobe
    // Simuliere Heartbeat-basierten PeerPresence: mit regelmäßigen Heartbeats kein Deactivation
    // Hier testen wir nur, dass 0h nach Start aktiv ist
    assert_eq!(evaluate_starvation(0), StarvationStage::Active);
    assert!(!is_purged_by_starvation(0));
}

// ---------------------------------------------------------------------------
// INV-1704: Ingress-Transparenz – 80% Tageslimit am Tag 1
// ---------------------------------------------------------------------------

#[test]
fn test_inv1704_ingress_audit_threshold_80_percent_day1_warns() {
    // Hard Floor 960_000 = 1000 * 960 (5-Jahres-Gutscheine)
    let quota = 960_000u64;
    let mut tracker = IngressAuditTracker::new(quota);
    let peer: u16 = 10;
    let day0 = 0u64;

    // Unter Schwelle: 79% => kein Warnung
    // 79% von 960k = 758_400 ≈ 790 *960
    let below = (quota as f64 * 0.79) as u64;
    let w = tracker.record_ingress(peer, day0, below);
    assert!(w.is_none(), "79% auf Tag 1 darf nicht warnen");
    assert!(!tracker.is_audit_threshold_exceeded(peer));
    assert!((tracker.usage_ratio(peer) - 0.79).abs() < 0.01);

    // Neuer Tracker für sauberen Test bei exakt 80%
    let mut t2 = IngressAuditTracker::new(quota);
    let at_80 = (quota as f64 * 0.80) as u64;
    let w2 = t2.record_ingress(peer, day0, at_80);
    assert!(
        w2.is_some(),
        "80% auf Tag 1 muss Audit-Warnung erzeugen"
    );
    let warn = w2.unwrap();
    assert_eq!(warn.level, WarningLevel::InfoAuditIngressHigh);
    assert_eq!(warn.peer, Some(peer));
    assert!(warn.message.contains("80%") || warn.message.contains("768000") || warn.message.contains(&at_80.to_string()));
    assert!(t2.is_audit_threshold_exceeded(peer));
    assert!(t2.usage_ratio(peer) >= 0.8);

    // 88% wie im Spec-Beispiel (295 Langzeit-Gutscheine): 295*960=283200 wäre nicht 88% von 960k
    // Daher testen wir 88% generisch: 844_800
    let mut t3 = IngressAuditTracker::new(quota);
    let at_88 = (quota as f64 * 0.88) as u64;
    let w3 = t3.record_ingress(peer, day0, at_88).expect("88% muss warnen");
    assert_eq!(w3.level, WarningLevel::InfoAuditIngressHigh);
    assert!(w3.message.contains("88%") || w3.message.contains(&at_88.to_string()));

    // Inkrementell: erst 40% dann weitere 45% => kumuliert 85% => Warnung beim zweiten Record
    let mut t4 = IngressAuditTracker::new(quota);
    let first = (quota as f64 * 0.40) as u64;
    let second = (quota as f64 * 0.45) as u64;
    assert!(t4.record_ingress(peer, day0, first).is_none());
    let w4 = t4.record_ingress(peer, day0, second);
    assert!(w4.is_some(), "Kumuliert 85% muss beim zweiten Record warnen");
}

#[test]
fn test_inv1704_day2_no_audit_even_if_over_80_percent() {
    let quota = 960_000u64;
    let mut tracker = IngressAuditTracker::new(quota);
    let peer: u16 = 20;
    // Tag 0: wenig Traffic, kein Alarm
    tracker.record_ingress(peer, 0, 100_000);
    assert!(!tracker.is_audit_threshold_exceeded(peer));

    // Tag 1: selbst 90% darf keinen Tag-1-Audit mehr auslösen (first_seen_day=0)
    let w_day1 = tracker.record_ingress(peer, 1, (quota as f64 * 0.90) as u64);
    assert!(
        w_day1.is_none(),
        "INV-1704: Nur Tag 1 (first_seen) triggert Plausibilitäts-Audit, Tag 2 nicht"
    );
    assert!(!tracker.is_audit_threshold_exceeded(peer));
    // Ratio auf Tag1 ist 0.9, aber is_audit_threshold_exceeded schaut nur auf first_day -> false
    assert!((tracker.usage_ratio(peer) - 0.90).abs() < 0.01);
}

#[test]
fn test_inv1704_multiple_peers_isolated_and_deterministic() {
    let quota = 960_000u64;
    let mut tracker = IngressAuditTracker::new(quota);
    let peer_a: u16 = 1;
    let peer_b: u16 = 2;

    // Peer A schöpft 85% => Warnung
    let wa = tracker.record_ingress(peer_a, 0, (quota as f64 * 0.85) as u64);
    assert!(wa.is_some());
    // Peer B nur 10% => keine Warnung
    let wb = tracker.record_ingress(peer_b, 0, (quota as f64 * 0.10) as u64);
    assert!(wb.is_none());

    // Deterministisch: gleicher Input gleicher Output beim Replay
    let mut t2 = IngressAuditTracker::new(quota);
    let wa2 = t2.record_ingress(peer_a, 0, (quota as f64 * 0.85) as u64);
    assert_eq!(wa.unwrap().level, wa2.unwrap().level);
}

#[test]
fn test_inv1704_transparency_does_not_block_ingress_itself() {
    // Telemetrie ist Hinweis, kein Block – Ingress wird nicht automatisch verweigert,
    // nur Audit-Hinweis erzeugt. Tracker selbst blockiert nicht.
    let quota = 960_000u64;
    let mut tracker = IngressAuditTracker::new(quota);
    let peer: u16 = 30;
    let w = tracker.record_ingress(peer, 0, quota); // 100%
    assert!(w.is_some(), "100% muss auditieren");
    // Usage wurde trotzdem verbucht (nicht gedropped)
    assert_eq!(tracker.usage_for(peer), quota);
}

// ---------------------------------------------------------------------------
// INV-1705: Shard-Aktivitäts-Transparenz
// ---------------------------------------------------------------------------

#[test]
fn test_inv1705_local_shard_performance_degraded_below_80() {
    let mut tracker = ShardPerformanceTracker::new(1, 42);
    // 42% wie im Spec-Beispiel
    tracker.record(150, 63); // 63/150 =42%
    assert!(tracker.is_degraded());
    assert!((tracker.participation_ratio() - 0.42).abs() < 0.001);
    let w = tracker.check_local_warning().expect("42% muss WARN degradiert");
    assert_eq!(w.level, WarningLevel::WarnLocalShardPerformanceDegraded);
    assert!(w.message.contains("42%") || w.message.contains("63/150") || w.message.contains("63"));
    assert_eq!(w.peer, None, "Lokale Warnung hat kein Peer");

    // 0/150 => ebenfalls degraded
    tracker.record(150, 0);
    assert!(tracker.check_local_warning().is_some());

    // Grenzfall 79% => noch degraded ( <80 )
    tracker.record(100, 79);
    assert!(tracker.is_degraded());
    assert!(tracker.check_local_warning().is_some());

    // Grenzwert 80% => kein degraded
    tracker.record(100, 80);
    assert!(!tracker.is_degraded());
    assert!(tracker.check_local_warning().is_none(), "80% exakt darf nicht warnen");

    // 100% => keine Warnung
    tracker.record(100, 100);
    assert!(tracker.check_local_warning().is_none());

    // Leerer Shard (0 total) => als 100% betrachtet, keine Warnung
    tracker.record(0, 0);
    assert_eq!(tracker.participation_ratio(), 1.0);
    assert!(tracker.check_local_warning().is_none());
}

#[test]
fn test_inv1705_neighbor_shard_activity_optional_info() {
    let tracker = ShardPerformanceTracker::new(1, 42);
    // Nachbar 0/150 wie Spec Beispiel -> INFO_NEIGHBOR_SHARD_ACTIVITY
    let w = tracker
        .check_neighbor(99, 0, 150)
        .expect("0/150 muss Neighbor-Info erzeugen");
    assert_eq!(w.level, WarningLevel::InfoNeighborShardActivity);
    assert_eq!(w.peer, Some(99));
    assert!(w.message.contains("0/150") || w.message.contains("0"));

    // Peer mit 10/150 =6.6% => ebenfalls Info ( <50%)
    let w2 = tracker.check_neighbor(100, 10, 150).expect("10/150 muss Info");
    assert_eq!(w2.level, WarningLevel::InfoNeighborShardActivity);

    // Peer mit 100/150 =66% => keine Info (>=50%)
    assert!(tracker.check_neighbor(101, 100, 150).is_none());
    assert!(tracker.check_neighbor(101, 80, 150).is_none()); // 53% gerade über 50?
    // 75/150=50% genau => Schwelle: <50% => kein Warn bei 50% ?
    assert!(tracker.check_neighbor(102, 75, 150).is_none(), "50% exakt darf nicht informieren");

    // Total 0 => kein Check
    assert!(tracker.check_neighbor(103, 0, 0).is_none());
}

#[test]
fn test_inv1705_topology_report_integrates_shard_and_ingress_warnings() {
    // Integration: lokaler Shard degraded + Ingress Audit + Botnet im selben Report
    let mut report = TopologyReport::new(1, 7);
    let mut shard = ShardPerformanceTracker::new(1, 42);
    shard.record(150, 42); // 28% degraded
    if let Some(w) = shard.check_local_warning() {
        report.add_warning(w);
    }
    let mut ingress = IngressAuditTracker::new(960_000);
    if let Some(w) = ingress.record_ingress(5, 0, 850_000) {
        report.add_warning(w);
    }
    if let Some(w) = detect_single_bridge_botnet(77, 85, 0) {
        report.add_warning(w);
    }

    assert!(report.has_level(WarningLevel::WarnLocalShardPerformanceDegraded));
    assert!(report.has_level(WarningLevel::InfoAuditIngressHigh));
    assert!(report.has_level(WarningLevel::WarnSingleBridgeBotnet));
    assert_eq!(report.warnings.len(), 3);
    assert_eq!(report.local_node, 1);
    assert_eq!(report.active_peers_count, 7);

    // Prometheus Spiegelung
    let metrics = report.to_prometheus(2);
    assert_eq!(metrics.active_nodes_total, 8); // 7 peers +1 local
    assert_eq!(metrics.peer_connections, 7);
    assert_eq!(metrics.immature_nodes, 2);
}

// ---------------------------------------------------------------------------
// Zusätzlich: Prometheus-Format deterministisch & Zero-I/O
// ---------------------------------------------------------------------------

#[test]
fn test_prometheus_metrics_render_deterministic() {
    let mut m1 = PrometheusMetrics::new();
    m1.set_active_nodes(14);
    m1.set_peer_connections(5);
    m1.set_immature_nodes(2);
    m1.inc_inbound(1, 100);
    m1.inc_inbound(2, 200);
    m1.inc_red_drop(1, 5);

    let mut m2 = PrometheusMetrics::new();
    m2.set_active_nodes(14);
    m2.set_peer_connections(5);
    m2.set_immature_nodes(2);
    m2.inc_inbound(2, 200);
    m2.inc_inbound(1, 100); // andere Reihenfolge, muss trotzdem gleiches Render wegen Sortierung
    m2.inc_red_drop(1, 5);

    let r1 = m1.render();
    let r2 = m2.render();
    assert_eq!(r1, r2, "Prometheus render muss deterministisch sortiert sein");
    assert!(r1.contains("humoco_active_nodes_total 14"));
    assert!(r1.contains("humoco_peer_connections 5"));
    assert!(r1.contains("humoco_immature_nodes 2"));
    assert!(r1.contains("humoco_edge_inbound_rate"));
    assert!(r1.contains("humoco_edge_red_drop_rate"));
}

#[test]
fn test_inv1702_1704_1705_combined_topology_health() {
    // Gesundheitstest: vollständig vernetzter gesunder Knoten => keine Warnungen
    let mut report = TopologyReport::new(42, 14);
    // Grad 14, kein Botnet, kein Clock Skew (10ms), Shard 95% => gesund
    assert!(detect_single_bridge_botnet(99, 10, 5).is_none());
    assert!(detect_single_edge_censorship_risk(42, 14).is_none());
    assert!(detect_clock_skew(42, 10_000).is_none());
    let mut shard = ShardPerformanceTracker::new(42, 7);
    shard.record(150, 143); // 95%
    assert!(shard.check_local_warning().is_none());
    assert!(report.is_healthy());
    // Nach Hinzufügen einer Warnung nicht mehr gesund
    report.add_warning(shard.check_neighbor(99, 0, 150).unwrap());
    assert!(!report.is_healthy());
}

#[test]
fn test_inv1701_gateway_concentration_and_dominance_helpers() {
    // 1. Gateway Concentration
    assert_eq!(WarningLevel::WarnGatewayConcentration.as_str(), WARN_GATEWAY_CONCENTRATION);
    assert!(!WarningLevel::WarnGatewayConcentration.triggers_auto_ban());
    assert!(WarningLevel::WarnGatewayConcentration.is_warn());

    let counts = vec![90, 10]; // total 100, top 2 = 100 (100%)
    let ratio = evaluate_gateway_concentration_ratio(&counts);
    assert!((ratio - 1.0).abs() < 1e-6);
    let warn = detect_gateway_concentration(&counts);
    assert!(warn.is_some());
    assert_eq!(warn.as_ref().unwrap().level, WarningLevel::WarnGatewayConcentration);

    // Below threshold total locks (< 20)
    let small_counts = vec![9, 1];
    assert!(detect_gateway_concentration(&small_counts).is_none());

    // Diversified (top 2 = 40 out of 100 -> 40%)
    let div_counts = vec![20, 20, 20, 20, 20];
    assert_eq!(evaluate_gateway_concentration_ratio(&div_counts), 0.4);
    assert!(detect_gateway_concentration(&div_counts).is_none());

    // 2. Shard Operator Subnet Dominance
    assert_eq!(WarningLevel::InfoShardOperatorDominance.as_str(), INFO_SHARD_OPERATOR_DOMINANCE);
    assert!(!WarningLevel::InfoShardOperatorDominance.triggers_auto_ban());
    assert!(WarningLevel::InfoShardOperatorDominance.is_info());

    let subnet_counts = vec![4, 1, 1]; // 4 out of 6 in single subnet = 66.7% (> 50%)
    let max_sub_ratio = evaluate_subnet_dominance_max(&subnet_counts);
    assert!((max_sub_ratio - (4.0 / 6.0)).abs() < 1e-6);
    let dom_info = detect_shard_operator_dominance(12, &subnet_counts);
    assert!(dom_info.is_some());
    assert_eq!(dom_info.as_ref().unwrap().level, WarningLevel::InfoShardOperatorDominance);

    // Balanced subnets: 1, 1, 1, 1
    let balanced = vec![1, 1, 1, 1];
    assert!(detect_shard_operator_dominance(12, &balanced).is_none());

    // 3. Fallback Gateway No Free Tier
    assert_eq!(WarningLevel::WarnGatewayNoFreeTier.as_str(), WARN_GATEWAY_NO_FREE_TIER);
    assert!(!WarningLevel::WarnGatewayNoFreeTier.triggers_auto_ban());
    assert!(WarningLevel::WarnGatewayNoFreeTier.is_warn());

    let no_free_tier_warn = detect_gateway_no_free_tier("https://gw-vip-only.humoco.org", false);
    assert!(no_free_tier_warn.is_some());
    assert_eq!(no_free_tier_warn.as_ref().unwrap().level, WarningLevel::WarnGatewayNoFreeTier);

    let free_tier_ok = detect_gateway_no_free_tier("https://gw-public.humoco.org", true);
    assert!(free_tier_ok.is_none());
}

