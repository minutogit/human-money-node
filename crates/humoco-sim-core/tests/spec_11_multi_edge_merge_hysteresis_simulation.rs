//! Spec 11 – [INV-1104 & INV-0305] Asynchrone Hysterese-Kaskade bei realistischen Netz-Merges
//!
//! Multi-Edge Percolation, Slow-Gossip vs. Sync-Status:
//! Zwei autark gewachsene Netz-Cluster A ($N_A = 50$) und B ($N_B = 50$) verbinden sich über
//! $k \ge 5$ simultane Brücken-Kanten (realistisches Multi-Ingress-Szenario).
//!
//! - **[INV-1104] First-Seen Neulings-Pacing**: First-Seen-Knoten werden lokal registriert,
//!   aber nur gedrosselt (1 Neuling pro Pacing-Intervall) an Nachbarn weitergeleitet.
//! - **[INV-0305] Sync-Status & Hysterese**: Jeder Knoten vergleicht $N_{local}$ mit dem Median
//!   der F2F-Nachbarn ($N_{median}$):
//!   - `IN_SYNC`: $N_{local} \ge 95\% \cdot N_{median}$
//!   - `SYNCING`: $N_{local} < 90\% \cdot N_{median}$ (Schutz vor verfrühter globaler Finalität)
//!
//! Phänomen:
//! Durch die Hop-Verzögerung vom Brückenkern zum Rand steigt $N_{median}$ an den Randknoten
//! schneller als ihr eigenes $N_{local}$. Die Randknoten fallen temporär in eine
//! "Syncing-Welle", bis die Neulinge durchgeperkoliert sind und 100 % Konvergenz erreicht wird.

use humoco_sim_core::types::{
    compute_f2f_median, evaluate_sync_status, F2FPresenceReport, FirstSeenPacer, NodeId,
    NodeSyncStatus, SimTime,
};
use std::collections::HashMap;

/// Repräsentiert einen Knoten im diskreten Simulationsnetz
struct SimulationNode {
    id: NodeId,
    /// Hop-Distanz zur nächsten Brückenkante (0 = Brückenknoten)
    _hop_distance: usize,
    /// F2F-Nachbarn im eigenen Cluster
    neighbors: Vec<NodeId>,
    /// FirstSeenPacer für gedrosselten Gossip-Austausch
    pacer: FirstSeenPacer,
    /// Aktueller Synchronisationszustand (Hysterese-behaftet)
    sync_status: NodeSyncStatus,
    /// Lokal bekannte Knotenanzahl
    n_local: usize,
}

impl SimulationNode {
    fn new(id: NodeId, hop_distance: usize, initial_known: &[NodeId], pacing_interval: u64) -> Self {
        Self {
            id,
            _hop_distance: hop_distance,
            neighbors: Vec::new(),
            pacer: FirstSeenPacer::with_known_nodes(initial_known.to_vec(), pacing_interval),
            sync_status: NodeSyncStatus::InSync,
            n_local: initial_known.len(),
        }
    }
}

fn add_bidirectional_edge(nodes: &mut HashMap<NodeId, SimulationNode>, u: NodeId, v: NodeId) {
    if let Some(node_u) = nodes.get_mut(&u) {
        if !node_u.neighbors.contains(&v) {
            node_u.neighbors.push(v);
        }
    }
    if let Some(node_v) = nodes.get_mut(&v) {
        if !node_v.neighbors.contains(&u) {
            node_v.neighbors.push(u);
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: Realistische Multi-Edge Merge Simulation (5 Brücken, Hysterese-Welle & Konvergenz)
// ---------------------------------------------------------------------------

#[test]
fn test_multi_edge_merge_5_bridges_hysteresis_wave_and_convergence() {
    let pacing_interval = 10u64; // 10 Sekunden pro Neulings-Freigabe pro Kante
    let cluster_size = 50usize;

    // Cluster A: Knoten 0..50, Cluster B: Knoten 100..150
    let cluster_a_nodes: Vec<NodeId> = (0..50).collect();
    let cluster_b_nodes: Vec<NodeId> = (100..150).collect();

    // Initialisiere Cluster A mit Topologie-Schichten:
    // - Hop 0 (Brücken-Knoten): 0..5 (k = 5 Brücken zu Cluster B)
    // - Hop 1 (Kern / Multi-Homed): 5..15
    // - Hop 2 (Mittlere Zone): 15..30
    // - Hop 3 (Randknoten / Peripherie): 30..50
    let mut nodes: HashMap<NodeId, SimulationNode> = HashMap::new();

    for &id in &cluster_a_nodes {
        let hop = match id {
            0..=4 => 0,
            5..=14 => 1,
            15..=29 => 2,
            _ => 3,
        };
        let node = SimulationNode::new(id, hop, &cluster_a_nodes, pacing_interval);
        nodes.insert(id, node);
    }

    // Topologie aufbauen:
    // 1. Hop 0 (Bridges) verbindet sich mit mehreren Hop 1 Knoten (Multi-Homed Core)
    for h0 in 0..5 {
        for h1 in 5..15 {
            if (h0 + h1) % 2 == 0 {
                add_bidirectional_edge(&mut nodes, h0, h1);
            }
        }
    }

    // 2. Hop 1 verbindet sich dicht mit Hop 2
    for h1 in 5..15 {
        for h2 in 15..30 {
            if (h1 + h2) % 3 == 0 {
                add_bidirectional_edge(&mut nodes, h1, h2);
            }
        }
    }

    // 3. Hop 2 verbindet sich mit Hop 3 (Rand)
    for h2 in 15..30 {
        let h3 = 30 + (h2 - 15);
        if h3 < 50 {
            add_bidirectional_edge(&mut nodes, h2, h3);
        }
        let h3_second = 30 + ((h2 - 15 + 5) % 20);
        if h3_second < 50 {
            add_bidirectional_edge(&mut nodes, h2, h3_second);
        }
    }

    // 4. Intra-Layer Ränder für F2F-Medianbildung
    for h3 in 30..49 {
        add_bidirectional_edge(&mut nodes, h3, h3 + 1);
    }

    // 1. Vor dem Merge: Alle Knoten in Cluster A haben N_local = 50 und sind stabil IN_SYNC
    for node in nodes.values() {
        assert_eq!(node.sync_status, NodeSyncStatus::InSync);
        assert_eq!(node.n_local, 50);
    }

    // 2. Merge-Ereignis bei t = 0 über k = 5 Brücken:
    // Die 5 Brückenknoten (0..5) teilen sich die 50 Knoten aus Cluster B auf
    for (i, &b_node) in cluster_b_nodes.iter().enumerate() {
        let bridge_id = (i % 5) as NodeId;
        if let Some(bridge_node) = nodes.get_mut(&bridge_id) {
            bridge_node.pacer.handle_incoming_node_gossip(b_node, 0);
            bridge_node.n_local = bridge_node.pacer.known_count();
        }
    }

    // Simuliere diskrete Zeitschritte (Ticks à 10 Sekunden über 200 Ticks = 2000s)
    let mut max_syncing_ratio = 0.0f64;
    let mut observed_syncing_wave = false;

    for tick in 0..200 {
        let current_time = tick * pacing_interval;

        // A. Gossip Weiterleitung: Knoten pollen fällige Neulinge und senden sie an Nachbarn
        let mut forwarded_messages: Vec<(NodeId, NodeId)> = Vec::new(); // (Empfänger, Neuer_Knoten)
        for node in nodes.values_mut() {
            while let Some(new_node_id) = node.pacer.poll_next_ready_forward(current_time) {
                for &neighbor_id in &node.neighbors {
                    forwarded_messages.push((neighbor_id, new_node_id));
                }
            }
        }

        // B. Gossip Ingress an Nachbarn verarbeiten
        for (recipient_id, new_node_id) in forwarded_messages {
            if let Some(recipient) = nodes.get_mut(&recipient_id) {
                recipient.pacer.handle_incoming_node_gossip(new_node_id, current_time);
                recipient.n_local = recipient.pacer.known_count();
            }
        }

        // C. F2F-Median Reporting & Sync-Status Neuberechnung
        let mut new_statuses: HashMap<NodeId, NodeSyncStatus> = HashMap::new();
        for node in nodes.values() {
            let neighbor_reports: Vec<usize> = node
                .neighbors
                .iter()
                .filter_map(|nbr_id| nodes.get(nbr_id).map(|n| n.n_local))
                .collect();

            if !neighbor_reports.is_empty() {
                let n_median = compute_f2f_median(&neighbor_reports);
                let updated_status = evaluate_sync_status(node.n_local, n_median, node.sync_status);
                new_statuses.insert(node.id, updated_status);
            }
        }

        for (id, status) in new_statuses {
            if let Some(node) = nodes.get_mut(&id) {
                node.sync_status = status;
            }
        }

        // D. Messung der Syncing-Welle
        let syncing_count = nodes
            .values()
            .filter(|n| n.sync_status == NodeSyncStatus::Syncing)
            .count();
        let syncing_ratio = syncing_count as f64 / cluster_size as f64;
        if syncing_ratio > max_syncing_ratio {
            max_syncing_ratio = syncing_ratio;
        }

        if syncing_count > 0 {
            observed_syncing_wave = true;
        }
    }

    // --- Verifikationen ---
    // 1. Die Syncing-Welle muss real aufgetreten sein (Knoten fallen temporär auf SYNCING zurück)
    assert!(
        observed_syncing_wave,
        "Während des Merges muss eine Hysterese-Syncing-Welle auftreten!"
    );
    assert!(
        max_syncing_ratio > 0.05,
        "Mindestens 5% des Netzwerks müssen temporär im SYNCING-Zustand gewesen sein (gemessen: {:.1}%)",
        max_syncing_ratio * 100.0
    );

    // 2. Nach vollständiger Perkolation: 100 % Konvergenz zu IN_SYNC
    for node in nodes.values() {
        assert_eq!(
            node.sync_status,
            NodeSyncStatus::InSync,
            "Nach Abschluss der Perkolation muss Knoten {} wieder stabil IN_SYNC sein!",
            node.id
        );
        assert_eq!(
            node.n_local, 100,
            "Alle 100 Knoten (50 aus A + 50 aus B) müssen final bekannt sein!"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: Skalierbarkeit der Brücken-Zahl (k = 1 vs k = 5 vs k = 10)
// ---------------------------------------------------------------------------

#[test]
fn test_bridge_count_scalability_k1_vs_k5_vs_k10() {
    // Vergleiche die Durchsatzrate von Neulings-Freigaben über k parallele Brücken
    let total_newcomers = 100usize;
    let pacing_interval = 60u64; // 60s pro Neuling

    let simulate_bridge_throughput = |k_bridges: usize| -> u64 {
        // Bei k Brücken teilen sich 100 Neulinge auf k Pacer auf
        let mut pacers: Vec<FirstSeenPacer> = (0..k_bridges)
            .map(|_| FirstSeenPacer::new(pacing_interval))
            .collect();

        // Verteile Neulinge gleichmäßig auf die k Brücken-Pacer
        for (i, node_id) in (1000..1000 + total_newcomers).enumerate() {
            let pacer_idx = i % k_bridges;
            pacers[pacer_idx].handle_incoming_node_gossip(node_id as NodeId, 0);
        }

        // Ermittle Zeit bis alle Neulinge freigegeben wurden
        let mut current_time = 0u64;
        let mut released_count = 0usize;

        while released_count < total_newcomers {
            for pacer in &mut pacers {
                if pacer.poll_next_ready_forward(current_time).is_some() {
                    released_count += 1;
                }
            }
            current_time += pacing_interval;
        }
        current_time
    };

    let time_k1 = simulate_bridge_throughput(1);
    let time_k5 = simulate_bridge_throughput(5);
    let time_k10 = simulate_bridge_throughput(10);

    // K10 muss signifikant schneller sein als K5 und K1
    assert!(
        time_k5 < time_k1,
        "k=5 ({}s) muss schneller sein als k=1 ({}s)",
        time_k5,
        time_k1
    );
    assert!(
        time_k10 < time_k5,
        "k=10 ({}s) muss schneller sein als k=5 ({}s)",
        time_k10,
        time_k5
    );

    // Nahezu proportionale Skalierung durch Multi-Ingress:
    // k=5 benötigt ca. 1/5 der Zeit von k=1
    assert_eq!(time_k1, 100 * pacing_interval);
    assert_eq!(time_k5, 20 * pacing_interval);
    assert_eq!(time_k10, 10 * pacing_interval);
}

// ---------------------------------------------------------------------------
// Test 3: Quorum-Safeguard während Syncing-Wave (Schutz vor verfrühter Finalität)
// ---------------------------------------------------------------------------

#[test]
fn test_shard_quorum_safeguard_during_syncing_wave() {
    let n_median = 70usize; // Median der F2F-Freunde
    let mut current_status = NodeSyncStatus::InSync;

    // 1. Initialer Zustand: InSync
    assert_eq!(current_status, NodeSyncStatus::InSync);

    // 2. Randknoten erfährt N_median = 70, hat selbst aber erst N_local = 60
    // 60 < 90% von 70 (63) -> Rückfall auf Syncing
    current_status = evaluate_sync_status(60, n_median, current_status);
    assert_eq!(
        current_status,
        NodeSyncStatus::Syncing,
        "Knoten mit 60/70 (85.7%) muss in den SYNCING-Zustand wechseln (503 Protection)"
    );

    // 3. Im Zustand SYNCING verhält sich der Knoten defensiv:
    // Er lehnt fremde Shard-Finalisierungen mit 503 NodeSyncing ab,
    // um Fehlentscheidungen bei unvollständiger Netz-Sicht zu verhindern.
    let can_finalize_foreign_shard = current_status == NodeSyncStatus::InSync;
    assert!(
        !can_finalize_foreign_shard,
        "Im Zustand SYNCING dürfen keine fremden Shard-Finalisierungen bestätigt werden!"
    );

    // 4. Hysterese-Schutz vor Oszillation:
    // Wenn N_local auf 65 steigt (zwischen 90% = 63 und 95% = 66.5), bleibt der Status SYNCING,
    // bis die 95%-Hürde voll genommen wird (verhindert Flapping).
    current_status = evaluate_sync_status(65, n_median, current_status);
    assert_eq!(
        current_status,
        NodeSyncStatus::Syncing,
        "Hysterese: N_local=65 (92.8%) reicht noch nicht für InSync-Reaktivierung (benötigt 95% = 67)"
    );

    // 5. Erst bei N_local = 68 (>= 95% von 70 = 67) schaltet der Knoten wieder auf InSync
    current_status = evaluate_sync_status(68, n_median, current_status);
    assert_eq!(
        current_status,
        NodeSyncStatus::InSync,
        "Erst ab >= 95% wird der Knoten wieder vollständig InSync geschaltet"
    );
}

// ---------------------------------------------------------------------------
// Test 4: F2F Presence Reports Filterung & Median-Stabilität
// ---------------------------------------------------------------------------

#[test]
fn test_f2f_reports_filtering_during_percolation() {
    let reports = [
        F2FPresenceReport { peer_id: 1, reported_network_size: 50, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 2, reported_network_size: 52, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 3, reported_network_size: 75, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 4, reported_network_size: 90, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 5, reported_network_size: 100, timestamp: SimTime(0) },
    ];

    let raw_sizes: Vec<usize> = reports.iter().map(|r| r.reported_network_size).collect();
    let median = compute_f2f_median(&raw_sizes);

    // Median von [50, 52, 75, 90, 100] ist genau 75
    assert_eq!(median, 75);
}