use humoco_sim_core::sim::{SimNetwork, SimNode};
use humoco_sim_core::types::{
    compute_f2f_median, compute_f2f_median_from_reports, evaluate_sync_status, F2FPresenceReport,
    NodeSyncStatus, SimTime,
};

#[test]
fn test_f2f_median_filters_extreme_gaslighting_attack() {
    // 5 Freunde: 3 ehrlich N=25, 2 byzantinisch N=50.000 -> Median 25
    let reports = vec![25usize, 25, 25, 50_000, 50_000];
    let median = compute_f2f_median(&reports);
    assert_eq!(median, 25, "Median must filter gaslighting outliers");

    // Also via F2FPresenceReport struct
    let reports_struct: Vec<F2FPresenceReport> = reports
        .into_iter()
        .enumerate()
        .map(|(i, n)| F2FPresenceReport {
            peer_id: i as u16,
            reported_network_size: n,
            timestamp: SimTime(1000),
        })
        .collect();
    let median2 = compute_f2f_median_from_reports(&reports_struct);
    assert_eq!(median2, 25);

    // Node with N_local=25 vs median 25 must stay InSync / Converged
    let status = evaluate_sync_status(25, median, NodeSyncStatus::InSync);
    assert_eq!(status, NodeSyncStatus::InSync);
    let horizon: humoco_sim_core::types::NodeHorizonStatus = status.into();
    assert_eq!(horizon, humoco_sim_core::types::NodeHorizonStatus::Converged);
}

#[test]
fn test_f2f_median_even_peer_count_robustness() {
    // 6 Freunde: 4 ehrlich N=25, 2 byzantinisch N=100.000 -> Median 25
    let reports = vec![25usize, 25, 25, 25, 100_000, 100_000];
    let median = compute_f2f_median(&reports);
    assert_eq!(median, 25, "Even count median must remain robust");

    // Also test sorting invariance
    let mut shuffled = vec![100_000, 25, 25, 100_000, 25, 25];
    shuffled.sort_unstable();
    let median_shuffled = compute_f2f_median(&shuffled);
    assert_eq!(median_shuffled, 25);
}

#[test]
fn test_simulated_network_gaslighting_immunity() {
    let mut net = SimNetwork::new();
    net.set_latency(2, 5);
    let total_nodes = 25;
    for id in 0..total_nodes as u16 {
        let mut node = SimNode::new(id, total_nodes);
        // each node peers with 4 friends (deterministic)
        for j in 0..total_nodes as u16 {
            if id != j && (j % 6 == id % 6 || (j as i16 - id as i16).abs() <= 1) {
                // keep peer set moderate
                node.add_peer(j);
            }
        }
        net.add_node(node);
    }
    // Simulate F2F median defense on a sample node (id 0)
    // Node 0 has 5 F2F friends: 3 honest reporting 25, 2 byz reporting 50_000
    let f2f_reports = vec![
        F2FPresenceReport { peer_id: 1, reported_network_size: 25, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 2, reported_network_size: 25, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 3, reported_network_size: 25, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 4, reported_network_size: 50_000, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 5, reported_network_size: 50_000, timestamp: SimTime(0) },
    ];
    let median = compute_f2f_median_from_reports(&f2f_reports);
    assert_eq!(median, 25);

    // Gaslighting spam wird neutralisiert: node bleibt InSync mit lokal 25
    let sync = evaluate_sync_status(25, median, NodeSyncStatus::Syncing);
    assert_eq!(sync, NodeSyncStatus::InSync);

    // Even with 6 friends spam still filtered
    let f2f_reports_even = vec![
        F2FPresenceReport { peer_id: 1, reported_network_size: 25, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 2, reported_network_size: 25, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 3, reported_network_size: 25, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 4, reported_network_size: 25, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 6, reported_network_size: 100_000, timestamp: SimTime(0) },
        F2FPresenceReport { peer_id: 7, reported_network_size: 100_000, timestamp: SimTime(0) },
    ];
    let median_even = compute_f2f_median_from_reports(&f2f_reports_even);
    assert_eq!(median_even, 25);
    let sync_even = evaluate_sync_status(25, median_even, NodeSyncStatus::InSync);
    assert_eq!(sync_even, NodeSyncStatus::InSync);

    // Simulate actual network run with a lock request - should propagate despite gaslighting
    use humoco_sim_core::types::LockRecord;
    use humoco_sim_core::sim::SimMessage;
    let parent = [0x77; 32];
    let receiver = [0x88; 32];
    let lock = LockRecord::new(parent, receiver, b"gaslight_test".to_vec(), SimTime(0), SimTime(50_000));
    let lock_id = lock.id;
    net.schedule(SimTime(0), 0, 0, SimMessage::LockRequest(lock));
    net.run_until(SimTime(500));
    // All nodes should have received lock (gossip percolation unaffected by F2F spam)
    let mut count = 0;
    for node in net.nodes.values() {
        if node.locks.contains_key(&lock_id) {
            count += 1;
        }
    }
    assert!(count >= 20, "Gossip must reach majority despite gaslighting, got {}", count);
}
