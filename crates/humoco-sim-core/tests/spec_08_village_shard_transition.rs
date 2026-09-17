use humoco_sim_core::sim::{SimMessage, SimNetwork, SimNode};
use humoco_sim_core::types::{
    required_quorum, LockRecord, LockStatus, SimTime,
};

#[test]
fn test_village_to_global_merge_lazy_upgrade_and_shard_shift() {
    let mut net = SimNetwork::new();
    net.set_latency(2, 5);

    // =========================================================================
    // Phase 1: Dorf A (5 Nodes: 0..5) operiert autonom (N=5)
    // =========================================================================
    for id in 0..5 {
        let node = SimNode::new(id, 5);
        net.add_node(node);
    }
    for i in 0..5 {
        for j in 0..5 {
            if i != j {
                net.nodes.get_mut(&i).unwrap().add_peer(j);
            }
        }
    }

    // Ein Dorfbewohner erzeugt Lock 1 im autarken Dorf
    let parent_1 = [0x55; 32];
    let receiver_1 = [0xAA; 32];
    let nonce_1 = b"village_local_payment".to_vec();
    let lock_1 = LockRecord::new(parent_1, receiver_1, nonce_1, SimTime(0), SimTime(50_000));
    let lock_1_id = lock_1.id;

    net.schedule(SimTime(0), 1, 1, SimMessage::LockRequest(lock_1.clone()));
    net.run_until(SimTime(100));

    // Verifiziere: Alle 5 Dorfknoten haben Lock 1 auf PROVISIONAL (Q = 4/5)
    for id in 0..5 {
        let node = &net.nodes[&id];
        assert!(node.locks.contains_key(&lock_1_id));
        let (req, is_final) = required_quorum(node.total_network_nodes);
        assert!(!is_final);
        assert_eq!(req, 4);
        assert_eq!(node.locks[&lock_1_id].signers.len(), 5);
        assert!(matches!(
            node.locks[&lock_1_id].status,
            LockStatus::Provisional { sigs: 5, required: 4 }
        ));
    }

    // =========================================================================
    // Phase 2: Dorf A dockt an das Weltnetz (20 Nodes: 10..30) an
    // =========================================================================
    for id in 10..30 {
        let node = SimNode::new(id, 25);
        net.add_node(node);
    }
    // Weltnetz untereinander voll vernetzen
    for i in 10..30 {
        for j in 10..30 {
            if i != j {
                net.nodes.get_mut(&i).unwrap().add_peer(j);
            }
        }
    }

    // Peering-Brücke: Node 0 verbindet sich mit Welt-Node 10
    net.nodes.get_mut(&0).unwrap().add_peer(10);
    net.nodes.get_mut(&10).unwrap().add_peer(0);

    // Node 0 lernt Weltnetz -> Sicht wechselt auf N=25
    net.nodes.get_mut(&0).unwrap().update_active_nodes(25);

    // =========================================================================
    // Phase 3: Lokale Dorfkontinuität vor weltweitem Sync
    // =========================================================================
    // Während Dorfknoten 1..5 noch auf N=5 stehen, können sie den bestehenden Zustand
    // weiterhin für lokale Validierungen nutzen:
    for id in 1..5 {
        let node = &net.nodes[&id];
        assert_eq!(node.total_network_nodes, 5);
        assert!(node.locks[&lock_1_id].status.is_active());
    }

    // =========================================================================
    // Phase 4: F2F-Propagation im Dorf (N=25) & Lazy Upgrade am Welt-Quorum
    // =========================================================================
    // Alle Dorfknoten lernen das Weltnetz kennen (N=25)
    for id in 1..5 {
        net.nodes.get_mut(&id).unwrap().update_active_nodes(25);
    }

    // Client initiiert Lazy Upgrade: Er reicht Lock 1 bei den neuen Weltnetz-Nodes ein
    net.schedule(SimTime(200), 10, 10, SimMessage::LockRequest(lock_1));
    net.run_until(SimTime(600));

    // Verifiziere: Das weltweite 25-Knoten-Netzwerk hat den Lock übernommen und auf FINAL gehoben!
    for id in 10..30 {
        let node = &net.nodes[&id];
        assert!(node.locks.contains_key(&lock_1_id));
        assert!(node.locks[&lock_1_id].status.is_final());
        assert!(node.locks[&lock_1_id].signers.len() >= 14);
    }
}
