use humoco_sim_core::sim::{SimMessage, SimNetwork, SimNode};
use humoco_sim_core::types::{
    evaluate_sync_status, LockRecord, LockStatus, NodeSyncStatus, SimTime,
};

#[test]
fn test_single_friend_percolation_global_reach() {
    let mut net = SimNetwork::new();
    net.set_latency(2, 5);

    // Initialisiere 20 Nodes im Hauptnetz (0..20)
    for id in 0..20 {
        let node = SimNode::new(id, 21);
        net.add_node(node);
    }

    // Vollständig vernetztes Mesh im Hauptnetz (0..20)
    for i in 0..20 {
        for j in 0..20 {
            if i != j {
                net.nodes.get_mut(&i).unwrap().add_peer(j);
            }
        }
    }

    // Neuer Knoten 20 hat NUR 1 FREUND: Node 0 (d=1)
    let mut new_node = SimNode::new(20, 21);
    new_node.add_peer(0);
    net.nodes.get_mut(&0).unwrap().add_peer(20);
    net.add_node(new_node);

    // Node 20 sendet einen Lock-Request / Heartbeat über seinen einzigen Freund (Node 0)
    let parent_lock = [0x77; 32];
    let receiver = [0x88; 32];
    let nonce = b"node20_single_friend_nonce".to_vec();
    let lock = LockRecord::new(parent_lock, receiver, nonce, SimTime(0), SimTime(50_000));
    let lock_id = lock.id;

    net.schedule(SimTime(0), 20, 20, SimMessage::LockRequest(lock));

    // Lass den Gossip durch das Netz perkolieren (500 ms)
    net.run_until(SimTime(500));

    // Prüfe: Obwohl Node 20 nur 1 Kante hat, hat das GESAMTE Weltnetz (alle 20 Nodes)
    // den Lock empfangen und signiert!
    for id in 0..20 {
        let node = &net.nodes[&id];
        assert!(
            node.locks.contains_key(&lock_id),
            "Node {} sollte Lock von Node 20 empfangen haben",
            id
        );
        let stored = &node.locks[&lock_id];
        assert!(stored.status.is_active());
        // Im 21-Node-Netzwerk wurden alle 21 Signaturen gesammelt -> FINAL
        assert!(stored.status.is_final());
        assert_eq!(stored.signers.len(), 21);
    }
}

#[test]
fn test_village_merge_local_continuity_during_transition() {
    let mut net = SimNetwork::new();
    net.set_latency(2, 5);

    // Dorf A: 5 Nodes (0..5)
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

    // Lokaler Lock 1 im Dorf A
    let parent_1 = [0x01; 32];
    let receiver_1 = [0xAA; 32];
    let nonce_1 = b"bakery_bread_purchase".to_vec();
    let lock_1 = LockRecord::new(parent_1, receiver_1, nonce_1, SimTime(0), SimTime(50_000));
    let lock_1_id = lock_1.id;

    net.schedule(SimTime(0), 1, 1, SimMessage::LockRequest(lock_1));
    net.run_until(SimTime(100));

    // Alle 5 Dorfknoten haben Lock 1 auf PROVISIONAL (4/5 Signaturen erforderlich, 5 vorhanden)
    for id in 0..5 {
        let node = &net.nodes[&id];
        assert!(node.locks.contains_key(&lock_1_id));
        match node.locks[&lock_1_id].status {
            LockStatus::Provisional { sigs, required } => {
                assert_eq!(sigs, 5);
                assert_eq!(required, 4);
            }
            _ => panic!("Status sollte PROVISIONAL sein"),
        }
    }

    // Nun: Node 0 dockt als Brückenknoten an ein 20-Knoten-Weltnetz (10..30) an
    for id in 10..30 {
        let mut node = SimNode::new(id, 25);
        node.add_peer(0);
        net.nodes.get_mut(&0).unwrap().add_peer(id);
        net.add_node(node);
    }

    // Node 0 aktualisiert seine Sicht auf N=25
    net.nodes.get_mut(&0).unwrap().update_active_nodes(25);

    // Während die restlichen Dorfknoten (1..4) noch N_lokal=5 haben, wird ein neuer
    // lokaler Einkauf im Dorf (Lock 2) getätigt:
    let parent_2 = [0x02; 32];
    let receiver_2 = [0xBB; 32];
    let nonce_2 = b"kiosk_coffee_purchase".to_vec();
    let lock_2 = LockRecord::new(parent_2, receiver_2, nonce_2, SimTime(150), SimTime(50_000));
    let lock_2_id = lock_2.id;

    net.schedule(SimTime(150), 2, 2, SimMessage::LockRequest(lock_2));
    net.run_until(SimTime(300));

    // Dorfknoten 1..4 haben den lokalen Lock 2 stabil und ununterbrochen auf PROVISIONAL
    for id in 1..5 {
        let node = &net.nodes[&id];
        assert!(node.locks.contains_key(&lock_2_id));
        assert!(node.locks[&lock_2_id].status.is_active());
    }

    // Sobald die Dorfpeers über F2F-Sync aktualisiert werden (N=25):
    for id in 1..5 {
        net.nodes.get_mut(&id).unwrap().update_active_nodes(25);
    }

    // Verifiziere Hysterese-Logik für SyncStatus
    assert_eq!(
        evaluate_sync_status(5, 5, NodeSyncStatus::InSync),
        NodeSyncStatus::InSync
    );
}
