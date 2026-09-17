use humoco_sim_core::crypto::compute_canonical_hash;
use humoco_sim_core::sim::{SimMessage, SimNetwork, SimNode};
use humoco_sim_core::types::{LockRecord, SimTime};

#[test]
fn test_split_brain_merge_convergence_20_nodes() {
    let mut net = SimNetwork::new();
    net.set_latency(5, 15);

    // Initialisiere 20 Nodes (0..10 in Gruppe A, 10..20 in Gruppe B)
    for id in 0..20 {
        let node = SimNode::new(id, 10); // Während Partition kennt jedes Dorf nur 10 Nodes
        net.add_node(node);
    }

    // Vollständig vernetztes Mesh innerhalb Gruppe A (0..10)
    for i in 0..10 {
        for j in 0..10 {
            if i != j {
                net.nodes.get_mut(&i).unwrap().add_peer(j);
            }
        }
    }

    // Vollständig vernetztes Mesh innerhalb Gruppe B (10..20)
    for i in 10..20 {
        for j in 10..20 {
            if i != j {
                net.nodes.get_mut(&i).unwrap().add_peer(j);
            }
        }
    }

    // Setze Partition: Gruppe A und Gruppe B sind vollständig isoliert
    net.partition(vec![(0..10).collect(), (10..20).collect()]);

    let parent_lock = [0x5A; 32];
    let receiver_a = [0xAA; 32];
    let receiver_b = [0xBB; 32];
    let nonce_a = b"village_a_nonce".to_vec();
    let nonce_b = b"village_b_nonce".to_vec();

    let lock_a = LockRecord::new(
        parent_lock,
        receiver_a,
        nonce_a.clone(),
        SimTime(0),
        SimTime(50_000),
    );
    let lock_b = LockRecord::new(
        parent_lock,
        receiver_b,
        nonce_b.clone(),
        SimTime(0),
        SimTime(50_000),
    );

    let lock_a_id = lock_a.id;
    let lock_b_id = lock_b.id;

    // Gruppe A sperrt Lock A
    net.schedule(SimTime(10), 0, 0, SimMessage::LockRequest(lock_a));

    // Gruppe B sperrt Lock B
    net.schedule(SimTime(10), 10, 10, SimMessage::LockRequest(lock_b));

    // Lass beide Inselnetze autark bis t=500ms laufen
    net.run_until(SimTime(500));

    // Prüfe: Gruppe A hat Lock A auf PROVISIONAL (7/10 Sigs)
    for id in 0..10 {
        let node = &net.nodes[&id];
        assert!(node.locks.contains_key(&lock_a_id));
        assert!(node.locks[&lock_a_id].status.is_active());
        assert!(!node.locks[&lock_a_id].status.is_final());
        assert!(!node.locks.contains_key(&lock_b_id));
    }

    // Prüfe: Gruppe B hat Lock B auf PROVISIONAL (7/10 Sigs)
    for id in 10..20 {
        let node = &net.nodes[&id];
        assert!(node.locks.contains_key(&lock_b_id));
        assert!(node.locks[&lock_b_id].status.is_active());
        assert!(!node.locks[&lock_b_id].status.is_final());
        assert!(!node.locks.contains_key(&lock_a_id));
    }

    // Berechne den mathematisch kanonischen Sieger gemäß H_canon
    let h_a = compute_canonical_hash(&parent_lock, &receiver_a, &nonce_a);
    let h_b = compute_canonical_hash(&parent_lock, &receiver_b, &nonce_b);
    let (expected_winner_id, expected_loser_id) = if h_a < h_b {
        (lock_a_id, lock_b_id)
    } else {
        (lock_b_id, lock_a_id)
    };

    // Jetzt: NETZ-MERGE bei t=500ms
    net.heal_partition();

    // Peering-Brücken zwischen den Dörfern herstellen (z. B. Node 8-9 mit Node 10-11)
    net.nodes.get_mut(&9).unwrap().add_peer(10);
    net.nodes.get_mut(&10).unwrap().add_peer(9);
    net.nodes.get_mut(&8).unwrap().add_peer(11);
    net.nodes.get_mut(&11).unwrap().add_peer(8);

    // Alle Knoten aktualisieren ihre Sicht auf das Gesamtweltnetz (N=20)
    for id in 0..20 {
        net.nodes.get_mut(&id).unwrap().update_active_nodes(20);
    }

    // Smart-Client Trigger: Lockholder senden ihren Lock an einen Peer der Gegenseite
    let stored_a = net.nodes[&9].locks[&lock_a_id].clone();
    let stored_b = net.nodes[&10].locks[&lock_b_id].clone();
    net.schedule(
        SimTime(510),
        9,
        10,
        SimMessage::GossipLock {
            lock: stored_a,
            hops: 0,
        },
    );
    net.schedule(
        SimTime(510),
        10,
        9,
        SimMessage::GossipLock {
            lock: stored_b,
            hops: 0,
        },
    );

    // Lass das vereinte Netzwerk 2000ms simulieren
    net.run_until(SimTime(2500));

    // INVARIANTE: Alle 20 Knoten müssen exakt auf denselben Sieger konvergiert sein!
    for id in 0..20 {
        let node = &net.nodes[&id];

        // Der Sieger-Lock muss vorhanden und FINAL sein (mit >= 14 Signaturen)
        assert!(
            node.locks.contains_key(&expected_winner_id),
            "Node {} does not have the winning lock!",
            id
        );
        let winner_lock = &node.locks[&expected_winner_id];
        assert!(
            winner_lock.status.is_final(),
            "Node {} winning lock is not FINAL: {:?}",
            id,
            winner_lock.status
        );

        // Der Verlierer-Lock muss, falls bekannt, als VOID markiert sein
        if let Some(loser_lock) = node.locks.get(&expected_loser_id) {
            assert!(
                loser_lock.status.is_void(),
                "Node {} loser lock is not VOID: {:?}",
                id,
                loser_lock.status
            );
        }

        // Der parent_to_lock Index muss überall auf den Sieger zeigen
        assert_eq!(
            node.parent_to_lock.get(&parent_lock),
            Some(&expected_winner_id),
            "Node {} parent index does not point to winner!",
            id
        );
    }
}
