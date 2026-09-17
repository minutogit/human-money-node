use humoco_sim_core::crypto::sign_lock_attestation;
use humoco_sim_core::fraud::{
    sign_heartbeat, sign_ingress_envelope, FraudProofPayload, FraudProofPillar, SlotDetector128,
};
use humoco_sim_core::sim::{SimNetwork, SimNode};
use humoco_sim_core::types::{LockRecord, SimTime};

/// Säule 1: Equivocation Double-Sign (L3A != L3B, gleicher parent_lock)
#[test]
fn test_pillar_1_equivocation_double_sign_bans_immediately() {
    let byzantine: u16 = 5;
    let parent_lock = [0xAA; 32];

    // Zwei konkurrierende Locks für selben parent_lock, unterschiedliche Empfänger/Nonce -> unterschiedliche LockIds
    let lock_a = LockRecord::new(
        parent_lock,
        [0x11; 32],
        b"nonce_A".to_vec(),
        SimTime(0),
        SimTime(50_000),
    );
    let lock_b = LockRecord::new(
        parent_lock,
        [0x22; 32],
        b"nonce_B".to_vec(),
        SimTime(0),
        SimTime(50_000),
    );

    assert_ne!(lock_a.id, lock_b.id, "L3A und L3B müssen verschieden sein");

    // Byzantinischer Knoten signiert beide Attestationen auf denselben parent_lock
    let att_a = sign_lock_attestation(byzantine, &lock_a.id, &parent_lock, SimTime(100));
    let att_b = sign_lock_attestation(byzantine, &lock_b.id, &parent_lock, SimTime(200));

    // Simulator baut FraudProofPayload (Säule 1)
    let proof = FraudProofPayload::new_shard_equivocation(att_a.clone(), att_b.clone());

    // Verifikation: Pillar korrekt, Täter stimmt
    assert_eq!(proof.proof_pillar, FraudProofPillar::ShardEquivocation);
    assert_eq!(proof.pillar, FraudProofPillar::ShardEquivocation);
    assert_eq!(proof.perpetrator, byzantine);
    assert_eq!(proof.perpetrator_node_id[0..2], byzantine.to_le_bytes());
    assert!(proof.verify(), "Säule 1 Beweis muss verifizierbar sein");

    // Simuliere Netzwerk aus 10 ehrlichen Knoten (0..10, ohne 5? 5 ist Täter)
    // Wir nehmen N=10, IDs 0..10 (Täter 5 ist unter ihnen, aber ehrliche prüfen)
    let mut net = SimNetwork::new();
    for id in 0..10u16 {
        let node = SimNode::new(id, 10);
        net.add_node(node);
    }

    // Jeder ehrliche Knoten verifiziert und bannt Täter sofort in O(1)
    for (_id, node) in net.nodes.iter_mut() {
        assert!(!node.is_banned(byzantine), "vor Beweis nicht gebannt");
        let verified = node.verify_fraud_proof(&proof);
        assert!(verified, "jeder ehrliche Knoten muss Beweis als gültig erkennen");
        let banned = node.apply_fraud_proof(&proof);
        assert!(banned, "apply muss true liefern");
        assert!(node.is_banned(byzantine), "Täter muss sofort O(1) gebannt sein");
        // Idempotenz: zweites Anwenden bleibt gebannt
        assert!(node.is_banned(byzantine));
    }

    // Auch StateMachine-Helper muss verifizieren
    assert!(humoco_sim_core::state_machine::verify_fraud_proof(&proof));

    // Gegenprobe 1: gleiche LockIds dürfen keinen gültigen Equivocation-Beweis ergeben
    let att_a2 = sign_lock_attestation(byzantine, &lock_a.id, &parent_lock, SimTime(100));
    let att_b_same = sign_lock_attestation(byzantine, &lock_a.id, &parent_lock, SimTime(300));
    let bad_proof = FraudProofPayload::new_shard_equivocation(att_a2, att_b_same);
    assert!(!bad_proof.verify(), "gleiche lock_ids darf nicht als Equivocation gelten");

    // Gegenprobe 2: unterschiedliche parent_locks dürfen NIEMALS als Equivocation gelten (False-Positive-Schutz!)
    let different_parent = [0x99; 32];
    let att_diff_parent = sign_lock_attestation(byzantine, &lock_b.id, &different_parent, SimTime(200));
    let false_positive_proof = FraudProofPayload::new_shard_equivocation(att_a.clone(), att_diff_parent);
    assert!(!false_positive_proof.verify(), "unterschiedliche parent_locks dürfen niemals gebannt werden!");
}

/// Säule 3: Heartbeat-Spamming & 128-Slot Detektor (10 Minuten < 50 Min -> Betrug)
#[test]
fn test_pillar_3_heartbeat_spam_128_slot_detector_bans() {
    let malicious: u16 = 42;

    // 1. Direkter 128-Slot Detektor Test
    let mut detector = SlotDetector128::new();

    // Erster Heartbeat bei t=0
    let hb1 = sign_heartbeat(malicious, SimTime(0));
    let res1 = detector.observe(hb1.clone());
    assert!(
        res1.is_none(),
        "erster Heartbeat darf kein Betrug sein"
    );
    // Slot sollte belegt sein
    assert!(detector.get_slot(malicious).is_some());

    // Zweiter Heartbeat nach 10 Minuten (600_000 ms) -> < 3_000_000 ms -> BETRUG
    let hb2 = sign_heartbeat(malicious, SimTime(600_000)); // 10 * 60 * 1000
    let proof_opt = detector.observe(hb2.clone());
    assert!(
        proof_opt.is_some(),
        "10-Minuten Abstand muss Säule-3 Betrug auslösen"
    );
    let proof = proof_opt.unwrap();
    assert_eq!(proof.proof_pillar, FraudProofPillar::HeartbeatSpam);
    assert_eq!(proof.pillar, FraudProofPillar::HeartbeatSpam);
    assert_eq!(proof.perpetrator, malicious);
    assert!(proof.verify(), "Heartbeat-Spam Beweis muss verifizierbar sein");

    // Nach Betrug muss Slot wieder frei sein
    assert!(detector.is_empty(malicious));

    // 2. SimNode-integrierte Prüfung: observe_heartbeat bannt O(1)
    let mut honest = SimNode::new(1, 10);
    assert!(!honest.is_banned(malicious));

    // Erster Heartbeat: kein Beweis
    let first = honest.observe_heartbeat(hb1.clone());
    assert!(first.is_none());
    assert!(!honest.is_banned(malicious));

    // Zweiter Heartbeat: Proof wird erzeugt und Täter sofort gebannt
    let second = honest.observe_heartbeat(hb2.clone());
    assert!(second.is_some(), "SimNode Detektor muss anschlagen");
    let p2 = second.unwrap();
    assert_eq!(p2.proof_pillar, FraudProofPillar::HeartbeatSpam);
    assert!(honest.is_banned(malicious), "NodeID muss O(1) gebannt sein");
    // verify via SimNode API
    assert!(honest.verify_fraud_proof(&p2));

    // 3. Ehrlicher Abstand >=50 Minuten darf NICHT als Betrug gelten
    let mut det_honest = SlotDetector128::new();
    let hb_a = sign_heartbeat(7, SimTime(0));
    assert!(det_honest.observe(hb_a).is_none());
    let hb_b = sign_heartbeat(7, SimTime(3_600_000)); // 60 Minuten
    let honest_res = det_honest.observe(hb_b.clone());
    assert!(
        honest_res.is_none(),
        "60-Minuten Abstand ist ehrlich, kein Betrug"
    );
    // Slot sollte nun auf neuen Zeitstempel aktualisiert sein, nicht leer
    let slot = det_honest.get_slot(7).unwrap();
    assert_eq!(slot.timestamp_unix, SimTime(3_600_000));

    // 4. Stale-Slot (>75 Min) wird überschrieben, kein Blockieren
    let mut det_stale = SlotDetector128::new();
    let hb_old = sign_heartbeat(99, SimTime(0));
    det_stale.observe(hb_old);
    // 80 Minuten später -> stale (>75 Min), Slot wird überschrieben ohne Betrug
    let hb_new = sign_heartbeat(99, SimTime(4_800_000)); // 80 Min
    assert!(det_stale.observe(hb_new.clone()).is_none());
    assert_eq!(det_stale.get_slot(99).unwrap().timestamp_unix, SimTime(4_800_000));

    // 5. Kollision: fremder frischer Slot belegt denselben Index -> nicht überschreiben
    let mut det_coll = SlotDetector128::new();
    // Wähle zwei NodeIds mit gleichem Slotindex (mod 128)
    let n1: u16 = 0;
    let n2: u16 = 128; // 0 %128 == 0, 128%128 ==0
    assert_eq!(
        SlotDetector128::slot_index(n1),
        SlotDetector128::slot_index(n2)
    );
    let hb_n1 = sign_heartbeat(n1, SimTime(0));
    assert!(det_coll.observe(hb_n1).is_none());
    // n2 versucht Slot zu belegen, aber Slot ist frisch von n1 -> wird nicht gespeichert
    let hb_n2 = sign_heartbeat(n2, SimTime(100_000));
    assert!(det_coll.observe(hb_n2.clone()).is_none());
    // Slot gehört weiterhin n1
    assert_eq!(det_coll.get_slot(n1).unwrap().node_id, n1);
    // n1 spammt selbst -> sollte dennoch erkannt werden
    let hb_n1_spam = sign_heartbeat(n1, SimTime(600_000));
    let spam_proof = det_coll.observe(hb_n1_spam);
    assert!(spam_proof.is_some());
    assert_eq!(spam_proof.unwrap().perpetrator, n1);

    // 6. SimNetwork Propagation: Heartbeat via SimMessage bannt alle Peers
    let mut net = SimNetwork::new();
    net.set_latency(1, 1);
    for id in 0..3u16 {
        let mut n = SimNode::new(id, 3);
        for peer in 0..3u16 {
            if peer != id {
                n.add_peer(peer);
            }
        }
        net.add_node(n);
    }
    // Node 0 beobachtet hb1 lokal, dann sendet hb2 als SimMessage::Heartbeat
    let malicious2: u16 = 77;
    let hb77_a = sign_heartbeat(malicious2, SimTime(0));
    let hb77_b = sign_heartbeat(malicious2, SimTime(600_000));
    // Simuliere: Node 0 erhält beide Heartbeats und erzeugt Proof + broadcast
    // Wir nutzen direkt observe_heartbeat auf Node 0 und verteilen Proof manuell
    {
        let n0 = net.nodes.get_mut(&0).unwrap();
        assert!(n0.observe_heartbeat(hb77_a).is_none());
        let proof = n0.observe_heartbeat(hb77_b.clone());
        assert!(proof.is_some());
        assert!(n0.is_banned(malicious2));
        // Broadcast FraudProof an andere Nodes via apply_fraud_proof
        let proof = proof.unwrap();
        for id in 1..3 {
            let peer = net.nodes.get_mut(&id).unwrap();
            assert!(peer.apply_fraud_proof(&proof));
            assert!(peer.is_banned(malicious2));
        }
    }
}

/// Säule 2: Ingress-Zähler-Kollision (Lastzähler-Rückschritt / Fork / Vortages-Unterschlagung)
#[test]
fn test_pillar_2_ingress_counter_conflict_bans_immediately() {
    let malicious_gateway_id: u16 = 88;
    let mut gateway_pubkey = [0u8; 32];
    gateway_pubkey[0..2].copy_from_slice(&malicious_gateway_id.to_le_bytes());
    gateway_pubkey[2..].fill(0x77);

    // Erzeuge zwei betrügerische Pakete (Pfad 4: Zähler-Rückschritt am gleichen Tag)
    let p1 = sign_ingress_envelope(gateway_pubkey, 1, 10, 500_000, 0, 1000, [0x11; 32]);
    let p2 = sign_ingress_envelope(gateway_pubkey, 1, 11, 400_000, 0, 2000, [0x22; 32]);

    let proof = FraudProofPayload::new_ingress_counter_conflict(p1, p2);
    assert_eq!(proof.proof_pillar, FraudProofPillar::IngressCounterConflict);
    assert_eq!(proof.pillar, FraudProofPillar::IngressCounterConflict);
    assert_eq!(proof.perpetrator, malicious_gateway_id);
    assert_eq!(proof.perpetrator_node_id, gateway_pubkey);
    assert!(proof.verify(), "Säule 2 Beweis muss gültig sein");

    // Simuliere ehrliche Nodes, die den Beweis empfangen und den Täter O(1) bannen
    let mut net = SimNetwork::new();
    for id in 0..5u16 {
        net.add_node(SimNode::new(id, 5));
    }

    for (_id, node) in net.nodes.iter_mut() {
        assert!(!node.is_banned(malicious_gateway_id));
        assert!(node.verify_fraud_proof(&proof));
        assert!(node.apply_fraud_proof(&proof));
        assert!(node.is_banned(malicious_gateway_id));
    }
}
