use humoco_sim_core::crypto::sign_lock_attestation;
use humoco_sim_core::fraud::{FraudProofPayload, FraudProofPillar};
use humoco_sim_core::types::SimTime;

/// Säule 1: Equivocation Double-Sign (L3A != L3B, gleicher parent_lock)
#[test]
fn test_pillar_1_equivocation_double_sign_bans_immediately() {
    let byzantine: u16 = 5;
    let parent_lock = [0xAA; 32];

    let lock_id_a = [0x11; 32];
    let lock_id_b = [0x22; 32];

    assert_ne!(lock_id_a, lock_id_b, "L3A und L3B müssen verschieden sein");

    // Byzantinischer Knoten signiert beide Attestationen auf denselben parent_lock
    let att_a = sign_lock_attestation(byzantine, &lock_id_a, &parent_lock, SimTime(100));
    let att_b = sign_lock_attestation(byzantine, &lock_id_b, &parent_lock, SimTime(200));

    // Simulator baut FraudProofPayload (Säule 1)
    let proof = FraudProofPayload::new_shard_equivocation(att_a.clone(), att_b.clone());

    // Verifikation: Pillar korrekt, Täter stimmt
    assert_eq!(proof.proof_pillar, FraudProofPillar::ShardEquivocation);
    assert_eq!(proof.perpetrator_node_id[0..2], byzantine.to_le_bytes());
    assert!(proof.verify(), "Säule 1 Beweis muss verifizierbar sein");

    // Gegenprobe 1: gleiche LockIds dürfen keinen gültigen Equivocation-Beweis ergeben
    let att_a2 = sign_lock_attestation(byzantine, &lock_id_a, &parent_lock, SimTime(100));
    let att_b_same = sign_lock_attestation(byzantine, &lock_id_a, &parent_lock, SimTime(300));
    let bad_proof = FraudProofPayload::new_shard_equivocation(att_a2, att_b_same);
    assert!(
        !bad_proof.verify(),
        "gleiche lock_ids darf nicht als Equivocation gelten"
    );

    // Gegenprobe 2: unterschiedliche parent_locks dürfen NIEMALS als Equivocation gelten (False-Positive-Schutz!)
    let different_parent = [0x99; 32];
    let att_diff_parent =
        sign_lock_attestation(byzantine, &lock_id_b, &different_parent, SimTime(200));
    let false_positive_proof =
        FraudProofPayload::new_shard_equivocation(att_a, att_diff_parent);
    assert!(
        !false_positive_proof.verify(),
        "unterschiedliche parent_locks dürfen niemals gebannt werden!"
    );
}

/// Säule 2: Ingress-Zähler-Kollision (Lastzähler-Rückschritt / Fork / Vortages-Unterschlagung)
#[test]
fn test_pillar_2_ingress_counter_conflict_bans_immediately() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let gateway_pubkey = signing_key.verifying_key().to_bytes();

    // Erzeuge zwei betrügerische Pakete (Pfad 4: Zähler-Rückschritt am gleichen Tag)
    let p1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        &signing_key,
        1,
        10,
        1000,
        500_000,
        0,
        100_000,
        false,
        [0x11; 32],
    );
    let p2 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        &signing_key,
        1,
        11,
        2000,
        400_000,
        0,
        100_000,
        false,
        [0x22; 32],
    );

    let proof = FraudProofPayload::new_ingress_counter_conflict(p1, p2);
    assert_eq!(proof.proof_pillar, FraudProofPillar::IngressCounterConflict);
    assert_eq!(proof.perpetrator_node_id, gateway_pubkey);
    assert!(proof.verify(), "Säule 2 Beweis muss gültig sein");
}

/// A08: Successor Shard Equivocation Evidence verifies when signed shard differs from parent bytes
#[test]
fn test_pillar_1_successor_equivocation_with_different_parent_shard_id() {
    use ed25519_dalek::Signer;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x88; 32]);
    let offender_pubkey = signing_key.verifying_key().to_bytes();
    let offender_node_id = FraudProofPayload::node_id_from_pubkey(&offender_pubkey);

    // Parent lock is a double-spend tag whose first bytes (e.g. 0xFE, 0xED) DO NOT match shard 42
    let parent_lock = [0xFE; 32];
    assert_ne!(humoco_sim_core::types::extract_shard_id(&parent_lock), 42);

    let lock_a = [0x11; 32];
    let lock_b = [0x22; 32];
    let canonical_shard_id: u16 = 42;

    let sign_successor_att = |lock_id: [u8; 32]| -> humoco_sim_core::types::Attestation {
        let payload_digest =
            humoco_sim_core::crypto::compute_attestation_payload_digest(&parent_lock, &lock_id);
        let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
            humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
            0,
            0,
            0,
            canonical_shard_id,
            1,
            &payload_digest,
        );
        let sig = signing_key.sign(&sig_digest).to_bytes();
        humoco_sim_core::types::Attestation {
            lock_id,
            parent_lock,
            node_id: offender_node_id,
            timestamp: SimTime(100),
            signature: sig,
            shard_id: canonical_shard_id,
        }
    };

    let att_a = sign_successor_att(lock_a);
    let att_b = sign_successor_att(lock_b);

    let proof =
        FraudProofPayload::new_shard_equivocation_with_pubkey(att_a, att_b, offender_pubkey);
    assert_eq!(proof.proof_pillar, FraudProofPillar::ShardEquivocation);
    assert_eq!(proof.perpetrator_node_id, offender_pubkey);
    assert!(proof.verify(), "A08: Successor equivocation proof must verify even when parent bytes differ from signed shard!");
}

/// A07: V2 Ingress Envelope Sequence Fork Detection
#[test]
fn test_pillar_2_v2_envelope_sequence_fork_conflict_bans_immediately() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x66; 32]);
    let gateway_pubkey = signing_key.verifying_key().to_bytes();

    let epoch_day = 12;
    let epoch_seq = 100;
    let ts = 1_000_000;
    let write_ema = 50_000;
    let read_ema = 10_000;
    let footprint = 5_000;

    // Two divergent write envelopes with IDENTICAL epoch_day and epoch_seq but DIFFERENT op_hash
    let op_a = [0xAA; 32];
    let op_b = [0xBB; 32];

    let p1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        &signing_key,
        epoch_day,
        epoch_seq,
        ts,
        write_ema,
        read_ema,
        footprint,
        false,
        op_a,
    );
    let p2 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        &signing_key,
        epoch_day,
        epoch_seq,
        ts + 10,
        write_ema,
        read_ema,
        footprint,
        false,
        op_b,
    );

    let proof = FraudProofPayload::new_ingress_counter_conflict(p1, p2);
    assert_eq!(proof.proof_pillar, FraudProofPillar::IngressCounterConflict);
    assert_eq!(proof.perpetrator_node_id, gateway_pubkey);
    assert!(
        proof.verify(),
        "A07: V2 envelope sequence fork must be detected as fraud!"
    );
}

/// S07-02: Sequenced V2 accounting under-reporting symmetry and honest progression
#[test]
fn test_s07_02_v2_sequenced_under_reporting_symmetry_and_honest_progression() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
    let gateway_pubkey = signing_key.verifying_key().to_bytes();

    let epoch_day = 1;
    let ts1 = 1_000_000;
    let write_ema_1 = 50_000;
    let read_ema_1 = 0;
    let footprint_1 = 1_000;

    // Packet 1: seq = 1
    let p1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        &signing_key,
        epoch_day,
        1,
        ts1,
        write_ema_1,
        read_ema_1,
        footprint_1,
        false,
        [0x11; 32],
    );

    // Packet 2: seq = 2, 10 seconds later.
    // Under-reporting malicious packet declares write_ema = 10_000 (< decayed(50_000, 10) + footprint).
    let ts2 = ts1 + 10_000;
    let fraudulent_write_ema = 10_000;
    let p2_under_report = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        &signing_key,
        epoch_day,
        2,
        ts2,
        fraudulent_write_ema,
        read_ema_1,
        footprint_1,
        false,
        [0x22; 32],
    );

    // Both orders (p1, p2) and (p2, p1) must detect under-reporting fraud
    let proof_ab = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_under_report.clone());
    assert_eq!(proof_ab.perpetrator_node_id, gateway_pubkey);
    assert!(proof_ab.verify(), "V2 under-reporting in (a, b) must verify as fraud");

    let proof_ba = FraudProofPayload::new_ingress_counter_conflict(p2_under_report, p1.clone());
    assert_eq!(proof_ba.perpetrator_node_id, gateway_pubkey);
    assert!(proof_ba.verify(), "V2 under-reporting in (b, a) must verify as fraud");

    // Honest progression: seq = 2 with declared_write_ema = write_ema_1 + footprint_1
    let honest_write_ema = humoco_sim_core::quota::decay_integer_ema(write_ema_1, 10) + footprint_1;
    let p2_honest = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        &signing_key,
        epoch_day,
        2,
        ts2,
        honest_write_ema,
        read_ema_1,
        footprint_1,
        false,
        [0x22; 32],
    );

    let honest_proof_ab = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_honest.clone());
    assert!(!honest_proof_ab.verify(), "Honest V2 progression in (a, b) must not be conflict");

    let honest_proof_ba = FraudProofPayload::new_ingress_counter_conflict(p2_honest, p1);
    assert!(!honest_proof_ba.verify(), "Honest V2 progression in (b, a) must not be conflict");
}
