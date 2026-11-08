use humoco_sim_core::crypto::sign_lock_attestation;
use humoco_sim_core::fraud::{FraudBuildError, FraudProofPayload, FraudProofPillar};
use humoco_sim_core::types::{NetworkId, SimTime};

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
        NetworkId::Mainnet,
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
        NetworkId::Mainnet,
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
    assert!(
        proof.verify_network(NetworkId::Mainnet),
        "Säule 2 Beweis muss unter Mainnet gültig sein"
    );
    assert!(
        !proof.verify(),
        "Säule 2 Beweis ohne explizites Netzwerk muss abgelehnt werden"
    );
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
        NetworkId::Mainnet,
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
        NetworkId::Mainnet,
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
        proof.verify_network(NetworkId::Mainnet),
        "A07: V2 envelope sequence fork must be detected as fraud!"
    );
    assert!(
        !proof.verify_network(NetworkId::Testnet),
        "A07: Mainnet proof must be rejected under Testnet!"
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
        NetworkId::Mainnet,
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
    // Under-reporting malicious packet declares write_ema = 10_000 (< decayed(50_000, 10)).
    let ts2 = ts1 + 10_000;
    let fraudulent_write_ema = 10_000;
    let p2_under_report = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
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
    assert!(proof_ab.verify_network(NetworkId::Mainnet), "V2 under-reporting in (a, b) must verify as fraud");

    let proof_ba = FraudProofPayload::new_ingress_counter_conflict(p2_under_report, p1.clone());
    assert_eq!(proof_ba.perpetrator_node_id, gateway_pubkey);
    assert!(proof_ba.verify_network(NetworkId::Mainnet), "V2 under-reporting in (b, a) must verify as fraud");

    // Honest progression: seq = 2 with declared_write_ema = write_ema_1 + footprint_1
    let honest_write_ema = humoco_sim_core::quota::decay_integer_ema(write_ema_1, 10) + footprint_1;
    let p2_honest = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
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
    assert!(!honest_proof_ab.verify_network(NetworkId::Mainnet), "Honest V2 progression in (a, b) must not be conflict");

    let honest_proof_ba = FraudProofPayload::new_ingress_counter_conflict(p2_honest, p1);
    assert!(!honest_proof_ba.verify_network(NetworkId::Mainnet), "Honest V2 progression in (b, a) must not be conflict");
}

/// S07-11: Network-bound ingress evidence & explicit-network verification
#[test]
fn test_s07_11_network_bound_ingress_evidence_verification() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]);
    let _pk = sk.verifying_key().to_bytes();

    let p1_main = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        1000,
        500_000,
        0,
        100,
        false,
        [0x01; 32],
    );
    let p2_main_conflict = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        2,
        2000,
        100_000, // rollback -> fraud!
        0,
        100,
        false,
        [0x02; 32],
    );

    // 1. Same-network conflict on Mainnet verifies under Mainnet
    let proof_main = FraudProofPayload::new_ingress_counter_conflict(p1_main.clone(), p2_main_conflict.clone());
    assert!(proof_main.verify_network(NetworkId::Mainnet));
    // Fails under foreign network Testnet
    assert!(!proof_main.verify_network(NetworkId::Testnet));
    // Networkless verify strictly returns false
    assert!(!proof_main.verify());

    // 2. Same-network conflict on Testnet verifies under Testnet, fails under Mainnet
    let p1_test = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Testnet,
        &sk,
        1,
        1,
        1000,
        500_000,
        0,
        100,
        false,
        [0x01; 32],
    );
    let p2_test_conflict = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Testnet,
        &sk,
        1,
        2,
        2000,
        100_000,
        0,
        100,
        false,
        [0x02; 32],
    );
    let proof_test = FraudProofPayload::new_ingress_counter_conflict(p1_test.clone(), p2_test_conflict.clone());
    assert!(proof_test.verify_network(NetworkId::Testnet));
    assert!(!proof_test.verify_network(NetworkId::Mainnet));
    assert!(!proof_test.verify());

    // 3. Mixed-network construction must fail with NetworkMismatch
    assert_eq!(
        FraudProofPayload::try_new_ingress_counter_conflict(p1_main.clone(), p2_test_conflict.clone()),
        Err(FraudBuildError::NetworkMismatch)
    );
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &p1_main, &p2_test_conflict));
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Testnet, &p1_main, &p2_test_conflict));

    // 4. Forged payload containing mismatched packets must fail verification
    let mut forged = FraudProofPayload::new_ingress_counter_conflict(p1_main.clone(), p1_main.clone());
    forged.evidence_packet_b = humoco_sim_core::fraud::encode_ingress_envelope(&p2_test_conflict);
    assert!(!forged.verify_network(NetworkId::Mainnet));
    assert!(!forged.verify_network(NetworkId::Testnet));
}

/// S07-10: Physical-time EMA decay bounds & symmetry
#[test]
fn test_s07_10_physical_time_ema_decay_bounds_and_symmetry() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);

    // Exact vector from finding: day=1, seq=1->2, timestamps=1_000_000->44_200_000ms (delta = 43_200s, 12h)
    // and write_ema = 1_000_000_000 -> 707_106_782.
    // 24h-half-life EMA decay for 12h: 1_000_000_000 * 2^(-0.5) = 707_106_781.18...
    // decay_integer_ema(1_000_000_000, 43_200) produces 707_106_781.
    // Declared 707_106_782 >= 707_106_781, so lawful decay MUST NOT be flagged as fraud!
    let p1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        1_000_000,
        1_000_000_000,
        0,
        0,
        false,
        [0x10; 32],
    );
    let p2 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        2,
        44_200_000,
        707_106_782,
        0,
        0,
        false,
        [0x20; 32],
    );

    // Both (p1, p2) and (p2, p1) must return fraud = false
    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &p1, &p2),
        "Lawful 12h write_ema decay in (p1, p2) must NOT be fraud!"
    );
    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &p2, &p1),
        "Lawful 12h write_ema decay in (p2, p1) must NOT be fraud!"
    );

    let proof_ab = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2.clone());
    assert!(!proof_ab.verify_network(NetworkId::Mainnet));
    let proof_ba = FraudProofPayload::new_ingress_counter_conflict(p2.clone(), p1.clone());
    assert!(!proof_ba.verify_network(NetworkId::Mainnet));

    // Lawful declared_read_ema_credits decay in both orders:
    let r1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        1_000_000,
        0,
        1_000_000,
        0,
        false,
        [0x30; 32],
    );
    let r2 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        2,
        44_200_000,
        0,
        707_107,
        0,
        false,
        [0x40; 32],
    );
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &r1, &r2));
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &r2, &r1));

    // Duplicate neutrality: identical seq=1 twice -> false
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &p1, &p1));

    // Genuine under-reporting: write_ema rollback below decay floor
    let p2_under = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        2,
        44_200_000,
        500_000_000, // strictly below 707_106_781
        0,
        0,
        false,
        [0x50; 32],
    );
    assert!(FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &p1, &p2_under));
    assert!(FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &p2_under, &p1));

    // Rollback to 0:
    let p2_zero = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        2,
        44_200_000,
        0, // rollback to 0
        0,
        0,
        false,
        [0x60; 32],
    );
    assert!(FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &p1, &p2_zero));
    assert!(FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &p2_zero, &p1));
}

/// S07-12: Lawful composed Q32 decay must never be classified as first-party fraud
#[test]
fn test_s07_12_composed_q32_decay_honest_reproduction_not_fraud() {
    use humoco_sim_core::quota::NetworkThermometer;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);

    // Exact S07-12 reproduction vector from finding:
    // 1. T = 100_000s, write_ingress = 1_000_000_000_000
    let mut therm = NetworkThermometer::new();
    therm.record_write_ingress(100_000, 1_000_000_000_000);
    let (write_ema_1, read_ema_1) = therm.checkpoint_emas_at(100_000);
    assert_eq!(write_ema_1, 1_000_000_000_000);
    assert_eq!(read_ema_1, 0);

    let env1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        100_000_000,
        write_ema_1,
        read_ema_1,
        1,
        false,
        [0x10; 32],
    );

    // 2. Unobserved intermediate write ingress at 101_350s (seq 2)
    therm.record_write_ingress(101_350, 1);

    // 3. Observed write ingress at 101_891s (seq 3)
    therm.record_write_ingress(101_891, 1);
    let (write_ema_3, read_ema_3) = therm.checkpoint_emas_at(101_891);
    assert_eq!(write_ema_3, 984_957_739_474);
    assert_eq!(read_ema_3, 0);

    let env3 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        3,
        101_891_000,
        write_ema_3,
        read_ema_3,
        1,
        false,
        [0x30; 32],
    );

    // Prior to S07-12 fix, direct decay gives 984_957_739_477, min_write gives 984_957_739_476,
    // which falsely flags genuine honest envelopes as fraud in BOTH orders!
    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env1, &env3),
        "S07-12: Lawful composed decay in (env1, env3) must NOT be fraud"
    );
    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env3, &env1),
        "S07-12: Lawful composed decay in (env3, env1) must NOT be fraud"
    );

    let proof_13 = FraudProofPayload::new_ingress_counter_conflict(env1.clone(), env3.clone());
    assert!(!proof_13.verify_network(NetworkId::Mainnet));
    let proof_31 = FraudProofPayload::new_ingress_counter_conflict(env3, env1);
    assert!(!proof_31.verify_network(NetworkId::Mainnet));
}

/// S07-12: Both write and read EMA counters with composed decay
#[test]
fn test_s07_12_composed_decay_read_ema_counters() {
    use humoco_sim_core::quota::NetworkThermometer;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x98; 32]);

    let mut therm = NetworkThermometer::new();
    therm.record_read_ingress(100_000, 10_000_000_000);
    let (write_1, read_1) = therm.checkpoint_emas_at(100_000);
    assert_eq!(read_1, 10_000_000_000);

    let env1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        100_000_000,
        write_1,
        read_1,
        1,
        true,
        [0x11; 32],
    );

    // Intermediate read events:
    therm.record_read_ingress(101_350, 1);
    therm.record_read_ingress(101_891, 1);
    let (write_3, read_3) = therm.checkpoint_emas_at(101_891);

    let env3 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        3,
        101_891_000,
        write_3,
        read_3,
        1,
        true,
        [0x33; 32],
    );

    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env1, &env3));
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env3, &env1));
}

/// S07-12: Table-boundary segments, exact knots, multi-hour jumps, and multi-day windows
#[test]
fn test_s07_12_table_boundary_knots_and_multi_day() {
    use humoco_sim_core::quota::NetworkThermometer;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x97; 32]);

    let mut therm = NetworkThermometer::new();
    therm.record_write_ingress(0, 500_000_000_000);
    let (w0, r0) = therm.checkpoint_emas_at(0);

    let env0 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        0,
        w0,
        r0,
        100,
        false,
        [0x01; 32],
    );

    // Sub-segment 500s, then jump to exact knot at 1350s:
    therm.record_write_ingress(500, 10);
    therm.record_write_ingress(1350, 10);
    // Sub-segment 2000s, then jump to exact knot at 2700s:
    therm.record_write_ingress(2000, 10);
    therm.record_write_ingress(2700, 10);
    // Multi-hour jumps (12h = 43200s, 24h = 86400s) and multi-day (3 days = 259200s):
    therm.record_write_ingress(43_200, 10);
    therm.record_write_ingress(86_400, 10);
    therm.record_write_ingress(259_200, 10);
    let (w_final, r_final) = therm.checkpoint_emas_at(259_200);

    let env_final = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        8,
        259_200_000,
        w_final,
        r_final,
        100,
        false,
        [0x08; 32],
    );

    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env0, &env_final));
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_final, &env0));
}

/// S07-12: Multiple hidden intermediate checkpoints and seq-zero read/status updates
#[test]
fn test_s07_12_hidden_intermediate_checkpoints_and_seq_zero() {
    use humoco_sim_core::quota::NetworkThermometer;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x96; 32]);

    let mut therm = NetworkThermometer::new();
    therm.record_write_ingress(10_000, 2_000_000_000_000);
    let (w_init, r_init) = therm.checkpoint_emas_at(10_000);

    let env_init = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        10_000_000,
        w_init,
        r_init,
        50,
        false,
        [0xA1; 32],
    );

    // Simulate 50 intermediate hidden updates: write events and seq=0 status checkpoints
    let mut current_sec = 10_000;
    for i in 1..=50 {
        current_sec += 25; // 25s elapsed per step
        if i % 2 == 0 {
            therm.record_write_ingress(current_sec, 5);
        } else {
            therm.record_read_ingress(current_sec, 2);
            therm.checkpoint_emas_at(current_sec); // status checkpoint without write sequence
        }
    }

    let (w_end, r_end) = therm.checkpoint_emas_at(current_sec);
    let env_end = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        26, // only 25 write events occurred
        current_sec * 1000,
        w_end,
        r_end,
        50,
        false,
        [0xA2; 32],
    );

    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_init, &env_end));
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_end, &env_init));
}

/// S07-12: Large bounded values up to u64::MAX (MAX_SCALED_USAGE whole units)
#[test]
fn test_s07_12_large_bounded_values_up_to_u64_max() {
    use humoco_sim_core::quota::NetworkThermometer;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x95; 32]);

    let mut therm = NetworkThermometer::new();
    // Ingress maximum bounded whole units (MAX_SCALED_USAGE >> 32 == u64::MAX)
    therm.record_write_ingress(1_000, u64::MAX);
    let (w_max, r_max) = therm.checkpoint_emas_at(1_000);

    let env_max = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        1_000_000,
        w_max,
        r_max,
        100,
        false,
        [0xB1; 32],
    );

    therm.record_write_ingress(2_350, 100);
    therm.record_write_ingress(2_891, 100);
    let (w_max_end, r_max_end) = therm.checkpoint_emas_at(2_891);

    let env_max_end = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        3,
        2_891_000,
        w_max_end,
        r_max_end,
        100,
        false,
        [0xB3; 32],
    );

    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_max, &env_max_end));
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_max_end, &env_max));
}

/// S07-12: Network isolation between Mainnet and Testnet
#[test]
fn test_s07_12_network_isolation_mainnet_and_testnet() {
    use humoco_sim_core::quota::NetworkThermometer;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x94; 32]);

    let mut therm = NetworkThermometer::new();
    therm.record_write_ingress(100_000, 1_000_000_000_000);
    let (w1, r1) = therm.checkpoint_emas_at(100_000);

    let env1_test = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Testnet,
        &sk,
        1,
        1,
        100_000_000,
        w1,
        r1,
        1,
        false,
        [0xC1; 32],
    );

    therm.record_write_ingress(101_350, 1);
    therm.record_write_ingress(101_891, 1);
    let (w3, r3) = therm.checkpoint_emas_at(101_891);

    let env3_test = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Testnet,
        &sk,
        1,
        3,
        101_891_000,
        w3,
        r3,
        1,
        false,
        [0xC3; 32],
    );

    // On Testnet:
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Testnet, &env1_test, &env3_test));
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Testnet, &env3_test, &env1_test));

    // Under foreign network Mainnet:
    assert!(!FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env1_test, &env3_test));
}

/// S07-12: Positive fraud controls preserved (same-slot fork, blatant under-reporting rollback)
#[test]
fn test_s07_12_positive_fraud_controls_preserved() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x93; 32]);

    // Control 1: Genuine same-slot sequence fork conflict (same day & seq, different op_hash)
    let env_fork_a = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        5,
        100_000_000,
        500_000,
        0,
        10,
        false,
        [0xD1; 32],
    );
    let env_fork_b = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        5,
        100_000_010,
        500_000,
        0,
        10,
        false,
        [0xD2; 32],
    );
    assert!(FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_fork_a, &env_fork_b));
    assert!(FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_fork_b, &env_fork_a));

    // Control 2: Blatant impossible under-reporting (rollback to 0 after short interval)
    let env_adv_zero = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        6,
        100_001_000, // 1s later
        0,           // rollback to 0
        0,
        10,
        false,
        [0xD3; 32],
    );
    assert!(FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_fork_a, &env_adv_zero));
    assert!(FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env_adv_zero, &env_fork_a));
}

/// S07-12: Verify that for all dt in 1..=86_400, decay_scaled_ema factor stays strictly within Q32 constants
#[test]
fn test_s07_12_dyadic_secant_slack_bounds_all_seconds() {
    use humoco_sim_core::quota::decay_scaled_ema;

    let base_scaled = 1u128 << 32;
    for dt in 1..=86_400u64 {
        let direct_scaled = decay_scaled_ema(base_scaled, dt);
        let exact_factor = 2.0f64.powf(-(dt as f64) / 86400.0);
        let exact_scaled = (exact_factor * ((1u128 << 32) as f64)).round() as i128;
        let diff_q32 = direct_scaled as i128 - exact_scaled;

        // Due to strictly convex secant interpolation, direct_scaled is >= exact (modulo at most 1 Q32 unit knot under-rounding)
        assert!(
            diff_q32 >= -1,
            "dt={} factor underflow: direct={} exact={} diff={}",
            dt, direct_scaled, exact_scaled, diff_q32
        );
        assert!(
            diff_q32 <= FraudProofPayload::MAX_DYADIC_SECANT_ERROR_Q32 as i128 + 1,
            "dt={} exceeded secant error bound: diff={} max={}",
            dt, diff_q32, FraudProofPayload::MAX_DYADIC_SECANT_ERROR_Q32
        );
        assert!(
            diff_q32 <= FraudProofPayload::MAX_COMPOSITE_DECAY_SLACK_Q32 as i128,
            "dt={} exceeded composite decay slack: diff={} max={}",
            dt, diff_q32, FraudProofPayload::MAX_COMPOSITE_DECAY_SLACK_Q32
        );
    }
}

/// S07-12: Integer boundary multi-step test for v1 = 68_500 (secant_slack * v1 ~ 0.999 * 2^32)
#[test]
fn test_s07_12_integer_boundary_v1_68500_multi_step() {
    use humoco_sim_core::quota::NetworkThermometer;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x92; 32]);
    let mut therm = NetworkThermometer::new();

    let v1 = 68_500u64;
    therm.record_write_ingress(100_000, v1);
    let (w1, r1) = therm.checkpoint_emas_at(100_000);
    assert_eq!(w1, v1);

    let env1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1,
        100_000_000,
        w1,
        r1,
        1,
        false,
        [0x71; 32],
    );

    // Multi-step decomposition across intermediate knots
    therm.record_write_ingress(100_675, 1);
    therm.record_write_ingress(101_350, 1);
    therm.record_write_ingress(102_025, 1);
    let (w2, r2) = therm.checkpoint_emas_at(102_025);

    let env2 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        4,
        102_025_000,
        w2,
        r2,
        1,
        false,
        [0x74; 32],
    );

    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env1, &env2),
        "v1=68_500 multi-step (env1, env2) must NOT be flagged as fraud"
    );
    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &env2, &env1),
        "v1=68_500 multi-step (env2, env1) must NOT be flagged as fraud"
    );
}

/// S07-12: Unsequenced envelopes (epoch_seq == 0) with non-zero epoch_day must not trigger false fraud
#[test]
fn test_s07_12_unsequenced_epoch_seq_zero_with_positive_epoch_day() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x91; 32]);

    // Scenario A: Two distinct unsequenced read/status envelopes on the same epoch_day
    let read_a = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        0, // unsequenced
        100_000_000,
        500_000,
        10_000,
        1,
        true,
        [0xE1; 32],
    );
    let read_b = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        0, // unsequenced
        100_002_000,
        499_900,
        10_001,
        1,
        true,
        [0xE2; 32],
    );

    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &read_a, &read_b),
        "Two unsequenced reads on same day must NOT conflict"
    );
    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &read_b, &read_a),
        "Two unsequenced reads on same day (reverse) must NOT conflict"
    );

    // Scenario B: An unsequenced read envelope paired with a sequenced write envelope
    let write_seq1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        NetworkId::Mainnet,
        &sk,
        1,
        1, // sequenced
        100_001_000,
        500_000,
        10_000,
        10,
        false,
        [0xE3; 32],
    );

    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &read_a, &write_seq1),
        "Unsequenced read + sequenced write must NOT conflict"
    );
    assert!(
        !FraudProofPayload::check_ingress_conflict(NetworkId::Mainnet, &write_seq1, &read_a),
        "Sequenced write + unsequenced read must NOT conflict"
    );
}



