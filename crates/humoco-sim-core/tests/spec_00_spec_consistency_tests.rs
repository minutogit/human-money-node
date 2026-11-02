use humoco_sim_core::crypto::{
    compute_canonical_hash, compute_canonical_hash_with_sig, compute_genesis_root,
};
use humoco_sim_core::fraud::SlotDetector1024;
use humoco_sim_core::types::{extract_shard_id, required_quorum};

#[test]
fn test_quorum_formula_consistency_table_r1_to_r20() {
    // Erwartete Quorum-Werte nach Q(R) = min(R, floor(2R/3) + 1):
    let expected: [(usize, usize, bool); 20] = [
        (1, 1, false),   // R=1: floor(2/3)+1 = 1 -> min(1, 1) = 1
        (2, 2, false),   // R=2: floor(4/3)+1 = 2 -> min(2, 2) = 2
        (3, 3, false),   // R=3: floor(6/3)+1 = 3 -> min(3, 3) = 3
        (4, 3, false),   // R=4: floor(8/3)+1 = 3
        (5, 4, false),   // R=5: floor(10/3)+1 = 4
        (6, 5, false),   // R=6: floor(12/3)+1 = 5
        (7, 5, false),   // R=7: floor(14/3)+1 = 5
        (8, 6, false),   // R=8: floor(16/3)+1 = 6
        (9, 7, false),   // R=9: floor(18/3)+1 = 7
        (10, 7, false),  // R=10: floor(20/3)+1 = 7 (floor, nicht ceil=8)
        (11, 8, false),  // R=11: floor(22/3)+1 = 8
        (12, 9, false),  // R=12: floor(24/3)+1 = 9
        (13, 9, false),  // R=13: floor(26/3)+1 = 9
        (14, 10, false), // R=14: floor(28/3)+1 = 10
        (15, 11, false), // R=15: floor(30/3)+1 = 11
        (16, 11, false), // R=16: floor(32/3)+1 = 11
        (17, 12, false), // R=17: floor(34/3)+1 = 12
        (18, 13, false), // R=18: floor(36/3)+1 = 13
        (19, 13, false), // R=19: floor(38/3)+1 = 13
        (20, 14, true),  // R=20: Global FINAL Threshold = 14
    ];

    for (r, exp_q, exp_is_final) in expected {
        let (q, is_final) = required_quorum(r);
        assert_eq!(q, exp_q, "Fehler bei Quorum für R={}", r);
        assert_eq!(is_final, exp_is_final, "Fehler bei is_final für R={}", r);
    }
}

#[test]
fn test_shard_id_extraction_endianness() {
    let mut genesis_root = [0u8; 32];
    genesis_root[0] = 0x12;
    genesis_root[1] = 0x34;

    let shard_id = extract_shard_id(&genesis_root);
    assert_eq!(
        shard_id, 0x1234,
        "2-Byte Big-Endian Extraktion muss 0x1234 ergeben"
    );
}

#[test]
fn test_canonical_hash_with_signature() {
    let parent = [0x11; 32];
    let receiver = [0x22; 32];
    let sig = [0x77; 64];

    let h1 = compute_canonical_hash_with_sig(&parent, &receiver, &sig);
    let h2 = compute_canonical_hash(&parent, &receiver, &sig);
    assert_eq!(
        h1, h2,
        "compute_canonical_hash_with_sig nutzt dieselbe Preimage-Berechnung"
    );
}

#[test]
fn test_slot_detector_1024_distribution() {
    assert_eq!(SlotDetector1024::slot_index(1025), 1);
    assert_eq!(SlotDetector1024::slot_index(2048), 0);
}

#[test]
fn test_compute_genesis_root_determinism_and_domain() {
    let root1 = compute_genesis_root(1, 1_700_000_000);
    let root2 = compute_genesis_root(1, 1_700_000_000);
    assert_eq!(root1, root2, "Genesis Root muss deterministisch sein");

    let root_v2 = compute_genesis_root(2, 1_700_000_000);
    assert_ne!(
        root1, root_v2,
        "Unterschiedliche Protokoll-Versionen erzeugen unterschiedliche Roots"
    );

    let root_t1 = compute_genesis_root(1, 1_700_000_001);
    assert_ne!(
        root1, root_t1,
        "Unterschiedliche T0 erzeugen unterschiedliche Roots"
    );
}
