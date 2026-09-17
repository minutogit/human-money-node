use humoco_sim_core::types::{
    hrw_rank_nodes, hrw_score_normalized, order_statistics_threshold,
    verify_order_statistics_quorum, NodeId, ShardId,
};

const SHARD_ID: ShardId = 42;
const K_MAX: f64 = 40.0;

#[test]
fn test_order_statistics_bootstrap_n2() {
    let n_active = 2;
    let nodes: Vec<NodeId> = vec![1, 2];

    // Threshold bei N=2 ist 0.0 (max(0.0, 1.0 - 40/2))
    let threshold = order_statistics_threshold(n_active, K_MAX);
    assert_eq!(threshold, 0.0, "Threshold must be 0.0 for N=2");

    // Q(2) = floor(4/3) + 1 = 2 Stimmen
    // 1. Beide Knoten signieren -> Gültig, PROVISIONAL (is_final = false)
    let (valid, is_final) = verify_order_statistics_quorum(&nodes, SHARD_ID, n_active, K_MAX);
    assert!(valid, "2 of 2 signatures must be valid in bootstrap");
    assert!(!is_final, "N=2 must be PROVISIONAL");

    // 2. Nur 1 Knoten signiert -> Ungültig (Q(2) = 2)
    let (valid_1, _) = verify_order_statistics_quorum(&[1], SHARD_ID, n_active, K_MAX);
    assert!(!valid_1, "1 of 2 signatures must fail quorum");
}

#[test]
fn test_order_statistics_bootstrap_n3() {
    let n_active = 3;
    let nodes: Vec<NodeId> = vec![1, 2, 3];

    // Threshold bei N=3 ist 0.0 (max(0.0, 1.0 - 40/3))
    let threshold = order_statistics_threshold(n_active, K_MAX);
    assert_eq!(threshold, 0.0, "Threshold must be 0.0 for small N");

    // 1. Alle 3 Knoten signieren -> Gültig, aber PROVISIONAL (Final: false)
    let (valid, is_final) = verify_order_statistics_quorum(&nodes, SHARD_ID, n_active, K_MAX);
    assert!(valid, "3 of 3 signatures must be valid");
    assert!(!is_final, "N=3 must be PROVISIONAL (is_final = false)");

    // 2. Grenzfall knapp drunter: Nur 2 Knoten signieren -> Ungültig (Q(3) = 3)
    let (valid_2, _) = verify_order_statistics_quorum(&[1, 2], SHARD_ID, n_active, K_MAX);
    assert!(!valid_2, "2 of 3 signatures must fail quorum");

    // 3. Duplikat-Signatur darf Quorum nicht austricksen
    let (valid_dup, _) = verify_order_statistics_quorum(&[1, 1, 2], SHARD_ID, n_active, K_MAX);
    assert!(!valid_dup, "Duplicate signatures must be rejected");
}

#[test]
fn test_order_statistics_village_n10() {
    let n_active = 10;
    let nodes: Vec<NodeId> = (1..=10).collect();

    // Threshold bei N=10 ist 0.0
    let threshold = order_statistics_threshold(n_active, K_MAX);
    assert_eq!(threshold, 0.0);

    // Q(10) = floor(20/3) + 1 = 7 Stimmen
    // 1. Genau 7 Stimmen -> Gültig, PROVISIONAL
    let (valid_7, is_final_7) = verify_order_statistics_quorum(&nodes[0..7], SHARD_ID, n_active, K_MAX);
    assert!(valid_7, "7 of 10 signatures must be valid");
    assert!(!is_final_7, "N=10 must be PROVISIONAL");

    // 2. Grenzfall knapp drunter: 6 Stimmen -> Ungültig
    let (valid_6, _) = verify_order_statistics_quorum(&nodes[0..6], SHARD_ID, n_active, K_MAX);
    assert!(!valid_6, "6 of 10 signatures must fail quorum");
}

#[test]
fn test_order_statistics_boundary_n20_and_all_signers_range() {
    let n_active = 20;
    let nodes: Vec<NodeId> = (1..=20).collect();

    // Q(20) = 14 Stimmen
    // Teste alle Anzahlen von 14 bis 20 Signaturen (Normalbetrieb: oft alle 20 antworten)
    for k in 14..=20 {
        let (valid_k, is_final_k) = verify_order_statistics_quorum(&nodes[0..k], SHARD_ID, n_active, K_MAX);
        assert!(valid_k, "k = {} of 20 signatures must be valid", k);
        assert!(is_final_k, "k = {} of 20 signatures must be FINAL", k);
    }

    // Grenzfall knapp drunter: 13 Stimmen -> Ungültig
    let (valid_13, _) = verify_order_statistics_quorum(&nodes[0..13], SHARD_ID, n_active, K_MAX);
    assert!(!valid_13, "13 of 20 signatures must fail quorum");
}

#[test]
fn test_order_statistics_large_network_n1000_normal_and_degraded() {
    let n_active = 1000;
    let all_nodes: Vec<NodeId> = (0..n_active as NodeId).collect();

    // Berechne HRW-Rangliste
    let ranked = hrw_rank_nodes(&all_nodes, SHARD_ID);

    // Threshold bei N=1000: 1.0 - 40/1000 = 0.960
    let threshold = order_statistics_threshold(n_active, K_MAX);
    assert!((threshold - 0.960).abs() < 1e-6);

    // Fall 1: Perfekter Normalbetrieb - ALLE 20 der Top-20 unterschreiben
    let all20_signers: Vec<NodeId> = ranked.iter().take(20).map(|(nid, _)| *nid).collect();
    let (valid_all20, is_final_all20) = verify_order_statistics_quorum(&all20_signers, SHARD_ID, n_active, K_MAX);
    assert!(valid_all20, "All 20 top signers must be valid");
    assert!(is_final_all20, "All 20 top signers must be FINAL");

    // Fall 2: Normalbetrieb mit 14, 15, 16, 17, 18, 19 Stimmen aus Top-20
    for k in 14..=20 {
        let subset: Vec<NodeId> = ranked.iter().take(k).map(|(nid, _)| *nid).collect();
        let (valid_k, is_final_k) = verify_order_statistics_quorum(&subset, SHARD_ID, n_active, K_MAX);
        assert!(valid_k, "k = {} from top-20 must be valid", k);
        assert!(is_final_k, "k = {} from top-20 must be FINAL", k);
    }

    // Fall 3: Großstörung (Nur 5 aus Top-20 + 9 Nachrücker aus Rängen 21..35)
    let mut degraded_signers: Vec<NodeId> = Vec::new();
    for (nid, _) in ranked.iter().take(5) {
        degraded_signers.push(*nid);
    }
    for (nid, _) in ranked.iter().skip(20).take(9) {
        degraded_signers.push(*nid);
    }
    assert_eq!(degraded_signers.len(), 14);

    let (valid_b, is_final_b) = verify_order_statistics_quorum(&degraded_signers, SHARD_ID, n_active, K_MAX);
    assert!(valid_b, "Degraded quorum with ranks 21..29 must PASS via order statistics");
    assert!(is_final_b, "Degraded quorum is still FINAL");

    // Fall 4: Sybil / Fake-Angreifer (14 Knoten aus dem Mittelfeld, z.B. Rang 500..514)
    let fake_signers: Vec<NodeId> = ranked.iter().skip(500).take(14).map(|(nid, _)| *nid).collect();
    let (valid_c, _) = verify_order_statistics_quorum(&fake_signers, SHARD_ID, n_active, K_MAX);
    assert!(!valid_c, "Random/fake nodes with low scores must be REJECTED");
}

#[test]
fn test_order_statistics_poisoning_immunity_and_junk_signers() {
    let n_active = 1000;
    let all_nodes: Vec<NodeId> = (0..n_active as NodeId).collect();
    let ranked = hrw_rank_nodes(&all_nodes, SHARD_ID);

    // Szenario 1: 19 legitime Top-20 Knoten unterschreiben + 1 unberechtigter Junk-Knoten auf Rang 500
    let mut signers_with_poison: Vec<NodeId> = ranked.iter().take(19).map(|(nid, _)| *nid).collect();
    let junk_node_rank500 = ranked[500].0;
    signers_with_poison.push(junk_node_rank500);
    assert_eq!(signers_with_poison.len(), 20);

    // WICHTIG: Die 1 Junk-Signatur darf das legitime Quorum NICHT zerstören!
    // Die 19 echten Stimmen reichen (>= 14), Rang 500 wird lautlos herausgefiltert.
    let (valid, is_final) = verify_order_statistics_quorum(&signers_with_poison, SHARD_ID, n_active, K_MAX);
    assert!(valid, "Valid 19 signers + 1 junk signature MUST be accepted (poisoning immunity)");
    assert!(is_final, "Must be FINAL");

    // Szenario 2: 14 legitime Top-Knoten + 5 Junk-Knoten (Rang 600..605)
    let mut signers_with_5_junk: Vec<NodeId> = ranked.iter().take(14).map(|(nid, _)| *nid).collect();
    for (nid, _) in ranked.iter().skip(600).take(5) {
        signers_with_5_junk.push(*nid);
    }
    assert_eq!(signers_with_5_junk.len(), 19);

    let (valid_14_plus_junk, is_final_14) = verify_order_statistics_quorum(&signers_with_5_junk, SHARD_ID, n_active, K_MAX);
    assert!(valid_14_plus_junk, "14 legit signers + 5 junk signatures MUST pass");
    assert!(is_final_14, "Must be FINAL");

    // Szenario 3: Nur 13 legitime Top-Knoten (zu wenig!) + 1 Junk-Knoten auf Rang 500
    let mut signers_13_plus_junk: Vec<NodeId> = ranked.iter().take(13).map(|(nid, _)| *nid).collect();
    signers_13_plus_junk.push(junk_node_rank500);

    let (valid_13, _) = verify_order_statistics_quorum(&signers_13_plus_junk, SHARD_ID, n_active, K_MAX);
    assert!(!valid_13, "13 legit signers + 1 junk MUST fail because legit count < 14");
}

#[test]
fn test_order_statistics_huge_network_n10000() {
    let n_active = 10_000;
    // Threshold bei N=10.000: 1.0 - 40 / 10.000 = 0.996
    let threshold = order_statistics_threshold(n_active, K_MAX);
    assert!((threshold - 0.996).abs() < 1e-6);

    // Verifiziere Score-Normalisierung
    let score_high = hrw_score_normalized(42, SHARD_ID);
    assert!((0.0..1.0).contains(&score_high));
}
