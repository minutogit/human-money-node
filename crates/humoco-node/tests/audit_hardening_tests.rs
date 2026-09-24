use std::sync::Arc;
use tempfile::tempdir;

use humoco_node::api::hmc::L2LockEntry;
use humoco_node::network::manager::PeerManager;
use humoco_node::storage::db::RedbStorage;
use humoco_node::storage::engine::{DualTierEngine, IngressOrigin};
use humoco_sim_core::storage::IngressVerdictLow;
use humoco_sim_core::types::{LockRecord, SimTime};

#[tokio::test]
async fn test_anti_framing_split_brain_collision_does_not_ban_signers() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("anti_framing.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _handle) = DualTierEngine::new(storage.clone());

    let parent_lock = [0x42u8; 32];
    let victim_node_id_u16 = 999u16;
    let victim_pk = {
        let mut pk = [0u8; 32];
        pk[0..2].copy_from_slice(&victim_node_id_u16.to_le_bytes());
        pk
    };

    // Lock A has victim in signers
    let mut lock_a = LockRecord::new(
        parent_lock,
        [0xaa; 32],
        vec![1, 2, 3],
        SimTime(0),
        SimTime(1_000_000),
    );
    lock_a.signers.insert(victim_node_id_u16);

    let res_a = engine
        .ingress_lock_with_origin(lock_a, SimTime(100), SimTime(2_000_000), IngressOrigin::PartitionSync)
        .await;
    assert_eq!(res_a.unwrap(), IngressVerdictLow::AcceptedNew);

    // Colliding Lock B also lists victim in signers (attacker framing attempt)
    let mut lock_b = LockRecord::new(
        parent_lock,
        [0xbb; 32],
        vec![4, 5, 6],
        SimTime(0),
        SimTime(1_000_000),
    );
    lock_b.signers.insert(victim_node_id_u16);

    // Ingress colliding lock — deterministic min(H_canon) decides WinnerA/B, never panic
    let res_b = engine
        .ingress_lock_with_origin(lock_b, SimTime(100), SimTime(2_000_000), IngressOrigin::PartitionSync)
        .await;
    assert!(
        matches!(
            res_b,
            Ok(IngressVerdictLow::AcceptedNew) | Err(IngressVerdictLow::RejectedCollision)
        ),
        "collision must be deterministic WinnerA/B via min(H_canon), got {:?}",
        res_b
    );

    // CRITICAL ANTI-FRAMING CHECK: Victim MUST NOT be banned!
    assert!(
        !engine.is_node_banned(&victim_pk).await,
        "Eisen-Regel 8 verletzt: Unschuldiger Knoten wurde durch gefälschtes signers-Feld gebannt!"
    );
}

#[tokio::test]
async fn test_24h_finality_hysteresis_and_immature_rejection() {
    let peer_mgr = Arc::new(PeerManager::new(vec![]));
    let now_ms = 1_000_000_000u64;

    // Initially, only self is active (1 node < 20)
    assert_eq!(peer_mgr.active_nodes_count(), 1);
    assert!(!peer_mgr.is_network_stable_ge20_for_24h(now_ms));

    // Add 25 nodes, but keep them IMMATURE (< 24h incubation)
    for i in 0..25u64 {
        let dummy_id = *blake3::hash(&i.to_le_bytes()).as_bytes();
        let addr = format!("127.0.0.1:{}", 20000 + i).parse().unwrap();
        peer_mgr.learn_node_from_gossip(dummy_id, addr, 1, None).await;
    }

    // Immature nodes MUST NOT be counted in active_nodes_count
    assert_eq!(peer_mgr.active_nodes_count(), 1);
    assert!(!peer_mgr.is_network_stable_ge20_for_24h(now_ms));

    // Mature 20 of the nodes (>24h incubation)
    for i in 0..20u64 {
        let dummy_id = *blake3::hash(&i.to_le_bytes()).as_bytes();
        peer_mgr
            .set_first_seen_for_test(
                &dummy_id,
                std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
            )
            .await;
    }

    // Now active count is 20 + 1 (self) = 21 >= 20
    assert_eq!(peer_mgr.active_nodes_count(), 21);

    // At t0: Hysteresis window just started -> NOT stable yet!
    assert!(
        !peer_mgr.is_network_stable_ge20_for_24h(now_ms),
        "INV-0802 verletzt: FINAL darf nicht sofort bei Erreichen von N>=20 vergeben werden!"
    );

    // After 12 hours (43_200_000 ms): Still not stable
    assert!(!peer_mgr.is_network_stable_ge20_for_24h(now_ms + 43_200_000));

    // After 24 hours + 1 ms: Stable!
    assert!(
        peer_mgr.is_network_stable_ge20_for_24h(now_ms + 86_400_001),
        "INV-0802 verletzt: Nach 24h ununterbrochener N>=20 Stabilität muss FINAL freigegeben werden!"
    );

    // If active nodes drop below 20 (e.g. suspension), hysteresis MUST reset!
    let base_instant = std::time::Instant::now();
    for i in 0..5u64 {
        let addr = format!("127.0.0.1:{}", 20000 + i).parse().unwrap();
        for step in 0..3 {
            peer_mgr
                .record_failure_at(addr, base_instant + std::time::Duration::from_secs(step * 65))
                .await;
        }
    }

    // Active count is now 16 < 20
    assert!(peer_mgr.active_nodes_count() < 20);
    assert!(!peer_mgr.is_network_stable_ge20_for_24h(now_ms + 86_400_002));
}

#[tokio::test]
async fn test_hmc_ingress_window_enforcement_on_hot_path() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("hmc_window.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _handle) = DualTierEngine::new(storage.clone());

    let voucher_id = "v_test_ingress_window".to_string();
    let now_ms = 1_000_000u64;
    let root_valid = now_ms + 500_000; // 500s in future

    // Anchor root
    engine.hmc_ram.write().await.voucher_roots.insert(voucher_id.clone(), root_valid);

    // 1. Entry with invalid time window: valid_until <= now + 30s (e.g. only 10s in future)
    let invalid_entry = L2LockEntry {
        layer2_voucher_id: voucher_id.clone(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x11; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some((now_ms + 10_000).to_string()),
        privacy_guard: None,
    };

    let (verdict_invalid, is_new) = engine
        .ingress_hmc_lock_with_origin(
            "tag_invalid".into(),
            invalid_entry,
            IngressOrigin::ClientApi,
            Some(now_ms),
        )
        .await;

    assert!(!is_new);
    assert!(
        matches!(verdict_invalid, humoco_node::api::hmc::L2Verdict::Rejected { .. }),
        "INV-1202 verletzt: Lock mit valid_until < now + 30s muss auf ClientApi abgewiesen werden!"
    );

    // 2. Entry with valid time window: now + 60s in future
    let valid_entry = L2LockEntry {
        layer2_voucher_id: voucher_id.clone(),
        t_id: [0x22; 32],
        sender_ephemeral_pub: [0x33; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some((now_ms + 60_000).to_string()),
        privacy_guard: None,
    };

    let (verdict_valid, is_new_valid) = engine
        .ingress_hmc_lock_with_origin(
            "tag_valid".into(),
            valid_entry,
            IngressOrigin::ClientApi,
            Some(now_ms),
        )
        .await;

    assert!(is_new_valid);
    assert!(matches!(verdict_valid, humoco_node::api::hmc::L2Verdict::Verified { .. }));
}
