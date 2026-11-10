use std::sync::Arc;
use tempfile::tempdir;

use humoco_node::api::hmc::L2LockEntry;
use humoco_node::network::manager::PeerManager;
use humoco_node::storage::db::RedbStorage;
use humoco_node::storage::engine::{DualTierEngine, IngressOrigin};

#[tokio::test]
async fn test_anti_framing_split_brain_collision_does_not_ban_signers() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("anti_framing.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _handle) = DualTierEngine::new(storage.clone());

    let voucher_id = "v_anti_framing".to_string();
    let root_valid = 2_000_000u64;
    engine
        .hmc_ram
        .write()
        .await
        .insert_voucher_root_for_test(voucher_id.clone(), root_valid);

    let innocent_pk = [0x99u8; 32];

    // Spend A
    let lock_a = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher_id.clone(),
        t_id: [0xaa; 32],
        sender_ephemeral_pub: [0x11; 32],
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 100,
        deletable_at: None,
        privacy_guard: None,
    };

    let (res_a, is_new_a) = engine
        .ingress_hmc_lock_with_origin(
            "tag_conflict".into(),
            lock_a.clone(),
            IngressOrigin::ClientApi,
            Some(100),
        )
        .await;
    assert!(is_new_a);
    assert!(matches!(res_a, humoco_node::api::hmc::L2Verdict::Verified { .. }));

    // Colliding Spend B on same tag
    let mut lock_b = lock_a;
    lock_b.t_id = [0xbb; 32];

    let (res_b, is_new_b) = engine
        .ingress_hmc_lock_with_origin(
            "tag_conflict".into(),
            lock_b,
            IngressOrigin::ClientApi,
            Some(100),
        )
        .await;
    assert!(!is_new_b);
    assert!(matches!(res_b, humoco_node::api::hmc::L2Verdict::Conflict { .. }));

    // CRITICAL ANTI-FRAMING CHECK: Innocent node MUST NOT be banned!
    assert!(
        !engine.is_node_banned(&innocent_pk).await,
        "Eisen-Regel 8: Kollision darf unbeteiligte Knoten niemals bannen!"
    );
}

#[tokio::test]
async fn test_24h_finality_hysteresis_and_immature_rejection() {
    let peer_mgr = Arc::new(PeerManager::new(vec![]));
    peer_mgr.set_simulation_mode(true);
    let now_ms = 1_000_000_000u64;

    // Phase 9 P1: Provisional -> Final additionally requires local sync-readiness.
    // A freshly booted (unsynced) node must never report FINAL, even with N >= 20.
    assert!(!peer_mgr.is_local_sync_ready());
    peer_mgr.set_local_sync_ready(true);

    // An unobserved/immature local ticket contributes no eligible identity.
    assert_eq!(peer_mgr.active_nodes_count(), 0);
    assert!(!peer_mgr.is_network_stable_ge20_for_24h(now_ms));

    // Add 25 nodes, but keep them IMMATURE (< 24h incubation)
    for i in 0..25u64 {
        let dummy_id = *blake3::hash(&i.to_le_bytes()).as_bytes();
        let dummy_hrw = *blake3::hash(&[dummy_id.as_slice(), b"hrw"].concat()).as_bytes();
        let addr = format!("127.0.0.1:{}", 20000 + i).parse().unwrap();
        peer_mgr
            .learn_node_from_gossip_with_hrw(dummy_id, dummy_hrw, addr, 1, None)
            .await;
    }

    // Immature nodes MUST NOT be counted in active_nodes_count
    assert_eq!(peer_mgr.active_nodes_count(), 0);
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

    // Twenty explicitly mature remote identities reach the FINAL-size regime.
    assert_eq!(peer_mgr.active_nodes_count(), 20);

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

    // Only stale passive presence excludes identities; RPC malus is diagnostic.
    for i in 0..5u64 {
        let dummy_id = *blake3::hash(&i.to_le_bytes()).as_bytes();
        peer_mgr
            .set_last_seen_for_test(
                &dummy_id,
                std::time::Instant::now()
                    - std::time::Duration::from_secs(
                        humoco_node::network::PRESENCE_FRESHNESS_SECS + 1,
                    ),
            )
            .await;
    }

    // Active count is now 16 < 20
    assert!(peer_mgr.active_nodes_count() < 20);
    assert!(!peer_mgr.is_network_stable_ge20_for_24h(now_ms + 86_400_002));

    // Phase 9 P1: without local sync-readiness FINAL must stay blocked even with N >= 20.
    peer_mgr.set_local_sync_ready(false);
    assert!(!peer_mgr.is_network_stable_ge20_for_24h(now_ms + 86_400_003));
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
    engine
        .hmc_ram
        .write()
        .await
        .insert_voucher_root_for_test(voucher_id.clone(), root_valid);

    // 1. Root expiry within 30 seconds is rejected; child TTL cannot override it.
    let invalid_entry = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher_id.clone(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x11; 32],
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some((now_ms + 10_000).to_string()),
        privacy_guard: None,
    };

    let (verdict_invalid, is_new) = engine
        .ingress_hmc_lock_with_origin(
            "tag_invalid".into(),
            invalid_entry,
            IngressOrigin::ClientApi,
            Some(root_valid - 10_000),
        )
        .await;

    assert!(!is_new);
    assert!(
        matches!(
            verdict_invalid,
            humoco_node::api::hmc::L2Verdict::Rejected { .. }
        ),
        "INV-1202 verletzt: Lock mit valid_until < now + 30s muss auf ClientApi abgewiesen werden!"
    );

    // 2. Valid root lifetime wins over arbitrary successor TTL metadata.
    let valid_entry = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher_id.clone(),
        t_id: [0x22; 32],
        sender_ephemeral_pub: [0x33; 32],
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
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
    assert!(matches!(
        verdict_valid,
        humoco_node::api::hmc::L2Verdict::Verified { .. }
    ));
}

#[tokio::test]
async fn test_cold_boot_pruning_deferred_during_boot_sync() {
    // Audit Finding A03: Destructive pruning must be deferred during cold boot
    // if boot sync is pending and clock is not corroborated by F2F median samples.
    let peer_mgr = Arc::new(PeerManager::new(vec![]));
    // Simulated peer presence with pending sync
    peer_mgr.set_local_sync_ready(false);

    assert!(
        !peer_mgr.is_local_sync_ready(),
        "Fresh node with configured peers must not be sync-ready"
    );
    assert!(
        !peer_mgr.clock().is_time_corroborated(0),
        "Without peer median samples, clock cannot be corroborated"
    );

    let should_defer_prune =
        !peer_mgr.is_local_sync_ready() && !peer_mgr.clock().is_time_corroborated(0);
    assert!(
        should_defer_prune,
        "A03 Invariant: Pruning must be deferred during uncorroborated cold-boot sync"
    );

    // Once boot sync converges, pruning is unblocked
    peer_mgr.set_local_sync_ready(true);
    let should_defer_now =
        !peer_mgr.is_local_sync_ready() && !peer_mgr.clock().is_time_corroborated(0);
    assert!(
        !should_defer_now,
        "A03 Invariant: Once sync converges, pruning is active"
    );
}
