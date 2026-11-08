use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use humoco_node::identity::NodeIdentity;
use humoco_node::network::manager::PeerManager;
use humoco_node::network::transport::{DefaultRequestHandler, QuicTransport};
use humoco_sim_core::wire::{MsgType, WireHeader};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_2_1_bootstrap_median_empty_and_single() {
    let pm = PeerManager::new(vec![]);
    // In production mode (empty network) -> W_MIN_FLOOR_PRODUCTION (256)
    assert_eq!(pm.calculate_network_median_work(), humoco_node::network::manager::W_MIN_FLOOR_PRODUCTION);

    let (is_acc, med) = pm.is_ticket_acceptable(humoco_node::network::manager::W_MIN_FLOOR_PRODUCTION);
    assert!(is_acc);
    assert_eq!(med, humoco_node::network::manager::W_MIN_FLOOR_PRODUCTION);

    // In simulation mode (empty network) -> W_MIN_FLOOR_SIMULATION (1)
    pm.set_simulation_mode(true);
    assert_eq!(pm.calculate_network_median_work(), humoco_node::network::manager::W_MIN_FLOOR_SIMULATION);
    let (is_acc_sim, med_sim) = pm.is_ticket_acceptable(1);
    assert!(is_acc_sim);
    assert_eq!(med_sim, 1);
}

#[tokio::test]
async fn test_2_2_bootstrap_median_1_and_2_nodes() {
    let pm = PeerManager::new(vec![]);
    pm.set_simulation_mode(true);
    let addr1: SocketAddr = "127.0.0.1:9091".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:9092".parse().unwrap();
    let pk1 = [1u8; 32];
    let pk2 = [2u8; 32];

    pm.learn_node_from_gossip_with_hrw_work_and_auth(pk1, pk1, addr1, 0, None, 50, true)
        .await;
    pm.set_first_seen_for_test(
        &pk1,
        Instant::now() - std::time::Duration::from_secs(25 * 3600),
    )
    .await;

    // 1 mature node: median = 50
    assert_eq!(pm.calculate_network_median_work(), 50);

    pm.learn_node_from_gossip_with_hrw_work_and_auth(pk2, pk2, addr2, 0, None, 150, true)
        .await;
    pm.set_first_seen_for_test(
        &pk2,
        Instant::now() - std::time::Duration::from_secs(25 * 3600),
    )
    .await;

    // 2 mature nodes: median = (50 + 150) / 2 = 100
    assert_eq!(pm.calculate_network_median_work(), 100);
}

#[tokio::test]
async fn test_2_3_large_network_median_21_nodes() {
    let pm = PeerManager::new(vec![]);
    pm.set_simulation_mode(true);
    // Populate 21 mature nodes with work scores 10, 20, 30, ... 210
    for i in 1..=21 {
        let mut pk = [0u8; 32];
        pk[0] = i as u8;
        let addr: SocketAddr = format!("127.0.0.1:{}", 9100 + i).parse().unwrap();
        let work = (i as u64) * 10;
        pm.learn_node_from_gossip_with_hrw_work_and_auth(pk, pk, addr, 0, None, work, true)
            .await;
        pm.set_first_seen_for_test(
            &pk,
            Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    }

    // 21 nodes sorted: element 11 (index 10) is 11 * 10 = 110
    assert_eq!(pm.calculate_network_median_work(), 110);
}

#[tokio::test]
async fn test_2_4_whale_immunity_3_supercomputers() {
    let pm = PeerManager::new(vec![]);
    pm.set_simulation_mode(true);
    // 20 normal nodes with W = 100
    for i in 1..=20 {
        let mut pk = [0u8; 32];
        pk[0] = i as u8;
        let addr: SocketAddr = format!("127.0.0.1:{}", 9200 + i).parse().unwrap();
        pm.learn_node_from_gossip_with_hrw_work_and_auth(pk, pk, addr, 0, None, 100, true)
            .await;
        pm.set_first_seen_for_test(
            &pk,
            Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    }
    assert_eq!(pm.calculate_network_median_work(), 100);

    // Add 3 supercomputers with W = 1_000_000
    for i in 21..=23 {
        let mut pk = [0u8; 32];
        pk[0] = i as u8;
        let addr: SocketAddr = format!("127.0.0.1:{}", 9200 + i).parse().unwrap();
        pm.learn_node_from_gossip_with_hrw_work_and_auth(pk, pk, addr, 0, None, 1_000_000, true)
            .await;
        pm.set_first_seen_for_test(
            &pk,
            Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    }

    // Median of 20x 100 and 3x 1,000,000 (total 23 nodes) -> element at index 11 is STILL 100!
    assert_eq!(pm.calculate_network_median_work(), 100);
}

#[tokio::test]
async fn test_3_1_and_3_2_monotonicity_downgrade_and_lateral_rejected() {
    let pm = PeerManager::new(vec![]);
    pm.set_simulation_mode(true);
    let pk = [0xAA; 32];
    let hrw1 = [0x11; 32];
    let hrw2 = [0x22; 32];
    let hrw_same = [0x33; 32];
    let addr: SocketAddr = "127.0.0.1:9301".parse().unwrap();

    // Initial node with W1 = 100
    pm.learn_node_from_gossip_with_hrw_work_and_auth(pk, hrw1, addr, 0, None, 100, true)
        .await;
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw1);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, None);

    // Test 3.1: Downgrade attempt with W2 = 50 (< 100) -> Rejected
    pm.update_routing_ticket_with_work(pk, hrw2, addr, 50).await;
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw1);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, None);

    // Test 3.2: Lateral hopping attempt with W2 = 100 (== 100) -> Rejected
    pm.update_routing_ticket_with_work(pk, hrw_same, addr, 100)
        .await;
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw1);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, None);
}

#[tokio::test]
async fn test_3_3_monotonicity_upgrade_enters_incubation() {
    let pm = PeerManager::new(vec![]);
    pm.set_simulation_mode(true);
    let pk = [0xBB; 32];
    let hrw1 = [0x11; 32];
    let hrw3 = [0x33; 32];
    let addr: SocketAddr = "127.0.0.1:9302".parse().unwrap();

    pm.learn_node_from_gossip_with_hrw_work_and_auth(pk, hrw1, addr, 0, None, 100, true)
        .await;

    // Test 3.3: Upgrade with W3 = 200 (> 100) -> Accepted into 24h incubation
    pm.update_routing_ticket_with_work(pk, hrw3, addr, 200)
        .await;
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw1);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await.unwrap(), hrw3);

    // After 24h incubation -> hrw3 becomes active with work = 200
    pm.set_pending_since_for_test(
        &pk,
        Instant::now() - std::time::Duration::from_secs(25 * 3600),
    )
    .await;
    let promoted = pm.promote_mature_pending_hrw().await;
    assert_eq!(promoted, 1);
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw3);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, None);
    assert_eq!(pm.get_known_node_info(&pk).await.unwrap().work_score(), 200);
}

#[tokio::test]
async fn test_3_4_pending_race_intermediate_rejected_and_higher_overwrites() {
    let pm = PeerManager::new(vec![]);
    pm.set_simulation_mode(true);
    let pk = [0xCC; 32];
    let hrw1 = [0x11; 32];
    let hrw3 = [0x33; 32];
    let hrw4 = [0x44; 32];
    let hrw5 = [0x55; 32];
    let addr: SocketAddr = "127.0.0.1:9303".parse().unwrap();

    pm.learn_node_from_gossip_with_hrw_work_and_auth(pk, hrw1, addr, 0, None, 100, true)
        .await;

    // W3 = 200 starts incubation
    pm.update_routing_ticket_with_work(pk, hrw3, addr, 200)
        .await;
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await.unwrap(), hrw3);

    // Intermediate attempt W4 = 150 (< W3 = 200) -> Rejected!
    pm.update_routing_ticket_with_work(pk, hrw4, addr, 150)
        .await;
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await.unwrap(), hrw3);

    // Higher attempt W5 = 300 (> W3 = 200) -> Overwrites pending incubation!
    pm.update_routing_ticket_with_work(pk, hrw5, addr, 300)
        .await;
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await.unwrap(), hrw5);
}

#[tokio::test]
async fn test_4_1_and_4_2_f2f_feedback_direct_ack_vs_multihop_drop() {
    let id_a = NodeIdentity::generate();
    let id_b = NodeIdentity::generate();
    let pk_a = *id_a.node_id();
    let pk_b = *id_b.node_id();

    let addr_a: SocketAddr = "127.0.0.1:9401".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:9402".parse().unwrap();

    let pm_b = Arc::new(PeerManager::with_f2f(
        vec![(Some(pk_a), addr_a)],
        vec![pk_a],
    ));
    pm_b.set_simulation_mode(true);

    // Set a high network median on Node B (e.g. 1000)
    for i in 1..=10 {
        let mut pk = [0xDD; 32];
        pk[0] = i as u8;
        let a: SocketAddr = format!("127.0.0.1:{}", 9450 + i).parse().unwrap();
        pm_b.learn_node_from_gossip_with_hrw_work_and_auth(pk, pk, a, 0, None, 1000, true)
            .await;
        pm_b.set_first_seen_for_test(
            &pk,
            Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    }
    assert_eq!(pm_b.calculate_network_median_work(), 1000);

    // Node A's ticket has work = 10 (< 1000 >> 3 = 125 -> Outdated!)
    pm_b.learn_node_from_gossip_with_hrw_work_and_auth(pk_a, pk_a, addr_a, 0, None, 10, true)
        .await;

    let cancel_b = CancellationToken::new();
    let transport_b = QuicTransport::bind_with_options(
        addr_b,
        &id_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .unwrap();
    let _accept_b = transport_b.spawn_accept_loop();

    let pm_a = Arc::new(PeerManager::with_f2f(
        vec![(Some(pk_b), addr_b)],
        vec![pk_b],
    ));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();
    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &id_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .unwrap();
    let _accept_a = transport_a.spawn_accept_loop();

    // Node A sends direct Heartbeat (hops = 0) to Node B
    let conn_a_to_b = transport_a.connect_peer_unchecked(addr_b).await.unwrap();
    let mut hb = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: pk_a,
        addr: addr_a,
        timestamp_ms: 1000,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: pk_a,
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb.sign_origin(&id_a, 1000, humoco_sim_core::types::NetworkId::Mainnet);
    let payload = bincode::serialize(&hb).unwrap();
    let mut header = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload.len() as u32);
    header.reserved = 0; // hops = 0

    transport_a
        .send_unidirectional(&conn_a_to_b, &header, &payload)
        .await
        .unwrap();

    // Give time for uni-stream processing and feedback ack
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Node A must have received HeartbeatAck with FLAG_POW_OUTDATED and updated its ticket_outdated status!
    assert!(
        pm_a.is_ticket_outdated(),
        "Node A must record ticket_outdated == true upon receiving feedback"
    );

    cancel_a.cancel();
    cancel_b.cancel();
}

#[tokio::test]
async fn test_4_3_connection_remains_open_despite_outdated_ticket() {
    let id_a = NodeIdentity::generate();
    let id_b = NodeIdentity::generate();
    let pk_a = *id_a.node_id();
    let pk_b = *id_b.node_id();

    let addr_a: SocketAddr = "127.0.0.1:9501".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:9502".parse().unwrap();

    let pm_b = Arc::new(PeerManager::with_f2f(
        vec![(Some(pk_a), addr_a)],
        vec![pk_a],
    ));
    pm_b.set_ticket_outdated(true); // Node B has outdated ticket

    let cancel_b = CancellationToken::new();
    let transport_b = QuicTransport::bind_with_options(
        addr_b,
        &id_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .unwrap();
    let _accept_b = transport_b.spawn_accept_loop();

    let pm_a = Arc::new(PeerManager::with_f2f(
        vec![(Some(pk_b), addr_b)],
        vec![pk_b],
    ));
    let cancel_a = CancellationToken::new();
    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &id_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .unwrap();
    let _accept_a = transport_a.spawn_accept_loop();

    // Node A connects to Node B -> TLS / F2F handshake succeeds 100%
    let conn = transport_a.connect_peer(addr_b).await;
    assert!(
        conn.is_ok(),
        "F2F connection must succeed regardless of shard ticket status"
    );

    cancel_a.cancel();
    cancel_b.cancel();
}

#[tokio::test]
async fn test_5_1_status_pow_formatting() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("status_test.redb");
    let socket_path = temp.path().join("control.sock");

    let storage = Arc::new(humoco_node::storage::RedbStorage::open(&db_path).unwrap());
    let (engine, _flush) = humoco_node::storage::DualTierEngine::new(storage.clone());
    let mut identity = NodeIdentity::generate();
    for nonce in 1..100 {
        let t0 = 1_700_000_000;
        let proof = humoco_node::identity::compute_pow_proof(identity.node_pubkey(), nonce, t0).unwrap();
        if humoco_sim_core::crypto::compute_work_from_hash(&proof) == 1 {
            identity = NodeIdentity::from_signing_key_with_pow(identity.signing_key().clone(), nonce, t0);
            break;
        }
    }
    let pm = Arc::new(PeerManager::new(vec![]));
    pm.set_simulation_mode(true);

    let cancel = CancellationToken::new();
    let server = humoco_node::control::ControlServer::new(
        socket_path.clone(),
        storage,
        engine,
        pm.clone(),
        identity.clone(),
        temp.path().to_path_buf(),
        cancel.clone(),
    );
    tokio::spawn(async move { server.run().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = humoco_node::control::ControlClient::new(socket_path);
    let resp = client.get_status().await.unwrap();

    match resp {
        humoco_node::control::ControlResponse::Status {
            own_work,
            net_median_work,
            headroom_pct,
            ticket_outdated,
            ..
        } => {
            assert_eq!(own_work, Some(1));
            assert_eq!(net_median_work, Some(1));
            assert_eq!(headroom_pct, Some(100));
            assert!(!ticket_outdated);
        }
        _ => panic!("Expected Status response"),
    }

    // Now test with outdated ticket
    pm.set_ticket_outdated(true);
    let resp2 = client.get_status().await.unwrap();
    match resp2 {
        humoco_node::control::ControlResponse::Status {
            ticket_outdated, ..
        } => {
            assert!(ticket_outdated);
        }
        _ => panic!("Expected Status response"),
    }

    cancel.cancel();
}

#[tokio::test]
async fn test_5_2_doctor_check_7_healthy_and_outdated() {
    let temp = tempfile::tempdir().unwrap();
    let cfg_path = temp.path().join("humoco.toml");
    let mut cfg = humoco_node::config::NodeConfig::default();
    cfg.identity.key_path = temp.path().join("node_key.bin");
    cfg.storage.data_dir = temp.path().join("data");

    let identity = NodeIdentity::generate();
    identity.save_to_file(&cfg.identity.key_path).unwrap();
    std::fs::write(&cfg_path, cfg.generate_toml_template()).unwrap();

    // Doctor offline check
    let res_offline = humoco_node::cli::execute_doctor(Some(cfg_path.clone()), false).await;
    assert!(res_offline.is_ok());

    // Doctor online check with server
    let storage = Arc::new(
        humoco_node::storage::RedbStorage::open(&cfg.storage.data_dir.join("humoco.redb")).unwrap(),
    );
    let (engine, _flush) = humoco_node::storage::DualTierEngine::new(storage.clone());
    let pm = Arc::new(PeerManager::new(vec![]));
    let cancel = CancellationToken::new();

    let server = humoco_node::control::ControlServer::new(
        cfg.control_socket_path(),
        storage,
        engine,
        pm.clone(),
        identity.clone(),
        cfg.storage.data_dir.clone(),
        cancel.clone(),
    );
    tokio::spawn(async move { server.run().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let res_online_healthy = humoco_node::cli::execute_doctor(Some(cfg_path.clone()), false).await;
    assert!(res_online_healthy.is_ok());

    // Mark outdated and re-run
    pm.set_ticket_outdated(true);
    let res_online_outdated = humoco_node::cli::execute_doctor(Some(cfg_path), false).await;
    assert!(res_online_outdated.is_ok());

    cancel.cancel();
}

#[tokio::test]
async fn test_6_1_consensus_time_monotonicity_and_no_inflation_on_rapid_queries() {
    let clock = humoco_node::network::NetworkClock::new();

    // 1. Verify monotonicity across 10,000 queries
    let mut prev = clock.net_time_ms();
    for _ in 0..10_000 {
        let cur = clock.net_time_ms();
        assert!(
            cur >= prev,
            "Consensus time monotonicity violated: cur ({cur}) < prev ({prev})"
        );
        prev = cur;
    }

    // 2. Critical Spec 07 Invariant: 20,000 rapid queries MUST NOT inflate consensus time by seconds!
    let start = clock.net_time_ms();
    for _ in 0..20_000 {
        clock.net_time_ms();
    }
    let end = clock.net_time_ms();
    let drift = end.saturating_sub(start);
    assert!(
        drift < 500,
        "Decoupling failed: 20,000 queries inflated consensus time by {} ms (must be < 500 ms)",
        drift
    );

    // 3. Sequence tie-breaking works without altering consensus time
    let (t1, s1) = clock.next_sequence_time_ms();
    let (t2, s2) = clock.next_sequence_time_ms();
    assert!(t2 >= t1);
    assert_eq!(s2, s1 + 1);
}

#[tokio::test]
async fn test_6_2_mesh_merge_dynamic_clamp_adaptation() {
    let clock = humoco_node::network::NetworkClock::new();

    // Partition separated for 45 minutes (2_700_000 ms > 15-min clamp)
    let partition_offset_ms = 45 * 60 * 1000;
    clock.fast_reseed_on_merge(partition_offset_ms);

    // Logical offset must adapt to the partition merge offset rather than being capped at 15 min
    assert_eq!(clock.logical_offset_ms(), partition_offset_ms);
}

#[tokio::test]
async fn test_6_3_pow_engine_clock_alignment() {
    let clock = Arc::new(humoco_node::network::NetworkClock::new());
    // Move clock into future by 10 minutes (600_000 ms)
    clock.fast_reseed_on_merge(600_000);

    let pow_engine = humoco_node::ingress::pow::PowEngine::new(8).with_clock(clock.clone());

    // Epoch slot must be derived from clock.net_time_ms() rather than naive host SystemTime
    let expected_slot = (clock.net_time_ms() / 1000) / 600;
    let (challenge_hex, diff, exp) = pow_engine.generate_challenge();
    assert_eq!(diff, 8);
    assert!(exp > clock.net_time_ms() / 1000);

    // Verify stateless challenge structure matches expected slot
    let payload = hex::decode(&challenge_hex).unwrap();
    let expected =
        humoco_node::ingress::pow::compute_stateless_challenge(&[0u8; 32], expected_slot);
    assert_eq!(payload.as_slice(), expected.as_slice());
}

#[tokio::test]
async fn test_6_4_pruning_ntp_warp_protection() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("prune_warp_test.redb");
    let storage = Arc::new(humoco_node::storage::RedbStorage::open(&db_path).unwrap());
    let (engine, _flush) = humoco_node::storage::DualTierEngine::new(storage.clone());
    let pm = Arc::new(PeerManager::new(vec![]));
    engine.set_peer_manager(pm.clone()).await;

    // Normal initial prune at t = 1_000_000 ms
    let res1 = engine
        .prune_expired(humoco_sim_core::types::SimTime(1_000_000))
        .await;
    assert!(res1.is_ok());

    // Sudden forward NTP jump by +48 hours (172_800_000 ms) without F2F consensus
    let res2 = engine
        .prune_expired(humoco_sim_core::types::SimTime(1_000_000 + 172_800_000))
        .await;
    assert_eq!(
        res2.unwrap(),
        0,
        "Prune must be rejected on forward jump >24h without F2F corroboration"
    );
}

#[tokio::test]
async fn test_s06_05_u64_floor_median_and_peer_manager_overflow_safety() {
    use humoco_node::network::manager::u64_floor_median;

    // Edge cases for u64_floor_median:
    assert_eq!(u64_floor_median(10, 13), 11);
    assert_eq!(u64_floor_median(13, 10), 11);
    assert_eq!(u64_floor_median(1 << 63, 1 << 63), 1 << 63);
    assert_eq!(u64_floor_median(u64::MAX - 2, u64::MAX), u64::MAX - 1);
    assert_eq!(u64_floor_median(u64::MAX, u64::MAX), u64::MAX);

    // Test PeerManager::calculate_network_median_work without overflow on 2 nodes
    let pm = PeerManager::new(vec![]);
    pm.set_simulation_mode(true);
    let addr1: SocketAddr = "127.0.0.1:9091".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:9092".parse().unwrap();
    let pk1 = [1u8; 32];
    let pk2 = [2u8; 32];

    // Case 1: [1 << 63, 1 << 63]
    pm.learn_node_from_gossip_with_hrw_work_and_auth(pk1, pk1, addr1, 0, None, 1 << 63, true).await;
    pm.learn_node_from_gossip_with_hrw_work_and_auth(pk2, pk2, addr2, 0, None, 1 << 63, true).await;
    pm.set_first_seen_for_test(&pk1, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;
    pm.set_first_seen_for_test(&pk2, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;
    assert_eq!(pm.calculate_network_median_work(), 1 << 63);

    // Case 2: [u64::MAX - 2, u64::MAX]
    pm.set_work_score_for_test(&pk1, u64::MAX - 2).await;
    pm.set_work_score_for_test(&pk2, u64::MAX).await;
    assert_eq!(pm.calculate_network_median_work(), u64::MAX - 1);

    // Case 3: [u64::MAX, u64::MAX]
    pm.set_work_score_for_test(&pk1, u64::MAX).await;
    pm.set_work_score_for_test(&pk2, u64::MAX).await;
    assert_eq!(pm.calculate_network_median_work(), u64::MAX);

    // Case 4: [10, 13]
    pm.set_work_score_for_test(&pk1, 10).await;
    pm.set_work_score_for_test(&pk2, 13).await;
    assert_eq!(pm.calculate_network_median_work(), 11);
}

#[tokio::test]
#[allow(clippy::type_complexity)]
async fn test_s06_06_replacement_ticket_promotion_order_invariance_production_rules() {
    let pk = [0x55u8; 32];
    let hrw1 = [0x11u8; 32];
    let hrw2 = [0x22u8; 32];
    let addr: SocketAddr = "127.0.0.1:9095".parse().unwrap();
    let local_pk = [0x99u8; 32];
    let local_hrw = [0x88u8; 32];

    let setup_node = |test_mode: &str| {
        let pm = PeerManager::new(vec![]);
        pm.set_min_work_floor_for_test(256);
        pm.seed_local_ticket_age(local_pk, local_hrw, std::time::Duration::from_secs(25 * 3600));

        let now = Instant::now();
        let mature_first_seen = now - std::time::Duration::from_secs(25 * 3600);

        // Seed mature & qualified initial ticket (work = 300)
        pm.seed_persisted_ticket_state(pk, hrw1, std::time::Duration::from_secs(25 * 3600), true);

        (pm, now, mature_first_seen, test_mode.to_string())
    };

    // Run 3 instances with different trigger orders:
    // A: Heartbeat-first (learn_node_from_gossip_with_hrw_work_and_auth)
    // B: Getter-first (get_effective_hrw_routing_id)
    // C: Periodic-promotion-first (promote_mature_pending_hrw)
    let modes = ["heartbeat_first", "getter_first", "periodic_promotion_first"];
    let mut results: Vec<(
        &str,
        Option<[u8; 32]>,
        u64,
        bool,
        usize,
        Vec<humoco_sim_core::types::CommitteeMember>,
        Vec<([u8; 32], [u8; 32])>,
    )> = Vec::new();

    for mode in modes {
        let (pm, now, mature_first_seen, _) = setup_node(mode);

        // 1. Initial admission: learn hrw1
        pm.learn_node_from_gossip_with_hrw_work_and_auth_at(
            pk,
            hrw1,
            addr,
            0,
            Some(addr),
            300,
            true,
            mature_first_seen,
        )
        .await;

        // Peer is mature and qualified
        let info_initial = pm.get_known_node_info(&pk).await.unwrap();
        assert!(info_initial.is_initial_admission_qualified());
        assert_eq!(pm.get_effective_hrw_routing_id(&pk).await, Some(hrw1));
        assert_eq!(info_initial.work_score(), 300);

        // 2. Stage stronger replacement ticket hrw2 with work = 600
        pm.learn_node_from_gossip_with_hrw_work_and_auth_at(
            pk,
            hrw2,
            addr,
            0,
            Some(addr),
            600,
            true,
            now,
        )
        .await;

        let _info_pending = pm.get_known_node_info(&pk).await.unwrap();
        assert_eq!(pm.get_effective_hrw_routing_id(&pk).await, Some(hrw1));
        assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, Some(hrw2));

        // Fast-forward pending incubation past 24h
        pm.set_pending_since_for_test(&pk, now - std::time::Duration::from_secs(25 * 3600)).await;

        // 3. Trigger promotion in different orders
        match mode {
            "heartbeat_first" => {
                // Incoming heartbeat triggers promotion in learn_node_from_gossip
                pm.learn_node_from_gossip_with_hrw_work_and_auth_at(
                    pk,
                    hrw2,
                    addr,
                    0,
                    Some(addr),
                    600,
                    true,
                    now,
                )
                .await;
            }
            "getter_first" => {
                // Querying effective HRW triggers promotion
                let effective = pm.get_effective_hrw_routing_id(&pk).await;
                assert_eq!(effective, Some(hrw2));
            }
            "periodic_promotion_first" => {
                // Background daemon ticker triggers promotion
                let promoted = pm.promote_mature_pending_hrw().await;
                assert_eq!(promoted, 1);
            }
            _ => unreachable!(),
        }

        // 4. Capture state after promotion
        let info_after = pm.get_known_node_info(&pk).await.unwrap();
        let effective_hrw = pm.get_effective_hrw_routing_id(&pk).await;
        let (committee, _, total) = pm.shard_committee(local_pk, local_hrw, 42).await;
        let qualified_snapshot = pm.snapshot_qualified_tickets().await;

        results.push((
            mode,
            effective_hrw,
            info_after.work_score(),
            info_after.is_initial_admission_qualified(),
            total,
            committee,
            qualified_snapshot,
        ));
    }

    // Assert that all 3 trigger orders produce identical results
    let (_, eff_0, work_0, qual_0, total_0, comm_0, snap_0) = &results[0];
    assert_eq!(*eff_0, Some(hrw2));
    assert_eq!(*work_0, 600);
    assert!(*qual_0);
    assert_eq!(*total_0, 2);

    for (mode, eff, work, qual, total, comm, snap) in &results[1..] {
        assert_eq!(*eff, *eff_0, "Mode {mode} effective HRW mismatch");
        assert_eq!(*work, *work_0, "Mode {mode} work score mismatch");
        assert_eq!(*qual, *qual_0, "Mode {mode} qualification mismatch");
        assert_eq!(*total, *total_0, "Mode {mode} total eligible mismatch");
        assert_eq!(comm.len(), comm_0.len(), "Mode {mode} committee size mismatch");
        assert_eq!(snap.len(), snap_0.len(), "Mode {mode} snapshot size mismatch");
    }
}

#[tokio::test]
async fn test_s06_06_admitted_peer_activates_replacement_ticket_over_real_quic_heartbeat() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).with_test_writer().try_init();
    let (id_a, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine ticket a v1");
    let (id_b, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine ticket b");

    let pk_a = *id_a.node_pubkey();
    let pk_b = *id_b.node_pubkey();
    let hrw_a_v1 = *id_a.hrw_routing_id();
    let hrw_b = *id_b.hrw_routing_id();

    let addr_a: SocketAddr = "127.0.0.1:9851".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:9852".parse().unwrap();

    let cancel_b = CancellationToken::new();
    let pm_b = Arc::new(PeerManager::with_f2f(
        vec![(Some(pk_a), addr_a)],
        vec![pk_a],
    ));
    pm_b.set_simulation_mode(true);
    pm_b.seed_local_ticket_age(pk_b, hrw_b, std::time::Duration::from_secs(25 * 3600));
    // Seed Node A as mature & qualified on Node B
    pm_b.seed_persisted_ticket_state(pk_a, hrw_a_v1, std::time::Duration::from_secs(25 * 3600), true);

    let transport_b = QuicTransport::bind_with_options(
        addr_b,
        &id_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .unwrap();
    let _accept_b = transport_b.spawn_accept_loop();

    let cancel_a = CancellationToken::new();
    let pm_a = Arc::new(PeerManager::with_f2f(
        vec![(Some(pk_b), addr_b)],
        vec![pk_b],
    ));
    pm_a.set_simulation_mode(true);

    let shared_id_a = Arc::new(parking_lot::RwLock::new(id_a.clone()));
    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &id_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .unwrap()
    .with_shared_identity(shared_id_a.clone());
    let _accept_a = transport_a.spawn_accept_loop();

    // 1. Node A sends signed QUIC heartbeat with initial ticket hrw_a_v1
    transport_a
        .send_heartbeat_to(addr_b, addr_a, 1, 0, 0, 1000, vec![])
        .await
        .unwrap();

    // Deterministically await Node B learning Node A
    let deadline = Instant::now() + std::time::Duration::from_secs(3);
    while Instant::now() < deadline {
        if pm_b.get_known_node_info(&pk_a).await.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // Node B must recognize Node A as admitted and committee-eligible with hrw_a_v1
    assert_eq!(pm_b.get_effective_hrw_routing_id(&pk_a).await, Some(hrw_a_v1));
    let (comm1, _, total1) = pm_b.shard_committee(pk_b, hrw_b, 42).await;
    assert_eq!(total1, 2, "Node A and Node B must both be committee eligible");
    assert!(comm1.iter().any(|m| m.node_pubkey == pk_a && m.hrw_routing_id == hrw_a_v1));

    // 2. Node A mines a stronger replacement ticket
    let (id_a_v2, _) = id_a
        .mine_ticket(id_a.work_score() + 1, 1_750_000_000, Some(500))
        .expect("mine ticket a v2");
    let hrw_a_v2 = *id_a_v2.hrw_routing_id();
    assert_ne!(hrw_a_v1, hrw_a_v2);
    assert!(id_a_v2.work_score() > id_a.work_score());

    // Update shared identity on Node A
    *shared_id_a.write() = id_a_v2.clone();

    // 3. Node A sends signed QUIC heartbeat with replacement ticket
    transport_a
        .send_heartbeat_to(addr_b, addr_a, 2, 0, 0, 2000, vec![])
        .await
        .unwrap();

    // Deterministically await Node B staging hrw_a_v2 as pending
    let deadline2 = Instant::now() + std::time::Duration::from_secs(3);
    while Instant::now() < deadline2 {
        if pm_b.get_pending_hrw_routing_id(&pk_a).await.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // Node B must have staged hrw_a_v2 as pending while hrw_a_v1 remains active
    assert_eq!(pm_b.get_effective_hrw_routing_id(&pk_a).await, Some(hrw_a_v1));
    assert_eq!(pm_b.get_pending_hrw_routing_id(&pk_a).await, Some(hrw_a_v2));
    assert!(pm_b.hrw_incubation_remaining(&pk_a).await.is_some());

    // 4. Fast-forward pending incubation past 24h
    pm_b.set_pending_since_for_test(&pk_a, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;

    // 5. Node A sends next signed QUIC heartbeat -> triggers promotion!
    transport_a
        .send_heartbeat_to(addr_b, addr_a, 3, 0, 0, 3000, vec![])
        .await
        .unwrap();

    // Deterministically await promotion
    let deadline3 = Instant::now() + std::time::Duration::from_secs(3);
    while Instant::now() < deadline3 {
        if pm_b.get_effective_hrw_routing_id(&pk_a).await == Some(hrw_a_v2) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // Node B now has hrw_a_v2 active, and Node A REMAINS committee eligible!
    assert_eq!(pm_b.get_effective_hrw_routing_id(&pk_a).await, Some(hrw_a_v2));
    assert_eq!(pm_b.get_pending_hrw_routing_id(&pk_a).await, None);

    let (comm2, _, total2) = pm_b.shard_committee(pk_b, hrw_b, 42).await;
    assert_eq!(total2, 2, "Node A must remain committee eligible with replacement ticket");
    assert!(comm2.iter().any(|m| m.node_pubkey == pk_a && m.hrw_routing_id == hrw_a_v2));

    cancel_a.cancel();
    cancel_b.cancel();
}
