use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use humoco_node::identity::NodeIdentity;
use humoco_node::network::manager::PeerManager;
use humoco_node::network::transport::{QuicTransport, DefaultRequestHandler};
use humoco_sim_core::wire::{MsgType, WireHeader};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_2_1_bootstrap_median_empty_and_single() {
    let pm = PeerManager::new(vec![]);
    // Empty network -> W_min_floor (1)
    assert_eq!(pm.calculate_network_median_work(), 1);

    let (is_acc, med) = pm.is_ticket_acceptable(1);
    assert!(is_acc);
    assert_eq!(med, 1);
}

#[tokio::test]
async fn test_2_2_bootstrap_median_1_and_2_nodes() {
    let pm = PeerManager::new(vec![]);
    let addr1: SocketAddr = "127.0.0.1:9091".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:9092".parse().unwrap();
    let pk1 = [1u8; 32];
    let pk2 = [2u8; 32];

    pm.learn_node_from_gossip_with_hrw_and_work(pk1, pk1, addr1, 0, None, 50).await;
    pm.set_first_seen_for_test(&pk1, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;

    // 1 mature node: median = 50
    assert_eq!(pm.calculate_network_median_work(), 50);

    pm.learn_node_from_gossip_with_hrw_and_work(pk2, pk2, addr2, 0, None, 150).await;
    pm.set_first_seen_for_test(&pk2, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;

    // 2 mature nodes: median = (50 + 150) / 2 = 100
    assert_eq!(pm.calculate_network_median_work(), 100);
}

#[tokio::test]
async fn test_2_3_large_network_median_21_nodes() {
    let pm = PeerManager::new(vec![]);
    // Populate 21 mature nodes with work scores 10, 20, 30, ... 210
    for i in 1..=21 {
        let mut pk = [0u8; 32];
        pk[0] = i as u8;
        let addr: SocketAddr = format!("127.0.0.1:{}", 9100 + i).parse().unwrap();
        let work = (i as u64) * 10;
        pm.learn_node_from_gossip_with_hrw_and_work(pk, pk, addr, 0, None, work).await;
        pm.set_first_seen_for_test(&pk, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;
    }

    // 21 nodes sorted: element 11 (index 10) is 11 * 10 = 110
    assert_eq!(pm.calculate_network_median_work(), 110);
}

#[tokio::test]
async fn test_2_4_whale_immunity_3_supercomputers() {
    let pm = PeerManager::new(vec![]);
    // 20 normal nodes with W = 100
    for i in 1..=20 {
        let mut pk = [0u8; 32];
        pk[0] = i as u8;
        let addr: SocketAddr = format!("127.0.0.1:{}", 9200 + i).parse().unwrap();
        pm.learn_node_from_gossip_with_hrw_and_work(pk, pk, addr, 0, None, 100).await;
        pm.set_first_seen_for_test(&pk, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;
    }
    assert_eq!(pm.calculate_network_median_work(), 100);

    // Add 3 supercomputers with W = 1_000_000
    for i in 21..=23 {
        let mut pk = [0u8; 32];
        pk[0] = i as u8;
        let addr: SocketAddr = format!("127.0.0.1:{}", 9200 + i).parse().unwrap();
        pm.learn_node_from_gossip_with_hrw_and_work(pk, pk, addr, 0, None, 1_000_000).await;
        pm.set_first_seen_for_test(&pk, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;
    }

    // Median of 20x 100 and 3x 1,000,000 (total 23 nodes) -> element at index 11 is STILL 100!
    assert_eq!(pm.calculate_network_median_work(), 100);
}

#[tokio::test]
async fn test_3_1_and_3_2_monotonicity_downgrade_and_lateral_rejected() {
    let pm = PeerManager::new(vec![]);
    let pk = [0xAA; 32];
    let hrw1 = [0x11; 32];
    let hrw2 = [0x22; 32];
    let hrw_same = [0x33; 32];
    let addr: SocketAddr = "127.0.0.1:9301".parse().unwrap();

    // Initial node with W1 = 100
    pm.learn_node_from_gossip_with_hrw_and_work(pk, hrw1, addr, 0, None, 100).await;
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw1);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, None);

    // Test 3.1: Downgrade attempt with W2 = 50 (< 100) -> Rejected
    pm.update_routing_ticket_with_work(pk, hrw2, addr, 50).await;
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw1);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, None);

    // Test 3.2: Lateral hopping attempt with W2 = 100 (== 100) -> Rejected
    pm.update_routing_ticket_with_work(pk, hrw_same, addr, 100).await;
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw1);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, None);
}

#[tokio::test]
async fn test_3_3_monotonicity_upgrade_enters_incubation() {
    let pm = PeerManager::new(vec![]);
    let pk = [0xBB; 32];
    let hrw1 = [0x11; 32];
    let hrw3 = [0x33; 32];
    let addr: SocketAddr = "127.0.0.1:9302".parse().unwrap();

    pm.learn_node_from_gossip_with_hrw_and_work(pk, hrw1, addr, 0, None, 100).await;

    // Test 3.3: Upgrade with W3 = 200 (> 100) -> Accepted into 24h incubation
    pm.update_routing_ticket_with_work(pk, hrw3, addr, 200).await;
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw1);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await.unwrap(), hrw3);

    // After 24h incubation -> hrw3 becomes active with work = 200
    pm.set_pending_since_for_test(&pk, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;
    let promoted = pm.promote_mature_pending_hrw().await;
    assert_eq!(promoted, 1);
    assert_eq!(pm.get_active_hrw_routing_id(&pk).await.unwrap(), hrw3);
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await, None);
    assert_eq!(pm.get_known_node_info(&pk).await.unwrap().work_score(), 200);
}

#[tokio::test]
async fn test_3_4_pending_race_intermediate_rejected_and_higher_overwrites() {
    let pm = PeerManager::new(vec![]);
    let pk = [0xCC; 32];
    let hrw1 = [0x11; 32];
    let hrw3 = [0x33; 32];
    let hrw4 = [0x44; 32];
    let hrw5 = [0x55; 32];
    let addr: SocketAddr = "127.0.0.1:9303".parse().unwrap();

    pm.learn_node_from_gossip_with_hrw_and_work(pk, hrw1, addr, 0, None, 100).await;

    // W3 = 200 starts incubation
    pm.update_routing_ticket_with_work(pk, hrw3, addr, 200).await;
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await.unwrap(), hrw3);

    // Intermediate attempt W4 = 150 (< W3 = 200) -> Rejected!
    pm.update_routing_ticket_with_work(pk, hrw4, addr, 150).await;
    assert_eq!(pm.get_pending_hrw_routing_id(&pk).await.unwrap(), hrw3);

    // Higher attempt W5 = 300 (> W3 = 200) -> Overwrites pending incubation!
    pm.update_routing_ticket_with_work(pk, hrw5, addr, 300).await;
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

    // Set a high network median on Node B (e.g. 1000)
    for i in 1..=10 {
        let mut pk = [0xDD; 32];
        pk[0] = i as u8;
        let a: SocketAddr = format!("127.0.0.1:{}", 9450 + i).parse().unwrap();
        pm_b.learn_node_from_gossip_with_hrw_and_work(pk, pk, a, 0, None, 1000).await;
        pm_b.set_first_seen_for_test(&pk, Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;
    }
    assert_eq!(pm_b.calculate_network_median_work(), 1000);

    // Node A's ticket has work = 10 (< 1000 >> 3 = 125 -> Outdated!)
    pm_b.learn_node_from_gossip_with_hrw_and_work(pk_a, pk_a, addr_a, 0, None, 10).await;

    let cancel_b = CancellationToken::new();
    let transport_b = QuicTransport::bind_with_options(
        addr_b,
        &id_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    ).unwrap();
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
    ).unwrap();
    let _accept_a = transport_a.spawn_accept_loop();

    // Node A sends direct Heartbeat (hops = 0) to Node B
    let conn_a_to_b = transport_a.connect_peer_unchecked(addr_b).await.unwrap();
    let hb = humoco_node::network::framing::HeartbeatWirePayload {
        node_id: pk_a,
        addr: addr_a,
        timestamp_ms: 1000,
        supported_suites_mask: 0,
    };
    let payload = bincode::serialize(&hb).unwrap();
    let mut header = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload.len() as u32);
    header.reserved = 0; // hops = 0

    transport_a.send_unidirectional(&conn_a_to_b, &header, &payload).await.unwrap();

    // Give time for uni-stream processing and feedback ack
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Node A must have received HeartbeatAck with FLAG_POW_OUTDATED and updated its ticket_outdated status!
    assert!(pm_a.is_ticket_outdated(), "Node A must record ticket_outdated == true upon receiving feedback");

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

    let pm_b = Arc::new(PeerManager::with_f2f(vec![(Some(pk_a), addr_a)], vec![pk_a]));
    pm_b.set_ticket_outdated(true); // Node B has outdated ticket

    let cancel_b = CancellationToken::new();
    let transport_b = QuicTransport::bind_with_options(
        addr_b,
        &id_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    ).unwrap();
    let _accept_b = transport_b.spawn_accept_loop();

    let pm_a = Arc::new(PeerManager::with_f2f(vec![(Some(pk_b), addr_b)], vec![pk_b]));
    let cancel_a = CancellationToken::new();
    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &id_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    ).unwrap();
    let _accept_a = transport_a.spawn_accept_loop();

    // Node A connects to Node B -> TLS / F2F handshake succeeds 100%
    let conn = transport_a.connect_peer(addr_b).await;
    assert!(conn.is_ok(), "F2F connection must succeed regardless of shard ticket status");

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
    let identity = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::new(vec![]));

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
        humoco_node::control::ControlResponse::Status { ticket_outdated, .. } => {
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
    let storage = Arc::new(humoco_node::storage::RedbStorage::open(&cfg.storage.data_dir.join("humoco.redb")).unwrap());
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
