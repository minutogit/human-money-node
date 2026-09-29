use std::net::SocketAddr;
use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::{
    api::{build_router, AppState},
    control::{parse_account_tag, ControlClient, ControlResponse, ControlServer},
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::PeerManager,
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::types::{LockRecord, SimTime};

#[tokio::test]
async fn test_control_socket_status_and_peers() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("control_test.redb");
    let socket_path = temp.path().join("control.sock");

    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();

    // Configure peers
    let addr1: SocketAddr = "127.0.0.1:9090".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:9092".parse().unwrap();
    let peer_manager = Arc::new(PeerManager::new(vec![addr1, addr2]));

    // Mark addr1 as connected
    peer_manager.record_success(addr1, Some([9u8; 32]), None).await;

    // Add a lock to engine RAM
    let record = LockRecord::new(
        [1u8; 32],
        [2u8; 32],
        b"nonce1".to_vec(),
        SimTime(100),
        SimTime(60_000),
    );
    let _ = engine.ingress_lock(record, SimTime(100), SimTime(600_000)).await;

    let cancel_token = CancellationToken::new();
    let server = ControlServer::new(
        socket_path.clone(),
        storage.clone(),
        engine.clone(),
        peer_manager.clone(),
        identity.clone(),
        temp.path().to_path_buf(),
        cancel_token.clone(),
    );

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    // Give server a brief moment to bind Unix socket
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client = ControlClient::new(socket_path.clone());

    // 1. Get Status
    let status_res = client.get_status().await.expect("get_status");
    match status_res {
        ControlResponse::Status {
            node_id,
            public_key,
            hrw_routing_id,
            routing_id,
            t0,
            nonce,
            incubation_until_ms,
            uptime_sec: _,
            active_locks,
            peers_connected,
            data_dir,
            ..
        } => {
            assert_eq!(node_id, identity.node_id_hex());
            assert_eq!(public_key, Some(identity.public_key_hex()));
            assert_eq!(hrw_routing_id, Some(identity.hrw_routing_id_hex()));
            assert_eq!(routing_id, Some(identity.hrw_routing_id_hex()));
            assert_eq!(t0, Some(identity.t0()));
            assert_eq!(nonce, Some(identity.nonce()));
            // incubation_until_ms should be consistent with t0
            if let Some(t) = t0 {
                if t == 0 {
                    assert_eq!(incubation_until_ms, None);
                } else {
                    assert!(incubation_until_ms.is_some());
                }
            }
            assert_eq!(active_locks, 1);
            assert_eq!(peers_connected, 1);
            assert_eq!(data_dir, temp.path());
        }
        other => panic!("Unexpected response: {:?}", other),
    }

    // 2. List Peers
    let peers = client.list_peers().await.expect("list_peers");
    assert_eq!(peers.len(), 2);
    let p1 = peers.iter().find(|p| p.addr == addr1.to_string()).unwrap();
    assert_eq!(p1.status, "Connected");
    assert_eq!(p1.node_id, Some(hex::encode([9u8; 32])));
    assert_eq!(p1.missing_count, 0);

    let p2 = peers.iter().find(|p| p.addr == addr2.to_string()).unwrap();
    assert_eq!(p2.status, "Degrading");

    // Test get_db_stats
    let db_stats = client.get_db_stats().await.expect("get_db_stats");
    assert_eq!(db_stats.active_locks, 1);
    assert!(db_stats.db_size_bytes > 0);

    // Test remove_peer
    let removed = client.remove_peer(&addr2.to_string()).await.expect("remove_peer");
    assert!(!removed.is_empty());
    let peers_after = client.list_peers().await.expect("list_peers after remove");
    assert_eq!(peers_after.len(), 1);

    // 3. Shutdown
    client.shutdown(5).await.expect("shutdown");
    let server_res = server_handle.await.expect("server handle join");
    assert!(server_res.is_ok());

    // Verify socket file is cleaned up
    assert!(!socket_path.exists());
}

#[tokio::test]
async fn test_control_quota_topup_and_get() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("quota_test.redb");
    let socket_path = temp.path().join("quota_control.sock");

    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let peer_manager = Arc::new(PeerManager::new(vec![]));

    let cancel_token = CancellationToken::new();
    let server = ControlServer::new(
        socket_path.clone(),
        storage.clone(),
        engine.clone(),
        peer_manager.clone(),
        identity.clone(),
        temp.path().to_path_buf(),
        cancel_token.clone(),
    );

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client = ControlClient::new(socket_path.clone());

    let account_tag = "vip_partner_charlie";
    let tag_bytes = parse_account_tag(account_tag);

    // Initial quota should be 0
    let balance_init = client.get_quota(account_tag).await.expect("get initial quota");
    assert_eq!(balance_init, 0);

    // Topup 10_000 byte-years
    let balance_after_1 = client.topup_quota(account_tag, 10_000).await.expect("topup 10k");
    assert_eq!(balance_after_1, 10_000);

    // Query quota again
    let balance_check = client.get_quota(account_tag).await.expect("get quota check");
    assert_eq!(balance_check, 10_000);

    // Topup another 5_500 byte-years
    let balance_after_2 = client.topup_quota(account_tag, 5_500).await.expect("topup 5.5k");
    assert_eq!(balance_after_2, 15_500);

    // Verify direct RedbStorage persistence
    let stored_quota = storage.get_quota(&tag_bytes).expect("storage get quota");
    assert_eq!(stored_quota, 15_500);

    // Shutdown
    client.shutdown(5).await.expect("shutdown");
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_prometheus_metrics_endpoint() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("metrics_test.redb");

    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
    let peer_manager = Arc::new(PeerManager::new(vec![addr]));
    peer_manager.record_success(addr, Some([5u8; 32]), None).await;

    // Add 2 active locks to RAM
    let lock1 = LockRecord::new(
        [10u8; 32],
        [11u8; 32],
        b"nonce_m1".to_vec(),
        SimTime(0),
        SimTime(60_000),
    );
    let lock2 = LockRecord::new(
        [20u8; 32],
        [21u8; 32],
        b"nonce_m2".to_vec(),
        SimTime(0),
        SimTime(60_000),
    );
    let _ = engine.ingress_lock(lock1, SimTime(0), SimTime(600_000)).await;
    let _ = engine.ingress_lock(lock2, SimTime(0), SimTime(600_000)).await;

    let app_state = AppState {
        engine,
        storage,
        identity,
        tier_controller,
        pow_engine,
        peer_manager: Some(peer_manager),
        transport: None,
        start_time: std::time::Instant::now(),
        metrics: Arc::new(humoco_node::api::metrics::NodeMetrics::default()),
        lifecycle: humoco_node::config::LifecycleConfig::default(),
        network_id: humoco_sim_core::types::NetworkId::default(),
        shard_query_depth: 3,
    };

    let router = build_router(app_state);

    let req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();

    let res = router.oneshot(req).await.expect("execute /metrics request");
    assert_eq!(res.status(), StatusCode::OK);

    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap();
    assert!(content_type.contains("text/plain"));

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    // Verify OpenMetrics / Prometheus metrics format and values
    assert!(body_str.contains("# HELP humoco_locks_active_total Total number of active locks in memory"));
    assert!(body_str.contains("# TYPE humoco_locks_active_total gauge"));
    assert!(body_str.contains("humoco_locks_active_total 2"));

    assert!(body_str.contains("# HELP humoco_p2p_connected_peers Number of active connected peers"));
    assert!(body_str.contains("# TYPE humoco_p2p_connected_peers gauge"));
    assert!(body_str.contains("humoco_p2p_connected_peers 1"));

    assert!(body_str.contains("# HELP humoco_node_uptime_seconds Total uptime of the node"));
    assert!(body_str.contains("# TYPE humoco_node_uptime_seconds counter"));
    assert!(body_str.contains("humoco_node_uptime_seconds "));
}

#[tokio::test]
async fn test_control_server_idle_client_and_cancellation() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("idle_control_test.redb");
    let socket_path = temp.path().join("idle_control.sock");

    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let peer_manager = Arc::new(PeerManager::new(vec![]));
    let cancel_token = CancellationToken::new();

    let server = ControlServer::new(
        socket_path.clone(),
        storage.clone(),
        engine.clone(),
        peer_manager.clone(),
        identity.clone(),
        temp.path().to_path_buf(),
        cancel_token.clone(),
    );

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Connect a hanging client that never sends a newline or command
    let client_stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("connect hanging client");

    // Signal cancellation while client is still connected and idle
    cancel_token.cancel();

    // Server should shut down promptly without getting stuck on the idle client connection
    let shutdown_res = tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    assert!(shutdown_res.is_ok(), "Server must not hang on cancellation with active idle client");
    let inner_res = shutdown_res.unwrap().expect("join server");
    assert!(inner_res.is_ok());

    drop(client_stream);
}

#[tokio::test]
async fn test_control_extensions_batch3() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("batch3_test.redb");
    let socket_path = temp.path().join("batch3_control.sock");

    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let peer_manager = Arc::new(PeerManager::new(vec![]));
    let cancel_token = CancellationToken::new();

    let server = ControlServer::new(
        socket_path.clone(),
        storage.clone(),
        engine.clone(),
        peer_manager.clone(),
        identity.clone(),
        temp.path().to_path_buf(),
        cancel_token.clone(),
    );

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client = ControlClient::new(socket_path.clone());

    // 1. Test add_peer
    let peer_identity = NodeIdentity::generate();
    let peer_str = format!("{}@127.0.0.1:9099", peer_identity.public_key_hex());
    let resp = client.add_peer(&peer_str).await.expect("add_peer ip");
    assert_eq!(resp, ControlResponse::PeerAdded);

    // Verify peer manager registered F2F friend
    let is_friend = peer_manager.is_f2f_friend(peer_identity.node_id()).await;
    assert!(is_friend, "Peer must be registered as F2F friend");

    // Add DNS peer
    let dns_peer_str = format!("{}@test.humoco.invalid:9090", peer_identity.public_key_hex());
    let resp_dns = client.add_peer(&dns_peer_str).await.expect("add_peer dns");
    assert_eq!(resp_dns, ControlResponse::PeerAdded);
    let dns_peers = peer_manager.list_dns_peers().await;
    assert!(!dns_peers.is_empty(), "DNS peers should contain added entry");

    // 2. Ingress lock and test get_recent_locks
    let parent = [42u8; 32];
    let child = [43u8; 32];
    let record = LockRecord::new(
        parent,
        child,
        b"nonce_b3".to_vec(),
        SimTime(500),
        SimTime(100_000),
    );
    let lock_id = record.id;
    let _ = engine.ingress_lock(record, SimTime(500), SimTime(500_000)).await;

    let recent_resp = client.get_recent_locks(10).await.expect("get_recent_locks");
    match recent_resp {
        ControlResponse::RecentLocks { locks } => {
            assert!(!locks.is_empty());
            assert_eq!(locks[0].parent_lock_hex, hex::encode(parent));
            assert_eq!(locks[0].child_lock_hex, hex::encode(lock_id));
        }
        other => panic!("Expected RecentLocks, got: {:?}", other),
    }

    // 3. Test inspect_lock
    let parent_hex = hex::encode(parent);
    let insp_resp = client.inspect_lock(&parent_hex).await.expect("inspect_lock");
    match insp_resp {
        ControlResponse::LockInspection { inspection } => {
            let insp = inspection.expect("inspection found");
            assert_eq!(insp.parent_lock_hex, parent_hex);
            assert_eq!(insp.lock_id_hex, hex::encode(lock_id));
            assert_eq!(insp.created_at_ms, 500);
            assert_eq!(insp.valid_until_ms, 100_000);
        }
        other => panic!("Expected LockInspection, got: {:?}", other),
    }

    // Query non-existent lock
    let non_existent_hex = hex::encode([99u8; 32]);
    let insp_none = client.inspect_lock(&non_existent_hex).await.expect("inspect non existent");
    assert_eq!(insp_none, ControlResponse::LockInspection { inspection: None });

    // Query invalid hex string
    let insp_err = client.inspect_lock("not-a-valid-hex").await.expect("inspect invalid hex");
    assert!(matches!(insp_err, ControlResponse::Error { .. }));

    // 4. Test create_backup
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let backup_path = temp.path().join("backup_destination.redb");
    let backup_str = backup_path.display().to_string();
    let backup_resp = client.create_backup(&backup_str).await.expect("create_backup");
    match backup_resp {
        ControlResponse::BackupCreated { path, locks_count } => {
            assert_eq!(path, backup_str);
            assert!(locks_count >= 1);
        }
        other => panic!("Expected BackupCreated, got: {:?}", other),
    }
    assert!(backup_path.exists());

    // Verify backup file can be read
    let backup_storage = RedbStorage::open(&backup_path).expect("open backup");
    let (backed_up_rec, root_valid) = backup_storage.get_lock(&parent).expect("get_lock").expect("found");
    assert_eq!(backed_up_rec.id, lock_id);
    assert_eq!(backed_up_rec.receiver_pub, child);
    assert_eq!(root_valid, 500_000);

    // Shutdown
    client.shutdown(5).await.expect("shutdown");
    let _ = server_handle.await;
}
