use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::{
    api::AppState,
    control::{parse_account_tag, ControlClient, ControlResponse, ControlServer},
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::PeerManager,
    storage::{DualTierEngine, RedbStorage},
};

fn make_control_root(voucher_id: &str, t_id: [u8; 32]) -> (String, humoco_node::api::hmc::L2LockEntry) {
    let tag = bs58::encode(t_id).into_string();
    let entry = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id,
        layer2_voucher_id: voucher_id.to_string(),
        sender_ephemeral_pub: [0x11; 32],
        layer2_signature: [0x22; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1000,
        created_at_ms: 1000,
        deletable_at: Some("600000".to_string()),
        privacy_guard: None,
    };
    (tag, entry)
}

fn make_control_spend(voucher_id: &str, t_id: [u8; 32]) -> (String, humoco_node::api::hmc::L2LockEntry) {
    let tag = bs58::encode(t_id).into_string();
    let entry = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id,
        layer2_voucher_id: voucher_id.to_string(),
        sender_ephemeral_pub: [0x33; 32],
        layer2_signature: [0x44; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1000,
        created_at_ms: 500,
        deletable_at: None,
        privacy_guard: None,
    };
    (tag, entry)
}

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
    peer_manager
        .record_success(addr1, Some([9u8; 32]), None)
        .await;

    // Add a lock to engine RAM
    let (root_tag, root) = make_control_root("v_ctrl", [1u8; 32]);
    let (spend_tag, spend) = make_control_spend("v_ctrl", [2u8; 32]);
    let _ = engine.ingress_hmc_lock(root_tag, root).await;
    let _ = engine.ingress_hmc_lock(spend_tag, spend).await;

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

    let server_handle = tokio::spawn(async move { server.run().await });

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
    let removed = client
        .remove_peer(&addr2.to_string())
        .await
        .expect("remove_peer");
    assert!(removed.is_empty());
    let peers_after = client.list_peers().await.expect("list_peers after remove");
    assert_eq!(peers_after.len(), 1);

    // 3. Shutdown
    assert!(matches!(
        client
            .send_request(humoco_node::ControlRequest::Shutdown)
            .await
            .expect("shutdown acceptance"),
        ControlResponse::Ok
    ));
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

    let server_handle = tokio::spawn(async move { server.run().await });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client = ControlClient::new(socket_path.clone());

    let account_tag = "vip_partner_charlie";
    let tag_bytes = parse_account_tag(account_tag);

    // Initial quota should be 0
    let balance_init = client
        .get_quota(account_tag)
        .await
        .expect("get initial quota");
    assert_eq!(balance_init, 0);

    // Topup 10_000 byte-years
    let balance_after_1 = client
        .topup_quota(account_tag, 10_000)
        .await
        .expect("topup 10k");
    assert_eq!(balance_after_1, 10_000);

    // Query quota again
    let balance_check = client
        .get_quota(account_tag)
        .await
        .expect("get quota check");
    assert_eq!(balance_check, 10_000);

    // Topup another 5_500 byte-years
    let balance_after_2 = client
        .topup_quota(account_tag, 5_500)
        .await
        .expect("topup 5.5k");
    assert_eq!(balance_after_2, 15_500);

    // Verify direct RedbStorage persistence
    let stored_quota = storage.get_quota(&tag_bytes).expect("storage get quota");
    assert_eq!(stored_quota, 15_500);

    // Shutdown
    assert!(matches!(
        client
            .send_request(humoco_node::ControlRequest::Shutdown)
            .await
            .expect("shutdown acceptance"),
        ControlResponse::Ok
    ));
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
    peer_manager
        .record_success(addr, Some([5u8; 32]), None)
        .await;

    // Add 2 active locks to RAM
    let (root1_tag, root1) = make_control_root("v_m1", [10u8; 32]);
    let (spend1_tag, spend1) = make_control_spend("v_m1", [11u8; 32]);
    let _ = engine.ingress_hmc_lock(root1_tag, root1).await;
    let _ = engine.ingress_hmc_lock(spend1_tag, spend1).await;

    let (root2_tag, root2) = make_control_root("v_m2", [20u8; 32]);
    let (spend2_tag, spend2) = make_control_spend("v_m2", [21u8; 32]);
    let _ = engine.ingress_hmc_lock(root2_tag, root2).await;
    let _ = engine.ingress_hmc_lock(spend2_tag, spend2).await;

    let mut app_state = AppState::new(engine, storage, identity, tier_controller, pow_engine);
    app_state.peer_manager = Some(peer_manager);

    let router = humoco_node::api::routes::build_operator_router(app_state);

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
    assert!(body_str
        .contains("# HELP humoco_locks_active_total Total number of active locks in memory"));
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

    let server_handle = tokio::spawn(async move { server.run().await });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Connect a hanging client that never sends a newline or command
    let client_stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("connect hanging client");

    // Signal cancellation while client is still connected and idle
    cancel_token.cancel();

    // Server should shut down promptly without getting stuck on the idle client connection
    let shutdown_res =
        tokio::time::timeout(tokio::time::Duration::from_secs(2), server_handle).await;
    assert!(
        shutdown_res.is_ok(),
        "Server must not hang on cancellation with active idle client"
    );
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

    let server_handle = tokio::spawn(async move { server.run().await });

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
    let dns_peer_str = format!(
        "{}@test.humoco.invalid:9090",
        peer_identity.public_key_hex()
    );
    let resp_dns = client.add_peer(&dns_peer_str).await.expect("add_peer dns");
    assert_eq!(resp_dns, ControlResponse::PeerAdded);
    let dns_peers = peer_manager.list_dns_peers().await;
    assert!(
        !dns_peers.is_empty(),
        "DNS peers should contain added entry"
    );

    // 2. Ingress lock and test get_recent_locks
    let parent = [42u8; 32];
    let parent_hex = hex::encode(parent);
    let (root_tag, root) = make_control_root("v_inspect", [41u8; 32]);
    let (_, mut spend) = make_control_spend("v_inspect", [43u8; 32]);
    spend.sender_ephemeral_pub = [44u8; 32];
    let lock_id = spend.t_id;
    let _ = engine.ingress_hmc_lock(root_tag, root).await;
    let _ = engine.ingress_hmc_lock(parent_hex.clone(), spend).await;

    let recent_resp = client.get_recent_locks(10).await.expect("get_recent_locks");
    match recent_resp {
        ControlResponse::RecentLocks { locks } => {
            assert!(!locks.is_empty());
            assert_eq!(locks[0].parent_lock_hex, parent_hex);
            assert_eq!(locks[0].child_lock_hex, hex::encode(lock_id));
        }
        other => panic!("Expected RecentLocks, got: {:?}", other),
    }

    // 3. Test inspect_lock
    let insp_resp = client
        .inspect_lock(&parent_hex)
        .await
        .expect("inspect_lock");
    match insp_resp {
        ControlResponse::LockInspection { inspection } => {
            let insp = inspection.expect("inspection found");
            assert_eq!(insp.parent_lock_hex, parent_hex);
            assert_eq!(insp.lock_id_hex, hex::encode(lock_id));
            assert_eq!(insp.valid_until_ms, 600_000);
            assert_eq!(insp.status, "Verified");
        }
        other => panic!("Expected LockInspection, got: {:?}", other),
    }

    // Query non-existent lock
    let non_existent_hex = hex::encode([99u8; 32]);
    let insp_none = client
        .inspect_lock(&non_existent_hex)
        .await
        .expect("inspect non existent");
    assert_eq!(
        insp_none,
        ControlResponse::LockInspection { inspection: None }
    );

    // Query invalid hex string
    let insp_err = client
        .inspect_lock("not-a-valid-hex")
        .await
        .expect("inspect invalid hex");
    assert!(matches!(insp_err, ControlResponse::Error { .. }));

    // 4. Test create_backup
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let backup_path = temp.path().join("backup_destination.redb");
    let backup_str = backup_path.display().to_string();
    let backup_resp = client
        .create_backup(&backup_str)
        .await
        .expect("create_backup");
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
    let backed_up_rec = backup_storage
        .get_hmc_lock(&parent_hex)
        .expect("get_hmc_lock")
        .expect("found");
    assert_eq!(backed_up_rec.t_id, lock_id);
    assert_eq!(backed_up_rec.sender_ephemeral_pub, [44u8; 32]);

    // Shutdown
    assert!(matches!(
        client
            .send_request(humoco_node::ControlRequest::Shutdown)
            .await
            .expect("shutdown acceptance"),
        ControlResponse::Ok
    ));
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_s02_01_control_backup_targeting_live_db_rejected() {
    let temp = tempdir().expect("tempdir");
    let db_dir = temp.path().join("db_dir");
    std::fs::create_dir_all(&db_dir).expect("create db_dir");
    let db_path = db_dir.join("daemon_live.redb");
    let socket_path = temp.path().join("control_s02.sock");

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
    let server_handle = tokio::spawn(async move { server.run().await });
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client = ControlClient::new(socket_path);

    // Initial state write
    storage.ban_node(&[0x11; 32], 1000).unwrap();

    // 1. Attempt backup to exact live DB path over control socket
    let live_path_str = db_path.display().to_string();
    let resp_exact = client.create_backup(&live_path_str).await.expect("create_backup exact");
    assert!(
        matches!(resp_exact, ControlResponse::Error { .. }),
        "Backup to exact live DB path over control socket must return Error, got: {:?}",
        resp_exact
    );

    // 2. Attempt backup to path with '.' component
    let dot_path = db_dir.join(".").join("daemon_live.redb");
    let resp_dot = client.create_backup(&dot_path.display().to_string()).await.expect("create_backup dot");
    assert!(
        matches!(resp_dot, ControlResponse::Error { .. }),
        "Backup to dot-normalized live DB path must return Error, got: {:?}",
        resp_dot
    );

    // 3. Attempt backup via symlinked parent directory
    #[cfg(unix)]
    {
        let symlink_dir = temp.path().join("sym_db_dir");
        std::os::unix::fs::symlink(&db_dir, &symlink_dir).expect("symlink dir");
        let sym_path = symlink_dir.join("daemon_live.redb");
        let resp_sym = client.create_backup(&sym_path.display().to_string()).await.expect("create_backup sym");
        assert!(
            matches!(resp_sym, ControlResponse::Error { .. }),
            "Backup to symlinked parent path must return Error, got: {:?}",
            resp_sym
        );
    }

    // 4. Prove live daemon DB remains usable and retains subsequent durable writes across reopen
    storage.ban_node(&[0x22; 32], 2000).unwrap();
    let (root3_tag, root3) = make_control_root("v_live_3", [0x31; 32]);
    let (spend3_tag, spend3) = make_control_spend("v_live_3", [0x33; 32]);
    storage.put_hmc_lock(&root3_tag, &root3).unwrap();
    storage.put_hmc_lock(&spend3_tag, &spend3).unwrap();

    // Shutdown daemon
    assert!(matches!(
        client.send_request(humoco_node::ControlRequest::Shutdown).await.expect("shutdown"),
        ControlResponse::Ok
    ));
    let _ = server_handle.await;
    _flush_handle.abort();
    let _ = _flush_handle.await;
    drop(engine);
    drop(storage);

    // Reopen DB and verify all writes are intact
    let reopened = RedbStorage::open(&db_path).expect("reopen redb");
    assert!(reopened.is_node_banned(&[0x11; 32]).unwrap());
    assert!(reopened.is_node_banned(&[0x22; 32]).unwrap());
    assert!(reopened.get_hmc_lock(&spend3_tag).unwrap().is_some());
}

#[tokio::test]
async fn test_cli_peer_removal_exact_matching_and_formats() {
    use humoco_node::cli::execute_peer_remove;
    use humoco_node::config::NodeConfig;
    use humoco_node::identity::NodeIdentity;

    let temp = tempfile::tempdir().unwrap();
    let cfg_path = temp.path().join("humoco.toml");

    let id1 = NodeIdentity::generate();
    let id2 = NodeIdentity::generate();
    let id1_hex = id1.public_key_hex();
    let id1_bs58 = id1.public_key_bs58();
    let id2_hex = id2.public_key_hex();

    let mut cfg = NodeConfig::default();
    cfg.f2f.peers = vec![
        "127.0.0.1:909".to_string(),
        "127.0.0.1:9090".to_string(),
        format!("{}@127.0.0.1:9091", id1_hex),
        id2_hex.clone(),
    ];
    cfg.f2f.trusted_pubkeys = vec![id1_hex.clone(), id2_hex.clone()];
    cfg.save_to_file(&cfg_path).unwrap();

    // 1. Empty/whitespace argument returns error without modifying config
    assert!(execute_peer_remove("".into(), true, false, Some(cfg_path.clone()), false).await.is_err());
    assert!(execute_peer_remove("   ".into(), true, false, Some(cfg_path.clone()), false).await.is_err());
    let loaded = NodeConfig::load_from_file(&cfg_path).unwrap();
    assert_eq!(loaded.f2f.peers.len(), 4);
    assert_eq!(loaded.f2f.trusted_pubkeys.len(), 2);

    // 2. Removing 127.0.0.1:909 removes ONLY 127.0.0.1:909 and preserves 127.0.0.1:9090
    execute_peer_remove("127.0.0.1:909".into(), true, false, Some(cfg_path.clone()), false).await.unwrap();
    let loaded = NodeConfig::load_from_file(&cfg_path).unwrap();
    assert!(!loaded.f2f.peers.contains(&"127.0.0.1:909".to_string()));
    assert!(loaded.f2f.peers.contains(&"127.0.0.1:9090".to_string()));
    assert_eq!(loaded.f2f.peers.len(), 3);
    assert_eq!(loaded.f2f.trusted_pubkeys.len(), 2);

    // 3. Removing id1 via Base58 removes hex-configured peer + trusted_pubkeys entry
    execute_peer_remove(id1_bs58.clone(), true, false, Some(cfg_path.clone()), false).await.unwrap();
    let loaded = NodeConfig::load_from_file(&cfg_path).unwrap();
    assert!(!loaded.f2f.peers.iter().any(|p| p.contains(&id1_hex)));
    assert!(!loaded.f2f.trusted_pubkeys.iter().any(|k| k == &id1_hex));
    // Unrelated peer and trusted_pubkey (id2) preserved
    assert!(loaded.f2f.peers.contains(&id2_hex));
    assert!(loaded.f2f.trusted_pubkeys.contains(&id2_hex));
    assert!(loaded.f2f.peers.contains(&"127.0.0.1:9090".to_string()));

    // 4. Removing id2 via hex removes id2 and preserves 127.0.0.1:9090
    execute_peer_remove(id2_hex.clone(), true, false, Some(cfg_path.clone()), false).await.unwrap();
    let loaded = NodeConfig::load_from_file(&cfg_path).unwrap();
    assert!(!loaded.f2f.peers.contains(&id2_hex));
    assert!(!loaded.f2f.trusted_pubkeys.contains(&id2_hex));
    assert_eq!(loaded.f2f.peers, vec!["127.0.0.1:9090".to_string()]);
    assert!(loaded.f2f.trusted_pubkeys.is_empty());
}

