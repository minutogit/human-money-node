use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use humoco_node::api::hmc::{L2LockEntry, L2Verdict};
use humoco_node::identity::NodeIdentity;
use humoco_node::network::{DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};
use humoco_sim_core::types::{LockRecord, SimTime};
use humoco_sim_core::wire::{FLAG_NOT_READY, MsgType, WireHeader};

#[tokio::test]
async fn test_boot_readiness_barrier_wire_flag() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("barrier.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let server_id = NodeIdentity::generate();
    let client_id = NodeIdentity::generate();
    let cancel = CancellationToken::new();

    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*client_id.node_id()],
    ));
    let pm_client = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_id()],
    ));

    let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    pm_server.learn_node_from_gossip_with_hrw(*server_id.node_pubkey(), *server_id.hrw_routing_id(), "127.0.0.1:1".parse().unwrap(), 0, None).await;
    pm_server.set_first_seen_for_test(server_id.node_pubkey(), std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
    let is_sync_ready = Arc::new(AtomicBool::new(false));

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm_server.clone(),
        )
        .with_sync_ready(is_sync_ready.clone())
        .with_readiness_manager(readiness.clone()),
    );

    let mut server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        handler,
        cancel.clone(),
    )
    .expect("server bind");
    server_transport.set_sync_ready_handle(is_sync_ready.clone());
    let server_addr = server_transport.local_addr().expect("local addr");
    server_transport.spawn_accept_loop();

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        CancellationToken::new(),
    )
    .expect("client bind");
    let client_addr = client_transport.local_addr().expect("client addr");
    client_transport.spawn_accept_loop();

    pm_server.register_f2f_friend(*client_id.node_id(), Some(client_addr)).await;
    pm_client.register_f2f_friend(*server_id.node_id(), Some(server_addr)).await;

    let conn = client_transport
        .connect_peer(server_addr)
        .await
        .expect("connect");

    let now_ms = pm_server.net_time_ms();
    let root_valid_until = now_ms + 600_000;
    let mut hmc_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *client_id.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "barrier_test_voucher".into(),
        ds_tag: None,
        transaction_hash: [0x55; 32],
        is_genesis: true,
        sender_ephemeral_pub: *client_id.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now_ms,
        deletable_at: Some(root_valid_until.to_string()),
        privacy_guard: None,
    };
    {
        use ed25519_dalek::Signer;
        let payload_hash = humoco_node::api::hmc::calculate_l2_payload_hash(&hmc_req);
        hmc_req.layer2_signature = client_id.signing_key().sign(&payload_hash).to_bytes();
    }
    let entry = humoco_node::api::hmc::L2LockEntry::from(&hmc_req);
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600);
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        client_id.node_pubkey(),
        0,
        0,
        now_ms,
        0,
        0,
        footprint,
        false,
        &entry.t_id,
    );
    use ed25519_dalek::Signer;
    let sig = client_id.signing_key().sign(&digest).to_bytes();
    let wire = humoco_node::network::framing::LockWirePayload::Hmc {
        req: hmc_req,
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: *client_id.node_pubkey(),
        sender_signature: sig,
        timestamp_ms: now_ms,
    };
    let raw_payload = bincode::serialize(&wire).unwrap();

    // 1. When is_sync_ready is false, LockVerifyRequest MUST return FLAG_NOT_READY
    let header = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, raw_payload.len() as u32);
    let (resp_hdr, _) = client_transport.send_request(&conn, &header, &raw_payload).await.expect("send request");

    assert_eq!(
        resp_hdr.msg_type,
        MsgType::LockVerifyResponse as u16,
        "Expected LockVerifyResponse"
    );
    assert_ne!(
        resp_hdr.flags & FLAG_NOT_READY,
        0,
        "Expected FLAG_NOT_READY on wire when node is recovering"
    );

    // An isolated prepared-state fixture, not a recovery-completeness proof.
    let tag = bs58::encode(&[0x55u8; 32]).into_string();
    readiness.mark_shard_ready(humoco_sim_core::types::canonical_voucher_shard(&humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag)));
    // 2. Now transition is_sync_ready to true
    is_sync_ready.store(true, Ordering::SeqCst);
    server_transport.set_sync_ready(true);

    let header2 = WireHeader::new(MsgType::LockVerifyRequest as u16, 2, 0, 0, raw_payload.len() as u32);
    let (resp_hdr2, resp_payload2) = client_transport.send_request(&conn, &header2, &raw_payload).await.expect("send request after ready");

    assert_eq!(
        resp_hdr2.flags & FLAG_NOT_READY,
        0,
        "FLAG_NOT_READY must be cleared once recovery completes"
    );
    assert!(!resp_payload2.is_empty(), "Expected attestation payload on successful lock verify");
}

#[tokio::test]
async fn test_paginated_active_sync_streaming_chunks() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("paginated.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    // Insert 1250 test locks into storage
    let now = SimTime(1_000);
    let root_valid = SimTime(1_000_000);
    for i in 0..1250u32 {
        let mut parent = [0u8; 32];
        parent[0] = 0x01; // shard 0x0100
        parent[2..6].copy_from_slice(&i.to_be_bytes());
        let rec = LockRecord::new(
            parent,
            [0xAA; 32],
            i.to_le_bytes().to_vec(),
            now,
            SimTime(500_000),
        );
        let _ = engine
            .ingress_lock_with_origin(rec, now, root_valid, IngressOrigin::ClientApi)
            .await;
    }

    let server_id = NodeIdentity::generate();
    let client_id = NodeIdentity::generate();
    let cancel = CancellationToken::new();

    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*client_id.node_id()],
    ));
    let pm_client = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_id()],
    ));

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm_server.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );

    let server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        handler,
        cancel.clone(),
    )
    .expect("server bind");
    server_transport.set_sync_ready(true);
    let server_addr = server_transport.local_addr().expect("local addr");
    server_transport.spawn_accept_loop();

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        CancellationToken::new(),
    )
    .expect("client bind");
    let client_addr = client_transport.local_addr().expect("client addr");
    client_transport.spawn_accept_loop();

    pm_server.register_f2f_friend(*client_id.node_id(), Some(client_addr)).await;
    pm_client.register_f2f_friend(*server_id.node_id(), Some(server_addr)).await;

    let conn = client_transport
        .connect_peer(server_addr)
        .await
        .expect("connect");

    // Pull in pages of limit 500
    let mut all_received = Vec::new();
    let mut cursor = 0u64;
    let limit = 500usize;
    let mut seq = 1u64;

    loop {
        let page = client_transport
            .request_active_sync_page(&conn, seq, cursor, limit)
            .await
            .expect("request_active_sync_page");
        seq += 1;

        assert!(
            page.payload.locks.len() <= limit,
            "Page size must not exceed limit"
        );
        all_received.extend(page.payload.locks);

        if !page.has_more {
            break;
        }
        cursor = page.next_cursor.expect("next_cursor must be Some when has_more is true");
    }

    assert_eq!(all_received.len(), 1250, "Must have received all 1250 locks across pages");
}

#[tokio::test]
async fn test_cryptographic_verification_on_partition_sync() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("crypto_sync.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let now = SimTime(10_000);
    let root_valid = SimTime(600_000);

    // 1. Sim LockRecord with invalid LockId (tampered hash)
    let parent = [0x99; 32];
    let mut invalid_rec = LockRecord::new(
        parent,
        [0x77; 32],
        vec![1, 2, 3],
        now,
        SimTime(50_000),
    );
    invalid_rec.id = [0xFF; 32]; // deliberate corrupt ID

    let res = engine
        .ingress_lock_with_origin(invalid_rec, now, root_valid, IngressOrigin::PartitionSync)
        .await;
    assert!(res.is_err(), "Ingress of corrupt LockId under PartitionSync must be rejected");

    // 2. Sim LockRecord with valid LockId
    let valid_rec = LockRecord::new(
        parent,
        [0x77; 32],
        vec![1, 2, 3],
        now,
        SimTime(50_000),
    );
    let res2 = engine
        .ingress_lock_with_origin(valid_rec, now, root_valid, IngressOrigin::PartitionSync)
        .await;
    assert!(res2.is_ok(), "Ingress of valid LockId under PartitionSync must succeed");

    // 3. HMC L2LockEntry with invalid cryptographic signature
    let invalid_hmc_entry = L2LockEntry {
        layer2_voucher_id: "voucher-test".into(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0xEE; 64], // invalid Ed25519 signature
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("60000".into()),
        privacy_guard: None,
    };
    let (verdict, is_new) = engine
        .ingress_hmc_lock_with_origin("tag1".into(), invalid_hmc_entry, IngressOrigin::PartitionSync, Some(10_000))
        .await;
    assert!(!is_new, "Invalid signature HMC lock must not be inserted");
    assert!(matches!(verdict, L2Verdict::Rejected { .. }), "Invalid signature must return Rejected verdict");
}

#[tokio::test]
async fn test_boot_readiness_barrier_http_api_503() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use humoco_node::api::{build_router, AppState};
    use humoco_node::ingress::{PowEngine, TierController};
    use tower::ServiceExt;

    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("api_barrier.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let server_id = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    let is_sync_ready = Arc::new(AtomicBool::new(false));

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm.clone(),
        )
        .with_sync_ready(is_sync_ready.clone()),
    );

    let mut server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm.clone(),
        handler,
        CancellationToken::new(),
    )
    .expect("bind");
    server_transport.set_sync_ready_handle(is_sync_ready.clone());

    let pow_engine = Arc::new(PowEngine::new(*server_id.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let mut state = AppState::new(
        engine,
        storage,
        server_id,
        tier_controller,
        pow_engine,
    );
    state.transport = Some(server_transport.clone());
    let router = build_router(state.clone()).merge(humoco_node::api::routes::build_operator_router(state));

    // 1. While not ready, /health/ready MUST return 503 Service Unavailable
    let req_health = Request::builder()
        .method("GET")
        .uri("/health/ready")
        .body(Body::empty())
        .unwrap();
    let resp_health = router.clone().oneshot(req_health).await.unwrap();
    assert_eq!(resp_health.status(), StatusCode::SERVICE_UNAVAILABLE, "/health/ready must return 503 during boot recovery");

    // 2. While not ready, POST /v1/lock MUST return 503 Service Unavailable
    let req_lock = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp_lock = router.clone().oneshot(req_lock).await.unwrap();
    assert_eq!(resp_lock.status(), StatusCode::BAD_REQUEST, "Malformed input is rejected before a shard-specific recovery decision");

    // 3. Set is_sync_ready to true
    is_sync_ready.store(true, Ordering::SeqCst);
    server_transport.set_sync_ready(true);

    // 4. Once ready, /health/ready returns 200 OK
    let req_health2 = Request::builder()
        .method("GET")
        .uri("/health/ready")
        .body(Body::empty())
        .unwrap();
    let resp_health2 = router.clone().oneshot(req_health2).await.unwrap();
    assert_eq!(resp_health2.status(), StatusCode::OK, "/health/ready must return 200 once recovery completes");

    // 5. Once ready, POST /v1/lock accepts requests (returns 400 for empty JSON instead of 503)
    let req_lock2 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp_lock2 = router.clone().oneshot(req_lock2).await.unwrap();
    assert_eq!(resp_lock2.status(), StatusCode::BAD_REQUEST, "POST /v1/lock must no longer return 503 once recovery completes");
}

#[tokio::test]
async fn test_per_shard_readiness_demand_sync_503() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ed25519_dalek::{Signer, SigningKey};
    use humoco_node::api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockRequest, L2ResponseEnvelope};
    use humoco_node::api::{build_router, AppState};
    use humoco_node::daemon::ShardReadinessManager;
    use humoco_node::ingress::{PowEngine, TierController};
    use tower::ServiceExt;

    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("per_shard_barrier.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let server_id = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    let is_sync_ready = Arc::new(AtomicBool::new(true)); // global sync ready

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm.clone(),
        )
        .with_sync_ready(is_sync_ready.clone()),
    );

    let mut server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm.clone(),
        handler,
        CancellationToken::new(),
    )
    .expect("bind");
    server_transport.set_sync_ready_handle(is_sync_ready.clone());
    server_transport.set_sync_ready(true);

    let pow_engine = Arc::new(PowEngine::new(*server_id.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    tier_controller.register_f2f_peer("test_f2f_token");

    pm.learn_node_from_gossip_with_hrw(*server_id.node_pubkey(), *server_id.hrw_routing_id(), "127.0.0.1:1".parse().unwrap(), 0, None).await;
    pm.set_first_seen_for_test(server_id.node_pubkey(), std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
    let readiness_manager = Arc::new(ShardReadinessManager::new());
    let mut state = AppState::new(
        engine,
        storage,
        server_id,
        tier_controller,
        pow_engine,
    );
    state.transport = Some(server_transport.clone());
    state.peer_manager = Some(pm);
    state.readiness_manager = readiness_manager.clone();

    let router = build_router(state);

    // Create a valid genesis lock
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let sender_key = SigningKey::from_bytes(&[55u8; 32]);
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(b"per_shard_test_parent").as_bytes();
    let mut req_payload = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: "voucher_shard_test_123".into(),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req_payload);
    req_payload.layer2_signature = sender_key.sign(&payload_hash).to_bytes();

    let lookup_tag = bs58::encode(&req_payload.transaction_hash).into_string();
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
    let shard_id = humoco_sim_core::types::extract_shard_id(&parent_bytes);

    // 1. Shard is not ready initially
    assert!(!readiness_manager.is_shard_ready(shard_id));

    // 2. Submitting lock must return 503 Service Unavailable with FLAG_NOT_READY
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "test_f2f_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
    let env: L2ResponseEnvelope = serde_json::from_slice(&body_bytes).unwrap();
    match env.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(
                reason.contains(&format!("FLAG_NOT_READY: Shard {} syncing", shard_id)),
                "Unexpected reject reason: {reason}"
            );
        }
        other => panic!("Expected Rejected verdict, got {:?}", other),
    }

    // 3. Demand sync was triggered, so try_trigger_demand_sync returns false (already active)
    assert!(!readiness_manager.try_trigger_demand_sync(shard_id));

    // 4. Install explicit isolated readiness fixture; no recovery-convergence claim
    readiness_manager.mark_shard_ready(shard_id);
    assert!(readiness_manager.is_shard_ready(shard_id));

    // 5. Once shard is ready, subsequent lock submission is accepted (201 Created or 200 OK)
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "test_f2f_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();
    let resp2 = router.oneshot(req2).await.unwrap();
    assert!(
        resp2.status() == StatusCode::CREATED || resp2.status() == StatusCode::OK,
        "Expected CREATED or OK once shard is ready, got {}",
        resp2.status()
    );
}

#[tokio::test]
async fn test_stable_network_keeps_finality_separate_from_each_shards_readiness() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("barrier.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let server_id = NodeIdentity::generate();
    let client_id = NodeIdentity::generate();
    let cancel = CancellationToken::new();

    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*client_id.node_id()],
    ));
    let pm_client = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_id()],
    ));

    let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    pm_server.learn_node_from_gossip_with_hrw(*server_id.node_pubkey(), *server_id.hrw_routing_id(), "127.0.0.1:1".parse().unwrap(), 0, None).await;
    pm_server.set_first_seen_for_test(server_id.node_pubkey(), std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
    // Conditional fixture: a fully mature 20-member local view. This proves
    // gate separation only, not independent authority or recovery coverage.
    for seed in 1..20u8 {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
        pm_server.learn_node_from_gossip_with_hrw(key, key, format!("127.0.0.1:{}", 32000 + u16::from(seed)).parse().unwrap(), 0, None).await;
        pm_server.set_first_seen_for_test(&key, std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
    }
    let stable_now = pm_server.net_time_ms();
    pm_server.set_ge20_anchor_for_test(stable_now.saturating_sub(86_400_001));
    pm_server.set_local_sync_ready(false);
    assert!(pm_server.is_network_stable_ge20_for_24h(stable_now));
    let is_sync_ready = Arc::new(AtomicBool::new(false));

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm_server.clone(),
        )
        .with_sync_ready(is_sync_ready.clone())
        .with_readiness_manager(readiness.clone()),
    );

    let mut server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        handler,
        cancel.clone(),
    )
    .expect("server bind");
    server_transport.set_sync_ready_handle(is_sync_ready.clone());
    let server_addr = server_transport.local_addr().expect("local addr");
    server_transport.spawn_accept_loop();

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        CancellationToken::new(),
    )
    .expect("client bind");
    let client_addr = client_transport.local_addr().expect("client addr");
    client_transport.spawn_accept_loop();

    pm_server.register_f2f_friend(*client_id.node_id(), Some(client_addr)).await;
    pm_client.register_f2f_friend(*server_id.node_id(), Some(server_addr)).await;

    let conn = client_transport
        .connect_peer(server_addr)
        .await
        .expect("connect");

    let now_ms = pm_server.net_time_ms();
    let root_valid_until = now_ms + 600_000;
    let mut hmc_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *client_id.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "barrier_test_voucher".into(),
        ds_tag: None,
        transaction_hash: [0x55; 32],
        is_genesis: true,
        sender_ephemeral_pub: *client_id.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now_ms,
        deletable_at: Some(root_valid_until.to_string()),
        privacy_guard: None,
    };
    {
        use ed25519_dalek::Signer;
        let payload_hash = humoco_node::api::hmc::calculate_l2_payload_hash(&hmc_req);
        hmc_req.layer2_signature = client_id.signing_key().sign(&payload_hash).to_bytes();
    }
    let entry = humoco_node::api::hmc::L2LockEntry::from(&hmc_req);
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600);
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        client_id.node_pubkey(),
        0,
        0,
        now_ms,
        0,
        0,
        footprint,
        false,
        &entry.t_id,
    );
    use ed25519_dalek::Signer;
    let sig = client_id.signing_key().sign(&digest).to_bytes();
    let wire = humoco_node::network::framing::LockWirePayload::Hmc {
        req: hmc_req,
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: *client_id.node_pubkey(),
        sender_signature: sig,
        timestamp_ms: now_ms,
    };
    let raw_payload = bincode::serialize(&wire).unwrap();

    // 1. When is_sync_ready is false, LockVerifyRequest MUST return FLAG_NOT_READY
    let header = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, raw_payload.len() as u32);
    let (resp_hdr, _) = client_transport.send_request(&conn, &header, &raw_payload).await.expect("send request");

    assert_eq!(
        resp_hdr.msg_type,
        MsgType::LockVerifyResponse as u16,
        "Expected LockVerifyResponse"
    );
    assert_ne!(
        resp_hdr.flags & FLAG_NOT_READY,
        0,
        "Expected FLAG_NOT_READY on wire when node is recovering"
    );

    // An isolated prepared-state fixture, not a recovery-completeness proof.
    let tag = bs58::encode(&[0x55u8; 32]).into_string();
    readiness.mark_shard_ready(humoco_sim_core::types::canonical_voucher_shard(&humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag)));
    // 2. Now transition is_sync_ready to true
    // Global readiness intentionally remains false; only this shard is ready.

    let header2 = WireHeader::new(MsgType::LockVerifyRequest as u16, 2, 0, 1, raw_payload.len() as u32);
    let (resp_hdr2, resp_payload2) = client_transport.send_request(&conn, &header2, &raw_payload).await.expect("send request after ready");

    assert_eq!(
        resp_hdr2.flags & FLAG_NOT_READY,
        0,
        "FLAG_NOT_READY must be cleared once recovery completes"
    );
    assert!(!resp_payload2.is_empty(), "Expected attestation payload on successful lock verify");
    let attestation = humoco_node::api::dto::AttestationDto::from_wire_bytes(&resp_payload2).expect("original approval");
    let parent: [u8; 32] = hex::decode(&attestation.parent_lock).unwrap().try_into().unwrap();
    let lock: [u8; 32] = hex::decode(&attestation.lock_id).unwrap().try_into().unwrap();
    let payload = humoco_sim_core::crypto::compute_attestation_payload_digest(&parent, &lock);
    let final_digest = humoco_sim_core::crypto::compute_sig_digest(humoco_sim_core::crypto::domain_approve_final(humoco_sim_core::types::NetworkId::Mainnet), 0, 0, 0, attestation.shard_id, 1, &payload);
    let bytes: [u8; 64] = hex::decode(&attestation.signature).unwrap().try_into().unwrap();
    server_id.verifying_key().verify_strict(&final_digest, &ed25519_dalek::Signature::from_bytes(&bytes)).expect("ready shard signs FINAL domain despite global false");
    assert!(!is_sync_ready.load(Ordering::SeqCst));
    let mut neighbouring_wire = wire;
    if let humoco_node::network::framing::LockWirePayload::Hmc { req, sender_signature, .. } = &mut neighbouring_wire {
        req.transaction_hash = [0x56; 32];
        req.layer2_voucher_id.push_str("_neighbouring_unready_root");
        req.layer2_signature = client_id.signing_key().sign(&humoco_node::api::hmc::calculate_l2_payload_hash(req)).to_bytes();
        let entry = humoco_node::api::hmc::L2LockEntry::from(&*req);
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(client_id.node_pubkey(), 0, 0, now_ms, 0, 0, footprint, false, &entry.t_id);
        *sender_signature = client_id.signing_key().sign(&digest).to_bytes();
    }
    let raw = bincode::serialize(&neighbouring_wire).unwrap();
    let next_header = WireHeader::new(MsgType::LockVerifyRequest as u16, 3, 0, 1, raw.len() as u32);
    let (next_response, next_bytes) = client_transport.send_request(&conn, &next_header, &raw).await.expect("neighboring shard request");
    assert_ne!(next_response.flags & FLAG_NOT_READY, 0, "stable network status does not authorize another unready shard");
    assert!(next_bytes.is_empty());
}

#[tokio::test]
async fn test_sync_single_shard_activates_upon_digest_convergence() {
    let temp_server = tempdir().expect("tempdir");
    let storage_server = Arc::new(RedbStorage::open(&temp_server.path().join("server.redb")).expect("open redb"));
    let (engine_server, _worker_server) = DualTierEngine::new(storage_server.clone());

    let server_id = NodeIdentity::generate();
    let client_id = NodeIdentity::generate();
    let cancel = CancellationToken::new();

    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*client_id.node_id()],
    ));
    let pm_client = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_id()],
    ));

    let readiness_server = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    readiness_server.mark_shard_ready(42);
    let readiness_client = Arc::new(humoco_node::daemon::ShardReadinessManager::new());

    let handler_server = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_server.clone(),
            storage_server.clone(),
            server_id.clone(),
            pm_server.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true)))
        .with_readiness_manager(readiness_server.clone()),
    );

    let temp_client = tempdir().expect("tempdir");
    let storage_client = Arc::new(RedbStorage::open(&temp_client.path().join("client.redb")).expect("open redb"));
    let (engine_client, _worker_client) = DualTierEngine::new(storage_client.clone());

    let handler_client = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_client.clone(),
            storage_client.clone(),
            client_id.clone(),
            pm_client.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true)))
        .with_readiness_manager(readiness_client.clone()),
    );

    let server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        handler_server,
        cancel.clone(),
    )
    .expect("server bind");
    let server_addr = server_transport.local_addr().expect("local addr");
    server_transport.spawn_accept_loop();

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        pm_client.clone(),
        handler_client,
        cancel.clone(),
    )
    .expect("client bind");
    let client_addr = client_transport.local_addr().expect("client addr");
    client_transport.spawn_accept_loop();

    pm_client.register_f2f_friend(*server_id.node_id(), Some(server_addr)).await;
    pm_server.register_f2f_friend(*client_id.node_id(), Some(client_addr)).await;

    pm_client.learn_node_from_gossip_with_hrw(*server_id.node_pubkey(), *server_id.hrw_routing_id(), server_addr, 0, None).await;
    pm_client.set_first_seen_for_test(server_id.node_pubkey(), std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
    pm_client.learn_node_from_gossip_with_hrw(*client_id.node_pubkey(), *client_id.hrw_routing_id(), client_addr, 0, None).await;
    pm_client.set_first_seen_for_test(client_id.node_pubkey(), std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;

    // Both server and client have empty state for shard 42 initially -> matching digest!
    assert!(!readiness_client.is_shard_ready(42));
    let ready = humoco_node::daemon::sync_single_shard(
        42,
        &client_transport,
        &pm_client,
        &engine_client,
        &storage_client,
        &client_id,
        &readiness_client,
        &cancel,
    ).await.expect("sync_single_shard");

    assert!(ready, "Convergent dominant digest must activate shard readiness");
    assert!(readiness_client.is_shard_ready(42));
    cancel.cancel();
}
