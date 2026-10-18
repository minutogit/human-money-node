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

    let is_sync_ready = Arc::new(AtomicBool::new(false));

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm_server.clone(),
        )
        .with_sync_ready(is_sync_ready.clone()),
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
        created_at_ms: 0,
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
    let router = build_router(state);

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
    assert_eq!(resp_lock.status(), StatusCode::SERVICE_UNAVAILABLE, "POST /v1/lock must return 503 during boot recovery");

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
