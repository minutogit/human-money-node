use std::net::SocketAddr;
use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::{
    api::{build_router, AppState},
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::{DefaultRequestHandler, PeerManager, QuicTransport},
    storage::{DualTierEngine, RedbStorage},
};

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[tokio::test]
async fn test_dos_correlated_failure_suppression_prevents_death_spiral() {
    // 1. Setup local node with storage, identity, and tier controller
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_dos.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    tier_controller.register_f2f_peer("friend_secret_token");

    // 2. Setup 20 shard candidate peers in the PeerManager
    let mut shard_entries = Vec::new();
    let mut shard_addrs = Vec::new();
    let mut shard_pubkeys = Vec::new();
    for i in 0..20 {
        let peer_ident = NodeIdentity::generate();
        // Use arbitrary non-listening loopback ports to simulate complete DoS drop / timeout
        let addr: SocketAddr = format!("127.0.0.1:{}", 19800 + i).parse().unwrap();
        let node_id = *peer_ident.node_id();
        shard_addrs.push(addr);
        shard_pubkeys.push(node_id);
        shard_entries.push((Some(node_id), addr));
    }

    // Configure all 20 as known F2F peers so they are eligible as active HRW nodes
    let peer_mgr = Arc::new(PeerManager::with_f2f(shard_entries, shard_pubkeys.clone()));

    let active_nodes = peer_mgr.active_hrw_nodes().await;
    assert_eq!(active_nodes.len(), 20, "Must have 20 eligible shard candidates");

    // Setup transport for local node
    let cancel_token = CancellationToken::new();
    let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let transport = QuicTransport::bind_with_options(
        local_addr,
        &identity,
        peer_mgr.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("bind transport");

    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state.peer_manager = Some(peer_mgr.clone());
    state.transport = Some(transport);

    let router = build_router(state);

    // 3. Simulate multiple lock requests under DoS: All 20 candidate peers are unreachable
    // Perform 3 rounds of lock requests
    for round in 1..=3 {
        let sender_key = ed25519_dalek::SigningKey::from_bytes(&[round as u8; 32]);
        let sender_pub = sender_key.verifying_key().to_bytes();
        let parent_bytes = [round as u8; 32];
        let now = test_now_ms();
        let valid_until_ms = now + 600_000;
        let del_str = valid_until_ms.to_string();

        let mut req_payload = humoco_node::api::hmc::L2LockRequest {
            auth: humoco_node::api::hmc::L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: format!("dos_voucher_{}", round),
            ds_tag: None,
            transaction_hash: parent_bytes,
            is_genesis: true,
            sender_ephemeral_pub: sender_pub,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: [0u8; 64],
            trap_r: Some("none".into()),
            trap_s: Some("none".into()),
            encrypted_timestamp: 0,
            deletable_at: Some(del_str),
            privacy_guard: None,
        };
        let payload_hash = humoco_node::api::hmc::calculate_l2_payload_hash(&req_payload);
        use ed25519_dalek::Signer;
        req_payload.layer2_signature = sender_key.sign(&payload_hash).to_bytes();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/lock")
            .header("content-type", "application/json")
            .header("x-peer-token", "friend_secret_token")
            .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
            .unwrap();

        let res = router.clone().oneshot(req).await.unwrap();
        // The lock is created locally even if remote shard quorum times out under DoS
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    // 4. Verify Correlated Failure Protection:
    // Because ALL 20 candidates timed out in each round (> 50% correlated failure),
    // the system correctly classified this as local overload / network DoS.
    // ZERO failure penalties must have been applied to any peer!
    for addr in &shard_addrs {
        let peer_info = peer_mgr.get_peer(addr).await.expect("peer exists");
        assert_eq!(
            peer_info.missing_count, 0,
            "Peer {} missing_count must be 0 (no penalty under correlated DoS)",
            addr
        );
        assert!(
            !peer_info.is_suspended(),
            "Peer {} must NOT be suspended under correlated DoS",
            addr
        );
    }

    // Active HRW node pool remains 100% intact (all 20 still active)
    let post_dos_active = peer_mgr.active_hrw_nodes().await;
    assert_eq!(
        post_dos_active.len(),
        20,
        "Active shard pool must remain intact without losing nodes"
    );
}

#[tokio::test]
async fn test_isolated_peer_failure_is_still_penalized() {
    // Verifies that genuine isolated peer failures (< 50% timeout) ARE penalized as expected.
    let addr1: SocketAddr = "127.0.0.1:19991".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:19992".parse().unwrap();
    let addr3: SocketAddr = "127.0.0.1:19993".parse().unwrap();

    let peer_mgr = Arc::new(PeerManager::new(vec![addr1, addr2, addr3]));

    // Record failure for isolated peer addr1 directly (or in an isolated scenario)
    peer_mgr.record_failure(addr1).await;

    let p1 = peer_mgr.get_peer(&addr1).await.unwrap();
    let p2 = peer_mgr.get_peer(&addr2).await.unwrap();
    let p3 = peer_mgr.get_peer(&addr3).await.unwrap();

    assert_eq!(p1.missing_count, 1, "Isolated failure MUST increment missing_count");
    assert_eq!(p2.missing_count, 0);
    assert_eq!(p3.missing_count, 0);
}
