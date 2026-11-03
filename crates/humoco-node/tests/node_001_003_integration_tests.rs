#![forbid(unsafe_code)]

//! Integration tests for NODE-001 and NODE-003:
//!
//! Acceptance Criteria:
//! 1. `GET /v1/regional-mesh-view` public endpoint + 5s cache hit (same signature, zero CPU re-signing) + valid Ed25519 signature.
//! 2. `POST /v1/lock` accepting genuine `HMC_TX_AUTH_V4` signature with past `created_at_ms` (offline spend) and rejecting future `created_at_ms > now + 30s`, and rejecting legacy V3 domain signatures.
//! 3. `POST /v1/verify-current` returning 14/20 `LiveSlotOccupancy::Unoccupied` proof on empty slot, and `Occupied` on locked slot.
//! 4. `POST /v1/checkout` committing offline buyer's lock and returning valid 14/20 `LiveStateProof` in 1 single HTTP roundtrip.
//! 5. `POST /v1/status` returning `MissingLocks { sync_point, anchor_lock: Some(...) }`.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::api::hmc::{
    calculate_l2_payload_hash, L2AuthPayload, L2ChainLockRequest, L2CheckoutRequest,
    L2CheckoutResponse, L2LockEntry, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};
use humoco_node::api::{build_router, AppState};
use humoco_node::daemon::ShardReadinessManager;
use humoco_node::identity::NodeIdentity;
use humoco_node::ingress::{PowEngine, TierController};
use humoco_node::network::{DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};
use humoco_proto::live::{
    verify_live_state_proof, verify_live_unoccupied_proof, LiveSlotOccupancy, LiveStateContext,
    LiveStateProof,
};
use humoco_proto::mesh::RegionalMeshView;

fn test_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_genesis_lock_with_deletable(
    voucher_tag: &str,
    deletable_at: Option<String>,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(voucher_tag.as_bytes()).as_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: format!("voucher_{voucher_tag}"),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at,
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_genesis_lock(
    voucher_tag: &str,
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    make_genesis_lock_with_deletable(voucher_tag, Some(valid_until_ms.to_string()), sender_key)
}

fn make_spend_lock_with_deletable(
    voucher_id: &str,
    parent_tag: &str,
    tx_hash: [u8; 32],
    deletable_at: Option<String>,
    created_at_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(parent_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms,
        deletable_at,
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_spend_lock(
    voucher_id: &str,
    parent_tag: &str,
    tx_hash: [u8; 32],
    valid_until_ms: u64,
    created_at_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    make_spend_lock_with_deletable(
        voucher_id,
        parent_tag,
        tx_hash,
        Some(valid_until_ms.to_string()),
        created_at_ms,
        sender_key,
    )
}

async fn force_stable_ge20(pm: &PeerManager) {
    pm.set_local_sync_ready(true);
    let now_ms = pm.net_time_ms();
    let anchor = now_ms.saturating_sub(86_400_001);
    let anchor = if anchor == 0 { 1 } else { anchor };
    pm.set_ge20_anchor_for_test(anchor);
    assert!(
        pm.is_network_stable_ge20_for_24h(now_ms),
        "Network must be marked ge20 stable for 24h"
    );
}

fn setup_standalone_app(temp: &tempfile::TempDir) -> (axum::Router, AppState, NodeIdentity) {
    let storage = Arc::new(RedbStorage::open(&temp.path().join("standalone.redb")).unwrap());
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*identity.node_id(), 1));
    let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
    tc.register_f2f_peer("test_peer_token");

    let state = AppState::new(engine, storage, identity.clone(), tc, pow);
    for shard in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(shard);
    }
    let router = build_router(state.clone());
    (router, state, identity)
}

struct TestShard {
    id: NodeIdentity,
    pm: Arc<PeerManager>,
    transport: QuicTransport,
    engine: DualTierEngine,
    ready: Arc<ShardReadinessManager>,
    storage: Arc<RedbStorage>,
}

fn build_shard_app(shard: &TestShard, shard_id: u16) -> axum::Router {
    let pow = Arc::new(PowEngine::new(*shard.id.node_id(), 1));
    let tc = Arc::new(TierController::new(shard.storage.clone(), pow.clone()));
    tc.register_f2f_peer("test_peer_token");
    let mut state = AppState::new(
        shard.engine.clone(),
        shard.storage.clone(),
        shard.id.clone(),
        tc,
        pow,
    );
    state.peer_manager = Some(shard.pm.clone());
    state.transport = Some(shard.transport.clone());
    state.readiness_manager = shard.ready.clone();
    state.readiness_manager.mark_shard_ready(shard_id);
    build_router(state)
}

struct TestCluster {
    app: axum::Router,
    shards: Vec<TestShard>,
    gateway_engine: DualTierEngine,
    gateway_transport: QuicTransport,
    cancel: CancellationToken,
    owner_key: SigningKey,
    genesis: L2LockRequest,
    genesis_tag: String,
    shard_id: u16,
    committee: Vec<[u8; 32]>,
    root_valid_until: u64,
}

async fn setup_test_cluster(temp: &tempfile::TempDir) -> TestCluster {
    setup_test_cluster_with_root(temp, None).await
}

async fn setup_test_cluster_with_root(
    temp: &tempfile::TempDir,
    root_deletable_override: Option<String>,
) -> TestCluster {
    const NUM_SHARDS: usize = 20;
    let cancel = CancellationToken::new();
    let gateway = NodeIdentity::generate();
    let gateway_pm = Arc::new(PeerManager::new(Vec::new()));
    gateway_pm.set_simulation_mode(true);
    let storage = Arc::new(RedbStorage::open(&temp.path().join("gw.redb")).unwrap());
    let (gateway_engine, _worker) = DualTierEngine::new(storage.clone());
    let gateway_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &gateway,
        gateway_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let gateway_addr = gateway_transport.local_addr().unwrap();

    let mut shards = Vec::new();
    for index in 0..NUM_SHARDS {
        let disk =
            Arc::new(RedbStorage::open(&temp.path().join(format!("shard_{index}.redb"))).unwrap());
        let (engine, _worker) = DualTierEngine::new(disk.clone());
        let id = NodeIdentity::generate();
        let pm = Arc::new(PeerManager::new(Vec::new()));
        pm.set_simulation_mode(true);
        let ready = Arc::new(ShardReadinessManager::with_cancel_token(cancel.clone()));
        let handler = Arc::new(
            NodeRequestHandler::with_peer_manager(engine.clone(), disk.clone(), id.clone(), pm.clone())
                .with_readiness_manager(ready.clone()),
        );
        let transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &id,
            pm.clone(),
            handler,
            cancel.clone(),
        )
        .unwrap();

        pm.register_f2f_friend(*gateway.node_pubkey(), Some(gateway_addr))
            .await;
        gateway_pm
            .register_f2f_friend(*id.node_pubkey(), Some(transport.local_addr().unwrap()))
            .await;

        shards.push(TestShard {
            id,
            pm,
            transport,
            engine,
            ready,
            storage: disk,
        });
    }

    let mut roster: Vec<_> = shards
        .iter()
        .map(|sh| (sh.id.clone(), sh.transport.local_addr().unwrap()))
        .collect();
    roster.push((gateway.clone(), gateway_addr));

    for pm in std::iter::once(gateway_pm.clone()).chain(shards.iter().map(|sh| sh.pm.clone())) {
        for (id, addr) in &roster {
            pm.learn_node_from_gossip_with_hrw(
                *id.node_pubkey(),
                *id.hrw_routing_id(),
                *addr,
                0,
                None,
            )
            .await;
            pm.set_first_seen_for_test(
                id.node_pubkey(),
                Instant::now() - Duration::from_secs(25 * 3600),
            )
            .await;
        }
        force_stable_ge20(&pm).await;
    }

    let owner_key = SigningKey::from_bytes(&[88u8; 32]);
    let now = gateway_pm.net_time_ms();
    let root_deletable_str = root_deletable_override
        .unwrap_or_else(|| (now + 2_000_000).to_string());
    let root_valid_until = humoco_node::storage::db::roots::parse_deletable_at_ms(&root_deletable_str)
        .expect("Valid root deletable_at");

    let mut selected = None;
    for index in 0..1000 {
        let req = make_genesis_lock_with_deletable(
            &format!("cluster_{index}"),
            Some(root_deletable_str.clone()),
            &owner_key,
        );
        let tag = bs58::encode(req.transaction_hash).into_string();
        let sid =
            humoco_sim_core::types::extract_shard_id(blake3::hash(tag.as_bytes()).as_bytes());
        let (committee, _, _) = gateway_pm
            .shard_committee(*gateway.node_pubkey(), *gateway.hrw_routing_id(), sid)
            .await;
        if !committee
            .iter()
            .any(|member| member.node_pubkey == *gateway.node_pubkey())
        {
            selected = Some((
                sid,
                req,
                tag,
                committee
                    .iter()
                    .map(|m| m.node_pubkey)
                    .collect::<Vec<_>>(),
            ));
            break;
        }
    }
    let (shard_id, genesis, genesis_tag, committee) =
        selected.expect("Must find committee of 20 shards excluding gateway");

    let anchor = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    for shard in &shards {
        let (verdict, _) = shard
            .engine
            .ingress_hmc_lock_durable(
                genesis_tag.clone(),
                L2LockEntry::from(&genesis),
                IngressOrigin::PartitionSync,
                Some(now),
                None,
                None,
                Some(genesis.layer2_voucher_id.clone()),
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
        shard
            .engine
            .record_hmc_voucher_genesis_parent(&genesis.layer2_voucher_id, anchor)
            .await;
        shard.ready.mark_shard_ready(shard_id);
        shard.transport.spawn_accept_loop();
    }

    let (verdict, _) = gateway_engine
        .ingress_hmc_lock_durable(
            genesis_tag.clone(),
            L2LockEntry::from(&genesis),
            IngressOrigin::PartitionSync,
            Some(now),
            None,
            None,
            Some(genesis.layer2_voucher_id.clone()),
        )
        .await;
    assert!(matches!(verdict, L2Verdict::Verified { .. }));
    gateway_engine
        .record_hmc_voucher_genesis_parent(&genesis.layer2_voucher_id, anchor)
        .await;
    gateway_transport.spawn_accept_loop();

    let pow = Arc::new(PowEngine::new(*gateway.node_id(), 1));
    let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
    tc.register_f2f_peer("test_peer_token");
    let mut state = AppState::new(gateway_engine.clone(), storage, gateway, tc, pow);
    state.peer_manager = Some(gateway_pm);
    state.transport = Some(gateway_transport.clone());
    state.readiness_manager.mark_shard_ready(shard_id);
    let app = build_router(state);

    TestCluster {
        app,
        shards,
        gateway_engine,
        gateway_transport,
        cancel,
        owner_key,
        genesis,
        genesis_tag,
        shard_id,
        committee,
        root_valid_until,
    }
}

// ===========================================================================
// Test 1: GET /v1/regional-mesh-view + 5s Cache Hit + Valid Ed25519 Signature
// ===========================================================================
#[tokio::test]
async fn test_public_regional_mesh_view_and_cache() {
    let temp = tempdir().unwrap();
    let (_app, mut state, identity) = setup_standalone_app(&temp);

    let pm = Arc::new(PeerManager::new(Vec::new()));
    pm.set_simulation_mode(true);
    for _ in 0..20 {
        let member = NodeIdentity::generate();
        pm.learn_node_from_gossip_with_hrw(
            *member.node_pubkey(),
            *member.hrw_routing_id(),
            "127.0.0.1:1".parse().unwrap(),
            0,
            None,
        )
        .await;
        pm.set_first_seen_for_test(
            member.node_pubkey(),
            Instant::now() - Duration::from_secs(25 * 3600),
        )
        .await;
    }
    force_stable_ge20(&pm).await;
    state.peer_manager = Some(pm);
    let app = build_router(state.clone());

    // First request: Cache Miss -> Computes and signs new RegionalMeshView
    let req1 = Request::builder()
        .method("GET")
        .uri("/v1/regional-mesh-view")
        .body(Body::empty())
        .unwrap();
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let bytes1 = resp1.into_body().collect().await.unwrap().to_bytes();
    let view1: RegionalMeshView = serde_json::from_slice(&bytes1).unwrap();

    assert_eq!(view1.source_key, *identity.node_pubkey());
    assert!(view1.members.len() >= 20);

    // Cryptographic verification of Ed25519 signature
    let digest1 = view1.digest().expect("Digest computation must succeed");
    let vk = VerifyingKey::from_bytes(&view1.source_key).expect("Valid source pubkey");
    let sig1 = Signature::from_bytes(&view1.signature);
    vk.verify_strict(&digest1, &sig1)
        .expect("Signature must be strictly valid");

    // Second request: Cache Hit (< 5s TTL) -> Returns exact cached view without re-signing
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/regional-mesh-view")
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let bytes2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let view2: RegionalMeshView = serde_json::from_slice(&bytes2).unwrap();

    assert_eq!(
        view2.signature, view1.signature,
        "Cache hit must return identical signature (zero CPU re-signing)"
    );
    assert_eq!(
        view2.issued_at_ms, view1.issued_at_ms,
        "Cache hit must preserve original timestamp"
    );
    assert!(
        state.mesh_view_cache.read().is_some(),
        "mesh_view_cache must be populated in AppState"
    );
}

// ===========================================================================
// Test 2: POST /v1/lock with HMC_TX_AUTH_V4 + Clock Drift Window Handling
// ===========================================================================
#[tokio::test]
async fn test_post_v1_lock_v4_signature_and_clock_drift() {
    let temp = tempdir().unwrap();
    let (app, state, _identity) = setup_standalone_app(&temp);
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let now = test_now_ms();

    // Setup Genesis anchor
    let genesis = make_genesis_lock("v4_drift", now + 1_000_000, &key);
    let genesis_tag = bs58::encode(genesis.transaction_hash).into_string();
    let anchor = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    state
        .engine
        .ingress_hmc_lock_durable(
            genesis_tag.clone(),
            L2LockEntry::from(&genesis),
            IngressOrigin::ClientApi,
            None,
            None,
            None,
            None,
        )
        .await;
    state
        .engine
        .record_hmc_voucher_genesis_parent(&genesis.layer2_voucher_id, anchor)
        .await;

    // Case 2a: Offline spend with past created_at_ms (5 minutes ago = 300_000 ms) -> ACCEPTED (201)
    let past_spend = make_spend_lock(
        &genesis.layer2_voucher_id,
        &genesis_tag,
        [101; 32],
        now + 800_000,
        now - 300_000,
        &key,
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "test_peer_token")
        .body(Body::from(serde_json::to_vec(&past_spend).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "Offline spend with past created_at_ms must be accepted"
    );

    // Case 2b: Future created_at_ms exceeding 30s (+35s) -> REJECTED with 400 Bad Request
    let future_spend = make_spend_lock(
        &genesis.layer2_voucher_id,
        "future_tag",
        [102; 32],
        now + 800_000,
        now + 35_000,
        &key,
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "test_peer_token")
        .body(Body::from(serde_json::to_vec(&future_spend).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Spend with future created_at_ms > 30s must be rejected"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let env: L2ResponseEnvelope = serde_json::from_slice(&bytes).unwrap();
    match env.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(
                reason.contains("30s"),
                "Error message must specify 30s clock drift bound, got: {}",
                reason
            );
        }
        other => panic!("Expected Rejected verdict, got {:?}", other),
    }

    // Case 2c: Invalid signature (legacy V3 domain or corrupted) -> REJECTED with 400
    let mut invalid_spend = make_spend_lock(
        &genesis.layer2_voucher_id,
        "v3_tag",
        [103; 32],
        now + 800_000,
        now,
        &key,
    );
    // Sign with arbitrary / wrong domain hash instead of HMC_TX_AUTH_V4_DOMAIN
    let bogus_hash = blake3::derive_key("WRONG_LEGACY_DOMAIN_TAG", &[0u8; 32]);
    invalid_spend.layer2_signature = key.sign(&bogus_hash).to_bytes();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "test_peer_token")
        .body(Body::from(serde_json::to_vec(&invalid_spend).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Lock signed with non-V4 domain must be rejected"
    );
}

// ===========================================================================
// Test 3: POST /v1/verify-current Unoccupied and Occupied 14/20 Proofs
// ===========================================================================
#[tokio::test]
async fn test_post_v1_verify_current_unoccupied_and_occupied() {
    let temp = tempdir().unwrap();
    let cluster = setup_test_cluster(&temp).await;
    let now = test_now_ms();

    // -----------------------------------------------------------------------
    // Part 3a: Empty slot -> LiveSlotOccupancy::Unoccupied 14/20 Quorum Proof
    // -----------------------------------------------------------------------
    let empty_tag = "unoccupied_test_slot";
    let unoccupied_ctx = LiveStateContext {
        version: 1,
        network: 0,
        shard_id: cluster.shard_id,
        voucher_id: cluster.genesis.layer2_voucher_id.clone(),
        lookup_tag: empty_tag.to_string(),
        parent_lock: *blake3::hash(empty_tag.as_bytes()).as_bytes(),
        child_lock: [0; 32],
        root_valid_until: 0,
        state_digest: [0; 32],
        recipient_nonce: [55; 32],
        committee: cluster.committee.clone(),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify-current")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&unoccupied_ctx).unwrap()))
        .unwrap();
    let resp = cluster.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let proof: LiveStateProof = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        proof.occupancy,
        LiveSlotOccupancy::Unoccupied,
        "Proof must be marked Unoccupied for empty slot"
    );
    assert!(
        proof.votes.len() >= 14,
        "Must accumulate >= 14 quorum votes, got {}",
        proof.votes.len()
    );
    verify_live_unoccupied_proof(&proof, &unoccupied_ctx)
        .expect("verify_live_unoccupied_proof must succeed");
    assert!(
        verify_live_state_proof(&proof, &unoccupied_ctx).is_err(),
        "verify_live_state_proof must reject unoccupied proof"
    );

    // -----------------------------------------------------------------------
    // Part 3b: Locked slot -> LiveSlotOccupancy::Occupied 14/20 Quorum Proof
    // -----------------------------------------------------------------------
    let spent_spend = make_spend_lock(
        &cluster.genesis.layer2_voucher_id,
        &cluster.genesis_tag,
        [222; 32],
        cluster.root_valid_until,
        now,
        &cluster.owner_key,
    );
    let entry = L2LockEntry::from(&spent_spend);
    let entry_digest = *blake3::hash(&serde_json::to_vec(&entry).unwrap()).as_bytes();

    for shard in &cluster.shards {
        let (verdict, _) = shard
            .engine
            .ingress_hmc_lock_durable(
                cluster.genesis_tag.clone(),
                entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
                None,
                None,
                Some(cluster.genesis.layer2_voucher_id.clone()),
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }
    let (verdict, _) = cluster
        .gateway_engine
        .ingress_hmc_lock_durable(
            cluster.genesis_tag.clone(),
            entry.clone(),
            IngressOrigin::PartitionSync,
            Some(now),
            None,
            None,
            Some(cluster.genesis.layer2_voucher_id.clone()),
        )
        .await;
    assert!(matches!(verdict, L2Verdict::Verified { .. }));

    let occupied_ctx = LiveStateContext {
        version: 1,
        network: 0,
        shard_id: cluster.shard_id,
        voucher_id: cluster.genesis.layer2_voucher_id.clone(),
        lookup_tag: cluster.genesis_tag.clone(),
        parent_lock: *blake3::hash(cluster.genesis_tag.as_bytes()).as_bytes(),
        child_lock: entry.t_id,
        root_valid_until: cluster.root_valid_until,
        state_digest: entry_digest,
        recipient_nonce: [77; 32],
        committee: cluster.committee.clone(),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify-current")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&occupied_ctx).unwrap()))
        .unwrap();
    let resp = cluster.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let proof: LiveStateProof = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        proof.occupancy,
        LiveSlotOccupancy::Occupied,
        "Proof must be marked Occupied for locked slot"
    );
    assert!(
        proof.votes.len() >= 14,
        "Must accumulate >= 14 quorum votes, got {}",
        proof.votes.len()
    );
    verify_live_state_proof(&proof, &occupied_ctx).expect("verify_live_state_proof must succeed");

    cluster.cancel.cancel();
    cluster.gateway_transport.close();
    for shard in cluster.shards {
        shard.transport.close();
    }
}

async fn checkout_request(cluster: &TestCluster, anchor_gateway: bool) -> L2CheckoutRequest {
    let now = test_now_ms();

    // Populate the terminal spend in the cluster
    let spend = make_spend_lock(
        &cluster.genesis.layer2_voucher_id,
        &cluster.genesis_tag,
        [188; 32],
        cluster.root_valid_until,
        now,
        &cluster.owner_key,
    );
    let entry = L2LockEntry::from(&spend);
    let entry_digest = *blake3::hash(&serde_json::to_vec(&entry).unwrap()).as_bytes();

    for shard in &cluster.shards {
        shard
            .engine
            .ingress_hmc_lock_durable(
                cluster.genesis_tag.clone(),
                entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
                None,
                None,
                Some(cluster.genesis.layer2_voucher_id.clone()),
            )
            .await;
    }
    if anchor_gateway {
        cluster
            .gateway_engine
            .ingress_hmc_lock_durable(
                cluster.genesis_tag.clone(),
                entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
                None,
                None,
                Some(cluster.genesis.layer2_voucher_id.clone()),
            )
            .await;
    }

    let live_context = LiveStateContext {
        version: 1,
        network: 0,
        shard_id: cluster.shard_id,
        voucher_id: cluster.genesis.layer2_voucher_id.clone(),
        lookup_tag: cluster.genesis_tag.clone(),
        parent_lock: *blake3::hash(cluster.genesis_tag.as_bytes()).as_bytes(),
        child_lock: entry.t_id,
        root_valid_until: cluster.root_valid_until,
        state_digest: entry_digest,
        recipient_nonce: [99; 32],
        committee: cluster.committee.clone(),
    };

    let chain_req = L2ChainLockRequest {
        auth: spend.auth.clone(),
        layer2_voucher_id: cluster.genesis.layer2_voucher_id.clone(),
        chain: vec![spend],
    };

    L2CheckoutRequest {
        lock_chain: Some(chain_req),
        live_context,
    }
}

// ===========================================================================
// Test 4: POST /v1/checkout 1-RTT PoS Single Roundtrip Proof
// ===========================================================================
#[tokio::test]
async fn test_post_v1_checkout_single_rtt() {
    let temp = tempdir().unwrap();
    let cluster = setup_test_cluster(&temp).await;
    let checkout_req = checkout_request(&cluster, true).await;
    let live_context = checkout_req.live_context.clone();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/checkout")
        .header("content-type", "application/json")
        .header("x-peer-token", "test_peer_token")
        .body(Body::from(serde_json::to_vec(&checkout_req).unwrap()))
        .unwrap();

    let resp = cluster.app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Checkout must succeed in 1-RTT"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let checkout_resp: L2CheckoutResponse = serde_json::from_slice(&bytes).unwrap();

    assert!(
        checkout_resp.conflicting_lock.is_none(),
        "No conflict expected on clean checkout"
    );
    assert_eq!(
        checkout_resp.proof.occupancy,
        LiveSlotOccupancy::Occupied,
        "Checkout proof must be Occupied"
    );
    assert!(
        checkout_resp.proof.votes.len() >= 14,
        "Checkout must return >= 14 quorum votes, got {}",
        checkout_resp.proof.votes.len()
    );
    verify_live_state_proof(&checkout_resp.proof, &live_context)
        .expect("verify_live_state_proof must succeed for checkout proof");

    cluster.cancel.cancel();
    cluster.gateway_transport.close();
    for shard in cluster.shards {
        shard.transport.close();
    }
}

#[tokio::test]
async fn checkout_deadline_includes_incomplete_json_extraction() {
    let temp = tempdir().unwrap();
    let (app, _state, _identity) = setup_standalone_app(&temp);
    let (mut sender, body) =
        http_body_util::channel::Channel::<bytes::Bytes, std::convert::Infallible>::new(1);
    sender
        .send_data(bytes::Bytes::from_static(b"{"))
        .await
        .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/checkout")
        .header("content-type", "application/json")
        .body(Body::new(body))
        .unwrap();

    let response = tokio::time::timeout(Duration::from_millis(900), app.oneshot(request)).await;
    drop(sender);
    assert_eq!(
        response
            .expect("Checkout must time out before the body completes")
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE,
    );
}

#[tokio::test]
async fn checkout_deadline_bounds_initial_ram_wait() {
    let temp = tempdir().unwrap();
    let cluster = setup_test_cluster(&temp).await;
    let checkout_req = checkout_request(&cluster, true).await;
    // The gateway RAM guard remains held through the deadline.
    let gateway_guard = cluster.gateway_engine.hmc_ram.write().await;
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/checkout")
            .header("content-type", "application/json")
            .header("x-peer-token", "test_peer_token")
            .body(Body::from(serde_json::to_vec(&checkout_req).unwrap()))
            .unwrap()
    };
    let initial_result = tokio::time::timeout(
        Duration::from_millis(900),
        cluster.app.clone().oneshot(request()),
    )
    .await;
    drop(gateway_guard);
    assert_eq!(
        initial_result
            .expect("Initial RAM wait must respect the request deadline")
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE,
    );

    cluster.cancel.cancel();
    cluster.gateway_transport.close();
    for shard in cluster.shards {
        shard.transport.close();
    }
}

#[tokio::test]
async fn checkout_deadline_shares_json_and_quic_budget() {
    let temp = tempdir().unwrap();
    let cluster = setup_test_cluster(&temp).await;
    let checkout_req = checkout_request(&cluster, false).await;
    let manager = cluster.gateway_transport.peer_manager();
    let mut connections = Vec::new();
    for shard in &cluster.shards {
        let addr = shard.transport.local_addr().unwrap();
        let connection = cluster.gateway_transport.connect_peer(addr).await.unwrap();
        connections.push((connection.clone(), connection.stats().frame_tx.stream));
    }

    assert!(cluster
        .gateway_engine
        .get_hmc_ram_lock(&checkout_req.live_context.lookup_tag)
        .await
        .is_none());
    // JSON extraction consumes part of the same budget before nested chain
    // registration blocks on real QUIC custodians' RAM guards. The gateway
    // has no terminal spend, so checkout cannot skip chain registration.
    let mut remote_guards = Vec::new();
    for shard in &cluster.shards {
        remote_guards.push(shard.engine.hmc_ram.write().await);
    }
    let bytes = serde_json::to_vec(&checkout_req).unwrap();
    let (mut sender, body) =
        http_body_util::channel::Channel::<bytes::Bytes, std::convert::Infallible>::new(1);
    sender
        .send_data(bytes::Bytes::copy_from_slice(&bytes[..1]))
        .await
        .unwrap();
    let streaming_request = Request::builder()
        .method("POST")
        .uri("/v1/checkout")
        .header("content-type", "application/json")
        .header("x-peer-token", "test_peer_token")
        .body(Body::new(body))
        .unwrap();
    let shared_request = async {
        let response = cluster.app.clone().oneshot(streaming_request);
        let finish_body = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            sender
                .send_data(bytes::Bytes::copy_from_slice(&bytes[1..]))
                .await
                .unwrap();
            drop(sender);
        };
        let (response, ()) = tokio::join!(response, finish_body);
        response
    };
    let shared_result = tokio::time::timeout(Duration::from_millis(900), shared_request).await;
    drop(remote_guards);
    assert_eq!(
        shared_result
            .expect("JSON extraction and QUIC collection must share one budget")
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE,
    );
    assert!(
        connections
            .iter()
            .any(|(connection, before)| connection.stats().frame_tx.stream > *before),
        "Nested chain registration must execute actual QUIC RPCs before its deadline"
    );
    for shard in &cluster.shards {
        let peer = manager
            .get_peer(&shard.transport.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(peer.missing_count, 0, "Deadline cancellation is neutral");
    }
    assert!(cluster.gateway_engine.is_signing_healthy());
    cluster.cancel.cancel();
    cluster.gateway_transport.close();
    for shard in cluster.shards {
        shard.transport.close();
    }
}

// ===========================================================================
// Test 5: POST /v1/status MissingLocks carries Anchor Lock
// ===========================================================================
#[tokio::test]
async fn test_post_v1_status_missing_locks_returns_anchor() {
    let temp = tempdir().unwrap();
    let (app, state, _identity) = setup_standalone_app(&temp);
    let key = SigningKey::from_bytes(&[77u8; 32]);
    let now = test_now_ms();

    let genesis = make_genesis_lock("anchor_test", now + 1_000_000, &key);
    let genesis_tag = bs58::encode(genesis.transaction_hash).into_string();
    let anchor = *blake3::hash(genesis_tag.as_bytes()).as_bytes();

    let (v_gen, is_new) = state
        .engine
        .ingress_hmc_lock_durable(
            genesis_tag.clone(),
            L2LockEntry::from(&genesis),
            IngressOrigin::ClientApi,
            None,
            None,
            None,
            None,
        )
        .await;
    assert!(is_new);
    assert!(matches!(v_gen, L2Verdict::Verified { .. }));
    state
        .engine
        .record_hmc_voucher_genesis_parent(&genesis.layer2_voucher_id, anchor)
        .await;

    // Status query on an unspent tag with empty locator prefixes
    let status_query = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: [1u8; 32],
            auth_signature: None,
        },
        layer2_voucher_id: genesis.layer2_voucher_id.clone(),
        challenge_ds_tag: "unspent_tag_probe".to_string(),
        locator_prefixes: Vec::new(),
        read_quorum: 1,
        root_context: None,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .header("content-type", "application/json")
        .header("x-peer-token", "test_peer_token")
        .body(Body::from(serde_json::to_vec(&status_query).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let env: L2ResponseEnvelope = serde_json::from_slice(&bytes).unwrap();

    match env.verdict {
        L2Verdict::MissingLocks {
            sync_point,
            anchor_lock,
        } => {
            assert_eq!(
                sync_point, "genesis",
                "Unspent query with empty locators must sync from genesis"
            );
            assert!(
                anchor_lock.is_some(),
                "query_status must attach anchor_lock on MissingLocks"
            );
            let anchor_entry = anchor_lock.unwrap();
            assert_eq!(
                anchor_entry.layer2_voucher_id, genesis.layer2_voucher_id,
                "anchor_lock must correspond to queried voucher"
            );
            assert_eq!(
                anchor_entry.t_id, genesis.transaction_hash,
                "anchor_lock must have t_id matching genesis transaction_hash"
            );
        }
        other => panic!("Expected MissingLocks, got {:?}", other),
    }
}

// ===========================================================================
// Regression Tests for S01-06:
// Unoccupied /v1/verify-current discovering occupied lock under 20-member committee
// ===========================================================================

#[tokio::test]
async fn test_post_v1_verify_current_unoccupied_discovering_occupied_remote_numeric_control() {
    let temp = tempdir().unwrap();
    let cluster = setup_test_cluster(&temp).await;
    let now = test_now_ms();

    let spent_spend = make_spend_lock(
        &cluster.genesis.layer2_voucher_id,
        &cluster.genesis_tag,
        [211; 32],
        cluster.root_valid_until,
        now,
        &cluster.owner_key,
    );
    let entry = L2LockEntry::from(&spent_spend);
    let entry_digest = *blake3::hash(&serde_json::to_vec(&entry).unwrap()).as_bytes();

    // 14 remote custodians (shards 0..14) durably store the occupied spend
    for shard in &cluster.shards[0..14] {
        let (verdict, _) = shard
            .engine
            .ingress_hmc_lock_durable(
                cluster.genesis_tag.clone(),
                entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
                None,
                None,
                Some(cluster.genesis.layer2_voucher_id.clone()),
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }
    // Make remaining 6 remote committee members unable to vote
    for shard in &cluster.shards[14..20] {
        shard.ready.invalidate_shard(cluster.shard_id);
    }

    // Collector is outside committee (gateway)
    let unoccupied_ctx = LiveStateContext {
        version: 1,
        network: 0,
        shard_id: cluster.shard_id,
        voucher_id: cluster.genesis.layer2_voucher_id.clone(),
        lookup_tag: cluster.genesis_tag.clone(),
        parent_lock: *blake3::hash(cluster.genesis_tag.as_bytes()).as_bytes(),
        child_lock: [0; 32],
        root_valid_until: 0,
        state_digest: [0; 32],
        recipient_nonce: [111; 32],
        committee: cluster.committee.clone(),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify-current")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&unoccupied_ctx).unwrap()))
        .unwrap();
    let resp = cluster.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let proof: LiveStateProof = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(proof.occupancy, LiveSlotOccupancy::Occupied);
    assert!(
        proof.votes.len() >= 14,
        "Must have >= 14 votes, got {}",
        proof.votes.len()
    );
    assert_eq!(proof.context.child_lock, entry.t_id);
    assert_eq!(proof.context.state_digest, entry_digest);
    assert_eq!(proof.context.root_valid_until, cluster.root_valid_until);
    verify_live_state_proof(&proof, &proof.context).expect("verify_live_state_proof must succeed");

    cluster.cancel.cancel();
    cluster.gateway_transport.close();
    for shard in cluster.shards {
        shard.transport.close();
    }
}

#[tokio::test]
async fn test_post_v1_verify_current_unoccupied_discovering_occupied_in_committee_numeric() {
    let temp = tempdir().unwrap();
    let cluster = setup_test_cluster(&temp).await;
    let now = test_now_ms();

    let collector_pubkey = *cluster.shards[0].id.node_pubkey();
    assert!(cluster.committee.contains(&collector_pubkey));
    let collector_app = build_shard_app(&cluster.shards[0], cluster.shard_id);

    let spent_spend = make_spend_lock(
        &cluster.genesis.layer2_voucher_id,
        &cluster.genesis_tag,
        [212; 32],
        cluster.root_valid_until,
        now,
        &cluster.owner_key,
    );
    let entry = L2LockEntry::from(&spent_spend);
    let entry_digest = *blake3::hash(&serde_json::to_vec(&entry).unwrap()).as_bytes();

    // 1 local collector (shard 0) + 13 remote custodians (shards 1..14) = 14 custodians
    for shard in &cluster.shards[0..14] {
        let (verdict, _) = shard
            .engine
            .ingress_hmc_lock_durable(
                cluster.genesis_tag.clone(),
                entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
                None,
                None,
                Some(cluster.genesis.layer2_voucher_id.clone()),
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }
    // Invalidate the other 6 remote committee members
    for shard in &cluster.shards[14..20] {
        shard.ready.invalidate_shard(cluster.shard_id);
    }

    let unoccupied_ctx = LiveStateContext {
        version: 1,
        network: 0,
        shard_id: cluster.shard_id,
        voucher_id: cluster.genesis.layer2_voucher_id.clone(),
        lookup_tag: cluster.genesis_tag.clone(),
        parent_lock: *blake3::hash(cluster.genesis_tag.as_bytes()).as_bytes(),
        child_lock: [0; 32],
        root_valid_until: 0,
        state_digest: [0; 32],
        recipient_nonce: [112; 32],
        committee: cluster.committee.clone(),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify-current")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&unoccupied_ctx).unwrap()))
        .unwrap();
    let resp = collector_app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let proof: LiveStateProof = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(proof.occupancy, LiveSlotOccupancy::Occupied);
    assert!(
        proof.votes.len() >= 14,
        "Must have >= 14 votes, got {}",
        proof.votes.len()
    );
    assert_eq!(proof.context.child_lock, entry.t_id);
    assert_eq!(proof.context.state_digest, entry_digest);
    assert_eq!(proof.context.root_valid_until, cluster.root_valid_until);
    verify_live_state_proof(&proof, &proof.context).expect("verify_live_state_proof must succeed");
    assert!(
        proof.votes.iter().any(|v| v.signer_pubkey == collector_pubkey),
        "Collector's own vote must be included in proof"
    );

    cluster.cancel.cancel();
    cluster.gateway_transport.close();
    for shard in cluster.shards {
        shard.transport.close();
    }
}

#[tokio::test]
async fn test_post_v1_verify_current_unoccupied_discovering_occupied_in_committee_rfc3339() {
    let temp = tempdir().unwrap();
    let now = test_now_ms();
    let root_ms = now + 3_600_000;
    let rfc_str = chrono::DateTime::from_timestamp_millis(root_ms as i64)
        .expect("valid timestamp")
        .to_rfc3339();
    let cluster = setup_test_cluster_with_root(&temp, Some(rfc_str.clone())).await;

    let collector_pubkey = *cluster.shards[0].id.node_pubkey();
    assert!(cluster.committee.contains(&collector_pubkey));
    let collector_app = build_shard_app(&cluster.shards[0], cluster.shard_id);

    let spent_spend = make_spend_lock_with_deletable(
        &cluster.genesis.layer2_voucher_id,
        &cluster.genesis_tag,
        [213; 32],
        Some(rfc_str.clone()),
        now,
        &cluster.owner_key,
    );
    let entry = L2LockEntry::from(&spent_spend);
    let entry_digest = *blake3::hash(&serde_json::to_vec(&entry).unwrap()).as_bytes();

    // 1 local collector (shard 0) + 13 remote custodians (shards 1..14) = 14 custodians
    for shard in &cluster.shards[0..14] {
        let (verdict, _) = shard
            .engine
            .ingress_hmc_lock_durable(
                cluster.genesis_tag.clone(),
                entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
                None,
                None,
                Some(cluster.genesis.layer2_voucher_id.clone()),
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }
    // Invalidate remaining 6 remote committee members
    for shard in &cluster.shards[14..20] {
        shard.ready.invalidate_shard(cluster.shard_id);
    }

    let unoccupied_ctx = LiveStateContext {
        version: 1,
        network: 0,
        shard_id: cluster.shard_id,
        voucher_id: cluster.genesis.layer2_voucher_id.clone(),
        lookup_tag: cluster.genesis_tag.clone(),
        parent_lock: *blake3::hash(cluster.genesis_tag.as_bytes()).as_bytes(),
        child_lock: [0; 32],
        root_valid_until: 0,
        state_digest: [0; 32],
        recipient_nonce: [113; 32],
        committee: cluster.committee.clone(),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify-current")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&unoccupied_ctx).unwrap()))
        .unwrap();
    let resp = collector_app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let proof: LiveStateProof = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(proof.occupancy, LiveSlotOccupancy::Occupied);
    assert!(
        proof.votes.len() >= 14,
        "Must have >= 14 votes, got {}",
        proof.votes.len()
    );
    assert_eq!(proof.context.child_lock, entry.t_id);
    assert_eq!(proof.context.state_digest, entry_digest);
    assert_eq!(proof.context.root_valid_until, root_ms);
    verify_live_state_proof(&proof, &proof.context).expect("verify_live_state_proof must succeed");
    assert!(
        proof.votes.iter().any(|v| v.signer_pubkey == collector_pubkey),
        "Collector's own vote must be included in proof"
    );

    cluster.cancel.cancel();
    cluster.gateway_transport.close();
    for shard in cluster.shards {
        shard.transport.close();
    }
}

#[tokio::test]
async fn test_post_v1_verify_current_unoccupied_discovering_occupied_in_committee_inherited_expiry() {
    let temp = tempdir().unwrap();
    let now = test_now_ms();
    let root_ms = now + 3_600_000;
    let rfc_str = chrono::DateTime::from_timestamp_millis(root_ms as i64)
        .expect("valid timestamp")
        .to_rfc3339();
    let cluster = setup_test_cluster_with_root(&temp, Some(rfc_str)).await;

    let collector_pubkey = *cluster.shards[0].id.node_pubkey();
    assert!(cluster.committee.contains(&collector_pubkey));
    let collector_app = build_shard_app(&cluster.shards[0], cluster.shard_id);

    // Spend lock with deletable_at: None (inherits root validity)
    let spent_spend = make_spend_lock_with_deletable(
        &cluster.genesis.layer2_voucher_id,
        &cluster.genesis_tag,
        [214; 32],
        None,
        now,
        &cluster.owner_key,
    );
    let entry = L2LockEntry::from(&spent_spend);
    let entry_digest = *blake3::hash(&serde_json::to_vec(&entry).unwrap()).as_bytes();

    // 1 local collector (shard 0) + 13 remote custodians (shards 1..14) = 14 custodians
    for shard in &cluster.shards[0..14] {
        let (verdict, _) = shard
            .engine
            .ingress_hmc_lock_durable(
                cluster.genesis_tag.clone(),
                entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
                None,
                None,
                Some(cluster.genesis.layer2_voucher_id.clone()),
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }
    // Invalidate remaining 6 remote committee members
    for shard in &cluster.shards[14..20] {
        shard.ready.invalidate_shard(cluster.shard_id);
    }

    let unoccupied_ctx = LiveStateContext {
        version: 1,
        network: 0,
        shard_id: cluster.shard_id,
        voucher_id: cluster.genesis.layer2_voucher_id.clone(),
        lookup_tag: cluster.genesis_tag.clone(),
        parent_lock: *blake3::hash(cluster.genesis_tag.as_bytes()).as_bytes(),
        child_lock: [0; 32],
        root_valid_until: 0,
        state_digest: [0; 32],
        recipient_nonce: [114; 32],
        committee: cluster.committee.clone(),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify-current")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&unoccupied_ctx).unwrap()))
        .unwrap();
    let resp = collector_app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let proof: LiveStateProof = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(proof.occupancy, LiveSlotOccupancy::Occupied);
    assert!(
        proof.votes.len() >= 14,
        "Must have >= 14 votes, got {}",
        proof.votes.len()
    );
    assert_eq!(proof.context.child_lock, entry.t_id);
    assert_eq!(proof.context.state_digest, entry_digest);
    assert_eq!(proof.context.root_valid_until, root_ms);
    verify_live_state_proof(&proof, &proof.context).expect("verify_live_state_proof must succeed");
    assert!(
        proof.votes.iter().any(|v| v.signer_pubkey == collector_pubkey),
        "Collector's own vote must be included in proof"
    );

    cluster.cancel.cancel();
    cluster.gateway_transport.close();
    for shard in cluster.shards {
        shard.transport.close();
    }
}
