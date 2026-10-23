#![forbid(unsafe_code)]

//! Integration tests verifying that `created_at_ms: u64` governs 5-minute bucket routing
//! and ActiveSync synchronization, completely decoupled from private Layer-1
//! voucher `encrypted_timestamp` ciphertext.
//!
//! Enforces:
//! 1. `created_at_ms` determines bucket ID (`floor(created_at_ms / 300_000)`).
//! 2. Arbitrary `encrypted_timestamp` ciphertext does NOT affect bucket calculation.
//! 3. Ingress request with `|created_at_ms - now_ms| > 30_000` is rejected with 400 Bad Request.
//! 4. Idempotent retries with identical `created_at_ms` return 200 OK in the same bucket.

use std::sync::Arc;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use tempfile::tempdir;
use ed25519_dalek::{Signer, SigningKey};

use humoco_node::{
    api::{
        build_router,
        hmc::{
            calculate_l2_payload_hash_raw, L2AuthPayload,
            L2ChainLockRequest, L2LockEntry, L2LockRequest, L2ResponseEnvelope, L2Verdict,
            TRAP_NONE_PLACEHOLDER,
        },
        AppState,
    },
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::{
        framing::{ActiveSyncRequest, ActiveSyncResponse},
        NodeRequestHandler,
    },
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::wire::{MsgType, WireHeader};

/// Explicit test-only readiness for a fresh, isolated registry with no peers.
/// This does not model activation after transfer or dynamic committee changes.
fn isolated_ready(state: &AppState) {
    for shard in 0..=u16::MAX { state.readiness_manager.mark_shard_ready(shard); }
}

fn setup_test_app() -> (
    axum::Router,
    Arc<RedbStorage>,
    NodeIdentity,
    Arc<TierController>,
    Arc<PowEngine>,
    DualTierEngine,
) {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_created_at_bucket.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let state = AppState::new(
        engine.clone(),
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );

    isolated_ready(&state);
    let router = build_router(state);
    (router, storage, identity, tier_controller, pow_engine, engine)
}

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn response_json<T: serde::de::DeserializeOwned>(resp: axum::response::Response) -> T {
    let bytes = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn find_two_tags_for_same_shard(prefix: &str) -> (String, String, u16) {
    // SST collision keys no longer select the voucher's shard. Both output
    // rows belong to the separate root below, regardless of their tag hashes.
    let root = humoco_sim_core::types::genesis_parent_bytes_from_tag(&bs58::encode([0xF0; 32]).into_string());
    (format!("{prefix}_a"), format!("{prefix}_b"), humoco_sim_core::types::canonical_voucher_shard(&root))
}
fn put_bucket_fixture(storage: &RedbStorage, tag: &str, entry: &L2LockEntry) {
    // Typed storage fixture, not a claim of L1 authentication or recovery.
    let mut root = entry.clone(); root.t_id = [0xF0; 32]; root.sender_ephemeral_pub = [0xF1; 32]; root.layer2_signature = [0; 64]; root.created_at_ms = 0; root.encrypted_timestamp = 0; root.trap_r = None; root.trap_s = None;
    storage.put_hmc_lock(&bs58::encode(root.t_id).into_string(), &root).unwrap();
    storage.put_hmc_lock(tag, entry).unwrap();
}
struct BucketWire { client: humoco_node::network::QuicTransport, server: humoco_node::network::QuicTransport, connection: humoco_node::network::pool::PeerConnectionLease, cancel: tokio_util::sync::CancellationToken }
impl BucketWire {
    async fn new(handler: NodeRequestHandler, identity: &NodeIdentity) -> Self {
        use humoco_node::network::{QuicTransport, PeerManager, DefaultRequestHandler};
        let client_id = NodeIdentity::generate();
        let server_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*client_id.node_pubkey()]));
        let client_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*identity.node_pubkey()]));
        let cancel = tokio_util::sync::CancellationToken::new();
        let server = QuicTransport::bind_with_options("127.0.0.1:0".parse().unwrap(), identity, server_pm.clone(), Arc::new(handler), cancel.clone()).unwrap();
        let client = QuicTransport::bind_with_options("127.0.0.1:0".parse().unwrap(), &client_id, client_pm.clone(), Arc::new(DefaultRequestHandler), cancel.clone()).unwrap();
        server_pm.register_f2f_friend(*client_id.node_pubkey(), Some(client.local_addr().unwrap())).await;
        client_pm.register_f2f_friend(*identity.node_pubkey(), Some(server.local_addr().unwrap())).await;
        server.spawn_accept_loop(); client.spawn_accept_loop();
        let connection = client.connect_peer(server.local_addr().unwrap()).await.unwrap();
        Self { client, server, connection, cancel }
    }
    async fn request(&self, header: WireHeader, payload: Vec<u8>) -> Result<(WireHeader, Vec<u8>), humoco_node::error::NodeError> { self.client.send_request(&self.connection, &header, &payload).await }
}
impl Drop for BucketWire { fn drop(&mut self) { self.cancel.cancel(); self.server.close(); self.client.close(); } }


// ---------------------------------------------------------------------------
// Test 1: created_at_ms determines bucket ID (floor(created_at_ms / 300_000))
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_created_at_determines_bucket_id() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_bucket_id.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let handler = NodeRequestHandler::new(engine.clone(), storage.clone(), identity.clone());
    let wire = BucketWire::new(handler, &identity).await;

    let now_ms = test_now_ms();
    let valid_until_ms = now_ms + 600_000;

    let (tag_bucket2, tag_bucket3, shard_id) = find_two_tags_for_same_shard("tag_bucket");

    // Lock 1 in bucket 2: 600_000 ms -> bucket_id = 600_000 / 300_000 = 2
    let created_at_2 = 600_000u64;
    let entry_b2 = L2LockEntry {
        causal_output: None,
        t_id: [0x22; 32],
        layer2_voucher_id: "bucket-fixture".into(),
        sender_ephemeral_pub: [0x11; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 100, // Arbitrary monotonic L1 timestamp
        created_at_ms: created_at_2,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: None,
    };

    // Lock 2 in bucket 3: 900_000 ms -> bucket_id = 900_000 / 300_000 = 3
    let created_at_3 = 900_000u64;
    let entry_b3 = L2LockEntry {
        causal_output: None,
        t_id: [0x33; 32],
        layer2_voucher_id: "bucket-fixture".into(),
        sender_ephemeral_pub: [0x12; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 200,
        created_at_ms: created_at_3,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: None,
    };

    put_bucket_fixture(&storage, &tag_bucket2, &entry_b2);
    put_bucket_fixture(&storage, &tag_bucket3, &entry_b3);

    // 1. ShardBucketRangeRequest for bucket 2 (count 1)
    let bucket_req_2 = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id,
        start_bucket: 2,
        bucket_count: 1,
    };
    let payload = bincode::serialize(&bucket_req_2).unwrap();
    let header = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 1, 0, 0, payload.len() as u32);
    let (_, resp_bytes) = wire.request(header, payload).await.expect("handle bucket range");
    let resp: humoco_sim_core::types::ShardBucketRangeResponse = bincode::deserialize(&resp_bytes).expect("deserialize");
    assert_eq!(resp.buckets.len(), 1);
    assert_eq!(resp.buckets[0].bucket_id, 2);
    assert_eq!(resp.buckets[0].lock_count, 1, "Bucket 2 must contain exactly 1 lock");
    assert_ne!(resp.buckets[0].digest, [0u8; 32]);

    // 2. ShardBucketRangeRequest for bucket 3 (count 1)
    let bucket_req_3 = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id,
        start_bucket: 3,
        bucket_count: 1,
    };
    let payload = bincode::serialize(&bucket_req_3).unwrap();
    let header = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 2, 0, 0, payload.len() as u32);
    let (_, resp_bytes) = wire.request(header, payload).await.expect("handle bucket range");
    let resp: humoco_sim_core::types::ShardBucketRangeResponse = bincode::deserialize(&resp_bytes).expect("deserialize");
    assert_eq!(resp.buckets.len(), 1);
    assert_eq!(resp.buckets[0].bucket_id, 3);
    assert_eq!(resp.buckets[0].lock_count, 1, "Bucket 3 must contain exactly 1 lock");
    assert_ne!(resp.buckets[0].digest, [0u8; 32]);

    // 3. ShardBucketRangeRequest for bucket 1 (count 1) -> must be empty
    let bucket_req_1 = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id,
        start_bucket: 1,
        bucket_count: 1,
    };
    let payload = bincode::serialize(&bucket_req_1).unwrap();
    let header = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 3, 0, 0, payload.len() as u32);
    let (_, resp_bytes) = wire.request(header, payload).await.expect("handle bucket range");
    let resp: humoco_sim_core::types::ShardBucketRangeResponse = bincode::deserialize(&resp_bytes).expect("deserialize");
    assert_eq!(resp.buckets.len(), 1);
    assert_eq!(resp.buckets[0].lock_count, 0, "Bucket 1 must be empty");

    // 4. ActiveSyncRequest filtering by target_bucket_id
    let sync_req_b2 = ActiveSyncRequest::with_bucket(0, 100, Some(2));
    let sync_payload = sync_req_b2.to_bytes().unwrap();
    let sync_hdr = WireHeader::new(MsgType::ActiveSyncRequest as u16, 4, 0, 0, sync_payload.len() as u32);
    let (_, resp_bytes) = wire.request(sync_hdr, sync_payload).await.expect("handle active sync");
    let mut sync_resp = ActiveSyncResponse::from_bytes(&resp_bytes).expect("deserialize sync resp");
    sync_resp.payload.hmc_locks.retain(|(tag, entry)| !humoco_node::storage::db::roots::is_root(tag, entry));
    assert_eq!(sync_resp.payload.hmc_locks.len(), 1, "ActiveSync target_bucket_id=2 must return only Lock 1");
    assert_eq!(sync_resp.payload.hmc_locks[0].1.t_id, [0x22; 32]);

    let sync_req_b3 = ActiveSyncRequest::with_bucket(0, 100, Some(3));
    let sync_payload = sync_req_b3.to_bytes().unwrap();
    let sync_hdr = WireHeader::new(MsgType::ActiveSyncRequest as u16, 5, 0, 0, sync_payload.len() as u32);
    let (_, resp_bytes) = wire.request(sync_hdr, sync_payload).await.expect("handle active sync");
    let mut sync_resp = ActiveSyncResponse::from_bytes(&resp_bytes).expect("deserialize sync resp");
    sync_resp.payload.hmc_locks.retain(|(tag, entry)| !humoco_node::storage::db::roots::is_root(tag, entry));
    assert_eq!(sync_resp.payload.hmc_locks.len(), 1, "ActiveSync target_bucket_id=3 must return only Lock 2");
    assert_eq!(sync_resp.payload.hmc_locks[0].1.t_id, [0x33; 32]);
}

// ---------------------------------------------------------------------------
// Test 2: Arbitrary encrypted_timestamp ciphertext does NOT affect bucket calculation
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_arbitrary_encrypted_timestamp_does_not_affect_bucket() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_ciphertext_independence.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let handler = NodeRequestHandler::new(engine.clone(), storage.clone(), identity.clone());
    let wire = BucketWire::new(handler, &identity).await;

    let now_ms = test_now_ms();
    let valid_until_ms = now_ms + 600_000;
    let (tag_a, tag_b, shard_id) = find_two_tags_for_same_shard("tag_cipher");

    // Both entries have identical created_at_ms = 600_000 (Bucket 2: 600_000 / 300_000 = 2)
    let created_at_ms = 600_000u64;

    // Entry A: encrypted_timestamp = 0
    let entry_a = L2LockEntry {
        causal_output: None,
        t_id: [0xAA; 32],
        layer2_voucher_id: "cipher-fixture".into(),
        sender_ephemeral_pub: [0x55; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: None,
    };

    // Entry B: encrypted_timestamp = massive 128-bit ciphertext
    // (If misused as timestamp, it would map to bucket ~3,333,333,333,333)
    let massive_ciphertext = 999_999_999_999_999_999_u128;
    let entry_b = L2LockEntry {
        causal_output: None,
        t_id: [0xBB; 32],
        layer2_voucher_id: "cipher-fixture".into(),
        sender_ephemeral_pub: [0x66; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: massive_ciphertext,
        created_at_ms,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: None,
    };

    put_bucket_fixture(&storage, &tag_a, &entry_a);
    put_bucket_fixture(&storage, &tag_b, &entry_b);

    // 1. ShardBucketRangeRequest for bucket 2 must find BOTH locks
    let bucket_req = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id,
        start_bucket: 2,
        bucket_count: 1,
    };
    let payload = bincode::serialize(&bucket_req).unwrap();
    let header = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 1, 0, 0, payload.len() as u32);
    let (_, resp_bytes) = wire.request(header, payload).await.expect("handle bucket range");
    let resp: humoco_sim_core::types::ShardBucketRangeResponse = bincode::deserialize(&resp_bytes).expect("deserialize");
    assert_eq!(resp.buckets.len(), 1);
    assert_eq!(resp.buckets[0].bucket_id, 2);
    assert_eq!(resp.buckets[0].lock_count, 2, "Both locks must be in bucket 2 regardless of encrypted_timestamp ciphertext");

    // 2. ShardBucketRangeRequest for the spurious bucket corresponding to encrypted_timestamp as u64
    let spurious_bucket = (massive_ciphertext as u64) / 300_000;
    let spurious_req = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id,
        start_bucket: spurious_bucket,
        bucket_count: 1,
    };
    let payload = bincode::serialize(&spurious_req).unwrap();
    let header = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 2, 0, 0, payload.len() as u32);
    let (_, resp_bytes) = wire.request(header, payload).await.expect("handle bucket range");
    let resp: humoco_sim_core::types::ShardBucketRangeResponse = bincode::deserialize(&resp_bytes).expect("deserialize");
    assert_eq!(resp.buckets[0].lock_count, 0, "Spurious bucket derived from encrypted_timestamp must be completely empty");

    // 3. ActiveSyncRequest with target_bucket_id = Some(2) must return BOTH locks
    let sync_req = ActiveSyncRequest::with_bucket(0, 100, Some(2));
    let sync_payload = sync_req.to_bytes().unwrap();
    let sync_hdr = WireHeader::new(MsgType::ActiveSyncRequest as u16, 3, 0, 0, sync_payload.len() as u32);
    let (_, resp_bytes) = wire.request(sync_hdr, sync_payload).await.expect("handle active sync");
    let mut sync_resp = ActiveSyncResponse::from_bytes(&resp_bytes).expect("deserialize sync resp");
    sync_resp.payload.hmc_locks.retain(|(tag, entry)| !humoco_node::storage::db::roots::is_root(tag, entry));
    assert_eq!(sync_resp.payload.hmc_locks.len(), 2, "ActiveSync for bucket 2 must return both locks");
}

// ---------------------------------------------------------------------------
// Test 3: Ingress request with |created_at_ms - now_ms| > 30_000 is rejected (400 Bad Request)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ingress_clock_drift_30s_window_enforced() {
    let (app, _storage, _identity, tier_controller, _, engine) = setup_test_app();
    tier_controller.register_f2f_peer("drift_test_token");

    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[42u8; 32]);
    let sender_pub = sender_key.verifying_key().to_bytes();
    let valid_until_str = (now + 600_000).to_string();

    let make_lock_req = |created_at_ms: u64| {
        let tx_hash = [0x77; 32];
        let lookup_tag = "clock-drift-parent".to_string();
        let payload_hash = calculate_l2_payload_hash_raw(
            "voucher_clock_drift",
            &lookup_tag,
            &tx_hash,
            &sender_pub,
            "none",
            "none",
            0,
            created_at_ms,
            None,
            "",
        );
        let sig = sender_key.sign(&payload_hash);
        L2LockRequest {
        causal_output: None,
            auth: L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: "voucher_clock_drift".into(),
            ds_tag: Some(lookup_tag),
            transaction_hash: tx_hash,
            is_genesis: false,
            sender_ephemeral_pub: sender_pub,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: sig.to_bytes(),
            trap_r: Some("none".into()),
            trap_s: Some("none".into()),
            encrypted_timestamp: 0,
            created_at_ms,
            deletable_at: None,
            privacy_guard: None,
        }
    };

    let mut root = make_lock_req(now); root.is_genesis = true; root.ds_tag = None; root.transaction_hash = [0x78; 32]; root.deletable_at = Some(valid_until_str.clone());
    root.layer2_signature = sender_key.sign(&humoco_node::api::hmc::calculate_l2_payload_hash(&root)).to_bytes();
    assert!(matches!(engine.ingress_hmc_lock_durable(bs58::encode(root.transaction_hash).into_string(), (&root).into(), humoco_node::storage::IngressOrigin::ClientApi, Some(now), None, None, None).await.0, L2Verdict::Verified { .. }));
    // Case A: Future drift exceeded (> 30s) -> 35 seconds in future
    let req_future_drift = make_lock_req(now + 35_000);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "drift_test_token")
                .body(Body::from(serde_json::to_vec(&req_future_drift).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "Future clock drift > 30s must be rejected with 400 Bad Request");
    let env: L2ResponseEnvelope = response_json(res).await;
    match env.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(
                reason.contains("30s") && reason.to_lowercase().contains("timestamp"),
                "Expected clock drift error message, got: {}",
                reason
            );
        }
        _ => panic!("Expected Rejected verdict"),
    }

    // Case B: Past drift exceeded (> 30s) -> 35 seconds in past
    let req_past_drift = make_lock_req(now.saturating_sub(35_000));
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "drift_test_token")
                .body(Body::from(serde_json::to_vec(&req_past_drift).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "Past clock drift > 30s must be rejected with 400 Bad Request");
    let env: L2ResponseEnvelope = response_json(res).await;
    match env.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(
                reason.contains("30s") && reason.to_lowercase().contains("timestamp"),
                "Expected clock drift error message, got: {}",
                reason
            );
        }
        _ => panic!("Expected Rejected verdict"),
    }

    // Case C: Chain lock submission with a hop exceeding clock drift
    let chain_req = L2ChainLockRequest {
        auth: req_future_drift.auth.clone(),
        layer2_voucher_id: req_future_drift.layer2_voucher_id.clone(),
        chain: vec![req_future_drift],
    };
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock/chain")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "drift_test_token")
                .body(Body::from(serde_json::to_vec(&chain_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "Chain lock with hop drifting > 30s must be rejected with 400");
    let env: L2ResponseEnvelope = response_json(res).await;
    match env.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(
                reason.contains("30s") && reason.to_lowercase().contains("timestamp"),
                "Expected clock drift error message, got: {}",
                reason
            );
        }
        _ => panic!("Expected Rejected verdict"),
    }

    // Case D: Within 30s window (10s in future) -> accepted (201 Created)
    let req_valid_drift = make_lock_req(now + 10_000);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "drift_test_token")
                .body(Body::from(serde_json::to_vec(&req_valid_drift).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "Clock drift within 30s must be accepted");

    // Case E: an omitted signed creation time cannot be rewritten by the server.
    let mut req_zero_drift = make_lock_req(0);
    req_zero_drift.transaction_hash = [0x88; 32];
    req_zero_drift.layer2_signature = sender_key.sign(&humoco_node::api::hmc::calculate_l2_payload_hash(&req_zero_drift)).to_bytes();
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "drift_test_token")
                .body(Body::from(serde_json::to_vec(&req_zero_drift).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "created_at_ms = 0 must fail without rewriting signed bytes");
}

// ---------------------------------------------------------------------------
// Test 4: Idempotent retries with identical created_at_ms return 200 OK
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_idempotent_retries_with_identical_created_at_returns_200() {
    let (app, _storage, _identity, tier_controller, _, engine) = setup_test_app();
    tier_controller.register_f2f_peer("idempotent_peer_token");

    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[99u8; 32]);
    let sender_pub = sender_key.verifying_key().to_bytes();
    let valid_until_str = (now + 600_000).to_string();

    let tx_hash = [0x44; 32];
    let lookup_tag = bs58::encode(&tx_hash).into_string();

    // Client supplies explicit created_at_ms matching current time
    let created_at_ms = now;
    let payload_hash = calculate_l2_payload_hash_raw(
        TRAP_NONE_PLACEHOLDER,
        &lookup_tag,
        &tx_hash,
        &sender_pub,
        "none",
        "none",
        0,
        created_at_ms,
        Some(&valid_until_str),
        "",
    );
    let sig = sender_key.sign(&payload_hash);
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: "voucher_idempotent_retry".into(),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms,
        deletable_at: Some(valid_until_str),
        privacy_guard: None,
    };

    let mut root = req.clone(); root.transaction_hash = [0x45; 32];
    root.layer2_signature = sender_key.sign(&humoco_node::api::hmc::calculate_l2_payload_hash(&root)).to_bytes();
    assert!(matches!(engine.ingress_hmc_lock_durable(bs58::encode(root.transaction_hash).into_string(), (&root).into(), humoco_node::storage::IngressOrigin::ClientApi, Some(now), None, None, None).await.0, L2Verdict::Verified { .. }));
    req.is_genesis = false; req.ds_tag = Some("idempotent-parent".into()); req.deletable_at = None;
    req.layer2_signature = sender_key.sign(&humoco_node::api::hmc::calculate_l2_payload_hash(&req)).to_bytes();
    let lookup_tag = req.ds_tag.clone().unwrap();
    // 1. First submission -> 201 Created
    let res1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "idempotent_peer_token")
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res1.status(), StatusCode::CREATED);
    let env1: L2ResponseEnvelope = response_json(res1).await;
    match env1.verdict {
        L2Verdict::Verified { ref lock_entry } => {
            assert_eq!(lock_entry.created_at_ms, created_at_ms);
            assert_eq!(lock_entry.t_id, tx_hash);
        }
        _ => panic!("Expected Verified verdict on initial submission"),
    }

    // 2. Retry with identical payload -> 200 OK (Idempotent)
    let res2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "idempotent_peer_token")
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res2.status(), StatusCode::OK, "Retry of same lock must return 200 OK");
    let env2: L2ResponseEnvelope = response_json(res2).await;
    match env2.verdict {
        L2Verdict::Verified { ref lock_entry } => {
            assert_eq!(lock_entry.created_at_ms, created_at_ms);
            assert_eq!(lock_entry.t_id, tx_hash);
        }
        _ => panic!("Expected Verified verdict on idempotent retry"),
    }

    // 3. Verify that the entry remains mapped to the correct bucket in engine RAM
    let hmc_ram = engine.hmc_ram.read().await;
    let stored = hmc_ram.locks.get(&lookup_tag).expect("Lock must be in RAM index");
    assert_eq!(stored.created_at_ms, created_at_ms);
    let expected_bucket = created_at_ms / 300_000;
    assert_eq!(
        humoco_sim_core::types::timestamp_to_bucket_id(stored.created_at_ms),
        expected_bucket
    );
}
