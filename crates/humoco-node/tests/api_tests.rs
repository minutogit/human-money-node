use std::sync::Arc;
use ed25519_dalek::{Signer, SigningKey};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tower::ServiceExt;

use humoco_node::{
    api::{
        build_router,
        hmc::{
            calculate_l2_payload_hash, L2AuthPayload, L2LockRequest, L2ResponseEnvelope, L2Verdict,
        },
        AppState, NodeStatusResponse, PowChallengeResponse, SyncRequest,
        SyncResponse,
    },
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    storage::{DualTierEngine, RedbStorage},
};

fn setup_test_app() -> (axum::Router, Arc<RedbStorage>, NodeIdentity, Arc<TierController>, Arc<PowEngine>) {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_api.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );

    let router = build_router(state);
    (router, storage, identity, tier_controller, pow_engine)
}

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn make_test_hmc_genesis(
    parent_hex: &str,
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(parent_hex.as_bytes()).as_bytes();
    let del_str = valid_until_ms.to_string();

    let mut req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: format!("voucher_{}", parent_hex),
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
        deletable_at: Some(del_str),
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_test_hmc_spend(
    voucher_id: &str,
    ds_tag: &str,
    tx_hash: [u8; 32],
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();

    let mut req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(ds_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

async fn response_json<T: serde::de::DeserializeOwned>(res: axum::response::Response) -> T {
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body_bytes).expect("Failed to deserialize response body")
}

#[tokio::test]
async fn test_api_lock_submission_and_idempotency() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_secret_token");

    let sender_key = SigningKey::from_bytes(&[1u8; 32]);
    let now = test_now_ms();
    let req_payload = make_test_hmc_genesis(&"01".repeat(32), now + 600_000, &sender_key);

    // 1. Initial lock submission -> 201 Created
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let submit_resp: L2ResponseEnvelope = response_json(res).await;
    assert!(matches!(submit_resp.verdict, L2Verdict::Verified { .. }));
    assert_ne!(submit_resp.server_signature, [0u8; 64]);

    // 2. Exact duplicate submission -> 200 OK (Idempotent)
    let req_dup = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res_dup = app.oneshot(req_dup).await.unwrap();
    assert_eq!(res_dup.status(), StatusCode::OK);

    let submit_resp_dup: L2ResponseEnvelope = response_json(res_dup).await;
    assert!(matches!(submit_resp_dup.verdict, L2Verdict::Verified { .. }));
    assert_ne!(submit_resp_dup.server_signature, [0u8; 64]);
}

#[tokio::test]
async fn test_api_lock_conflict_double_spend() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_secret_token");

    let parent_lock = "aa".repeat(32);
    let now = test_now_ms();

    let genesis_key = SigningKey::from_bytes(&[9u8; 32]);
    let genesis_req = make_test_hmc_genesis(&parent_lock, now + 600_000, &genesis_key);

    let res_gen = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "friend_secret_token")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_gen.status(), StatusCode::CREATED);

    let sender_key_a = SigningKey::from_bytes(&[1u8; 32]);
    let req_lock_a = make_test_hmc_spend(&genesis_req.layer2_voucher_id, "spent_tag_01", [0x11; 32], &sender_key_a);

    let res_a = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "friend_secret_token")
                .body(Body::from(serde_json::to_vec(&req_lock_a).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_a.status(), StatusCode::CREATED);

    // Second lock on same ds_tag with different transaction_hash -> 409 Conflict
    let sender_key_b = SigningKey::from_bytes(&[2u8; 32]);
    let req_lock_b = make_test_hmc_spend(&genesis_req.layer2_voucher_id, "spent_tag_01", [0x22; 32], &sender_key_b);

    let res_b = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "friend_secret_token")
                .body(Body::from(serde_json::to_vec(&req_lock_b).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_b.status(), StatusCode::CONFLICT);
    let conflict_resp: L2ResponseEnvelope = response_json(res_b).await;
    assert!(matches!(conflict_resp.verdict, L2Verdict::Conflict { .. }));
}

#[tokio::test]
async fn test_api_pow_challenge_and_public_ingress() {
    let (app, _storage, _identity, _tier_controller, _pow_engine) = setup_test_app();

    let parent_lock = "bb".repeat(32);
    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[3u8; 32]);
    let req_payload = make_test_hmc_genesis(&parent_lock, now + 600_000, &sender_key);

    // 1. Submit without PoW -> 401 Unauthorized
    let res_unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_unauth.status(), StatusCode::UNAUTHORIZED);
    let err_resp: L2ResponseEnvelope = response_json(res_unauth).await;
    assert!(matches!(err_resp.verdict, L2Verdict::Rejected { .. }));

    // Test GET /v1/pow-challenge endpoint
    let res_pow_endpoint = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/pow-challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_pow_endpoint.status(), StatusCode::OK);
    let pow_dto: PowChallengeResponse = response_json(res_pow_endpoint).await;
    assert_eq!(pow_dto.difficulty, 8);

    // 2. Solve PoW Challenge
    let challenge = pow_dto.challenge;
    let nonce = PowEngine::solve_pow(&challenge, 8, 10_000).expect("Solve PoW");

    // 3. Submit with solved PoW -> 201 Created
    let res_pow_ok = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-pow-challenge", &challenge)
                .header("x-pow-nonce", nonce.to_string())
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_pow_ok.status(), StatusCode::CREATED);
    let ok_resp: L2ResponseEnvelope = response_json(res_pow_ok).await;
    assert!(matches!(ok_resp.verdict, L2Verdict::Verified { .. }));
}

#[tokio::test]
async fn test_api_vip_tier_quota_deduction() {
    let (app, storage, _identity, tier_controller, _) = setup_test_app();

    let account_tag = [0x77u8; 32];
    let vip_token = "vip_token_super_secret";
    tier_controller.register_vip_token(vip_token, account_tag);

    // Set initial quota in redb storage: 1000 Byte-Years
    storage.set_quota(&account_tag, 1000).unwrap();
    assert_eq!(storage.get_quota(&account_tag).unwrap(), 1000);

    // 1 Year TTL = 192 Byte-Years (31_536_000 seconds = 31_536_000_000 ms)
    let now = test_now_ms();
    let sender_key_1 = SigningKey::from_bytes(&[4u8; 32]);
    let req_payload = make_test_hmc_genesis(&"dd".repeat(32), now + 31_536_000_000, &sender_key_1);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", vip_token))
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let submit_resp: L2ResponseEnvelope = response_json(res).await;
    assert!(matches!(submit_resp.verdict, L2Verdict::Verified { .. }));

    // Quota should now be deducted in-memory atomically (<1µs, no fsync stall): 1000 - 192 = 808
    assert_eq!(tier_controller.get_cached_vip_quota(&account_tag), Some(808));
    // Durable storage is updated asynchronously; poll for eventual persistence
    for _ in 0..20 {
        if storage.get_quota(&account_tag).unwrap() == 808 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(storage.get_quota(&account_tag).unwrap(), 808);

    // Try submitting with TTL that exceeds remaining quota (e.g. 5 years = 960 BY > 808)
    let sender_key_2 = SigningKey::from_bytes(&[5u8; 32]);
    let req_excess = make_test_hmc_genesis(&"ff".repeat(32), now + 5 * 31_536_000_000, &sender_key_2);

    let res_excess = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", vip_token))
                .body(Body::from(serde_json::to_vec(&req_excess).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_excess.status(), StatusCode::TOO_MANY_REQUESTS);
    let err_resp: L2ResponseEnvelope = response_json(res_excess).await;
    assert!(matches!(err_resp.verdict, L2Verdict::Rejected { .. }));
    // Quota remains 808 (in-memory and eventually on disk)
    assert_eq!(tier_controller.get_cached_vip_quota(&account_tag), Some(808));
    assert_eq!(storage.get_quota(&account_tag).unwrap(), 808);
}

#[tokio::test]
async fn test_api_status_and_sync() {
    let (app, _storage, identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("sync_peer");

    // 1. Check health / status endpoint
    let res_health = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_health.status(), StatusCode::OK);
    let status_dto: NodeStatusResponse = response_json(res_health).await;
    assert_eq!(status_dto.status, "ok");
    assert_eq!(status_dto.node_id, identity.node_id_hex());

    // 2. Submit a lock
    let parent_lock = "12".repeat(32);
    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[6u8; 32]);
    let req_lock = make_test_hmc_genesis(&parent_lock, now + 600_000, &sender_key);
    let tx_id_hex = hex::encode(req_lock.transaction_hash);

    let res_sub = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "sync_peer")
                .body(Body::from(serde_json::to_vec(&req_lock).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_sub.status(), StatusCode::CREATED);

    // 3. Call sync without locator -> lock is returned
    let sync_req = SyncRequest {
        sparse_locators: vec![],
    };
    let res_sync = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_sync.status(), StatusCode::OK);
    let sync_resp: SyncResponse = response_json(res_sync).await;
    assert!(!sync_resp.locks.is_empty());
    assert!(sync_resp.locks.iter().any(|l| l.id == tx_id_hex));

    // 4. Call sync with locator including lock id -> filtered out
    let sync_req_filtered = SyncRequest {
        sparse_locators: vec![tx_id_hex],
    };
    let res_sync_filt = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_req_filtered).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_sync_filt.status(), StatusCode::OK);
    let sync_resp_filt: SyncResponse = response_json(res_sync_filt).await;
    assert!(sync_resp_filt.locks.is_empty());
}

#[tokio::test]
async fn test_api_hmc_native_flow() {
    use humoco_node::api::hmc::{
        calculate_l2_payload_hash_raw, L2AuthPayload, L2LockRequest, L2ResponseEnvelope,
        L2StatusQuery, L2Verdict, TRAP_NONE_PLACEHOLDER,
    };
    use rand::rngs::OsRng;
    use rand::RngCore;
    use ed25519_dalek::{Signer, SigningKey};

    let (app, _storage, identity, tier_controller, _) = setup_test_app();

    let mut rng = OsRng;
    let sender_key = SigningKey::generate(&mut rng);
    let sender_pub = sender_key.verifying_key().to_bytes();

    let mut t_id_bytes = [0u8; 32];
    rng.fill_bytes(&mut t_id_bytes);
    let t_id_bs58 = bs58::encode(&t_id_bytes).into_string();

    let mut vid_bytes = [0u8; 32];
    rng.fill_bytes(&mut vid_bytes);
    let voucher_id = hex::encode(vid_bytes);

    // 1. Create Genesis Lock
    let challenge_ds_tag = t_id_bs58.clone();
    let valid_until_ms = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64) + 600_000;
    let del_str = valid_until_ms.to_string();
    let payload_hash = calculate_l2_payload_hash_raw(
        TRAP_NONE_PLACEHOLDER,
        &challenge_ds_tag,
        &t_id_bytes,
        &sender_pub,
        "none",
        "none",
        0,
        Some(&del_str),
        "",
    );
    let sig = sender_key.sign(&payload_hash);

    let genesis_req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: None,
        transaction_hash: t_id_bytes,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: Some(del_str),
        privacy_guard: None,
    };

    // 0. Verify unauthenticated request without PoW or token gets rejected (Fix for P0-1 Quota-Bypass)
    let res_unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_unauth.status(), StatusCode::UNAUTHORIZED);

    // Register F2F peer token for remaining flow
    tier_controller.register_f2f_peer("hmc_test_token");

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "hmc_test_token")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let envelope: L2ResponseEnvelope = response_json(res).await;
    match envelope.verdict {
        L2Verdict::Verified { ref lock_entry } => {
            assert_eq!(lock_entry.layer2_voucher_id, voucher_id);
            assert_eq!(lock_entry.t_id, t_id_bytes);
        }
        _ => panic!("Expected Verified verdict for genesis"),
    }

    // 1b. Idempotent Retry of Genesis -> 200 OK
    let res_retry = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "hmc_test_token")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_retry.status(), StatusCode::OK);
    let env_retry: L2ResponseEnvelope = response_json(res_retry).await;
    match env_retry.verdict {
        L2Verdict::Verified { ref lock_entry } => {
            assert_eq!(lock_entry.t_id, t_id_bytes);
        }
        _ => panic!("Expected Verified verdict on idempotent retry"),
    }

    // Verify server signature
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&envelope.verdict).unwrap());
    let digest = hasher.finalize();
    let server_sig = ed25519_dalek::Signature::from_bytes(&envelope.server_signature);
    assert!(identity.verifying_key().verify_strict(&digest, &server_sig).is_ok());

    // 2. Query status for Genesis
    let query = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        challenge_ds_tag: t_id_bs58.clone(),
        locator_prefixes: vec![],
        read_quorum: 1,
    };

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/status")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&query).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let envelope: L2ResponseEnvelope = response_json(res).await;
    match envelope.verdict {
        L2Verdict::Verified { lock_entry } => {
            assert_eq!(lock_entry.t_id, t_id_bytes);
        }
        _ => panic!("Expected Verified verdict for status query"),
    }

    // 3. Double-spend attempt on same ds_tag -> 409 Conflict
    let parent_bytes = *blake3::hash(t_id_bs58.as_bytes()).as_bytes();
    let ds_spend_key = SigningKey::generate(&mut rng);
    let ds_spend_pub = ds_spend_key.verifying_key().to_bytes();
    let h_genesis = humoco_node::storage::compute_hmc_canonical_hash(&parent_bytes, &sender_pub, &t_id_bytes);
    let mut diff_t_id = [0u8; 32];
    loop {
        rng.fill_bytes(&mut diff_t_id);
        let h_diff = humoco_node::storage::compute_hmc_canonical_hash(&parent_bytes, &ds_spend_pub, &diff_t_id);
        if h_diff > h_genesis {
            break;
        }
    }
    let ds_payload_hash = calculate_l2_payload_hash_raw(
        &voucher_id,
        &t_id_bs58,
        &diff_t_id,
        &ds_spend_pub,
        "none",
        "none",
        0,
        None,
        "",
    );
    let ds_sig = ds_spend_key.sign(&ds_payload_hash);

    let ds_req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: ds_spend_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: Some(t_id_bs58.clone()),
        transaction_hash: diff_t_id,
        is_genesis: false,
        sender_ephemeral_pub: ds_spend_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: ds_sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let res_spend1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "hmc_test_token")
                .body(Body::from(serde_json::to_vec(&ds_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_spend1.status(), StatusCode::CONFLICT);
    let env_spend1: L2ResponseEnvelope = response_json(res_spend1).await;
    match env_spend1.verdict {
        L2Verdict::Conflict { existing_lock } => {
            // Must return the EXISTING genesis lock entry as evidence!
            assert_eq!(existing_lock.t_id, t_id_bytes);
            assert_ne!(existing_lock.t_id, diff_t_id);
        }
        _ => panic!("Expected Conflict verdict with existing entry on double spend"),
    }

    // Conflicting second spend attempt on same ds_tag -> 409 Conflict
    let ds_spend_key2 = SigningKey::generate(&mut rng);
    let ds_spend_pub2 = ds_spend_key2.verifying_key().to_bytes();
    let mut diff_t_id2 = [0u8; 32];
    loop {
        rng.fill_bytes(&mut diff_t_id2);
        let h_diff2 = humoco_node::storage::compute_hmc_canonical_hash(&parent_bytes, &ds_spend_pub2, &diff_t_id2);
        if h_diff2 > h_genesis {
            break;
        }
    }
    let ds_payload_hash2 = calculate_l2_payload_hash_raw(
        &voucher_id,
        &t_id_bs58,
        &diff_t_id2,
        &ds_spend_pub2,
        "none",
        "none",
        0,
        None,
        "",
    );
    let ds_sig2 = ds_spend_key2.sign(&ds_payload_hash2);

    let ds_req2 = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: ds_spend_pub2,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: Some(t_id_bs58.clone()),
        transaction_hash: diff_t_id2,
        is_genesis: false,
        sender_ephemeral_pub: ds_spend_pub2,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: ds_sig2.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let res_spend2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "hmc_test_token")
                .body(Body::from(serde_json::to_vec(&ds_req2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_spend2.status(), StatusCode::CONFLICT);
    let env_spend2: L2ResponseEnvelope = response_json(res_spend2).await;
    match env_spend2.verdict {
        L2Verdict::Conflict { existing_lock } => {
            // Must return the EXISTING genesis lock entry as evidence!
            assert_eq!(existing_lock.t_id, t_id_bytes);
            assert_ne!(existing_lock.t_id, diff_t_id2);
        }
        _ => panic!("Expected Conflict verdict with existing entry on double spend"),
    }

    // 3b. Missing ds_tag on non-genesis spend -> 400 Bad Request
    let mut no_ds_req = ds_req2.clone();
    no_ds_req.ds_tag = None;
    let no_ds_hash = humoco_node::api::hmc::calculate_l2_payload_hash(&no_ds_req);
    no_ds_req.layer2_signature = ds_spend_key2.sign(&no_ds_hash).to_bytes();
    let res_no_ds = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "hmc_test_token")
                .body(Body::from(serde_json::to_vec(&no_ds_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_no_ds.status(), StatusCode::BAD_REQUEST);
    let env_no_ds: L2ResponseEnvelope = response_json(res_no_ds).await;
    match env_no_ds.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(reason.contains("Missing or empty ds_tag"));
        }
        _ => panic!("Expected Rejected verdict for missing ds_tag"),
    }

    // 4. Query unknown voucher
    let unknown_query = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: "unknown_voucher_hex".to_string(),
        challenge_ds_tag: "abcde".to_string(),
        locator_prefixes: vec![],
        read_quorum: 1,
    };
    let res_unknown = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/status")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&unknown_query).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_unknown.status(), StatusCode::OK);
    let env_unknown: L2ResponseEnvelope = response_json(res_unknown).await;
    match env_unknown.verdict {
        L2Verdict::UnknownVoucher => {}
        _ => panic!("Expected UnknownVoucher verdict"),
    }

    // 5. Invalid signature with valid F2F token -> 400 Bad Request
    let mut bad_sig_req = genesis_req.clone();
    bad_sig_req.layer2_signature[0] ^= 0xFF;
    let res_bad = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "hmc_test_token")
                .body(Body::from(serde_json::to_vec(&bad_sig_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_bad.status(), StatusCode::BAD_REQUEST);
    let env_bad: L2ResponseEnvelope = response_json(res_bad).await;
    match env_bad.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(reason.contains("Invalid cryptographic signature"));
        }
        _ => panic!("Expected Rejected verdict for bad signature"),
    }

    // 5b. Rule 9 (Cheap-Checks-First): unauthenticated bad signature must be rejected with 401 BEFORE signature check
    let res_unauth_bad = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&bad_sig_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res_unauth_bad.status(),
        StatusCode::UNAUTHORIZED,
        "Rule 9 / A09: Unauthenticated spam must be rejected with 401 before expensive signature verification"
    );
}

#[tokio::test]
async fn test_banned_node_ingress_403_rejection() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_banned.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    tier_controller.register_f2f_peer("friend_token");

    let banned_signing_key = SigningKey::from_bytes(&[0x99u8; 32]);
    let banned_pub = banned_signing_key.verifying_key().to_bytes();
    engine.ban_node(banned_pub, 12345).await;

    let state = AppState::new(
        engine.clone(),
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    let app = build_router(state);

    // 1. Submit HMC lock from banned ephemeral key
    let now = test_now_ms();
    let banned_req = make_test_hmc_genesis(&"01".repeat(32), now + 600_000, &banned_signing_key);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "friend_token")
                .body(Body::from(serde_json::to_vec(&banned_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN, "Banned node must be rejected with 403 Forbidden");
}

#[tokio::test]
async fn test_api_quorum_certificate_assembly_standalone() {
    let (app, _storage, identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_token");

    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[8u8; 32]);
    let req_payload = make_test_hmc_genesis(&"0a".repeat(32), now + 600_000, &sender_key);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let submit_resp: L2ResponseEnvelope = response_json(res).await;
    assert!(submit_resp.quorum_certificate.is_some(), "QuorumCertificate must be attached");

    let qc = submit_resp.quorum_certificate.unwrap();
    assert_eq!(qc.status, 0, "Standalone status must be 0 (PROVISIONAL)");
    assert_eq!(qc.active_nodes_count, 1, "Active nodes count must be 1 for standalone");
    assert_eq!(qc.signer_count, 1, "Signer count must be 1 for standalone");
    assert_eq!(qc.signatures.len(), 1);
    assert_eq!(qc.signatures[0].node_id, u16::from_be_bytes([identity.node_id()[0], identity.node_id()[1]]));
}

#[tokio::test]
async fn test_node_request_handler_lock_verify_and_digest() {
    use ed25519_dalek::Signer;
    use humoco_node::network::{NodeRequestHandler, RequestHandler};
    use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_UNAUTHORIZED};

    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_handler.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();

    let handler = NodeRequestHandler::new(engine.clone(), storage.clone(), identity.clone());

    // 1a. Legacy tuple / Sim bypass must be hard-rejected (Phase 1 P0).
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut parent_lock = [0x44; 32];
    parent_lock[0] = 0;
    parent_lock[1] = 1;
    let record = humoco_sim_core::types::LockRecord::new(
        parent_lock,
        [0x33; 32],
        vec![0x01, 0x02],
        humoco_sim_core::types::SimTime(now_ms),
        humoco_sim_core::types::SimTime(now_ms + 60_000),
    );
    let legacy_payload = bincode::serialize(&(record.clone(), now_ms + 600_000u64)).unwrap();
    let legacy_header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        legacy_payload.len() as u32,
    );
    let (legacy_resp, legacy_bytes) = handler
        .handle(legacy_header, legacy_payload)
        .await
        .expect("handle legacy LockVerifyRequest");
    assert_eq!(legacy_resp.msg_type, MsgType::LockVerifyResponse as u16);
    assert_eq!(
        legacy_resp.flags & FLAG_UNAUTHORIZED,
        FLAG_UNAUTHORIZED,
        "Legacy Sim/tuple payload must be rejected with FLAG_UNAUTHORIZED"
    );
    assert!(legacy_bytes.is_empty());

    // 1b. Valid Hmc LockVerifyRequest (epoch-bound envelope, fresh timestamp).
    let sender = NodeIdentity::generate();
    let root_valid_until = now_ms + 600_000;
    let mut hmc_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *sender.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "handler_test_voucher".into(),
        ds_tag: None,
        transaction_hash: [0x55; 32],
        is_genesis: true,
        sender_ephemeral_pub: *sender.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: Some(root_valid_until.to_string()),
        privacy_guard: None,
    };
    {
        let payload_hash = humoco_node::api::hmc::calculate_l2_payload_hash(&hmc_req);
        hmc_req.layer2_signature = sender.signing_key().sign(&payload_hash).to_bytes();
    }
    let entry = humoco_node::api::hmc::L2LockEntry::from(&hmc_req);
    let footprint =
        humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600);
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        sender.node_pubkey(),
        0,
        0,
        now_ms,
        0,
        0,
        footprint,
        false,
        &entry.t_id,
    );
    let sig = sender.signing_key().sign(&digest).to_bytes();
    // Register sender as known peer so direct RPC auth passes without peer_manager.
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
        sender_pubkey: *sender.node_pubkey(),
        sender_signature: sig,
        timestamp_ms: now_ms,
    };
    let payload = bincode::serialize(&wire).unwrap();
    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_header, resp_payload) = handler.handle(header, payload).await.expect("handle LockVerifyRequest");
    assert_eq!(resp_header.msg_type, MsgType::LockVerifyResponse as u16);
    assert!(!resp_payload.is_empty(), "Response payload must contain signed attestation");

    let att: humoco_node::api::AttestationDto = bincode::deserialize(&resp_payload).expect("deserialize attestation");
    assert_eq!(att.lock_id, hex::encode(entry.t_id));
    assert_eq!(att.node_id, u16::from_be_bytes([identity.node_id()[0], identity.node_id()[1]]));

    // 2. Test ShardDigestRequest for the actual Hmc shard.
    let lookup_tag = bs58::encode(&[0x55; 32]).into_string();
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
    let hmc_shard = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
    let digest_header = WireHeader::new(
        MsgType::ShardDigestRequest as u16,
        2,
        0,
        0,
        2,
    );
    let shard_payload = hmc_shard.to_le_bytes().to_vec();
    let (d_resp_header, d_resp_payload) = handler.handle(digest_header, shard_payload).await.expect("handle ShardDigestRequest");
    assert_eq!(d_resp_header.msg_type, MsgType::ShardDigestResponse as u16);
    assert_eq!(d_resp_payload.len(), 40); // 32 bytes digest + 8 bytes count

    let (digest, count): ([u8; 32], u64) = bincode::deserialize(&d_resp_payload).expect("deserialize digest response");
    assert_eq!(count, 1, "Should have 1 active lock");
    assert_ne!(digest, [0u8; 32]);
}

#[tokio::test]
async fn test_phase1_idempotent_retry_with_pow_and_created_at() {
    let (app, _storage, _identity, _tier_controller, pow_engine) = setup_test_app();

    let parent_lock = "88".repeat(32);
    let (challenge, difficulty, _) = pow_engine.generate_challenge();
    let nonce = PowEngine::solve_blake3_hashcash(&challenge, difficulty, 50_000).expect("Solve BLAKE3 PoW");

    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[10u8; 32]);
    let req_payload = make_test_hmc_genesis(&parent_lock, now + 600_000, &sender_key);

    // 1. Initial submission -> 201 Created
    let res1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-pow-challenge", &challenge)
                .header("x-pow-nonce", nonce.to_string())
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res1.status(), StatusCode::CREATED);
    let resp1: L2ResponseEnvelope = response_json(res1).await;
    assert!(matches!(resp1.verdict, L2Verdict::Verified { .. }));

    // 2. Retry with identical payload & PoW -> 200 OK (IdempotentReplay)
    let res2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-pow-challenge", &challenge)
                .header("x-pow-nonce", nonce.to_string())
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res2.status(), StatusCode::OK, "Retry of same lock must be recognized as idempotent (HTTP 200)");
    let resp2: L2ResponseEnvelope = response_json(res2).await;
    assert!(matches!(resp2.verdict, L2Verdict::Verified { .. }));
}

#[tokio::test]
async fn test_phase1_idempotent_retry_without_created_at() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_retry_token");

    let now_ms = test_now_ms();
    let parent_lock = "77".repeat(32);
    let sender_key = SigningKey::from_bytes(&[11u8; 32]);
    let req_payload = make_test_hmc_genesis(&parent_lock, now_ms + 600_000, &sender_key);

    // 1. Initial submission -> 201 Created
    let res1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "friend_retry_token")
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res1.status(), StatusCode::CREATED);
    let resp1: L2ResponseEnvelope = response_json(res1).await;
    assert!(matches!(resp1.verdict, L2Verdict::Verified { .. }));

    // Artificial delay to ensure now_ms would be different
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    // 2. Retry -> 200 OK
    let res2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "friend_retry_token")
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res2.status(), StatusCode::OK, "Retry must succeed as idempotent (HTTP 200)");
    let resp2: L2ResponseEnvelope = response_json(res2).await;
    assert!(matches!(resp2.verdict, L2Verdict::Verified { .. }));
}

#[tokio::test]
async fn test_phase1_hmc_shard_id_derived_from_voucher_anchor_not_tid() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_hmc_token");

    let mut rng = rand::thread_rng();
    let sender_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let sender_pub = sender_key.verifying_key().to_bytes();

    let tx_hash = [0x42u8; 32];
    let lookup_tag = bs58::encode(&tx_hash).into_string();
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();

    // Intentional mismatch: t_id prefix does NOT match parent_bytes prefix
    let mut different_t_id = [0x99u8; 32];
    different_t_id[0] = parent_bytes[0] ^ 0xFF; // guaranteed different from parent_bytes
    different_t_id[1] = parent_bytes[1] ^ 0xFF;

    let voucher_id = "genesis_voucher_anchor".to_string();

    // Anchor Genesis Lock first so origin root is known
    let genesis_tx_hash = [0x77u8; 32];
    let genesis_lookup_tag = bs58::encode(&genesis_tx_hash).into_string();
    let genesis_del_ms = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64) + 600_000;
    let genesis_del_str = genesis_del_ms.to_string();
    let genesis_hash = humoco_node::api::hmc::calculate_l2_payload_hash_raw(
        "none",
        &genesis_lookup_tag,
        &genesis_tx_hash,
        &sender_pub,
        "none",
        "none",
        0,
        Some(&genesis_del_str),
        "",
    );
    let genesis_sig = sender_key.sign(&genesis_hash);
    let genesis_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: None,
        transaction_hash: genesis_tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: genesis_sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: Some(genesis_del_str),
        privacy_guard: None,
    };
    let res_gen = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "friend_hmc_token")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_gen.status(), StatusCode::CREATED);

    let payload_hash = humoco_node::api::hmc::calculate_l2_payload_hash_raw(
        &voucher_id,
        &lookup_tag,
        &different_t_id,
        &sender_pub,
        "none",
        "none",
        0,
        None,
        "",
    );
    let sig = sender_key.sign(&payload_hash);

    let hmc_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id,
        ds_tag: Some(lookup_tag.clone()),
        transaction_hash: different_t_id,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "friend_hmc_token")
                .body(Body::from(serde_json::to_vec(&hmc_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let envelope: humoco_node::api::hmc::L2ResponseEnvelope = response_json(res).await;
    assert!(envelope.quorum_certificate.is_some());
    let qc = envelope.quorum_certificate.unwrap();
    let genesis_parent_bytes = *blake3::hash(genesis_lookup_tag.as_bytes()).as_bytes();
    let expected_genesis_shard_id = u16::from_be_bytes([genesis_parent_bytes[0], genesis_parent_bytes[1]]);

    // Verify: Shard-ID MUST equal expected_genesis_shard_id (derived from genesis voucher anchor), NOT from t_id!
    assert_eq!(qc.shard_id, expected_genesis_shard_id, "Shard ID must be derived from genesis voucher anchor, never from t_id");
}

#[tokio::test]
async fn test_phase1_gateway_hrw_rank_filtering_in_quorum_certificate() {
    let (_router, _storage, identity, _tier_controller, _pow_engine) = setup_test_app();
    let peer_mgr = Arc::new(humoco_node::network::PeerManager::new(vec![]));
    let transport = humoco_node::network::QuicTransport::bind("127.0.0.1:0".parse().unwrap(), &identity).unwrap();

    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[12u8; 32]);
    let req_payload = make_test_hmc_genesis("qc_rank_filtering_parent", now + 600_000, &sender_key);
    let lookup_tag = bs58::encode(&req_payload.transaction_hash).into_string();
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
    let shard_id = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);

    let self_hrw = *identity.hrw_routing_id();
    let self_score = humoco_sim_core::client_flow::compute_hrw_score_f64(&self_hrw, shard_id);

    // Register 25 known peers that have a strictly HIGHER score than self for this shard
    // so that self's rank is > 20 (specifically rank 26).
    let mut found = 0;
    let mut counter = 0u64;
    while found < 25 {
        let mut candidate_id = [0u8; 32];
        candidate_id[0..8].copy_from_slice(&counter.to_le_bytes());
        let candidate_hash = *blake3::hash(&candidate_id).as_bytes();
        let score = humoco_sim_core::client_flow::compute_hrw_score_f64(&candidate_hash, shard_id);
        if score > self_score {
            let addr = format!("127.0.0.1:{}", 15000 + found).parse().unwrap();
            peer_mgr.learn_node_from_gossip(candidate_hash, addr, 1, None).await;
            // Mature the node so it counts in active_known_nodes (24h incubation filter)
            peer_mgr.set_first_seen_for_test(&candidate_hash, std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
            found += 1;
        }
        counter += 1;
    }

    let active_nodes = peer_mgr.active_known_nodes().await;
    assert_eq!(active_nodes.len(), 25);

    // Create AppState with network (transport and peer_mgr)
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_qc_rank.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    tier_controller.register_f2f_peer("gateway_test_token");

    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state.peer_manager = Some(peer_mgr);
    state.transport = Some(transport);

    let app = build_router(state);

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "gateway_test_token")
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Since the 25 peers are uncontactable and the gateway itself is rank > 20,
    // quorum (14/20) cannot be reached. Strict Quorum-Gating returns 503 Service Unavailable.
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let resp: L2ResponseEnvelope = response_json(res).await;
    assert!(resp.quorum_certificate.is_some());
    let qc = resp.quorum_certificate.unwrap();

    let self_node_u16 = identity.node_id_u16();
    // Gateway's own attestation must NOT be present in QuorumCertificate because its rank is > 20!
    let self_attestation_present = qc.signatures.iter().any(|s| s.node_id == self_node_u16);
    assert!(!self_attestation_present, "Gateway with HRW rank > 20 must NOT attest itself into the QuorumCertificate");

    // Task 1: Stateless gateway must NOT write foreign shard lock to local engine or redb!
    assert!(storage.get_hmc_lock(&lookup_tag).unwrap().is_none(), "Stateless gateway must not write foreign shard lock to redb storage");
}

#[tokio::test]
async fn test_api_created_at_clock_drift_exceeded() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("drift_peer_token");

    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[15u8; 32]);

    // 1. Time window invalid: valid_until < now + 30s (e.g. now + 10s)
    let req_future = make_test_hmc_genesis(&"33".repeat(32), now + 10_000, &sender_key);

    let res_future = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "drift_peer_token")
                .body(Body::from(serde_json::to_vec(&req_future).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_future.status(), StatusCode::BAD_REQUEST);

    // 2. Past clock drift: valid_until in the past
    let req_past = make_test_hmc_genesis(&"33".repeat(32), now.saturating_sub(90_000_000), &sender_key);

    let res_past = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "drift_peer_token")
                .body(Body::from(serde_json::to_vec(&req_past).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_past.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_api_pow_adaptive_backpressure_and_stateless_hashcash() {
    let (app, _storage, _identity, _tier_controller, pow_engine) = setup_test_app();

    let now = test_now_ms();
    let parent_hex = "55".repeat(32);
    let sender_key = SigningKey::from_bytes(&[13u8; 32]);
    let req_payload = make_test_hmc_genesis(&parent_hex, now + 600_000, &sender_key);

    // 1. Submit with insufficient difficulty (nonce = 0 doesn't satisfy difficulty 8)
    let (challenge, difficulty, _) = pow_engine.generate_challenge();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-pow-challenge", &challenge)
                .header("x-pow-nonce", "0")
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Must return 429 Too Many Requests with header X-Required-Difficulty
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        res.headers().get("x-required-difficulty").unwrap().to_str().unwrap(),
        difficulty.to_string()
    );

    // 2. Solve stateless PoW properly for parent_bytes
    let valid_nonce = humoco_node::ingress::pow::solve_blake3_hashcash(&challenge, difficulty, 50_000)
        .expect("Must solve PoW");

    let res_valid = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-pow-challenge", &challenge)
                .header("x-pow-nonce", valid_nonce.to_string())
                .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_valid.status(), StatusCode::CREATED);
    let ok_resp: L2ResponseEnvelope = response_json(res_valid).await;
    assert!(matches!(ok_resp.verdict, L2Verdict::Verified { .. }));
}

#[tokio::test]
async fn test_dashboard_endpoint_rendering_and_airgap() {
    let (app, _storage, _identity, _, _) = setup_test_app();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let content_type = res.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(content_type.contains("text/html"));
    assert!(content_type.contains("charset=utf-8"));

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    // Verify branding & live status badge
    assert!(body_str.contains("Human Money Node Control Center") || body_str.contains("HuMoCo Node Control Center"));
    assert!(body_str.contains("STANDALONE") || body_str.contains("COMMUNITY") || body_str.contains("VILLAGE MODE") || body_str.contains("ONLINE") || body_str.contains("HEALTHY"));

    // Verify 3-Tier Latencies Pills & Fast Stats
    assert!(body_str.contains("In-RAM"));
    assert!(body_str.contains("Quorum"));
    assert!(body_str.contains("Kasse"));
    assert!(body_str.contains("8080/9090"));
    assert!(body_str.contains("Admin-Modus"));

    // Verify Phase 1 Dashboard SRE enhancements:
    assert!(body_str.contains(&format!("v{}", env!("CARGO_PKG_VERSION"))));
    assert!(body_str.contains("id=\"hdr-lat-local\""));
    assert!(body_str.contains("id=\"hdr-lat-e2e\""));
    assert!(body_str.contains("Lokale RAM-Kollisionsprüfung und In-Memory Attestierung"));
    assert!(body_str.contains("End-to-End Kassen-Checkout inklusive Shard-Quorum"));
    assert!(body_str.contains("updateHeader"));
    assert!(body_str.contains("HASH_TAB_MAP"));
    assert!(body_str.contains("humoco_admin_token"));
    assert!(body_str.contains("isFetchInProgress"));

    // Verify 5-Tab Navigation Identifiers (Phase 4 Role-Based Tabs)
    assert!(body_str.contains("Cockpit &amp; Vitalwerte") || body_str.contains("Cockpit & Vitalwerte"));
    assert!(body_str.contains("Netzwerk &amp; Shards") || body_str.contains("Netzwerk & Shards"));
    assert!(body_str.contains("Ingress &amp; Lastkontrolle") || body_str.contains("Ingress & Lastkontrolle"));
    assert!(body_str.contains("Kassen &amp; Zugänge") || body_str.contains("Kassen & Zugänge"));
    assert!(body_str.contains("Diagnose, Forensik &amp; OS") || body_str.contains("Diagnose, Forensik & OS"));

    // Verify Phase 4 6-Tile Hero KPI Bar
    assert!(body_str.contains("hero-grid"));
    assert!(body_str.contains("hero-kpi-status"));
    assert!(body_str.contains("hero-kpi-peers"));
    assert!(body_str.contains("hero-kpi-queue"));
    assert!(body_str.contains("hero-kpi-lat"));
    assert!(body_str.contains("hero-kpi-disk"));
    assert!(body_str.contains("hero-kpi-rej"));

    // Verify Visual Cards & Systems
    assert!(body_str.contains("Schreib-Durchsatz"));
    assert!(body_str.contains("Lese-Durchsatz"));
    assert!(body_str.contains("Hardware &amp; Ressourcen") || body_str.contains("Hardware & Ressourcen"));
    assert!(body_str.contains("Persistenz") || body_str.contains("Knoten-Kapazität") || body_str.contains("Knoten-Kapazitätsrechner"));
    assert!(body_str.contains("Netzwerk-Thermometer"));
    assert!(body_str.contains("P2P Nachbarknoten") || body_str.contains("F2F Web-of-Trust Freunde") || body_str.contains("Server-zu-Server Mesh"));
    assert!(body_str.contains("Peer Explorer"));
    assert!(body_str.contains("Free Tier"));
    assert!(body_str.contains("VIP Tier"));
    assert!(body_str.contains("Recent Locks Ring Buffer") || body_str.contains("Recent Locks Ringpuffer"));
    assert!(body_str.contains("Aktive Gutschein-Wurzeln"));
    assert!(body_str.contains("qr-svg"));
    assert!(body_str.contains("Kopieren") || body_str.contains("Copy"));
    assert!(body_str.contains("poll-pause-btn"));
    assert!(body_str.contains("sys-disk-bar"));
    assert!(body_str.contains("shards-tbody"));

    // Verify Modals & Search bar
    assert!(body_str.contains("voucher-modal"));
    assert!(body_str.contains("json-modal"));
    assert!(body_str.contains("admin-modal"));
    assert!(body_str.contains("voucher-search-input"));
    assert!(body_str.contains("searchVoucher"));
    assert!(body_str.contains("vouchers-count-sub"));

    // Size under 128 KiB (self-contained offline air-gapped dashboard)
    assert!(body_str.len() < 128 * 1024, "Dashboard HTML must be under 128 KiB, was {}", body_str.len());

    // Air-gap check: ZERO external script or link tags with http:// or https://
    let lower = body_str.to_lowercase();
    assert!(!lower.contains("<script src=\"http"), "No external scripts allowed");
    assert!(!lower.contains("<link href=\"http"), "No external stylesheets allowed");
    assert!(!lower.contains("<link rel=\"stylesheet\" href=\"http"), "No external CDN allowed");

    // Also test GET /dashboard/data
    let res_data = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/data")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_data.status(), StatusCode::OK);
    let data_bytes = res_data.into_body().collect().await.unwrap().to_bytes();
    let data_json: serde_json::Value = serde_json::from_slice(&data_bytes).unwrap();
    assert!(data_json.get("status").is_some());
    assert!(data_json.get("peering_string").is_some());
    assert!(data_json.get("recent_locks").is_some());
    assert!(data_json.get("total_writes").is_some());
    assert!(data_json.get("total_reads").is_some());
    assert!(data_json.get("total_active_vouchers_count").is_some());
    assert!(data_json.get("disk_free_gb").is_some());
    assert!(data_json.get("quorum_display").is_some());

    // Test GET /dashboard/voucher/unknown_voucher
    let res_v = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/voucher/non_existent_voucher")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_v.status(), StatusCode::NOT_FOUND);

    // Test GET /dashboard/history
    let res_hist = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/history?window=1h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_hist.status(), StatusCode::OK);
    let hist_bytes = res_hist.into_body().collect().await.unwrap().to_bytes();
    let hist_json: serde_json::Value = serde_json::from_slice(&hist_bytes).unwrap();
    assert!(hist_json.get("points").is_some());

    // Test GET /dashboard/events
    let res_ev = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/events?limit=50")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_ev.status(), StatusCode::OK);
    let ev_bytes = res_ev.into_body().collect().await.unwrap().to_bytes();
    let ev_json: serde_json::Value = serde_json::from_slice(&ev_bytes).unwrap();
    assert!(ev_json.get("events").is_some());
}

#[tokio::test]
async fn test_healthcheck_split_live_and_ready() {
    let (app, _storage, _identity, _, _) = setup_test_app();

    // 1. GET /health/live returns 200 OK {"status": "alive"}
    let res_live = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_live.status(), StatusCode::OK);
    let live_bytes = res_live.into_body().collect().await.unwrap().to_bytes();
    let live_json: serde_json::Value = serde_json::from_slice(&live_bytes).unwrap();
    assert_eq!(live_json["status"], "alive");

    // 2. GET /health/ready returns 200 OK {"status": "ready"}
    let res_ready = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_ready.status(), StatusCode::OK);
    let ready_bytes = res_ready.into_body().collect().await.unwrap().to_bytes();
    let ready_json: serde_json::Value = serde_json::from_slice(&ready_bytes).unwrap();
    assert_eq!(ready_json["status"], "ready");

    // 3. Keep GET /health and GET /v1/node-status working as before
    let res_health = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_health.status(), StatusCode::OK);

    let res_status = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/node-status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_status.status(), StatusCode::OK);

    // 4. GET /healthz returns 200 OK {"status": "ok"}
    let res_healthz = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_healthz.status(), StatusCode::OK);
    let val_healthz: serde_json::Value = response_json(res_healthz).await;
    assert_eq!(val_healthz["status"], "ok");
}

#[tokio::test]
async fn test_prometheus_metrics_expansion() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("metrics_peer_token");

    // Submit a valid lock to increment pos_latency_count
    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[14u8; 32]);
    let req = make_test_hmc_genesis(&"77".repeat(32), now + 600_000, &sender_key);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "metrics_peer_token")
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Query /metrics
    let res_metrics = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_metrics.status(), StatusCode::OK);
    let bytes = res_metrics.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(bytes.to_vec()).unwrap();

    // Verify all Prometheus metrics are present
    assert!(body.contains("humoco_locks_active_total"));
    assert!(body.contains("humoco_p2p_connected_peers"));
    assert!(body.contains("humoco_node_uptime_seconds"));
    assert!(body.contains("humoco_flush_queue_depth"));
    assert!(body.contains("humoco_pos_latency_seconds_count 1"));
    assert!(body.contains("humoco_locks_rejected_total 0"));
    assert!(body.contains("humoco_rejections_total{reason=\"conflict_409\"} 0"));
    assert!(body.contains("humoco_persistence_flush_batches_total"));
    assert!(body.contains("humoco_health_status"));
}

#[tokio::test]
async fn test_api_hmc_read_quorum_and_adaptive_logic() {
    use humoco_node::api::hmc::{
        calculate_l2_payload_hash_raw, L2AuthPayload, L2LockRequest, L2ResponseEnvelope,
        L2StatusQuery, L2Verdict, TRAP_NONE_PLACEHOLDER,
    };
    use rand::rngs::OsRng;
    use rand::RngCore;
    use ed25519_dalek::{Signer, SigningKey};

    let (app, _storage, identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("read_quorum_test_token");

    let mut rng = OsRng;
    let sender_key = SigningKey::generate(&mut rng);
    let sender_pub = sender_key.verifying_key().to_bytes();

    let mut t_id_bytes = [0u8; 32];
    rng.fill_bytes(&mut t_id_bytes);
    let t_id_bs58 = bs58::encode(&t_id_bytes).into_string();

    let mut vid_bytes = [0u8; 32];
    rng.fill_bytes(&mut vid_bytes);
    let voucher_id = hex::encode(vid_bytes);

    let valid_until_ms = test_now_ms() + 600_000;
    let del_str = valid_until_ms.to_string();
    let payload_hash = calculate_l2_payload_hash_raw(
        TRAP_NONE_PLACEHOLDER,
        &t_id_bs58,
        &t_id_bytes,
        &sender_pub,
        "none",
        "none",
        0,
        Some(&del_str),
        "",
    );
    let sig = sender_key.sign(&payload_hash);

    let genesis_req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: None,
        transaction_hash: t_id_bytes,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: Some(del_str),
        privacy_guard: None,
    };

    let res_gen = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "read_quorum_test_token")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_gen.status(), StatusCode::CREATED);

    // 1. Query with default read_quorum (omitted from JSON) -> should default to 1 and have no QC
    let query_json = serde_json::json!({
        "auth": {
            "ephemeral_pubkey": bs58::encode(&sender_pub).into_string(),
        },
        "layer2_voucher_id": voucher_id,
        "challenge_ds_tag": t_id_bs58,
        "locator_prefixes": [],
    });

    let res_default = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/status")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&query_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_default.status(), StatusCode::OK);
    let env_default: L2ResponseEnvelope = response_json(res_default).await;
    assert!(env_default.quorum_certificate.is_none(), "read_quorum=1 must omit quorum_certificate");
    match env_default.verdict {
        L2Verdict::Verified { ref lock_entry } => {
            assert_eq!(lock_entry.t_id, t_id_bytes);
        }
        _ => panic!("Expected Verified"),
    }

    // 2. Query with explicit read_quorum: 1 -> QC is None
    let query_q1 = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        challenge_ds_tag: t_id_bs58.clone(),
        locator_prefixes: vec![],
        read_quorum: 1,
    };
    let res_q1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/status")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&query_q1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_q1.status(), StatusCode::OK);
    let env_q1: L2ResponseEnvelope = response_json(res_q1).await;
    assert!(env_q1.quorum_certificate.is_none());

    // 3. Query with read_quorum > 1 in Village Mode (N=1)
    // Adaptive quorum logic: caps quorum by active_nodes_count (1), returning local attestation QC
    let query_q3 = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        challenge_ds_tag: t_id_bs58.clone(),
        locator_prefixes: vec![],
        read_quorum: 3,
    };
    let res_q3 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/status")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&query_q3).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_q3.status(), StatusCode::OK);
    let env_q3: L2ResponseEnvelope = response_json(res_q3).await;
    assert!(env_q3.quorum_certificate.is_some(), "read_quorum > 1 must include quorum_certificate");
    let qc = env_q3.quorum_certificate.unwrap();
    assert_eq!(qc.active_nodes_count, 1, "Village mode must cap active_nodes_count to 1");
    assert_eq!(qc.signer_count, 1);
    assert_eq!(qc.signatures.len(), 1);
    assert_eq!(qc.status, 0);
    assert_eq!(qc.signer_bitmap, 1);

    // Verify attestation cryptographic signature (parent_lock-bound, Phase 1 P0)
    let att = &qc.signatures[0];
    let sig_bytes = hex::decode(&att.signature).unwrap();
    let ed_sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    let parent_bytes = {
        let v = hex::decode(&att.parent_lock).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    };
    let payload_digest =
        humoco_sim_core::crypto::compute_attestation_payload_digest(&parent_bytes, &t_id_bytes);
    let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
        humoco_sim_core::crypto::DOMAIN_APPROVE_PROV,
        0,
        0,
        0,
        qc.shard_id,
        0,
        &payload_digest,
    );
    assert!(identity.verifying_key().verify_strict(&sig_digest, &ed_sig).is_ok());

    // 4. Multi-node adaptive quorum test with PeerManager
    let peer_mgr = Arc::new(humoco_node::network::PeerManager::new(vec![]));

    let temp2 = tempdir().expect("tempdir");
    let db_path2 = temp2.path().join("test_read_quorum_peers.redb");
    let storage2 = Arc::new(RedbStorage::open(&db_path2).expect("open redb"));
    let (engine2, _flush2) = DualTierEngine::new(storage2.clone());
    let pow2 = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tc2 = Arc::new(TierController::new(storage2.clone(), pow2.clone()));
    tc2.register_f2f_peer("token_multi");

    let mut state_multi = AppState::new(
        engine2,
        storage2.clone(),
        identity.clone(),
        tc2.clone(),
        pow2.clone(),
    );
    state_multi.peer_manager = Some(peer_mgr.clone());
    let app_multi = build_router(state_multi);

    // Anchor genesis on app before peer expansion (reaches provisional quorum 1/1)
    let res_gen2 = app_multi
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "token_multi")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_gen2.status(), StatusCode::CREATED);

    // Populate peer_mgr with 4 mature peers so active_nodes_count = 5
    for i in 0..4u64 {
        let dummy_id = *blake3::hash(&i.to_le_bytes()).as_bytes();
        let addr = format!("127.0.0.1:{}", 17000 + i).parse().unwrap();
        peer_mgr.learn_node_from_gossip(dummy_id, addr, 1, None).await;
        peer_mgr.set_first_seen_for_test(&dummy_id, std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
    }

    // Query status with read_quorum: 2
    let query_multi = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        challenge_ds_tag: t_id_bs58.clone(),
        locator_prefixes: vec![],
        read_quorum: 2,
    };
    let res_multi = app_multi
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/status")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&query_multi).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_multi.status(), StatusCode::OK);
    let env_multi: L2ResponseEnvelope = response_json(res_multi).await;
    assert!(env_multi.quorum_certificate.is_some());
    let qc_multi = env_multi.quorum_certificate.unwrap();
    assert_eq!(qc_multi.active_nodes_count, 5); // 4 peers + self
    assert!(!qc_multi.signatures.is_empty());
    assert_ne!(qc_multi.signer_bitmap, 0);
}

#[tokio::test]
async fn test_api_hmc_fast_forward_leap_locks() {
    use humoco_node::api::hmc::{
        calculate_l2_payload_hash_raw, L2AuthPayload, L2LockRequest, L2ResponseEnvelope,
        L2StatusQuery, L2Verdict, TRAP_NONE_PLACEHOLDER,
    };
    use rand::rngs::OsRng;
    use rand::RngCore;
    use ed25519_dalek::{Signer, SigningKey};

    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("leap_lock_test_token");

    let mut rng = OsRng;
    let sender_key = SigningKey::generate(&mut rng);
    let sender_pub = sender_key.verifying_key().to_bytes();

    let mut genesis_t_id = [0u8; 32];
    rng.fill_bytes(&mut genesis_t_id);
    let genesis_t_id_bs58 = bs58::encode(&genesis_t_id).into_string();

    let mut vid_bytes = [0u8; 32];
    rng.fill_bytes(&mut vid_bytes);
    let voucher_id = hex::encode(vid_bytes);

    let valid_until_ms = test_now_ms() + 600_000;
    let del_str = valid_until_ms.to_string();

    // 1. Anchor Genesis Lock (Nonce 0 / Init)
    let genesis_hash = calculate_l2_payload_hash_raw(
        TRAP_NONE_PLACEHOLDER,
        &genesis_t_id_bs58,
        &genesis_t_id,
        &sender_pub,
        "none",
        "none",
        0,
        Some(&del_str),
        "",
    );
    let genesis_sig = sender_key.sign(&genesis_hash);

    let genesis_req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: None,
        transaction_hash: genesis_t_id,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: genesis_sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: Some(del_str.clone()),
        privacy_guard: None,
    };

    let res_gen = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "leap_lock_test_token")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_gen.status(), StatusCode::CREATED);

    // 2. Fast-Forward Leap Lock:
    // Offline transactions happened (nonces 1 and 2 skipped).
    // Client directly submits Leap Lock for state 3 with unspent ds_tag pointing to leap_t_id.
    let mut leap_t_id = [0u8; 32];
    rng.fill_bytes(&mut leap_t_id);
    let leap_t_id_bs58 = bs58::encode(&leap_t_id).into_string();

    let mut leap_ds_tag_bytes = [0u8; 32];
    rng.fill_bytes(&mut leap_ds_tag_bytes);
    let leap_ds_tag = bs58::encode(&leap_ds_tag_bytes).into_string();

    let leap_key = SigningKey::generate(&mut rng);
    let leap_pub = leap_key.verifying_key().to_bytes();

    let leap_hash = calculate_l2_payload_hash_raw(
        &voucher_id,
        &leap_ds_tag,
        &leap_t_id,
        &leap_pub,
        "none",
        "none",
        0,
        None,
        "",
    );
    let leap_sig = leap_key.sign(&leap_hash);

    let leap_req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: leap_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: Some(leap_ds_tag.clone()),
        transaction_hash: leap_t_id,
        is_genesis: false,
        sender_ephemeral_pub: leap_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: leap_sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    // 3. Submit Leap Lock -> 201 Created (accepted despite skipped intermediate nonces)
    let res_leap = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "leap_lock_test_token")
                .body(Body::from(serde_json::to_vec(&leap_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_leap.status(), StatusCode::CREATED);
    let env_leap: L2ResponseEnvelope = response_json(res_leap).await;
    match env_leap.verdict {
        L2Verdict::Verified { ref lock_entry } => {
            assert_eq!(lock_entry.t_id, leap_t_id);
            assert_eq!(lock_entry.layer2_voucher_id, voucher_id);
        }
        _ => panic!("Expected Verified verdict for fast-forward leap lock"),
    }

    // 4. Idempotent Retry of Leap Lock -> 200 OK
    let res_retry = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "leap_lock_test_token")
                .body(Body::from(serde_json::to_vec(&leap_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_retry.status(), StatusCode::OK);
    let env_retry: L2ResponseEnvelope = response_json(res_retry).await;
    match env_retry.verdict {
        L2Verdict::Verified { ref lock_entry } => {
            assert_eq!(lock_entry.t_id, leap_t_id);
        }
        _ => panic!("Expected Verified verdict on idempotent retry of leap lock"),
    }

    // 5. Conflicting double-spend attempt on the leap lock's ds_tag -> 409 Conflict
    let mut conflict_t_id = [0u8; 32];
    rng.fill_bytes(&mut conflict_t_id);
    let conflict_key = SigningKey::generate(&mut rng);
    let conflict_pub = conflict_key.verifying_key().to_bytes();

    let conflict_hash = calculate_l2_payload_hash_raw(
        &voucher_id,
        &leap_ds_tag,
        &conflict_t_id,
        &conflict_pub,
        "none",
        "none",
        0,
        None,
        "",
    );
    let conflict_sig = conflict_key.sign(&conflict_hash);

    let conflict_req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: conflict_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: Some(leap_ds_tag.clone()),
        transaction_hash: conflict_t_id,
        is_genesis: false,
        sender_ephemeral_pub: conflict_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: conflict_sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let res_conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "leap_lock_test_token")
                .body(Body::from(serde_json::to_vec(&conflict_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_conflict.status(), StatusCode::CONFLICT);
    let env_conflict: L2ResponseEnvelope = response_json(res_conflict).await;
    match env_conflict.verdict {
        L2Verdict::Conflict { existing_lock } => {
            assert_eq!(existing_lock.t_id, leap_t_id, "Evidence must be the existing leap lock");
        }
        _ => panic!("Expected Conflict verdict"),
    }

    // 6. Query status by leap_ds_tag with read_quorum: 3 (village mode -> adaptive quorum 1)
    let query_by_tag = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: leap_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        challenge_ds_tag: leap_ds_tag.clone(),
        locator_prefixes: vec![],
        read_quorum: 3,
    };
    let res_qtag = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/status")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&query_by_tag).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_qtag.status(), StatusCode::OK);
    let env_qtag: L2ResponseEnvelope = response_json(res_qtag).await;
    assert!(env_qtag.quorum_certificate.is_some());
    let qc_tag = env_qtag.quorum_certificate.unwrap();
    assert_eq!(qc_tag.active_nodes_count, 1);
    assert_eq!(qc_tag.signer_count, 1);
    match env_qtag.verdict {
        L2Verdict::Verified { lock_entry } => {
            assert_eq!(lock_entry.t_id, leap_t_id);
        }
        _ => panic!("Expected Verified for query by leap_ds_tag"),
    }

    // 7. Query status by new state hash (leap_t_id Base58) -> Verified
    let query_by_tid = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: leap_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        challenge_ds_tag: leap_t_id_bs58.clone(),
        locator_prefixes: vec![],
        read_quorum: 1,
    };
    let res_qtid = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/status")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&query_by_tid).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_qtid.status(), StatusCode::OK);
    let env_qtid: L2ResponseEnvelope = response_json(res_qtid).await;
    match env_qtid.verdict {
        L2Verdict::Verified { lock_entry } => {
            assert_eq!(lock_entry.t_id, leap_t_id);
        }
        _ => panic!("Expected Verified for query by leap transaction hash"),
    }
}

#[tokio::test]
async fn test_api_pex_peers_and_node_status_network() {
    let (app, _storage, _identity, _tier_controller, _pm) = setup_test_app();

    // 1. GET /v1/node-status must contain network field
    let res_status = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/node-status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_status.status(), StatusCode::OK);
    let status_dto: humoco_node::api::dto::NodeStatusResponse = response_json(res_status).await;
    assert_eq!(status_dto.network, "mainnet");

    // 2. GET /api/v1/network/peers must return PeersResponse
    let res_peers = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/network/peers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_peers.status(), StatusCode::OK);
    let peers_dto: humoco_node::api::dto::PeersResponse = response_json(res_peers).await;
    assert_eq!(peers_dto.network, "mainnet");
    assert!(peers_dto.active_nodes_count >= 1);

    // 3. Alias /peers must return identical structure
    let res_alias = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/peers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_alias.status(), StatusCode::OK);
    let alias_dto: humoco_node::api::dto::PeersResponse = response_json(res_alias).await;
    assert_eq!(alias_dto.network, "mainnet");
}

// ---------------------------------------------------------------------------
// Kassen-Szenarien (Checkout Flow) + Randfälle – Cuckoo + Chain Locking
// ---------------------------------------------------------------------------

fn make_genesis_hmc_req(
    voucher_id: &str,
    sender_key: &ed25519_dalek::SigningKey,
    valid_until_ms: u64,
    encrypted_timestamp: u128,
) -> humoco_node::api::hmc::L2LockRequest {
    use humoco_node::api::hmc::{calculate_l2_payload_hash_raw, L2AuthPayload, L2LockRequest, TRAP_NONE_PLACEHOLDER};
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = {
        let mut h = blake3::Hasher::new();
        h.update(voucher_id.as_bytes());
        h.update(&encrypted_timestamp.to_le_bytes());
        h.update(&sender_pub);
        *h.finalize().as_bytes()
    };
    let lookup_tag = bs58::encode(&tx_hash).into_string();
    let del_str = valid_until_ms.to_string();
    let payload_hash = calculate_l2_payload_hash_raw(
        TRAP_NONE_PLACEHOLDER,
        &lookup_tag,
        &tx_hash,
        &sender_pub,
        "none",
        "none",
        encrypted_timestamp,
        Some(&del_str),
        "",
    );
    let sig = sender_key.sign(&payload_hash);
    L2LockRequest {
        auth: L2AuthPayload { ephemeral_pubkey: sender_pub, auth_signature: None },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp,
        deletable_at: Some(del_str),
        privacy_guard: None,
    }
}

fn make_follow_hmc_req(
    voucher_id: &str,
    ds_tag: String,
    sender_key: &ed25519_dalek::SigningKey,
    encrypted_timestamp: u128,
    change_hash: Option<[u8; 32]>,
    receiver_hash: Option<[u8; 32]>,
) -> humoco_node::api::hmc::L2LockRequest {
    use humoco_node::api::hmc::{calculate_l2_payload_hash_raw, L2AuthPayload, L2LockRequest};
    let sender_pub = sender_key.verifying_key().to_bytes();
    // deterministic t_id from ds_tag + timestamp + pub
    let mut h = blake3::Hasher::new();
    h.update(ds_tag.as_bytes());
    h.update(&encrypted_timestamp.to_le_bytes());
    h.update(&sender_pub);
    let tx_hash = *h.finalize().as_bytes();
    let payload_hash = calculate_l2_payload_hash_raw(
        voucher_id,
        &ds_tag,
        &tx_hash,
        &sender_pub,
        "none",
        "none",
        encrypted_timestamp,
        None,
        "",
    );
    let sig = sender_key.sign(&payload_hash);
    L2LockRequest {
        auth: L2AuthPayload { ephemeral_pubkey: sender_pub, auth_signature: None },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(ds_tag),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: receiver_hash,
        change_ephemeral_pub_hash: change_hash,
        layer2_signature: sig.to_bytes(),
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp,
        deletable_at: None,
        privacy_guard: None,
    }
}

#[tokio::test]
async fn test_checkout_case_1_happy_single_lock() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_peer");
    let voucher_id = format!("voucher_case1_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let sender_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let sender_pub = sender_key.verifying_key().to_bytes();
    // Anchor genesis via single lock
    let genesis = make_genesis_hmc_req(&voucher_id, &sender_key, valid_until, 100);
    let _genesis_tag = bs58::encode(&genesis.transaction_hash).into_string();
    let res_gen = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock").header("content-type","application/json").header("X-Peer-Token","checkout_peer").body(Body::from(serde_json::to_vec(&genesis).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_gen.status(), StatusCode::CREATED);
    // Happy single lock: chain with 1 follow hop via /v1/lock/chain
    let follow_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let follow_tag = format!("ds_tag_follow_{}", test_now_ms());
    let follow = make_follow_hmc_req(&voucher_id, follow_tag, &follow_key, 200, None, None);
    let chain_req = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: sender_pub, auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![follow.clone()] };
    let res_chain = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer").body(Body::from(serde_json::to_vec(&chain_req).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_chain.status(), StatusCode::CREATED, "happy single lock chain should be 201");
    let env: L2ResponseEnvelope = response_json(res_chain).await;
    match env.verdict { L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, follow.transaction_hash), _ => panic!("expected Verified") };
    assert!(env.quorum_certificate.is_some());
}

#[tokio::test]
async fn test_checkout_case_2_brand_new_genesis_voucher() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_peer2");
    let voucher_id = format!("voucher_case2_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let sender_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let sender_pub = sender_key.verifying_key().to_bytes();
    let genesis = make_genesis_hmc_req(&voucher_id, &sender_key, valid_until, 1000);
    let chain_req = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: sender_pub, auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis.clone()] };
    let res = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer2").body(Body::from(serde_json::to_vec(&chain_req).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let env: L2ResponseEnvelope = response_json(res).await;
    match env.verdict { L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, genesis.transaction_hash), _ => panic!("expected Verified genesis") };
    // Verify via status query
    let status_q = humoco_node::api::hmc::L2StatusQuery { auth: L2AuthPayload { ephemeral_pubkey: sender_pub, auth_signature: None }, layer2_voucher_id: voucher_id.clone(), challenge_ds_tag: bs58::encode(&genesis.transaction_hash).into_string(), locator_prefixes: vec![], read_quorum: 1 };
    let res_q = app.clone().oneshot(Request::builder().method("POST").uri("/v1/status").header("content-type","application/json").body(Body::from(serde_json::to_vec(&status_q).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_q.status(), StatusCode::OK);
    let env_q: L2ResponseEnvelope = response_json(res_q).await;
    match env_q.verdict { L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, genesis.transaction_hash), _ => panic!("status should be Verified") };
}

#[tokio::test]
async fn test_checkout_case_3_offline_voucher_full_chain() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_peer3");
    let voucher_id = format!("voucher_case3_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let k1 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k2 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k3 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let genesis = make_genesis_hmc_req(&voucher_id, &k1, valid_until, 10);
    let tag2 = format!("ds_tag_hop2_{}", test_now_ms());
    let hop2 = make_follow_hmc_req(&voucher_id, tag2.clone(), &k2, 20, None, None);
    let tag3 = format!("ds_tag_hop3_{}", test_now_ms());
    let hop3 = make_follow_hmc_req(&voucher_id, tag3.clone(), &k3, 30, None, None);
    let chain_req = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k1.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis.clone(), hop2.clone(), hop3.clone()] };
    let res = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer3").body(Body::from(serde_json::to_vec(&chain_req).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let env: L2ResponseEnvelope = response_json(res).await;
    match env.verdict { L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, hop3.transaction_hash), _ => panic!("expected terminal Verified") };
    // All 3 should now be queryable
    for hop in [&genesis, &hop2, &hop3] {
        let tag = if hop.is_genesis { bs58::encode(&hop.transaction_hash).into_string() } else { hop.ds_tag.clone().unwrap() };
        let q = humoco_node::api::hmc::L2StatusQuery { auth: L2AuthPayload { ephemeral_pubkey: hop.sender_ephemeral_pub, auth_signature: None }, layer2_voucher_id: voucher_id.clone(), challenge_ds_tag: tag, locator_prefixes: vec![], read_quorum: 1 };
        let r = app.clone().oneshot(Request::builder().method("POST").uri("/v1/status").header("content-type","application/json").body(Body::from(serde_json::to_vec(&q).unwrap())).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let e: L2ResponseEnvelope = response_json(r).await;
        match e.verdict { L2Verdict::Verified { .. } => {}, _ => panic!("hop not found") };
    }
}

#[tokio::test]
async fn test_checkout_case_4_reconcile_missing_hops() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_peer4");
    let voucher_id = format!("voucher_case4_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let k1 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k2 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k3 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k4 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let genesis = make_genesis_hmc_req(&voucher_id, &k1, valid_until, 10);
    let tag2 = format!("ds_tag4_hop2_{}", test_now_ms());
    let hop2 = make_follow_hmc_req(&voucher_id, tag2.clone(), &k2, 20, None, None);
    let tag3 = format!("ds_tag4_hop3_{}", test_now_ms());
    let hop3 = make_follow_hmc_req(&voucher_id, tag3.clone(), &k3, 30, None, None);
    let tag4 = format!("ds_tag4_hop4_{}", test_now_ms());
    let hop4 = make_follow_hmc_req(&voucher_id, tag4.clone(), &k4, 40, None, None);
    // Initially anchor genesis + hop2 via chain
    let chain_first = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k1.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis.clone(), hop2.clone()] };
    let res_first = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer4").body(Body::from(serde_json::to_vec(&chain_first).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_first.status(), StatusCode::CREATED);
    // Now reconcile full chain including missing hops 3,4 (first two already known)
    let chain_full = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k1.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis.clone(), hop2.clone(), hop3.clone(), hop4.clone()] };
    let res_full = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer4").body(Body::from(serde_json::to_vec(&chain_full).unwrap())).unwrap()).await.unwrap();
    // Should have inserted missing hops atomically -> 201
    assert_eq!(res_full.status(), StatusCode::CREATED);
    let env: L2ResponseEnvelope = response_json(res_full).await;
    match env.verdict { L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, hop4.transaction_hash), _ => panic!("expected Verified terminal") };
}

#[tokio::test]
async fn test_checkout_case_5_exponential_overlap_deduplication() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_peer5");
    let voucher_id = format!("voucher_case5_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let k1 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k2 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let genesis = make_genesis_hmc_req(&voucher_id, &k1, valid_until, 100);
    let tag2 = format!("ds_tag5_hop2_{}", test_now_ms());
    let hop2 = make_follow_hmc_req(&voucher_id, tag2.clone(), &k2, 200, None, None);
    let chain = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k1.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis.clone(), hop2.clone()] };
    let res1 = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer5").body(Body::from(serde_json::to_vec(&chain).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res1.status(), StatusCode::CREATED);
    // exponential overlap: same chain again via generic /v1/lock endpoint (tests delegation)
    let res2 = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock").header("content-type","application/json").header("X-Peer-Token","checkout_peer5").body(Body::from(serde_json::to_vec(&chain).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res2.status(), StatusCode::OK, "duplicate chain must be idempotent 200");
    let env2: L2ResponseEnvelope = response_json(res2).await;
    match env2.verdict { L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, hop2.transaction_hash), _ => panic!("expected Verified idempotent") };
    // third time via direct chain endpoint still 200
    let res3 = app.oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer5").body(Body::from(serde_json::to_vec(&chain).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res3.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_checkout_case_6_intermediate_hop_double_spend_rollback() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_peer6");
    let voucher_id = format!("voucher_case6_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let k_gen = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k_a = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k_b = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k_c = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let genesis = make_genesis_hmc_req(&voucher_id, &k_gen, valid_until, 10);
    // Initial legitimate hop A with unique tag
    let tag_spend = format!("ds_tag_spend_{}", test_now_ms());
    let hop_a = make_follow_hmc_req(&voucher_id, tag_spend.clone(), &k_a, 20, None, None);
    let chain_init = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k_gen.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis.clone(), hop_a.clone()] };
    let res_init = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer6").body(Body::from(serde_json::to_vec(&chain_init).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_init.status(), StatusCode::CREATED);
    // Now attempt chain with intermediate double-spend: genesis (idempotent) + hop_b conflicting on SAME tag_spend as hop_a (different t_id) + hop_c following hop_b
    let hop_b = make_follow_hmc_req(&voucher_id, tag_spend.clone(), &k_b, 25, None, None);
    assert_ne!(hop_b.transaction_hash, hop_a.transaction_hash);
    let tag_c = format!("ds_tag_c_{}", test_now_ms());
    let hop_c = make_follow_hmc_req(&voucher_id, tag_c.clone(), &k_c, 30, None, None);
    let chain_conflict = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k_gen.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis.clone(), hop_b.clone(), hop_c.clone()] };
    let res_conf = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_peer6").body(Body::from(serde_json::to_vec(&chain_conflict).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_conf.status(), StatusCode::CONFLICT, "intermediate double-spend must yield 409 and rollback");
    let env_conf: L2ResponseEnvelope = response_json(res_conf).await;
    match env_conf.verdict { L2Verdict::Conflict { existing_lock } => assert_eq!(existing_lock.t_id, hop_a.transaction_hash), _ => panic!("expected Conflict with existing hop_a") };
    // Verify hop_c was NOT inserted (rollback) – query by its tag should be Unknown/Missing
    let q_c = humoco_node::api::hmc::L2StatusQuery { auth: L2AuthPayload { ephemeral_pubkey: k_c.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), challenge_ds_tag: tag_c, locator_prefixes: vec![], read_quorum: 1 };
    let res_qc = app.clone().oneshot(Request::builder().method("POST").uri("/v1/status").header("content-type","application/json").body(Body::from(serde_json::to_vec(&q_c).unwrap())).unwrap()).await.unwrap();
    let _env_qc: L2ResponseEnvelope = response_json(res_qc).await;
    // hop_c's parent tag_b corresponds to hop_b which was not inserted, so querying tag_b should return Verified for hop_a? Actually tag_gen still maps to hop_a Verified. But tag_b not present, query should be Missing or Verified not found.
    // Instead verify hop_c not present via its t_id lookup (challenge = tag_b should still show hop_a)
    // Query for hop_c's own tag (its ds_tag is tag_b, t_id is hop_c.tx) – but hop_c not inserted, so its t_id lookup should be Missing
    let q_c2 = humoco_node::api::hmc::L2StatusQuery { auth: L2AuthPayload { ephemeral_pubkey: k_c.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), challenge_ds_tag: bs58::encode(&hop_c.transaction_hash).into_string(), locator_prefixes: vec![], read_quorum: 1 };
    let res_qc2 = app.oneshot(Request::builder().method("POST").uri("/v1/status").header("content-type","application/json").body(Body::from(serde_json::to_vec(&q_c2).unwrap())).unwrap()).await.unwrap();
    let env_qc2: L2ResponseEnvelope = response_json(res_qc2).await;
    match env_qc2.verdict { L2Verdict::MissingLocks { .. } | L2Verdict::UnknownVoucher => {}, L2Verdict::Verified { .. } => panic!("hop_c should not have been inserted after rollback"), _ => {} };
}

#[tokio::test]
async fn test_checkout_edge_case_historical_offline_timestamp_monotonicity() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_edge1");
    let voucher_id = format!("voucher_edge1_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let k1 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k2 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k3 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let genesis = make_genesis_hmc_req(&voucher_id, &k1, valid_until, 300);
    let tag1 = bs58::encode(&genesis.transaction_hash).into_string();
    // hop2 timestamp 200 < genesis 300 -> violates monotonicity (historical offline out-of-order)
    let hop2 = make_follow_hmc_req(&voucher_id, tag1.clone(), &k2, 200, None, None);
    let tag2 = bs58::encode(&hop2.transaction_hash).into_string();
    let hop3 = make_follow_hmc_req(&voucher_id, tag2.clone(), &k3, 400, None, None);
    let chain = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k1.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis, hop2, hop3] };
    let res = app.oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_edge1").body(Body::from(serde_json::to_vec(&chain).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let env: L2ResponseEnvelope = response_json(res).await;
    match env.verdict { L2Verdict::Rejected { reason } => assert!(reason.contains("monotonicity") || reason.contains("Timestamp")), _ => panic!("expected Rejected monotonicity") };
}

#[tokio::test]
async fn test_checkout_edge_case_split_dag_change_branch() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_edge2");
    let voucher_id = format!("voucher_edge2_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let k_gen = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k_recv = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k_change = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let k_next = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let genesis = make_genesis_hmc_req(&voucher_id, &k_gen, valid_until, 10);
    let tag_split_in = format!("ds_tag_split_{}", test_now_ms());
    let change_hash = *blake3::hash(k_change.verifying_key().to_bytes().as_slice()).as_bytes();
    let recv_hash = *blake3::hash(k_recv.verifying_key().to_bytes().as_slice()).as_bytes();
    let split_hop = make_follow_hmc_req(&voucher_id, tag_split_in, &k_gen, 20, Some(change_hash), Some(recv_hash));
    let tag_next_in = format!("ds_tag_next_{}", test_now_ms());
    let next_hop = make_follow_hmc_req(&voucher_id, tag_next_in, &k_next, 30, None, None);
    let chain = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k_gen.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis, split_hop.clone(), next_hop.clone()] };
    let res = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_edge2").body(Body::from(serde_json::to_vec(&chain).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let env: L2ResponseEnvelope = response_json(res).await;
    match env.verdict { L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, next_hop.transaction_hash), _ => panic!("split DAG chain should be Verified") };
    // Also test independent branches in same chain
    let voucher2 = format!("voucher_edge2b_{}", test_now_ms());
    let genesis2 = make_genesis_hmc_req(&voucher2, &k_gen, valid_until, 10);
    let tag_leaf_a = format!("ds_tag_leaf_a_{}", test_now_ms());
    let leaf_a = make_follow_hmc_req(&voucher2, tag_leaf_a, &k_recv, 20, None, None);
    let chain2 = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: k_gen.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher2.clone(), chain: vec![genesis2, leaf_a.clone()] };
    let res2 = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_edge2").body(Body::from(serde_json::to_vec(&chain2).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res2.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_checkout_edge_case_empty_and_single_hop_chains() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2AuthPayload, L2ResponseEnvelope, L2Verdict};
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("checkout_edge3");
    let voucher_id = format!("voucher_edge3_{}", test_now_ms());
    let valid_until = test_now_ms() + 600_000;
    let k1 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let sender_pub = k1.verifying_key().to_bytes();
    // empty chain -> 400 Bad Request
    let empty_chain = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: sender_pub, auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![] };
    let res_empty = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_edge3").body(Body::from(serde_json::to_vec(&empty_chain).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_empty.status(), StatusCode::BAD_REQUEST);
    let env_empty: L2ResponseEnvelope = response_json(res_empty).await;
    match env_empty.verdict { L2Verdict::Rejected { reason } => assert!(reason.contains("Empty")), _ => panic!("empty chain should be Rejected") };
    // single hop chain via generic /v1/lock route (delegated)
    let genesis = make_genesis_hmc_req(&voucher_id, &k1, valid_until, 500);
    let single_chain = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: sender_pub, auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![genesis.clone()] };
    let res_single = app.clone().oneshot(Request::builder().method("POST").uri("/v1/lock").header("content-type","application/json").header("X-Peer-Token","checkout_edge3").body(Body::from(serde_json::to_vec(&single_chain).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_single.status(), StatusCode::CREATED);
    let env_single: L2ResponseEnvelope = response_json(res_single).await;
    match env_single.verdict { L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, genesis.transaction_hash), _ => panic!("single hop chain should be Verified") };
    // single follow hop chain (after genesis) -> should also work
    let k2 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let tag = format!("ds_tag_single_follow_{}", test_now_ms());
    let follow = make_follow_hmc_req(&voucher_id, tag, &k2, 600, None, None);
    let single_follow = L2ChainLockRequest { auth: L2AuthPayload { ephemeral_pubkey: sender_pub, auth_signature: None }, layer2_voucher_id: voucher_id.clone(), chain: vec![follow.clone()] };
    let res_follow = app.oneshot(Request::builder().method("POST").uri("/v1/lock/chain").header("content-type","application/json").header("X-Peer-Token","checkout_edge3").body(Body::from(serde_json::to_vec(&single_follow).unwrap())).unwrap()).await.unwrap();
    assert_eq!(res_follow.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_max_11_years_ttl_ingress_boundary_enforcement() {
    use humoco_node::api::hmc::{L2ResponseEnvelope, L2Verdict};
    use humoco_sim_core::storage::MAX_LOCK_TTL_MS;

    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("ttl_test_peer");

    let now_ms = test_now_ms();
    let k_gen = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

    // 1. Genesis lock with valid_until within 11 years (e.g. 10 years) -> ACCEPTED (201 Created)
    let voucher_valid = format!("voucher_10y_{}", now_ms);
    let valid_10y_ms = now_ms + (10 * 31_536_000 * 1_000);
    let req_10y = make_genesis_hmc_req(&voucher_valid, &k_gen, valid_10y_ms, 100);

    let res_valid = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/lock")
            .header("content-type", "application/json")
            .header("X-Peer-Token", "ttl_test_peer")
            .body(Body::from(serde_json::to_vec(&req_10y).unwrap()))
            .unwrap()
    ).await.unwrap();

    assert_eq!(res_valid.status(), StatusCode::CREATED);
    let env_valid: L2ResponseEnvelope = response_json(res_valid).await;
    match env_valid.verdict {
        L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, req_10y.transaction_hash),
        _ => panic!("10-year lock should be verified successfully"),
    }

    // 2. Genesis lock exceeding 11 years (e.g. 11 years + 10 days) -> REJECTED (400 Bad Request)
    let voucher_exceed = format!("voucher_exceed_{}", now_ms);
    let exceed_ms = now_ms + MAX_LOCK_TTL_MS + (10 * 86_400 * 1_000);
    let req_exceed = make_genesis_hmc_req(&voucher_exceed, &k_gen, exceed_ms, 200);

    let res_exceed = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/lock")
            .header("content-type", "application/json")
            .header("X-Peer-Token", "ttl_test_peer")
            .body(Body::from(serde_json::to_vec(&req_exceed).unwrap()))
            .unwrap()
    ).await.unwrap();

    assert_eq!(res_exceed.status(), StatusCode::BAD_REQUEST);
    let env_exceed: L2ResponseEnvelope = response_json(res_exceed).await;
    match env_exceed.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(reason.contains("Invalid ingress time window"), "Rejection must specify time window violation: {}", reason);
        }
        _ => panic!("Lock exceeding 11 years must be rejected"),
    }
}

#[tokio::test]
async fn test_node_status_and_metrics_telemetry_gauges() {
    let (app, _storage, _identity, _tier_controller, _pow_engine) = setup_test_app();

    // 1. Check /v1/node-status returns free_tier_enabled: true
    let res_status = app.clone().oneshot(
        Request::builder()
            .method("GET")
            .uri("/v1/node-status")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res_status.status(), StatusCode::OK);
    let status_dto: NodeStatusResponse = response_json(res_status).await;
    assert!(status_dto.free_tier_enabled);

    // 2. Check /metrics contains the 3 new gauges
    let res_metrics = app.clone().oneshot(
        Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res_metrics.status(), StatusCode::OK);
    let body_bytes = res_metrics.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(body_str.contains("humoco_gateway_concentration_ratio"));
    assert!(body_str.contains("humoco_shard_subnet_dominance_max"));
    assert!(body_str.contains("humoco_free_tier_enabled 1"));

    // 3. Check /dashboard/data contains telemetry fields
    let res_dash = app.clone().oneshot(
        Request::builder()
            .method("GET")
            .uri("/dashboard/data")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res_dash.status(), StatusCode::OK);
    let dash_bytes = res_dash.into_body().collect().await.unwrap().to_bytes();
    let dash_json: serde_json::Value = serde_json::from_slice(&dash_bytes).unwrap();
    assert_eq!(dash_json["free_tier_enabled"], true);
    assert!(dash_json.get("gateway_concentration_ratio").is_some());
    assert!(dash_json.get("shard_subnet_dominance_max").is_some());
    assert!(dash_json.get("warnings").is_some());

    // 4. Check HTML dashboard renders
    let res_html = app.oneshot(
        Request::builder()
            .method("GET")
            .uri("/dashboard")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res_html.status(), StatusCode::OK);
    let html_bytes = res_html.into_body().collect().await.unwrap().to_bytes();
    let html_str = String::from_utf8_lossy(&html_bytes);
    assert!(html_str.contains("Netzwerk-Thermometer") || html_str.contains("Ingress &amp; Telemetrie"));
    assert!(html_str.contains("Top-2 Konzentration"));
}

#[tokio::test]
async fn test_admin_verify_token_endpoint() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_admin_auth.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let auth = Arc::new(humoco_node::api::auth::AdminTokenManager::with_token("secret_token_42", false));
    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state = state.with_auth(auth);

    let app = build_router(state.clone());

    // 1. Without Authorization header -> 401
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/verify-token")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 2. With invalid token -> 401
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/verify-token")
            .header("Authorization", "Bearer wrong_token")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 3. With valid Bearer token -> 200
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/verify-token")
            .header("Authorization", "Bearer secret_token_42")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 4. With raw token -> 200
    let res = app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/verify-token")
            .header("Authorization", "secret_token_42")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Verify audit events recorded in event_log
    let events = state.event_log.list();
    assert!(events.iter().any(|e| e.message == "Fehlgeschlagene Admin-Authentifizierung"));
    assert!(events.iter().any(|e| e.message == "Erfolgreiche Admin-Authentifizierung"));
}

#[tokio::test]
async fn test_admin_verify_token_rate_limiting() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_verify_token_rate_limit.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let auth = Arc::new(humoco_node::api::auth::AdminTokenManager::with_token(
        "secret_token_rate_limit",
        false,
    ));
    let event_log = Arc::new(humoco_node::api::events::EventLog::default());
    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state = state.with_auth(auth).with_event_log(event_log.clone());

    let app = build_router(state);

    // 5 consecutive failed attempts
    for _ in 0..5 {
        let res = app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/admin/verify-token")
                .header("Authorization", "Bearer invalid_pass")
                .body(Body::empty())
                .unwrap(),
        ).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // 6th attempt should be blocked by rate-limiter with 429
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/verify-token")
            .header("Authorization", "Bearer invalid_pass")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // Verify rate limit and auth failure events were logged
    assert!(event_log.len() >= 6);
    let events = event_log.list();
    assert!(events.iter().any(|e| e.message.contains("Fehlgeschlagene Admin-Authentifizierung")));
    assert!(events.iter().any(|e| e.message.contains("Rate-Limit für Admin-Authentifizierung")));
}

#[tokio::test]
async fn test_admin_friends_mutation() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_admin_friends.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    let peer_manager = Arc::new(humoco_node::network::PeerManager::with_f2f(vec![], vec![]));

    let auth = Arc::new(humoco_node::api::auth::AdminTokenManager::with_token("admin_secret_99", false));
    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state.peer_manager = Some(peer_manager.clone());
    state = state.with_auth(auth);

    let app = build_router(state.clone());

    let test_friend_key = [7u8; 32];
    let test_friend_hex = hex::encode(test_friend_key);

    // 1. POST without auth -> 401
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/friends")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"pubkey": "{}"}}"#, test_friend_hex)))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 2. POST with invalid hex -> 400
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/friends")
            .header("Authorization", "Bearer admin_secret_99")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"pubkey": "not_hex"}"#))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 3. POST with valid auth and valid pubkey -> 200
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/friends")
            .header("Authorization", "Bearer admin_secret_99")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"pubkey": "{}", "label": "Bob"}}"#, test_friend_hex)))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["status"], "ok");
    assert_eq!(body_json["pubkey"], test_friend_hex);

    // Verify peer_manager has the friend
    assert!(peer_manager.is_f2f_friend(&test_friend_key).await);

    // 4. DELETE with invalid hex -> 400
    let res = app.clone().oneshot(
        Request::builder()
            .method("DELETE")
            .uri("/dashboard/admin/friends/invalid_key")
            .header("Authorization", "Bearer admin_secret_99")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 5. DELETE without auth -> 401
    let res = app.clone().oneshot(
        Request::builder()
            .method("DELETE")
            .uri(format!("/dashboard/admin/friends/{}", test_friend_hex))
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 6. DELETE with valid auth -> 200
    let res = app.oneshot(
        Request::builder()
            .method("DELETE")
            .uri(format!("/dashboard/admin/friends/{}", test_friend_hex))
            .header("Authorization", "Bearer admin_secret_99")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Verify peer_manager removed the friend
    assert!(!peer_manager.is_f2f_friend(&test_friend_key).await);
}

#[tokio::test]
async fn test_admin_mesh_and_ingress_client_routes() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_admin_mesh_ingress.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    let peer_manager = Arc::new(humoco_node::network::PeerManager::with_f2f(vec![], vec![]));

    let auth = Arc::new(humoco_node::api::auth::AdminTokenManager::with_token("admin_secret_99", false));
    let event_log = Arc::new(humoco_node::api::events::EventLog::default());
    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state.peer_manager = Some(peer_manager.clone());
    state = state.with_auth(auth).with_event_log(event_log.clone());

    let app = build_router(state);

    let test_peer_key = [9u8; 32];
    let test_peer_hex = hex::encode(test_peer_key);

    // 1. POST /dashboard/admin/mesh/peers (Pure mesh peer registration, no dual-role)
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/mesh/peers")
            .header("Authorization", "Bearer admin_secret_99")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"pubkey": "{}", "label": "PeerAlice"}}"#,
                test_peer_hex
            )))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["status"], "ok");
    assert_eq!(body_json["pubkey"], test_peer_hex);

    // Verify peer manager registered the peer
    assert!(peer_manager.is_f2f_friend(&test_peer_key).await);

    // Verify events recorded
    assert!(!event_log.is_empty());

    // 2. DELETE /dashboard/admin/mesh/peers/:key
    let res = app.clone().oneshot(
        Request::builder()
            .method("DELETE")
            .uri(format!("/dashboard/admin/mesh/peers/{}", test_peer_hex))
            .header("Authorization", "Bearer admin_secret_99")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!peer_manager.is_f2f_friend(&test_peer_key).await);

    // 3. POST /dashboard/admin/ingress/clients with explicit token
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/ingress/clients")
            .header("Authorization", "Bearer admin_secret_99")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"label": "Bob Wallet", "token": "f2f_custom_token_12345"}"#))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let bob_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(bob_json["status"], "ok");
    assert_eq!(bob_json["token"], "f2f_custom_token_12345");
    assert_eq!(bob_json["label"], "Bob Wallet");
    assert!(bob_json["wallet_uri"].as_str().unwrap().starts_with("humoco://"));
    assert!(bob_json["wallet_uri"].as_str().unwrap().contains("token=f2f_custom_token_12345"));

    // 4. POST /dashboard/admin/ingress/clients without token -> auto-generated f2f_... token
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/ingress/clients")
            .header("Authorization", "Bearer admin_secret_99")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"label": "Charlie PoS"}"#))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let charlie_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(charlie_json["status"], "ok");
    let gen_token = charlie_json["token"].as_str().unwrap();
    assert!(gen_token.starts_with("f2f_"));
    assert_eq!(gen_token.len(), 4 + 32); // f2f_ + 32 hex chars
    assert!(charlie_json["wallet_uri"].as_str().unwrap().contains(gen_token));

    // Verify Bob and Charlie in list_f2f_clients
    let clients = tier_controller.list_f2f_clients(1000, 0);
    assert!(clients.iter().any(|c| c.label == "Bob Wallet"));
    assert!(clients.iter().any(|c| c.label == "Charlie PoS"));

    // Verify GET /dashboard/data NEVER leaks plaintext tokens in f2f_clients
    let res_dash = app.clone().oneshot(
        Request::builder()
            .method("GET")
            .uri("/dashboard/data")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res_dash.status(), StatusCode::OK);
    let dash_bytes = res_dash.into_body().collect().await.unwrap().to_bytes();
    let dash_json: serde_json::Value = serde_json::from_slice(&dash_bytes).unwrap();
    let dash_clients = dash_json["f2f_clients"].as_array().expect("f2f_clients array");
    assert_eq!(dash_clients.len(), 2);
    for client in dash_clients {
        assert!(client["token"].is_null(), "Token leak detected! Plaintext token must be null in /dashboard/data");
        assert!(client["token_hash"].as_str().is_some());
    }

    let bob_client = clients.iter().find(|c| c.label == "Bob Wallet").unwrap();
    let bob_hash = bob_client.token_hash.clone();

    // 5. DELETE /dashboard/admin/ingress/clients/:token_hash
    let res = app.clone().oneshot(
        Request::builder()
            .method("DELETE")
            .uri(format!("/dashboard/admin/ingress/clients/{}", bob_hash))
            .header("Authorization", "Bearer admin_secret_99")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let del_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(del_json["status"], "ok");
    assert_eq!(del_json["removed"], bob_hash);

    // Verify Bob is removed
    let clients_after = tier_controller.list_f2f_clients(1000, 0);
    assert!(!clients_after.iter().any(|c| c.label == "Bob Wallet"));
    assert!(clients_after.iter().any(|c| c.label == "Charlie PoS"));
}

#[tokio::test]
async fn test_admin_quota_mutation() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_admin_quota.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let auth = Arc::new(humoco_node::api::auth::AdminTokenManager::with_token("admin_secret_vip", false));
    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state = state.with_auth(auth);

    let app = build_router(state.clone());

    let test_account_tag = [42u8; 32];
    let test_tag_hex = hex::encode(test_account_tag);

    // 1. POST /dashboard/admin/quota without auth -> 401
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/quota")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"account_tag": "{}", "byte_years": 5000}}"#, test_tag_hex)))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 2. POST with plain-text token name -> 200 OK
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/quota")
            .header("Authorization", "Bearer admin_secret_vip")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"account_tag": "pos_terminal_vip_1", "byte_years": 1000}"#))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["status"], "ok");
    assert_eq!(body_json["account_tag"], "pos_terminal_vip_1");
    assert_eq!(body_json["new_balance"], 1000);

    // 3. POST top-up 5000 byte-years -> 200
    let res = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/quota")
            .header("Authorization", "Bearer admin_secret_vip")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"account_tag": "{}", "byte_years": 5000}}"#, test_tag_hex)))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["status"], "ok");
    assert_eq!(body_json["account_tag"], test_tag_hex);
    assert_eq!(body_json["new_balance"], 5000);

    // 4. POST another 2500 byte-years -> 200 (balance 7500)
    let res = app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/dashboard/admin/quota")
            .header("Authorization", "Bearer admin_secret_vip")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"account_tag": "{}", "byte_years": 2500}}"#, test_tag_hex)))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["new_balance"], 7500);

    // Verify cache in tier_controller
    assert_eq!(tier_controller.get_cached_vip_quota(&test_account_tag), Some(7500));

    // Verify audit events recorded in event_log
    let events = state.event_log.list();
    assert!(events.iter().any(|e| e.message == "Fehlgeschlagene Admin-Authentifizierung"));
    assert!(events.iter().any(|e| e.kind == humoco_node::api::events::EventKind::QuotaTopup && e.message.contains("VIP Quota aufgeladen")));
}

// ============================================================================
// Phase 4: QA & Verification Integration Tests
// ============================================================================

#[test]
fn test_qa_key_parsing_formats() {
    use humoco_node::api::keys::{normalize_pubkey_display, parse_client_token, parse_pubkey};

    let sample_key = [0xabu8; 32];
    let hex_lower = hex::encode(sample_key);
    let hex_upper = hex_lower.to_uppercase();
    let b58_str = bs58::encode(sample_key).into_string();

    // 1. Hex parsing (lower, upper, 0x, 0X, with whitespace)
    assert_eq!(parse_pubkey(&hex_lower).unwrap(), sample_key);
    assert_eq!(parse_pubkey(&hex_upper).unwrap(), sample_key);
    assert_eq!(parse_pubkey(&format!("0x{}", hex_lower)).unwrap(), sample_key);
    assert_eq!(parse_pubkey(&format!("0X{}", hex_upper)).unwrap(), sample_key);
    assert_eq!(parse_pubkey(&format!("  \n  {} \t ", hex_lower)).unwrap(), sample_key);

    // 2. Base58 parsing (plain and with whitespace)
    assert_eq!(parse_pubkey(&b58_str).unwrap(), sample_key);
    assert_eq!(parse_pubkey(&format!("  \t {} \n ", b58_str)).unwrap(), sample_key);

    // 3. Peering string formats (<pubkey>@<ip_or_host>:<port>)
    let peering_b58 = format!("{}@127.0.0.1:9090", b58_str);
    assert_eq!(parse_pubkey(&peering_b58).unwrap(), sample_key);

    let peering_hex = format!("{}@mesh-node.example.org:9090", hex_lower);
    assert_eq!(parse_pubkey(&peering_hex).unwrap(), sample_key);

    let peering_spaces = format!("  {}  @  192.168.1.100:9090  ", hex_upper);
    assert_eq!(parse_pubkey(&peering_spaces).unwrap(), sample_key);

    // 4. Invalid key inputs
    assert!(parse_pubkey("").is_err());
    assert!(parse_pubkey("   ").is_err());
    assert!(parse_pubkey("not_a_valid_key").is_err());
    assert!(parse_pubkey("@127.0.0.1:9090").is_err());
    assert!(parse_pubkey(&format!("{}@", b58_str)).is_err());
    // Truncated hex (62 chars) and oversized hex (66 chars)
    assert!(parse_pubkey(&hex_lower[..62]).is_err());
    assert!(parse_pubkey(&format!("{}00", hex_lower)).is_err());
    // Base58 that decodes to wrong length
    let b58_16 = bs58::encode(&[1u8; 16]).into_string();
    assert!(parse_pubkey(&b58_16).is_err());

    // 5. Normalization display
    let (h, b) = normalize_pubkey_display(&sample_key);
    assert_eq!(h, hex_lower);
    assert_eq!(b, b58_str);

    // 6. Client token parsing
    assert_eq!(parse_client_token("f2f_test_token_123").unwrap(), "f2f_test_token_123");
    assert_eq!(parse_client_token("  token_with_whitespace  ").unwrap(), "token_with_whitespace");
    assert!(parse_client_token("").is_err());
    assert!(parse_client_token("short").is_err()); // < 8 chars
    let long_token = "a".repeat(129);
    assert!(parse_client_token(&long_token).is_err()); // > 128 chars
}

fn create_qa_mock_dashboard_data() -> humoco_node::api::DashboardData {
    use humoco_node::api::*;
    use humoco_node::api::metrics::LatencyTierStats;

    DashboardData {
        status: "ONLINE".to_string(),
        status_badge: "ONLINE".to_string(),
        node_id: "node_123".to_string(),
        public_key: "pk_123".to_string(),
        hrw_routing_id: "hrw_123".to_string(),
        peering_string: "pk_123@127.0.0.1:9090".to_string(),
        uptime_seconds: 7200,
        uptime_formatted: "2h 0m 0s".to_string(),
        active_locks: 5,
        flush_queue_depth: 10,
        connected_peers: 3,
        configured_peers: 3,
        active_nodes_count: 4,
        total_writes: 50,
        total_reads: 200,
        local_latency: LatencyTierStats {
            avg_ms: 0.8,
            p95_ms: 1.5,
            min_ms: 0.3,
            max_ms: 3.0,
            sample_count: 50,
            sla_compliant: true,
        },
        quorum_latency: LatencyTierStats {
            avg_ms: 20.0,
            p95_ms: 35.0,
            min_ms: 10.0,
            max_ms: 50.0,
            sample_count: 50,
            sla_compliant: true,
        },
        e2e_latency: LatencyTierStats {
            avg_ms: 22.0,
            p95_ms: 40.0,
            min_ms: 11.0,
            max_ms: 60.0,
            sample_count: 50,
            sla_compliant: true,
        },
        pos_latency_count: 50,
        pos_latency_avg_ms: 0.8,
        pos_sla_compliant: true,
        broom_patterns_detected: 0,
        gateway_concentration_ratio: 0.1,
        shard_subnet_dominance_max: 0.2,
        free_tier_enabled: true,
        warnings: Vec::new(),
        total_shards: 65536,
        shard_mode: "Community-Mesh (N < 20)".to_string(),
        shard_responsibility_ratio: 1.0,
        sample_shard_scores: vec![
            ShardScoreSampleDto {
                shard_id: 0,
                score: 0.85,
                is_responsible: true,
                rank: 1,
            },
        ],
        disk_free_gb: 10.0,
        quorum_display: "14/20 (Final)".to_string(),
        network_nodes: Vec::new(),
        total_active_vouchers_count: 1,
        active_vouchers: Vec::new(),
        recent_locks: Vec::new(),
        system: humoco_node::api::system_stats::SystemStatsDto::default(),
        thermometer: ThermometerStatsDto {
            gossip_write_load: 0.0,
            gossip_read_load: 0.0,
            ncb_eff: 960_000.0,
            ncb_read_eff: 960_000.0,
            daily_write_quota: 960_000,
            daily_read_quota: 960_000,
            today_write_used: 50,
            today_read_used: 200,
            total_write_used: 50,
            total_read_used: 200,
            vip_writes_today: 5,
            f2f_writes_today: 10,
            free_writes_today: 35,
            write_quota_limit: 4_800_000,
            read_quota_limit: 4_800_000,
            write_quota_percent: 0.1,
            read_quota_percent: 0.1,
        },
        sparklines: humoco_node::api::system_stats::SparklinesDto::default(),
        tiers: TierOverviewDto {
            free_pow_diff: 8,
            free_pow_hashes: 256,
            free_pow_time_est: "< 0.1 ms".to_string(),
            free_req_sec: 0.0,
            free_reserved_pct: 20.0,
            free_used_pct: 0.5,
            free_writes_today: 35,
            friends_reserved_pct: 30.0,
            friends_used_pct: 1.0,
            friends_writes_today: 10,
            active_friends_count: 1,
            vip_reserved_pct: 50.0,
            vip_used_pct: 0.5,
            vip_writes_today: 5,
            vip_accounts_count: 1,
            vip_total_balance: 500,
            vip_accounts: Vec::new(),
            total_writes_today: 50,
            total_quota_used_pct: 0.05,
        },
        f2f: F2fOverviewDto {
            my_pubkey: "pk_123".to_string(),
            friends: Vec::new(),
        },
        network_time_ms: 1_700_000_000_000,
        is_simulation: false,
        f2f_clients: Vec::new(),
        health: HealthSummary::default(),
        config_view: ConfigViewDto::default(),
        clock_drift_ms: 0,
        persistence: humoco_node::api::PersistenceDto::default(),
        rejections: humoco_node::api::RejectionsDto::default(),
    }
}

#[test]
fn test_qa_health_evaluation_all_levels() {
    use humoco_node::api::health::{evaluate_health, HealthLevel};

    // 1. Ok Level
    let base_data = create_qa_mock_dashboard_data();
    let summary = evaluate_health(&base_data);
    assert_eq!(summary.level, HealthLevel::Ok);
    assert!(summary.items.is_empty());

    // 2. Warn Level triggers
    // 2a. Flush queue warning (> 1000)
    let mut data_q_warn = base_data.clone();
    data_q_warn.flush_queue_depth = 1500;
    let s_q_warn = evaluate_health(&data_q_warn);
    assert_eq!(s_q_warn.level, HealthLevel::Warn);
    assert!(s_q_warn.items.iter().any(|i| i.code == "QUEUE_HIGH"));

    // 2b. PoS SLA violation
    let mut data_sla = base_data.clone();
    data_sla.pos_sla_compliant = false;
    let s_sla = evaluate_health(&data_sla);
    assert_eq!(s_sla.level, HealthLevel::Warn);
    assert!(s_sla.items.iter().any(|i| i.code == "SLA_VIOLATED"));

    // 2c. Broom pattern detected
    let mut data_broom = base_data.clone();
    data_broom.broom_patterns_detected = 3;
    let s_broom = evaluate_health(&data_broom);
    assert_eq!(s_broom.level, HealthLevel::Warn);
    assert!(s_broom.items.iter().any(|i| i.code == "BROOM"));

    // 2d. Gateway concentration > 50%
    let mut data_gw = base_data.clone();
    data_gw.gateway_concentration_ratio = 0.65;
    let s_gw = evaluate_health(&data_gw);
    assert_eq!(s_gw.level, HealthLevel::Warn);
    assert!(s_gw.items.iter().any(|i| i.code == "GATEWAY_CONC"));

    // 2e. Shard subnet dominance > 50%
    let mut data_dom = base_data.clone();
    data_dom.shard_subnet_dominance_max = 0.70;
    let s_dom = evaluate_health(&data_dom);
    assert_eq!(s_dom.level, HealthLevel::Warn);
    assert!(s_dom.items.iter().any(|i| i.code == "SUBNET_DOM"));

    // 2f. Clock drift > 5,000 ms
    let mut data_drift_warn = base_data.clone();
    data_drift_warn.clock_drift_ms = 6_000;
    let s_drift_warn = evaluate_health(&data_drift_warn);
    assert_eq!(s_drift_warn.level, HealthLevel::Warn);
    assert!(s_drift_warn.items.iter().any(|i| i.code == "CLOCK_DRIFT"));

    // 3. Crit Level triggers
    // 3a. Disconnected peers when configured > 0
    let mut data_no_peers = base_data.clone();
    data_no_peers.connected_peers = 0;
    data_no_peers.configured_peers = 5;
    let s_no_peers = evaluate_health(&data_no_peers);
    assert_eq!(s_no_peers.level, HealthLevel::Crit);
    assert!(s_no_peers.items.iter().any(|i| i.code == "NO_PEERS"));

    // 3b. Extreme flush queue depth (>= 9000)
    let mut data_q_crit = base_data.clone();
    data_q_crit.flush_queue_depth = 9500;
    let s_q_crit = evaluate_health(&data_q_crit);
    assert_eq!(s_q_crit.level, HealthLevel::Crit);
    assert!(s_q_crit.items.iter().any(|i| i.code == "QUEUE_HIGH" && i.severity == HealthLevel::Crit));

    // 3c. Extreme clock drift (> 30,000 ms)
    let mut data_drift_crit = base_data.clone();
    data_drift_crit.clock_drift_ms = -35_000;
    let s_drift_crit = evaluate_health(&data_drift_crit);
    assert_eq!(s_drift_crit.level, HealthLevel::Crit);
    assert!(s_drift_crit.items.iter().any(|i| i.code == "CLOCK_DRIFT" && i.severity == HealthLevel::Crit));

    // 3d. Dashboard exposed on non-loopback
    let mut data_exposed = base_data.clone();
    data_exposed.config_view.bind_addr = "0.0.0.0".to_string();
    data_exposed.config_view.loopback_only = false;
    let s_exposed = evaluate_health(&data_exposed);
    assert_eq!(s_exposed.level, HealthLevel::Crit);
    assert!(s_exposed.items.iter().any(|i| i.code == "DASHBOARD_EXPOSED"));
}

#[test]
fn test_qa_dashboard_data_dto_backward_compatibility() {
    use humoco_node::api::DashboardData;
    use humoco_node::api::health::HealthLevel;

    // Minimal JSON representing DashboardData before Phase 1-4 additions:
    // Missing: f2f_clients, health, config_view, clock_drift_ms, thermometer extended counters, recent_locks extended fields
    let legacy_json = r#"{
        "status": "ONLINE",
        "status_badge": "ONLINE",
        "node_id": "legacy_node_1",
        "public_key": "legacy_pubkey_1",
        "hrw_routing_id": "legacy_hrw_1",
        "peering_string": "legacy_pubkey_1@127.0.0.1:9090",
        "uptime_seconds": 3600,
        "uptime_formatted": "1h 0m 0s",
        "active_locks": 12,
        "flush_queue_depth": 0,
        "connected_peers": 4,
        "configured_peers": 4,
        "active_nodes_count": 5,
        "total_writes": 120,
        "total_reads": 450,
        "local_latency": {
            "avg_ms": 0.5, "p95_ms": 1.0, "min_ms": 0.2, "max_ms": 2.0,
            "sample_count": 100, "sla_compliant": true
        },
        "quorum_latency": {
            "avg_ms": 15.0, "p95_ms": 25.0, "min_ms": 5.0, "max_ms": 40.0,
            "sample_count": 100, "sla_compliant": true
        },
        "e2e_latency": {
            "avg_ms": 18.0, "p95_ms": 30.0, "min_ms": 7.0, "max_ms": 45.0,
            "sample_count": 100, "sla_compliant": true
        },
        "pos_latency_count": 100,
        "pos_latency_avg_ms": 0.5,
        "pos_sla_compliant": true,
        "broom_patterns_detected": 0,
        "gateway_concentration_ratio": 0.15,
        "shard_subnet_dominance_max": 0.25,
        "free_tier_enabled": true,
        "warnings": [],
        "total_shards": 1024,
        "shard_mode": "Global Mesh",
        "shard_responsibility_ratio": 1.0,
        "sample_shard_scores": [],
        "network_nodes": [],
        "total_active_vouchers_count": 2,
        "active_vouchers": [],
        "recent_locks": [
            {
                "parent_lock_hex": "1111111111111111111111111111111111111111111111111111111111111111",
                "child_lock_hex": "2222222222222222222222222222222222222222222222222222222222222222",
                "timestamp_ms": 1700000000000,
                "status": "Verified"
            }
        ],
        "system": {
            "cpu_percent": 5.0,
            "rss_mb": 100.0,
            "redb_bytes": 52428800,
            "netto_locks_bytes": 1000,
            "disk_free_bytes": 10737418240,
            "peak_tps_single_core": 50000,
            "peak_tps_multi_core": 120000,
            "max_storage_locks": 50000000,
            "byte_years_capacity": 10000000,
            "ttl_purged_count": 0
        },
        "thermometer": {
            "gossip_write_load": 0.0,
            "gossip_read_load": 0.0,
            "ncb_eff": 960000.0,
            "ncb_read_eff": 960000.0,
            "daily_write_quota": 960000,
            "daily_read_quota": 960000,
            "today_write_used": 120,
            "today_read_used": 450
        },
        "sparklines": {
            "writes": [],
            "reads": [],
            "latency": [],
            "nodes": []
        },
        "tiers": {
            "free_pow_diff": 8,
            "free_pow_hashes": 256,
            "free_pow_time_est": "< 0.1 ms",
            "free_req_sec": 0.0,
            "free_reserved_pct": 20.0,
            "free_used_pct": 1.0,
            "free_writes_today": 70,
            "friends_reserved_pct": 30.0,
            "friends_used_pct": 2.0,
            "friends_writes_today": 30,
            "active_friends_count": 2,
            "vip_reserved_pct": 50.0,
            "vip_used_pct": 1.0,
            "vip_writes_today": 20,
            "vip_accounts_count": 1,
            "vip_total_balance": 1000,
            "vip_accounts": [],
            "total_writes_today": 120,
            "total_quota_used_pct": 0.1
        },
        "f2f": {
            "my_pubkey": "legacy_pubkey_1",
            "friends": []
        },
        "network_time_ms": 1700000000000,
        "is_simulation": false
    }"#;

    let parsed: Result<DashboardData, _> = serde_json::from_str(legacy_json);
    assert!(parsed.is_ok(), "Failed to deserialize legacy DashboardData: {:?}", parsed.err());

    let dto = parsed.unwrap();
    // Verify default populated fields
    assert_eq!(dto.f2f_clients.len(), 0);
    assert_eq!(dto.health.level, HealthLevel::Ok);
    assert!(dto.health.items.is_empty());
    assert_eq!(dto.config_view.api_port, 8080);
    assert_eq!(dto.config_view.bind_addr, "127.0.0.1");
    assert!(dto.config_view.loopback_only);
    assert_eq!(dto.clock_drift_ms, 0);

    // Verify recent_locks defaults
    assert_eq!(dto.recent_locks.len(), 1);
    assert_eq!(dto.recent_locks[0].tier, "");
    assert_eq!(dto.recent_locks[0].byte_years, 0);
    assert_eq!(dto.recent_locks[0].voucher_id, None);

    // Verify thermometer defaults
    assert_eq!(dto.thermometer.total_write_used, 0);
    assert_eq!(dto.thermometer.vip_writes_today, 0);
    assert_eq!(dto.thermometer.f2f_writes_today, 0);
    assert_eq!(dto.thermometer.free_writes_today, 0);

    // Verify persistence and rejections defaults
    assert_eq!(dto.persistence.flush_batches_total, 0);
    assert_eq!(dto.persistence.flush_queue_depth, 0);
    assert_eq!(dto.rejections.total_rejected, 0);
    assert_eq!(dto.rejections.conflict_409, 0);

    // Verify Phase 5 dashboard fields backward compatibility
    assert_eq!(dto.disk_free_gb, 0.0);
    assert_eq!(dto.quorum_display, "");

    // Verify ShardScoreSampleDto backward compatibility without rank field
    use humoco_node::api::ShardScoreSampleDto;
    let legacy_shard_json = r#"{"shard_id": 42, "score": 0.85, "is_responsible": true}"#;
    let parsed_shard: Result<ShardScoreSampleDto, _> = serde_json::from_str(legacy_shard_json);
    assert!(parsed_shard.is_ok(), "Failed to deserialize legacy ShardScoreSampleDto: {:?}", parsed_shard.err());
    let shard_dto = parsed_shard.unwrap();
    assert_eq!(shard_dto.shard_id, 42);
    assert_eq!(shard_dto.score, 0.85);
    assert!(shard_dto.is_responsible);
    assert_eq!(shard_dto.rank, 0);
}

#[test]
fn test_qa_dashboard_status_badges_and_quorum_display() {
    let compute_badge_and_quorum = |connected_peers: usize, configured_peers: usize, total_active: usize, is_stable_24h: bool| -> (String, String, String) {
        let (status, status_badge) = if connected_peers == 0 && configured_peers > 0 {
            ("DEGRADED".to_string(), "DEGRADED (0 Peers)".to_string())
        } else if total_active == 1 || configured_peers == 0 {
            ("STANDALONE".to_string(), "STANDALONE (N=1, PROVISIONAL)".to_string())
        } else if total_active < 20 {
            ("COMMUNITY MESH".to_string(), format!("COMMUNITY-MESH (N={}, PROVISIONAL)", total_active))
        } else if !is_stable_24h {
            ("STABILIZING".to_string(), "WELTNETZ (24h-Stabilisierung)".to_string())
        } else {
            ("ONLINE".to_string(), "WELTNETZ (FINAL)".to_string())
        };

        let (required_q, _) = humoco_sim_core::types::required_quorum(total_active);
        let quorum_display = if total_active < 20 {
            format!("{}/{} (Prov)", required_q, total_active)
        } else {
            "14/20 (Final)".to_string()
        };

        (status, status_badge, quorum_display)
    };

    // 1. DEGRADED (configured > 0 but 0 connected)
    let (s, b, q) = compute_badge_and_quorum(0, 3, 1, false);
    assert_eq!(s, "DEGRADED");
    assert_eq!(b, "DEGRADED (0 Peers)");
    assert_eq!(q, "1/1 (Prov)");

    // 2. STANDALONE (configured == 0 or total_active == 1)
    let (s, b, q) = compute_badge_and_quorum(0, 0, 1, false);
    assert_eq!(s, "STANDALONE");
    assert_eq!(b, "STANDALONE (N=1, PROVISIONAL)");
    assert_eq!(q, "1/1 (Prov)");

    // 3. COMMUNITY MESH (total_active < 20, e.g. 5 nodes)
    let (s, b, q) = compute_badge_and_quorum(4, 4, 5, false);
    assert_eq!(s, "COMMUNITY MESH");
    assert_eq!(b, "COMMUNITY-MESH (N=5, PROVISIONAL)");
    assert_eq!(q, "4/5 (Prov)");

    // 4. STABILIZING (total_active >= 20, is_stable_24h == false)
    let (s, b, q) = compute_badge_and_quorum(20, 20, 21, false);
    assert_eq!(s, "STABILIZING");
    assert_eq!(b, "WELTNETZ (24h-Stabilisierung)");
    assert_eq!(q, "14/20 (Final)");

    // 5. ONLINE / WELTNETZ (total_active >= 20, is_stable_24h == true)
    let (s, b, q) = compute_badge_and_quorum(20, 20, 21, true);
    assert_eq!(s, "ONLINE");
    assert_eq!(b, "WELTNETZ (FINAL)");
    assert_eq!(q, "14/20 (Final)");
}

#[tokio::test]
async fn test_qa_dashboard_history_and_events_endpoints_structure() {
    let (app, _storage, _identity, _tier_controller, _pow_engine) = setup_test_app();

    // 1. GET /dashboard/history with various windows
    for window in &["30m", "1h", "6h", "24h", "all"] {
        let uri = format!("/dashboard/history?window={}", window);
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();

        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let content_type = res.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("application/json"));

        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("points").is_some());
        assert!(json["points"].is_array());
    }

    // 2. GET /dashboard/events with limit and since_id parameters
    let req_ev = Request::builder()
        .method("GET")
        .uri("/dashboard/events?limit=25&since_id=0")
        .body(Body::empty())
        .unwrap();

    let res_ev = app.oneshot(req_ev).await.unwrap();
    assert_eq!(res_ev.status(), StatusCode::OK);
    let bytes_ev = res_ev.into_body().collect().await.unwrap().to_bytes();
    let json_ev: serde_json::Value = serde_json::from_slice(&bytes_ev).unwrap();
    assert!(json_ev.get("events").is_some());
    assert!(json_ev["events"].is_array());
}

#[tokio::test]
async fn test_qa_admin_endpoints_unauthorized_and_mutations() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_qa_admin.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    let peer_manager = Arc::new(humoco_node::network::PeerManager::with_f2f(vec![], vec![]));

    let auth = Arc::new(humoco_node::api::auth::AdminTokenManager::with_token("qa_admin_secret", false));
    let event_log = Arc::new(humoco_node::api::events::EventLog::default());
    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state.peer_manager = Some(peer_manager.clone());
    state = state.with_auth(auth).with_event_log(event_log.clone());

    let app = build_router(state);

    let test_peer = [7u8; 32];
    let test_peer_hex = hex::encode(test_peer);

    // 1. Unauthorized requests (no token / wrong token)
    let endpoints_to_test = vec![
        ("POST", "/dashboard/admin/mesh/peers", r#"{"pubkey": "test"}"#),
        ("DELETE", "/dashboard/admin/mesh/peers/somekey", ""),
        ("POST", "/dashboard/admin/ingress/clients", r#"{"label": "test"}"#),
        ("DELETE", "/dashboard/admin/ingress/clients/somehash", ""),
        ("POST", "/dashboard/admin/quota", r#"{"account_tag": "test", "byte_years": 100}"#),
    ];

    for (meth, uri, body) in endpoints_to_test {
        // Without header -> 401
        let req_no_auth = Request::builder()
            .method(meth)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let res = app.clone().oneshot(req_no_auth).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // With invalid header -> 401
        let req_bad_auth = Request::builder()
            .method(meth)
            .uri(uri)
            .header("Authorization", "Bearer wrong_secret")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let res_bad = app.clone().oneshot(req_bad_auth).await.unwrap();
        assert_eq!(res_bad.status(), StatusCode::UNAUTHORIZED);
    }

    // 2. Add mesh peer (dual_role_ingress is ignored; server peering does NOT register F2F ingress client)
    let req_dual = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/mesh/peers")
        .header("Authorization", "Bearer qa_admin_secret")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"pubkey": "{}", "label": "DualPeer", "dual_role_ingress": true}}"#,
            test_peer_hex
        )))
        .unwrap();
    let res_dual = app.clone().oneshot(req_dual).await.unwrap();
    assert_eq!(res_dual.status(), StatusCode::OK);
    assert!(peer_manager.is_f2f_friend(&test_peer).await);
    let clients = tier_controller.list_f2f_clients(1000, 0);
    assert!(!clients.iter().any(|c| c.label == "DualPeer"));

    // 3. Add client friend and then remove
    let req_add_client = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/ingress/clients")
        .header("Authorization", "Bearer qa_admin_secret")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"label": "Kasse-A", "token": "f2f_kasse_a_secret_token"}"#))
        .unwrap();
    let res_client = app.clone().oneshot(req_add_client).await.unwrap();
    assert_eq!(res_client.status(), StatusCode::OK);
    let client_json: serde_json::Value = serde_json::from_slice(
        &res_client.into_body().collect().await.unwrap().to_bytes(),
    ).unwrap();
    assert_eq!(client_json["label"], "Kasse-A");

    let client_list = tier_controller.list_f2f_clients(1000, 0);
    let kasse_client = client_list.iter().find(|c| c.label == "Kasse-A").unwrap();
    let token_hash = kasse_client.token_hash.clone();

    // Remove client friend
    let req_del = Request::builder()
        .method("DELETE")
        .uri(format!("/dashboard/admin/ingress/clients/{}", token_hash))
        .header("Authorization", "Bearer qa_admin_secret")
        .body(Body::empty())
        .unwrap();
    let res_del = app.oneshot(req_del).await.unwrap();
    assert_eq!(res_del.status(), StatusCode::OK);
    assert!(!tier_controller.list_f2f_clients(1000, 0).iter().any(|c| c.label == "Kasse-A"));
}

#[test]
fn test_qa_ring_buffer_boundary_conditions() {
    use humoco_node::api::history::{HistoryPoint, HistorySampler, HISTORY_CAPACITY};
    use humoco_node::api::events::{EventKind, EventLog, EVENT_LOG_CAPACITY};
    use humoco_node::api::health::HealthLevel;

    // 1. HistorySampler: exact 1440 limit
    assert_eq!(HISTORY_CAPACITY, 1440);
    let sampler = HistorySampler::new(HISTORY_CAPACITY);
    assert_eq!(sampler.capacity(), 1440);

    for i in 1..=1440 {
        sampler.record(HistoryPoint {
            timestamp_sec: i as u64,
            write_count: i as u64,
            read_count: 0,
            free_writes: 0,
            f2f_writes: 0,
            vip_writes: 0,
            connected_peers: 1,
            active_locks: 1,
            queue_depth: 0,
            pow_diff: 8,
        });
    }
    assert_eq!(sampler.len(), 1440);
    let points = sampler.query("all");
    assert_eq!(points.len(), 1440);
    assert_eq!(points[0].timestamp_sec, 1);
    assert_eq!(points[1439].timestamp_sec, 1440);

    // Overflow by 1: point 1 must be evicted, point 2 is first, point 1441 is last
    sampler.record(HistoryPoint {
        timestamp_sec: 1441,
        write_count: 1441,
        read_count: 0,
        free_writes: 0,
        f2f_writes: 0,
        vip_writes: 0,
        connected_peers: 1,
        active_locks: 1,
        queue_depth: 0,
        pow_diff: 8,
    });
    assert_eq!(sampler.len(), 1440);
    let overflow_points = sampler.query("all");
    assert_eq!(overflow_points.len(), 1440);
    assert_eq!(overflow_points[0].timestamp_sec, 2);
    assert_eq!(overflow_points[1439].timestamp_sec, 1441);

    // 2. EventLog: exact 1000 limit
    assert_eq!(EVENT_LOG_CAPACITY, 1000);
    let log = EventLog::new(EVENT_LOG_CAPACITY);
    assert_eq!(log.capacity(), 1000);

    for i in 1..=1000 {
        log.record_at(
            10000 + i as u64,
            EventKind::System,
            HealthLevel::Ok,
            format!("Event {}", i),
        );
    }
    assert_eq!(log.len(), 1000);
    let events = log.query(None, None);
    assert_eq!(events.len(), 1000);
    assert_eq!(events[0].id, 1);
    assert_eq!(events[999].id, 1000);

    // Overflow by 1: event id 1 must be evicted, event 2 is first, event 1001 is last
    log.record_at(
        11001,
        EventKind::PeerConnect,
        HealthLevel::Ok,
        "Event 1001",
    );
    assert_eq!(log.len(), 1000);
    let overflow_events = log.query(None, None);
    assert_eq!(overflow_events.len(), 1000);
    assert_eq!(overflow_events[0].id, 2);
    assert_eq!(overflow_events[999].id, 1001);
}

#[tokio::test]
async fn test_admin_peer_reset_and_ping_endpoints() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_admin_peer.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    let peer_manager = Arc::new(humoco_node::network::PeerManager::with_f2f(vec![], vec![]));

    let auth = Arc::new(humoco_node::api::auth::AdminTokenManager::with_token("test_admin_token", false));
    let event_log = Arc::new(humoco_node::api::events::EventLog::default());
    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    state.peer_manager = Some(peer_manager.clone());
    state = state.with_auth(auth).with_event_log(event_log.clone());

    let app = build_router(state);

    let test_addr: std::net::SocketAddr = "127.0.0.1:9095".parse().unwrap();
    let unknown_addr = "127.0.0.1:9999";
    let bad_addr_str = "not-a-valid-socket";

    // 1. Auth check
    let req_no_auth = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/peers/{}/reset", test_addr))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_no_auth).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let req_bad_auth = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/peers/{}/ping", test_addr))
        .header("Authorization", "Bearer wrong_secret")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_bad_auth).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 2. Bad request check (malformed address)
    let req_bad_addr_reset = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/peers/{}/reset", bad_addr_str))
        .header("Authorization", "Bearer test_admin_token")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_bad_addr_reset).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let req_bad_addr_ping = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/peers/{}/ping", bad_addr_str))
        .header("Authorization", "Bearer test_admin_token")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_bad_addr_ping).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 3. Not Found check for reset
    let req_not_found = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/peers/{}/reset", unknown_addr))
        .header("Authorization", "Bearer test_admin_token")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_not_found).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 4. Reset execution on degraded/suspended peer
    peer_manager.add_peer(test_addr).await;
    let t0 = std::time::Instant::now();
    peer_manager.record_failure_at(test_addr, t0).await;
    peer_manager.record_failure_at(test_addr, t0 + std::time::Duration::from_secs(65)).await;
    peer_manager.record_failure_at(test_addr, t0 + std::time::Duration::from_secs(130)).await;
    let p = peer_manager.get_peer(&test_addr).await.unwrap();
    assert_eq!(p.missing_count, 3);
    assert_eq!(p.status, humoco_node::network::peer::PeerStatus::Suspended);

    let req_reset = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/peers/{}/reset", test_addr))
        .header("Authorization", "Bearer test_admin_token")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_reset).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json_resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json_resp["status"], "ok");
    assert_eq!(json_resp["addr"], test_addr.to_string());

    let p_after = peer_manager.get_peer(&test_addr).await.unwrap();
    assert_eq!(p_after.missing_count, 0);
    assert_eq!(p_after.last_failure, None);
    assert_eq!(p_after.status, humoco_node::network::peer::PeerStatus::Degrading);

    // Verify event log recorded the action
    let events = event_log.query(None, None);
    assert!(events.iter().any(|e| e.message.contains(&format!("Admin reset suspension for peer {}", test_addr))));

    // 5. Banned peer check for reset
    let banned_addr: std::net::SocketAddr = "127.0.0.1:9096".parse().unwrap();
    let banned_nid = [88u8; 32];
    peer_manager.add_peer(banned_addr).await;
    peer_manager.record_success(banned_addr, Some(banned_nid), None).await;
    peer_manager.ban_node(&banned_nid).await;

    let req_banned = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/peers/{}/reset", banned_addr))
        .header("Authorization", "Bearer test_admin_token")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_banned).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json_banned: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json_banned["error"], "Banned");

    // 6. Ping check when transport is unavailable -> 502 Bad Gateway
    let req_ping_no_transport = Request::builder()
        .method("POST")
        .uri(format!("/dashboard/admin/peers/{}/ping", test_addr))
        .header("Authorization", "Bearer test_admin_token")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req_ping_no_transport).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn test_event_log_persister_and_populate() {
    use humoco_node::api::events::{EventItem, EventKind, EventLog};
    use humoco_node::api::health::HealthLevel;

    // 1. Populate test
    let log = EventLog::new(10);
    let existing = vec![
        EventItem {
            id: 10,
            timestamp_sec: 1000,
            kind: EventKind::System,
            severity: HealthLevel::Ok,
            message: "Initial boot".into(),
        },
        EventItem {
            id: 15,
            timestamp_sec: 1005,
            kind: EventKind::PeerConnect,
            severity: HealthLevel::Ok,
            message: "Peer connected".into(),
        },
    ];

    log.populate(existing);
    assert_eq!(log.len(), 2);
    // next_id should be max(existing.id) + 1 = 16
    let new_id = log.record(EventKind::System, HealthLevel::Ok, "Third event");
    assert_eq!(new_id, 16);

    // 2. Persister integration test
    let (tx, mut rx) = tokio::sync::mpsc::channel::<EventItem>(100);
    log.set_persister(tx);

    // Ok severity, normal kind -> should NOT persist
    let _id_ok = log.record(EventKind::System, HealthLevel::Ok, "Normal info");
    assert!(rx.try_recv().is_err(), "Ok system events must not be sent to persister");

    // Warn severity -> should persist
    let id_warn = log.record(EventKind::HealthWarning, HealthLevel::Warn, "Disk space low");
    let item_warn = rx.try_recv().expect("Warn event must be sent to persister");
    assert_eq!(item_warn.id, id_warn);
    assert_eq!(item_warn.severity, HealthLevel::Warn);

    // PeerBan kind (even if Ok severity) -> should persist
    let id_ban = log.record(EventKind::PeerBan, HealthLevel::Ok, "Peer banned");
    let item_ban = rx.try_recv().expect("PeerBan event must be sent to persister");
    assert_eq!(item_ban.id, id_ban);
    assert_eq!(item_ban.kind, EventKind::PeerBan);

    // EquivocationFraud kind -> should persist
    let id_fraud = log.record(EventKind::EquivocationFraud, HealthLevel::Crit, "Double spend fraud");
    let item_fraud = rx.try_recv().expect("EquivocationFraud event must be sent to persister");
    assert_eq!(item_fraud.id, id_fraud);

    // ClientRegistered kind -> should persist
    let id_reg = log.record(EventKind::ClientRegistered, HealthLevel::Ok, "Client token registered");
    let item_reg = rx.try_recv().expect("ClientRegistered event must be sent to persister");
    assert_eq!(item_reg.id, id_reg);
}

#[tokio::test]
async fn test_dashboard_sre_monitoring_and_conflict_deep_link() {
    let (app, _, _, _, _) = setup_test_app();

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    // 409 Conflict deep link checks
    assert!(body_str.contains("jumpToConflictLocks()"), "Dashboard must contain jumpToConflictLocks");
    assert!(body_str.contains("setLockFilter"), "Dashboard must contain setLockFilter");

    // SRE Monitoring & Ecosystem checks
    assert!(body_str.contains("📡 Externe Monitoring- &amp; Alerting-Schnittstellen") || body_str.contains("Externe Monitoring-"));
    assert!(body_str.contains("scrape_configs:"), "Must contain prometheus scrape snippet");
    assert!(body_str.contains("/metrics"), "Must reference /metrics endpoint");
    assert!(body_str.contains("/healthz"), "Must reference /healthz endpoint");
    assert!(body_str.contains("/health/ready"), "Must reference /health/ready endpoint");
    assert!(body_str.contains("deploy/grafana/dashboard.json"), "Must reference Grafana template path");
    assert!(body_str.contains("/tmp/humoco.sock"), "Must reference UNIX control socket");
    assert!(body_str.contains("journalctl -u humoco-node -f"), "Must reference journalctl command");
    assert!(body_str.contains("copySnippet"), "Must contain copySnippet helper");
}

#[tokio::test]
async fn test_dashboard_etag_and_304_not_modified() {
    let (app, _storage, _identity, _tier_controller, _pow_engine) = setup_test_app();

    // 1. Initial GET /dashboard/data -> 200 OK with ETag header
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/data")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let etag = res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("ETag header must be present")
        .to_str()
        .unwrap()
        .to_string();
    assert!(!etag.is_empty(), "ETag must not be empty");

    // 2. GET /dashboard/data with matching If-None-Match -> 304 Not Modified
    let res_304 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/data")
                .header(axum::http::header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_304.status(), StatusCode::NOT_MODIFIED);
    let etag_304 = res_304
        .headers()
        .get(axum::http::header::ETAG)
        .expect("ETag header must be present in 304 response")
        .to_str()
        .unwrap();
    assert_eq!(etag_304, etag);
    let body_304 = res_304.into_body().collect().await.unwrap().to_bytes();
    assert!(body_304.is_empty(), "304 response body must be empty");

    // 3. GET /dashboard/data with mismatched If-None-Match -> 200 OK
    let res_mismatch = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/data")
                .header(axum::http::header::IF_NONE_MATCH, "\"mismatched-etag-12345\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_mismatch.status(), StatusCode::OK);
    let mismatch_etag = res_mismatch
        .headers()
        .get(axum::http::header::ETAG)
        .expect("ETag header must be present in 200 response")
        .to_str()
        .unwrap();
    assert_eq!(mismatch_etag, etag);
}


