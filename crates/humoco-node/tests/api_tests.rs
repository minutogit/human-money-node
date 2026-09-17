use std::sync::Arc;
use ed25519_dalek::Signer;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tower::ServiceExt;

use humoco_node::{
    api::{
        build_router, AppState, ErrorResponse, LockSubmitRequest, LockSubmitResponse,
        NodeStatusResponse, PowChallengeResponse, SyncRequest, SyncResponse,
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

async fn response_json<T: serde::de::DeserializeOwned>(res: axum::response::Response) -> T {
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body_bytes).expect("Failed to deserialize response body")
}

#[tokio::test]
async fn test_api_lock_submission_and_idempotency() {
    let (app, _storage, identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_secret_token");

    let now = test_now_ms();
    let req_payload = LockSubmitRequest {
        parent_lock: "01".repeat(32),
        receiver_pub: "02".repeat(32),
        nonce: "test_nonce_123".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("friend_secret_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    // 1. Initial lock submission -> 201 Created
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let submit_resp: LockSubmitResponse = response_json(res).await;
    assert_eq!(submit_resp.status, "ACCEPTED");
    assert!(submit_resp.attestation.is_some());

    let attestation = submit_resp.attestation.unwrap();
    assert_eq!(attestation.lock_id, submit_resp.lock_id);
    assert_eq!(attestation.signature.len(), 128); // 64 bytes hex encoded

    // Verify signature with node identity using canonical SigDigest
    let sig_bytes = hex::decode(&attestation.signature).unwrap();
    let lock_id_bytes: [u8; 32] = hex::decode(&attestation.lock_id).unwrap().try_into().unwrap();
    let parent_lock_bytes: [u8; 32] = hex::decode(&attestation.parent_lock).unwrap().try_into().unwrap();
    let shard_id = u16::from_be_bytes([parent_lock_bytes[0], parent_lock_bytes[1]]);
    let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
        humoco_sim_core::crypto::DOMAIN_APPROVE_PROV,
        0,
        0,
        0,
        shard_id,
        0,
        &lock_id_bytes,
    );
    let ed_sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    assert!(identity.verifying_key().verify_strict(&sig_digest, &ed_sig).is_ok());

    // 2. Exact duplicate submission -> 200 OK (Idempotent)
    let req_dup = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res_dup = app.oneshot(req_dup).await.unwrap();
    assert_eq!(res_dup.status(), StatusCode::OK);

    let submit_resp_dup: LockSubmitResponse = response_json(res_dup).await;
    assert_eq!(submit_resp_dup.status, "IDEMPOTENT");
    assert_eq!(submit_resp_dup.lock_id, submit_resp.lock_id);
    assert!(submit_resp_dup.attestation.is_some());
}

#[tokio::test]
async fn test_api_lock_conflict_double_spend() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_secret_token");

    let parent_lock = "aa".repeat(32);
    let now = test_now_ms();

    let req_lock_a = LockSubmitRequest {
        parent_lock: parent_lock.clone(),
        receiver_pub: "11".repeat(32),
        nonce: "nonce_a".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("friend_secret_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res_a = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_lock_a).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_a.status(), StatusCode::CREATED);

    // Second lock on same parent with different receiver/nonce -> 409 Conflict
    let req_lock_b = LockSubmitRequest {
        parent_lock,
        receiver_pub: "22".repeat(32),
        nonce: "nonce_b".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("friend_secret_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res_b = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_lock_b).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_b.status(), StatusCode::CONFLICT);
    let conflict_resp: LockSubmitResponse = response_json(res_b).await;
    assert_eq!(conflict_resp.status, "REJECTED");
    assert!(conflict_resp.reason.unwrap().contains("Double-spend"));
}

#[tokio::test]
async fn test_api_pow_challenge_and_public_ingress() {
    let (app, _storage, _identity, _tier_controller, _pow_engine) = setup_test_app();

    let parent_lock = "bb".repeat(32);
    let now = test_now_ms();
    let mut req_payload = LockSubmitRequest {
        parent_lock,
        receiver_pub: "cc".repeat(32),
        nonce: "public_nonce".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: None,
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    // 1. Submit without PoW -> 401 Unauthorized + Challenge
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
    let err_resp: ErrorResponse = response_json(res_unauth).await;
    assert_eq!(err_resp.error, "PoWRequired");
    assert!(err_resp.challenge.is_some());
    assert_eq!(err_resp.difficulty, Some(8));

    // Also test GET /v1/pow-challenge endpoint
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
    let challenge = err_resp.challenge.unwrap();
    let nonce = PowEngine::solve_pow(&challenge, 8, 10_000).expect("Solve PoW");

    req_payload.pow_challenge = Some(challenge);
    req_payload.pow_nonce = Some(nonce);

    // 3. Submit with solved PoW -> 201 Created
    let res_pow_ok = app
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

    assert_eq!(res_pow_ok.status(), StatusCode::CREATED);
    let ok_resp: LockSubmitResponse = response_json(res_pow_ok).await;
    assert_eq!(ok_resp.status, "ACCEPTED");
    assert!(ok_resp.attestation.is_some());
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
    let req_payload = LockSubmitRequest {
        parent_lock: "dd".repeat(32),
        receiver_pub: "ee".repeat(32),
        nonce: "vip_nonce_1".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 31_536_000_000,
        created_at: Some(now),
        auth_token: Some(vip_token.into()),
        peer_token: None,
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res = app
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

    assert_eq!(res.status(), StatusCode::CREATED);
    let submit_resp: LockSubmitResponse = response_json(res).await;
    assert_eq!(submit_resp.status, "ACCEPTED");

    // Quota should now be deducted: 1000 - 192 = 808
    assert_eq!(storage.get_quota(&account_tag).unwrap(), 808);

    // Try submitting with TTL that exceeds remaining quota (e.g. 5 years = 960 BY > 808)
    let req_excess = LockSubmitRequest {
        parent_lock: "ff".repeat(32),
        receiver_pub: "ee".repeat(32),
        nonce: "vip_nonce_2".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 5 * 31_536_000_000,
        created_at: Some(now),
        auth_token: Some(vip_token.into()),
        peer_token: None,
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res_excess = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_excess).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_excess.status(), StatusCode::TOO_MANY_REQUESTS);
    let err_resp: ErrorResponse = response_json(res_excess).await;
    assert_eq!(err_resp.error, "QuotaExceeded");
    // Quota remains 808
    assert_eq!(storage.get_quota(&account_tag).unwrap(), 808);
}

#[tokio::test]
async fn test_api_status_and_sync() {
    let (app, storage, identity, tier_controller, _) = setup_test_app();
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
    let req_lock = LockSubmitRequest {
        parent_lock: parent_lock.clone(),
        receiver_pub: "34".repeat(32),
        nonce: "sync_nonce".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("sync_peer".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res_sub = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_lock).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_sub.status(), StatusCode::CREATED);

    // Wait a brief moment or manually persist to disk table
    let mut parent_arr = [0u8; 32];
    parent_arr.copy_from_slice(&hex::decode(&parent_lock).unwrap());
    let rec = humoco_sim_core::types::LockRecord::new(
        parent_arr,
        [0x34; 32],
        b"sync_nonce".to_vec(),
        humoco_sim_core::types::SimTime(0),
        humoco_sim_core::types::SimTime(60_000_000_000), // unexpired
    );
    storage.put_lock(&rec, 600_000_000_000).unwrap();

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
    assert_eq!(sync_resp.locks[0].parent_lock, parent_lock);

    // 4. Call sync with locator including parent_lock -> filtered out
    let sync_req_filtered = SyncRequest {
        sparse_locators: vec![parent_lock],
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
                .uri("/lock")
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
                .uri("/lock")
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
                .uri("/lock")
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
                .uri("/status")
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
                .uri("/lock")
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
                .uri("/lock")
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
                .uri("/lock")
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
                .uri("/status")
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

    // 5. Invalid signature
    let mut bad_sig_req = genesis_req.clone();
    bad_sig_req.layer2_signature[0] ^= 0xFF;
    let res_bad = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lock")
                .header("content-type", "application/json")
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

    let banned_key = [0x99u8; 32];
    engine.ban_node(banned_key, 12345).await;

    let state = AppState::new(
        engine.clone(),
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    let app = build_router(state);

    // 1. Submit standard lock from banned node
    let now = test_now_ms();
    let banned_req = LockSubmitRequest {
        parent_lock: "01".repeat(32),
        receiver_pub: hex::encode(banned_key),
        nonce: "test_nonce".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("f2f_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&banned_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN, "Banned node must be rejected with 403 Forbidden");

    // 2. Submit HMC lock from banned ephemeral key
    let hmc_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: banned_key,
            auth_signature: None,
        },
        layer2_voucher_id: "test_voucher_1".into(),
        ds_tag: None,
        transaction_hash: [0x11; 32],
        is_genesis: true,
        sender_ephemeral_pub: banned_key,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let res_hmc = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&hmc_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_hmc.status(), StatusCode::FORBIDDEN, "Banned node in HMC must be rejected with 403 Forbidden");
}

#[tokio::test]
async fn test_api_quorum_certificate_assembly_standalone() {
    let (app, _storage, identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_token");

    // 1. Submit standard Lock -> QuorumCertificateDto should be assembled with status 0 PROVISIONAL (N=1)
    let now = test_now_ms();
    let req_payload = LockSubmitRequest {
        parent_lock: "0a".repeat(32),
        receiver_pub: "0b".repeat(32),
        nonce: "standalone_qc_test".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("friend_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let submit_resp: LockSubmitResponse = response_json(res).await;
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
    use humoco_node::network::{NodeRequestHandler, RequestHandler};
    use humoco_sim_core::wire::{MsgType, WireHeader};

    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_handler.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();

    let handler = NodeRequestHandler::new(engine.clone(), storage.clone(), identity.clone());

    // 1. Test LockVerifyRequest
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let record = humoco_sim_core::types::LockRecord::new(
        [0x33; 32],
        [0x44; 32],
        vec![0x01, 0x02],
        humoco_sim_core::types::SimTime(now_ms),
        humoco_sim_core::types::SimTime(now_ms + 60_000),
    );
    let payload = bincode::serialize(&(record.clone(), now_ms + 600_000u64)).unwrap();
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
    assert_eq!(att.lock_id, hex::encode(record.id));
    assert_eq!(att.parent_lock, hex::encode(record.parent_lock));
    assert_eq!(att.node_id, u16::from_be_bytes([identity.node_id()[0], identity.node_id()[1]]));

    // 2. Test ShardDigestRequest
    let digest_header = WireHeader::new(
        MsgType::ShardDigestRequest as u16,
        2,
        0,
        0,
        2,
    );
    let shard_payload = 1u16.to_le_bytes().to_vec();
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
    let parent_bytes = hex::decode(&parent_lock).unwrap();
    let mut parent_arr = [0u8; 32];
    parent_arr.copy_from_slice(&parent_bytes);

    let (challenge, difficulty, _) = pow_engine.generate_challenge_for_parent(&parent_arr);
    let nonce = PowEngine::solve_blake3_hashcash(&challenge, difficulty, 50_000).expect("Solve BLAKE3 PoW");

    let now = test_now_ms();
    let req_payload = LockSubmitRequest {
        parent_lock: parent_lock.clone(),
        receiver_pub: "99".repeat(32),
        nonce: "pow_retry_nonce".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: None,
        pow_challenge: Some(challenge),
        pow_nonce: Some(nonce),
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    // 1. Initial submission -> 201 Created
    let res1 = app
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

    assert_eq!(res1.status(), StatusCode::CREATED);
    let resp1: LockSubmitResponse = response_json(res1).await;
    assert_eq!(resp1.status, "ACCEPTED");

    // 2. Retry with identical payload & PoW -> 200 OK (IdempotentReplay, not 401 ReplayDetected!)
    let res2 = app
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

    assert_eq!(res2.status(), StatusCode::OK, "Retry of same lock must be recognized as idempotent (HTTP 200)");
    let resp2: LockSubmitResponse = response_json(res2).await;
    assert_eq!(resp2.status, "IDEMPOTENT");
    assert_eq!(resp2.lock_id, resp1.lock_id);
}

#[tokio::test]
async fn test_phase1_idempotent_retry_without_created_at() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("friend_retry_token");

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let parent_lock = "77".repeat(32);
    let req_payload = LockSubmitRequest {
        parent_lock: parent_lock.clone(),
        receiver_pub: "66".repeat(32),
        nonce: "no_created_at_nonce".into(),
        valid_until: now_ms + 60_000,
        root_valid_until: now_ms + 600_000,
        created_at: None, // Client does not provide created_at
        auth_token: None,
        peer_token: Some("friend_retry_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    // 1. Initial submission -> 201 Created
    let res1 = app
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

    assert_eq!(res1.status(), StatusCode::CREATED);
    let resp1: LockSubmitResponse = response_json(res1).await;
    assert_eq!(resp1.status, "ACCEPTED");

    // Artificial delay to ensure now_ms would be different
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    // 2. Retry without created_at -> 200 OK (server reuses existing created_at, preventing 409 Conflict!)
    let res2 = app
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

    assert_eq!(res2.status(), StatusCode::OK, "Retry without created_at must succeed as idempotent (HTTP 200)");
    let resp2: LockSubmitResponse = response_json(res2).await;
    assert_eq!(resp2.status, "IDEMPOTENT");
    assert_eq!(resp2.lock_id, resp1.lock_id);
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
    let expected_shard_id = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);

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

    // Verify: Shard-ID MUST equal expected_shard_id (derived from parent_bytes anchor), NOT from t_id!
    assert_eq!(qc.shard_id, expected_shard_id, "Shard ID must be derived from parent voucher anchor, never from t_id");
}

#[tokio::test]
async fn test_phase1_gateway_hrw_rank_filtering_in_quorum_certificate() {
    let (_router, _storage, identity, _tier_controller, _pow_engine) = setup_test_app();
    let peer_mgr = Arc::new(humoco_node::network::PeerManager::new(vec![]));
    let transport = humoco_node::network::QuicTransport::bind("127.0.0.1:0".parse().unwrap(), &identity).unwrap();

    let shard_id: u16 = 42;
    let self_node_id = *identity.node_id();
    let self_score = humoco_sim_core::client_flow::compute_hrw_score_f64(&self_node_id, shard_id);

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

    let mut parent_lock = [0x77u8; 32];
    parent_lock[0..2].copy_from_slice(&shard_id.to_be_bytes());
    let now = test_now_ms();
    let req_payload = LockSubmitRequest {
        parent_lock: hex::encode(parent_lock),
        receiver_pub: "55".repeat(32),
        nonce: "gateway_qc_nonce".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("gateway_test_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res = app
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

    assert_eq!(res.status(), StatusCode::CREATED);
    let resp: LockSubmitResponse = response_json(res).await;
    assert!(resp.quorum_certificate.is_some());
    let qc = resp.quorum_certificate.unwrap();

    let self_node_u16 = identity.node_id_u16();
    // Gateway's own attestation must NOT be present in QuorumCertificate because its rank is > 20!
    let self_attestation_present = qc.signatures.iter().any(|s| s.node_id == self_node_u16);
    assert!(!self_attestation_present, "Gateway with HRW rank > 20 must NOT attest itself into the QuorumCertificate");
}

#[tokio::test]
async fn test_api_created_at_clock_drift_exceeded() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("drift_peer_token");

    let now = test_now_ms();

    // 1. Future clock drift > 30s
    let req_future = LockSubmitRequest {
        parent_lock: "33".repeat(32),
        receiver_pub: "44".repeat(32),
        nonce: "drift_nonce_1".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now + 35_000), // > +30s in future
        auth_token: None,
        peer_token: Some("drift_peer_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res_future = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_future).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_future.status(), StatusCode::BAD_REQUEST);

    // 2. Past clock drift > 24h (86_400_000 ms)
    let req_past = LockSubmitRequest {
        parent_lock: "33".repeat(32),
        receiver_pub: "44".repeat(32),
        nonce: "drift_nonce_2".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now.saturating_sub(90_000_000)), // > 24h past
        auth_token: None,
        peer_token: Some("drift_peer_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res_past = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
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
    let parent_bytes = [0x55u8; 32];

    // 1. Submit with insufficient difficulty (nonce = 0 doesn't satisfy difficulty 8)
    let (challenge, difficulty, _) = pow_engine.generate_challenge_for_parent(&parent_bytes);
    let req_insufficient = LockSubmitRequest {
        parent_lock: parent_hex.clone(),
        receiver_pub: "66".repeat(32),
        nonce: "pow_test_nonce_1".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: None,
        pow_challenge: Some(challenge.clone()),
        pow_nonce: Some(0),
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None, // Fails difficulty
    };

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_insufficient).unwrap()))
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

    let req_valid = LockSubmitRequest {
        parent_lock: parent_hex,
        receiver_pub: "66".repeat(32),
        nonce: "pow_test_nonce_1".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: None,
        pow_challenge: Some(challenge),
        pow_nonce: Some(valid_nonce),
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res_valid = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_valid).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res_valid.status(), StatusCode::CREATED);
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

    // Verify visual components
    assert!(body_str.contains("HuMoCo Layer-2 Node"));
    assert!(body_str.contains("VILLAGE MODE") || body_str.contains("ONLINE"));
    assert!(body_str.contains("PoS"));
    assert!(body_str.contains("Peering"));
    assert!(body_str.contains("Storage"));
    assert!(body_str.contains("qr-svg"));
    assert!(body_str.contains("Recent Locks Ring Buffer") || body_str.contains("Recent Locks Ringpuffer"));
    assert!(body_str.contains("Copy") || body_str.contains("Kopieren"));

    // Size under 20 KiB
    assert!(body_str.len() < 20 * 1024, "Dashboard HTML must be under 20 KiB, was {}", body_str.len());

    // Air-gap check: ZERO external script or link tags with http:// or https://
    let lower = body_str.to_lowercase();
    assert!(!lower.contains("<script src=\"http"), "No external scripts allowed");
    assert!(!lower.contains("<link href=\"http"), "No external stylesheets allowed");
    assert!(!lower.contains("<link rel=\"stylesheet\" href=\"http"), "No external CDN allowed");

    // Also test GET /dashboard/data
    let res_data = app
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
}

#[tokio::test]
async fn test_prometheus_metrics_expansion() {
    let (app, _storage, _identity, tier_controller, _) = setup_test_app();
    tier_controller.register_f2f_peer("metrics_peer_token");

    // Submit a valid lock to increment pos_latency_count
    let now = test_now_ms();
    let req = LockSubmitRequest {
        parent_lock: "77".repeat(32),
        receiver_pub: "88".repeat(32),
        nonce: "metrics_nonce".into(),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("metrics_peer_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite: None,
        is_bridge_lock: None,
        pqc_receiver: None,
    };

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
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
    assert!(body.contains("humoco_pos_latency_seconds_sum"));
    assert!(body.contains("humoco_locks_rejected_total 0"));
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
                .uri("/lock")
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
                .uri("/status")
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
                .uri("/status")
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
                .uri("/status")
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

    // Verify attestation cryptographic signature
    let att = &qc.signatures[0];
    let sig_bytes = hex::decode(&att.signature).unwrap();
    let ed_sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
        humoco_sim_core::crypto::DOMAIN_APPROVE_PROV,
        0,
        0,
        0,
        qc.shard_id,
        0,
        &t_id_bytes,
    );
    assert!(identity.verifying_key().verify_strict(&sig_digest, &ed_sig).is_ok());

    // 4. Multi-node adaptive quorum test with PeerManager
    let peer_mgr = Arc::new(humoco_node::network::PeerManager::new(vec![]));
    for i in 0..4u64 {
        let dummy_id = *blake3::hash(&i.to_le_bytes()).as_bytes();
        let addr = format!("127.0.0.1:{}", 17000 + i).parse().unwrap();
        peer_mgr.learn_node_from_gossip(dummy_id, addr, 1, None).await;
        peer_mgr.set_first_seen_for_test(&dummy_id, std::time::Instant::now() - std::time::Duration::from_secs(25*3600)).await;
    }

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
    state_multi.peer_manager = Some(peer_mgr);
    let app_multi = build_router(state_multi);

    // Anchor genesis on multi-node app
    let res_gen2 = app_multi
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lock")
                .header("content-type", "application/json")
                .header("X-Peer-Token", "token_multi")
                .body(Body::from(serde_json::to_vec(&genesis_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_gen2.status(), StatusCode::CREATED);

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
                .uri("/status")
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
                .uri("/lock")
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
                .uri("/lock")
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
                .uri("/lock")
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
                .uri("/lock")
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
                .uri("/status")
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
                .uri("/status")
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

    // 2. GET /peers must return PeersResponse
    let res_peers = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/peers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_peers.status(), StatusCode::OK);
    let peers_dto: humoco_node::api::dto::PeersResponse = response_json(res_peers).await;
    assert_eq!(peers_dto.network, "mainnet");
    assert!(peers_dto.active_nodes_count >= 1);

    // 3. Alias /api/v1/network/peers must return identical structure
    let res_alias = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/network/peers")
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
    let res_q = app.clone().oneshot(Request::builder().method("POST").uri("/status").header("content-type","application/json").body(Body::from(serde_json::to_vec(&status_q).unwrap())).unwrap()).await.unwrap();
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
        let r = app.clone().oneshot(Request::builder().method("POST").uri("/status").header("content-type","application/json").body(Body::from(serde_json::to_vec(&q).unwrap())).unwrap()).await.unwrap();
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
    let res_qc = app.clone().oneshot(Request::builder().method("POST").uri("/status").header("content-type","application/json").body(Body::from(serde_json::to_vec(&q_c).unwrap())).unwrap()).await.unwrap();
    let _env_qc: L2ResponseEnvelope = response_json(res_qc).await;
    // hop_c's parent tag_b corresponds to hop_b which was not inserted, so querying tag_b should return Verified for hop_a? Actually tag_gen still maps to hop_a Verified. But tag_b not present, query should be Missing or Verified not found.
    // Instead verify hop_c not present via its t_id lookup (challenge = tag_b should still show hop_a)
    // Query for hop_c's own tag (its ds_tag is tag_b, t_id is hop_c.tx) – but hop_c not inserted, so its t_id lookup should be Missing
    let q_c2 = humoco_node::api::hmc::L2StatusQuery { auth: L2AuthPayload { ephemeral_pubkey: k_c.verifying_key().to_bytes(), auth_signature: None }, layer2_voucher_id: voucher_id.clone(), challenge_ds_tag: bs58::encode(&hop_c.transaction_hash).into_string(), locator_prefixes: vec![], read_quorum: 1 };
    let res_qc2 = app.oneshot(Request::builder().method("POST").uri("/status").header("content-type","application/json").body(Body::from(serde_json::to_vec(&q_c2).unwrap())).unwrap()).await.unwrap();
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



