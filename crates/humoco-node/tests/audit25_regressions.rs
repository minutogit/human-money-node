#![forbid(unsafe_code)]

//! Audit 25 Regressions (Ingress Defense and Stateless PoW)
//!
//! Covers:
//! - A25-01: Canonical direct work and exact parent binding (P2)
//! - A25-02: Remove mandatory used-work state and restore retries (P2)
//! - A25-03: Separate client credentials from peer topology (P2)
//! - A25-04: Early bounded admission and inexpensive unsigned rejection (P2)
//! - A25-05: Honor public quota denial (P2)

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

use humoco_node::api::{build_router, routes::build_operator_router, AppState};
use humoco_node::identity::NodeIdentity;
use humoco_node::ingress::pow::PowEngine;
use humoco_node::ingress::tier::{is_valid_client_token, IngressError, TierController};
use humoco_node::storage::{DualTierEngine, RedbStorage};

// ---------------------------------------------------------------------------
// A25-01: Canonical direct work and exact parent binding
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_01_canonical_direct_work_and_parent_binding() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let pow = PowEngine::new([0x42; 32], 0);

    let concrete_parent = [0x77u8; 32];
    let zero_parent = [0u8; 32];
    let other_parent = [0x88u8; 32];

    // Challenge generated for generic zero parent
    let (generic_challenge, _, _) = pow.generate_challenge_for_parent(&zero_parent);

    // 1. Verifying generic zero-parent challenge against concrete parent:
    // On unfixed code: accepted because of `|| challenge_bytes == gen_curr || challenge_bytes == gen_prev`!
    // On fixed code: MUST reject!
    let res_generic = pow
        .verify_pow_for_parent(&generic_challenge, 0, 0, Some(&concrete_parent))
        .await;
    assert!(
        res_generic.is_err(),
        "A25-01 RED check: Generic zero-parent challenge MUST NOT be accepted for concrete nonzero parent: got {:?}",
        res_generic
    );

    // 2. Cross-parent transplant: challenge generated for other_parent must reject for concrete_parent
    let (other_challenge, _, _) = pow.generate_challenge_for_parent(&other_parent);
    let res_transplant = pow
        .verify_pow_for_parent(&other_challenge, 0, 0, Some(&concrete_parent))
        .await;
    assert!(
        res_transplant.is_err(),
        "Cross-parent transplanted work must reject: got {:?}",
        res_transplant
    );
}

// ---------------------------------------------------------------------------
// A25-02: Stateless admission allows identical work retries (no ReplayDetected)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_02_identical_valid_work_retry_succeeds_without_replay_error() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let pow = PowEngine::new([0x42; 32], 0);

    let parent = [0x33u8; 32];
    let (challenge, _, _) = pow.generate_challenge_for_parent(&parent);

    // First verification succeeds
    let res1 = pow
        .verify_pow_for_parent(&challenge, 0, 0, Some(&parent))
        .await;
    assert!(res1.is_ok(), "First work verification must succeed");

    // Second verification with identical valid work (idempotent retry):
    // On unfixed code: fails with Err(ReplayDetected)!
    // On fixed code: stateless admission succeeds without ReplayDetected!
    let res2 = pow
        .verify_pow_for_parent(&challenge, 0, 0, Some(&parent))
        .await;
    assert!(
        res2.is_ok(),
        "A25-02 RED check: Exact retry of valid stateless work MUST NOT fail with ReplayDetected: got {:?}",
        res2
    );
}

// ---------------------------------------------------------------------------
// A25-03: Separate client credentials from peer topology
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_03_separate_client_credentials_from_peer_topology() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let peer_identity = NodeIdentity::generate();
    let peer_pubkey_hex = hex::encode(peer_identity.node_pubkey());
    let base58_pubkey = bs58::encode(peer_identity.node_pubkey()).into_string();
    let endpoint_str = format!("{}@127.0.0.1:9090", peer_pubkey_hex);

    // Verify token format validator rejects P2P topology strings
    assert!(
        !is_valid_client_token(&peer_pubkey_hex),
        "A25-03: Bare NodePubKey hex MUST NOT be accepted as a client token"
    );
    assert!(
        !is_valid_client_token(&base58_pubkey),
        "A25-03: Base58 NodePubKey MUST NOT be accepted as a client token"
    );
    assert!(
        !is_valid_client_token(&endpoint_str),
        "A25-03: P2P endpoint string MUST NOT be accepted as a client token"
    );
    assert!(
        !is_valid_client_token("custom_alice_token"),
        "A25-03: Arbitrary custom token MUST NOT be accepted as a client token"
    );

    // Valid random 128-bit secret token matching f2f_<32 hex digits>
    let valid_token = format!("f2f_{}", hex::encode([0xAAu8; 16]));
    assert!(
        is_valid_client_token(&valid_token),
        "Valid random 128-bit secret token matching f2f_<32 hex> must be accepted"
    );

    // API-level check: operator provisioning with a bare pubkey or malformed token
    // MUST be rejected with 400 Bad Request.
    // On unfixed code: admin_add_ingress_client accepts any string and returns 200 OK!
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("a25_03.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(PowEngine::new([0x42; 32], 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let identity = NodeIdentity::generate();
    let state = AppState::new(engine, storage, identity, tier_controller, pow);
    let operator_app = build_operator_router(state);

    let provision_req = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/ingress/clients")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "label": "unauthorized_peer",
                "token": peer_pubkey_hex
            }))
            .unwrap(),
        ))
        .unwrap();

    let provision_resp = operator_app.oneshot(provision_req).await.unwrap();
    assert_eq!(
        provision_resp.status(),
        StatusCode::BAD_REQUEST,
        "A25-03 RED check: Provisioning bare NodePubKey as client token MUST return 400 Bad Request: got {:?}",
        provision_resp.status()
    );
}

// ---------------------------------------------------------------------------
// A25-04: Early bounded admission returns unsigned lightweight 401 error
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_04_unauthenticated_request_returns_unsigned_error() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("a25_04.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(PowEngine::new([0x42; 32], 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let identity = NodeIdentity::generate();

    let state = AppState::new(engine, storage, identity, tier_controller, pow);
    for shard in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(shard);
    }
    let app = build_router(state);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Send POST /v1/lock with an unauthenticated lock request (no token, no PoW)
    let body = serde_json::json!({
        "auth": {
            "ephemeral_pubkey": bs58::encode([1u8; 32]).into_string(),
            "auth_signature": null
        },
        "layer2_voucher_id": "test_voucher_a25_04",
        "ds_tag": null,
        "transaction_hash": bs58::encode([2u8; 32]).into_string(),
        "is_genesis": true,
        "sender_ephemeral_pub": bs58::encode([1u8; 32]).into_string(),
        "receiver_ephemeral_pub_hash": null,
        "change_ephemeral_pub_hash": null,
        "layer2_signature": bs58::encode([0u8; 64]).into_string(),
        "created_at_ms": now_ms,
        "deletable_at": (now_ms + 600_000).to_string()
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let resp_bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&resp_bytes).unwrap();

    // On unfixed code: 401 response contains "server_signature" (asymmetric Ed25519 signature before admission)!
    // On fixed code: lightweight error response has NO server_signature!
    assert!(
        json.get("server_signature").is_none(),
        "A25-04 RED check: Unadmitted 401 error response MUST NOT contain a server_signature: got {:?}",
        json
    );
}

// ---------------------------------------------------------------------------
// A25-05: Public admission honors daily-quota rejection
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_05_public_admission_honors_daily_quota_exhaustion() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("a25_05.redb")).expect("open redb"));
    let pow = Arc::new(PowEngine::new([0x42; 32], 0));
    let controller = TierController::new(storage, pow);

    let parent = [0x55u8; 32];
    // A daily quota of 960_000 byte-years:
    // With 144 bytes per lock, 300_000_000_000 seconds = ~1_369_863 byte-years (> 960_000 daily quota)
    let huge_ttl_seconds = 300_000_000_000u64;

    let res = controller
        .evaluate_and_charge(None, None, None, None, huge_ttl_seconds, Some(&parent))
        .await;

    // On unfixed code: try_accept_lock return bool was ignored, returning Ok(Tier3Public)!
    // On fixed code: MUST return Err(IngressError::QuotaExceeded)!
    assert!(
        matches!(res, Err(IngressError::QuotaExceeded { .. })),
        "A25-05 RED check: Over-quota public write MUST be rejected with QuotaExceeded: got {:?}",
        res
    );
}

// ---------------------------------------------------------------------------
// A25-R1: Canonical hash_work accepted and legacy solution hash rejected
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_r1_canonical_hash_work_accepted_and_legacy_solution_hash_rejected() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let pow = PowEngine::new([0x42; 32], 8);

    let parent = [9u8; 32];
    let slot = 2u64;
    let canonical_nonce = 475u64;
    let difficulty = 8u32;
    let now_sec = slot * 600 + 30; // Within slot 2

    // 1. Verify that canonical hash_work meets difficulty >= 8
    let hash = humoco_node::ingress::pow::hash_work(&parent, slot, canonical_nonce);
    let leading_zeros = humoco_node::ingress::pow::count_leading_zero_bits(&hash);
    assert!(
        leading_zeros >= difficulty,
        "Test vector invariant: hash_work(&[9; 32], 2, 475) must have >= 8 leading zeros, got {}",
        leading_zeros
    );

    // 2. Verification with canonical nonce succeeds
    let (challenge, _, _) = pow.generate_challenge_for_parent_at(&parent, now_sec);
    let verify_res = pow
        .verify_pow_for_parent_at(
            &challenge,
            canonical_nonce,
            difficulty,
            Some(&parent),
            now_sec,
        )
        .await;
    assert_eq!(
        verify_res,
        Ok(true),
        "Canonical hash_work nonce must be accepted by verify_pow_for_parent_at"
    );

    // 3. Solve a nonce using legacy compute_solution_hash
    let challenge_bytes = hex::decode(&challenge).unwrap();
    let mut chal_arr = [0u8; 32];
    chal_arr.copy_from_slice(&challenge_bytes);
    let mut legacy_nonce = 0u64;
    for n in 0..10_000 {
        let legacy_hash = humoco_node::ingress::pow::compute_solution_hash(&chal_arr, n);
        if humoco_node::ingress::pow::count_leading_zero_bits(&legacy_hash) >= difficulty {
            legacy_nonce = n;
            break;
        }
    }

    // 4. Verification with legacy solution hash MUST be rejected
    // (unless legacy nonce coincidentally satisfies hash_work too, check hash_work first)
    let legacy_work_zeros = humoco_node::ingress::pow::count_leading_zero_bits(
        &humoco_node::ingress::pow::hash_work(&parent, slot, legacy_nonce),
    );
    if legacy_work_zeros < difficulty {
        let legacy_res = pow
            .verify_pow_for_parent_at(&challenge, legacy_nonce, difficulty, Some(&parent), now_sec)
            .await;
        assert!(
            matches!(legacy_res, Err(humoco_node::ingress::pow::PowError::InsufficientDifficulty { .. })),
            "Legacy compute_solution_hash nonce must be rejected by canonical hash_work verification: got {:?}",
            legacy_res
        );
    }
}

// ---------------------------------------------------------------------------
// A25-R2: Chain PoW bound to terminal parent rejects cross-chain transplant
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_r2_chain_pow_bound_to_parent_rejects_cross_chain_transplant() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("a25_r2.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(PowEngine::new([0x42; 32], 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let identity = NodeIdentity::generate();
    let state = AppState::new(engine, storage, identity, tier_controller, pow.clone());
    for shard in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(shard);
    }
    let app = build_router(state);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Chain A with ds_tag "chain_parent_a"
    let parent_a_bytes = *blake3::hash(b"chain_parent_a").as_bytes();
    let (challenge_a, diff_a, _) = pow.generate_challenge_for_parent(&parent_a_bytes);
    let nonce_a = pow
        .solve_pow_for_parent(&parent_a_bytes, diff_a, 50_000)
        .expect("Solve PoW for Chain A parent");

    let chain_b_body = serde_json::json!({
        "auth": {
            "ephemeral_pubkey": bs58::encode([3u8; 32]).into_string(),
            "auth_signature": null
        },
        "layer2_voucher_id": "voucher_chain_b",
        "chain": [
            {
                "causal_output": null,
                "auth": {
                    "ephemeral_pubkey": bs58::encode([3u8; 32]).into_string(),
                    "auth_signature": null
                },
                "layer2_voucher_id": "voucher_chain_b",
                "ds_tag": "chain_parent_b",
                "transaction_hash": bs58::encode([4u8; 32]).into_string(),
                "is_genesis": false,
                "sender_ephemeral_pub": bs58::encode([3u8; 32]).into_string(),
                "receiver_ephemeral_pub_hash": null,
                "change_ephemeral_pub_hash": null,
                "layer2_signature": bs58::encode([0u8; 64]).into_string(),
                "created_at_ms": now_ms,
                "deletable_at": null
            }
        ]
    });

    // Submitting Chain B with challenge and nonce of Chain A -> MUST be rejected (InvalidPoW / 400 Bad Request)
    let req_transplant = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("content-type", "application/json")
        .header("x-pow-challenge", &challenge_a)
        .header("x-pow-nonce", nonce_a.to_string())
        .body(Body::from(serde_json::to_vec(&chain_b_body).unwrap()))
        .unwrap();

    let resp_transplant = app.clone().oneshot(req_transplant).await.unwrap();
    assert_eq!(
        resp_transplant.status(),
        StatusCode::BAD_REQUEST,
        "Transplanted PoW challenge from parent A MUST be rejected for Chain B (parent B)"
    );
    let bytes_transplant = axum::body::to_bytes(resp_transplant.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json_transplant: Value = serde_json::from_slice(&bytes_transplant).unwrap();
    assert_eq!(
        json_transplant.get("error").and_then(|v| v.as_str()),
        Some("InvalidPoW"),
        "Transplanted PoW must return InvalidPoW error: got {:?}",
        json_transplant
    );

    // Submitting Chain A with its own matching PoW -> passes PoW admission!
    let chain_a_body = serde_json::json!({
        "auth": {
            "ephemeral_pubkey": bs58::encode([3u8; 32]).into_string(),
            "auth_signature": null
        },
        "layer2_voucher_id": "voucher_chain_a",
        "chain": [
            {
                "causal_output": null,
                "auth": {
                    "ephemeral_pubkey": bs58::encode([3u8; 32]).into_string(),
                    "auth_signature": null
                },
                "layer2_voucher_id": "voucher_chain_a",
                "ds_tag": "chain_parent_a",
                "transaction_hash": bs58::encode([4u8; 32]).into_string(),
                "is_genesis": false,
                "sender_ephemeral_pub": bs58::encode([3u8; 32]).into_string(),
                "receiver_ephemeral_pub_hash": null,
                "change_ephemeral_pub_hash": null,
                "layer2_signature": bs58::encode([0u8; 64]).into_string(),
                "created_at_ms": now_ms,
                "deletable_at": null
            }
        ]
    });

    let req_chain_a = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("content-type", "application/json")
        .header("x-pow-challenge", &challenge_a)
        .header("x-pow-nonce", nonce_a.to_string())
        .body(Body::from(serde_json::to_vec(&chain_a_body).unwrap()))
        .unwrap();

    let resp_a = app.clone().oneshot(req_chain_a).await.unwrap();
    let bytes_a = axum::body::to_bytes(resp_a.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json_a: Value = serde_json::from_slice(&bytes_a).unwrap();
    assert_ne!(
        json_a.get("error").and_then(|v| v.as_str()),
        Some("InvalidPoW"),
        "Chain A with matching PoW must pass PoW validation, got {:?}",
        json_a
    );
}

// ---------------------------------------------------------------------------
// A25-R3: Unauthenticated empty or invalid requests rejected unsigned before root I/O
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_r3_unauthenticated_empty_or_invalid_requests_rejected_unsigned_before_root_io() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("a25_r3.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(PowEngine::new([0x42; 32], 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let identity = NodeIdentity::generate();
    let state = AppState::new(engine, storage, identity, tier_controller, pow);
    let app = build_router(state);

    // 1. Empty chain request -> 400 Bad Request, unsigned (no server_signature)
    let empty_body = serde_json::json!({
        "auth": {
            "ephemeral_pubkey": bs58::encode([1u8; 32]).into_string(),
            "auth_signature": null
        },
        "layer2_voucher_id": "test_empty_chain",
        "chain": []
    });

    let req_empty = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&empty_body).unwrap()))
        .unwrap();

    let resp_empty = app.clone().oneshot(req_empty).await.unwrap();
    assert_eq!(resp_empty.status(), StatusCode::BAD_REQUEST);
    let bytes_empty = axum::body::to_bytes(resp_empty.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json_empty: Value = serde_json::from_slice(&bytes_empty).unwrap();
    assert!(
        json_empty.get("server_signature").is_none(),
        "Empty chain error response MUST NOT contain a server_signature: got {:?}",
        json_empty
    );

    // 2. Unauthenticated chain spend with unknown root -> 401 Unauthorized, unsigned (no server_signature)
    let unauth_chain_body = serde_json::json!({
        "auth": {
            "ephemeral_pubkey": bs58::encode([5u8; 32]).into_string(),
            "auth_signature": null
        },
        "layer2_voucher_id": "unknown_voucher_nonexistent",
        "chain": [
            {
                "causal_output": null,
                "auth": {
                    "ephemeral_pubkey": bs58::encode([5u8; 32]).into_string(),
                    "auth_signature": null
                },
                "layer2_voucher_id": "unknown_voucher_nonexistent",
                "ds_tag": "ds_tag_spend_1",
                "transaction_hash": bs58::encode([6u8; 32]).into_string(),
                "is_genesis": false,
                "sender_ephemeral_pub": bs58::encode([5u8; 32]).into_string(),
                "receiver_ephemeral_pub_hash": null,
                "change_ephemeral_pub_hash": null,
                "layer2_signature": bs58::encode([0u8; 64]).into_string(),
                "created_at_ms": 1_000_000,
                "deletable_at": null
            }
        ]
    });

    let req_unauth = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&unauth_chain_body).unwrap()))
        .unwrap();

    let resp_unauth = app.oneshot(req_unauth).await.unwrap();
    assert_eq!(resp_unauth.status(), StatusCode::UNAUTHORIZED);
    let bytes_unauth = axum::body::to_bytes(resp_unauth.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json_unauth: Value = serde_json::from_slice(&bytes_unauth).unwrap();
    assert!(
        json_unauth.get("server_signature").is_none(),
        "Unauthenticated chain response MUST NOT contain a server_signature: got {:?}",
        json_unauth
    );
}

// ---------------------------------------------------------------------------
// A25-R4: Client token validator enforces strict 128-bit hex format
// ---------------------------------------------------------------------------
#[test]
fn test_a25_r4_client_token_validator_enforces_strict_128bit_hex() {
    // Rejected: password strings or arbitrary identifiers
    assert!(!is_valid_client_token("f2f_password"));
    assert!(!is_valid_client_token("f2f_alice_friend_token"));
    assert!(!is_valid_client_token("f2f_secret"));

    // Rejected: wrong lengths (less or more than 32 hex chars)
    assert!(!is_valid_client_token("f2f_0123"));
    assert!(!is_valid_client_token(
        "f2f_0123456789abcdef0123456789abcde"
    )); // 31 chars
    assert!(!is_valid_client_token(
        "f2f_0123456789abcdef0123456789abcdef0"
    )); // 33 chars

    // Rejected: non-hex characters
    assert!(!is_valid_client_token(
        "f2f_0123456789abcdef0123456789abcdeg"
    )); // 'g' is non-hex
    assert!(!is_valid_client_token(
        "f2f_0123456789abcdef0123456789abcde-"
    )); // '-' is non-hex

    // Accepted: exactly 32 hex characters (128-bit secret)
    assert!(is_valid_client_token(
        "f2f_0123456789abcdef0123456789abcdef"
    ));
    assert!(is_valid_client_token(
        "f2f_00000000000000000000000000000000"
    ));
    assert!(is_valid_client_token(
        "f2f_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    ));
    assert!(is_valid_client_token(
        "  f2f_0123456789abcdef0123456789abcdef  "
    ));
}
