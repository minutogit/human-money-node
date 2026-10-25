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
