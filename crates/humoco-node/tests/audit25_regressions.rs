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
use humoco_node::ingress::tier::{is_valid_client_token, IngressError, StorageCharge, TierController};
use humoco_node::storage::{DualTierEngine, RedbStorage};

// ---------------------------------------------------------------------------
// A25-01: Canonical direct work and exact parent binding
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a25_01_canonical_direct_work_and_parent_binding() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let pow = PowEngine::new(0);

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
    let pow = PowEngine::new(0);

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
    let pow = Arc::new(PowEngine::new(8));
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
    let pow = Arc::new(PowEngine::new(8));
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
    let pow = Arc::new(PowEngine::new(0));
    let controller = TierController::new(storage, pow);

    let parent = [0x55u8; 32];
    // A daily quota of 960_000 byte-years:
    // With 144 bytes per lock, 300_000_000_000 seconds = ~1_369_863 byte-years (> 960_000 daily quota)
    let huge_ttl_seconds = 300_000_000_000u64;

    let res = controller
        .evaluate_and_charge(
            None,
            None,
            None,
            None,
            StorageCharge::single(huge_ttl_seconds),
            Some(&parent),
        )
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
    let pow = PowEngine::new(8);

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
    fn legacy_compute_solution_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        let tag = b"HUMOCO_POW_SOLUTION";
        hasher.update(&(tag.len() as u8).to_le_bytes());
        hasher.update(tag);
        hasher.update(challenge);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    let challenge_bytes = hex::decode(&challenge).unwrap();
    let mut chal_arr = [0u8; 32];
    chal_arr.copy_from_slice(&challenge_bytes);
    let mut legacy_nonce = 0u64;
    for n in 0..10_000 {
        let legacy_hash = legacy_compute_solution_hash(&chal_arr, n);
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
    let pow = Arc::new(PowEngine::new(8));
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
    let pow = Arc::new(PowEngine::new(8));
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

// ---------------------------------------------------------------------------
// S05-20: Single-lock early credential & PoW validation before root lookup/signing
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_s05_20_single_lock_rejects_invalid_credentials_and_work_before_root_lookup_and_signing() {
    use ed25519_dalek::{Signer, SigningKey};
    use humoco_node::api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockRequest};
    use humoco_node::ingress::pow::{count_leading_zero_bits, hash_work};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing::instrument::WithSubscriber;

    struct RootLookupProbeSubscriber {
        hits: Arc<AtomicUsize>,
    }

    struct MessageVisitor {
        hits: Arc<AtomicUsize>,
    }

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                let formatted = format!("{value:?}");
                if formatted.contains("Voucher root read permit saturated") {
                    self.hits.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    impl tracing::Subscriber for RootLookupProbeSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = MessageVisitor {
                hits: self.hits.clone(),
            };
            event.record(&mut visitor);
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("s05_20.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(PowEngine::new(8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow.clone()));

    let vip_tag = [0x44u8; 32];
    tier_controller.topup_vip_quota(vip_tag, 10_000).unwrap();
    let valid_vip_token = tier_controller.provision_vip_credential(vip_tag).unwrap();
    let valid_f2f_token = format!("f2f_{}", hex::encode([0xCDu8; 16]));
    tier_controller.register_f2f_peer(&valid_f2f_token);

    let identity = NodeIdentity::generate();
    let state = AppState::new(engine, storage, identity, tier_controller.clone(), pow.clone());
    for shard in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(shard);
    }

    // Close fallback semaphore so any entry into lookup_local_voucher_root emits a deterministic trace event
    // without touching disk.
    state.voucher_root_reads.close();
    let app = build_router(state.clone());

    let now_ms = state.net_time_ms();
    let now_sec = now_ms / 1000;
    let slot = pow.current_epoch_slot(now_sec);

    let sender_key = SigningKey::from_bytes(&[0x33u8; 32]);
    let sender_pub = sender_key.verifying_key().to_bytes();

    let make_spend = |voucher_id: &str, ds_tag: &str, tx_seed: u8| -> L2LockRequest {
        let mut req = L2LockRequest {
            causal_output: None,
            auth: L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            ds_tag: Some(ds_tag.to_string()),
            transaction_hash: [tx_seed; 32],
            is_genesis: false,
            sender_ephemeral_pub: sender_pub,
            layer2_signature: [0u8; 64],
            trap_r: Some("none".into()),
            trap_s: Some("none".into()),
            encrypted_timestamp: 0,
            created_at_ms: now_ms,
            deletable_at: None,
            privacy_guard: Some("none".into()),
        };
        let h = calculate_l2_payload_hash(&req);
        req.layer2_signature = sender_key.sign(&h).to_bytes();
        req
    };

    let unknown_ds_tag = "unknown_root_spend_parent";
    let unknown_parent = *blake3::hash(unknown_ds_tag.as_bytes()).as_bytes();
    let unknown_spend = make_spend("unknown_voucher_s05_20", unknown_ds_tag, 0x11);
    let unknown_spend_bytes = serde_json::to_vec(&unknown_spend).unwrap();

    let (valid_challenge, diff, _) = pow.generate_challenge_for_parent_at(&unknown_parent, now_sec);
    assert_eq!(diff, 8);
    let valid_nonce = pow
        .solve_pow_for_parent(&unknown_parent, diff, 100_000)
        .expect("solve valid nonce");
    let weak_nonce = (0..10_000u64)
        .find(|&n| count_leading_zero_bits(&hash_work(&unknown_parent, slot, n)) < diff)
        .expect("find insufficient-difficulty nonce");

    let other_parent = *blake3::hash(b"other_parent_s05_20").as_bytes();
    let (other_challenge, _, _) = pow.generate_challenge_for_parent_at(&other_parent, now_sec);
    let other_nonce = pow
        .solve_pow_for_parent(&other_parent, diff, 100_000)
        .expect("solve other parent nonce");

    let run_router = |req: Request<Body>| {
        let hits = Arc::new(AtomicUsize::new(0));
        let sub = RootLookupProbeSubscriber { hits: hits.clone() };
        let app_clone = app.clone();
        async move {
            let resp = app_clone.oneshot(req).with_subscriber(sub).await.unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap();
            let json: Value = serde_json::from_slice(&bytes).unwrap();
            (status, headers, json, hits.load(Ordering::SeqCst))
        }
    };

    // 1. Missing credentials -> 401 PoWRequired, unsigned, no root lookup
    let req_missing = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(unknown_spend_bytes.clone()))
        .unwrap();
    let (st, hdrs, json, root_hits) = run_router(req_missing).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(json.get("error").and_then(|v| v.as_str()), Some("PoWRequired"));
    assert_eq!(hdrs.get("x-required-difficulty").and_then(|v| v.to_str().ok()), Some("8"));
    assert!(json.get("server_signature").is_none());
    assert_eq!(root_hits, 0, "Missing credentials must not attempt root lookup");

    // 2. Invalid VIP secret -> 401 InvalidAuthToken, unsigned, no root lookup
    let req_bad_vip = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("authorization", "Bearer vip_unknown_secret_0000")
        .body(Body::from(unknown_spend_bytes.clone()))
        .unwrap();
    let (st, _, json, root_hits) = run_router(req_bad_vip).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(json.get("error").and_then(|v| v.as_str()), Some("InvalidAuthToken"));
    assert!(json.get("server_signature").is_none(), "Invalid VIP must be unsigned");
    assert_eq!(root_hits, 0, "Invalid VIP must reject before root lookup");

    // 3. Invalid Friends secret -> 401 InvalidPeerToken, unsigned, no root lookup
    let req_bad_f2f = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "f2f_ffffffffffffffffffffffffffffffff")
        .body(Body::from(unknown_spend_bytes.clone()))
        .unwrap();
    let (st, _, json, root_hits) = run_router(req_bad_f2f).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(json.get("error").and_then(|v| v.as_str()), Some("InvalidPeerToken"));
    assert!(json.get("server_signature").is_none(), "Invalid F2F must be unsigned");
    assert_eq!(root_hits, 0, "Invalid F2F must reject before root lookup");

    // 4. Malformed PoW challenge -> 401 InvalidPoW, unsigned, no root lookup
    let req_bad_chal = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-pow-challenge", "not_valid_hex_challenge")
        .header("x-pow-nonce", "0")
        .body(Body::from(unknown_spend_bytes.clone()))
        .unwrap();
    let (st, _, json, root_hits) = run_router(req_bad_chal).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(json.get("error").and_then(|v| v.as_str()), Some("InvalidPoW"));
    assert!(json.get("server_signature").is_none(), "Malformed challenge must be unsigned");
    assert_eq!(root_hits, 0, "Malformed challenge must reject before root lookup");

    // 5. Parent-mismatched PoW -> 401 InvalidPoW, unsigned, no root lookup
    let req_wrong_parent = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-pow-challenge", &other_challenge)
        .header("x-pow-nonce", other_nonce.to_string())
        .body(Body::from(unknown_spend_bytes.clone()))
        .unwrap();
    let (st, _, json, root_hits) = run_router(req_wrong_parent).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(json.get("error").and_then(|v| v.as_str()), Some("InvalidPoW"));
    assert!(json.get("server_signature").is_none(), "Parent mismatch must be unsigned");
    assert_eq!(root_hits, 0, "Parent mismatch must reject before root lookup");

    // 6. Valid parent-/slot-bound insufficient work -> 429 + X-Required-Difficulty, unsigned, no root lookup
    let req_weak_pow = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-pow-challenge", &valid_challenge)
        .header("x-pow-nonce", weak_nonce.to_string())
        .body(Body::from(unknown_spend_bytes.clone()))
        .unwrap();
    let (st, hdrs, json, root_hits) = run_router(req_weak_pow).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(hdrs.get("x-required-difficulty").and_then(|v| v.to_str().ok()), Some("8"));
    assert_eq!(json.get("error").and_then(|v| v.as_str()), Some("InvalidPoW"));
    assert!(json.get("server_signature").is_none(), "Insufficient work must be unsigned");
    assert_eq!(root_hits, 0, "Insufficient work must reject before root lookup");

    // 7. Valid credentials on unknown root reach root lookup & signed 400 without debiting credits/quota
    for (name, hdr_k, hdr_v, extra_k, extra_v) in [
        ("vip", "authorization", format!("Bearer {valid_vip_token}"), None, None),
        ("f2f", "x-peer-token", valid_f2f_token.clone(), None, None),
        (
            "pow",
            "x-pow-challenge",
            valid_challenge.clone(),
            Some("x-pow-nonce"),
            Some(valid_nonce.to_string()),
        ),
    ] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/lock")
            .header("content-type", "application/json")
            .header(hdr_k, hdr_v);
        if let (Some(k2), Some(v2)) = (extra_k, extra_v.as_ref()) {
            builder = builder.header(k2, v2);
        }
        let req = builder.body(Body::from(unknown_spend_bytes.clone())).unwrap();
        let (st, _, json, root_hits) = run_router(req).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "Valid {name} reaches unknown-root 400");
        assert!(json.get("server_signature").is_some(), "Unknown-root 400 for valid {name} is signed");
        assert_eq!(root_hits, 1, "Valid {name} reaches root fallback");
    }
    assert_eq!(
        tier_controller.get_cached_vip_quota(&vip_tag),
        Some(10_000),
        "Early validation / unknown-root rejection must not debit VIP balance"
    );
    assert_eq!(
        tier_controller.vip_rolling_usage_at_for_test(&vip_tag, now_ms),
        0,
        "Early validation / unknown-root rejection must not consume VIP rolling quota"
    );
    assert_eq!(
        tier_controller.free_rolling_usage_at_for_test(now_ms),
        0,
        "Early validation / unknown-root rejection must not consume free rolling quota"
    );

    // 8. Real HTTP fixture: invalid admission, valid genesis + spend, and exact idempotent retry
    let temp2 = tempdir().expect("tempdir2");
    let storage2 = Arc::new(RedbStorage::open(&temp2.path().join("s05_20_http.redb")).expect("open redb"));
    let (engine2, _worker2) = DualTierEngine::new(storage2.clone());
    let pow2 = Arc::new(PowEngine::new(8));
    let tc2 = Arc::new(TierController::new(storage2.clone(), pow2.clone()));
    tc2.topup_vip_quota(vip_tag, 10_000).unwrap();
    let vip2 = tc2.provision_vip_credential(vip_tag).unwrap();
    let f2f2 = format!("f2f_{}", hex::encode([0xEFu8; 16]));
    tc2.register_f2f_peer(&f2f2);

    let state2 = AppState::new(engine2, storage2, NodeIdentity::generate(), tc2.clone(), pow2.clone());
    for shard in 0..=u16::MAX {
        state2.readiness_manager.mark_shard_ready(shard);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, build_router(state2)).await;
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}/v1/lock");

    // 8a. Insufficient work over real HTTP -> 429 + x-required-difficulty + unsigned
    let http_weak = client
        .post(&url)
        .header("x-pow-challenge", &valid_challenge)
        .header("x-pow-nonce", weak_nonce.to_string())
        .json(&unknown_spend)
        .send()
        .await
        .unwrap();
    assert_eq!(http_weak.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        http_weak
            .headers()
            .get("x-required-difficulty")
            .and_then(|v| v.to_str().ok()),
        Some("8")
    );
    let weak_json: Value = http_weak.json().await.unwrap();
    assert!(weak_json.get("server_signature").is_none());

    // 8b. Anchor valid genesis with F2F token -> 201 Created
    let valid_until_ms = now_ms + 86_400_000;
    let mut genesis = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: "known_voucher_s05_20".into(),
        ds_tag: None,
        transaction_hash: [0x77u8; 32],
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now_ms,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    genesis.layer2_signature = sender_key.sign(&calculate_l2_payload_hash(&genesis)).to_bytes();
    let gen_resp = client
        .post(&url)
        .header("x-peer-token", &f2f2)
        .json(&genesis)
        .send()
        .await
        .unwrap();
    assert_eq!(gen_resp.status(), reqwest::StatusCode::CREATED);

    // 8c. Valid spend with VIP token -> 201 Created (charges once) and exact retry -> 200 OK (no double charge)
    let known_spend = make_spend("known_voucher_s05_20", "known_ds_tag_s05_20", 0x88);
    let spend_resp1 = client
        .post(&url)
        .header("authorization", format!("Bearer {vip2}"))
        .json(&known_spend)
        .send()
        .await
        .unwrap();
    assert_eq!(spend_resp1.status(), reqwest::StatusCode::CREATED);
    let bal_after_first = tc2.get_cached_vip_quota(&vip_tag).unwrap();
    assert!(bal_after_first < 10_000, "Valid spend must debit VIP balance once");

    let spend_resp2 = client
        .post(&url)
        .header("authorization", format!("Bearer {vip2}"))
        .json(&known_spend)
        .send()
        .await
        .unwrap();
    assert_eq!(spend_resp2.status(), reqwest::StatusCode::OK);
    assert_eq!(
        tc2.get_cached_vip_quota(&vip_tag).unwrap(),
        bal_after_first,
        "Exact retry must not double-charge VIP balance"
    );

    server_handle.abort();
}

