use std::sync::Arc;
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
        hmc::{L2LockRequest, L2ResponseEnvelope, L2Verdict},
        AppState, ErrorResponse,
    },
    config::LifecycleConfig,
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    storage::{DualTierEngine, RedbStorage},
};

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn now_secs() -> u64 {
    test_now_ms() / 1000
}

fn setup_with_lifecycle(lifecycle: LifecycleConfig) -> axum::Router {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_dual.redb");
    std::mem::forget(temp);
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    tier_controller.register_f2f_peer("friend_secret_token");

    let state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    )
    .with_lifecycle(lifecycle);

    build_router(state)
}

fn setup_default_router() -> axum::Router {
    setup_with_lifecycle(LifecycleConfig::default())
}

async fn response_json<T: serde::de::DeserializeOwned>(res: axum::response::Response) -> T {
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body_bytes).expect("Failed to deserialize response body")
}

fn make_lock_request(
    parent_hex: &str,
    crypto_suite: Option<u8>,
    is_bridge: Option<bool>,
    pqc_receiver: Option<String>,
) -> L2LockRequest {
    use humoco_node::api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockRequest};
    use ed25519_dalek::Signer;
    let sender_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(parent_hex.as_bytes()).as_bytes();
    let now = test_now_ms();
    let valid_until_ms = now + 600_000;
    let del_str = valid_until_ms.to_string();
    let privacy_guard = if is_bridge == Some(true) && pqc_receiver.is_none() {
        Some("bridge_missing_pqc".into())
    } else if crypto_suite == Some(2) {
        Some("suite2".into())
    } else {
        None
    };

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
        privacy_guard,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

// a) Einreichung eines normalen Locks (Suite 1) vor Sunset -> 201 Created.
#[tokio::test]
async fn test_normal_suite1_before_sunset_201() {
    let lifecycle = LifecycleConfig {
        supported_suites: vec![1, 2],
        warn_deprecated_suite_after: Some(now_secs() + 10_000),
        reject_deprecated_suite_after: Some(now_secs() + 20_000),
    };
    let app = setup_with_lifecycle(lifecycle);
    let req_payload = make_lock_request(&"aa".repeat(32), None, None, None);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body: L2ResponseEnvelope = response_json(res).await;
    assert!(matches!(body.verdict, L2Verdict::Verified { .. }));
}

// b) Einreichung eines Locks mit Warn-Header nach warn_deprecated_suite_after -> 201 Created und Header X-Deprecation-Warning vorhanden.
#[tokio::test]
async fn test_warn_header_after_warn_time() {
    let lifecycle = LifecycleConfig {
        supported_suites: vec![1, 2],
        warn_deprecated_suite_after: Some(now_secs().saturating_sub(10)),
        reject_deprecated_suite_after: Some(now_secs() + 20_000),
    };
    let app = setup_with_lifecycle(lifecycle);
    let parent = "bb".repeat(32);
    let req_payload = make_lock_request(&parent, Some(1), None, None);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(
        res.headers().contains_key("x-deprecation-warning"),
        "Expected X-Deprecation-Warning header, got headers: {:?}",
        res.headers()
    );
    let body: L2ResponseEnvelope = response_json(res).await;
    assert!(matches!(body.verdict, L2Verdict::Verified { .. }));
}

#[tokio::test]
async fn test_no_warn_before_time_or_for_suite2() {
    let lifecycle_before = LifecycleConfig {
        supported_suites: vec![1, 2],
        warn_deprecated_suite_after: Some(now_secs() + 10_000),
        reject_deprecated_suite_after: None,
    };
    let app = setup_with_lifecycle(lifecycle_before);
    let parent = "cc".repeat(32);
    let req_payload = make_lock_request(&parent, Some(1), None, None);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(
        !res.headers().contains_key("x-deprecation-warning"),
        "Should NOT have deprecation warning before warn time"
    );

    let lifecycle_after = LifecycleConfig {
        supported_suites: vec![1, 2],
        warn_deprecated_suite_after: Some(now_secs().saturating_sub(5)),
        reject_deprecated_suite_after: None,
    };
    let app2 = setup_with_lifecycle(lifecycle_after);
    let parent2 = "dd".repeat(32);
    let req_payload2 = make_lock_request(&parent2, Some(2), None, None);
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload2).unwrap()))
        .unwrap();
    let res2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::CREATED);
    assert!(
        !res2.headers().contains_key("x-deprecation-warning"),
        "Suite 2 must NOT receive deprecation warning"
    );
}

// c) Einreichung eines Locks (Suite 1) nach reject_deprecated_suite_after -> 400 Bad Request mit CryptoSuiteDeprecated.
#[tokio::test]
async fn test_reject_suite1_after_sunset_400() {
    let lifecycle = LifecycleConfig {
        supported_suites: vec![1, 2],
        warn_deprecated_suite_after: None,
        reject_deprecated_suite_after: Some(now_secs().saturating_sub(5)),
    };
    let app = setup_with_lifecycle(lifecycle);
    let parent = "ee".repeat(32);
    let req_payload = make_lock_request(&parent, Some(1), None, None);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let err: ErrorResponse = response_json(res).await;
    assert_eq!(err.error, "CryptoSuiteDeprecated");
    assert!(err.message.contains("Suite 1 (Ed25519) has reached final sunset"));

    let parent2 = "ef".repeat(32);
    let req_payload2 = make_lock_request(&parent2, None, None, None);
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload2).unwrap()))
        .unwrap();
    let res2 = app.oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::BAD_REQUEST);
    let err2: ErrorResponse = response_json(res2).await;
    assert_eq!(err2.error, "CryptoSuiteDeprecated");
}

// d) Einreichung eines Suite 2 (Hybrid/PQC) Locks nach reject_deprecated_suite_after -> 201 Created (nicht abgelehnt!).
#[tokio::test]
async fn test_suite2_after_reject_not_rejected() {
    let lifecycle = LifecycleConfig {
        supported_suites: vec![1, 2],
        warn_deprecated_suite_after: None,
        reject_deprecated_suite_after: Some(now_secs().saturating_sub(5)),
    };
    let app = setup_with_lifecycle(lifecycle);
    let parent = "ff".repeat(32);
    let req_payload = make_lock_request(&parent, Some(2), None, None);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body: L2ResponseEnvelope = response_json(res).await;
    assert!(matches!(body.verdict, L2Verdict::Verified { .. }));
}

// e) Einreichung eines Quantum-Bridge-Locks mit pqc_receiver -> 201 Created; ohne pqc_receiver -> 400 Bad Request.
#[tokio::test]
async fn test_quantum_bridge_lock_validation() {
    let app = setup_default_router();

    // Without pqc_receiver -> 400 InvalidBridgeLock
    let parent_fail = "11".repeat(32);
    let req_fail = make_lock_request(&parent_fail, Some(2), Some(true), None);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_fail).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let err: ErrorResponse = response_json(res).await;
    assert_eq!(err.error, "InvalidBridgeLock");

    // With pqc_receiver -> 201
    let parent_ok = "22".repeat(32);
    let req_ok = make_lock_request(
        &parent_ok,
        Some(2),
        Some(true),
        Some("pqc_receiver_hex_1234567890".into()),
    );
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_ok).unwrap()))
        .unwrap();
    let res2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::CREATED);
    let body: L2ResponseEnvelope = response_json(res2).await;
    assert!(matches!(body.verdict, L2Verdict::Verified { .. }));

    // Non-bridge lock without pqc_receiver should succeed
    let parent_normal = "33".repeat(32);
    let req_normal = make_lock_request(&parent_normal, Some(1), Some(false), None);
    let req3 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "friend_secret_token")
        .body(Body::from(serde_json::to_vec(&req_normal).unwrap()))
        .unwrap();
    let res3 = app.oneshot(req3).await.unwrap();
    assert_eq!(res3.status(), StatusCode::CREATED);
}
