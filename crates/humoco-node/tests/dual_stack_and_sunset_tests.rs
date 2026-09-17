use std::sync::Arc;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tower::ServiceExt;

use humoco_node::{
    api::{build_router, AppState, ErrorResponse, LockSubmitRequest, LockSubmitResponse},
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
    // leak tempdir path via storage: we need temp to live? We'll keep tempdir inside setup by not dropping
    // Instead, use a unique path in /tmp
    let db_path = temp.path().join("test_dual.redb");
    // leak temp dir so it is not deleted until test ends? We'll forget temp
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

fn make_lock_request(parent_hex: &str, crypto_suite: Option<u8>, is_bridge: Option<bool>, pqc_receiver: Option<String>) -> LockSubmitRequest {
    let now = test_now_ms();
    LockSubmitRequest {
        parent_lock: parent_hex.to_string(),
        receiver_pub: "02".repeat(32),
        nonce: format!("nonce_{}", parent_hex),
        valid_until: now + 60_000,
        root_valid_until: now + 600_000,
        created_at: Some(now),
        auth_token: None,
        peer_token: Some("friend_secret_token".into()),
        pow_challenge: None,
        pow_nonce: None,
        crypto_suite,
        is_bridge_lock: is_bridge,
        pqc_receiver,
    }
}

// a) Einreichung eines normalen Locks (Suite 1) vor Sunset -> 201 Created.
#[tokio::test]
async fn test_normal_suite1_before_sunset_201() {
    // warn and reject far in the future
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
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body: LockSubmitResponse = response_json(res).await;
    assert_eq!(body.status, "ACCEPTED");
    assert!(body.attestation.is_some());
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
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    // Header must be present (case-insensitive: axum stores lowercased)
    assert!(
        res.headers().contains_key("x-deprecation-warning"),
        "Expected X-Deprecation-Warning header, got headers: {:?}", res.headers()
    );
    let body: LockSubmitResponse = response_json(res).await;
    assert_eq!(body.status, "ACCEPTED");

    // Also test warn header on idempotent replay
    // Need to re-use same app state? Create new app with same lifecycle and same lock should also give header on 200.
    // Instead test that suite2 does NOT get header even after warn time.
}

#[tokio::test]
async fn test_no_warn_before_time_or_for_suite2() {
    // Before warn time: no header
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
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(
        !res.headers().contains_key("x-deprecation-warning"),
        "Should NOT have deprecation warning before warn time"
    );

    // After warn time but suite 2: no header
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
    // Test explicit suite 1
    let parent = "ee".repeat(32);
    let req_payload = make_lock_request(&parent, Some(1), None, None);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let err: ErrorResponse = response_json(res).await;
    assert_eq!(err.error, "CryptoSuiteDeprecated");
    assert!(err.message.contains("Suite 1 (Ed25519) has reached final sunset"));

    // Also test default suite (None => 1) must be rejected
    let parent2 = "ef".repeat(32);
    let req_payload2 = make_lock_request(&parent2, None, None, None);
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
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
        .body(Body::from(serde_json::to_vec(&req_payload).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body: LockSubmitResponse = response_json(res).await;
    assert_eq!(body.status, "ACCEPTED");
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
        .body(Body::from(serde_json::to_vec(&req_fail).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let err: ErrorResponse = response_json(res).await;
    assert_eq!(err.error, "InvalidBridgeLock");

    // With pqc_receiver -> 201
    let parent_ok = "22".repeat(32);
    let req_ok = make_lock_request(&parent_ok, Some(2), Some(true), Some("pqc_receiver_hex_1234567890".into()));
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_ok).unwrap()))
        .unwrap();
    let res2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::CREATED);
    let body: LockSubmitResponse = response_json(res2).await;
    assert_eq!(body.status, "ACCEPTED");

    // Non-bridge lock without pqc_receiver should succeed (no validation)
    let parent_normal = "33".repeat(32);
    let req_normal = make_lock_request(&parent_normal, Some(1), Some(false), None);
    let req3 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_normal).unwrap()))
        .unwrap();
    let res3 = app.oneshot(req3).await.unwrap();
    assert_eq!(res3.status(), StatusCode::CREATED);
}
