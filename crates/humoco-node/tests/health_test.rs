//! # Health and SRE Observability Integration Tests (Phase 2)
//!
//! Validates stateful health duration tracking, duration formatting,
//! POSIX disk free space parsing, and redb growth projections.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tower::ServiceExt;

use humoco_node::api::auth::AdminTokenManager;
use humoco_node::api::health::{
    format_health_duration, HealthItem, HealthLevel, HealthStateTracker,
};
use humoco_node::api::routes::build_operator_router;
use humoco_node::api::system_stats::SystemStatsCollector;
use humoco_node::api::AppState;
use humoco_node::identity::NodeIdentity;
use humoco_node::ingress::{PowEngine, TierController};
use humoco_node::storage::{DualTierEngine, RedbStorage};

#[test]
fn test_duration_formatting_all_ranges() {
    assert_eq!(format_health_duration(0), "0s");
    assert_eq!(format_health_duration(42), "42s");
    assert_eq!(format_health_duration(59), "59s");
    assert_eq!(format_health_duration(60), "1m 0s");
    assert_eq!(format_health_duration(61), "1m 1s");
    assert_eq!(format_health_duration(900), "15m 0s");
    assert_eq!(format_health_duration(3599), "59m 59s");
    assert_eq!(format_health_duration(3600), "1h 0m");
    assert_eq!(format_health_duration(3665), "1h 1m");
    assert_eq!(format_health_duration(7200), "2h 0m");
    assert_eq!(format_health_duration(86400), "24h 0m");
}

#[test]
fn test_health_state_tracker_lifecycle_and_pruning() {
    let tracker = HealthStateTracker::new();

    let mut items = vec![
        HealthItem::new("NO_PEERS", HealthLevel::Crit, "No peers", "Check network"),
        HealthItem::new("QUEUE_HIGH", HealthLevel::Warn, "Queue high", "Check disk"),
    ];

    // Initial cycle: both start at 0s
    tracker.track(&mut items);
    assert_eq!(items[0].active_since_sec, 0);
    assert_eq!(items[0].duration_formatted, "0s");
    assert_eq!(items[1].active_since_sec, 0);
    assert_eq!(items[1].duration_formatted, "0s");

    // Simulate QUEUE_HIGH resolving, while NO_PEERS persists
    let mut items_cycle_2 = vec![HealthItem::new(
        "NO_PEERS",
        HealthLevel::Crit,
        "No peers",
        "Check network",
    )];
    tracker.track(&mut items_cycle_2);
    assert_eq!(items_cycle_2[0].code, "NO_PEERS");

    // Simulate all resolved
    let mut items_cycle_3 = Vec::new();
    tracker.track(&mut items_cycle_3);
    assert!(items_cycle_3.is_empty());

    // Re-occurrence of NO_PEERS starts fresh at 0s
    let mut items_cycle_4 = vec![HealthItem::new(
        "NO_PEERS",
        HealthLevel::Crit,
        "No peers",
        "Check network",
    )];
    tracker.track(&mut items_cycle_4);
    assert_eq!(items_cycle_4[0].active_since_sec, 0);
    assert_eq!(items_cycle_4[0].duration_formatted, "0s");
}

#[tokio::test]
async fn test_evaluate_health_tracked_with_dashboard_data() {
    let tracker = HealthStateTracker::new();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("test_health.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let state = AppState::new(engine, storage, identity, tier_controller, pow_engine)
        .with_health_tracker(Arc::new(tracker));

    let data = humoco_node::api::dashboard::collect_dashboard_data(&state).await;
    // Health is evaluated with tracking
    assert_eq!(data.health.level, HealthLevel::Ok);

    // Serialization check: Ensure all new SRE fields serialize cleanly into JSON
    let json = serde_json::to_value(&data).expect("serialize DashboardData");
    assert!(json.get("health").is_some());
    assert!(json["persistence"].get("flush_queue_capacity").is_some());
    assert_eq!(json["persistence"]["flush_queue_capacity"], 10_000);
    assert!(json["system"].get("redb_growth_mb_per_day").is_some());
    assert!(json["system"].get("days_until_full").is_some());
    assert!(json["system"].get("disk_headroom_label").is_some());
    assert_eq!(json["system"]["disk_headroom_label"], "> 365 Tage (stabil)");
}

#[test]
fn test_system_stats_redb_growth_and_headroom_projection() {
    let collector = SystemStatsCollector::new(".");
    collector.clear_redb_history_for_testing();

    // Baseline stats without growth
    let stats_empty = collector.get_system_stats(100, 1.0, 0);
    assert_eq!(stats_empty.redb_growth_mb_per_day, 0.0);
    assert_eq!(stats_empty.days_until_full, None);
    assert_eq!(stats_empty.disk_headroom_label, "> 365 Tage (stabil)");

    // Simulate 20 MB growth over 12 hours (43200s) -> 40 MB/day
    let t0 = Instant::now() - Duration::from_secs(43200);
    let t1 = Instant::now();
    collector.push_redb_history_for_testing(t0, 10 * 1024 * 1024);
    collector.push_redb_history_for_testing(t1, 30 * 1024 * 1024);

    let stats_growing = collector.get_system_stats(100, 1.0, 0);
    let growth = stats_growing.redb_growth_mb_per_day;
    assert!(
        (growth - 40.0).abs() < 0.5,
        "Expected ~40 MB/day, got {growth}"
    );
    assert!(stats_growing.days_until_full.is_some());
    let days = stats_growing.days_until_full.unwrap();
    assert_eq!(stats_growing.disk_headroom_label, format!("{days} Tage"));
}

fn setup_test_operator_state() -> (AppState, Arc<AdminTokenManager>, tempfile::TempDir) {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("health_operator.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    let auth = Arc::new(AdminTokenManager::load_or_create(temp.path(), false).unwrap());

    let state = AppState::new(engine, storage, identity, tier_controller, pow_engine)
        .with_auth(auth.clone());

    (state, auth, temp)
}

#[tokio::test]
async fn test_operator_history_window_bounds_and_overflow() {
    let (state, _, _temp) = setup_test_operator_state();
    let router = build_operator_router(state);

    let windows = [
        "0h",
        "24h",
        "1d",
        &format!("{}h", (usize::MAX / 60).saturating_add(1)),
        &format!("{}h", usize::MAX),
        &format!("{}d", usize::MAX),
    ];

    for win in windows {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/dashboard/history?window={}", win))
            .body(Body::empty())
            .unwrap();

        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Failed on window={}", win);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(json["points"].is_array(), "History response points must be an array for window={}", win);
        // Ensure bounded size
        assert!(json["points"].as_array().unwrap().len() <= 1440);
    }
}

#[tokio::test]
async fn test_operator_vip_credential_redaction_and_lookup_safety() {
    let (state, auth, _temp) = setup_test_operator_state();
    let router = build_operator_router(state.clone());

    let secret_token = "vip_bearer_ultra_secret_passphrase_456789";

    // Provision VIP account via POST /dashboard/admin/quota
    let topup_body = serde_json::json!({
        "account_tag": secret_token,
        "byte_years": 5000
    });
    let req = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/quota")
        .header("Authorization", format!("Bearer {}", auth.token()))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&topup_body).unwrap()))
        .unwrap();

    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 1. Check GET /dashboard/data
    let req = Request::builder()
        .method("GET")
        .uri("/dashboard/data")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(!body_str.contains(secret_token), "Raw secret bearer token must not leak into /dashboard/data");

    let data_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let vip_accounts = data_json["tiers"]["vip_accounts"].as_array().unwrap();
    assert!(!vip_accounts.is_empty(), "Must have registered VIP accounts");

    for acc in vip_accounts {
        let tag = acc["account_tag"].as_str().unwrap();
        assert!(tag.starts_with("vip_"), "VIP account tag must be an opaque diagnostic ID starting with 'vip_'");
        // resolve_account_tag must REJECT diagnostic ID
        assert!(state.tier_controller.resolve_account_tag(tag).is_err(), "resolve_account_tag must reject diagnostic ID '{}'", tag);
    }

    // Raw secret authenticates
    assert!(state.tier_controller.resolve_account_tag(secret_token).is_ok(), "Raw secret must authenticate");

    // 2. Check GET /dashboard (HTML)
    let req = Request::builder()
        .method("GET")
        .uri("/dashboard")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let html_str = String::from_utf8_lossy(&body_bytes);
    assert!(!html_str.contains(secret_token), "Raw secret bearer token must not leak into HTML dashboard");

    // 3. Check GET /dashboard/events
    let req = Request::builder()
        .method("GET")
        .uri("/dashboard/events")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let events_str = String::from_utf8_lossy(&body_bytes);
    assert!(!events_str.contains(secret_token), "Raw secret bearer token must not leak into /dashboard/events");
}

#[tokio::test]
async fn test_operator_vip_quota_saturation_no_overflow_panic() {
    let (state, auth, _temp) = setup_test_operator_state();
    let router = build_operator_router(state);

    // Top up VIP account 1 with near u64::MAX
    let req1 = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/quota")
        .header("Authorization", format!("Bearer {}", auth.token()))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "account_tag": "vip_user_one_token",
            "byte_years": u64::MAX - 100
        })).unwrap()))
        .unwrap();
    let res1 = router.clone().oneshot(req1).await.unwrap();
    assert_eq!(res1.status(), StatusCode::OK);

    // Top up VIP account 2 with amount that would overflow u64::MAX
    let req2 = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/quota")
        .header("Authorization", format!("Bearer {}", auth.token()))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "account_tag": "vip_user_two_token",
            "byte_years": 500
        })).unwrap()))
        .unwrap();
    let res2 = router.clone().oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::OK);

    // GET /dashboard/data: must not panic, and total balance must saturate at u64::MAX
    let req = Request::builder()
        .method("GET")
        .uri("/dashboard/data")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let data_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(data_json["tiers"]["vip_total_balance"], u64::MAX);

    // GET /dashboard (HTML): must render cleanly without overflow panic
    let req_html = Request::builder()
        .method("GET")
        .uri("/dashboard")
        .body(Body::empty())
        .unwrap();
    let res_html = router.oneshot(req_html).await.unwrap();
    assert_eq!(res_html.status(), StatusCode::OK);
}
