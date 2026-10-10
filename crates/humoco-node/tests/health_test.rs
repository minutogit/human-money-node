//! # Health and SRE Observability Integration Tests (Phase 2)
//!
//! Validates stateful health duration tracking, duration formatting,
//! POSIX disk free space parsing, and redb growth projections.

use std::sync::Arc;
use std::time::{Duration, Instant};

use humoco_node::api::health::{
    format_health_duration, HealthItem, HealthLevel, HealthStateTracker,
};
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
    let mut items_cycle_2 = vec![
        HealthItem::new("NO_PEERS", HealthLevel::Crit, "No peers", "Check network"),
    ];
    tracker.track(&mut items_cycle_2);
    assert_eq!(items_cycle_2[0].code, "NO_PEERS");

    // Simulate all resolved
    let mut items_cycle_3 = Vec::new();
    tracker.track(&mut items_cycle_3);
    assert!(items_cycle_3.is_empty());

    // Re-occurrence of NO_PEERS starts fresh at 0s
    let mut items_cycle_4 = vec![
        HealthItem::new("NO_PEERS", HealthLevel::Crit, "No peers", "Check network"),
    ];
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
    assert!((growth - 40.0).abs() < 0.5, "Expected ~40 MB/day, got {growth}");
    assert!(stats_growing.days_until_full.is_some());
    let days = stats_growing.days_until_full.unwrap();
    assert_eq!(stats_growing.disk_headroom_label, format!("{days} Tage"));
}
