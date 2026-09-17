use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{extract::Json, routing::post, Router};
use tempfile::tempdir;

use humoco_node::alert::{AlertDispatcher, AlertKind};
use humoco_node::config::AlertConfig;

/// Helper to spawn a mock webhook server that counts POSTs and stores last payload.
async fn spawn_mock_server() -> (String, Arc<AtomicUsize>, Arc<tokio::sync::Mutex<Option<serde_json::Value>>>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let last_payload: Arc<tokio::sync::Mutex<Option<serde_json::Value>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let counter_clone = counter.clone();
    let payload_clone = last_payload.clone();

    let app = Router::new().route(
        "/webhook",
        post(move |Json(payload): Json<serde_json::Value>| {
            let c = counter_clone.clone();
            let p = payload_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                *p.lock().await = Some(payload);
                axum::http::StatusCode::OK
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{}/webhook", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock server");
    });

    // small delay to ensure server is listening
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (url, counter, last_payload)
}

#[tokio::test]
async fn test_alert_config_debug_masks_token() {
    let config = AlertConfig {
        webhook_url: Some("http://example.com/hook".into()),
        telegram_bot_token: Some("super_secret_bot_token_12345".into()),
        telegram_chat_id: Some("123456".into()),
        notify_on_outdated_version: true,
        peer_upgrade_threshold_percent: 50,
        min_peers_for_alert: 3,
        notify_on_sunset_warning: true,
    };
    let debug_str = format!("{:?}", config);
    assert!(
        debug_str.contains("[REDACTED]"),
        "Debug output must contain [REDACTED], got: {}",
        debug_str
    );
    assert!(
        !debug_str.contains("super_secret_bot_token_12345"),
        "Debug output must NOT leak raw token, got: {}",
        debug_str
    );
    // Ensure other fields are still visible
    assert!(debug_str.contains("http://example.com/hook"));
    assert!(debug_str.contains("123456"));
}

#[tokio::test]
async fn test_webhook_success_when_threshold_reached() {
    let (webhook_url, counter, last_payload) = spawn_mock_server().await;

    let temp = tempdir().expect("tempdir");
    let config = AlertConfig {
        webhook_url: Some(webhook_url.clone()),
        telegram_bot_token: None,
        telegram_chat_id: None,
        notify_on_outdated_version: true,
        peer_upgrade_threshold_percent: 50,
        min_peers_for_alert: 3,
        notify_on_sunset_warning: true,
    };

    let dispatcher = AlertDispatcher::new(config, temp.path().to_path_buf());

    // total 4, upgraded 3 => 75% >=50 and total >=3 => should trigger
    dispatcher.check_and_alert_outdated(4, 3).await;

    // give reqwest time to complete even if quickly
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "Webhook should have been called exactly once when threshold reached"
    );

    let payload = last_payload.lock().await.clone().expect("payload present");
    assert_eq!(payload.get("kind").and_then(|v| v.as_str()), Some("OutdatedVersion"));
    assert!(payload.get("message").is_some());
    assert!(payload.get("timestamp").is_some());
}

#[tokio::test]
async fn test_cooldown_suppresses_duplicate_alerts() {
    let (webhook_url, counter, _last) = spawn_mock_server().await;
    let temp = tempdir().expect("tempdir");

    let config = AlertConfig {
        webhook_url: Some(webhook_url),
        telegram_bot_token: None,
        telegram_chat_id: None,
        notify_on_outdated_version: true,
        peer_upgrade_threshold_percent: 50,
        min_peers_for_alert: 3,
        notify_on_sunset_warning: true,
    };

    let dispatcher = AlertDispatcher::new(config, temp.path().to_path_buf());

    // First alert should succeed
    dispatcher.send_alert(AlertKind::OutdatedVersion, "first alert").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // Second immediate alert with same kind must be suppressed by 24h cooldown
    dispatcher.send_alert(AlertKind::OutdatedVersion, "second alert").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "Second alert within 24h cooldown must be suppressed"
    );

    // Different kind should not be suppressed (SunsetApproaching has separate cooldown)
    dispatcher.send_alert(AlertKind::SunsetApproaching, "sunset alert").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "Different AlertKind should have independent cooldown"
    );
}

#[tokio::test]
async fn test_no_alert_when_too_few_peers() {
    let (webhook_url, counter, _last) = spawn_mock_server().await;
    let temp = tempdir().expect("tempdir");

    let config = AlertConfig {
        webhook_url: Some(webhook_url),
        telegram_bot_token: None,
        telegram_chat_id: None,
        notify_on_outdated_version: true,
        peer_upgrade_threshold_percent: 50,
        min_peers_for_alert: 3,
        notify_on_sunset_warning: true,
    };

    let dispatcher = AlertDispatcher::new(config, temp.path().to_path_buf());

    // total 2 < min_peers 3 => no alert even though 100% upgraded
    dispatcher.check_and_alert_outdated(2, 2).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "No webhook should be sent when total_peers < min_peers_for_alert"
    );

    // total 2, upgraded 1 => also no alert
    dispatcher.check_and_alert_outdated(2, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    // Now with sufficient peers but threshold not reached => no alert
    dispatcher.check_and_alert_outdated(10, 2).await; // 20% < 50%
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(counter.load(Ordering::SeqCst), 0, "Threshold 50% not reached with 20% should not alert");

    // Finally threshold reached with sufficient peers => alert
    dispatcher.check_and_alert_outdated(10, 6).await; // 60% >=50%
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(counter.load(Ordering::SeqCst), 1, "Should alert when threshold reached and min_peers satisfied");
}

#[tokio::test]
async fn test_cooldown_persistence_across_dispatcher_instances() {
    let (webhook_url, counter, _last) = spawn_mock_server().await;
    let temp = tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();

    let config = AlertConfig {
        webhook_url: Some(webhook_url.clone()),
        telegram_bot_token: None,
        telegram_chat_id: None,
        notify_on_outdated_version: true,
        peer_upgrade_threshold_percent: 50,
        min_peers_for_alert: 1,
        notify_on_sunset_warning: true,
    };

    let d1 = AlertDispatcher::new(config.clone(), data_dir.clone());
    d1.send_alert(AlertKind::OutdatedVersion, "alert from d1").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // New instance with same data_dir should respect persisted cooldown
    let d2 = AlertDispatcher::new(config, data_dir);
    d2.send_alert(AlertKind::OutdatedVersion, "alert from d2").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "Cooldown must persist across dispatcher instances via file"
    );
}
