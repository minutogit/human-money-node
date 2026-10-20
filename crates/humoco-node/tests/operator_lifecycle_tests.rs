//! Real process teardown evidence and private diagnostic retention boundaries.
use humoco_node::{
    config::NodeConfig, control::ControlClient, identity::NodeIdentity, storage::RedbStorage,
};
use std::{
    process::{Command, Stdio},
    time::Duration,
};

#[tokio::test]
async fn stop_waits_for_process_exit_and_database_can_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.storage.data_dir = temp.path().join("data");
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.identity.key_path = temp.path().join("node.key");
    NodeIdentity::generate()
        .save_to_file(&config.identity.key_path)
        .unwrap();
    let config_path = temp.path().join("node.toml");
    config.save_to_file(&config_path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_humoco"))
        .arg("run")
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let socket = config.control_socket_path();
    let client = ControlClient::new(socket.clone());
    let ready = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if client.get_status().await.is_ok() {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("daemon exited before control ready: {status}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if ready.is_err() {
        let _ = child.kill();
        panic!("control startup timed out");
    }
    let stopped = client.shutdown(10).await;
    if stopped.is_err() {
        let _ = child.kill();
    }
    stopped.unwrap();
    assert!(child.wait().unwrap().success());
    assert!(!socket.exists());
    let db = RedbStorage::open(&config.storage.data_dir.join("humoco.redb")).unwrap();
    drop(db);
}

#[test]
fn operator_configuration_cannot_bind_publicly_or_advertise_credentials() {
    let mut config = NodeConfig::default();
    config.network.operator_listen_addr = Some("0.0.0.0:9091".parse().unwrap());
    assert!(config.validate_network_boundaries().is_err());
    config.network.operator_listen_addr = Some("127.0.0.1:9091".parse().unwrap());
    config.discovery.public_gateway_urls = vec!["https://user:secret@example.com".into()];
    assert!(config.validate_network_boundaries().is_err());
    config.discovery.public_gateway_urls = vec!["https://gateway.example.com/api".into()];
    assert!(config.validate_network_boundaries().is_ok());
}

#[test]
fn hourly_retention_preserves_deltas_and_marks_restart_gaps() {
    use humoco_node::api::{history::HistoryPoint, history_retention::HourlyHistory};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("hourly.json");
    let history = HourlyHistory::default();
    history.load(&path).unwrap();
    let point = HistoryPoint {
        timestamp_sec: 3600,
        write_count: 100,
        read_count: 50,
        free_writes: 80,
        f2f_writes: 10,
        vip_writes: 10,
        connected_peers: 3,
        active_locks: 9,
        queue_depth: 0,
        pow_diff: 8,
    };
    history.record(point.clone());
    let mut next = point.clone();
    next.timestamp_sec += 60;
    next.write_count += 4;
    next.connected_peers = 6;
    history.record(next.clone());
    history.persist().unwrap();
    let restored = HourlyHistory::default();
    restored.load(&path).unwrap();
    assert_eq!(restored.query()[0].observed_write_delta, 4);
    assert_eq!(restored.query()[0].last_sample.connected_peers, 6);
    next.timestamp_sec += 60;
    next.write_count = 0;
    restored.record(next);
    assert!(restored.query()[0].incomplete);
    assert_eq!(restored.query()[0].observed_write_delta, 4);
    std::fs::write(&path, b"not-json").unwrap();
    assert!(HourlyHistory::default().load(&path).is_err());
}

#[test]
fn hourly_history_never_interpolates_missing_years_or_unbounded_slots() {
    use humoco_node::api::{
        history::HistoryPoint,
        history_retention::{HourlyHistory, HOURLY_CAPACITY},
    };
    let history = HourlyHistory::default();
    for hour in 0..(HOURLY_CAPACITY as u64 + 20) {
        history.record(HistoryPoint {
            timestamp_sec: hour * 3600,
            write_count: hour,
            read_count: hour,
            free_writes: hour,
            f2f_writes: 0,
            vip_writes: 0,
            connected_peers: 0,
            active_locks: 0,
            queue_depth: 0,
            pow_diff: 8,
        });
    }
    let points = history.query();
    assert_eq!(points.len(), HOURLY_CAPACITY);
    assert!(points
        .iter()
        .all(|p| p.incomplete && p.observed_write_delta == 0));
    assert_eq!(points[0].hour, 20);
}
