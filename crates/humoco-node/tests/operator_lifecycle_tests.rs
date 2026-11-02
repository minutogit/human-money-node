//! Real process teardown evidence and private diagnostic retention boundaries.
use humoco_node::{
    cli::execute_restore, config::NodeConfig, control::ControlClient, identity::NodeIdentity,
    storage::RedbStorage,
};
use std::{
    io::{BufRead, BufReader, Read, Write},
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

#[test]
fn helper_child_process_db_locker() {
    if let Ok(path_str) = std::env::var("HUMOCO_TEST_CHILD_LOCK_DB") {
        let path = std::path::PathBuf::from(path_str);
        let db = redb::Database::open(&path).expect("open target redb in child");
        println!("READY");
        let _ = std::io::stdout().flush();
        let mut buf = [0u8; 1];
        let _ = std::io::stdin().read_exact(&mut buf);
        drop(db);
        std::process::exit(0);
    }
}

#[tokio::test]
async fn test_two_process_restore_exclusivity_and_alias_safety() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let target_db_path = data_dir.join("humoco.redb");
    let source_path = temp.path().join("source_backup.redb");

    // Initialize source database with some distinctive data
    {
        let src_storage = RedbStorage::open(&source_path).unwrap();
        src_storage.set_quota(&[0x11u8; 32], 12345).unwrap();
    }
    let initial_source_bytes = std::fs::read(&source_path).unwrap();

    // Initialize target database with different data
    {
        let tgt_storage = RedbStorage::open(&target_db_path).unwrap();
        tgt_storage.set_quota(&[0x22u8; 32], 99999).unwrap();
    }
    let initial_target_bytes = std::fs::read(&target_db_path).unwrap();
    assert_ne!(initial_source_bytes, initial_target_bytes);

    let config_path = temp.path().join("humoco.toml");
    let mut config = NodeConfig::default();
    config.storage.data_dir = data_dir.clone();
    config.save_to_file(&config_path).unwrap();

    // 1. Spawn real child process holding redb lock on target_db_path (no control socket)
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("helper_child_process_db_locker")
        .arg("--exact")
        .arg("--nocapture")
        .env("HUMOCO_TEST_CHILD_LOCK_DB", &target_db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut ready = false;
    for _ in 0..50 {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if line.trim() == "READY" {
            ready = true;
            break;
        }
    }
    assert!(ready, "Child process did not signal READY");

    let target_bytes_while_locked = std::fs::read(&target_db_path).unwrap();

    // While child holds the lock, attempt execute_restore
    let res = execute_restore(Some(source_path.clone()), None, Some(config_path.clone()), false).await;
    assert!(res.is_err(), "Restore must fail when target database is locked by another process");

    // Assert both files are byte-for-byte identical to their pre-restore bytes
    assert_eq!(std::fs::read(&source_path).unwrap(), initial_source_bytes);
    assert_eq!(std::fs::read(&target_db_path).unwrap(), target_bytes_while_locked);

    // Terminate child
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(b"q");
    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    // After child cleanup, verify bytes and storage integrity
    {
        let s = RedbStorage::open(&target_db_path).unwrap();
        assert_eq!(s.get_quota(&[0x22u8; 32]).unwrap(), 99999);
    }
    let target_bytes_after_child = std::fs::read(&target_db_path).unwrap();

    // 2. Corrupt source file leaving target byte-for-byte unchanged
    let corrupt_source_path = temp.path().join("corrupt_source.bin");
    std::fs::write(&corrupt_source_path, b"not_a_valid_redb_database_header_bytes").unwrap();
    let res_corrupt = execute_restore(Some(corrupt_source_path), None, Some(config_path.clone()), false).await;
    assert!(res_corrupt.is_err(), "Restore must fail with corrupt source");
    assert_eq!(std::fs::read(&target_db_path).unwrap(), target_bytes_after_child);

    // 3. Existing path alias (source == target)
    let res_alias = execute_restore(Some(target_db_path.clone()), None, Some(config_path.clone()), false).await;
    assert!(res_alias.is_err(), "Restore must fail when source and target refer to the same file");
    assert_eq!(std::fs::read(&target_db_path).unwrap(), target_bytes_after_child);

    // 4. Symlink target held by child process
    #[cfg(unix)]
    {
        let sym_target_real = temp.path().join("real_sym_target.redb");
        {
            let s = RedbStorage::open(&sym_target_real).unwrap();
            s.set_quota(&[0x33u8; 32], 77777).unwrap();
        }

        let symlink_dir = temp.path().join("symlink_dir");
        std::fs::create_dir_all(&symlink_dir).unwrap();
        let symlink_path = symlink_dir.join("humoco.redb");
        std::os::unix::fs::symlink(&sym_target_real, &symlink_path).unwrap();

        let sym_cfg_path = temp.path().join("sym_cfg.toml");
        let mut sym_cfg = NodeConfig::default();
        sym_cfg.storage.data_dir = symlink_dir;
        sym_cfg.save_to_file(&sym_cfg_path).unwrap();

        // Lock real target in child
        let mut child_sym = Command::new(std::env::current_exe().unwrap())
            .arg("helper_child_process_db_locker")
            .arg("--exact")
            .arg("--nocapture")
            .env("HUMOCO_TEST_CHILD_LOCK_DB", &sym_target_real)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();

        let stdout = child_sym.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut ready = false;
        for _ in 0..50 {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if line.trim() == "READY" {
                ready = true;
                break;
            }
        }
        assert!(ready, "Symlink child process did not signal READY");
        let sym_target_locked = std::fs::read(&sym_target_real).unwrap();

        let res_sym = execute_restore(Some(source_path.clone()), None, Some(sym_cfg_path.clone()), false).await;
        assert!(res_sym.is_err(), "Restore must detect lock on symlinked target");
        assert_eq!(std::fs::read(&sym_target_real).unwrap(), sym_target_locked);

        let mut stdin = child_sym.stdin.take().unwrap();
        let _ = stdin.write_all(b"q");
        drop(stdin);
        let _ = child_sym.wait().unwrap();
    }

    // 5. Positive restore case when unlocked
    let res_ok = execute_restore(Some(source_path.clone()), None, Some(config_path.clone()), false).await;
    assert!(res_ok.is_ok(), "Restore must succeed when target is unlocked and source is valid");
    // Verify target now has source data and .bak was created
    let bak_path = data_dir.join("humoco.redb.bak");
    assert!(bak_path.exists(), "Target backup .bak must exist");
    {
        let bak_storage = RedbStorage::open(&bak_path).unwrap();
        assert_eq!(bak_storage.get_quota(&[0x22u8; 32]).unwrap(), 99999);
    }
    let restored_storage = RedbStorage::open(&target_db_path).unwrap();
    assert_eq!(restored_storage.get_quota(&[0x11u8; 32]).unwrap(), 12345);
}
