use humoco_node::storage::{DualTierEngine, RedbStorage};
use humoco_sim_core::storage::IngressVerdictLow;
use humoco_sim_core::types::{Hash256, LockRecord, SimTime};
use std::sync::Arc;
use tempfile::tempdir;

fn create_sample_lock(parent_byte: u8, valid_until_ms: u64) -> LockRecord {
    let parent = [parent_byte; 32];
    let receiver = [0xEE; 32];
    let nonce = vec![parent_byte, 0x01, 0x02];
    LockRecord::new(parent, receiver, nonce, SimTime(0), SimTime(valid_until_ms))
}

#[test]
fn test_redb_storage_crud() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_crud.redb");
    let storage = RedbStorage::open(&db_path).expect("failed to open redb");

    // 1. Lock CRUD
    let lock1 = create_sample_lock(0x01, 60_000);
    let root_valid_until_1 = 600_000;
    storage
        .put_lock(&lock1, root_valid_until_1)
        .expect("put_lock failed");

    let retrieved = storage
        .get_lock(&lock1.parent_lock)
        .expect("get_lock failed");
    assert!(retrieved.is_some(), "lock should be retrieved");
    let (rec, rv) = retrieved.unwrap();
    assert_eq!(rec.id, lock1.id);
    assert_eq!(rec.parent_lock, lock1.parent_lock);
    assert_eq!(rec.receiver_pub, lock1.receiver_pub);
    assert_eq!(rec.nonce, lock1.nonce);
    assert_eq!(rec.valid_until, lock1.valid_until);
    assert_eq!(rv, root_valid_until_1);

    // Non-existent lock
    let non_existent = storage.get_lock(&[0xFF; 32]).expect("get_lock failed");
    assert!(non_existent.is_none());

    // 2. Quota CRUD & Atomic Charge
    let account: Hash256 = [0xAA; 32];
    assert_eq!(storage.get_quota(&account).unwrap(), 0);

    storage.set_quota(&account, 960_000).unwrap();
    assert_eq!(storage.get_quota(&account).unwrap(), 960_000);

    storage.set_quota(&account, 1_200_000).unwrap();
    assert_eq!(storage.get_quota(&account).unwrap(), 1_200_000);

    // Atomic check and charge
    let remaining = storage.check_and_charge_quota(&account, 200_000).unwrap();
    assert_eq!(remaining, 1_000_000);
    assert_eq!(storage.get_quota(&account).unwrap(), 1_000_000);

    // Charge more than available -> fails and leaves quota intact
    let charge_err = storage
        .check_and_charge_quota(&account, 1_500_000)
        .unwrap_err();
    match charge_err {
        humoco_node::storage::StorageError::QuotaExceeded {
            available,
            required,
        } => {
            assert_eq!(available, 1_000_000);
            assert_eq!(required, 1_500_000);
        }
        _ => panic!("Expected QuotaExceeded error"),
    }
    assert_eq!(storage.get_quota(&account).unwrap(), 1_000_000);

    // 3. Evidence CRUD
    let ev_hash: Hash256 = [0xBB; 32];
    assert!(storage.get_evidence(&ev_hash).unwrap().is_none());

    let raw_payload = b"fraud_slashing_proof_data_v1";
    storage.put_evidence(&ev_hash, raw_payload).unwrap();

    let ev_retrieved = storage.get_evidence(&ev_hash).unwrap();
    assert_eq!(ev_retrieved.as_deref(), Some(&raw_payload[..]));

    // 4. Batch Put & all_valid_locks
    let lock2 = create_sample_lock(0x02, 120_000);
    let lock3 = create_sample_lock(0x03, 180_000);
    storage
        .put_locks_batch(vec![(&lock2, 300_000), (&lock3, 400_000)])
        .unwrap();

    let all_valid = storage.all_valid_locks(50_000).unwrap();
    assert_eq!(all_valid.len(), 3);

    // Filtered by valid_until at 150s: lock1(60s) and lock2(120s) are expired, lock3(180s) valid
    let valid_later = storage.all_valid_locks(150_000).unwrap();
    assert_eq!(valid_later.len(), 1);
    assert_eq!(valid_later[0].0.id, lock3.id);

    // 5. TTL Pruning
    // lock1: root_valid_until = 600s -> bucket_sec = (600_000 + 30_000)/1000 = 630
    // lock2: root_valid_until = 300s -> bucket_sec = (300_000 + 30_000)/1000 = 330
    // prune at now_sec = 350 -> should prune lock2, keep lock1 & lock3
    let (pruned, _) = storage.prune_expired_buckets(350).unwrap();
    assert_eq!(pruned.len(), 1);
    assert_eq!(pruned[0], lock2.parent_lock);
    assert!(storage.get_lock(&lock2.parent_lock).unwrap().is_none());
    assert!(storage.get_lock(&lock1.parent_lock).unwrap().is_some());
    assert!(storage.get_lock(&lock3.parent_lock).unwrap().is_some());
}

#[tokio::test]
async fn test_dual_tier_engine_hotpath_and_async_flush() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_engine.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("failed to open redb"));

    let (engine, worker_handle) = DualTierEngine::new(Arc::clone(&storage));

    let now = SimTime(0);
    let root_valid = SimTime(600_000);
    let lock1 = create_sample_lock(0x10, 60_000);

    // 1. Hotpath Ingress (< 1µs RAM insert)
    let verdict = engine
        .ingress_lock(lock1.clone(), now, root_valid)
        .await
        .expect("ingress should succeed");
    assert_eq!(verdict, IngressVerdictLow::AcceptedNew);

    // Immediately present in RAM index
    {
        let ram = engine.ram.read().await;
        assert_eq!(ram.len(), 1);
        assert!(ram.get(&lock1.parent_lock).is_some());
    }

    // 2. Idempotent Replay
    let replay_verdict = engine
        .ingress_lock(lock1.clone(), now, root_valid)
        .await
        .expect("replay should succeed");
    assert_eq!(replay_verdict, IngressVerdictLow::IdempotentReplay);

    // 3. Collision (different lock on same parent) where existing lock1 wins min(H_canon)
    let h1 = humoco_sim_core::crypto::compute_canonical_hash(
        &lock1.parent_lock,
        &lock1.receiver_pub,
        &lock1.nonce,
    );
    let mut nonce_b = 0u8;
    let colliding_lock = loop {
        let cand = LockRecord::new(
            lock1.parent_lock,
            [0x99; 32],
            vec![nonce_b],
            SimTime(0),
            SimTime(60_000),
        );
        let h_cand = humoco_sim_core::crypto::compute_canonical_hash(
            &cand.parent_lock,
            &cand.receiver_pub,
            &cand.nonce,
        );
        if h_cand > h1 {
            break cand;
        }
        nonce_b = nonce_b.wrapping_add(1);
    };
    let collision_verdict = engine.ingress_lock(colliding_lock, now, root_valid).await;
    assert_eq!(collision_verdict, Err(IngressVerdictLow::RejectedCollision));

    // 4. Time Window Rejection (valid_until <= now + 30s)
    let invalid_window_lock = create_sample_lock(0x20, 20_000); // 20s <= 30s
    let window_verdict = engine
        .ingress_lock(invalid_window_lock, now, root_valid)
        .await;
    assert_eq!(window_verdict, Err(IngressVerdictLow::RejectedWindow));

    // 5. Async Flush verification: Wait for 50ms periodic batch flush
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Check that lock1 is now durable in redb storage
    let disk_lock = storage.get_lock(&lock1.parent_lock).unwrap();
    assert!(disk_lock.is_some(), "lock1 must be flushed to disk");
    let (rec, rv) = disk_lock.unwrap();
    assert_eq!(rec.id, lock1.id);
    assert_eq!(rv, root_valid.0);

    // 6. Batch flushing under load (> 100 entries)
    for i in 100..220u8 {
        let l = create_sample_lock(i, 80_000);
        let _ = engine.ingress_lock(l, now, root_valid).await;
    }

    // Poll for remaining items to be flushed under heavy test-runner load (batch 2 has 20 items, waits for periodic tick)
    for _ in 0..50 {
        if storage.get_lock(&[219; 32]).unwrap().is_some() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;
    }

    for i in 100..220u8 {
        let parent = [i; 32];
        assert!(storage.get_lock(&parent).unwrap().is_some());
    }

    drop(engine);
    let _ = worker_handle.await;
}

#[tokio::test]
async fn test_coldstart_crash_recovery_and_ttl_pruning() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_recovery.redb");

    let lock_short = create_sample_lock(0x31, 50_000); // valid_until 50s, root 60s
    let lock_long = create_sample_lock(0x32, 500_000); // valid_until 500s, root 600s

    // Phase 1: Setup engine and write locks
    {
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let (engine, worker_handle) = DualTierEngine::new(Arc::clone(&storage));

        let now = SimTime(0);
        engine
            .ingress_lock(lock_short.clone(), now, SimTime(60_000))
            .await
            .unwrap();
        engine
            .ingress_lock(lock_long.clone(), now, SimTime(600_000))
            .await
            .unwrap();

        // Wait for persistence flush
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Drop engine to simulate shutdown / crash
        drop(engine);
        let _ = worker_handle.await;
    }

    // Phase 2: Cold-start recovery at t = 100s
    // At t = 100s:
    // lock_short (valid_until 50s, root 60s + 30s grace = 90s) is expired and should be pruned (> 90s).
    // lock_long (valid_until 500s, root 600s) is fully valid.
    {
        let recovery_time = SimTime(100_000); // 100s
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let (engine, worker_handle) = DualTierEngine::new(Arc::clone(&storage));

        // RAM is empty before recovery
        assert_eq!(engine.ram.read().await.len(), 0);

        // Recover from disk
        let recovered = engine.recover_from_disk(recovery_time).await.unwrap();
        assert_eq!(recovered, 1, "only 1 unexpired lock should be recovered");

        // Verify RAM state
        {
            let ram = engine.ram.read().await;
            assert_eq!(ram.len(), 1);
            assert!(ram.get(&lock_short.parent_lock).is_none());
            assert!(ram.get(&lock_long.parent_lock).is_some());
        }

        // Test Pruning of disk storage
        let pruned = engine.prune_expired(recovery_time).await.unwrap();
        assert_eq!(pruned, 1, "expired lock_short should be pruned on disk");

        // Verify disk storage state
        assert!(storage.get_lock(&lock_short.parent_lock).unwrap().is_none());
        assert!(storage.get_lock(&lock_long.parent_lock).unwrap().is_some());

        drop(engine);
        let _ = worker_handle.await;
    }
}

#[tokio::test]
async fn test_dual_tier_engine_hmc_ttl_pruning_and_recovery() {
    use humoco_node::api::hmc::L2LockEntry;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_hmc_ttl.redb");

    let entry_short = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "v_short".to_string(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("50000".to_string()), // 50s -> expires at 50s + 30s = 80s
        privacy_guard: None,
    };

    let entry_long = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "v_long".to_string(),
        t_id: [0x44; 32],
        sender_ephemeral_pub: [0x55; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x66; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("500000".to_string()), // 500s -> expires at 530s
        privacy_guard: None,
    };

    // Phase 1: Ingress both into DualTierEngine and flush
    {
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let (engine, worker_handle) = DualTierEngine::new(Arc::clone(&storage));

        anchor_storage_fixture(&engine, &entry_short).await;
        anchor_storage_fixture(&engine, &entry_long).await;
        let (_, is_new1) = engine
            .ingress_hmc_lock("tag_short".to_string(), entry_short.clone())
            .await;
        assert!(is_new1);
        let (_, is_new2) = engine
            .ingress_hmc_lock("tag_long".to_string(), entry_long.clone())
            .await;
        assert!(is_new2);

        // Verify RAM index initially
        {
            let hmc = engine.hmc_ram.read().await;
            assert_eq!(hmc.locks().len(), 2);
            assert!(hmc.locks().contains_key("tag_short"));
            assert!(hmc.locks().contains_key("tag_long"));
        }

        // Wait for persistence flush
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        drop(engine);
        let _ = worker_handle.await;
    }

    // Phase 2: Cold-start recovery and pruning at t = 100s (100_000 ms)
    {
        let recovery_time = SimTime(100_000); // 100s > 80s grace for short, < 530s for long
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let (engine, worker_handle) = DualTierEngine::new(Arc::clone(&storage));

        // In recover_from_disk, unexpired HMC locks are loaded
        let _ = engine.recover_from_disk(recovery_time).await.unwrap();

        // Check RAM state: tag_short expired, tag_long valid
        {
            let hmc = engine.hmc_ram.read().await;
            assert_eq!(hmc.locks().len(), 1);
            assert!(!hmc.locks().contains_key("tag_short"));
            assert!(hmc.locks().contains_key("tag_long"));
        }

        // Prune expired buckets
        let pruned = engine.prune_expired(recovery_time).await.unwrap();
        assert!(pruned >= 1, "at least 1 expired HMC lock pruned");

        // Verify disk state
        assert!(storage.get_hmc_lock("tag_short").unwrap().is_none());
        assert!(storage.get_hmc_lock("tag_long").unwrap().is_some());

        drop(engine);
        let _ = worker_handle.await;
    }
}

#[test]
fn test_defensive_deserialization_corrupted_entries() {
    use humoco_node::storage::db::{TABLE_HMC_LOCKS, TABLE_LOCKS};
    use redb::Database;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_corrupt.redb");

    let storage = RedbStorage::open(&db_path).unwrap();

    // 1. Put one valid LockRecord and one valid HMC lock
    let lock1 = create_sample_lock(0x42, 100_000);
    storage.put_lock(&lock1, 600_000).unwrap();

    let entry = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "v_valid".to_string(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("600000".to_string()),
        privacy_guard: None,
    };
    let root = root_fixture(&entry);
    storage
        .put_hmc_lock(&bs58::encode(root.t_id).into_string(), &root)
        .unwrap();
    storage.put_hmc_lock("tag_valid", &entry).unwrap();
    storage.ban_node(&[0x99; 32], 12345).unwrap();

    // 2. Open DB with raw redb to inject corrupted / garbage bytes
    drop(storage);
    {
        let db = Database::open(&db_path).unwrap();
        let write_txn = db.begin_write().unwrap();
        {
            let mut table_locks = write_txn.open_table(TABLE_LOCKS).unwrap();
            // Corrupt binary bytes that cannot be deserialized as LockRecord
            let corrupt_parent = [0xDE; 32];
            table_locks
                .insert(
                    &corrupt_parent,
                    b"garbage_corrupted_payload_bytes".as_slice(),
                )
                .unwrap();

            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS).unwrap();
            // Corrupt JSON bytes that cannot be deserialized as L2LockEntry
            table_hmc
                .insert("tag_corrupt", b"not_a_valid_json{{}".as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Corruption may hide a prior root/spend decision. Migration must fail
    // closed rather than advertise a source-complete state after skipping it.
    assert!(RedbStorage::open(&db_path).is_err());
}

#[tokio::test]
async fn test_recent_locks_ringbuffer_and_inspection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_recent.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _handle) = DualTierEngine::new(storage);

    // Initial state: empty ringbuffer
    assert!(engine.get_recent_locks(10).is_empty());

    // 1. Ingress first lock
    let lock1 = create_sample_lock(0x11, 100_000);
    let v1 = engine
        .ingress_lock(lock1.clone(), SimTime(1000), SimTime(200_000))
        .await;
    assert!(v1.is_ok());

    let recent = engine.get_recent_locks(10);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].parent_lock_hex, hex::encode(lock1.parent_lock));
    assert_eq!(recent[0].child_lock_hex, hex::encode(lock1.id));
    assert_eq!(
        recent[0].status,
        humoco_node::storage::RecentLockStatus::Provisional
    );

    // 2. Ingress colliding lock (same parent, different child) -> Conflict
    let lock2 = LockRecord::new(
        lock1.parent_lock,
        [0xAA; 32],
        vec![0x99, 0x88],
        SimTime(0),
        SimTime(100_000),
    );
    let v2 = engine
        .ingress_lock(lock2.clone(), SimTime(1050), SimTime(200_000))
        .await;
    assert_eq!(v2, Err(IngressVerdictLow::RejectedCollision));

    let recent2 = engine.get_recent_locks(10);
    assert_eq!(recent2.len(), 2);
    // Newest is the conflict
    assert_eq!(
        recent2[0].status,
        humoco_node::storage::RecentLockStatus::Conflict
    );
    assert_eq!(
        recent2[1].status,
        humoco_node::storage::RecentLockStatus::Provisional
    );

    // 3. inspect_lock on existing parent
    let insp = engine.inspect_lock(&lock1.parent_lock).await;
    assert!(insp.is_some());
    let inspection = insp.unwrap();
    assert_eq!(inspection.parent_lock_hex, hex::encode(lock1.parent_lock));
    assert_eq!(inspection.lock_id_hex, hex::encode(lock1.id));

    // 4. inspect_lock on non-existent parent
    let non_existent = engine.inspect_lock(&[0xFA; 32]).await;
    assert!(non_existent.is_none());

    // 5. Ingress HMC lock and inspect
    let hmc_parent = [0x55u8; 32];
    let hmc_parent_hex = hex::encode(hmc_parent);
    let hmc_entry = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id: [0x77; 32],
        layer2_voucher_id: "voucher_test".to_string(),
        sender_ephemeral_pub: [0x88; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0xAA; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("150000".to_string()),
        privacy_guard: None,
    };
    anchor_storage_fixture(&engine, &hmc_entry).await;
    let (h_verdict, is_new) = engine
        .ingress_hmc_lock(hmc_parent_hex.clone(), hmc_entry.clone())
        .await;
    assert!(is_new);
    assert!(matches!(
        h_verdict,
        humoco_node::api::hmc::L2Verdict::Verified { .. }
    ));

    let hmc_insp = engine.inspect_lock(&hmc_parent).await;
    assert!(hmc_insp.is_some());
    let hmc_inspection = hmc_insp.unwrap();
    assert_eq!(hmc_inspection.parent_lock_hex, hmc_parent_hex);
    assert_eq!(hmc_inspection.lock_id_hex, hex::encode(hmc_entry.t_id));
}

#[tokio::test]
async fn test_voucher_query_methods() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_vouchers.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _worker_handle) = DualTierEngine::new(Arc::clone(&storage));

    let tag1 = "tag_01".to_string();
    let entry1 = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id: [0x01; 32],
        layer2_voucher_id: "voucher_alpha".to_string(),
        sender_ephemeral_pub: [0x11; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x11; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1000,
        created_at_ms: 1000,
        deletable_at: Some("2000000000000".to_string()),
        privacy_guard: None,
    };

    let tag2 = "tag_02".to_string();
    let entry2 = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id: [0x02; 32],
        layer2_voucher_id: "voucher_beta".to_string(),
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x22; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 2000,
        created_at_ms: 2000,
        deletable_at: Some("2500000000000".to_string()),
        privacy_guard: None,
    };

    anchor_storage_fixture(&engine, &entry1).await;
    anchor_storage_fixture(&engine, &entry2).await;
    let _ = engine.ingress_hmc_lock(tag1.clone(), entry1.clone()).await;
    let _ = engine.ingress_hmc_lock(tag2.clone(), entry2.clone()).await;

    // Test get_total_active_vouchers_count
    let count = engine.get_total_active_vouchers_count().await;
    assert_eq!(count, 2);

    // Test get_recent_active_vouchers with limit
    let recent1 = engine.get_recent_active_vouchers(1).await;
    assert_eq!(recent1.len(), 1);
    assert_eq!(recent1[0].voucher_id, "voucher_beta"); // Higher root_valid_until_ms first

    let recent_all = engine.get_recent_active_vouchers(10).await;
    assert_eq!(recent_all.len(), 2);

    // Test get_voucher_lineage by voucher_id
    let lin_by_vid = engine.get_voucher_lineage("voucher_alpha").await;
    assert!(lin_by_vid.is_some());
    assert_eq!(lin_by_vid.unwrap().voucher_id, "voucher_alpha");

    // Test get_voucher_lineage by lookup_tag
    let lin_by_tag = engine.get_voucher_lineage(&tag1).await;
    assert!(lin_by_tag.is_some());
    assert_eq!(lin_by_tag.unwrap().voucher_id, "voucher_alpha");

    // Test non-existent
    assert!(engine.get_voucher_lineage("non_existent").await.is_none());
}

#[test]
fn test_system_audit_events_storage_and_pruning() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_audit.redb");
    let storage = RedbStorage::open(&db_path).expect("failed to open redb");

    // Initially empty
    let initial = storage.load_recent_audit_events(100).unwrap();
    assert!(initial.is_empty());

    // Insert 120 events: ids 1 to 120
    for id in 1..=120 {
        let event = humoco_node::api::events::EventItem {
            id,
            timestamp_sec: 1700000000 + id,
            kind: if id % 2 == 0 {
                humoco_node::api::events::EventKind::PeerBan
            } else {
                humoco_node::api::events::EventKind::System
            },
            severity: if id > 100 {
                humoco_node::api::health::HealthLevel::Crit
            } else {
                humoco_node::api::health::HealthLevel::Ok
            },
            message: format!("Audit event #{}", id),
        };
        storage.insert_audit_event(&event).expect("insert failed");
    }

    // Should be capped at 100 entries: oldest 20 (ids 1..=20) pruned, keeping ids 21..=120
    let loaded_all = storage.load_recent_audit_events(200).unwrap();
    assert_eq!(loaded_all.len(), 100);
    assert_eq!(loaded_all.first().unwrap().id, 21);
    assert_eq!(loaded_all.last().unwrap().id, 120);

    // Limit respects limit argument
    let loaded_10 = storage.load_recent_audit_events(10).unwrap();
    assert_eq!(loaded_10.len(), 10);
    assert_eq!(loaded_10.first().unwrap().id, 111);
    assert_eq!(loaded_10.last().unwrap().id, 120);

    // Reopen storage and verify persistence
    drop(storage);
    let reopened = RedbStorage::open(&db_path).expect("failed to reopen redb");
    let after_reopen = reopened.load_recent_audit_events(50).unwrap();
    assert_eq!(after_reopen.len(), 50);
    assert_eq!(after_reopen.first().unwrap().id, 71);
    assert_eq!(after_reopen.last().unwrap().id, 120);
}

#[tokio::test]
async fn test_durable_before_vote_crash_durability() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_crash_durability.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, worker_handle) = DualTierEngine::new(Arc::clone(&storage));

    let parent_bytes = [0x42u8; 32];
    let tag = hex::encode(parent_bytes);
    let entry = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id: [0x42; 32],
        layer2_voucher_id: "voucher_crash".to_string(),
        sender_ephemeral_pub: [0x42; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x42; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1000,
        created_at_ms: 1000,
        deletable_at: Some("600000".to_string()),
        privacy_guard: None,
    };

    anchor_storage_fixture(&engine, &entry).await;
    // Ingress using durable method (DEC-029 restoration)
    let (verdict, is_new) = engine
        .ingress_hmc_lock_durable(
            tag.clone(),
            entry.clone(),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(1000),
            Some("Free"),
            Some(10),
            Some("voucher_crash".to_string()),
        )
        .await;

    assert!(
        matches!(verdict, humoco_node::api::hmc::L2Verdict::Verified { .. }),
        "{verdict:?}"
    );
    assert!(is_new);

    // Now simulate an abrupt crash without graceful shutdown drain:
    // Drop the engine and abort the worker immediately (simulating SIGKILL / sudden power loss)
    worker_handle.abort();
    let _ = worker_handle.await;
    drop(engine);
    drop(storage);

    // Reopen database directly from disk
    let reopened_storage = Arc::new(RedbStorage::open(&db_path).expect("failed to reopen redb"));

    // Check that entry is durably persisted on disk in TABLE_HMC_LOCKS
    let disk_entry = reopened_storage
        .get_hmc_lock(&tag)
        .expect("disk read failed");
    assert!(
        disk_entry.is_some(),
        "Lock MUST be durably present on disk before vote/verdict"
    );
    assert_eq!(disk_entry.unwrap().t_id, [0x42; 32]);

    // Re-instantiate a fresh DualTierEngine and verify recovery from disk
    let (new_engine, _new_worker) = DualTierEngine::new(Arc::clone(&reopened_storage));
    let _ = new_engine
        .recover_from_disk(SimTime(1000))
        .await
        .expect("recovery failed");

    // Verify the lock is in the RAM index and voucher lineage is recovered
    let insp = new_engine.inspect_lock(&parent_bytes).await;
    assert!(insp.is_some());
    assert_eq!(insp.unwrap().lock_id_hex, hex::encode([0x42; 32]));

    let lin = new_engine.get_voucher_lineage("voucher_crash").await;
    assert!(lin.is_some());
    assert_eq!(lin.unwrap().voucher_id, "voucher_crash");
}

// Byte-storage fixtures use artificial signatures. Separate roots exercise the
// production namespace/TTL boundary; genuine author authentication is covered
// by chain_causality_and_prefix_tests over HTTP and QUIC.
fn root_fixture(entry: &humoco_node::api::hmc::L2LockEntry) -> humoco_node::api::hmc::L2LockEntry {
    let mut root = entry.clone();
    root.t_id[0] ^= 0x80;
    root
}
async fn anchor_storage_fixture(
    engine: &DualTierEngine,
    entry: &humoco_node::api::hmc::L2LockEntry,
) {
    let root = root_fixture(entry);
    let (verdict, _) = engine
        .ingress_hmc_lock_durable(
            bs58::encode(root.t_id).into_string(),
            root,
            humoco_node::storage::IngressOrigin::ClientApi,
            None,
            None,
            None,
            None,
        )
        .await;
    assert!(
        matches!(verdict, humoco_node::api::hmc::L2Verdict::Verified { .. }),
        "{verdict:?}"
    );
}

// Helper to construct deterministic HMC entries
fn make_test_root_entry(
    voucher_id: &str,
    t_id: [u8; 32],
    valid_until_ms: u64,
) -> (String, humoco_node::api::hmc::L2LockEntry) {
    let tag = bs58::encode(t_id).into_string();
    let entry = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id,
        layer2_voucher_id: voucher_id.to_string(),
        sender_ephemeral_pub: [0x11; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x22; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1000,
        created_at_ms: 1000,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: None,
    };
    (tag, entry)
}

fn make_test_spend_entry(
    voucher_id: &str,
    t_id: [u8; 32],
    created_at_ms: u64,
) -> (String, humoco_node::api::hmc::L2LockEntry) {
    let tag = bs58::encode(t_id).into_string();
    let entry = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id,
        layer2_voucher_id: voucher_id.to_string(),
        sender_ephemeral_pub: [0x33; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x44; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: created_at_ms as u128,
        created_at_ms,
        deletable_at: None,
        privacy_guard: None,
    };
    (tag, entry)
}

fn shard_for_tid(t_id: [u8; 32]) -> u16 {
    let tag = bs58::encode(t_id).into_string();
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
    humoco_sim_core::types::canonical_voucher_shard(&parent)
}

#[test]
fn test_s02_01_backup_to_live_source_path_rejected_and_preserves_durability() {
    let dir = tempdir().unwrap();
    let sub_dir = dir.path().join("db_dir");
    std::fs::create_dir_all(&sub_dir).unwrap();
    let db_path = sub_dir.join("live.redb");
    let storage = RedbStorage::open(&db_path).unwrap();

    // 1. Write retained original approval + non-signing state
    let node_key = [0x11u8; 32];
    let parent1 = [0x22u8; 32];
    let record1 = LockRecord::new(parent1, [0x33u8; 32], vec![1, 2, 3], SimTime(1000), SimTime(50_000));
    storage
        .commit_original_record_approval(&record1, 50_000, &node_key, b"approval_1", 0)
        .unwrap();
    storage.set_quota(&[0x44u8; 32], 5000).unwrap();
    storage.ban_node(&[0x55u8; 32], 2000).unwrap();
    storage.put_lock(&record1, 50_000).unwrap();

    // (a) Exact source path
    let err_exact = storage.create_backup(&db_path);
    assert!(err_exact.is_err(), "backup to exact source path must fail");

    // (b) Path with '.' component
    let dot_path = sub_dir.join(".").join("live.redb");
    let err_dot = storage.create_backup(&dot_path);
    assert!(err_dot.is_err(), "backup to '.' normalized source path must fail");

    // (c) Path via symlinked parent directory
    #[cfg(unix)]
    {
        let symlink_dir = dir.path().join("symlink_dir");
        std::os::unix::fs::symlink(&sub_dir, &symlink_dir).unwrap();
        let symlink_path = symlink_dir.join("live.redb");
        let err_symlink_dir = storage.create_backup(&symlink_path);
        assert!(err_symlink_dir.is_err(), "backup via symlinked parent directory must fail");
    }

    // (c2) Destination symlink file pointing directly to source DB
    #[cfg(unix)]
    {
        let symlink_file = dir.path().join("live_symlink.redb");
        std::os::unix::fs::symlink(&db_path, &symlink_file).unwrap();
        let err_symlink_file = storage.create_backup(&symlink_file);
        assert!(err_symlink_file.is_err(), "backup via symlink file to live DB must fail");
    }

    // 2. Subsequent writes to live DB
    let parent2 = [0x66u8; 32];
    let record2 = LockRecord::new(parent2, [0x77u8; 32], vec![4, 5, 6], SimTime(2000), SimTime(50_000));
    storage
        .commit_original_record_approval(&record2, 50_000, &node_key, b"approval_2", 0)
        .unwrap();
    storage.ban_node(&[0x88u8; 32], 3000).unwrap();

    // 3. Close and reopen DB at source path
    drop(storage);
    let reopened = RedbStorage::open(&db_path).unwrap();

    // Verify both preexisting and subsequent writes remain intact!
    assert!(reopened.own_signing_choice(&node_key, &hex::encode(parent1)).unwrap().is_some());
    assert!(reopened.own_signing_choice(&node_key, &hex::encode(parent2)).unwrap().is_some());
    assert_eq!(reopened.get_quota(&[0x44u8; 32]).unwrap(), 5000);
    assert!(reopened.is_node_banned(&[0x55u8; 32]).unwrap());
    assert!(reopened.is_node_banned(&[0x88u8; 32]).unwrap());
    assert!(reopened.get_lock(&parent1).unwrap().is_some());

    // 4. Distinct-destination backup succeeds (and overwriting existing distinct file succeeds)
    let distinct_dest = dir.path().join("distinct_backup.redb");
    let count1 = reopened.create_backup(&distinct_dest).unwrap();
    assert!(count1 >= 1);
    assert!(distinct_dest.exists());
    let count2 = reopened.create_backup(&distinct_dest).unwrap();
    assert_eq!(count1, count2);
}

#[test]
fn test_s02_02_prune_expired_buckets_257_spends_retains_root_until_drained() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("prune_257.redb");
    let storage = RedbStorage::open(&db_path).unwrap();

    // 1. Expired voucher with 257 spends (valid_until = 50_000 ms, expires at sec 81)
    let expired_vid = "voucher_exp_257";
    let mut exp_root_tid = [0xAAu8; 32];
    exp_root_tid[0] = 0x01;
    let (exp_root_tag, exp_root) = make_test_root_entry(expired_vid, exp_root_tid, 50_000);
    storage.put_hmc_lock(&exp_root_tag, &exp_root).unwrap();

    for i in 0..257u32 {
        let mut spend_tid = [0xBBu8; 32];
        spend_tid[..4].copy_from_slice(&i.to_le_bytes());
        let (spend_tag, spend) = make_test_spend_entry(expired_vid, spend_tid, 1000 + i as u64);
        storage.put_hmc_lock(&spend_tag, &spend).unwrap();
    }

    // 2. Unrelated live voucher in a different shard (valid_until = 500_000 ms)
    let exp_shard = shard_for_tid(exp_root_tid);
    let mut live_root_tid = [0xCCu8; 32];
    while shard_for_tid(live_root_tid) == exp_shard {
        live_root_tid[0] = live_root_tid[0].wrapping_add(1);
    }
    let live_shard = shard_for_tid(live_root_tid);
    let live_vid = "voucher_live_diff_shard";
    let (live_root_tag, live_root) = make_test_root_entry(live_vid, live_root_tid, 500_000);
    storage.put_hmc_lock(&live_root_tag, &live_root).unwrap();
    let mut live_spend_tid = [0xDDu8; 32];
    live_spend_tid[0] = 0x01;
    let (live_spend_tag, live_spend) = make_test_spend_entry(live_vid, live_spend_tid, 2000);
    storage.put_hmc_lock(&live_spend_tag, &live_spend).unwrap();

    // Pass 1: Prune at sec 81 (prunes up to 256 expired spends, leaving 1 spend)
    let (_pruned_native, pruned_hmc_pass1) = storage.prune_expired_buckets(81).unwrap();
    assert_eq!(pruned_hmc_pass1, 256, "Pass 1 must prune exactly 256 expired spends");

    // ASSERTIONS AFTER PASS 1:
    // Root MUST be retained because 1 spend remains!
    assert!(
        storage.voucher_root(expired_vid).unwrap().is_some(),
        "Expired root must be retained while dependent spends remain in DB"
    );
    // Unrelated live shard digest MUST succeed!
    let live_digest = storage.committed_shard_digest(live_shard, 81_000);
    assert!(live_digest.is_ok(), "Live shard digest must succeed after Pass 1: {:?}", live_digest.err());

    // Sync reads MUST succeed without missing-root corruption!
    let unbounded = storage.read_committed_sync_snapshot(81_000);
    assert!(unbounded.is_ok(), "read_committed_sync_snapshot must succeed: {:?}", unbounded.err());
    let page = storage.read_committed_sync_snapshot_bounded(81_000, &std::collections::HashSet::new(), 100, 4 * 1024 * 1024);
    assert!(page.is_ok(), "read_committed_sync_snapshot_bounded must succeed: {:?}", page.err());

    // Pass 2: Prune remaining 1 expired spend
    let (_pruned_native, pruned_hmc_pass2) = storage.prune_expired_buckets(81).unwrap();
    assert_eq!(pruned_hmc_pass2, 1, "Pass 2 must prune the remaining 1 expired spend");

    // After all spends for expired voucher are gone, the root is pruned
    assert!(
        storage.voucher_root(expired_vid).unwrap().is_none(),
        "Expired root must be pruned once all dependent spends are drained"
    );

    // Live voucher remains 100% intact!
    assert!(storage.voucher_root(live_vid).unwrap().is_some());
    assert!(storage.get_hmc_lock(&live_spend_tag).unwrap().is_some());
    let live_digest_pass2 = storage.committed_shard_digest(live_shard, 81_000);
    assert!(live_digest_pass2.is_ok());
}

#[test]
fn test_s02_02_apply_flush_batch_atomic_prune_retains_root_until_drained() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("flush_prune_257.redb");
    let storage = RedbStorage::open(&db_path).unwrap();

    let expired_vid = "voucher_flush_257";
    let exp_root_tid = [0x1Au8; 32];
    let (exp_root_tag, exp_root) = make_test_root_entry(expired_vid, exp_root_tid, 50_000);
    storage.put_hmc_lock(&exp_root_tag, &exp_root).unwrap();

    for i in 0..257u32 {
        let mut spend_tid = [0x2Bu8; 32];
        spend_tid[..4].copy_from_slice(&i.to_le_bytes());
        let (spend_tag, spend) = make_test_spend_entry(expired_vid, spend_tid, 1000 + i as u64);
        storage.put_hmc_lock(&spend_tag, &spend).unwrap();
    }

    let exp_shard = shard_for_tid(exp_root_tid);
    let mut live_root_tid = [0x3Cu8; 32];
    while shard_for_tid(live_root_tid) == exp_shard {
        live_root_tid[0] = live_root_tid[0].wrapping_add(1);
    }
    let live_shard = shard_for_tid(live_root_tid);
    let live_vid = "voucher_flush_live";
    let (live_root_tag, live_root) = make_test_root_entry(live_vid, live_root_tid, 500_000);
    storage.put_hmc_lock(&live_root_tag, &live_root).unwrap();
    let live_spend_tid = [0x4Du8; 32];
    let (live_spend_tag, live_spend) = make_test_spend_entry(live_vid, live_spend_tid, 2000);
    storage.put_hmc_lock(&live_spend_tag, &live_spend).unwrap();

    // Pass 1 via apply_flush_batch_atomic
    storage.apply_flush_batch_atomic(&[], &[], &[], &[], &[], &[81]).unwrap();

    // After Pass 1: 1 spend remains; root MUST NOT be deleted
    assert!(
        storage.voucher_root(expired_vid).unwrap().is_some(),
        "apply_flush_batch_atomic must not delete root while spends remain"
    );
    let live_digest = storage.committed_shard_digest(live_shard, 81_000);
    assert!(live_digest.is_ok(), "Live shard digest must succeed after pass 1: {:?}", live_digest.err());

    // Pass 2 via apply_flush_batch_atomic
    storage.apply_flush_batch_atomic(&[], &[], &[], &[], &[], &[81]).unwrap();

    // After Pass 2: all spends drained, childless root deleted
    assert!(
        storage.voucher_root(expired_vid).unwrap().is_none(),
        "childless root must be deleted once spends reach zero"
    );
    assert!(storage.voucher_root(live_vid).unwrap().is_some());
}

#[test]
fn test_s02_02_quarantined_provisional_spends_retain_root() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("quarantine_prune.redb");
    let storage = RedbStorage::open(&db_path).unwrap();

    let expired_vid = "voucher_quarantine";
    let exp_root_tid = [0x5Eu8; 32];
    let (exp_root_tag, exp_root) = make_test_root_entry(expired_vid, exp_root_tid, 50_000);
    storage.put_hmc_lock(&exp_root_tag, &exp_root).unwrap();

    let spend_tid = [0x6Fu8; 32];
    let (spend_tag, spend) = make_test_spend_entry(expired_vid, spend_tid, 1000);
    storage.put_hmc_lock(&spend_tag, &spend).unwrap();

    let shard = shard_for_tid(exp_root_tid);

    // Quarantine the spend into TABLE_PROVISIONAL_HMC_LOCKS
    let (_q_native, q_hmc) = storage
        .quarantine_subquorum_locks(shard, &std::collections::HashSet::new(), &std::collections::HashSet::new())
        .unwrap();
    assert_eq!(q_hmc.len(), 1);
    assert!(storage.get_hmc_lock(&spend_tag).unwrap().is_none(), "Spend moved out of active locks");
    assert!(storage.get_provisional_hmc_lock(&spend_tag).unwrap().is_some(), "Spend is in provisional locks");

    // Root must be retained while provisional spend exists
    assert!(storage.voucher_root(expired_vid).unwrap().is_some());

    // Prune at sec 81: the shared worker purges provisional lock AND the root
    let (_p_native, p_hmc) = storage.prune_expired_buckets(81).unwrap();
    assert_eq!(p_hmc, 1, "Provisional lock must be purged at expiry");
    assert!(storage.get_provisional_hmc_lock(&spend_tag).unwrap().is_none());
    assert!(storage.voucher_root(expired_vid).unwrap().is_none(), "Root must be pruned once provisional lock is purged");
}

#[test]
fn test_s02_02_multiple_vouchers_ttl_ordering_differs_from_tag_ordering() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("ordering_diff.redb");
    let storage = RedbStorage::open(&db_path).unwrap();

    // Voucher "v_zebra": TTL = 40_000 ms (expires at sec 71). 200 spends.
    // Voucher "v_aardvark": TTL = 50_000 ms (expires at sec 81). 100 spends.
    // Alphabetical order: v_aardvark < v_zebra.
    // Expiry order: v_zebra (71s) < v_aardvark (81s).
    let vid_zebra = "v_zebra";
    let tid_zebra = [0x70u8; 32];
    let (root_tag_z, root_z) = make_test_root_entry(vid_zebra, tid_zebra, 40_000);
    storage.put_hmc_lock(&root_tag_z, &root_z).unwrap();
    for i in 0..200u32 {
        let mut spend_tid = [0x71u8; 32];
        spend_tid[..4].copy_from_slice(&i.to_le_bytes());
        let (spend_tag, spend) = make_test_spend_entry(vid_zebra, spend_tid, 1000 + i as u64);
        storage.put_hmc_lock(&spend_tag, &spend).unwrap();
    }

    let vid_aardvark = "v_aardvark";
    let tid_aardvark = [0x80u8; 32];
    let (root_tag_a, root_a) = make_test_root_entry(vid_aardvark, tid_aardvark, 50_000);
    storage.put_hmc_lock(&root_tag_a, &root_a).unwrap();
    for i in 0..100u32 {
        let mut spend_tid = [0x81u8; 32];
        spend_tid[..4].copy_from_slice(&i.to_le_bytes());
        let (spend_tag, spend) = make_test_spend_entry(vid_aardvark, spend_tid, 1000 + i as u64);
        storage.put_hmc_lock(&spend_tag, &spend).unwrap();
    }

    // Prune at sec 81 (both are expired).
    // Pass 1: prunes 256 spends (200 of zebra + 56 of aardvark).
    let (_, pruned_pass1) = storage.prune_expired_buckets(81).unwrap();
    assert_eq!(pruned_pass1, 256);

    // v_aardvark still has 44 spends remaining, so its root MUST be present!
    assert!(
        storage.voucher_root(vid_aardvark).unwrap().is_some(),
        "v_aardvark root must be retained because 44 spends remain"
    );
    // Every remaining spend in DB has its root anchor present!
    assert!(storage.read_committed_sync_snapshot(81_000).is_ok());

    // Pass 2: prunes remaining 44 spends of aardvark.
    let (_, pruned_pass2) = storage.prune_expired_buckets(81).unwrap();
    assert_eq!(pruned_pass2, 44);

    // Both roots are now childless and completely pruned
    assert!(storage.voucher_root(vid_zebra).unwrap().is_none());
    assert!(storage.voucher_root(vid_aardvark).unwrap().is_none());
}

