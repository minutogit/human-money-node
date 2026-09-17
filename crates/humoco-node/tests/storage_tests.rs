use std::sync::Arc;
use humoco_node::storage::{DualTierEngine, RedbStorage};
use humoco_sim_core::storage::IngressVerdictLow;
use humoco_sim_core::types::{Hash256, LockRecord, SimTime};
use tempfile::tempdir;

fn create_sample_lock(parent_byte: u8, valid_until_ms: u64) -> LockRecord {
    let parent = [parent_byte; 32];
    let receiver = [0xEE; 32];
    let nonce = vec![parent_byte, 0x01, 0x02];
    LockRecord::new(
        parent,
        receiver,
        nonce,
        SimTime(0),
        SimTime(valid_until_ms),
    )
}

#[test]
fn test_redb_storage_crud() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_crud.redb");
    let storage = RedbStorage::open(&db_path).expect("failed to open redb");

    // 1. Lock CRUD
    let lock1 = create_sample_lock(0x01, 60_000);
    let root_valid_until_1 = 600_000;
    storage.put_lock(&lock1, root_valid_until_1).expect("put_lock failed");

    let retrieved = storage.get_lock(&lock1.parent_lock).expect("get_lock failed");
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
    let charge_err = storage.check_and_charge_quota(&account, 1_500_000).unwrap_err();
    match charge_err {
        humoco_node::storage::StorageError::QuotaExceeded { available, required } => {
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
    let h1 = humoco_sim_core::crypto::compute_canonical_hash(&lock1.parent_lock, &lock1.receiver_pub, &lock1.nonce);
    let mut nonce_b = 0u8;
    let colliding_lock = loop {
        let cand = LockRecord::new(
            lock1.parent_lock,
            [0x99; 32],
            vec![nonce_b],
            SimTime(0),
            SimTime(60_000),
        );
        let h_cand = humoco_sim_core::crypto::compute_canonical_hash(&cand.parent_lock, &cand.receiver_pub, &cand.nonce);
        if h_cand > h1 {
            break cand;
        }
        nonce_b = nonce_b.wrapping_add(1);
    };
    let collision_verdict = engine
        .ingress_lock(colliding_lock, now, root_valid)
        .await;
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

    tokio::time::sleep(tokio::time::Duration::from_millis(120)).await;

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

    let lock_short = create_sample_lock(0x31, 50_000);   // valid_until 50s, root 60s
    let lock_long = create_sample_lock(0x32, 500_000);   // valid_until 500s, root 600s

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
        layer2_voucher_id: "v_short".to_string(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("50000".to_string()), // 50s -> expires at 50s + 30s = 80s
        privacy_guard: None,
    };

    let entry_long = L2LockEntry {
        layer2_voucher_id: "v_long".to_string(),
        t_id: [0x44; 32],
        sender_ephemeral_pub: [0x55; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x66; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("500000".to_string()), // 500s -> expires at 530s
        privacy_guard: None,
    };

    // Phase 1: Ingress both into DualTierEngine and flush
    {
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let (engine, worker_handle) = DualTierEngine::new(Arc::clone(&storage));

        let (_, is_new1) = engine.ingress_hmc_lock("tag_short".to_string(), entry_short.clone()).await;
        assert!(is_new1);
        let (_, is_new2) = engine.ingress_hmc_lock("tag_long".to_string(), entry_long.clone()).await;
        assert!(is_new2);

        // Verify RAM index initially
        {
            let hmc = engine.hmc_ram.read().await;
            assert_eq!(hmc.locks.len(), 2);
            assert!(hmc.locks.contains_key("tag_short"));
            assert!(hmc.locks.contains_key("tag_long"));
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
            assert_eq!(hmc.locks.len(), 1);
            assert!(!hmc.locks.contains_key("tag_short"));
            assert!(hmc.locks.contains_key("tag_long"));
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
        layer2_voucher_id: "v_valid".to_string(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("600000".to_string()),
        privacy_guard: None,
    };
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
            table_locks.insert(&corrupt_parent, b"garbage_corrupted_payload_bytes".as_slice()).unwrap();

            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS).unwrap();
            // Corrupt JSON bytes that cannot be deserialized as L2LockEntry
            table_hmc.insert("tag_corrupt", b"not_a_valid_json{{}".as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // 3. Re-open storage and verify defensive loading
    let storage = RedbStorage::open(&db_path).unwrap();

    // all_valid_locks should skip corrupted entry and return the intact one
    let valid_locks = storage.all_valid_locks(0).unwrap();
    assert_eq!(valid_locks.len(), 1, "Should skip corrupted lock and return valid one");
    assert_eq!(valid_locks[0].0.id, lock1.id);

    // active_locks_for_shard should also skip corrupted entry
    let shard_id = u16::from_be_bytes([lock1.parent_lock[0], lock1.parent_lock[1]]);
    let shard_locks = storage.active_locks_for_shard(shard_id, 0).unwrap();
    assert_eq!(shard_locks.len(), 1);
    assert_eq!(shard_locks[0].0.id, lock1.id);

    // all_hmc_locks and all_valid_hmc_locks should skip corrupted entry
    let hmc_locks = storage.all_hmc_locks().unwrap();
    assert_eq!(hmc_locks.len(), 1, "Should skip corrupted HMC entry");
    assert_eq!(hmc_locks[0].0, "tag_valid");

    let valid_hmc = storage.all_valid_hmc_locks(0).unwrap();
    assert_eq!(valid_hmc.len(), 1);
    assert_eq!(valid_hmc[0].0, "tag_valid");

    // all_slashed_nodes should return the valid banned node
    let slashed = storage.all_slashed_nodes().unwrap();
    assert_eq!(slashed.len(), 1);
    assert_eq!(slashed[0], [0x99; 32]);
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
    assert_eq!(recent[0].status, humoco_node::storage::RecentLockStatus::Provisional);

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
    assert_eq!(recent2[0].status, humoco_node::storage::RecentLockStatus::Conflict);
    assert_eq!(recent2[1].status, humoco_node::storage::RecentLockStatus::Provisional);

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
        t_id: [0x77; 32],
        layer2_voucher_id: "voucher_test".to_string(),
        sender_ephemeral_pub: [0x88; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0xAA; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("150000".to_string()),
        privacy_guard: None,
    };
    let (h_verdict, is_new) = engine
        .ingress_hmc_lock(hmc_parent_hex.clone(), hmc_entry.clone())
        .await;
    assert!(is_new);
    assert!(matches!(h_verdict, humoco_node::api::hmc::L2Verdict::Verified { .. }));

    let hmc_insp = engine.inspect_lock(&hmc_parent).await;
    assert!(hmc_insp.is_some());
    let hmc_inspection = hmc_insp.unwrap();
    assert_eq!(hmc_inspection.parent_lock_hex, hmc_parent_hex);
    assert_eq!(hmc_inspection.lock_id_hex, hex::encode(hmc_entry.t_id));
}


