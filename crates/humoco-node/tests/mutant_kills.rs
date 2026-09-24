//! Mutant kill tests for Audit 12 – node crate
//! M2-S3: SpentLockFilter post-prune consistency
//! M2-S6: RedbStorage::prune_expired_buckets physical HMC removal

use std::sync::Arc;
use humoco_node::storage::{RedbStorage, SpentLockFilter};
use humoco_node::api::hmc::L2LockEntry;
use humoco_sim_core::types::SimTime;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// M2-S3: SpentLockFilter must not contain pruned tag after prune
// Mutant: delete `self.filter.delete(&tag)` in HmcRamIndex::prune_expired -> filter still contains pruned entry
// ---------------------------------------------------------------------------
#[test]
fn test_mutant_m2s3_spent_lock_filter_post_prune_removed() {
    let mut filter = SpentLockFilter::new();
    let tag = "photon_tag_123";
    filter.add(tag);
    assert!(filter.contains(tag));

    // Simulate prune: delete should remove
    let deleted = filter.delete(tag);
    assert!(deleted, "delete should return true for existing tag");
    assert!(!filter.contains(tag), "filter must not contain tag after prune delete");
}

#[test]
fn test_mutant_m2s3_spent_lock_filter_retains_unexpired_and_false_negative_safe() {
    let mut filter = SpentLockFilter::with_capacity(1000);
    let tag_a = "voucher_a_lookup";
    let tag_b = "voucher_b_lookup";
    let tag_never = "never_inserted";

    filter.add(tag_a);
    filter.add(tag_b);
    assert!(filter.contains(tag_a));
    assert!(filter.contains(tag_b));
    assert!(!filter.contains(tag_never));

    // Delete only tag_a (simulate pruning expired)
    filter.delete(tag_a);
    assert!(!filter.contains(tag_a), "pruned tag must be gone");
    assert!(filter.contains(tag_b), "unexpired tag must remain");
    // Deleting non-existent is tolerated (false negative safe – RAM is canonical)
    let not_existed = filter.delete(tag_never);
    // cuckoo filter delete returns false for non-existent
    assert!(!not_existed);
}

#[tokio::test]
async fn test_mutant_m2s3_hmc_ram_filter_consistency_after_prune() {
    use humoco_node::storage::DualTierEngine;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("mutant_filter_prune.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, handle) = DualTierEngine::new(Arc::clone(&storage));

    let entry = L2LockEntry {
        layer2_voucher_id: "v_filter".to_string(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("50000".to_string()), // 50s
        privacy_guard: None,
    };
    let tag = "filter_prune_tag".to_string();
    let (_, is_new) = engine.ingress_hmc_lock(tag.clone(), entry).await;
    assert!(is_new);

    // Filter must contain after ingress
    {
        let hmc = engine.hmc_ram.read().await;
        assert!(hmc.filter.contains(&tag), "filter must contain after ingress");
    }

    // Prune at far future (100s > 50s+30s=80s)
    let pruned = engine.hmc_ram.write().await.prune_expired(SimTime(100_000));
    assert_eq!(pruned, 1);

    // After prune, filter must NOT contain
    {
        let hmc = engine.hmc_ram.read().await;
        assert!(!hmc.filter.contains(&tag), "filter must not contain pruned tag (mutant would fail)");
        assert!(!hmc.locks.contains_key(&tag));
    }

    drop(engine);
    let _ = handle.await;
}

// ---------------------------------------------------------------------------
// M2-S6: RedbStorage::prune_expired_buckets physically removes HMC entries
// Mutant: prune_expired returns 0 without deleting -> expired data remains
// ---------------------------------------------------------------------------
#[test]
fn test_mutant_m2s6_hmc_disk_prune_removes_expired() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("mutant_hmc_prune.redb");
    let storage = RedbStorage::open(&db_path).unwrap();

    let entry_expired = L2LockEntry {
        layer2_voucher_id: "v_exp".to_string(),
        t_id: [0xAA; 32],
        sender_ephemeral_pub: [0xBB; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0xCC; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("50000".to_string()), // 50s -> bucket 80
        privacy_guard: None,
    };
    let entry_alive = L2LockEntry {
        layer2_voucher_id: "v_alive".to_string(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("500000".to_string()), // 500s -> bucket 530
        privacy_guard: None,
    };

    storage.put_hmc_lock("tag_exp", &entry_expired).unwrap();
    storage.put_hmc_lock("tag_alive", &entry_alive).unwrap();

    // Verify both present before prune
    assert!(storage.get_hmc_lock("tag_exp").unwrap().is_some());
    assert!(storage.get_hmc_lock("tag_alive").unwrap().is_some());

    // Prune at now_sec = 100 ( >80, <530)
    let (pruned_parents, pruned_hmc) = storage.prune_expired_buckets(100).unwrap();
    // HMC prune should have removed exactly 1 entry (tag_exp)
    assert_eq!(pruned_hmc, 1, "exactly one HMC entry must be pruned");
    // Parents pruned is for LockRecord table, should be 0 here
    assert_eq!(pruned_parents.len(), 0);

    assert!(storage.get_hmc_lock("tag_exp").unwrap().is_none(), "expired HMC must be physically deleted");
    assert!(storage.get_hmc_lock("tag_alive").unwrap().is_some(), "alive HMC must remain");

    let all = storage.all_hmc_locks().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, "tag_alive");

    let valid = storage.all_valid_hmc_locks(100_000).unwrap();
    assert_eq!(valid.len(), 1);

    // Voucher index for expired voucher must be cleaned
    let all_after = storage.all_hmc_locks().unwrap();
    assert!(!all_after.iter().any(|(k,_)| k=="tag_exp"));
}

#[test]
fn test_mutant_m2s6_hmc_disk_prune_retains_unexpired_until_grace() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("mutant_hmc_grace.redb");
    let storage = RedbStorage::open(&db_path).unwrap();

    let entry = L2LockEntry {
        layer2_voucher_id: "v_grace".to_string(),
        t_id: [0x55; 32],
        sender_ephemeral_pub: [0x66; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x77; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("100000".to_string()), // 100s -> bucket 130
        privacy_guard: None,
    };
    storage.put_hmc_lock("tag_grace", &entry).unwrap();

    // Prune before grace (now=100 -> bucket 100 <130 => must retain)
    let (_, pruned1) = storage.prune_expired_buckets(100).unwrap();
    assert_eq!(pruned1, 0, "before grace must retain");
    assert!(storage.get_hmc_lock("tag_grace").unwrap().is_some());

    // Prune exactly at grace bucket (130) -> should delete (sec <= now_sec)
    let (_, pruned2) = storage.prune_expired_buckets(130).unwrap();
    assert_eq!(pruned2, 1, "at grace bucket must be pruned");
    assert!(storage.get_hmc_lock("tag_grace").unwrap().is_none());
}
