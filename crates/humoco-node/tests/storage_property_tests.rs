//! Stateful property-based tests for DualTierEngine + RedbStorage (A14-02)
//! Generates random sequences of operations:
//!   - InsertGenesis
//!   - Spend
//!   - Retry (idempotency)
//!   - Conflict (double-spend rejection)
//!   - Prune (TTL eviction)
//!   - Reopen (crash-recovery consistency)
//!
//! Asserting strict RAM and disk state consistency against a reference model.

use humoco_node::api::hmc::{L2LockEntry, L2Verdict};
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};
use humoco_sim_core::types::SimTime;
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[derive(Debug, Clone)]
enum StorageOp {
    InsertGenesis { voucher_idx: u8, valid_until_sec: u32 },
    Spend { voucher_idx: u8, slot: u8 },
    Retry { voucher_idx: u8, slot: u8 },
    Conflict { voucher_idx: u8, slot: u8, salt: u8 },
    Prune { advance_sec: u32 },
    Reopen,
}

fn arb_storage_op() -> impl Strategy<Value = StorageOp> {
    prop_oneof![
        3 => (0u8..3, 100u32..5_000).prop_map(|(v, vu)| StorageOp::InsertGenesis { voucher_idx: v, valid_until_sec: vu }),
        5 => (0u8..3, 0u8..4).prop_map(|(v, slot)| StorageOp::Spend { voucher_idx: v, slot }),
        2 => (0u8..3, 0u8..4).prop_map(|(v, slot)| StorageOp::Retry { voucher_idx: v, slot }),
        2 => (0u8..3, 0u8..4, 1u8..255).prop_map(|(v, slot, salt)| StorageOp::Conflict { voucher_idx: v, slot, salt }),
        2 => (10u32..500).prop_map(|adv| StorageOp::Prune { advance_sec: adv }),
        1 => Just(StorageOp::Reopen),
    ]
}

fn root_fixture(entry: &L2LockEntry) -> L2LockEntry {
    let mut root = entry.clone();
    root.t_id[0] ^= 0x80;
    root
}

fn make_entry(voucher_id: &str, _parent: [u8; 32], t_id: [u8; 32], valid_until_ms: u64) -> L2LockEntry {
    L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher_id.to_string(),
        t_id,
        sender_ephemeral_pub: [0x55; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x66; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 1000,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: None,
    }
}

async fn execute_stateful_test(ops: Vec<StorageOp>) {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("stateful_property.redb");

    let mut storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (mut engine, mut worker_handle) = DualTierEngine::new(storage.clone());

    // Reference model state
    let mut model_vouchers: HashMap<u8, u64> = HashMap::new(); // voucher_idx -> valid_until_ms
    let mut model_spends: HashMap<String, (u8, [u8; 32], u64)> = HashMap::new(); // tag -> (voucher_idx, t_id, valid_until_ms)
    let mut current_time_ms: u64 = 1_000;

    for op in ops {
        match op {
            StorageOp::InsertGenesis { voucher_idx, valid_until_sec } => {
                let valid_until_ms = current_time_ms + (valid_until_sec as u64) * 1_000;
                let voucher_id = format!("v_{}", voucher_idx);
                let genesis_t_id = *blake3::hash(format!("genesis_{}", voucher_id).as_bytes()).as_bytes();
                let genesis_entry = make_entry(&voucher_id, [0u8; 32], genesis_t_id, valid_until_ms);
                let root = root_fixture(&genesis_entry);

                let (verdict, _) = engine
                    .ingress_hmc_lock_durable(
                        bs58::encode(root.t_id).into_string(),
                        root,
                        IngressOrigin::ClientApi,
                        Some(current_time_ms),
                        Some("Free"),
                        Some(10),
                        Some(voucher_id.clone()),
                    )
                    .await;

                if let std::collections::hash_map::Entry::Vacant(e) = model_vouchers.entry(voucher_idx) {
                    assert!(
                        matches!(verdict, L2Verdict::Verified { .. }),
                        "Fresh genesis must verify, got: {verdict:?}"
                    );
                    e.insert(valid_until_ms);
                }
            }

            StorageOp::Spend { voucher_idx, slot } => {
                if let Some(&voucher_valid_until) = model_vouchers.get(&voucher_idx) {
                    // Check if voucher root is unexpired (with 30s grace)
                    if voucher_valid_until > current_time_ms.saturating_add(30_000) {
                        let tag = format!("spend_tag_{}_{}", voucher_idx, slot);
                        let parent = *blake3::hash(tag.as_bytes()).as_bytes();
                        let t_id = *blake3::hash(format!("{}_spend", tag).as_bytes()).as_bytes();
                        let voucher_id = format!("v_{}", voucher_idx);
                        let entry = make_entry(&voucher_id, parent, t_id, voucher_valid_until);

                        let (verdict, is_new) = engine
                            .ingress_hmc_lock_durable(
                                tag.clone(),
                                entry,
                                IngressOrigin::ClientApi,
                                Some(current_time_ms),
                                Some("Free"),
                                Some(10),
                                Some(voucher_id),
                            )
                            .await;

                        if !model_spends.contains_key(&tag) {
                            assert!(
                                matches!(verdict, L2Verdict::Verified { .. }),
                                "First spend must verify: {verdict:?}"
                            );
                            assert!(is_new, "first spend must be marked new");
                            model_spends.insert(tag.clone(), (voucher_idx, t_id, voucher_valid_until));

                            // Verify RAM and Disk state consistency immediately
                            let ram = engine.hmc_ram.read().await;
                            assert!(ram.locks.contains_key(&tag), "RAM must contain newly spent tag");
                            drop(ram);

                            let disk = storage.get_hmc_lock(&tag).unwrap();
                            assert!(disk.is_some(), "Disk must contain newly spent tag");
                            assert_eq!(disk.unwrap().t_id, t_id, "Disk t_id must match");
                        } else {
                            // Already spent in model: idempotent retry
                            assert!(
                                matches!(verdict, L2Verdict::Verified { .. }),
                                "Re-spending same entry must be verified: {verdict:?}"
                            );
                            assert!(!is_new, "re-spend must not be marked new");
                        }
                    }
                }
            }

            StorageOp::Retry { voucher_idx, slot } => {
                let tag = format!("spend_tag_{}_{}", voucher_idx, slot);
                if let Some(&(_, expected_tid, voucher_valid_until)) = model_spends.get(&tag) {
                    let parent = *blake3::hash(tag.as_bytes()).as_bytes();
                    let voucher_id = format!("v_{}", voucher_idx);
                    let entry = make_entry(&voucher_id, parent, expected_tid, voucher_valid_until);

                    let (verdict, is_new) = engine
                        .ingress_hmc_lock_durable(
                            tag.clone(),
                            entry,
                            IngressOrigin::ClientApi,
                            Some(current_time_ms),
                            Some("Free"),
                            Some(10),
                            Some(voucher_id),
                        )
                        .await;

                    assert!(
                        matches!(verdict, L2Verdict::Verified { .. }),
                        "Idempotent retry must be verified: {verdict:?}"
                    );
                    assert!(!is_new, "idempotent retry must not be is_new");

                    // Assert disk state is unaltered
                    let disk = storage.get_hmc_lock(&tag).unwrap().expect("disk entry must exist");
                    assert_eq!(disk.t_id, expected_tid);
                }
            }

            StorageOp::Conflict { voucher_idx, slot, salt } => {
                let tag = format!("spend_tag_{}_{}", voucher_idx, slot);
                if let Some(&(_, original_tid, voucher_valid_until)) = model_spends.get(&tag) {
                    let parent = *blake3::hash(tag.as_bytes()).as_bytes();
                    let conflicting_tid = *blake3::hash(format!("{}_conflict_{}", tag, salt).as_bytes()).as_bytes();
                    if conflicting_tid != original_tid {
                        let voucher_id = format!("v_{}", voucher_idx);
                        let conflicting_entry = make_entry(&voucher_id, parent, conflicting_tid, voucher_valid_until);

                        let (verdict, is_new) = engine
                            .ingress_hmc_lock_durable(
                                tag.clone(),
                                conflicting_entry,
                                IngressOrigin::ClientApi,
                                Some(current_time_ms),
                                Some("Free"),
                                Some(10),
                                Some(voucher_id),
                            )
                            .await;

                        assert!(
                            matches!(verdict, L2Verdict::Rejected { .. }),
                            "Conflicting double-spend must be rejected: {verdict:?}"
                        );
                        assert!(!is_new);

                        // Assert the original entry was NOT overwritten in RAM or Disk
                        let ram = engine.hmc_ram.read().await;
                        assert_eq!(ram.locks.get(&tag).unwrap().t_id, original_tid);
                        drop(ram);

                        let disk = storage.get_hmc_lock(&tag).unwrap().expect("disk entry must exist");
                        assert_eq!(disk.t_id, original_tid, "Disk must retain original t_id on collision");
                    }
                }
            }

            StorageOp::Prune { advance_sec } => {
                current_time_ms = current_time_ms.saturating_add((advance_sec as u64) * 1_000);
                let _ = engine.prune_expired(SimTime(current_time_ms)).await;

                // Model updates: prune entries where current_time > valid_until + 30_000
                model_spends.retain(|_, (_, _, vu)| current_time_ms <= vu.saturating_add(30_000));
                model_vouchers.retain(|_, vu| current_time_ms <= vu.saturating_add(30_000));

                // Assert RAM and Disk state consistency against model
                let ram = engine.hmc_ram.read().await;
                for (tag, (_, expected_tid, _)) in &model_spends {
                    let ram_entry = ram.locks.get(tag);
                    assert!(ram_entry.is_some(), "unexpired tag {} must be in RAM", tag);
                    assert_eq!(ram_entry.unwrap().t_id, *expected_tid);
                }
            }

            StorageOp::Reopen => {
                // Abort worker and drop existing engine & storage handles
                worker_handle.abort();
                let _ = worker_handle.await;
                drop(engine);
                drop(storage);

                // Reopen RedbStorage and instantiate fresh DualTierEngine
                storage = Arc::new(RedbStorage::open(&db_path).unwrap());
                let (new_engine, new_worker) = DualTierEngine::new(storage.clone());
                engine = new_engine;
                worker_handle = new_worker;

                // Recover state from disk at current simulated time
                let _ = engine.recover_from_disk(SimTime(current_time_ms)).await.unwrap();

                // Assert RAM and Disk consistency after reopen
                let ram = engine.hmc_ram.read().await;
                for (tag, (_, expected_tid, _)) in &model_spends {
                    let ram_entry = ram.locks.get(tag);
                    assert!(
                        ram_entry.is_some(),
                        "Recovered RAM must contain active spend: {}",
                        tag
                    );
                    assert_eq!(ram_entry.unwrap().t_id, *expected_tid);

                    let disk_entry = storage.get_hmc_lock(tag).unwrap();
                    assert!(
                        disk_entry.is_some(),
                        "Disk must contain active spend: {}",
                        tag
                    );
                    assert_eq!(disk_entry.unwrap().t_id, *expected_tid);
                }
            }
        }
    }

    worker_handle.abort();
    let _ = worker_handle.await;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(15))]

    #[test]
    fn prop_dual_tier_storage_model_consistency(
        ops in prop::collection::vec(arb_storage_op(), 5..20),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(execute_stateful_test(ops));
    }
}
