#![forbid(unsafe_code)]

//! Certified Epoch Handoff (CEH) Dual-Store Isolation and Genesis Handshake Guard Tests.
//!
//! Validates:
//! - INV-CEH-01: Dual-store zero contamination (provisional locks never leak into finalized state roots).
//! - INV-CEH-02: Causal completeness for finality (predecessors must be finalized before children).
//! - INV-CEH-03: Atomic promotion from provisional to final tier.
//! - INV-CEH-04: Incompatible genesis handshake rejection.
//! - INV-CEH-05: Island node pioneer genesis adoption under 14/20 quorum.

use ed25519_dalek::SigningKey;
use humoco_sim_core::ceh::*;
use humoco_sim_core::storage::{DualRamIndex, IngressVerdictLow, LockTier};
use humoco_sim_core::types::{LockRecord, NodePubKey, SimTime};

fn generate_keypair(seed: u8) -> (SigningKey, NodePubKey) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = seed;
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let pubkey = signing_key.verifying_key().to_bytes();
    (signing_key, pubkey)
}

fn generate_committee(
    start_seed: u8,
) -> (
    [SigningKey; CEH_COMMITTEE_SIZE],
    [NodePubKey; CEH_COMMITTEE_SIZE],
) {
    let mut signers = Vec::with_capacity(CEH_COMMITTEE_SIZE);
    let mut pubkeys = Vec::with_capacity(CEH_COMMITTEE_SIZE);
    for i in 0..CEH_COMMITTEE_SIZE {
        let (sk, pk) = generate_keypair(start_seed.wrapping_add(i as u8));
        signers.push(sk);
        pubkeys.push(pk);
    }
    (
        signers.try_into().map_err(|_| ()).expect("committee signers"),
        pubkeys.try_into().map_err(|_| ()).expect("committee pubkeys"),
    )
}

fn snapshot_from_records<'a>(
    records: impl Iterator<Item = &'a LockRecord>,
    shard_id: u16,
    epoch: u64,
) -> HierarchicalShardSnapshot {
    let mut snapshot = HierarchicalShardSnapshot::new(shard_id, epoch);
    for rec in records {
        let hop = VoucherHop::direct(rec.parent_lock, rec.id, rec.valid_until.0);
        let mut tree = VoucherSplitTree::new(rec.parent_lock);
        tree.add_hop(hop);
        snapshot.insert_tree(tree);
    }
    snapshot
}

/// Test 1: Zero Contamination
///
/// Insert 20 final locks into `DualRamIndex`, build `HierarchicalShardSnapshot` from `final_records()`,
/// compute `closed_state_root`. Insert 50 provisional locks. Recompute `closed_state_root`
/// from `final_records()`. Assert hashes match 100% byte-for-byte.
#[test]
fn test_inv_ceh_01_dual_store_zero_contamination() {
    let mut dual_ram = DualRamIndex::new();
    let now = SimTime(1000);
    let root_valid_until = SimTime(1_000_000);
    let valid_until = SimTime(500_000);

    // Insert 20 final locks
    for i in 1..=20u8 {
        let mut parent = [0u8; 32];
        parent[0] = i;
        let rec = LockRecord::new(parent, [0xAA; 32], vec![i], now, valid_until);
        let res = dual_ram.insert_final(rec, now, root_valid_until, true);
        assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew));
    }
    assert_eq!(dual_ram.final_len(), 20);
    assert_eq!(dual_ram.provisional_len(), 0);

    // Snapshot from finalized records and initial closed state root
    let snap_before = snapshot_from_records(dual_ram.final_records(), 0, 1);
    let root_before = snap_before.compute_hierarchical_closed_state_root();

    // Insert 50 provisional locks
    for j in 1..=50u8 {
        let mut parent = [0u8; 32];
        parent[0] = 100 + j;
        let rec = LockRecord::new(parent, [0xBB; 32], vec![j], now, valid_until);
        let res = dual_ram.insert_provisional(rec, now, root_valid_until);
        assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew));
    }
    assert_eq!(dual_ram.final_len(), 20);
    assert_eq!(dual_ram.provisional_len(), 50);

    // Recompute state root from finalized records
    let snap_after = snapshot_from_records(dual_ram.final_records(), 0, 1);
    let root_after = snap_after.compute_hierarchical_closed_state_root();

    // Verify 100% byte-for-byte state root isolation
    assert_eq!(
        root_before, root_after,
        "Provisional locks must not contaminate finalized closed state root"
    );
}

/// Test 2: Causal Completeness for Finality
///
/// Insert parent L1 into `provisional_index`.
/// Attempt to insert child L2 into `final_index` with `is_root = false` -> must fail with `CausalPredecessorNotFinal`.
/// Promote L1 to final with `is_root = true` -> succeeds.
/// Now insert child L2 into `final_index` with `is_root = false` -> succeeds!
#[test]
fn test_inv_ceh_02_causal_completeness_for_finality() {
    let mut dual_ram = DualRamIndex::new();
    let now = SimTime(1000);
    let root_valid_until = SimTime(1_000_000);
    let valid_until = SimTime(500_000);

    // Parent L1
    let parent_l1 = [0x11; 32];
    let l1 = LockRecord::new(parent_l1, [0x01; 32], vec![1], now, valid_until);
    let verdict = dual_ram.insert_provisional(l1.clone(), now, root_valid_until);
    assert_eq!(verdict, Ok(IngressVerdictLow::AcceptedNew));
    assert!(dual_ram.is_provisional(&parent_l1));
    assert!(!dual_ram.is_final(&parent_l1));

    // Child L2 spending L1
    let l2_parent = l1.id;
    let l2 = LockRecord::new(l2_parent, [0x02; 32], vec![2], now, valid_until);

    // Attempt to insert child L2 into final_index with is_root = false -> must fail with CausalPredecessorNotFinal
    let res = dual_ram.insert_final(l2.clone(), now, root_valid_until, false);
    assert_eq!(res, Err(CehError::CausalPredecessorNotFinal(l2_parent)));
    assert!(!dual_ram.is_final(&l2_parent));

    // Promote L1 to final with is_root = true -> succeeds
    let promoted = dual_ram.promote_to_final(&parent_l1, now, root_valid_until, true);
    assert!(promoted.is_ok());
    assert_eq!(promoted.unwrap().id, l1.id);
    assert!(dual_ram.is_final(&parent_l1));
    assert!(!dual_ram.is_provisional(&parent_l1));

    // Now insert child L2 into final_index with is_root = false -> succeeds!
    let res2 = dual_ram.insert_final(l2.clone(), now, root_valid_until, false);
    assert_eq!(res2, Ok(IngressVerdictLow::AcceptedNew));
    assert!(dual_ram.is_final(&l2_parent));
}

/// Test 3: Atomic Promotion
///
/// Test provisional insertion, followed by promotion, verifying `is_final` becomes true
/// and `is_provisional` becomes false.
#[test]
fn test_inv_ceh_03_atomic_promotion() {
    let mut dual_ram = DualRamIndex::new();
    let now = SimTime(1000);
    let root_valid_until = SimTime(1_000_000);
    let valid_until = SimTime(500_000);

    let parent = [0x42; 32];
    let rec = LockRecord::new(parent, [0x99; 32], vec![42], now, valid_until);

    // Provisional insertion
    let verdict = dual_ram.insert_provisional(rec.clone(), now, root_valid_until);
    assert_eq!(verdict, Ok(IngressVerdictLow::AcceptedNew));

    assert!(dual_ram.is_provisional(&parent));
    assert!(!dual_ram.is_final(&parent));
    assert_eq!(dual_ram.get(&parent), Some((&rec, LockTier::Provisional)));

    // Promotion to final
    let promoted = dual_ram
        .promote_to_final(&parent, now, root_valid_until, true)
        .expect("promotion succeeds");
    assert_eq!(promoted.id, rec.id);

    // Verify is_final becomes true and is_provisional becomes false
    assert!(dual_ram.is_final(&parent));
    assert!(!dual_ram.is_provisional(&parent));
    assert_eq!(dual_ram.get(&parent), Some((&rec, LockTier::Final)));
}

/// Test 4: Incompatible Genesis Handshake Reject
///
/// Two distinct `GenesisManifest`s with different committees.
/// `verify_handshake_genesis(Some(&g1), Some(&g2))` returns `Err(CehError::IncompatibleGenesisManifest { .. })`.
#[test]
fn test_inv_ceh_04_genesis_handshake_incompatible_reject() {
    let (_, comm1) = generate_committee(1);
    let (_, comm2) = generate_committee(21);

    let g1 = GenesisManifest::new(1, [0x01; 32], 1_700_000_000, comm1);
    let g2 = GenesisManifest::new(1, [0x02; 32], 1_700_000_000, comm2);

    let res = verify_handshake_genesis(Some(&g1), Some(&g2));
    assert_eq!(
        res,
        Err(CehError::IncompatibleGenesisManifest {
            local: g1.canonical_hash(),
            remote: g2.canonical_hash(),
        })
    );

    // Same manifests must succeed with Ok(None)
    assert_eq!(verify_handshake_genesis(Some(&g1), Some(&g1)), Ok(None));
}

/// Test 5: Genesis Pioneer Adoption
///
/// Island node (`local = None`), remote has valid `GenesisManifest` with 14 pioneer signatures.
/// `verify_handshake_genesis(None, Some(&pioneer_g))` returns `Ok(Some(pioneer_g))`.
#[test]
fn test_inv_ceh_05_genesis_pioneer_adoption() {
    let (signers, committee) = generate_committee(10);
    let mut pioneer_g = GenesisManifest::new(1, [0xAA; 32], 1_700_000_000, committee);

    // 14 pioneer signatures (CEH_BFT_QUORUM)
    for sk in signers.iter().take(CEH_BFT_QUORUM) {
        let (pk, sig) = sign_genesis_manifest(sk, &pioneer_g);
        pioneer_g.add_signature(pk, sig);
    }

    // Island node (local = None), remote has valid pioneer_g
    let res = verify_handshake_genesis(None, Some(&pioneer_g));
    assert_eq!(res, Ok(Some(pioneer_g.clone())));

    // Counter-test: fewer than 14 signatures fails quorum
    let mut insufficient_g = pioneer_g.clone();
    insufficient_g.genesis_signatures.truncate(CEH_BFT_QUORUM - 1);
    let res_fail = verify_handshake_genesis(None, Some(&insufficient_g));
    assert!(matches!(
        res_fail,
        Err(CehError::QuorumNotReached { have: 13, required: 14 })
    ));

    // Both None -> Ok(None)
    assert_eq!(verify_handshake_genesis(None, None), Ok(None));

    // Local Some, remote None -> Ok(None)
    assert_eq!(verify_handshake_genesis(Some(&pioneer_g), None), Ok(None));
}
