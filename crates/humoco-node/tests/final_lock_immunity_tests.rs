#![forbid(unsafe_code)]

//! Integration tests for Certified FINAL Lock Immunity (Spec 02, 08, Pillar 4, INV-0206).
//!
//! Validates:
//! 1. A certified FINAL lock (confirmation class 2) strictly refuses overwrite by an
//!    unquorated / provisional lock (class 0 or 1), even if the provisional lock has
//!    a strictly lower canonical hash (H_canon(Rogue) < H_canon(Final)).
//! 2. Conversely, a certified FINAL lock arriving via P2P sync successfully displaces a
//!    provisional lock (class 0 or 1), even if the provisional lock had a lower canonical hash.
//! 3. When both locks are provisional (equal class 1), min(H_canon) resolves deterministically.
//! 4. If two FINAL locks collide (equal class 2 Byzantine equivocation), min(H_canon) acts as the deterministic tie-breaker.

use std::sync::Arc;
use tempfile::tempdir;

use ed25519_dalek::{Signer, SigningKey};
use humoco_node::api::hmc::{L2LockEntry, L2Verdict};
use humoco_node::storage::engine::compute_hmc_canonical_hash;
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};

const VOUCHER: &str = "final-immunity-voucher";
const COLLIDE_TAG: &str = "final-collide-tag";
const ROOT_TTL_MS: u64 = 200_000;

async fn setup_engine() -> (DualTierEngine, tempfile::TempDir) {
    let temp = tempdir().expect("tempdir");
    let storage =
        Arc::new(RedbStorage::open(&temp.path().join("final_immunity.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage);

    // Anchor genesis root
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let mut genesis = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: VOUCHER.into(),
        t_id: [11u8; 32],
        sender_ephemeral_pub: key.verifying_key().to_bytes(),
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1,
        created_at_ms: 1_000,
        deletable_at: Some(ROOT_TTL_MS.to_string()),
        privacy_guard: None,
    };
    let tag = bs58::encode(genesis.t_id).into_string();
    genesis.layer2_signature = key
        .sign(&humoco_node::api::hmc::calculate_l2_payload_hash_for_entry(
            &genesis, &tag,
        ))
        .to_bytes();
    engine.ingress_hmc_lock(tag, genesis).await;
    (engine, temp)
}

fn signed_spend(t_id: [u8; 32], key: &SigningKey) -> L2LockEntry {
    let mut entry = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: VOUCHER.into(),
        t_id,
        sender_ephemeral_pub: key.verifying_key().to_bytes(),
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1,
        created_at_ms: 1_000,
        deletable_at: None,
        privacy_guard: None,
    };
    entry.layer2_signature = key
        .sign(&humoco_node::api::hmc::calculate_l2_payload_hash_for_entry(
            &entry,
            COLLIDE_TAG,
        ))
        .to_bytes();
    entry
}

fn ordered_collision_pair() -> (L2LockEntry, L2LockEntry) {
    let key = SigningKey::from_bytes(&[88u8; 32]);
    let a = signed_spend([1u8; 32], &key);
    let b = signed_spend([2u8; 32], &key);
    let parent_bytes = *blake3::hash(COLLIDE_TAG.as_bytes()).as_bytes();
    let h_a = compute_hmc_canonical_hash(&parent_bytes, &a.sender_ephemeral_pub, &a.t_id);
    let h_b = compute_hmc_canonical_hash(&parent_bytes, &b.sender_ephemeral_pub, &b.t_id);
    if h_a < h_b {
        (a, b)
    } else {
        (b, a)
    }
}

async fn ingress_with_class(
    engine: &DualTierEngine,
    entry: L2LockEntry,
    class: u8,
) -> (L2Verdict, bool) {
    engine
        .hmc_ram
        .write()
        .await
        .insert_or_check_with_class(
            COLLIDE_TAG.to_string(),
            entry,
            IngressOrigin::PartitionSync,
            None,
            class,
        )
}

#[tokio::test]
async fn test_final_lock_immune_to_unquorated_lower_hash_displacement() {
    let (engine, _temp) = setup_engine().await;
    let (low_h, high_h) = ordered_collision_pair();

    // 1. Ingest certified FINAL lock (high_h, class 2)
    let (v1, is_new) = ingress_with_class(&engine, high_h.clone(), 2).await;
    assert!(matches!(v1, L2Verdict::Verified { .. }));
    assert!(is_new);

    // 2. Incoming provisional/unquorated rogue lock with lower canonical hash (low_h, class 1)
    let (v2, displaced) = ingress_with_class(&engine, low_h, 1).await;
    assert!(
        matches!(v2, L2Verdict::Conflict { .. }),
        "Certified FINAL lock (class 2) must refuse overwrite by lower class even with lower H_canon"
    );
    assert!(!displaced);

    // 3. Verify RAM still holds the certified FINAL lock
    let ram = engine.hmc_ram.read().await;
    assert_eq!(ram.locks().get(COLLIDE_TAG).unwrap().t_id, high_h.t_id);
    assert_eq!(ram.get_confirmation_class(COLLIDE_TAG), 2);
}

#[tokio::test]
async fn test_final_lock_displaces_provisional_lock_with_lower_hash() {
    let (engine, _temp) = setup_engine().await;
    let (low_h, high_h) = ordered_collision_pair();

    // 1. Ingest provisional lock with lower canonical hash (low_h, class 1)
    let (v1, is_new) = ingress_with_class(&engine, low_h, 1).await;
    assert!(matches!(v1, L2Verdict::Verified { .. }));
    assert!(is_new);

    // 2. Certified FINAL lock arrives (high_h, class 2) with higher canonical hash
    let (v2, displaced) = ingress_with_class(&engine, high_h.clone(), 2).await;
    assert!(
        matches!(v2, L2Verdict::Verified { .. }),
        "Certified FINAL lock (class 2) must displace provisional lock (class 1)"
    );
    assert!(displaced);

    // 3. RAM now holds the certified FINAL lock
    let ram = engine.hmc_ram.read().await;
    assert_eq!(ram.locks().get(COLLIDE_TAG).unwrap().t_id, high_h.t_id);
    assert_eq!(ram.get_confirmation_class(COLLIDE_TAG), 2);
}

#[tokio::test]
async fn test_two_provisional_locks_split_brain_uses_min_canonical_hash() {
    let (engine, _temp) = setup_engine().await;
    let (low_h, high_h) = ordered_collision_pair();

    // Ingest high_h first at class 1
    let (v1, is_new) = ingress_with_class(&engine, high_h, 1).await;
    assert!(matches!(v1, L2Verdict::Verified { .. }));
    assert!(is_new);

    // low_h arrives at same class 1 -> min(H_canon) tie-breaker wins and displaces high_h
    let (v2, displaced) = ingress_with_class(&engine, low_h.clone(), 1).await;
    assert!(matches!(v2, L2Verdict::Verified { .. }));
    assert!(displaced);

    let ram = engine.hmc_ram.read().await;
    assert_eq!(ram.locks().get(COLLIDE_TAG).unwrap().t_id, low_h.t_id);
}

#[tokio::test]
async fn test_two_final_locks_equivocation_uses_min_canonical_hash() {
    let (engine, _temp) = setup_engine().await;
    let (low_h, high_h) = ordered_collision_pair();

    // Ingest high_h first at class 2
    let (v1, is_new) = ingress_with_class(&engine, high_h, 2).await;
    assert!(matches!(v1, L2Verdict::Verified { .. }));
    assert!(is_new);

    // low_h arrives at same class 2 -> min(H_canon) tie-breaker wins and displaces high_h
    let (v2, displaced) = ingress_with_class(&engine, low_h.clone(), 2).await;
    assert!(matches!(v2, L2Verdict::Verified { .. }));
    assert!(displaced);

    let ram = engine.hmc_ram.read().await;
    assert_eq!(ram.locks().get(COLLIDE_TAG).unwrap().t_id, low_h.t_id);
}
