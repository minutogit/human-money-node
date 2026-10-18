#![forbid(unsafe_code)]

//! Integration tests for Certified FINAL Lock Immunity (Spec 02, 08, Pillar 4, INV-0206).
//!
//! Validates:
//! 1. A certified FINAL lock (14/20 quorum, status = LockStatus::Final { sigs: 14 })
//!    strictly refuses overwrite by an unquorated / provisional rogue lock, even if the
//!    unquorated lock has a strictly lower canonical hash (H_canon(Rogue) < H_canon(Final)).
//! 2. Conversely, a certified FINAL lock arriving via P2P sync successfully displaces a
//!    provisional / unquorated lock, even if the provisional lock had a lower canonical hash.
//! 3. When both locks are provisional (sub-quorum split), min(H_canon) resolves deterministically.
//! 4. If two FINAL locks collide (Byzantine equivocation), min(H_canon) acts as the deterministic tie-breaker.

use std::sync::Arc;
use tempfile::tempdir;

use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};
use humoco_sim_core::crypto::compute_canonical_hash;
use humoco_sim_core::resolver::{resolve_split_brain_canonical, ResolutionResult};
use humoco_sim_core::types::{Hash256, LockRecord, LockStatus, SimTime};
use humoco_sim_core::IngressVerdictLow;

fn make_test_lock(
    parent_lock: Hash256,
    receiver_pub: Hash256,
    nonce: [u8; 32],
    now: SimTime,
    valid_until: SimTime,
    status: LockStatus,
) -> LockRecord {
    let mut rec = LockRecord::new(parent_lock, receiver_pub, nonce.to_vec(), now, valid_until);
    rec.status = status;
    rec
}

#[tokio::test]
async fn test_final_lock_immune_to_unquorated_lower_hash_displacement() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("final_immunity.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage);

    let parent_lock: Hash256 = [0xAAu8; 32];
    let receiver_pub: Hash256 = [0xBBu8; 32];
    let now = SimTime(100_000);
    let valid_until = SimTime(200_000);
    let root_valid_until = SimTime(300_000);

    // Pick two nonces such that H_canon(Rogue) < H_canon(Final)
    let mut nonce_final: Hash256 = [0x11u8; 32];
    let mut nonce_rogue: Hash256 = [0x22u8; 32];

    let mut h_final = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_final);
    let mut h_rogue = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_rogue);

    // Ensure h_rogue < h_final (Rogue lock has lower canonical hash)
    if h_final < h_rogue {
        std::mem::swap(&mut nonce_final, &mut nonce_rogue);
        std::mem::swap(&mut h_final, &mut h_rogue);
    }
    assert!(
        h_rogue < h_final,
        "Precondition: Rogue lock must have lower canonical hash than Final lock"
    );

    let final_lock = make_test_lock(
        parent_lock,
        receiver_pub,
        nonce_final,
        now,
        valid_until,
        LockStatus::Final { sigs: 14 },
    );
    let final_lock_id = final_lock.id;

    let mut rogue_lock = make_test_lock(
        parent_lock,
        receiver_pub,
        nonce_rogue,
        now,
        valid_until,
        LockStatus::Provisional { sigs: 3, required: 14 },
    );
    let rogue_lock_id = rogue_lock.id;

    // 1. Ingest certified FINAL lock into engine
    let res = engine
        .ingress_lock_with_origin(
            final_lock.clone(),
            now,
            root_valid_until,
            IngressOrigin::ClientApi,
        )
        .await;
    assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew));

    // Verify FINAL lock is in RAM
    let ram_lock = engine.get_ram_lock(&parent_lock).await.expect("final lock in ram");
    assert_eq!(ram_lock.id, final_lock_id);
    assert!(ram_lock.status.is_final());

    // 2. Direct resolver verification (INV-0206):
    // Even though h_rogue < h_final, resolve_split_brain MUST crown final_lock as WinnerA
    let mut final_copy = final_lock.clone();
    let res_split = resolve_split_brain_canonical(&mut final_copy, &mut rogue_lock, None, None);
    assert_eq!(
        res_split,
        ResolutionResult::WinnerA {
            winner_hash: h_final,
            loser_hash: h_rogue,
        },
        "Finality immunity: Certified FINAL lock must defeat rogue lock with lower hash"
    );
    assert!(
        matches!(rogue_lock.status, LockStatus::Void { .. }),
        "Rogue lock must be set to Void"
    );

    // 3. Engine P2P sync verification:
    // Sync rogue lock with lower hash into node holding FINAL lock
    let sync_res = engine
        .ingress_lock_with_origin(
            rogue_lock.clone(),
            now,
            root_valid_until,
            IngressOrigin::PartitionSync,
        )
        .await;
    assert_eq!(
        sync_res,
        Err(IngressVerdictLow::RejectedCollision),
        "Engine must strictly refuse overwrite of certified FINAL lock by rogue lock"
    );

    // 4. Verify RAM state is immutable: still holds final_lock_id, never rogue_lock_id
    let ram_after = engine.get_ram_lock(&parent_lock).await.expect("final lock in ram");
    assert_eq!(
        ram_after.id, final_lock_id,
        "RAM index must still hold certified FINAL lock"
    );
    assert_ne!(
        ram_after.id, rogue_lock_id,
        "RAM index must NEVER be overwritten by rogue lock"
    );
    assert!(ram_after.status.is_final());
}

#[tokio::test]
async fn test_final_lock_displaces_provisional_lock_with_lower_hash() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("final_displaces.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage);

    let parent_lock: Hash256 = [0xCCu8; 32];
    let receiver_pub: Hash256 = [0xDDu8; 32];
    let now = SimTime(100_000);
    let valid_until = SimTime(200_000);
    let root_valid_until = SimTime(300_000);

    let mut nonce_prov: Hash256 = [0x11u8; 32];
    let mut nonce_final: Hash256 = [0x22u8; 32];

    let mut h_prov = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_prov);
    let mut h_final = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_final);

    // Ensure h_prov < h_final (Provisional lock has lower hash!)
    if h_final < h_prov {
        std::mem::swap(&mut nonce_prov, &mut nonce_final);
        std::mem::swap(&mut h_prov, &mut h_final);
    }
    assert!(h_prov < h_final);

    let prov_lock = make_test_lock(
        parent_lock,
        receiver_pub,
        nonce_prov,
        now,
        valid_until,
        LockStatus::Provisional { sigs: 7, required: 14 },
    );
    let prov_lock_id = prov_lock.id;

    let final_lock = make_test_lock(
        parent_lock,
        receiver_pub,
        nonce_final,
        now,
        valid_until,
        LockStatus::Final { sigs: 14 },
    );
    let final_lock_id = final_lock.id;

    // 1. Node initially accepted Provisional lock (sigs = 7)
    let res = engine
        .ingress_lock_with_origin(
            prov_lock.clone(),
            now,
            root_valid_until,
            IngressOrigin::ClientApi,
        )
        .await;
    assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew));
    assert_eq!(engine.get_ram_lock(&parent_lock).await.unwrap().id, prov_lock_id);

    // 2. Incoming sync brings certified FINAL lock from global network (14 sigs)
    let sync_res = engine
        .ingress_lock_with_origin(
            final_lock.clone(),
            now,
            root_valid_until,
            IngressOrigin::PartitionSync,
        )
        .await;
    assert_eq!(
        sync_res,
        Ok(IngressVerdictLow::AcceptedNew),
        "Certified FINAL lock must displace provisional lock even though provisional had lower hash"
    );

    // 3. RAM index now holds the certified FINAL lock
    let ram_after = engine.get_ram_lock(&parent_lock).await.unwrap();
    assert_eq!(ram_after.id, final_lock_id);
    assert!(ram_after.status.is_final());
}

#[tokio::test]
async fn test_two_provisional_locks_split_brain_uses_min_canonical_hash() {
    let parent_lock: Hash256 = [0xEEu8; 32];
    let receiver_pub: Hash256 = [0xFFu8; 32];
    let now = SimTime(100_000);
    let valid_until = SimTime(200_000);

    let mut nonce_a: Hash256 = [0x01u8; 32];
    let mut nonce_b: Hash256 = [0x02u8; 32];

    let mut h_a = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_a);
    let mut h_b = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_b);

    if h_b < h_a {
        std::mem::swap(&mut nonce_a, &mut nonce_b);
        std::mem::swap(&mut h_a, &mut h_b);
    }
    assert!(h_a < h_b);

    let mut lock_a = make_test_lock(
        parent_lock,
        receiver_pub,
        nonce_a,
        now,
        valid_until,
        LockStatus::Provisional { sigs: 7, required: 14 },
    );
    let mut lock_b = make_test_lock(
        parent_lock,
        receiver_pub,
        nonce_b,
        now,
        valid_until,
        LockStatus::Provisional { sigs: 13, required: 14 },
    );

    let res = resolve_split_brain_canonical(&mut lock_a, &mut lock_b, None, None);
    assert_eq!(
        res,
        ResolutionResult::WinnerA {
            winner_hash: h_a,
            loser_hash: h_b,
        }
    );
    assert!(matches!(lock_b.status, LockStatus::Void { .. }));
}

#[tokio::test]
async fn test_two_final_locks_equivocation_uses_min_canonical_hash() {
    let parent_lock: Hash256 = [0x12u8; 32];
    let receiver_pub: Hash256 = [0x34u8; 32];
    let now = SimTime(100_000);
    let valid_until = SimTime(200_000);

    let mut nonce_a: Hash256 = [0x05u8; 32];
    let mut nonce_b: Hash256 = [0x06u8; 32];

    let mut h_a = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_a);
    let mut h_b = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_b);

    if h_b < h_a {
        std::mem::swap(&mut nonce_a, &mut nonce_b);
        std::mem::swap(&mut h_a, &mut h_b);
    }
    assert!(h_a < h_b);

    let mut lock_a = make_test_lock(
        parent_lock,
        receiver_pub,
        nonce_a,
        now,
        valid_until,
        LockStatus::Final { sigs: 14 },
    );
    let mut lock_b = make_test_lock(
        parent_lock,
        receiver_pub,
        nonce_b,
        now,
        valid_until,
        LockStatus::Final { sigs: 14 },
    );

    let res = resolve_split_brain_canonical(&mut lock_a, &mut lock_b, None, None);
    assert_eq!(
        res,
        ResolutionResult::WinnerA {
            winner_hash: h_a,
            loser_hash: h_b,
        }
    );
    assert!(matches!(lock_b.status, LockStatus::Void { .. }));
}
