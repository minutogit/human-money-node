use humoco_sim_core::crypto::compute_canonical_hash;
use humoco_sim_core::resolver::{resolve_split_brain, ResolutionResult};
use humoco_sim_core::types::{LockRecord, SimTime};

#[test]
fn test_canon_resolver_deterministic_choice() {
    let parent_lock = [0xAA; 32];

    let receiver_a = [0x01; 32];
    let receiver_b = [0x02; 32];

    let nonce_a = b"branch_alpha".to_vec();
    let nonce_b = b"branch_beta".to_vec();

    let mut lock_a = LockRecord::new(
        parent_lock,
        receiver_a,
        nonce_a.clone(),
        SimTime(0),
        SimTime(10_000),
    );
    let mut lock_b = LockRecord::new(
        parent_lock,
        receiver_b,
        nonce_b.clone(),
        SimTime(0),
        SimTime(10_000),
    );

    let h_a = compute_canonical_hash(&parent_lock, &receiver_a, &nonce_a);
    let h_b = compute_canonical_hash(&parent_lock, &receiver_b, &nonce_b);

    assert_ne!(h_a, h_b);

    let res = resolve_split_brain(&mut lock_a, &mut lock_b);

    if h_a < h_b {
        assert_eq!(
            res,
            ResolutionResult::WinnerA {
                winner_hash: h_a,
                loser_hash: h_b
            }
        );
        assert!(!lock_a.status.is_void());
        assert!(lock_b.status.is_void());
    } else {
        assert_eq!(
            res,
            ResolutionResult::WinnerB {
                winner_hash: h_b,
                loser_hash: h_a
            }
        );
        assert!(lock_a.status.is_void());
        assert!(!lock_b.status.is_void());
    }
}

#[test]
fn test_canon_resolver_order_independence() {
    let parent_lock = [0xBB; 32];

    let receiver_a = [0x11; 32];
    let receiver_b = [0x22; 32];

    // Scenario 1: A first, B second
    let mut lock_a1 = LockRecord::new(
        parent_lock,
        receiver_a,
        b"salt1".to_vec(),
        SimTime(0),
        SimTime(5000),
    );
    let mut lock_b1 = LockRecord::new(
        parent_lock,
        receiver_b,
        b"salt2".to_vec(),
        SimTime(0),
        SimTime(5000),
    );
    let res1 = resolve_split_brain(&mut lock_a1, &mut lock_b1);

    // Scenario 2: B first, A second
    let mut lock_a2 = LockRecord::new(
        parent_lock,
        receiver_a,
        b"salt1".to_vec(),
        SimTime(0),
        SimTime(5000),
    );
    let mut lock_b2 = LockRecord::new(
        parent_lock,
        receiver_b,
        b"salt2".to_vec(),
        SimTime(0),
        SimTime(5000),
    );
    let res2 = resolve_split_brain(&mut lock_b2, &mut lock_a2);

    match (res1, res2) {
        (
            ResolutionResult::WinnerA {
                winner_hash: w1, ..
            },
            ResolutionResult::WinnerB {
                winner_hash: w2, ..
            },
        ) => {
            // In Scenario 1, A was first param (WinnerA). In Scenario 2, A was second param (WinnerB).
            assert_eq!(w1, w2);
            assert!(!lock_a1.status.is_void());
            assert!(lock_b1.status.is_void());
            assert!(!lock_a2.status.is_void());
            assert!(lock_b2.status.is_void());
        }
        (
            ResolutionResult::WinnerB {
                winner_hash: w1, ..
            },
            ResolutionResult::WinnerA {
                winner_hash: w2, ..
            },
        ) => {
            // In Scenario 1, B won (WinnerB). In Scenario 2, B was first param (WinnerA).
            assert_eq!(w1, w2);
            assert!(lock_a1.status.is_void());
            assert!(!lock_b1.status.is_void());
            assert!(lock_a2.status.is_void());
            assert!(!lock_b2.status.is_void());
        }
        _ => panic!("Order independence violated!"),
    }
}

#[test]
fn test_canon_resolver_idempotent_duplicate() {
    let parent_lock = [0xCC; 32];
    let receiver = [0xDD; 32];
    let mut lock1 = LockRecord::new(
        parent_lock,
        receiver,
        b"identical".to_vec(),
        SimTime(0),
        SimTime(5000),
    );
    let mut lock2 = lock1.clone();

    let res = resolve_split_brain(&mut lock1, &mut lock2);
    assert_eq!(res, ResolutionResult::Identical);
    assert!(!lock1.status.is_void());
    assert!(!lock2.status.is_void());
}
