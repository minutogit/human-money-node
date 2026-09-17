use humoco_sim_core::crypto::{compute_canonical_hash, sign_lock_attestation};
use humoco_sim_core::resolver::{resolve_split_brain_with_proof, ResolutionResult};
use humoco_sim_core::state_machine::apply_fraud_proof;
use humoco_sim_core::types::{LockRecord, SimTime};
use std::collections::HashSet;

#[test]
fn test_split_brain_symmetric_double_spend_resolution() {
    let parent = [0x5A; 32];
    let recv_a = [0xAA; 32];
    let recv_b = [0xBB; 32];
    let nonce_a = b"branch_a".to_vec();
    let nonce_b = b"branch_b".to_vec();

    let mut lock_a = LockRecord::new(parent, recv_a, nonce_a.clone(), SimTime(0), SimTime(50_000));
    let mut lock_b = LockRecord::new(parent, recv_b, nonce_b.clone(), SimTime(0), SimTime(50_000));

    let h_a = compute_canonical_hash(&parent, &recv_a, &nonce_a);
    let h_b = compute_canonical_hash(&parent, &recv_b, &nonce_b);
    let expected_winner_is_a = h_a < h_b;

    // No attestations needed for basic resolution
    let (res, proofs) = resolve_split_brain_with_proof(&mut lock_a, &mut lock_b, &[], &[]);
    assert!(proofs.is_empty(), "No equivocation without overlapping signers");

    match res {
        ResolutionResult::WinnerA { winner_hash, loser_hash } => {
            assert!(expected_winner_is_a, "Expected A to win via min(H_canon)");
            assert_eq!(winner_hash, h_a);
            assert_eq!(loser_hash, h_b);
            assert!(!lock_a.status.is_void(), "Winner must stay active");
            assert!(lock_b.status.is_void(), "Loser must be VOID");
        }
        ResolutionResult::WinnerB { winner_hash, loser_hash } => {
            assert!(!expected_winner_is_a, "Expected B to win via min(H_canon)");
            assert_eq!(winner_hash, h_b);
            assert_eq!(loser_hash, h_a);
            assert!(lock_a.status.is_void(), "Loser must be VOID");
            assert!(!lock_b.status.is_void(), "Winner must stay active");
        }
        _ => panic!("Expected WinnerA or WinnerB"),
    }
}

#[test]
fn test_equivocation_proof_generation_and_o1_slashing() {
    let parent = [0x5A; 32];
    let recv_a = [0xAA; 32];
    let recv_b = [0xBB; 32];
    let nonce_a = b"branch_a_proof".to_vec();
    let nonce_b = b"branch_b_proof".to_vec();

    let mut lock_a = LockRecord::new(parent, recv_a, nonce_a.clone(), SimTime(0), SimTime(50_000));
    let mut lock_b = LockRecord::new(parent, recv_b, nonce_b.clone(), SimTime(0), SimTime(50_000));

    let lock_a_id = lock_a.id;
    let lock_b_id = lock_b.id;

    // Attestations: nodes 1,2,3 sign both locks; node 4 only signs A, node 5 only B
    // Doppel-Signierer = 1,2,3 -> 3 equivocation proofs expected
    let mut atts_a = Vec::new();
    let mut atts_b = Vec::new();
    for nid in [1u16, 2, 3] {
        atts_a.push(sign_lock_attestation(nid, &lock_a_id, &parent, SimTime(10)));
        atts_b.push(sign_lock_attestation(nid, &lock_b_id, &parent, SimTime(10)));
    }
    atts_a.push(sign_lock_attestation(4, &lock_a_id, &parent, SimTime(10)));
    atts_b.push(sign_lock_attestation(5, &lock_b_id, &parent, SimTime(10)));

    let (res, proofs) = resolve_split_brain_with_proof(&mut lock_a, &mut lock_b, &atts_a, &atts_b);

    assert!(
        matches!(res, ResolutionResult::WinnerA { .. } | ResolutionResult::WinnerB { .. }),
        "Should have a winner"
    );
    assert_eq!(proofs.len(), 3, "Should generate 3 equivocation proofs for nodes 1,2,3");

    // Verify each proof is valid and slashing is O(1)
    let mut banned: HashSet<u16> = HashSet::new();
    for proof in &proofs {
        assert!(proof.verify(), "Proof must verify");
        let was_banned = apply_fraud_proof(proof, &mut banned);
        assert!(was_banned, "apply_fraud_proof must succeed");
        // O(1) check: banned set contains perpetrator
        assert!(banned.contains(&proof.perpetrator), "Perpetrator must be banned O(1)");
    }
    assert_eq!(banned.len(), 3);
    assert!(banned.contains(&1));
    assert!(banned.contains(&2));
    assert!(banned.contains(&3));
    assert!(!banned.contains(&4));
    assert!(!banned.contains(&5));

    // Verify that one of the locks is VOID
    assert!(
        lock_a.status.is_void() || lock_b.status.is_void(),
        "One lock must be VOID after resolution"
    );
    assert!(
        !(lock_a.status.is_void() && lock_b.status.is_void()),
        "Only one loser should be VOID"
    );
}
