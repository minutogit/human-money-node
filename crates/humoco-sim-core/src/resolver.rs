use crate::crypto::compute_canonical_hash;
use crate::fraud::FraudProofPayload;
use crate::types::{Attestation, Hash256, LockRecord, LockStatus};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolutionResult {
    /// Both locks are identical (idempotent replay, no real conflict)
    Identical,
    /// No common parent locks (no collision)
    NoConflict,
    /// Lock A wins by smaller canonical hash
    WinnerA {
        winner_hash: Hash256,
        loser_hash: Hash256,
    },
    /// Lock B wins by smaller canonical hash
    WinnerB {
        winner_hash: Hash256,
        loser_hash: Hash256,
    },
}

/// ARCHITECTURAL INVARIANT / AUDIT NOTE (Spec 02, 12, 14):
/// Zero State Bloat & No Tombstones Doctrine:
/// - Losing split-brain branches are resolved in RAM via min(H_canon).
/// - Permanent loser/void records are INTENTIONALLY NOT persisted to disk.
/// - Cryptographic equivocation proofs (double-signing by shard nodes) are captured
///   in `TABLE_FRAUD_EVIDENCE` in O(1); non-malicious split-brain branches expire
///   naturally with voucher TTL. Do NOT add persistent tombstone tables.
///
/// Resolves split-brain double-spend conflicts deterministically based on min(H_canon)
/// Per docs/02:
/// H_canon(Lock) = BLAKE3("HUMOCO_V1_CANON_RESOLVER" || Parent_Hash || Receiver_Pub || Nonce)
/// Winner: min(H_canon(A), H_canon(B))
/// Loser: atomically receives LockStatus::Void
pub fn resolve_split_brain(lock_a: &mut LockRecord, lock_b: &mut LockRecord) -> ResolutionResult {
    resolve_split_brain_canonical(lock_a, lock_b, None, None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCandidateOrdering {
    /// Candidate A strictly takes precedence over Candidate B.
    PrecedenceA,
    /// Candidate B strictly takes precedence over Candidate A.
    PrecedenceB,
    /// Candidates are identical.
    Equal,
}

/// Pure native comparison helper returning a total ordering from
/// `(confirmation class, H_canon, valid lock ID)` with explicit precedence semantics (A22-01).
///
/// Precedence rules:
/// 1. Higher confirmation class strictly takes precedence (DEC-064 / INV-0206).
/// 2. Smaller canonical hash takes precedence on equal classes (min(H_canon), Spec 02).
/// 3. Smaller lock ID takes precedence as secondary tie-breaker on equal primary hashes (A22-01).
pub fn compare_native_precedence(
    class_a: u8,
    h_a: &Hash256,
    id_a: &Hash256,
    class_b: u8,
    h_b: &Hash256,
    id_b: &Hash256,
) -> NativeCandidateOrdering {
    if id_a == id_b {
        return NativeCandidateOrdering::Equal;
    }
    if class_a > class_b {
        return NativeCandidateOrdering::PrecedenceA;
    }
    if class_b > class_a {
        return NativeCandidateOrdering::PrecedenceB;
    }
    if h_a < h_b {
        return NativeCandidateOrdering::PrecedenceA;
    }
    if h_b < h_a {
        return NativeCandidateOrdering::PrecedenceB;
    }
    if id_a < id_b {
        NativeCandidateOrdering::PrecedenceA
    } else {
        NativeCandidateOrdering::PrecedenceB
    }
}

/// Canonical split-brain resolution with signature entropy (Spec 02:97, INV-0201)
pub fn resolve_split_brain_canonical(
    lock_a: &mut LockRecord,
    lock_b: &mut LockRecord,
    sig_a: Option<&[u8; 64]>,
    sig_b: Option<&[u8; 64]>,
) -> ResolutionResult {
    // Idempotency check: identical locks result in no-op
    if lock_a.id == lock_b.id {
        return ResolutionResult::Identical;
    }

    // Different parent locks -> no conflict
    if lock_a.parent_lock != lock_b.parent_lock {
        return ResolutionResult::NoConflict;
    }

    let h_a = match sig_a {
        Some(sig) => crate::crypto::compute_canonical_hash_with_sig(
            &lock_a.parent_lock,
            &lock_a.receiver_pub,
            sig,
        ),
        None => compute_canonical_hash(&lock_a.parent_lock, &lock_a.receiver_pub, &lock_a.nonce),
    };
    let h_b = match sig_b {
        Some(sig) => crate::crypto::compute_canonical_hash_with_sig(
            &lock_b.parent_lock,
            &lock_b.receiver_pub,
            sig,
        ),
        None => compute_canonical_hash(&lock_b.parent_lock, &lock_b.receiver_pub, &lock_b.nonce),
    };

    let class_a = lock_a.status.confirmation_class();
    let class_b = lock_b.status.confirmation_class();

    match compare_native_precedence(class_a, &h_a, &lock_a.id, class_b, &h_b, &lock_b.id) {
        NativeCandidateOrdering::Equal => ResolutionResult::Identical,
        NativeCandidateOrdering::PrecedenceA => {
            lock_b.status = LockStatus::Void {
                reason: if class_a > class_b {
                    format!(
                        "Equivocation collision: Class {} lock cannot displace Class {} lock {:?}",
                        class_b, class_a, lock_a.id
                    )
                } else if h_a < h_b {
                    format!(
                        "Equivocation collision: lost min(H_canon) against winner lock {:?}",
                        lock_a.id
                    )
                } else {
                    format!(
                        "Equivocation collision: lost tie-breaker min(LockId) against winner lock {:?}",
                        lock_a.id
                    )
                },
            };
            ResolutionResult::WinnerA {
                winner_hash: h_a,
                loser_hash: h_b,
            }
        }
        NativeCandidateOrdering::PrecedenceB => {
            lock_a.status = LockStatus::Void {
                reason: if class_b > class_a {
                    format!(
                        "Equivocation collision: Class {} lock cannot displace Class {} lock {:?}",
                        class_a, class_b, lock_b.id
                    )
                } else if h_b < h_a {
                    format!(
                        "Equivocation collision: lost min(H_canon) against winner lock {:?}",
                        lock_b.id
                    )
                } else {
                    format!(
                        "Equivocation collision: lost tie-breaker min(LockId) against winner lock {:?}",
                        lock_b.id
                    )
                },
            };
            ResolutionResult::WinnerB {
                winner_hash: h_b,
                loser_hash: h_a,
            }
        }
    }
}

/// Resolves symmetric double-spends via min(H_canon) and automatically creates
/// FraudProofPayload::new_shard_equivocation (pillar 1) for all double-signers.
/// Returns (ResolutionResult, Vec<FraudProof>).
pub fn resolve_split_brain_with_proof(
    lock_a: &mut LockRecord,
    lock_b: &mut LockRecord,
    attestations_a: &[Attestation],
    attestations_b: &[Attestation],
) -> (ResolutionResult, Vec<FraudProofPayload>) {
    let sig_a = attestations_a
        .iter()
        .min_by_key(|a| a.node_id)
        .map(|a| &a.signature);
    let sig_b = attestations_b
        .iter()
        .min_by_key(|b| b.node_id)
        .map(|b| &b.signature);
    let result = resolve_split_brain_canonical(lock_a, lock_b, sig_a, sig_b);
    // Only create proofs on a real conflict (WinnerA/B)
    let need_proofs = matches!(
        result,
        ResolutionResult::WinnerA { .. } | ResolutionResult::WinnerB { .. }
    );
    if !need_proofs {
        return (result, Vec::new());
    }

    use std::collections::HashMap;
    let map_a: HashMap<u16, &Attestation> = attestations_a.iter().map(|a| (a.node_id, a)).collect();
    let map_b: HashMap<u16, &Attestation> = attestations_b.iter().map(|b| (b.node_id, b)).collect();

    let mut proofs = Vec::new();
    for (&nid, &a) in &map_a {
        if let Some(&b) = map_b.get(&nid) {
            if a.parent_lock == b.parent_lock && a.lock_id != b.lock_id {
                proofs.push(FraudProofPayload::new_shard_equivocation(
                    a.clone(),
                    b.clone(),
                ));
            }
        }
    }
    // Deterministic ordering by node_id
    proofs.sort_by_key(|p| p.perpetrator);

    (result, proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SimTime;

    #[test]
    fn test_identical_locks_no_op() {
        let mut l1 = LockRecord::new(
            [1u8; 32],
            [2u8; 32],
            b"salt".to_vec(),
            SimTime(0),
            SimTime(1000),
        );
        let mut l2 = l1.clone();

        let res = resolve_split_brain(&mut l1, &mut l2);
        assert_eq!(res, ResolutionResult::Identical);
        assert_ne!(l1.status, LockStatus::Void { reason: "".into() });
    }

    #[test]
    fn test_split_brain_no_conflict_different_parents() {
        let mut l1 = LockRecord::new(
            [1u8; 32],
            [2u8; 32],
            b"salt_a".to_vec(),
            SimTime(0),
            SimTime(1000),
        );
        let mut l2 = LockRecord::new(
            [99u8; 32],
            [3u8; 32],
            b"salt_b".to_vec(),
            SimTime(0),
            SimTime(1000),
        );

        let res = resolve_split_brain(&mut l1, &mut l2);
        assert_eq!(res, ResolutionResult::NoConflict);
        assert!(!l1.status.is_void());
        assert!(!l2.status.is_void());
    }

    #[test]
    fn test_split_brain_winner_loser_and_equal_hash() {
        let mut l1 = LockRecord::new(
            [1u8; 32],
            [2u8; 32],
            b"salt_a".to_vec(),
            SimTime(0),
            SimTime(1000),
        );
        let mut l2 = LockRecord::new(
            [1u8; 32],
            [3u8; 32],
            b"salt_b".to_vec(),
            SimTime(0),
            SimTime(1000),
        );

        let res = resolve_split_brain(&mut l1, &mut l2);
        match res {
            ResolutionResult::WinnerA {
                winner_hash,
                loser_hash,
            } => {
                assert!(winner_hash < loser_hash);
                assert!(l2.status.is_void());
                assert!(!l1.status.is_void());
            }
            ResolutionResult::WinnerB {
                winner_hash,
                loser_hash,
            } => {
                assert!(winner_hash < loser_hash);
                assert!(l1.status.is_void());
                assert!(!l2.status.is_void());
            }
            _ => panic!("Expected winner/loser resolution"),
        }

        // Test h_a == h_b (deterministic resolution without panic)
        let mut la = LockRecord::new(
            [10u8; 32],
            [20u8; 32],
            b"same_nonce".to_vec(),
            SimTime(0),
            SimTime(1000),
        );
        let mut lb = LockRecord::new(
            [10u8; 32],
            [20u8; 32],
            b"same_nonce".to_vec(),
            SimTime(0),
            SimTime(1000),
        );
        // Distinguish IDs deterministically (la.id < lb.id)
        la.id = [0x01; 32];
        lb.id = [0xFF; 32];

        let res_eq = resolve_split_brain(&mut la, &mut lb);
        match res_eq {
            ResolutionResult::WinnerA {
                winner_hash,
                loser_hash,
            } => {
                assert_eq!(winner_hash, loser_hash);
                assert!(!la.status.is_void());
                assert!(lb.status.is_void());
            }
            _ => panic!("Expected WinnerA when la.id < lb.id on equal canonical hash"),
        }

        // Swapping inputs must select the same winner (la)
        let mut la2 = la.clone();
        let mut lb2 = lb.clone();
        let res_swap = resolve_split_brain(&mut lb2, &mut la2);
        match res_swap {
            ResolutionResult::WinnerB {
                winner_hash,
                loser_hash,
            } => {
                assert_eq!(winner_hash, loser_hash);
                assert!(!la2.status.is_void());
                assert!(lb2.status.is_void());
            }
            _ => panic!("Expected WinnerB (la2) when reversed"),
        }
    }

    #[test]
    fn test_resolve_split_brain_canonical_with_signatures() {
        let mut l1 = LockRecord::new(
            [1u8; 32],
            [2u8; 32],
            b"salt_a".to_vec(),
            SimTime(0),
            SimTime(1000),
        );
        let mut l2 = LockRecord::new(
            [1u8; 32],
            [3u8; 32],
            b"salt_b".to_vec(),
            SimTime(0),
            SimTime(1000),
        );

        let sig_a = [0x11u8; 64];
        let sig_b = [0x22u8; 64];

        let res = resolve_split_brain_canonical(&mut l1, &mut l2, Some(&sig_a), Some(&sig_b));
        assert!(matches!(
            res,
            ResolutionResult::WinnerA { .. } | ResolutionResult::WinnerB { .. }
        ));
    }

    #[test]
    fn test_resolve_split_brain_with_proof_scenarios() {
        let parent_lock = [1u8; 32];
        let mut l1 = LockRecord::new(
            parent_lock,
            [2u8; 32],
            b"salt_1".to_vec(),
            SimTime(0),
            SimTime(1000),
        );
        let mut l2 = LockRecord::new(
            parent_lock,
            [3u8; 32],
            b"salt_2".to_vec(),
            SimTime(0),
            SimTime(1000),
        );

        // 1. No signer overlap (empty intersection)
        let (res_no_overlap, proofs_no_overlap) =
            resolve_split_brain_with_proof(&mut l1, &mut l2, &[], &[]);
        assert!(matches!(
            res_no_overlap,
            ResolutionResult::WinnerA { .. } | ResolutionResult::WinnerB { .. }
        ));
        assert!(proofs_no_overlap.is_empty());

        // 2. Signer overlap with identical parent_lock and distinct lock_id -> creates shard equivocation proof
        let att1 = Attestation {
            lock_id: l1.id,
            parent_lock,
            node_id: 42,
            timestamp: SimTime(100),
            signature: [0xAA; 64],
            shard_id: 0,
        };
        let att2 = Attestation {
            lock_id: l2.id,
            parent_lock,
            node_id: 42,
            timestamp: SimTime(101),
            signature: [0xBB; 64],
            shard_id: 0,
        };

        let mut l1_copy = l1.clone();
        let mut l2_copy = l2.clone();
        let (res_equiv, proofs_equiv) = resolve_split_brain_with_proof(
            &mut l1_copy,
            &mut l2_copy,
            std::slice::from_ref(&att1),
            std::slice::from_ref(&att2),
        );
        assert!(matches!(
            res_equiv,
            ResolutionResult::WinnerA { .. } | ResolutionResult::WinnerB { .. }
        ));
        assert_eq!(proofs_equiv.len(), 1);
        let p = &proofs_equiv[0];
        assert_eq!(p.pillar, crate::fraud::FraudProofPillar::ShardEquivocation);
        assert_eq!(p.perpetrator, 42);
        let dec_a = crate::fraud::decode_attestation(&p.evidence_packet_a).unwrap();
        let dec_b = crate::fraud::decode_attestation(&p.evidence_packet_b).unwrap();
        assert_eq!(dec_a.node_id, 42);
        assert_eq!(dec_b.node_id, 42);
        assert_eq!(dec_a.parent_lock, parent_lock);
        assert_eq!(dec_b.parent_lock, parent_lock);
        assert_ne!(dec_a.lock_id, dec_b.lock_id);

        // 3. Signer overlap with different parent_lock -> no equivocation proof
        let att2_diff_parent = Attestation {
            lock_id: l2.id,
            parent_lock: [0x99; 32],
            node_id: 42,
            timestamp: SimTime(101),
            signature: [0xBB; 64],
            shard_id: 0,
        };
        let mut l1_copy2 = l1.clone();
        let mut l2_copy2 = l2.clone();
        let (_res_diff_p, proofs_diff_p) = resolve_split_brain_with_proof(
            &mut l1_copy2,
            &mut l2_copy2,
            std::slice::from_ref(&att1),
            &[att2_diff_parent],
        );
        assert!(proofs_diff_p.is_empty());

        // 4. Signer overlap with same lock_id -> no equivocation proof
        let att2_same_id = Attestation {
            lock_id: l1.id,
            parent_lock,
            node_id: 42,
            timestamp: SimTime(101),
            signature: [0xBB; 64],
            shard_id: 0,
        };
        let mut l1_copy3 = l1.clone();
        let mut l2_copy3 = l2.clone();
        let (_res_same_id, proofs_same_id) = resolve_split_brain_with_proof(
            &mut l1_copy3,
            &mut l2_copy3,
            std::slice::from_ref(&att1),
            &[att2_same_id],
        );
        assert!(proofs_same_id.is_empty());

        // 5. Secondary fallback path: attestations intersection is empty, but lock.signers has overlap
        let mut l1_signers = l1.clone();
        let mut l2_signers = l2.clone();
        l1_signers.signers.insert(99);
        l2_signers.signers.insert(99);

        let att1_99 = Attestation {
            lock_id: l1.id,
            parent_lock,
            node_id: 99,
            timestamp: SimTime(100),
            signature: [0x11; 64],
            shard_id: 0,
        };
        let att2_99 = Attestation {
            lock_id: l2.id,
            parent_lock,
            node_id: 99,
            timestamp: SimTime(101),
            signature: [0x22; 64],
            shard_id: 0,
        };

        // Here attestation slice for A has node 99 and B has node 99
        let (_res_fallback, proofs_fallback) = resolve_split_brain_with_proof(
            &mut l1_signers,
            &mut l2_signers,
            std::slice::from_ref(&att1_99),
            std::slice::from_ref(&att2_99),
        );
        assert_eq!(proofs_fallback.len(), 1);

        // Secondary fallback when attestation is missing for one side
        let mut l1_fallback_missing = l1.clone();
        let mut l2_fallback_missing = l2.clone();
        l1_fallback_missing.signers.insert(99);
        l2_fallback_missing.signers.insert(99);
        let (_res_fb_miss, proofs_fb_miss) = resolve_split_brain_with_proof(
            &mut l1_fallback_missing,
            &mut l2_fallback_missing,
            std::slice::from_ref(&att1_99),
            &[],
        );
        assert!(proofs_fb_miss.is_empty());

        // 6. No conflict / identical returns empty proofs immediately
        let mut l1_id = l1.clone();
        let mut l1_id_copy = l1.clone();
        let (res_ident, proofs_ident) = resolve_split_brain_with_proof(
            &mut l1_id,
            &mut l1_id_copy,
            std::slice::from_ref(&att1),
            std::slice::from_ref(&att1),
        );
        assert_eq!(res_ident, ResolutionResult::Identical);
        assert!(proofs_ident.is_empty());

        let mut l1_diff_p = l1.clone();
        let mut l2_diff_p = l2.clone();
        l2_diff_p.parent_lock = [0xDE; 32];
        let (res_noconf, proofs_noconf) = resolve_split_brain_with_proof(
            &mut l1_diff_p,
            &mut l2_diff_p,
            std::slice::from_ref(&att1),
            std::slice::from_ref(&att2),
        );
        assert_eq!(res_noconf, ResolutionResult::NoConflict);
        assert!(proofs_noconf.is_empty());
    }

    #[test]
    fn test_a22_01_equal_native_hash_must_converge_independently_of_order() {
        let parent = [21u8; 32];
        let receiver = [22u8; 32];
        let nonce = vec![23u8];
        let mut a = LockRecord::new(
            parent,
            receiver,
            nonce.clone(),
            SimTime(1000),
            SimTime(600_000),
        );
        let mut b = LockRecord::new(parent, receiver, nonce, SimTime(1001), SimTime(600_000));
        a.status = LockStatus::Provisional {
            sigs: 3,
            required: 3,
        };
        b.status = LockStatus::Provisional {
            sigs: 3,
            required: 3,
        };

        assert_ne!(a.id, b.id);
        assert_eq!(
            compute_canonical_hash(&a.parent_lock, &a.receiver_pub, &a.nonce),
            compute_canonical_hash(&b.parent_lock, &b.receiver_pub, &b.nonce)
        );

        let (mut a1, mut b1) = (a.clone(), b.clone());
        resolve_split_brain(&mut a1, &mut b1);
        let winner_ab = if a1.status.is_void() { b1.id } else { a1.id };

        let (mut b2, mut a2) = (b.clone(), a.clone());
        resolve_split_brain(&mut b2, &mut a2);
        let winner_ba = if b2.status.is_void() { a2.id } else { b2.id };

        assert_eq!(
            winner_ab, winner_ba,
            "equal-hash same-class native records must converge to the same winner regardless of arrival order"
        );
    }

    #[test]
    fn test_a22_01_different_validity_shared_lifetime_deterministic_order() {
        let parent = [31u8; 32];
        let receiver = [32u8; 32];
        let nonce = vec![33u8];
        let mut a = LockRecord::new(
            parent,
            receiver,
            nonce.clone(),
            SimTime(1000),
            SimTime(500_000),
        );
        let mut b = LockRecord::new(parent, receiver, nonce, SimTime(1000), SimTime(600_000));
        a.status = LockStatus::Provisional {
            sigs: 3,
            required: 3,
        };
        b.status = LockStatus::Provisional {
            sigs: 3,
            required: 3,
        };

        assert_ne!(a.id, b.id);
        assert_eq!(
            compute_canonical_hash(&a.parent_lock, &a.receiver_pub, &a.nonce),
            compute_canonical_hash(&b.parent_lock, &b.receiver_pub, &b.nonce)
        );

        let (mut a1, mut b1) = (a.clone(), b.clone());
        resolve_split_brain(&mut a1, &mut b1);
        let winner_ab = if a1.status.is_void() { b1.id } else { a1.id };

        let (mut b2, mut a2) = (b, a);
        resolve_split_brain(&mut b2, &mut a2);
        let winner_ba = if b2.status.is_void() { a2.id } else { b2.id };

        assert_eq!(
            winner_ab, winner_ba,
            "different-validity equal-hash records must converge to the same winner"
        );
    }

    #[test]
    fn test_a22_01_lower_class_with_smaller_id_still_loses_to_higher_class() {
        let parent = [41u8; 32];
        let receiver = [42u8; 32];
        let nonce = vec![43u8];
        let a = LockRecord::new(
            parent,
            receiver,
            nonce.clone(),
            SimTime(1000),
            SimTime(600_000),
        );
        let b = LockRecord::new(parent, receiver, nonce, SimTime(1001), SimTime(600_000));

        // Determine which ID is smaller
        let (small, big) = if a.id < b.id { (a, b) } else { (b, a) };
        let mut lower_class = small;
        let mut higher_class = big;
        lower_class.status = LockStatus::Pending; // class 0
        higher_class.status = LockStatus::Final { sigs: 14 }; // class 2

        let mut lc_copy = lower_class.clone();
        let mut hc_copy = higher_class.clone();
        resolve_split_brain(&mut lc_copy, &mut hc_copy);
        assert!(
            lc_copy.status.is_void(),
            "lower class with smaller id must lose"
        );
        assert!(
            !hc_copy.status.is_void(),
            "higher class with larger id must win"
        );

        let mut hc_copy2 = higher_class.clone();
        let mut lc_copy2 = lower_class.clone();
        resolve_split_brain(&mut hc_copy2, &mut lc_copy2);
        assert!(
            lc_copy2.status.is_void(),
            "lower class must lose in reversed order"
        );
        assert!(
            !hc_copy2.status.is_void(),
            "higher class must win in reversed order"
        );
    }
}
