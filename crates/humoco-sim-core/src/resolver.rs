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
        Some(sig) => crate::crypto::compute_canonical_hash_with_sig(&lock_a.parent_lock, &lock_a.receiver_pub, sig),
        None => compute_canonical_hash(&lock_a.parent_lock, &lock_a.receiver_pub, &lock_a.nonce),
    };
    let h_b = match sig_b {
        Some(sig) => crate::crypto::compute_canonical_hash_with_sig(&lock_b.parent_lock, &lock_b.receiver_pub, sig),
        None => compute_canonical_hash(&lock_b.parent_lock, &lock_b.receiver_pub, &lock_b.nonce),
    };

    if h_a < h_b {
        lock_b.status = LockStatus::Void {
            reason: format!(
                "Equivocation collision: lost min(H_canon) against winner lock {:?}",
                lock_a.id
            ),
        };
        ResolutionResult::WinnerA {
            winner_hash: h_a,
            loser_hash: h_b,
        }
    } else {
        lock_a.status = LockStatus::Void {
            reason: format!(
                "Equivocation collision: lost min(H_canon) against winner lock {:?}",
                lock_b.id
            ),
        };
        ResolutionResult::WinnerB {
            winner_hash: h_b,
            loser_hash: h_a,
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
    let sig_a = attestations_a.iter().min_by_key(|a| a.node_id).map(|a| &a.signature);
    let sig_b = attestations_b.iter().min_by_key(|b| b.node_id).map(|b| &b.signature);
    let result = resolve_split_brain_canonical(lock_a, lock_b, sig_a, sig_b);
    // Only create proofs on a real conflict (WinnerA/B)
    let need_proofs = matches!(
        result,
        ResolutionResult::WinnerA { .. } | ResolutionResult::WinnerB { .. }
    );
    if !need_proofs {
        return (result, Vec::new());
    }
    // Intersection of signers: node_id in both attestation sets
    use std::collections::{HashMap, HashSet};
    let set_a: HashSet<u16> = attestations_a.iter().map(|a| a.node_id).collect();
    let set_b: HashSet<u16> = attestations_b.iter().map(|a| a.node_id).collect();
    let intersection: Vec<u16> = set_a.intersection(&set_b).copied().collect();

    // Fallback: if attestations are empty but locks have signers, use those
    let mut proofs = Vec::new();
    if !intersection.is_empty() {
        let map_a: HashMap<u16, &Attestation> =
            attestations_a.iter().map(|a| (a.node_id, a)).collect();
        let map_b: HashMap<u16, &Attestation> =
            attestations_b.iter().map(|a| (a.node_id, a)).collect();
        for nid in intersection {
            if let (Some(&a), Some(&b)) = (map_a.get(&nid), map_b.get(&nid)) {
                if a.parent_lock == b.parent_lock && a.lock_id != b.lock_id {
                    let p = FraudProofPayload::new_shard_equivocation(a.clone(), b.clone());
                    proofs.push(p);
                }
            }
        }
    } else {
        // Check lock signers intersection as secondary source (if attestations exist but intersection is empty)
        let inter_signers: Vec<u16> = lock_a
            .signers
            .intersection(&lock_b.signers)
            .copied()
            .collect();
        for nid in inter_signers {
            let maybe_a = attestations_a.iter().find(|x| x.node_id == nid);
            let maybe_b = attestations_b.iter().find(|x| x.node_id == nid);
            if let (Some(a), Some(b)) = (maybe_a, maybe_b) {
                if a.parent_lock == b.parent_lock && a.lock_id != b.lock_id {
                    proofs.push(FraudProofPayload::new_shard_equivocation(
                        a.clone(),
                        b.clone(),
                    ));
                }
            }
            // First-Party Evidence Doctrine: no synthetic attestations!
        }
    }
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
    fn test_split_brain_winner_loser() {
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
    }
}
