#![forbid(unsafe_code)]

//! CEH Light-Client / PoS Verifier, In-RAM LRU Cache & Late-Certificate Redemption.
//!
//! Provides:
//! 1. Tier-1 Cryptographic Verification:
//!    - Verifies `EpochCertificate` chains back to `GenesisManifest` or trusted Checkpoints.
//!    - Verifies `LockReceipt` (>= 14 signatures) against the authorized epoch committee.
//!    - Verifies `UnifiedNetworkEpochManifest` leaf proofs for Pioneer Mode (N=20).
//! 2. In-RAM LRU Cache:
//!    - Bounds terminal RAM usage to ~1.35 MB for 500 distinct shards.
//! 3. Late-Certificate Redemption:
//!    - Pre-quorum splits are marked `ProvisionalConflict`.
//!    - Submission of a valid 14-vote predecessor `LockReceipt` within 30 days clears the conflict.
//!    - Unredeemed conflicts freeze permanently after 30 days until voucher root expiry.

use std::collections::{HashMap, VecDeque};

use crate::ceh::crypto::verify_shard_merkle_leaf;
use crate::ceh::types::{
    CehError, EpochCertificate, LockReceipt, NodePubKey, UnifiedNetworkEpochManifest,
    CEH_BFT_QUORUM,
};

/// 30-day retention horizon in seconds (30 * 86,400s = 2,592,000s).
pub const LATE_CERTIFICATE_WINDOW_SECS: u64 = 30 * 86_400;

/// 30-day retention horizon in daily epochs.
pub const LATE_CERTIFICATE_WINDOW_EPOCHS: u64 = 30;

/// State of a voucher spend slot in node persistence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotState {
    /// Slot is open, no lock registered.
    Available,
    /// Lock finalized irreversibly.
    Settled(LockReceipt),
    /// Pre-quorum split detected in predecessor epoch. Awaiting late certificate redemption.
    ProvisionalConflict {
        parent_lock: [u8; 32],
        marked_epoch: u64,
        marked_time: u64,
        divergent_children: Vec<[u8; 32]>,
    },
    /// 30 days elapsed without 14-vote certificate. Slot frozen permanently until voucher expiry.
    PermanentlyFrozenUntilExpiry {
        parent_lock: [u8; 32],
        valid_until: u64,
    },
}

/// Verifies an `EpochCertificate` chain from an authorized root anchor/checkpoint.
pub fn verify_epoch_certificate_chain(
    target_cert: &EpochCertificate,
    trusted_anchor_hash: &[u8; 32],
    intermediate_chain: &[EpochCertificate],
) -> Result<(), CehError> {
    if intermediate_chain.is_empty() {
        if target_cert.predecessor_cert_hash != *trusted_anchor_hash {
            return Err(CehError::ProposalHashMismatch {
                expected: *trusted_anchor_hash,
                got: target_cert.predecessor_cert_hash,
            });
        }
        return Ok(());
    }

    let mut current_expected_hash = *trusted_anchor_hash;
    for cert in intermediate_chain {
        if cert.predecessor_cert_hash != current_expected_hash {
            return Err(CehError::ProposalHashMismatch {
                expected: current_expected_hash,
                got: cert.predecessor_cert_hash,
            });
        }
        current_expected_hash = cert.canonical_hash();
    }

    if target_cert.predecessor_cert_hash != current_expected_hash {
        return Err(CehError::ProposalHashMismatch {
            expected: current_expected_hash,
            got: target_cert.predecessor_cert_hash,
        });
    }

    Ok(())
}

/// Verifies that a `LockReceipt` satisfies the BFT quorum from the committee authorized in `EpochCertificate`.
pub fn verify_lock_receipt(
    receipt: &LockReceipt,
    epoch_cert: &EpochCertificate,
) -> Result<(), CehError> {
    if receipt.shard_id != epoch_cert.shard_id {
        return Err(CehError::ShardMismatch {
            expected: epoch_cert.shard_id,
            got: receipt.shard_id,
        });
    }
    if receipt.epoch != epoch_cert.epoch {
        return Err(CehError::EpochMismatch {
            expected: epoch_cert.epoch,
            got: receipt.epoch,
        });
    }

    receipt.verify(&epoch_cert.successor_committee)
}

/// Verifies a shard's `closed_state_root` in Pioneer Mode (N=20) against `UnifiedNetworkEpochManifest`.
pub fn verify_unified_manifest_shard(
    manifest: &UnifiedNetworkEpochManifest,
    shard_id: u16,
    closed_state_root: &[u8; 32],
    audit_path: &[[u8; 32]],
) -> Result<(), CehError> {
    // First verify manifest signatures from pioneer committee
    manifest.verify(&manifest.pioneer_committee)?;

    // Then verify Merkle leaf proof
    if !verify_shard_merkle_leaf(
        &manifest.shards_merkle_root,
        shard_id,
        closed_state_root,
        audit_path,
    ) {
        return Err(CehError::InvalidMerkleProof);
    }
    Ok(())
}

/// In-RAM LRU Cache for PoS Terminals and Gateways to verify and store active `EpochCertificate`s.
#[derive(Debug)]
pub struct CehCertificateCache {
    capacity: usize,
    cache: HashMap<(u16, u64), EpochCertificate>,
    lru_order: VecDeque<(u16, u64)>,
}

impl CehCertificateCache {
    /// Creates a new certificate cache with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            cache: HashMap::with_capacity(capacity),
            lru_order: VecDeque::with_capacity(capacity),
        }
    }

    /// Looks up a certificate by `(shard_id, epoch)`.
    pub fn get(&mut self, shard_id: u16, epoch: u64) -> Option<&EpochCertificate> {
        let key = (shard_id, epoch);
        if self.cache.contains_key(&key) {
            // Move key to back of LRU order
            if let Some(pos) = self.lru_order.iter().position(|k| *k == key) {
                self.lru_order.remove(pos);
            }
            self.lru_order.push_back(key);
            self.cache.get(&key)
        } else {
            None
        }
    }

    /// Inserts a verified certificate into the cache. Evicts the oldest entry if capacity exceeded.
    pub fn insert(&mut self, cert: EpochCertificate) {
        let key = (cert.shard_id, cert.epoch);
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.cache.entry(key) {
            e.insert(cert);
            return;
        }

        if self.cache.len() >= self.capacity {
            if let Some(oldest) = self.lru_order.pop_front() {
                self.cache.remove(&oldest);
            }
        }

        self.lru_order.push_back(key);
        self.cache.insert(key, cert);
    }

    /// Returns the number of cached certificates.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// Handles Late-Certificate Redemption for unresolved `ProvisionalConflict` spend slots.
#[derive(Debug, Default)]
pub struct ConflictResolver;

impl ConflictResolver {
    /// Evaluates a potentially redeeming `LockReceipt` against an active slot.
    pub fn process_receipt(
        current_slot: SlotState,
        receipt: LockReceipt,
        current_epoch: u64,
        current_time: u64,
        predecessor_committee: &[NodePubKey; 20],
    ) -> Result<SlotState, CehError> {
        match current_slot {
            SlotState::Available => {
                // Verify lock receipt against predecessor/current committee
                receipt.verify(predecessor_committee)?;
                Ok(SlotState::Settled(receipt))
            }
            SlotState::Settled(existing) => {
                if existing.parent_lock == receipt.parent_lock && existing.child_lock == receipt.child_lock {
                    Ok(SlotState::Settled(existing)) // Idempotent 200 OK
                } else {
                    // Divergent lock on settled slot -> reject
                    Err(CehError::QuorumNotReached {
                        have: 0,
                        required: CEH_BFT_QUORUM,
                    })
                }
            }
            SlotState::ProvisionalConflict {
                parent_lock,
                marked_epoch,
                marked_time,
                divergent_children: _,
            } => {
                if receipt.parent_lock != parent_lock {
                    return Err(CehError::ProposalHashMismatch {
                        expected: parent_lock,
                        got: receipt.parent_lock,
                    });
                }

                // Check 30-day retention window
                let epoch_diff = current_epoch.saturating_sub(marked_epoch);
                let time_diff = current_time.saturating_sub(marked_time);

                if epoch_diff > LATE_CERTIFICATE_WINDOW_EPOCHS || time_diff > LATE_CERTIFICATE_WINDOW_SECS {
                    // Window expired! Conflict freezes permanently
                    return Ok(SlotState::PermanentlyFrozenUntilExpiry {
                        parent_lock,
                        valid_until: receipt.valid_until,
                    });
                }

                // Verify receipt against predecessor committee
                receipt.verify(predecessor_committee)?;

                // Redemption successful: clear conflict in favor of the verified certificate!
                Ok(SlotState::Settled(receipt))
            }
            SlotState::PermanentlyFrozenUntilExpiry { parent_lock, valid_until } => {
                // Permanently blocked slot rejects any subsequent redemption
                Ok(SlotState::PermanentlyFrozenUntilExpiry {
                    parent_lock,
                    valid_until,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn generate_committee(start_seed: u8) -> ([SigningKey; 20], [NodePubKey; 20]) {
        let mut keys = Vec::new();
        let mut committee = [[0u8; 32]; 20];
        for (i, pk_slot) in committee.iter_mut().enumerate() {
            let mut seed = [0u8; 32];
            seed[0] = start_seed + i as u8;
            let sk = SigningKey::from_bytes(&seed);
            *pk_slot = sk.verifying_key().to_bytes();
            keys.push(sk);
        }
        (keys.try_into().map_err(|_| ()).unwrap(), committee)
    }

    #[test]
    fn test_lru_cache_eviction() {
        let mut cache = CehCertificateCache::new(2);

        let cert1 = EpochCertificate::new(1, 1, 0, [0u8; 32], [0u8; 32], [[0u8; 32]; 20]);
        let cert2 = EpochCertificate::new(1, 2, 0, [0u8; 32], [0u8; 32], [[0u8; 32]; 20]);
        let cert3 = EpochCertificate::new(1, 3, 0, [0u8; 32], [0u8; 32], [[0u8; 32]; 20]);

        cache.insert(cert1.clone());
        cache.insert(cert2.clone());
        assert_eq!(cache.len(), 2);
        assert!(cache.get(1, 1).is_some());

        // Inserting cert3 evicts cert2 because cert1 was recently accessed!
        cache.insert(cert3.clone());
        assert_eq!(cache.len(), 2);
        assert!(cache.get(1, 1).is_some());
        assert!(cache.get(1, 3).is_some());
        assert!(cache.get(1, 2).is_none());
    }

    #[test]
    fn test_late_certificate_redemption_clears_conflict() {
        let (keys, committee) = generate_committee(10);
        let parent_lock = [0xaa; 32];
        let child_lock = [0xbb; 32];

        // Slot has provisional conflict from Day 5
        let slot = SlotState::ProvisionalConflict {
            parent_lock,
            marked_epoch: 5,
            marked_time: 5 * 86_400,
            divergent_children: vec![[0x11; 32], [0x22; 32]],
        };

        // Construct legitimate 14-vote LockReceipt from Day 5 predecessor committee
        let mut receipt = LockReceipt::new(1, 5, parent_lock, child_lock, 100 * 86_400);
        for sk in keys.iter().take(14) {
            let (pk, sig) = crate::ceh::crypto::sign_lock_receipt(sk, &receipt);
            receipt.add_attestation(pk, sig);
        }

        // Present receipt at Day 15 (within 30 days) -> Clears conflict to Settled!
        let new_state = ConflictResolver::process_receipt(
            slot.clone(),
            receipt.clone(),
            15,
            15 * 86_400,
            &committee,
        )
        .expect("redemption must succeed");

        assert_eq!(new_state, SlotState::Settled(receipt.clone()));

        // If presented at Day 45 (> 30 days) -> Freezes permanently
        let expired_state = ConflictResolver::process_receipt(
            slot,
            receipt,
            45,
            45 * 86_400,
            &committee,
        )
        .expect("permanently frozen");

        assert!(matches!(
            expired_state,
            SlotState::PermanentlyFrozenUntilExpiry { .. }
        ));
    }
}
