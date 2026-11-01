//! Recipient-bound ephemeral live-state proofs. Expected authority is supplied independently.
use crate::{verify_quorum_proof, AttestationVote, QuorumProof};
use serde::{Deserialize, Serialize};

/// Domain tag for Layer 2 occupied live-state proof digests.
pub const LIVE_OCCUPIED_DOMAIN: &[u8] = b"HUMOCO_V1_LIVE_CURRENT_STATE";

/// Domain tag for Layer 2 unoccupied live-state proof digests.
pub const LIVE_UNOCCUPIED_DOMAIN: &[u8] = b"HUMOCO_V1_LIVE_UNOCCUPIED_STATE";

/// Occupancy state attested by shard custodians for a queried parent lock slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiveSlotOccupancy {
    /// Slot is occupied by `context.child_lock` with `context.state_digest`.
    #[default]
    Occupied,
    /// Slot has no committed successor lock on ready shard custodians (`child_lock == [0; 32]`).
    Unoccupied,
}

/// Exact current-state claim; no historical write approvals are embedded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveStateContext {
    /// Protocol version; currently one.
    pub version: u8,
    /// Network domain: zero mainnet, one testnet.
    pub network: u8,
    /// Voucher's canonical shard.
    pub shard_id: u16,
    /// Voucher domain identifier.
    pub voucher_id: String,
    /// Exact predecessor lookup tag, hashed into parent_lock.
    pub lookup_tag: String,
    /// Consumed predecessor/output identifier.
    pub parent_lock: [u8; 32],
    /// Expected successor transaction identifier.
    pub child_lock: [u8; 32],
    /// Verified root expiry.
    pub root_valid_until: u64,
    /// Hash of the complete canonical current lock representation.
    pub state_digest: [u8; 32],
    /// Fresh unpredictable recipient-generated challenge.
    pub recipient_nonce: [u8; 32],
    /// Ordered frozen committee; the recipient must independently justify this list.
    pub committee: Vec<[u8; 32]>,
}

/// Current-state signatures tied to one exact challenge and snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveStateProof {
    /// Exact signed claim.
    pub context: LiveStateContext,
    /// Distinct current full-key signatures.
    pub votes: Vec<AttestationVote>,
    /// Whether the quorum attests to an occupied lock or an unoccupied slot.
    #[serde(default)]
    pub occupancy: LiveSlotOccupancy,
}

/// Validates finite FINAL context structure, never membership authority.
pub fn validate_live_context(c: &LiveStateContext) -> Result<(), &'static str> {
    if c.version != 1
        || c.network > 1
        || c.committee.len() != 20
        || c.voucher_id.len() > 256
        || c.lookup_tag.is_empty()
        || c.lookup_tag.len() > 128
        || c.recipient_nonce == [0; 32]
        || c.parent_lock != *blake3::hash(c.lookup_tag.as_bytes()).as_bytes()
    {
        return Err("invalid live context");
    }
    let mut seen = std::collections::HashSet::new();
    if c.committee.iter().any(|p| !seen.insert(*p)) {
        return Err("duplicate committee member");
    }
    Ok(())
}

/// Computes an unambiguous domain-separated digest binding every live claim field for an occupied slot.
pub fn live_state_digest(c: &LiveStateContext) -> Result<[u8; 32], &'static str> {
    validate_live_context(c)?;
    if c.child_lock == [0; 32] {
        return Err("occupied live context requires non-zero child_lock");
    }
    let mut h = blake3::Hasher::new();
    let tag = LIVE_OCCUPIED_DOMAIN;
    h.update(&[tag.len() as u8]);
    h.update(tag);
    h.update(&[c.version, c.network]);
    h.update(&c.shard_id.to_le_bytes());
    for s in [&c.voucher_id, &c.lookup_tag] {
        h.update(&(s.len() as u32).to_le_bytes());
        h.update(s.as_bytes());
    }
    h.update(&c.parent_lock);
    h.update(&c.child_lock);
    h.update(&c.root_valid_until.to_le_bytes());
    h.update(&c.state_digest);
    h.update(&c.recipient_nonce);
    h.update(&(c.committee.len() as u32).to_le_bytes());
    for p in &c.committee {
        h.update(p);
    }
    Ok(*h.finalize().as_bytes())
}

/// Computes an unambiguous domain-separated digest binding live-state context for an unoccupied slot.
///
/// Preimage layout:
/// `BLAKE3( [tag_len] || LIVE_UNOCCUPIED_DOMAIN || [version, network] || shard_id_le || voucher_id || lookup_tag || parent_lock || recipient_nonce || committee )`
pub fn live_unoccupied_digest(c: &LiveStateContext) -> Result<[u8; 32], &'static str> {
    validate_live_context(c)?;
    if c.child_lock != [0; 32] || c.state_digest != [0; 32] {
        return Err("unoccupied live context requires zero child_lock and state_digest");
    }
    let mut h = blake3::Hasher::new();
    let tag = LIVE_UNOCCUPIED_DOMAIN;
    h.update(&[tag.len() as u8]);
    h.update(tag);
    h.update(&[c.version, c.network]);
    h.update(&c.shard_id.to_le_bytes());
    for s in [&c.voucher_id, &c.lookup_tag] {
        h.update(&(s.len() as u32).to_le_bytes());
        h.update(s.as_bytes());
    }
    h.update(&c.parent_lock);
    h.update(&c.recipient_nonce);
    h.update(&(c.committee.len() as u32).to_le_bytes());
    for p in &c.committee {
        h.update(p);
    }
    Ok(*h.finalize().as_bytes())
}

/// Verifies a fresh FINAL live proof against an independently established exact context.
/// A proof-supplied roster alone is never an authority source.
pub fn verify_live_state_proof(
    proof: &LiveStateProof,
    expected: &LiveStateContext,
) -> Result<(), &'static str> {
    if proof.occupancy != LiveSlotOccupancy::Occupied {
        return Err("live proof is not occupied");
    }
    if &proof.context != expected || proof.votes.len() > 20 {
        return Err("live context mismatch");
    }
    let digest = live_state_digest(expected)?;
    verify_quorum_proof(
        &QuorumProof {
            shard_id: expected.shard_id,
            votes: proof.votes.clone(),
        },
        &digest,
        &expected.committee,
        14,
    )
}

/// Verifies a fresh FINAL unoccupied live proof against an independently established base context.
pub fn verify_live_unoccupied_proof(
    proof: &LiveStateProof,
    expected_base: &LiveStateContext,
) -> Result<(), &'static str> {
    if proof.occupancy != LiveSlotOccupancy::Unoccupied {
        return Err("live proof is not unoccupied");
    }
    if proof.votes.len() > 20 {
        return Err("live context mismatch");
    }
    validate_live_context(expected_base)?;

    if proof.context.version != expected_base.version
        || proof.context.network != expected_base.network
        || proof.context.shard_id != expected_base.shard_id
        || proof.context.voucher_id != expected_base.voucher_id
        || proof.context.lookup_tag != expected_base.lookup_tag
        || proof.context.parent_lock != expected_base.parent_lock
        || proof.context.recipient_nonce != expected_base.recipient_nonce
        || proof.context.committee != expected_base.committee
        || proof.context.child_lock != [0; 32]
        || proof.context.state_digest != [0; 32]
        || proof.context.root_valid_until != 0
    {
        return Err("live context mismatch");
    }

    let digest = live_unoccupied_digest(&proof.context)?;
    verify_quorum_proof(
        &QuorumProof {
            shard_id: expected_base.shard_id,
            votes: proof.votes.clone(),
        },
        &digest,
        &expected_base.committee,
        14,
    )
}

/// Computes the canonical original node-approval digest used by the production node.
/// This purpose is distinct from recipient-challenged live-state verification.
pub fn original_approval_digest(
    network: u8,
    shard_id: u16,
    status: u8,
    parent: &[u8; 32],
    child: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    let tag: &[u8] = match (network, status) {
        (0, 0) => b"HUMOCO_V1_APPROVE_PROV_MAINNET",
        (0, 1) => b"HUMOCO_V1_APPROVE_FINAL_MAINNET",
        (1, 0) => b"HUMOCO_V1_APPROVE_PROV_TESTNET",
        (1, 1) => b"HUMOCO_V1_APPROVE_FINAL_TESTNET",
        _ => return Err("invalid approval domain"),
    };
    let ptag = b"HUMOCO_V1_ATTESTATION_PAYLOAD";
    let mut payload = blake3::Hasher::new();
    payload.update(&[ptag.len() as u8]);
    payload.update(ptag);
    payload.update(parent);
    payload.update(child);
    let mut h = blake3::Hasher::new();
    h.update(&[tag.len() as u8]);
    h.update(tag);
    h.update(&0u32.to_le_bytes());
    h.update(&0u64.to_le_bytes());
    h.update(&0u32.to_le_bytes());
    h.update(&shard_id.to_le_bytes());
    h.update(&[status]);
    h.update(payload.finalize().as_bytes());
    Ok(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_test_committee() -> (Vec<SigningKey>, Vec<[u8; 32]>) {
        let mut signers = Vec::with_capacity(20);
        let mut pubkeys = Vec::with_capacity(20);
        for i in 1..=20 {
            let sk = SigningKey::from_bytes(&[i; 32]);
            let pk = sk.verifying_key().to_bytes();
            signers.push(sk);
            pubkeys.push(pk);
        }
        (signers, pubkeys)
    }

    fn make_contexts() -> (LiveStateContext, LiveStateContext, Vec<SigningKey>) {
        let (signers, committee) = make_test_committee();
        let tag = "voucher-pred-tag";
        let parent_lock = *blake3::hash(tag.as_bytes()).as_bytes();

        let occupied = LiveStateContext {
            version: 1,
            network: 0,
            shard_id: 7,
            voucher_id: "test-voucher-42".into(),
            lookup_tag: tag.into(),
            parent_lock,
            child_lock: [0x55; 32],
            root_valid_until: 1_900_000_000,
            state_digest: [0xaa; 32],
            recipient_nonce: [0xbb; 32],
            committee: committee.clone(),
        };

        let unoccupied = LiveStateContext {
            version: 1,
            network: 0,
            shard_id: 7,
            voucher_id: "test-voucher-42".into(),
            lookup_tag: tag.into(),
            parent_lock,
            child_lock: [0; 32],
            root_valid_until: 0,
            state_digest: [0; 32],
            recipient_nonce: [0xbb; 32],
            committee,
        };

        (occupied, unoccupied, signers)
    }

    #[test]
    fn test_occupied_proof_success_and_unoccupied_rejection() {
        let (occupied_ctx, unoccupied_ctx, signers) = make_contexts();
        let digest = live_state_digest(&occupied_ctx).expect("digest");

        let votes: Vec<AttestationVote> = signers
            .iter()
            .take(14)
            .map(|sk| AttestationVote {
                signer_pubkey: sk.verifying_key().to_bytes(),
                signature: sk.sign(&digest).to_bytes(),
            })
            .collect();

        let proof = LiveStateProof {
            context: occupied_ctx.clone(),
            votes,
            occupancy: LiveSlotOccupancy::Occupied,
        };

        // 14/20 Occupied proof passes verify_live_state_proof
        assert_eq!(verify_live_state_proof(&proof, &occupied_ctx), Ok(()));

        // Fails verify_live_unoccupied_proof because occupancy is Occupied and context has non-zero child_lock
        assert_eq!(
            verify_live_unoccupied_proof(&proof, &occupied_ctx),
            Err("live proof is not unoccupied")
        );
        assert_eq!(
            verify_live_unoccupied_proof(&proof, &unoccupied_ctx),
            Err("live proof is not unoccupied")
        );
    }

    #[test]
    fn test_unoccupied_proof_success_and_strict_goods_release_safety() {
        let (occupied_ctx, unoccupied_ctx, signers) = make_contexts();
        let digest = live_unoccupied_digest(&unoccupied_ctx).expect("unoccupied digest");

        let votes: Vec<AttestationVote> = signers
            .iter()
            .take(14)
            .map(|sk| AttestationVote {
                signer_pubkey: sk.verifying_key().to_bytes(),
                signature: sk.sign(&digest).to_bytes(),
            })
            .collect();

        let unocc_proof = LiveStateProof {
            context: unoccupied_ctx.clone(),
            votes,
            occupancy: LiveSlotOccupancy::Unoccupied,
        };

        // 14/20 Unoccupied proof passes verify_live_unoccupied_proof
        assert_eq!(
            verify_live_unoccupied_proof(&unocc_proof, &unoccupied_ctx),
            Ok(())
        );

        // STRICTLY FAILS verify_live_state_proof (cross-domain / goods-release safety)
        assert_eq!(
            verify_live_state_proof(&unocc_proof, &unoccupied_ctx),
            Err("live proof is not occupied")
        );
        assert_eq!(
            verify_live_state_proof(&unocc_proof, &occupied_ctx),
            Err("live proof is not occupied")
        );

        // Even if an attacker forges occupancy = Occupied on the unoccupied proof
        let mut forged_proof = unocc_proof.clone();
        forged_proof.occupancy = LiveSlotOccupancy::Occupied;

        // Fails against unoccupied_ctx because live_state_digest rejects child_lock == [0; 32]
        assert_eq!(
            verify_live_state_proof(&forged_proof, &unoccupied_ctx),
            Err("occupied live context requires non-zero child_lock")
        );

        // Fails against occupied_ctx because context fields mismatch
        assert_eq!(
            verify_live_state_proof(&forged_proof, &occupied_ctx),
            Err("live context mismatch")
        );
    }

    #[test]
    fn test_unoccupied_proof_replay_nonce_and_insufficient_votes() {
        let (_, unoccupied_ctx, signers) = make_contexts();
        let digest = live_unoccupied_digest(&unoccupied_ctx).expect("unoccupied digest");

        let votes: Vec<AttestationVote> = signers
            .iter()
            .take(14)
            .map(|sk| AttestationVote {
                signer_pubkey: sk.verifying_key().to_bytes(),
                signature: sk.sign(&digest).to_bytes(),
            })
            .collect();

        let unocc_proof = LiveStateProof {
            context: unoccupied_ctx.clone(),
            votes,
            occupancy: LiveSlotOccupancy::Unoccupied,
        };

        // Replay with different recipient_nonce in expected_base
        let mut alt_base = unoccupied_ctx.clone();
        alt_base.recipient_nonce[0] ^= 1;
        assert_eq!(
            verify_live_unoccupied_proof(&unocc_proof, &alt_base),
            Err("live context mismatch")
        );

        // Replay with different recipient_nonce in proof.context
        let mut alt_proof = unocc_proof.clone();
        alt_proof.context.recipient_nonce[0] ^= 1;
        assert_eq!(
            verify_live_unoccupied_proof(&alt_proof, &unoccupied_ctx),
            Err("live context mismatch")
        );

        // Insufficient votes (< 14)
        let mut short_proof = unocc_proof.clone();
        short_proof.votes.pop(); // 13 votes
        assert_eq!(
            verify_live_unoccupied_proof(&short_proof, &unoccupied_ctx),
            Err("insufficient votes")
        );

        // Duplicate vote
        let mut dup_proof = unocc_proof.clone();
        dup_proof.votes[13] = dup_proof.votes[0].clone();
        assert_eq!(
            verify_live_unoccupied_proof(&dup_proof, &unoccupied_ctx),
            Err("duplicate signer")
        );

        // More than 20 votes rejected
        let mut bloated_proof = unocc_proof.clone();
        let dummy_sk = SigningKey::from_bytes(&[21; 32]);
        while bloated_proof.votes.len() < 21 {
            bloated_proof.votes.push(AttestationVote {
                signer_pubkey: dummy_sk.verifying_key().to_bytes(),
                signature: dummy_sk.sign(&digest).to_bytes(),
            });
        }
        assert_eq!(
            verify_live_unoccupied_proof(&bloated_proof, &unoccupied_ctx),
            Err("live context mismatch")
        );
    }

    #[test]
    fn test_zero_child_lock_restrictions() {
        let (mut occupied, mut unoccupied, _) = make_contexts();

        // Occupied digest requires non-zero child_lock
        occupied.child_lock = [0; 32];
        assert_eq!(
            live_state_digest(&occupied),
            Err("occupied live context requires non-zero child_lock")
        );

        // Unoccupied digest requires zero child_lock and state_digest
        unoccupied.child_lock = [1; 32];
        assert_eq!(
            live_unoccupied_digest(&unoccupied),
            Err("unoccupied live context requires zero child_lock and state_digest")
        );

        unoccupied.child_lock = [0; 32];
        unoccupied.state_digest = [1; 32];
        assert_eq!(
            live_unoccupied_digest(&unoccupied),
            Err("unoccupied live context requires zero child_lock and state_digest")
        );
    }

    #[test]
    fn test_occupancy_default_and_bincode_roundtrip() {
        assert_eq!(LiveSlotOccupancy::default(), LiveSlotOccupancy::Occupied);

        let (occupied, _, signers) = make_contexts();
        let digest = live_state_digest(&occupied).expect("digest");
        let proof = LiveStateProof {
            context: occupied,
            votes: vec![AttestationVote {
                signer_pubkey: signers[0].verifying_key().to_bytes(),
                signature: signers[0].sign(&digest).to_bytes(),
            }],
            occupancy: LiveSlotOccupancy::Occupied,
        };

        let encoded = bincode::serialize(&proof).expect("serialize");
        let decoded: LiveStateProof = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(proof, decoded);
    }
}
