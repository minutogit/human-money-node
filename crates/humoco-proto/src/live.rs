//! Recipient-bound ephemeral live-state proofs. Expected authority is supplied independently.
use crate::{verify_quorum_proof, AttestationVote, QuorumProof};
use serde::{Deserialize, Serialize};

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveStateProof {
    /// Exact signed claim.
    pub context: LiveStateContext,
    /// Distinct current full-key signatures.
    pub votes: Vec<AttestationVote>,
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

/// Computes an unambiguous domain-separated digest binding every live claim field.
pub fn live_state_digest(c: &LiveStateContext) -> Result<[u8; 32], &'static str> {
    validate_live_context(c)?;
    let mut h = blake3::Hasher::new();
    let tag = b"HUMOCO_V1_LIVE_CURRENT_STATE";
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

/// Verifies a fresh FINAL live proof against an independently established exact context.
/// A proof-supplied roster alone is never an authority source.
pub fn verify_live_state_proof(
    proof: &LiveStateProof,
    expected: &LiveStateContext,
) -> Result<(), &'static str> {
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
