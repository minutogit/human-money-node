//! Spec 06: Smart Client / Dumb Server Flow (INV-0601 .. 0605)
use std::collections::{HashMap, HashSet};

use crate::crypto::{sign_lock_attestation, verify_attestation};
use crate::storage::{ingress_time_window_valid, RamIndex};
use crate::types::{Attestation, Hash256, HrwRoutingId, LockId, LockRecord, NodePubKey, SimTime};

/// Simulation quorum certificate assembled by the gateway (INV-0603 case 3).
/// Its `Attestation` values use deterministic test signatures; production approvals
/// and `verify_zero_trust_quorum` use real Ed25519 signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub lock_id: LockId,
    pub shard_id: u16,
    pub signatures: Vec<Attestation>, // Individual node attestations; this model uses deterministic test signatures
    pub signer_bitmap: u32,
}

impl QuorumCertificate {
    pub fn signer_count(&self) -> usize { self.signatures.len() }
}

/// Three-way ingress verdict (INV-0603)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressVerdict {
    /// Case 1: Verified - lock already exists with identical id/t_id
    Verified { lock: LockRecord },
    /// Case 2: Conflict - parent already locked with different lock (409)
    Conflict { existing: LockRecord, reason: String },
    /// Case 3: New lock - needs quorum, returns certificate if >=14
    NewLock { cert: QuorumCertificate, status_is_final: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressError {
    InvalidWindow,
    InvalidProofChain(String),
}

/// Dumb Server: only RAM collision filter, no history
pub struct DumbServer {
    pub ram: RamIndex,
    pub top20: Vec<u16>, // NodeIds of shard
    pub root_valid: SimTime,
    pub hysteresis_stable: bool,
}

impl DumbServer {
    pub fn new(top20: Vec<u16>, root_valid: SimTime) -> Self {
        Self { ram: RamIndex::new(), top20, root_valid, hysteresis_stable: true }
    }

    pub fn with_hysteresis(top20: Vec<u16>, root_valid: SimTime, hysteresis_stable: bool) -> Self {
        Self { ram: RamIndex::new(), top20, root_valid, hysteresis_stable }
    }

    /// Ingress handling with 3-way verdict. Idempotent for identical lock.
    pub fn ingress(&mut self, record: LockRecord, now: SimTime) -> Result<IngressVerdict, IngressError> {
        if !ingress_time_window_valid(now, record.valid_until, self.root_valid) {
            return Err(IngressError::InvalidWindow);
        }
        let parent = record.parent_lock;
        if let Some(existing) = self.ram.get(&parent).cloned() {
            if existing.id == record.id {
                // INV-0602 idempotent: identical lock -> 200 OK Verified
                return Ok(IngressVerdict::Verified { lock: existing });
            } else {
                // Case 2: double-spend
                return Ok(IngressVerdict::Conflict { existing, reason: "409 Conflict: parent already locked".into() });
            }
        }
        // First-seen: insert and generate quorum cert
        // Simulate each top20 node attesting (deterministic signing)
        let mut sigs = Vec::new();
        let mut bitmap: u32 = 0;
        for (i, &nid) in self.top20.iter().enumerate() {
            let att = sign_lock_attestation(nid, &record.id, &record.parent_lock, now);
            sigs.push(att);
            bitmap |= 1u32 << i;
        }
        // apply to ram (need to clone record)
        let _ = self.ram.try_insert(record.clone(), now, self.root_valid);
        // For N>=20, FINAL requires >=14 and 24h network stability hysteresis (INV-0802)
        let is_final = sigs.len() >= 14 && self.top20.len() >= 20 && self.hysteresis_stable;
        let cert = QuorumCertificate { lock_id: record.id, shard_id: 0, signatures: sigs, signer_bitmap: bitmap };
        // Case 1 if somehow reassessed? Already handled. So new lock
        // But also if server already had verified path, that would be Verified above.
        Ok(IngressVerdict::NewLock { cert, status_is_final: is_final })
    }
    /// Checks the model certificate (>=14 deterministic test attestations from `top20`).
    pub fn verify_quorum_certificate(&self, cert: &QuorumCertificate) -> bool {
        verify_quorum_certificate(cert, &self.top20, 14)
    }
}

/// Checks model attestations against the caller-supplied committee and threshold (INV-0604).
/// This helper verifies deterministic test signatures, not production Ed25519 approvals.
pub fn verify_quorum_certificate(cert: &QuorumCertificate, top20: &[u16], threshold: usize) -> bool {
    if cert.signatures.len() < threshold {
        return false;
    }
    // distinct signers must be subset of top20 and signatures valid
    let mut seen = HashSet::new();
    let top_set: HashSet<u16> = top20.iter().copied().collect();
    for att in &cert.signatures {
        if !top_set.contains(&att.node_id) {
            return false;
        }
        if !seen.insert(att.node_id) {
            return false; // duplicate signer
        }
        if att.lock_id != cert.lock_id {
            return false;
        }
        if !verify_attestation(att) {
            return false;
        }
    }
    // bitmap must match signers (popcount >= threshold)
    let bitmap_count = cert.signer_bitmap.count_ones() as usize;
    if bitmap_count < threshold {
        return false;
    }
    if bitmap_count != cert.signatures.len() {
        // allow bitmap to match count, but if mismatch fail
        return false;
    }
    true
}

/// Smart Client custody: stores own ProofChain, not server (INV-0601)
#[derive(Clone, Debug)]
pub struct SmartClient {
    pub id: u16,
    /// Client-side custody of own proof chains per parent
    pub proof_chains: HashMap<Hash256, Vec<LockRecord>>, // chain from genesis
    pub pending_offline: Vec<LockRecord>, // INV-0605 offline pending queue
}

impl SmartClient {
    pub fn new(id: u16) -> Self {
        Self { id, proof_chains: HashMap::new(), pending_offline: Vec::new() }
    }
    pub fn add_to_chain(&mut self, record: LockRecord) {
        self.proof_chains.entry(record.parent_lock).or_default().push(record.clone());
        // also keep by id for client signature generation etc.
    }
    pub fn custody_len(&self) -> usize { self.proof_chains.values().map(|v| v.len()).sum() }
    pub fn is_custody_empty(&self) -> bool { self.custody_len() == 0 }
    /// INV-0605: collect offline (no network), queue for later
    pub fn collect_offline(&mut self, record: LockRecord) {
        self.pending_offline.push(record);
    }
    /// Upon reconnect, submit each pending lock idempotently to server; returns results
    pub fn reconnect_and_submit(&mut self, server: &mut DumbServer, now: SimTime) -> Vec<Result<IngressVerdict, IngressError>> {
        let pending = std::mem::take(&mut self.pending_offline);
        let mut results = Vec::new();
        for rec in pending {
            let res = server.ingress(rec.clone(), now);
            // idempotent: if Verified, still success
            // store in custody if new
            if let Ok(IngressVerdict::NewLock { .. }) = &res {
                self.add_to_chain(rec);
            } else if let Ok(IngressVerdict::Verified { .. }) = &res {
                // already have
            }
            results.push(res);
        }
        results
    }
}

/// Helper to create deterministic LockRecord for tests
pub fn make_lock(parent: Hash256, receiver: Hash256, nonce: Vec<u8>, now: SimTime, valid_until: SimTime) -> LockRecord {
    LockRecord::new(parent, receiver, nonce, now, valid_until)
}

// ---------------------------------------------------------------------------
// Zero-trust light-client verification: consensus Bloom filter & order statistics (INV-0605)
// ---------------------------------------------------------------------------

/// Fixed size for the deterministic light-client consensus filter (2048 bytes = 16384 bits)
pub const CONSENSUS_FILTER_BYTES: usize = 2048;
pub const CONSENSUS_FILTER_BITS: usize = CONSENSUS_FILTER_BYTES * 8;
pub const CONSENSUS_FILTER_K: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusBloomFilter {
    pub bits: Vec<u8>,
}

impl Default for ConsensusBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusBloomFilter {
    pub fn new() -> Self {
        Self { bits: vec![0u8; CONSENSUS_FILTER_BYTES] }
    }

    /// Inserts a node (bound to HrwRoutingId + NodePubKey) into the filter
    /// Semantically decoupled: routing ticket + permanent identity
    pub fn insert_identity(&mut self, hrw_id: &HrwRoutingId, pub_key: &NodePubKey) {
        let binding = compute_identity_binding(hrw_id, pub_key);
        for h in 0..CONSENSUS_FILTER_K {
            let bit_idx = compute_bloom_hash(&binding, h, CONSENSUS_FILTER_BITS);
            self.bits[bit_idx / 8] |= 1 << (bit_idx % 8);
        }
    }

    /// Checks whether the identity (HrwRoutingId + NodePubKey) is contained in the filter
    pub fn contains_identity(&self, hrw_id: &HrwRoutingId, pub_key: &NodePubKey) -> bool {
        let binding = compute_identity_binding(hrw_id, pub_key);
        for h in 0..CONSENSUS_FILTER_K {
            let bit_idx = compute_bloom_hash(&binding, h, CONSENSUS_FILTER_BITS);
            if (self.bits[bit_idx / 8] & (1 << (bit_idx % 8))) == 0 {
                return false;
            }
        }
        true
    }

    /// Counts the set bits (popcount)
    pub fn popcount(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Estimates the number of active nodes N from the bit density
    pub fn estimate_network_size(&self) -> usize {
        let x = self.popcount() as f64;
        let m = CONSENSUS_FILTER_BITS as f64;
        let k = CONSENSUS_FILTER_K as f64;
        if x >= m || x == 0.0 {
            return 0;
        }
        let est = -(m / k) * (1.0 - (x / m)).ln();
        est.round().max(1.0) as usize
    }

    /// Bitwise 2-of-3 consensus voting over 3 server filters
    pub fn bitwise_majority(a: &Self, b: &Self, c: &Self) -> Self {
        let mut consensus = Self::new();
        for i in 0..CONSENSUS_FILTER_BYTES {
            let byte_a = a.bits[i];
            let byte_b = b.bits[i];
            let byte_c = c.bits[i];
            consensus.bits[i] = (byte_a & byte_b) | (byte_b & byte_c) | (byte_a & byte_c);
        }
        consensus
    }
}

pub fn compute_identity_binding(hrw_id: &HrwRoutingId, pub_key: &NodePubKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"HUMOCO_IDENTITY_BINDING");
    hasher.update(hrw_id);
    hasher.update(pub_key);
    *hasher.finalize().as_bytes()
}

pub fn compute_bloom_hash(data: &[u8; 32], index: usize, num_bits: usize) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"HUMOCO_BLOOM_HASH");
    hasher.update(data);
    hasher.update(&(index as u32).to_le_bytes());
    let hash = hasher.finalize();
    let val = u32::from_le_bytes(hash.as_bytes()[0..4].try_into().unwrap()) as usize;
    val % num_bits
}

/// Computes the HRW score of a node for a shard as f64 [0.0, 1.0]
/// Semantically decoupled: based on HrwRoutingId (Argon2d ticket), not on NodePubKey
pub fn compute_hrw_score_f64(hrw_id: &HrwRoutingId, shard_id: u16) -> f64 {
    crate::types::hrw_score_32_normalized(hrw_id, shard_id)
}

/// A complete identity and signature entry of a shard signer
/// Semantically decoupled: HrwRoutingId (routing) + NodePubKey (identity) + signature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerEntry {
    pub hrw_id: HrwRoutingId,
    pub pub_key: NodePubKey,
    pub signature: [u8; 64],
}

impl SignerEntry {
    /// Compatibility alias: formerly `node_id`, now `hrw_id`
    pub fn node_id(&self) -> &HrwRoutingId {
        &self.hrw_id
    }
    /// Alias for `routing_id`
    pub fn routing_id(&self) -> &HrwRoutingId {
        &self.hrw_id
    }
}

/// Errors when checking a certificate against an independently authenticated committee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZeroTrustVerifyError {
    InvalidCommittee,
    InsufficientSignatures,
    UnknownNodeIdentity { index: usize },
    DuplicateSigner { index: usize },
    InvalidSignature { index: usize },
}

/// Checks exact membership and real Ed25519 signatures for the expected decision.
/// The caller MUST authenticate the snapshot independently; a gateway-provided list
/// or Bloom filter alone does not establish committee authority. This does not prove
/// agreement between independently observed committees or safe reconfiguration.
/// The digest matches the current Node approve attestation format (zero wire counters).
pub fn verify_zero_trust_quorum(
    network_id: crate::types::NetworkId,
    expected_status: u8,
    shard_id: u16,
    parent_lock: &[u8; 32],
    lock_id: &[u8; 32],
    signers: &[SignerEntry],
    authenticated_committee: &[crate::types::CommitteeMember],
) -> Result<(), ZeroTrustVerifyError> {
    let members: HashMap<_, _> = authenticated_committee.iter()
        .map(|m| (m.node_pubkey, m.hrw_routing_id)).collect();
    if members.is_empty() || members.len() > 20 || members.len() != authenticated_committee.len() {
        return Err(ZeroTrustVerifyError::InvalidCommittee);
    }
    if expected_status > 1 || (expected_status == 1 && members.len() != 20) {
        return Err(ZeroTrustVerifyError::InvalidCommittee);
    }
    let (required, _) = crate::types::required_quorum(members.len());
    if signers.len() < required {
        return Err(ZeroTrustVerifyError::InsufficientSignatures);
    }
    let payload = crate::crypto::compute_attestation_payload_digest(parent_lock, lock_id);
    let domain = if expected_status == 1 { crate::crypto::domain_approve_final(network_id) }
        else { crate::crypto::domain_approve_prov(network_id) };
    let digest = crate::crypto::compute_sig_digest(domain, 0, 0, 0, shard_id, expected_status, &payload);
    let mut seen = HashSet::new();
    for (index, signer) in signers.iter().enumerate() {
        if members.get(&signer.pub_key) != Some(&signer.hrw_id) {
            return Err(ZeroTrustVerifyError::UnknownNodeIdentity { index });
        }
        if !seen.insert(signer.pub_key) {
            return Err(ZeroTrustVerifyError::DuplicateSigner { index });
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&signer.pub_key)
            .map_err(|_| ZeroTrustVerifyError::InvalidSignature { index })?;
        let signature = ed25519_dalek::Signature::from_bytes(&signer.signature);
        key.verify_strict(&digest, &signature)
            .map_err(|_| ZeroTrustVerifyError::InvalidSignature { index })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_verify_quorum_threshold() {
        let top20: Vec<u16> = (0..20).collect();
        let lock_id = [0xAA; 32];
        let parent_lock = [0xBB; 32];
        let mut sigs = Vec::new();
        for i in 0..14 {
            sigs.push(sign_lock_attestation(i, &lock_id, &parent_lock, SimTime(100)));
        }
        let cert = QuorumCertificate { lock_id, shard_id: 0, signatures: sigs, signer_bitmap: (1u32<<14)-1 };
        assert!(verify_quorum_certificate(&cert, &top20, 14));
        // only 13 fails
        let mut sigs13 = Vec::new();
        for i in 0..13 {
            sigs13.push(sign_lock_attestation(i, &lock_id, &parent_lock, SimTime(100)));
        }
        let cert13 = QuorumCertificate { lock_id, shard_id: 0, signatures: sigs13, signer_bitmap: (1u32<<13)-1 };
        assert!(!verify_quorum_certificate(&cert13, &top20, 14));
    }
}
