#![forbid(unsafe_code)]

//! Certified Epoch Handoff (CEH) cryptographic primitives.
//!
//! Provides length-prefixed BLAKE3 hashing, 65,536-leaf Merkle tree computation,
//! and Ed25519 signature signing and verification for CEH protocol messages.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::ceh::types::{
    CandidateProof, CehError, CommitVote, EpochCertificate, GenesisManifest, LockReceipt,
    NewViewCertificate, PrepareVote, PreparedProof, RoundChangeMessage, ShardMerkleProof,
    UnifiedNetworkEpochManifest, CEH_COMMITTEE_SIZE, CEH_MERKLE_TREE_DEPTH, CEH_NUM_SHARDS,
};
use crate::types::NodePubKey;


// ---------------------------------------------------------------------------
// Domain Tags
// ---------------------------------------------------------------------------

pub const DOMAIN_CEH_GENESIS: &[u8] = b"HUMOCO_V1_CEH_GENESIS";
pub const DOMAIN_CEH_CERT: &[u8] = b"HUMOCO_V1_CEH_CERT";
pub const DOMAIN_CEH_UNIFIED_MANIFEST: &[u8] = b"HUMOCO_V1_CEH_UNIFIED_MANIFEST";
pub const DOMAIN_CEH_LOCK_RECEIPT: &[u8] = b"HUMOCO_V1_CEH_LOCK_RECEIPT";
pub const DOMAIN_CEH_PROPOSAL: &[u8] = b"HUMOCO_V1_CEH_PROPOSAL";
pub const DOMAIN_CEH_PREPARE: &[u8] = b"HUMOCO_V1_CEH_PREPARE";
pub const DOMAIN_CEH_COMMIT: &[u8] = b"HUMOCO_V1_CEH_COMMIT";
pub const DOMAIN_CEH_ROUND_CHANGE: &[u8] = b"HUMOCO_V1_CEH_ROUND_CHANGE";
pub const DOMAIN_CEH_CANDIDATE_PROOF: &[u8] = b"HUMOCO_V1_CEH_CANDIDATE_PROOF";
pub const DOMAIN_CEH_PREPARED_PROOF: &[u8] = b"HUMOCO_V1_CEH_PREPARED_PROOF";
pub const DOMAIN_CEH_MERKLE_LEAF: &[u8] = b"HUMOCO_V1_CEH_MERKLE_LEAF";
pub const DOMAIN_CEH_MERKLE_NODE: &[u8] = b"HUMOCO_V1_CEH_MERKLE_NODE";
pub const DOMAIN_CEH_VOUCHER_HOP: &[u8] = b"HUMOCO_V1_CEH_VOUCHER_HOP";
pub const DOMAIN_CEH_VOUCHER_TREE: &[u8] = b"HUMOCO_V1_CEH_VOUCHER_TREE";
pub const DOMAIN_CEH_HIERARCHICAL_STATE_ROOT: &[u8] = b"HUMOCO_V1_CEH_HIERARCHICAL_STATE_ROOT";

// Aliases matching exact spec names
pub const HUMOCO_V1_CEH_GENESIS: &[u8] = DOMAIN_CEH_GENESIS;
pub const HUMOCO_V1_CEH_CERT: &[u8] = DOMAIN_CEH_CERT;
pub const HUMOCO_V1_CEH_UNIFIED_MANIFEST: &[u8] = DOMAIN_CEH_UNIFIED_MANIFEST;
pub const HUMOCO_V1_CEH_LOCK_RECEIPT: &[u8] = DOMAIN_CEH_LOCK_RECEIPT;
pub const HUMOCO_V1_CEH_PROPOSAL: &[u8] = DOMAIN_CEH_PROPOSAL;
pub const HUMOCO_V1_CEH_PREPARE: &[u8] = DOMAIN_CEH_PREPARE;
pub const HUMOCO_V1_CEH_COMMIT: &[u8] = DOMAIN_CEH_COMMIT;
pub const HUMOCO_V1_CEH_ROUND_CHANGE: &[u8] = DOMAIN_CEH_ROUND_CHANGE;
pub const HUMOCO_V1_CEH_CANDIDATE_PROOF: &[u8] = DOMAIN_CEH_CANDIDATE_PROOF;
pub const HUMOCO_V1_CEH_PREPARED_PROOF: &[u8] = DOMAIN_CEH_PREPARED_PROOF;
pub const HUMOCO_V1_CEH_MERKLE_LEAF: &[u8] = DOMAIN_CEH_MERKLE_LEAF;
pub const HUMOCO_V1_CEH_MERKLE_NODE: &[u8] = DOMAIN_CEH_MERKLE_NODE;
pub const HUMOCO_V1_CEH_VOUCHER_HOP: &[u8] = DOMAIN_CEH_VOUCHER_HOP;
pub const HUMOCO_V1_CEH_VOUCHER_TREE: &[u8] = DOMAIN_CEH_VOUCHER_TREE;
pub const HUMOCO_V1_CEH_HIERARCHICAL_STATE_ROOT: &[u8] = DOMAIN_CEH_HIERARCHICAL_STATE_ROOT;

/// Injects length-prefixed BLAKE3 domain separation into the hasher.
#[inline]
pub fn update_with_domain(hasher: &mut blake3::Hasher, domain_tag: &[u8]) {
    hasher.update(&(domain_tag.len() as u8).to_le_bytes());
    hasher.update(domain_tag);
}

// ---------------------------------------------------------------------------
// Canonical Hashing Methods
// ---------------------------------------------------------------------------

/// Computes the canonical BLAKE3 hash of a `GenesisManifest`.
pub fn hash_genesis_manifest(
    protocol_version: u32,
    network_id: &[u8; 32],
    genesis_timestamp: u64,
    initial_committee: &[NodePubKey; CEH_COMMITTEE_SIZE],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_GENESIS);
    hasher.update(&protocol_version.to_le_bytes());
    hasher.update(network_id);
    hasher.update(&genesis_timestamp.to_le_bytes());
    for pubkey in initial_committee {
        hasher.update(pubkey);
    }
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 hash of an `EpochCertificate`.
pub fn hash_epoch_certificate(
    shard_id: u16,
    epoch: u64,
    round: u32,
    predecessor_cert_hash: &[u8; 32],
    closed_state_root: &[u8; 32],
    successor_committee: &[NodePubKey; CEH_COMMITTEE_SIZE],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_CERT);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(predecessor_cert_hash);
    hasher.update(closed_state_root);
    for pubkey in successor_committee {
        hasher.update(pubkey);
    }
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 hash of a `UnifiedNetworkEpochManifest`.
pub fn hash_unified_network_epoch_manifest(
    epoch: u64,
    round: u32,
    predecessor_manifest_hash: &[u8; 32],
    shards_merkle_root: &[u8; 32],
    pioneer_committee: &[NodePubKey; CEH_COMMITTEE_SIZE],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_UNIFIED_MANIFEST);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(predecessor_manifest_hash);
    hasher.update(shards_merkle_root);
    for pubkey in pioneer_committee {
        hasher.update(pubkey);
    }
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 hash of a `LockReceipt`.
pub fn hash_lock_receipt(
    shard_id: u16,
    epoch: u64,
    parent_lock: &[u8; 32],
    child_lock: &[u8; 32],
    valid_until: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_LOCK_RECEIPT);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(parent_lock);
    hasher.update(child_lock);
    hasher.update(&valid_until.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 hash of a `CandidateProof`.
pub fn hash_candidate_proof(pubkey: &[u8; 32], ticket: &[u8; 32], timestamp: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_CANDIDATE_PROOF);
    hasher.update(pubkey);
    hasher.update(ticket);
    hasher.update(&timestamp.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 hash of an `EpochProposal`.
pub fn hash_epoch_proposal(
    shard_id: u16,
    epoch: u64,
    round: u32,
    closed_state_root: &[u8; 32],
    successor_committee: &[NodePubKey; CEH_COMMITTEE_SIZE],
    candidate_proofs: &[CandidateProof],
    prepared_proof: Option<&PreparedProof>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_PROPOSAL);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(closed_state_root);
    for pubkey in successor_committee {
        hasher.update(pubkey);
    }
    hasher.update(&(candidate_proofs.len() as u32).to_le_bytes());
    for cp in candidate_proofs {
        hasher.update(&cp.pubkey);
        hasher.update(&cp.ticket);
        hasher.update(&cp.timestamp.to_le_bytes());
        hasher.update(&cp.f2f_sig);
    }
    match prepared_proof {
        None => {
            hasher.update(&[0u8]);
        }
        Some(prep) => {
            hasher.update(&[1u8]);
            hasher.update(&prep.shard_id.to_le_bytes());
            hasher.update(&prep.epoch.to_le_bytes());
            hasher.update(&prep.round.to_le_bytes());
            hasher.update(&prep.proposal_hash);
            hasher.update(&(prep.prepare_signatures.len() as u32).to_le_bytes());
            for (pubkey, sig) in &prep.prepare_signatures {
                hasher.update(pubkey);
                hasher.update(sig);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 hash of a `PreparedProof`.
pub fn hash_prepared_proof(
    shard_id: u16,
    epoch: u64,
    round: u32,
    proposal_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_PREPARED_PROOF);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(proposal_hash);
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 signing digest for a `PrepareVote`.
pub fn hash_prepare_vote(
    shard_id: u16,
    epoch: u64,
    round: u32,
    proposal_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_PREPARE);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(proposal_hash);
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 signing digest for a `CommitVote`.
pub fn hash_commit_vote(
    shard_id: u16,
    epoch: u64,
    round: u32,
    proposal_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_COMMIT);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(proposal_hash);
    *hasher.finalize().as_bytes()
}

/// Computes the canonical BLAKE3 signing digest for a `RoundChangeMessage`.
pub fn hash_round_change(
    shard_id: u16,
    epoch: u64,
    failed_round: u32,
    next_round: u32,
    highest_prepared: Option<&PreparedProof>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_ROUND_CHANGE);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&failed_round.to_le_bytes());
    hasher.update(&next_round.to_le_bytes());
    match highest_prepared {
        None => {
            hasher.update(&[0u8]);
        }
        Some(prep) => {
            hasher.update(&[1u8]);
            let prep_hash = hash_prepared_proof(
                prep.shard_id,
                prep.epoch,
                prep.round,
                &prep.proposal_hash,
            );
            hasher.update(&prep_hash);
        }
    }
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// 65,536-Leaf Merkle Tree Primitives
// ---------------------------------------------------------------------------

/// Computes a Merkle leaf hash for `(shard_id, closed_state_root)`.
pub fn hash_shard_merkle_leaf(shard_id: u16, closed_state_root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_MERKLE_LEAF);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(closed_state_root);
    *hasher.finalize().as_bytes()
}

/// Computes an internal Merkle node hash for `left` and `right` child digests.
pub fn hash_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update_with_domain(&mut hasher, HUMOCO_V1_CEH_MERKLE_NODE);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Computes the deterministic 65,536-leaf Merkle tree root for `UnifiedNetworkEpochManifest`.
pub fn compute_unified_shards_merkle_root(shard_roots: &[[u8; 32]; CEH_NUM_SHARDS]) -> [u8; 32] {
    let mut current = Vec::with_capacity(CEH_NUM_SHARDS);
    for (shard_id, root) in shard_roots.iter().enumerate() {
        current.push(hash_shard_merkle_leaf(shard_id as u16, root));
    }

    let mut next = Vec::with_capacity(CEH_NUM_SHARDS / 2);
    while current.len() > 1 {
        next.clear();
        for chunk in current.chunks_exact(2) {
            next.push(hash_merkle_node(&chunk[0], &chunk[1]));
        }
        std::mem::swap(&mut current, &mut next);
    }
    current[0]
}

/// Generates a 16-element Merkle audit path for a specific shard in the 65,536-shard tree.
pub fn generate_shard_merkle_proof(
    shard_roots: &[[u8; 32]; CEH_NUM_SHARDS],
    shard_id: u16,
) -> ShardMerkleProof {
    let target_shard = shard_id as usize;
    let closed_state_root = shard_roots[target_shard];
    let mut audit_path = Vec::with_capacity(CEH_MERKLE_TREE_DEPTH);

    let mut current = Vec::with_capacity(CEH_NUM_SHARDS);
    for (idx, root) in shard_roots.iter().enumerate() {
        current.push(hash_shard_merkle_leaf(idx as u16, root));
    }

    let mut target_idx = target_shard;
    let mut next = Vec::with_capacity(CEH_NUM_SHARDS / 2);

    while current.len() > 1 {
        let sibling_idx = target_idx ^ 1;
        audit_path.push(current[sibling_idx]);

        next.clear();
        for chunk in current.chunks_exact(2) {
            next.push(hash_merkle_node(&chunk[0], &chunk[1]));
        }
        std::mem::swap(&mut current, &mut next);
        target_idx /= 2;
    }

    ShardMerkleProof {
        shard_id,
        closed_state_root,
        audit_path,
    }
}

/// Verifies a Merkle audit path for an individual shard leaf against the tree root.
pub fn verify_shard_merkle_leaf(
    root: &[u8; 32],
    shard_id: u16,
    closed_state_root: &[u8; 32],
    audit_path: &[[u8; 32]],
) -> bool {
    if audit_path.len() != CEH_MERKLE_TREE_DEPTH {
        return false;
    }

    let mut current = hash_shard_merkle_leaf(shard_id, closed_state_root);
    for (level, sibling) in audit_path.iter().enumerate() {
        if ((shard_id as usize >> level) & 1) == 0 {
            // Current node is left child, sibling is right child
            current = hash_merkle_node(&current, sibling);
        } else {
            // Sibling is left child, current node is right child
            current = hash_merkle_node(sibling, &current);
        }
    }

    current == *root
}

/// Verifies a `ShardMerkleProof` against the tree root.
pub fn verify_shard_merkle_proof(root: &[u8; 32], proof: &ShardMerkleProof) -> bool {
    verify_shard_merkle_leaf(
        root,
        proof.shard_id,
        &proof.closed_state_root,
        &proof.audit_path,
    )
}

// ---------------------------------------------------------------------------
// Ed25519 Signing and Verification Helpers
// ---------------------------------------------------------------------------

/// Signs an arbitrary 32-byte digest using an Ed25519 signing key.
pub fn sign_digest(signing_key: &SigningKey, digest: &[u8; 32]) -> [u8; 64] {
    signing_key.sign(digest).to_bytes()
}

/// Verifies an Ed25519 signature over a 32-byte digest using a public key.
pub fn verify_signature(pubkey: &NodePubKey, digest: &[u8; 32], signature: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    vk.verify_strict(digest, &sig).is_ok()
}

/// Signs a `GenesisManifest` and returns `(NodePubKey, [u8; 64])`.
pub fn sign_genesis_manifest(
    signing_key: &SigningKey,
    manifest: &GenesisManifest,
) -> (NodePubKey, [u8; 64]) {
    let pubkey = signing_key.verifying_key().to_bytes();
    let digest = manifest.canonical_hash();
    let sig = sign_digest(signing_key, &digest);
    (pubkey, sig)
}

/// Verifies a single signature on a `GenesisManifest`.
pub fn verify_genesis_signature(
    manifest: &GenesisManifest,
    pubkey: &NodePubKey,
    signature: &[u8; 64],
) -> bool {
    verify_signature(pubkey, &manifest.canonical_hash(), signature)
}

/// Verifies all signatures on a `GenesisManifest` against its initial committee.
pub fn verify_genesis_manifest_signatures(
    manifest: &GenesisManifest,
    min_signatures: usize,
) -> Result<(), CehError> {
    crate::ceh::types::validate_signatures_against_committee(
        &manifest.genesis_signatures,
        &manifest.initial_committee,
        min_signatures,
        |pk, sig| verify_genesis_signature(manifest, pk, sig),
    )
}

/// Signs an `EpochCertificate` and returns `(NodePubKey, [u8; 64])`.
pub fn sign_epoch_certificate(
    signing_key: &SigningKey,
    cert: &EpochCertificate,
) -> (NodePubKey, [u8; 64]) {
    let pubkey = signing_key.verifying_key().to_bytes();
    let digest = cert.canonical_hash();
    let sig = sign_digest(signing_key, &digest);
    (pubkey, sig)
}

/// Verifies a single signature on an `EpochCertificate`.
pub fn verify_epoch_certificate_signature(
    cert: &EpochCertificate,
    pubkey: &NodePubKey,
    signature: &[u8; 64],
) -> bool {
    verify_signature(pubkey, &cert.canonical_hash(), signature)
}

/// Verifies predecessor committee signatures on an `EpochCertificate`.
pub fn verify_epoch_certificate_signatures(
    cert: &EpochCertificate,
    expected_committee: &[NodePubKey; CEH_COMMITTEE_SIZE],
    min_signatures: usize,
) -> Result<(), CehError> {
    crate::ceh::types::validate_signatures_against_committee(
        &cert.predecessor_signatures,
        expected_committee,
        min_signatures,
        |pk, sig| verify_epoch_certificate_signature(cert, pk, sig),
    )
}

/// Signs a `UnifiedNetworkEpochManifest` and returns `(NodePubKey, [u8; 64])`.
pub fn sign_unified_manifest(
    signing_key: &SigningKey,
    manifest: &UnifiedNetworkEpochManifest,
) -> (NodePubKey, [u8; 64]) {
    let pubkey = signing_key.verifying_key().to_bytes();
    let digest = manifest.canonical_hash();
    let sig = sign_digest(signing_key, &digest);
    (pubkey, sig)
}

/// Verifies a single signature on a `UnifiedNetworkEpochManifest`.
pub fn verify_unified_manifest_signature(
    manifest: &UnifiedNetworkEpochManifest,
    pubkey: &NodePubKey,
    signature: &[u8; 64],
) -> bool {
    verify_signature(pubkey, &manifest.canonical_hash(), signature)
}

/// Verifies pioneer committee signatures on a `UnifiedNetworkEpochManifest`.
pub fn verify_unified_manifest_signatures(
    manifest: &UnifiedNetworkEpochManifest,
    min_signatures: usize,
) -> Result<(), CehError> {
    crate::ceh::types::validate_signatures_against_committee(
        &manifest.pioneer_signatures,
        &manifest.pioneer_committee,
        min_signatures,
        |pk, sig| verify_unified_manifest_signature(manifest, pk, sig),
    )
}

/// Signs a `LockReceipt` and returns `(NodePubKey, [u8; 64])`.
pub fn sign_lock_receipt(
    signing_key: &SigningKey,
    receipt: &LockReceipt,
) -> (NodePubKey, [u8; 64]) {
    let pubkey = signing_key.verifying_key().to_bytes();
    let digest = receipt.canonical_hash();
    let sig = sign_digest(signing_key, &digest);
    (pubkey, sig)
}

/// Verifies a single attestation on a `LockReceipt`.
pub fn verify_lock_receipt_signature(
    receipt: &LockReceipt,
    pubkey: &NodePubKey,
    signature: &[u8; 64],
) -> bool {
    verify_signature(pubkey, &receipt.canonical_hash(), signature)
}

/// Verifies attestations on a `LockReceipt`.
pub fn verify_lock_receipt_signatures(
    receipt: &LockReceipt,
    expected_committee: Option<&[NodePubKey; CEH_COMMITTEE_SIZE]>,
    min_signatures: usize,
) -> Result<(), CehError> {
    if receipt.attestations.len() < min_signatures {
        return Err(CehError::QuorumNotReached {
            have: receipt.attestations.len(),
            required: min_signatures,
        });
    }

    let committee_set: Option<HashSet<&NodePubKey>> =
        expected_committee.map(|comm| comm.iter().collect());
    let mut seen_signers = HashSet::with_capacity(receipt.attestations.len());

    for (pubkey, sig) in &receipt.attestations {
        if let Some(ref set) = committee_set {
            if !set.contains(pubkey) {
                return Err(CehError::SignerNotInCommittee(*pubkey));
            }
        }
        if !seen_signers.insert(*pubkey) {
            return Err(CehError::DuplicateSigner(*pubkey));
        }
        if !verify_lock_receipt_signature(receipt, pubkey, sig) {
            return Err(CehError::InvalidSignature(*pubkey));
        }
    }

    Ok(())
}

/// Creates a signed `CandidateProof`.
pub fn sign_candidate_proof(
    signing_key: &SigningKey,
    ticket: [u8; 32],
    timestamp: u64,
) -> CandidateProof {
    let pubkey = signing_key.verifying_key().to_bytes();
    let digest = hash_candidate_proof(&pubkey, &ticket, timestamp);
    let f2f_sig = sign_digest(signing_key, &digest);
    CandidateProof {
        pubkey,
        ticket,
        timestamp,
        f2f_sig,
    }
}

/// Verifies the signature on a `CandidateProof`.
pub fn verify_candidate_proof(candidate: &CandidateProof) -> bool {
    let digest = hash_candidate_proof(
        &candidate.pubkey,
        &candidate.ticket,
        candidate.timestamp,
    );
    verify_signature(&candidate.pubkey, &digest, &candidate.f2f_sig)
}

/// Creates a signed `PrepareVote`.
pub fn sign_prepare_vote(
    signing_key: &SigningKey,
    shard_id: u16,
    epoch: u64,
    round: u32,
    proposal_hash: [u8; 32],
) -> PrepareVote {
    let voter = signing_key.verifying_key().to_bytes();
    let digest = hash_prepare_vote(shard_id, epoch, round, &proposal_hash);
    let signature = sign_digest(signing_key, &digest);
    PrepareVote {
        shard_id,
        epoch,
        round,
        proposal_hash,
        voter,
        signature,
    }
}

/// Verifies a `PrepareVote`.
pub fn verify_prepare_vote(vote: &PrepareVote) -> bool {
    let digest = hash_prepare_vote(vote.shard_id, vote.epoch, vote.round, &vote.proposal_hash);
    verify_signature(&vote.voter, &digest, &vote.signature)
}

/// Creates a signed `CommitVote`.
pub fn sign_commit_vote(
    signing_key: &SigningKey,
    shard_id: u16,
    epoch: u64,
    round: u32,
    proposal_hash: [u8; 32],
) -> CommitVote {
    let voter = signing_key.verifying_key().to_bytes();
    let digest = hash_commit_vote(shard_id, epoch, round, &proposal_hash);
    let signature = sign_digest(signing_key, &digest);
    CommitVote {
        shard_id,
        epoch,
        round,
        proposal_hash,
        voter,
        signature,
    }
}

/// Verifies a `CommitVote`.
pub fn verify_commit_vote(vote: &CommitVote) -> bool {
    let digest = hash_commit_vote(vote.shard_id, vote.epoch, vote.round, &vote.proposal_hash);
    verify_signature(&vote.voter, &digest, &vote.signature)
}

/// Verifies signatures in a `PreparedProof` against the committee.
pub fn verify_prepared_proof(
    proof: &PreparedProof,
    committee: &[NodePubKey; CEH_COMMITTEE_SIZE],
    min_signatures: usize,
) -> Result<(), CehError> {
    let digest = hash_prepare_vote(proof.shard_id, proof.epoch, proof.round, &proof.proposal_hash);
    crate::ceh::types::validate_signatures_against_committee(
        &proof.prepare_signatures,
        committee,
        min_signatures,
        |pk, sig| verify_signature(pk, &digest, sig),
    )
}

/// Creates a signed `RoundChangeMessage`.
pub fn sign_round_change(
    signing_key: &SigningKey,
    shard_id: u16,
    epoch: u64,
    failed_round: u32,
    next_round: u32,
    highest_prepared: Option<PreparedProof>,
) -> RoundChangeMessage {
    let voter = signing_key.verifying_key().to_bytes();
    let digest = hash_round_change(
        shard_id,
        epoch,
        failed_round,
        next_round,
        highest_prepared.as_ref(),
    );
    let signature = sign_digest(signing_key, &digest);
    RoundChangeMessage {
        shard_id,
        epoch,
        failed_round,
        next_round,
        highest_prepared,
        voter,
        signature,
    }
}

/// Verifies a `RoundChangeMessage`.
pub fn verify_round_change(rc: &RoundChangeMessage) -> bool {
    let digest = hash_round_change(
        rc.shard_id,
        rc.epoch,
        rc.failed_round,
        rc.next_round,
        rc.highest_prepared.as_ref(),
    );
    verify_signature(&rc.voter, &digest, &rc.signature)
}

/// Verifies a `NewViewCertificate` against the committee.
pub fn verify_new_view_certificate(
    nvc: &NewViewCertificate,
    committee: &[NodePubKey; CEH_COMMITTEE_SIZE],
    min_messages: usize,
) -> Result<(), CehError> {
    if nvc.round_change_messages.len() < min_messages {
        return Err(CehError::QuorumNotReached {
            have: nvc.round_change_messages.len(),
            required: min_messages,
        });
    }

    let committee_set: HashSet<&NodePubKey> = committee.iter().collect();
    let mut seen_voters = HashSet::with_capacity(nvc.round_change_messages.len());

    for msg in &nvc.round_change_messages {
        if msg.shard_id != nvc.shard_id {
            return Err(CehError::ShardMismatch {
                expected: nvc.shard_id,
                got: msg.shard_id,
            });
        }
        if msg.epoch != nvc.epoch {
            return Err(CehError::EpochMismatch {
                expected: nvc.epoch,
                got: msg.epoch,
            });
        }
        if msg.next_round != nvc.new_round {
            return Err(CehError::RoundMismatch {
                expected: nvc.new_round,
                got: msg.next_round,
            });
        }
        if !committee_set.contains(&msg.voter) {
            return Err(CehError::SignerNotInCommittee(msg.voter));
        }
        if !seen_voters.insert(msg.voter) {
            return Err(CehError::DuplicateSigner(msg.voter));
        }
        if !verify_round_change(msg) {
            return Err(CehError::InvalidSignature(msg.voter));
        }
    }

    Ok(())
}
