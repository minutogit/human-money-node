#![forbid(unsafe_code)]

//! Certified Epoch Handoff (CEH) domain types.
//!
//! Defines the core message structures for epoch progression,
//! shard handoffs, pioneer mode manifests, and consensus votes.
//!
//! ⚠️ ARCHITECTURAL NOTICE (DEC-053 / DEC-055):
//! The types in this module originate from the evaluated/historical Certified Epoch Handoff
//! (CEH) specification. In production HuMoCo:
//! - Shard committees are computed dynamically per snapshot/request via HRW (`select_shard_committee`).
//! - Predecessor baton passing (requiring the old committee to sign off on the new one) is strictly rejected.
//! - `epoch_day` is strictly a calendar slot for Ingress rate-limiting and thermometer decay, not a committee term.
//! - The 24h incubation wall applies strictly to Argon2d ticket mining maturity.
//! - Peer liveness is tracked dynamically via passive Dunbar gossip without 24h committee tenures.

use std::collections::HashSet;
use std::fmt;

pub use crate::types::NodePubKey;


/// Canonical committee size for CEH consensus (20 nodes).
pub const CEH_COMMITTEE_SIZE: usize = 20;

/// BFT 2/3 + 1 quorum threshold for 20-node committees (14 nodes).
pub const CEH_BFT_QUORUM: usize = 14;

/// Total number of shards in HuMoCo (2^16 = 65,536).
pub const CEH_NUM_SHARDS: usize = 65536;

/// Depth of the 65,536-leaf binary Merkle tree (log2(65536) = 16).
pub const CEH_MERKLE_TREE_DEPTH: usize = 16;

/// Safely allocates a zero-initialized array for all 65,536 shards directly on the heap
/// without overflowing the call stack.
pub fn alloc_shards_closed_state_roots() -> Box<[[u8; 32]; CEH_NUM_SHARDS]> {
    let v = vec![[0u8; 32]; CEH_NUM_SHARDS];
    match v.into_boxed_slice().try_into() {
        Ok(b) => b,
        Err(_) => unreachable!("length is guaranteed to be CEH_NUM_SHARDS"),
    }
}


/// Serialization helper module for `Vec<(NodePubKey, [u8; 64])>`.
pub mod serde_sig_vec {
    use crate::types::NodePubKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct SignatureEntry {
        pubkey: NodePubKey,
        #[serde(with = "crate::types::serde_bytes_64")]
        sig: [u8; 64],
    }

    pub fn serialize<S>(vec: &[(NodePubKey, [u8; 64])], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for (pubkey, sig) in vec {
            seq.serialize_element(&SignatureEntry {
                pubkey: *pubkey,
                sig: *sig,
            })?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<(NodePubKey, [u8; 64])>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<SignatureEntry>::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|e| (e.pubkey, e.sig)).collect())
    }
}

/// Errors occurring during Certified Epoch Handoff operations and verifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CehError {
    /// Invalid cryptographic signature from the specified node.
    InvalidSignature(NodePubKey),
    /// Invalid public key format or curve point.
    InvalidKey(NodePubKey),
    /// Quorum requirement not met.
    QuorumNotReached { have: usize, required: usize },
    /// Invalid Merkle audit path or root mismatch.
    InvalidMerkleProof,
    /// Merkle audit path length did not match expected depth.
    InvalidAuditPathLength { have: usize, expected: usize },
    /// Shard count did not match the expected 65,536.
    InvalidShardCount { have: usize, expected: usize },
    /// Node is not an authorized member of the expected committee.
    SignerNotInCommittee(NodePubKey),
    /// Duplicate signer detected in signature list.
    DuplicateSigner(NodePubKey),
    /// Consensus round does not match expected round.
    RoundMismatch { expected: u32, got: u32 },
    /// Epoch identifier does not match expected epoch.
    EpochMismatch { expected: u64, got: u64 },
    /// Shard identifier does not match expected shard.
    ShardMismatch { expected: u16, got: u16 },
    /// Proposal hash does not match expected hash.
    ProposalHashMismatch {
        expected: [u8; 32],
        got: [u8; 32],
    },
    /// Incompatible genesis manifest encountered during peer handshake.
    IncompatibleGenesisManifest {
        local: [u8; 32],
        remote: [u8; 32],
    },
    /// Causal predecessor lock is not yet finalized in the collision lock registry.
    CausalPredecessorNotFinal([u8; 32]),
}

impl fmt::Display for CehError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature(pk) => {
                write!(f, "invalid signature from node {}", hex_prefix(pk))
            }
            Self::InvalidKey(pk) => {
                write!(f, "invalid public key format {}", hex_prefix(pk))
            }
            Self::QuorumNotReached { have, required } => {
                write!(f, "quorum not reached: have {have}, required {required}")
            }
            Self::InvalidMerkleProof => write!(f, "invalid Merkle proof or root mismatch"),
            Self::InvalidAuditPathLength { have, expected } => write!(
                f,
                "invalid audit path length: have {have}, expected {expected}"
            ),
            Self::InvalidShardCount { have, expected } => write!(
                f,
                "invalid shard count: have {have}, expected {expected}"
            ),
            Self::SignerNotInCommittee(pk) => {
                write!(f, "signer {} not in committee", hex_prefix(pk))
            }
            Self::DuplicateSigner(pk) => {
                write!(f, "duplicate signature from node {}", hex_prefix(pk))
            }
            Self::RoundMismatch { expected, got } => {
                write!(f, "round mismatch: expected {expected}, got {got}")
            }
            Self::EpochMismatch { expected, got } => {
                write!(f, "epoch mismatch: expected {expected}, got {got}")
            }
            Self::ShardMismatch { expected, got } => {
                write!(f, "shard mismatch: expected {expected}, got {got}")
            }
            Self::ProposalHashMismatch { expected, got } => {
                write!(
                    f,
                    "proposal hash mismatch: expected {}, got {}",
                    hex_prefix(expected),
                    hex_prefix(got)
                )
            }
            Self::IncompatibleGenesisManifest { local, remote } => {
                write!(
                    f,
                    "incompatible genesis manifest: local {}, remote {}",
                    hex_prefix(local),
                    hex_prefix(remote)
                )
            }
            Self::CausalPredecessorNotFinal(parent) => {
                write!(
                    f,
                    "causal predecessor lock not final: {}",
                    hex_prefix(parent)
                )
            }
        }
    }
}

impl std::error::Error for CehError {}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &bytes[..4] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// # Federation Activation Manifest (Network Birth Certificate)
///
/// Sealed when a network matures across the $N = 20$ phase transition after 24 hours of stability.
///
/// ### 🏛️ Architectural Context & Domain Invariants:
/// 1. **Phase Transition from Island to Federation ($N < 20 \to N \ge 20$):**
///    - **Island / Embryonic Mesh ($N < 20$):** Operates on adaptive quorums with status `PROVISIONAL` (0x00).
///      It has *no* `GenesisManifest` of its own (`local = None`). It can adopt an established federation's
///      manifest via *Pioneer Adoption* when bridging to the global network.
///    - **Sovereign Federation ($N \ge 20$):** Once 20 mature nodes are stable for 24h, the initial 20-node
///      pioneer committee co-signs this manifest ($\ge 14/20$ BFT quorum).
/// 2. **Network Genesis Fingerprint & Cryptographic Universe Isolation:**
///    - The `canonical_hash()` of this manifest defines the immutable `NetworkGenesisFingerprint`.
///    - This fingerprint seals the network universe: it binds TLS ALPN, QUIC session negotiation,
///      and signature domain separators (`domain_approve_final`).
/// 3. **Mutual Incompatibility between Distinct $N \ge 20$ Federations (Anti-Collision & Anti-Spam):**
///    - If two separate networks grow to $N \ge 20$ independently, each signs a divergent `GenesisManifest`.
///    - During P2P handshakes, [`verify_handshake_genesis`] enforces that divergent manifests result in
///      an immediate hard abort (`CehError::IncompatibleGenesisManifest`).
///    - This guarantees that two large networks can *never* silently merge or cross-contaminate each other's
///      `FINAL` collision lock state, completely neutralizing cross-network double-spends and mass spam dumps.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenesisManifest {
    pub protocol_version: u32,
    pub network_id: [u8; 32],
    pub genesis_timestamp: u64,
    pub initial_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    #[serde(with = "serde_sig_vec")]
    pub genesis_signatures: Vec<(NodePubKey, [u8; 64])>,
}

impl GenesisManifest {
    pub fn new(
        protocol_version: u32,
        network_id: [u8; 32],
        genesis_timestamp: u64,
        initial_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    ) -> Self {
        Self {
            protocol_version,
            network_id,
            genesis_timestamp,
            initial_committee,
            genesis_signatures: Vec::new(),
        }
    }

    /// Computes the canonical BLAKE3 hash of this genesis manifest body.
    pub fn canonical_hash(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_genesis_manifest(
            self.protocol_version,
            &self.network_id,
            self.genesis_timestamp,
            &self.initial_committee,
        )
    }

    /// Adds a valid signature to the genesis manifest.
    pub fn add_signature(&mut self, pubkey: NodePubKey, signature: [u8; 64]) {
        self.genesis_signatures.push((pubkey, signature));
    }

    /// Verifies all pioneer signatures on this genesis manifest against its initial committee.
    pub fn verify_signatures(&self) -> Result<(), CehError> {
        crate::ceh::crypto::verify_genesis_manifest_signatures(self, CEH_BFT_QUORUM)
    }
}

/// Certified epoch certificate sealing a shard's state and handing off to the successor committee.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochCertificate {
    pub shard_id: u16,
    pub epoch: u64,
    pub round: u32,
    pub predecessor_cert_hash: [u8; 32],
    pub closed_state_root: [u8; 32],
    pub successor_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    #[serde(with = "serde_sig_vec")]
    pub predecessor_signatures: Vec<(NodePubKey, [u8; 64])>,
}

impl EpochCertificate {
    pub fn new(
        shard_id: u16,
        epoch: u64,
        round: u32,
        predecessor_cert_hash: [u8; 32],
        closed_state_root: [u8; 32],
        successor_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    ) -> Self {
        Self {
            shard_id,
            epoch,
            round,
            predecessor_cert_hash,
            closed_state_root,
            successor_committee,
            predecessor_signatures: Vec::new(),
        }
    }

    /// Computes the canonical BLAKE3 hash of this epoch certificate body.
    pub fn canonical_hash(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_epoch_certificate(
            self.shard_id,
            self.epoch,
            self.round,
            &self.predecessor_cert_hash,
            &self.closed_state_root,
            &self.successor_committee,
        )
    }

    /// Adds a predecessor committee member's signature.
    pub fn add_signature(&mut self, pubkey: NodePubKey, signature: [u8; 64]) {
        self.predecessor_signatures.push((pubkey, signature));
    }

    /// Adds a predecessor signature (alias for `add_signature`).
    pub fn add_predecessor_signature(&mut self, pubkey: NodePubKey, signature: [u8; 64]) {
        self.add_signature(pubkey, signature);
    }

    /// Verifies this epoch certificate signatures against the expected predecessor committee.
    pub fn verify(&self, expected_committee: &[NodePubKey; CEH_COMMITTEE_SIZE]) -> Result<(), CehError> {
        crate::ceh::crypto::verify_epoch_certificate_signatures(self, expected_committee, CEH_BFT_QUORUM)
    }
}

/// Unified network epoch manifest for N=20 pioneer mode sealing all 65,536 shards via Merkle root.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnifiedNetworkEpochManifest {
    pub epoch: u64,
    pub round: u32,
    pub predecessor_manifest_hash: [u8; 32],
    pub shards_merkle_root: [u8; 32],
    pub pioneer_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    #[serde(with = "serde_sig_vec")]
    pub pioneer_signatures: Vec<(NodePubKey, [u8; 64])>,
}

impl UnifiedNetworkEpochManifest {
    pub fn new(
        epoch: u64,
        round: u32,
        predecessor_manifest_hash: [u8; 32],
        shards_merkle_root: [u8; 32],
        pioneer_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    ) -> Self {
        Self {
            epoch,
            round,
            predecessor_manifest_hash,
            shards_merkle_root,
            pioneer_committee,
            pioneer_signatures: Vec::new(),
        }
    }

    /// Computes the canonical BLAKE3 hash of this unified network epoch manifest body.
    pub fn canonical_hash(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_unified_network_epoch_manifest(
            self.epoch,
            self.round,
            &self.predecessor_manifest_hash,
            &self.shards_merkle_root,
            &self.pioneer_committee,
        )
    }

    /// Adds a pioneer committee member's signature.
    pub fn add_signature(&mut self, pubkey: NodePubKey, signature: [u8; 64]) {
        self.pioneer_signatures.push((pubkey, signature));
    }

    /// Verifies this manifest pioneer signatures against the pioneer committee.
    pub fn verify(&self, pioneer_committee: &[NodePubKey; CEH_COMMITTEE_SIZE]) -> Result<(), CehError> {
        if &self.pioneer_committee != pioneer_committee {
            return Err(CehError::SignerNotInCommittee(pioneer_committee[0]));
        }
        crate::ceh::crypto::verify_unified_manifest_signatures(self, CEH_BFT_QUORUM)
    }
}

/// Lock receipt proving a lock transition in a specific shard and epoch with attestations.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockReceipt {
    pub shard_id: u16,
    pub epoch: u64,
    pub parent_lock: [u8; 32],
    pub child_lock: [u8; 32],
    pub valid_until: u64,
    #[serde(with = "serde_sig_vec")]
    pub attestations: Vec<(NodePubKey, [u8; 64])>,
}

impl LockReceipt {
    pub fn new(
        shard_id: u16,
        epoch: u64,
        parent_lock: [u8; 32],
        child_lock: [u8; 32],
        valid_until: u64,
    ) -> Self {
        Self {
            shard_id,
            epoch,
            parent_lock,
            child_lock,
            valid_until,
            attestations: Vec::new(),
        }
    }

    /// Computes the canonical BLAKE3 hash of this lock receipt body.
    pub fn canonical_hash(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_lock_receipt(
            self.shard_id,
            self.epoch,
            &self.parent_lock,
            &self.child_lock,
            self.valid_until,
        )
    }

    /// Adds a committee attestation.
    pub fn add_attestation(&mut self, pubkey: NodePubKey, signature: [u8; 64]) {
        self.attestations.push((pubkey, signature));
    }

    /// Verifies this lock receipt attestations against the expected committee.
    pub fn verify(&self, expected_committee: &[NodePubKey; CEH_COMMITTEE_SIZE]) -> Result<(), CehError> {
        crate::ceh::crypto::verify_lock_receipt_signatures(self, Some(expected_committee), CEH_BFT_QUORUM)
    }
}

/// Candidate proof for HRW committee eligibility.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CandidateProof {
    pub pubkey: NodePubKey,
    pub ticket: [u8; 32],
    pub timestamp: u64,
    #[serde(with = "crate::types::serde_bytes_64")]
    pub f2f_sig: [u8; 64],
}

impl CandidateProof {
    pub fn new(pubkey: NodePubKey, ticket: [u8; 32], timestamp: u64, f2f_sig: [u8; 64]) -> Self {
        Self {
            pubkey,
            ticket,
            timestamp,
            f2f_sig,
        }
    }

    /// Computes the canonical BLAKE3 hash of this candidate proof.
    pub fn canonical_hash(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_candidate_proof(&self.pubkey, &self.ticket, self.timestamp)
    }
}

/// Prepared proof aggregating >= 14 prepare votes on a proposal in a round.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreparedProof {
    pub shard_id: u16,
    pub epoch: u64,
    pub round: u32,
    pub proposal_hash: [u8; 32],
    #[serde(with = "serde_sig_vec")]
    pub prepare_signatures: Vec<(NodePubKey, [u8; 64])>,
}

impl PreparedProof {
    pub fn new(shard_id: u16, epoch: u64, round: u32, proposal_hash: [u8; 32]) -> Self {
        Self {
            shard_id,
            epoch,
            round,
            proposal_hash,
            prepare_signatures: Vec::new(),
        }
    }

    /// Computes the canonical BLAKE3 hash of this prepared proof.
    pub fn canonical_hash(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_prepared_proof(
            self.shard_id,
            self.epoch,
            self.round,
            &self.proposal_hash,
        )
    }

    /// Adds a prepare signature from a committee member.
    pub fn add_signature(&mut self, voter: NodePubKey, signature: [u8; 64]) {
        self.prepare_signatures.push((voter, signature));
    }

    /// Verifies this prepared proof signatures against the committee.
    pub fn verify(&self, committee: &[NodePubKey; CEH_COMMITTEE_SIZE]) -> Result<(), CehError> {
        crate::ceh::crypto::verify_prepared_proof(self, committee, CEH_BFT_QUORUM)
    }
}

/// Epoch proposal submitted by a round leader during consensus.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochProposal {
    pub shard_id: u16,
    pub epoch: u64,
    pub round: u32,
    pub closed_state_root: [u8; 32],
    pub successor_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    pub candidate_proofs: Vec<CandidateProof>,
    pub prepared_proof: Option<PreparedProof>,
}

impl EpochProposal {
    pub fn new(
        shard_id: u16,
        epoch: u64,
        round: u32,
        closed_state_root: [u8; 32],
        successor_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
        candidate_proofs: Vec<CandidateProof>,
        prepared_proof: Option<PreparedProof>,
    ) -> Self {
        Self {
            shard_id,
            epoch,
            round,
            closed_state_root,
            successor_committee,
            candidate_proofs,
            prepared_proof,
        }
    }

    /// Computes the canonical BLAKE3 hash of this epoch proposal.
    pub fn canonical_hash(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_epoch_proposal(
            self.shard_id,
            self.epoch,
            self.round,
            &self.closed_state_root,
            &self.successor_committee,
            &self.candidate_proofs,
            self.prepared_proof.as_ref(),
        )
    }
}

/// Prepare vote by a committee member on an epoch proposal.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrepareVote {
    pub shard_id: u16,
    pub epoch: u64,
    pub round: u32,
    pub proposal_hash: [u8; 32],
    pub voter: NodePubKey,
    #[serde(with = "crate::types::serde_bytes_64")]
    pub signature: [u8; 64],
}

impl PrepareVote {
    pub fn new(
        shard_id: u16,
        epoch: u64,
        round: u32,
        proposal_hash: [u8; 32],
        voter: NodePubKey,
        signature: [u8; 64],
    ) -> Self {
        Self {
            shard_id,
            epoch,
            round,
            proposal_hash,
            voter,
            signature,
        }
    }

    /// Computes the canonical BLAKE3 signing digest for this prepare vote.
    pub fn signing_digest(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_prepare_vote(
            self.shard_id,
            self.epoch,
            self.round,
            &self.proposal_hash,
        )
    }
}

/// Commit vote by a committee member on an epoch proposal.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommitVote {
    pub shard_id: u16,
    pub epoch: u64,
    pub round: u32,
    pub proposal_hash: [u8; 32],
    pub voter: NodePubKey,
    #[serde(with = "crate::types::serde_bytes_64")]
    pub signature: [u8; 64],
}

impl CommitVote {
    pub fn new(
        shard_id: u16,
        epoch: u64,
        round: u32,
        proposal_hash: [u8; 32],
        voter: NodePubKey,
        signature: [u8; 64],
    ) -> Self {
        Self {
            shard_id,
            epoch,
            round,
            proposal_hash,
            voter,
            signature,
        }
    }

    /// Computes the canonical BLAKE3 signing digest for this commit vote.
    pub fn signing_digest(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_commit_vote(
            self.shard_id,
            self.epoch,
            self.round,
            &self.proposal_hash,
        )
    }
}

/// Round change message sent when a round times out.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoundChangeMessage {
    pub shard_id: u16,
    pub epoch: u64,
    pub failed_round: u32,
    pub next_round: u32,
    pub highest_prepared: Option<PreparedProof>,
    pub voter: NodePubKey,
    #[serde(with = "crate::types::serde_bytes_64")]
    pub signature: [u8; 64],
}

impl RoundChangeMessage {
    pub fn new(
        shard_id: u16,
        epoch: u64,
        failed_round: u32,
        next_round: u32,
        highest_prepared: Option<PreparedProof>,
        voter: NodePubKey,
        signature: [u8; 64],
    ) -> Self {
        Self {
            shard_id,
            epoch,
            failed_round,
            next_round,
            highest_prepared,
            voter,
            signature,
        }
    }

    /// Computes the canonical BLAKE3 signing digest for this round change message.
    pub fn signing_digest(&self) -> [u8; 32] {
        crate::ceh::crypto::hash_round_change(
            self.shard_id,
            self.epoch,
            self.failed_round,
            self.next_round,
            self.highest_prepared.as_ref(),
        )
    }
}

/// New view certificate aggregating >= 14 round change messages to advance to `new_round`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NewViewCertificate {
    pub shard_id: u16,
    pub epoch: u64,
    pub new_round: u32,
    pub round_change_messages: Vec<RoundChangeMessage>,
}

impl NewViewCertificate {
    pub fn new(shard_id: u16, epoch: u64, new_round: u32) -> Self {
        Self {
            shard_id,
            epoch,
            new_round,
            round_change_messages: Vec::new(),
        }
    }

    /// Adds a round change message to this certificate.
    pub fn add_message(&mut self, message: RoundChangeMessage) {
        self.round_change_messages.push(message);
    }

    /// Verifies this new view certificate messages against the committee.
    pub fn verify(&self, committee: &[NodePubKey; CEH_COMMITTEE_SIZE]) -> Result<(), CehError> {
        crate::ceh::crypto::verify_new_view_certificate(self, committee, CEH_BFT_QUORUM)
    }

    /// Finds the prepared proof with the highest round among all round change messages.
    pub fn find_highest_prepared(&self) -> Option<&PreparedProof> {
        self.round_change_messages
            .iter()
            .filter_map(|m| m.highest_prepared.as_ref())
            .max_by_key(|p| p.round)
    }
}

/// Merkle audit proof for a single shard's closed state root in the 65,536-shard tree.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShardMerkleProof {
    pub shard_id: u16,
    pub closed_state_root: [u8; 32],
    /// 16 sibling hashes from leaf to root.
    pub audit_path: Vec<[u8; 32]>,
}

impl ShardMerkleProof {
    pub fn new(shard_id: u16, closed_state_root: [u8; 32], audit_path: Vec<[u8; 32]>) -> Self {
        Self {
            shard_id,
            closed_state_root,
            audit_path,
        }
    }

    /// Verifies this proof against the given Merkle root.
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        crate::ceh::crypto::verify_shard_merkle_proof(root, self)
    }
}

/// Checks that a set of signatures meets quorum requirements and contains no duplicates or non-committee signers.
pub fn validate_signatures_against_committee(
    signatures: &[(NodePubKey, [u8; 64])],
    committee: &[NodePubKey; CEH_COMMITTEE_SIZE],
    min_signatures: usize,
    verify_fn: impl Fn(&NodePubKey, &[u8; 64]) -> bool,
) -> Result<(), CehError> {
    if signatures.len() < min_signatures {
        return Err(CehError::QuorumNotReached {
            have: signatures.len(),
            required: min_signatures,
        });
    }

    let committee_set: HashSet<&NodePubKey> = committee.iter().collect();
    let mut seen_signers = HashSet::with_capacity(signatures.len());

    for (pubkey, sig) in signatures {
        if !committee_set.contains(pubkey) {
            return Err(CehError::SignerNotInCommittee(*pubkey));
        }
        if !seen_signers.insert(*pubkey) {
            return Err(CehError::DuplicateSigner(*pubkey));
        }
        if !verify_fn(pubkey, sig) {
            return Err(CehError::InvalidSignature(*pubkey));
        }
    }

    Ok(())
}

/// # Federation Boundary Guard (Genesis Compatibility & Island Adoption)
///
/// Enforces cryptographic federation boundaries during P2P handshakes:
///
/// 1. **Federation Collision Defense ($N \ge 20$ vs $N \ge 20$):**
///    If both peers have an established [`GenesisManifest`] (`Some(loc)` and `Some(rem)`), their canonical
///    hashes must be strictly identical. If they diverge, returns `Err(CehError::IncompatibleGenesisManifest)`.
///    The handshake fails immediately and the QUIC session is closed. This prevents two independently grown
///    federations from creating conflicting `FINAL` signatures or contaminating each other's collision registry.
/// 2. **Island Mesh Adoption ($N < 20$ into $N \ge 20$):**
///    If the local node is an embryonic island mesh (`local = None`), and the remote peer presents a valid
///    federation manifest (`remote = Some(rem)`), the island node verifies the 14 pioneer signatures
///    ([`GenesisManifest::verify_signatures`]) and adopts the remote manifest (`Ok(Some(rem.clone()))`).
/// 3. **Island-to-Island Peering ($N < 20$ with $N < 20$):**
///    If neither peer has crossed the $N = 20$ threshold (`local = None`, `remote = None`), they operate
///    freely in provisional mode (`Ok(None)`).
pub fn verify_handshake_genesis(
    local: Option<&GenesisManifest>,
    remote: Option<&GenesisManifest>,
) -> Result<Option<GenesisManifest>, CehError> {
    match (local, remote) {
        (Some(loc), Some(rem)) => {
            let loc_hash = loc.canonical_hash();
            let rem_hash = rem.canonical_hash();
            if loc_hash != rem_hash {
                Err(CehError::IncompatibleGenesisManifest {
                    local: loc_hash,
                    remote: rem_hash,
                })
            } else {
                Ok(None)
            }
        }
        (None, Some(rem)) => {
            rem.verify_signatures()?;
            Ok(Some(rem.clone()))
        }
        (Some(_), None) => Ok(None),
        (None, None) => Ok(None),
    }
}
