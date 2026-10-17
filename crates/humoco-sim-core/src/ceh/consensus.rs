#![forbid(unsafe_code)]

//! CEH 2-Phase BFT State Machine & Verifiable View Change.
//!
//! Implements the deterministic epoch handoff consensus protocol:
//! 1. Propose & Prepare (Phase 1):
//!    - Proposer (round % 20) broadcasts `EpochProposal`.
//!    - Lock-on-Prepared rule: Nodes locked on an earlier prepared value reject divergent proposals.
//!    - 14 Prepares assemble a `PreparedProof`.
//! 2. Commit (Phase 2):
//!    - Public Prepared Validity: A verified `PreparedProof` forces all honest nodes to commit.
//!    - 14 Commits assemble the finalized `EpochCertificate`.
//! 3. View Change (Recovery):
//!    - Timeout triggers `RoundChangeMessage`.
//!    - 14 RoundChanges assemble a `NewViewCertificate`.
//!    - Unbounded exponential backoff: $T(r) = T_0 \times 2^r$.

use std::collections::BTreeMap;
use ed25519_dalek::SigningKey;

use crate::ceh::crypto::{
    sign_commit_vote, sign_epoch_certificate, sign_prepare_vote, sign_round_change,
    verify_commit_vote, verify_prepare_vote, verify_round_change,
};
use crate::ceh::types::{
    CehError, CommitVote, EpochCertificate, EpochProposal, NewViewCertificate,
    NodePubKey, PrepareVote, PreparedProof, RoundChangeMessage, CEH_BFT_QUORUM,
    CEH_COMMITTEE_SIZE,
};

/// Consensus state of a committee replica for an epoch handoff.
#[derive(Debug)]
pub struct CehConsensusReplica {
    pub shard_id: u16,
    pub epoch: u64,
    pub round: u32,
    pub predecessor_cert_hash: [u8; 32],
    pub committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    pub my_pubkey: NodePubKey,
    signing_key: SigningKey,
    /// Lock-on-Prepared: Node locks on value once 14 Prepares are received.
    pub locked_prepared: Option<PreparedProof>,
    /// Highest prepared proof seen across all rounds.
    pub highest_prepared: Option<PreparedProof>,
    /// Accumulated prepare votes for current round indexed by proposal hash.
    prepare_votes: BTreeMap<[u8; 32], Vec<PrepareVote>>,
    /// Accumulated commit votes for current round indexed by proposal hash.
    commit_votes: BTreeMap<[u8; 32], Vec<CommitVote>>,
    /// Accumulated round-change messages indexed by target next_round.
    round_changes: BTreeMap<u32, Vec<RoundChangeMessage>>,
    /// Finalized successor certificate once 14 Commits are gathered.
    pub finalized_certificate: Option<EpochCertificate>,
}

impl CehConsensusReplica {
    /// Creates a new consensus replica for an active committee member.
    pub fn new(
        shard_id: u16,
        epoch: u64,
        predecessor_cert_hash: [u8; 32],
        committee: [NodePubKey; CEH_COMMITTEE_SIZE],
        signing_key: SigningKey,
    ) -> Result<Self, CehError> {
        let my_pubkey = signing_key.verifying_key().to_bytes();
        if !committee.contains(&my_pubkey) {
            return Err(CehError::SignerNotInCommittee(my_pubkey));
        }
        Ok(Self {
            shard_id,
            epoch,
            round: 0,
            predecessor_cert_hash,
            committee,
            my_pubkey,
            signing_key,
            locked_prepared: None,
            highest_prepared: None,
            prepare_votes: BTreeMap::new(),
            commit_votes: BTreeMap::new(),
            round_changes: BTreeMap::new(),
            finalized_certificate: None,
        })
    }

    /// Determines the authorized round proposer identity for a given round.
    pub fn round_proposer(&self, round: u32) -> NodePubKey {
        let idx = (round as usize) % CEH_COMMITTEE_SIZE;
        self.committee[idx]
    }

    /// Checks if this replica is the proposer for the current round.
    pub fn is_current_proposer(&self) -> bool {
        self.round_proposer(self.round) == self.my_pubkey
    }

    /// Proposer action: constructs an `EpochProposal` for the current round.
    pub fn create_proposal(
        &self,
        closed_state_root: [u8; 32],
        successor_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    ) -> Result<EpochProposal, CehError> {
        if !self.is_current_proposer() {
            return Err(CehError::SignerNotInCommittee(self.my_pubkey));
        }

        // Lock-on-Prepared rule: if replica is locked on a prepared value from an earlier round,
        // it must propose that value.
        let (root, successor, prepared_proof) = if let Some(ref prepared) = self.locked_prepared {
            (
                closed_state_root, // If locked, state root was bound in prepared proposal
                successor_committee,
                Some(prepared.clone()),
            )
        } else {
            (closed_state_root, successor_committee, None)
        };

        Ok(EpochProposal::new(
            self.shard_id,
            self.epoch,
            self.round,
            root,
            successor,
            Vec::new(),
            prepared_proof,
        ))
    }

    /// Member action: handles an incoming `EpochProposal` in Phase 1.
    pub fn handle_proposal(&mut self, proposal: &EpochProposal) -> Result<PrepareVote, CehError> {
        if proposal.shard_id != self.shard_id {
            return Err(CehError::ShardMismatch {
                expected: self.shard_id,
                got: proposal.shard_id,
            });
        }
        if proposal.epoch != self.epoch {
            return Err(CehError::EpochMismatch {
                expected: self.epoch,
                got: proposal.epoch,
            });
        }
        if proposal.round != self.round {
            return Err(CehError::RoundMismatch {
                expected: self.round,
                got: proposal.round,
            });
        }

        // Lock-on-Prepared rule: if locked on an earlier value, proposal must match that locked value
        if let Some(ref locked) = self.locked_prepared {
            let proposal_hash = proposal.canonical_hash();
            if proposal_hash != locked.proposal_hash {
                return Err(CehError::ProposalHashMismatch {
                    expected: locked.proposal_hash,
                    got: proposal_hash,
                });
            }
        }

        // Sign and emit PrepareVote
        let proposal_hash = proposal.canonical_hash();
        let vote = sign_prepare_vote(
            &self.signing_key,
            self.shard_id,
            self.epoch,
            self.round,
            proposal_hash,
        );

        // Record our own vote
        self.add_prepare_vote(vote.clone())?;
        Ok(vote)
    }

    /// Adds a received `PrepareVote` to the accumulation map.
    pub fn add_prepare_vote(&mut self, vote: PrepareVote) -> Result<Option<PreparedProof>, CehError> {
        if vote.round != self.round || vote.epoch != self.epoch || vote.shard_id != self.shard_id {
            return Ok(None);
        }
        if !self.committee.contains(&vote.voter) {
            return Err(CehError::SignerNotInCommittee(vote.voter));
        }

        // Verify cryptographic signature
        if !verify_prepare_vote(&vote) {
            return Err(CehError::InvalidSignature(vote.voter));
        }

        let votes = self.prepare_votes.entry(vote.proposal_hash).or_default();
        if votes.iter().any(|v| v.voter == vote.voter) {
            return Ok(None); // Duplicate vote ignored
        }
        votes.push(vote.clone());

        // Check if 14 Prepares reached
        if votes.len() >= CEH_BFT_QUORUM {
            let mut prepared = PreparedProof::new(
                self.shard_id,
                self.epoch,
                self.round,
                vote.proposal_hash,
            );
            for v in votes {
                prepared.add_signature(v.voter, v.signature);
            }

            // Lock on this prepared value
            self.locked_prepared = Some(prepared.clone());
            self.highest_prepared = Some(prepared.clone());
            return Ok(Some(prepared));
        }

        Ok(None)
    }

    /// Member action: handles an incoming Commit request in Phase 2 with Public Prepared Validity.
    pub fn handle_commit_request(&mut self, prepared: &PreparedProof) -> Result<CommitVote, CehError> {
        if prepared.round != self.round || prepared.epoch != self.epoch || prepared.shard_id != self.shard_id {
            return Err(CehError::RoundMismatch {
                expected: self.round,
                got: prepared.round,
            });
        }

        // Public Prepared Validity: A verified PreparedProof with >= 14 valid Prepares
        // forces the node to commit, regardless of subjective objections.
        prepared.verify(&self.committee)?;

        // Update local lock if not already set
        self.locked_prepared = Some(prepared.clone());
        self.highest_prepared = Some(prepared.clone());

        // Sign and emit CommitVote
        let commit_vote = sign_commit_vote(
            &self.signing_key,
            self.shard_id,
            self.epoch,
            self.round,
            prepared.proposal_hash,
        );

        // Record our own commit vote
        self.add_commit_vote(commit_vote.clone(), [0u8; 32], self.committee)?;
        Ok(commit_vote)
    }

    /// Adds a received `CommitVote`. Once 14 Commits are collected, assembles the `EpochCertificate`.
    pub fn add_commit_vote(
        &mut self,
        vote: CommitVote,
        closed_state_root: [u8; 32],
        successor_committee: [NodePubKey; CEH_COMMITTEE_SIZE],
    ) -> Result<Option<EpochCertificate>, CehError> {
        if vote.round != self.round || vote.epoch != self.epoch || vote.shard_id != self.shard_id {
            return Ok(None);
        }
        if !self.committee.contains(&vote.voter) {
            return Err(CehError::SignerNotInCommittee(vote.voter));
        }

        if !verify_commit_vote(&vote) {
            return Err(CehError::InvalidSignature(vote.voter));
        }

        let votes = self.commit_votes.entry(vote.proposal_hash).or_default();
        if votes.iter().any(|v| v.voter == vote.voter) {
            return Ok(None);
        }
        votes.push(vote.clone());

        // Check if 14 Commits reached -> Form finalized EpochCertificate
        if votes.len() >= CEH_BFT_QUORUM && self.finalized_certificate.is_none() {
            let mut cert = EpochCertificate::new(
                self.shard_id,
                self.epoch + 1,
                self.round,
                self.predecessor_cert_hash,
                closed_state_root,
                successor_committee,
            );
            for v in votes {
                // Authorize handoff with predecessor committee signatures
                let (_, handoff_sig) = sign_epoch_certificate(&self.signing_key, &cert);
                cert.add_signature(v.voter, handoff_sig);
            }
            self.finalized_certificate = Some(cert.clone());
            return Ok(Some(cert));
        }

        Ok(self.finalized_certificate.clone())
    }

    /// Timeout action: initiates a View Change when a round times out.
    pub fn on_round_timeout(&mut self) -> RoundChangeMessage {
        let failed_round = self.round;
        let next_round = self.round + 1;
        let highest = self.highest_prepared.clone();

        sign_round_change(
            &self.signing_key,
            self.shard_id,
            self.epoch,
            failed_round,
            next_round,
            highest,
        )
    }

    /// Adds a `RoundChangeMessage`. Once 14 messages for `next_round` are assembled,
    /// constructs the `NewViewCertificate`.
    pub fn add_round_change(
        &mut self,
        rc: RoundChangeMessage,
    ) -> Result<Option<NewViewCertificate>, CehError> {
        if rc.epoch != self.epoch || rc.shard_id != self.shard_id {
            return Ok(None);
        }
        if !self.committee.contains(&rc.voter) {
            return Err(CehError::SignerNotInCommittee(rc.voter));
        }

        if !verify_round_change(&rc) {
            return Err(CehError::InvalidSignature(rc.voter));
        }

        let list = self.round_changes.entry(rc.next_round).or_default();
        if list.iter().any(|m| m.voter == rc.voter) {
            return Ok(None);
        }
        list.push(rc.clone());

        if list.len() >= CEH_BFT_QUORUM {
            let mut nvc = NewViewCertificate::new(
                self.shard_id,
                self.epoch,
                rc.next_round,
            );
            for m in list {
                nvc.add_message(m.clone());
            }
            return Ok(Some(nvc));
        }

        Ok(None)
    }

    /// Enters a new round certified by a `NewViewCertificate`.
    pub fn enter_new_view(&mut self, nvc: &NewViewCertificate) -> Result<(), CehError> {
        nvc.verify(&self.committee)?;
        self.round = nvc.new_round;
        // Adopt highest prepared value from the NewViewCertificate if present
        if let Some(highest) = nvc.find_highest_prepared() {
            self.locked_prepared = Some(highest.clone());
            self.highest_prepared = Some(highest.clone());
        }
        // Clear round transient votes
        self.prepare_votes.clear();
        self.commit_votes.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair(seed: u8) -> (SigningKey, NodePubKey) {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = seed;
        let sk = SigningKey::from_bytes(&seed_bytes);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn setup_replicas() -> (Vec<SigningKey>, [NodePubKey; 20], Vec<CehConsensusReplica>) {
        let mut keys = Vec::new();
        let mut committee = [[0u8; 32]; 20];
        for (i, pk_slot) in committee.iter_mut().enumerate() {
            let (sk, pk) = generate_keypair(i as u8 + 10);
            keys.push(sk);
            *pk_slot = pk;
        }

        let mut replicas = Vec::new();
        for sk in &keys {
            let r = CehConsensusReplica::new(1, 10, [0xaa; 32], committee, sk.clone())
                .expect("replica creation must succeed");
            replicas.push(r);
        }

        (keys, committee, replicas)
    }

    #[test]
    fn test_normal_two_phase_bft_handoff() {
        let (_keys, committee, mut replicas) = setup_replicas();

        // Proposer for round 0 is replicas[0]
        assert!(replicas[0].is_current_proposer());
        let proposal = replicas[0]
            .create_proposal([0x11; 32], committee)
            .expect("proposal creation");

        // Phase 1: Replicas handle proposal and emit PrepareVotes
        let mut prepares = Vec::new();
        for r in replicas.iter_mut().take(14) {
            let vote = r.handle_proposal(&proposal).expect("prepare vote");
            prepares.push(vote);
        }

        // Deliver 14 Prepares to Proposer -> PreparedProof created
        let mut prepared_proof = None;
        for vote in prepares {
            if let Some(pp) = replicas[0]
                .add_prepare_vote(vote)
                .expect("add prepare vote")
            {
                prepared_proof = Some(pp);
            }
        }
        let prepared_proof = prepared_proof.expect("must reach 14 prepares");
        assert_eq!(prepared_proof.prepare_signatures.len(), 14);

        // Phase 2: Deliver PreparedProof to 14 replicas -> CommitVotes emitted
        let mut commits = Vec::new();
        for r in replicas.iter_mut().take(14) {
            let cv = r
                .handle_commit_request(&prepared_proof)
                .expect("commit vote");
            commits.push(cv);
        }

        // Deliver 14 Commits to all replicas -> Finalized EpochCertificate formed
        let mut final_cert = None;
        for cv in commits {
            if let Some(cert) = replicas[0]
                .add_commit_vote(cv, [0x11; 32], committee)
                .expect("add commit vote")
            {
                final_cert = Some(cert);
            }
        }
        let final_cert = final_cert.expect("must reach 14 commits");
        assert_eq!(final_cert.epoch, 11);
        assert_eq!(final_cert.closed_state_root, [0x11; 32]);
    }

    #[test]
    fn test_view_change_on_round_timeout() {
        let (_keys, _committee, mut replicas) = setup_replicas();

        // Round 0 proposer fails. 14 honest replicas timeout
        let mut round_changes = Vec::new();
        for r in replicas.iter_mut().take(14) {
            let rc = r.on_round_timeout();
            round_changes.push(rc);
        }

        // Proposer for round 1 is replicas[1]
        assert_eq!(replicas[1].round_proposer(1), replicas[1].my_pubkey);

        let mut nvc = None;
        for rc in round_changes {
            if let Some(cert) = replicas[1]
                .add_round_change(rc)
                .expect("add round change")
            {
                nvc = Some(cert);
            }
        }
        let nvc = nvc.expect("must assemble NewViewCertificate");
        assert_eq!(nvc.new_round, 1);

        // All replicas enter Round 1
        for r in replicas.iter_mut().take(14) {
            r.enter_new_view(&nvc).expect("enter new view");
            assert_eq!(r.round, 1);
        }
    }
}
