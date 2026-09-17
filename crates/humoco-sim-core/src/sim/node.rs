use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::crypto::sign_lock_attestation;
use crate::fraud::{FraudProofPayload, Heartbeat, SlotDetector128};
use crate::resolver::{resolve_split_brain, ResolutionResult};
use crate::sim::network::SimMessage;
use crate::state_machine::apply_attestation;
use crate::types::{
    self, Hash256, LockId, LockRecord, LockStatus, NodeId,
    ShardId, SignersBitmask, SimTime,
};

/// O(1) Collision Lock Registry for banned nodes (ServerBann)
pub type BannedNodes = HashSet<NodeId>;
pub type ServerBann = BannedNodes;

/// A virtual shard node in the discrete simulation lab
#[derive(Clone, Debug)]
pub struct SimNode {
    pub id: NodeId,
    pub peers: BTreeSet<NodeId>,
    pub locks: BTreeMap<LockId, LockRecord>,
    pub parent_to_lock: BTreeMap<Hash256, LockId>,
    pub seen_gossips: BTreeSet<Hash256>,
    pub pending_attestations: BTreeMap<LockId, Vec<crate::types::Attestation>>,
    pub clock_drift_ms: i64,
    pub total_network_nodes: usize,
    /// O(1) ban list (ServerBann / BannedNodes) – banned perpetrators
    pub banned_nodes: BannedNodes,
    /// 128-slot direct-mapped detector for heartbeat spam (pillar 3)
    pub heartbeat_detector: SlotDetector128,
    /// Local missing_count counters per (LockId, NodeId): how often a candidate failed to respond
    pub missing_count: HashMap<(LockId, NodeId), u32>,
    /// Locally suspended nodes (HRW ranks removed from the quorum)
    pub suspended_nodes: HashSet<NodeId>,
    /// Active shard context: top-20 candidates per ShardId
    pub shard_candidates: HashMap<ShardId, Vec<NodeId>>,
}

impl SimNode {
    pub fn new(id: NodeId, total_network_nodes: usize) -> Self {
        Self {
            id,
            peers: BTreeSet::new(),
            locks: BTreeMap::new(),
            parent_to_lock: BTreeMap::new(),
            seen_gossips: BTreeSet::new(),
            pending_attestations: BTreeMap::new(),
            clock_drift_ms: 0,
            total_network_nodes,
            banned_nodes: HashSet::new(),
            heartbeat_detector: SlotDetector128::new(),
            missing_count: HashMap::new(),
            suspended_nodes: HashSet::new(),
            shard_candidates: HashMap::new(),
        }
    }

    /// Sets the top-20 candidates for a shard
    pub fn set_shard_candidates(&mut self, shard_id: ShardId, candidates: Vec<NodeId>) {
        self.shard_candidates.insert(shard_id, candidates);
    }

    /// Returns the HRW rank-21 node, if present
    pub fn hrw_rank_21(&self, shard_id: ShardId) -> Option<NodeId> {
        let active_nodes: Vec<NodeId> = self
            .peers
            .iter()
            .chain(std::iter::once(&self.id))
            .copied()
            .collect();
        let ranked = crate::types::hrw_rank_nodes(&active_nodes, shard_id);
        ranked.get(20).map(|(nid, _)| *nid)
    }

    /// Records a missing attestation from a candidate.
    /// Returns true if the failure threshold has been exceeded.
    pub fn record_missing(&mut self, lock_id: LockId, node_id: NodeId) -> bool {
        let count = self
            .missing_count
            .entry((lock_id, node_id))
            .or_insert(0);
        *count += 1;
        *count >= crate::types::MISSING_COUNT_THRESHOLD
    }

    /// Suspends a node locally
    pub fn suspend_node(&mut self, node_id: NodeId) {
        self.suspended_nodes.insert(node_id);
        self.missing_count.retain(|(_, nid), _| *nid != node_id);
    }

    /// Checks whether a node is suspended
    pub fn is_suspended(&self, node_id: NodeId) -> bool {
        self.suspended_nodes.contains(&node_id)
    }

    /// Creates a SignersBitmask from the current attestants of a lock
    pub fn signers_bitmask(&self, lock_id: &LockId, candidates: &[NodeId]) -> SignersBitmask {
        let mut mask: SignersBitmask = 0;
        if let Some(lock) = self.locks.get(lock_id) {
            for (i, candidate) in candidates.iter().enumerate() {
                if lock.signers.contains(candidate) && !self.is_suspended(*candidate) {
                    mask |= 1u32 << i;
                }
            }
        }
        mask
    }

    /// Processes a StreamClose message: checks the bitmask and suspends
    /// nodes that repeatedly failed to respond.
    /// Returns the promoted node (rank 21) if a candidate was suspended.
    pub fn handle_stream_close(
        &mut self,
        shard_id: ShardId,
        bitmask: SignersBitmask,
        lock_id: LockId,
    ) -> Option<NodeId> {
        let candidates = self.shard_candidates.get(&shard_id).cloned()?;

        let mut promoted = None;

        for (i, candidate) in candidates.iter().enumerate() {
            if !types::bitmask_has_bit(bitmask, i as u32) {
                if self.record_missing(lock_id, *candidate) {
                    self.suspend_node(*candidate);
                    if let Some(rank21) = self.hrw_rank_21(shard_id) {
                        promoted = Some(rank21);
                    }
                }
            } else {
                self.missing_count.remove(&(lock_id, *candidate));
            }
        }

        promoted
    }

    /// Removes a node from suspension
    pub fn unsuspend_node(&mut self, node_id: NodeId) {
        self.suspended_nodes.remove(&node_id);
    }

    // --- Bann / FraudProof API (O(1)) ---

    /// Checks whether a node is banned (O(1))
    pub fn is_banned(&self, node_id: NodeId) -> bool {
        self.banned_nodes.contains(&node_id)
    }

    /// Checks whether a public key is banned (32-byte, first 2 bytes NodeId)
    pub fn is_banned_pubkey(&self, pubkey: &[u8; 32]) -> bool {
        let nid = u16::from_le_bytes([pubkey[0], pubkey[1]]);
        self.is_banned(nid)
    }

    /// Verifies a FraudProofPayload (<100µs stateless)
    pub fn verify_fraud_proof(&self, proof: &FraudProofPayload) -> bool {
        proof.verify()
    }

    /// Verifies and bans the perpetrator in O(1). Returns true if banned.
    pub fn apply_fraud_proof(&mut self, proof: &FraudProofPayload) -> bool {
        if !proof.verify() {
            return false;
        }
        // O(1) insert
        self.banned_nodes.insert(proof.perpetrator);
        // If proof arrives via pubkey, fallback
        let pk_nid = u16::from_le_bytes([proof.perpetrator_node_id[0], proof.perpetrator_node_id[1]]);
        if pk_nid != proof.perpetrator {
            self.banned_nodes.insert(pk_nid);
        }
        true
    }

    /// Alias for apply_fraud_proof (satisfies the "ServerBann" requirement)
    pub fn ban_from_proof(&mut self, proof: &FraudProofPayload) -> bool {
        self.apply_fraud_proof(proof)
    }

    /// Direct O(1) ban without proof (for tests)
    pub fn ban_node(&mut self, node_id: NodeId) {
        self.banned_nodes.insert(node_id);
    }

    /// Observes heartbeats via 128-slot detector; on spam a proof is created and the node is banned immediately
    pub fn observe_heartbeat(&mut self, hb: Heartbeat) -> Option<FraudProofPayload> {
        if let Some(proof) = self.heartbeat_detector.observe(hb) {
            self.apply_fraud_proof(&proof);
            Some(proof)
        } else {
            None
        }
    }

    pub fn with_clock_drift(mut self, drift_ms: i64) -> Self {
        self.clock_drift_ms = drift_ms;
        self
    }

    pub fn add_peer(&mut self, peer_id: NodeId) {
        if peer_id != self.id {
            self.peers.insert(peer_id);
        }
    }

    /// Computes the local time of the node including drift
    pub fn local_time(&self, global_time: SimTime) -> SimTime {
        let drifted = (global_time.0 as i64 + self.clock_drift_ms).max(0) as u64;
        SimTime(drifted)
    }

    /// Updates the view of active network nodes (e.g. after a network merge)
    pub fn update_active_nodes(&mut self, new_total: usize) {
        self.total_network_nodes = new_total;
        // Re-evaluate all existing locks
        for lock in self.locks.values_mut() {
            if lock.status != LockStatus::Expired && !lock.status.is_void() {
                let sigs = lock.signers.len();
                let (req, is_final) = crate::types::required_quorum(new_total);
                if is_final {
                    if sigs >= req {
                        lock.status = LockStatus::Final { sigs };
                    }
                } else if sigs >= req {
                    lock.status = LockStatus::Provisional {
                        sigs,
                        required: req,
                    };
                }
            }
        }
    }

    /// Deterministically selects k = min(d, ceil(sqrt(d)) + 1) peers for epidemic gossip fan-out (docs/11:124)
    pub fn select_gossip_targets(&self, msg_hash: &Hash256, exclude: Option<NodeId>) -> Vec<NodeId> {
        let candidates: Vec<NodeId> = self
            .peers
            .iter()
            .copied()
            .filter(|&p| Some(p) != exclude)
            .collect();
        let d = candidates.len();
        if d <= 3 {
            return candidates; // Up to 3 friends: forward to all (100%)
        }
        let k = ((d as f64).sqrt().ceil() as usize + 1).min(d);

        let mut scored: Vec<(Hash256, NodeId)> = candidates
            .into_iter()
            .map(|p| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(msg_hash);
                hasher.update(&self.id.to_le_bytes());
                hasher.update(&p.to_le_bytes());
                (*hasher.finalize().as_bytes(), p)
            })
            .collect();
        scored.sort_by(|a, b| a.0.cmp(&b.0));
        scored.into_iter().take(k).map(|(_, p)| p).collect()
    }

    /// Processes an incoming message and returns outgoing messages
    pub fn handle_message(
        &mut self,
        from: NodeId,
        msg: SimMessage,
        global_time: SimTime,
    ) -> Vec<(NodeId, SimMessage)> {
        let mut outgoing = Vec::new();
        let local_t = self.local_time(global_time);

        match msg {
            SimMessage::LockRequest(mut record) => {
                self.seen_gossips.insert(record.id);
                let parent = record.parent_lock;

                if let Some(&existing_id) = self.parent_to_lock.get(&parent) {
                    if let Some(existing_lock) = self.locks.get_mut(&existing_id) {
                        let res = resolve_split_brain(existing_lock, &mut record);
                        match res {
                            ResolutionResult::Identical => {
                                // Idempotent: No-op
                                return outgoing;
                            }
                            ResolutionResult::WinnerA { .. } => {
                                // Existing lock won -> reject incoming
                                return outgoing;
                            }
                            ResolutionResult::WinnerB { .. } => {
                                // Incoming lock won -> replace existing
                                self.parent_to_lock.insert(parent, record.id);
                                self.locks.insert(record.id, record.clone());
                            }
                            ResolutionResult::NoConflict => {}
                        }
                    }
                } else {
                    self.parent_to_lock.insert(parent, record.id);
                    self.locks.insert(record.id, record.clone());
                }

                // Node signs local attestation
                let att = sign_lock_attestation(self.id, &record.id, &record.parent_lock, local_t);
                let mut receipt_hash_hasher = blake3::Hasher::new();
                receipt_hash_hasher.update(&record.id);
                receipt_hash_hasher.update(&self.id.to_le_bytes());
                let receipt_hash: Hash256 = *receipt_hash_hasher.finalize().as_bytes();
                self.seen_gossips.insert(receipt_hash);

                if let Some(stored) = self.locks.get_mut(&record.id) {
                    let _ = apply_attestation(stored, att.clone(), self.total_network_nodes);
                }

                // Apply pending attestations
                if let Some(pending) = self.pending_attestations.remove(&record.id) {
                    if let Some(stored) = self.locks.get_mut(&record.id) {
                        for pending_att in pending {
                            let _ =
                                apply_attestation(stored, pending_att, self.total_network_nodes);
                        }
                    }
                }

                // Gossip to k selected peers
                let targets = self.select_gossip_targets(&record.id, None);
                for peer in targets {
                    outgoing.push((
                        peer,
                        SimMessage::GossipLock {
                            lock: record.clone(),
                            hops: 1,
                        },
                    ));
                    outgoing.push((peer, SimMessage::LockAttestation(att.clone())));
                }
            }

            SimMessage::GossipLock { mut lock, hops } => {
                if hops > 16 {
                    return outgoing; // hop limit reached
                }

                // Dedup check via seen cache
                if !self.seen_gossips.insert(lock.id) {
                    return outgoing;
                }

                let parent = lock.parent_lock;
                let mut should_attest = true;

                if let Some(&existing_id) = self.parent_to_lock.get(&parent) {
                    if existing_id != lock.id {
                        if let Some(existing_lock) = self.locks.get_mut(&existing_id) {
                            let res = resolve_split_brain(existing_lock, &mut lock);
                            match res {
                                ResolutionResult::WinnerA { .. } => {
                                    // Existing won
                                    should_attest = false;
                                }
                                ResolutionResult::WinnerB { .. } => {
                                    // Incoming won
                                    self.parent_to_lock.insert(parent, lock.id);
                                    self.locks.insert(lock.id, lock.clone());
                                }
                                ResolutionResult::Identical => {
                                    should_attest = false;
                                }
                                ResolutionResult::NoConflict => {}
                            }
                        }
                    }
                } else {
                    self.parent_to_lock.insert(parent, lock.id);
                    self.locks.insert(lock.id, lock.clone());
                }

                if should_attest {
                    let att = sign_lock_attestation(self.id, &lock.id, &lock.parent_lock, local_t);
                    let mut receipt_hash_hasher = blake3::Hasher::new();
                    receipt_hash_hasher.update(&lock.id);
                    receipt_hash_hasher.update(&self.id.to_le_bytes());
                    let receipt_hash: Hash256 = *receipt_hash_hasher.finalize().as_bytes();
                    self.seen_gossips.insert(receipt_hash);

                    if let Some(stored) = self.locks.get_mut(&lock.id) {
                        let _ = apply_attestation(stored, att.clone(), self.total_network_nodes);
                    }

                    // Apply pending attestations
                    if let Some(pending) = self.pending_attestations.remove(&lock.id) {
                        if let Some(stored) = self.locks.get_mut(&lock.id) {
                            for pending_att in pending {
                                let _ = apply_attestation(
                                    stored,
                                    pending_att,
                                    self.total_network_nodes,
                                );
                            }
                        }
                    }

                    // Forward attestation and gossip to k selected peers
                    let targets = self.select_gossip_targets(&lock.id, Some(from));
                    for peer in targets {
                        outgoing.push((
                            peer,
                            SimMessage::GossipLock {
                                lock: lock.clone(),
                                hops: hops + 1,
                            },
                        ));
                        outgoing.push((peer, SimMessage::LockAttestation(att.clone())));
                    }
                }
            }

            SimMessage::LockAttestation(att) => {
                let mut receipt_hash_hasher = blake3::Hasher::new();
                receipt_hash_hasher.update(&att.lock_id);
                receipt_hash_hasher.update(&att.node_id.to_le_bytes());
                let receipt_hash: Hash256 = *receipt_hash_hasher.finalize().as_bytes();

                if !self.seen_gossips.insert(receipt_hash) {
                    return outgoing;
                }

                if let Some(stored) = self.locks.get_mut(&att.lock_id) {
                    let _ = apply_attestation(stored, att.clone(), self.total_network_nodes);
                } else {
                    self.pending_attestations
                        .entry(att.lock_id)
                        .or_default()
                        .push(att.clone());
                }

                // Forward attestation to k selected peers
                let targets = self.select_gossip_targets(&receipt_hash, Some(from));
                for peer in targets {
                    outgoing.push((
                        peer,
                        SimMessage::GossipReceipt {
                            lock_id: att.lock_id,
                            attestation: att.clone(),
                            hops: 1,
                        },
                    ));
                }
            }

            SimMessage::GossipReceipt {
                lock_id,
                attestation,
                hops,
            } => {
                if hops > 16 {
                    return outgoing;
                }

                let mut receipt_hash_hasher = blake3::Hasher::new();
                receipt_hash_hasher.update(&lock_id);
                receipt_hash_hasher.update(&attestation.node_id.to_le_bytes());
                let receipt_hash: Hash256 = *receipt_hash_hasher.finalize().as_bytes();

                if !self.seen_gossips.insert(receipt_hash) {
                    return outgoing;
                }

                if let Some(stored) = self.locks.get_mut(&lock_id) {
                    let _ =
                        apply_attestation(stored, attestation.clone(), self.total_network_nodes);
                } else {
                    self.pending_attestations
                        .entry(lock_id)
                        .or_default()
                        .push(attestation.clone());
                }

                // Forward to k selected peers
                let targets = self.select_gossip_targets(&receipt_hash, Some(from));
                for peer in targets {
                    outgoing.push((
                        peer,
                        SimMessage::GossipReceipt {
                            lock_id,
                            attestation: attestation.clone(),
                            hops: hops + 1,
                        },
                    ));
                }
            }

            SimMessage::FraudProof(proof) => {
                // Verify statelessly <100µs and ban in O(1)
                if self.apply_fraud_proof(&proof) {
                    // Priority-0 forwarding to all peers (except sender)
                    for &peer in &self.peers {
                        if peer != from {
                            outgoing.push((peer, SimMessage::FraudProof(proof.clone())));
                        }
                    }
                }
            }

            SimMessage::Heartbeat(hb) => {
                // 128-slot detector checks heartbeat spam
                if let Some(proof) = self.heartbeat_detector.observe(hb.clone()) {
                    // Ban self
                    self.apply_fraud_proof(&proof);
                    // Emergency alert to all peers
                    for &peer in &self.peers {
                        outgoing.push((peer, SimMessage::FraudProof(proof.clone())));
                    }
                } else {
                    // Forward normally (TTL not needed for test, simple flood)
                    for &peer in &self.peers {
                        if peer != from {
                            outgoing.push((peer, SimMessage::Heartbeat(hb.clone())));
                        }
                    }
                }
            }
        }

        outgoing
    }
}
