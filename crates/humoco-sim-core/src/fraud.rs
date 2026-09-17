use crate::crypto::{verify_attestation, DOMAIN_INGRESS_DECL};
use crate::types::{Attestation, NodeId, SimTime};

// ---------------------------------------------------------------------------
// Constants per spec 11 + 05
// ---------------------------------------------------------------------------

/// Threshold for Heartbeat spam: < 50 Minuten = 3000 Sekunden
pub const HEARTBEAT_SPAM_THRESHOLD_MS: u64 = 3_000_000; // 50*60*1000
/// Stale slot: > 75 Minuten (toter Knoten)
pub const SLOT_STALE_THRESHOLD_MS: u64 = 4_500_000; // 75*60*1000

pub const DOMAIN_HEARTBEAT: &[u8] = b"HUMOCO_V1_HEARTBEAT";

// ---------------------------------------------------------------------------
// FraudProofPillar
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FraudProofPillar {
    ShardEquivocation = 1,
    IngressCounterConflict = 2,
    HeartbeatSpam = 3,
}

impl FraudProofPillar {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Heartbeat {
    pub node_id: NodeId,
    pub timestamp: SimTime,
    #[serde(with = "crate::types::serde_bytes_64")]
    pub signature: [u8; 64],
}

pub fn sign_heartbeat(node_id: NodeId, timestamp: SimTime) -> Heartbeat {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[DOMAIN_HEARTBEAT.len() as u8]);
    hasher.update(DOMAIN_HEARTBEAT);
    hasher.update(&node_id.to_le_bytes());
    hasher.update(&timestamp.0.to_le_bytes());
    let digest = hasher.finalize();
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(digest.as_bytes());
    signature[32..34].copy_from_slice(&node_id.to_le_bytes());
    Heartbeat {
        node_id,
        timestamp,
        signature,
    }
}

pub fn verify_heartbeat(hb: &Heartbeat) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[DOMAIN_HEARTBEAT.len() as u8]);
    hasher.update(DOMAIN_HEARTBEAT);
    hasher.update(&hb.node_id.to_le_bytes());
    hasher.update(&hb.timestamp.0.to_le_bytes());
    let digest = hasher.finalize();
    hb.signature[..32] == *digest.as_bytes()
        && u16::from_le_bytes([hb.signature[32], hb.signature[33]]) == hb.node_id
}

// Serialization for Heartbeat (for evidence Vec<u8>)

fn encode_heartbeat(hb: &Heartbeat) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + 8 + 64);
    v.extend_from_slice(&hb.node_id.to_le_bytes());
    v.extend_from_slice(&hb.timestamp.0.to_le_bytes());
    v.extend_from_slice(&hb.signature);
    v
}

fn decode_heartbeat(bytes: &[u8]) -> Option<Heartbeat> {
    if bytes.len() != 2 + 8 + 64 {
        return None;
    }
    let node_id = u16::from_le_bytes([bytes[0], bytes[1]]);
    let ts = u64::from_le_bytes(bytes[2..10].try_into().ok()?);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[10..74]);
    Some(Heartbeat {
        node_id,
        timestamp: SimTime(ts),
        signature: sig,
    })
}

// Attestation serialisierung

fn encode_attestation(att: &Attestation) -> Vec<u8> {
    // lock_id 32 + parent_lock 32 + node_id 2 + timestamp 8 + signature 64 = 138
    let mut v = Vec::with_capacity(138);
    v.extend_from_slice(&att.lock_id);
    v.extend_from_slice(&att.parent_lock);
    v.extend_from_slice(&att.node_id.to_le_bytes());
    v.extend_from_slice(&att.timestamp.0.to_le_bytes());
    v.extend_from_slice(&att.signature);
    v
}

pub fn decode_attestation(bytes: &[u8]) -> Option<Attestation> {
    if bytes.len() != 138 {
        return None;
    }
    let mut lock_id = [0u8; 32];
    lock_id.copy_from_slice(&bytes[0..32]);
    let mut parent_lock = [0u8; 32];
    parent_lock.copy_from_slice(&bytes[32..64]);
    let node_id = u16::from_le_bytes([bytes[64], bytes[65]]);
    let ts = u64::from_le_bytes(bytes[66..74].try_into().ok()?);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[74..138]);
    Some(Attestation {
        lock_id,
        parent_lock,
        node_id,
        timestamp: SimTime(ts),
        signature: sig,
    })
}

// ---------------------------------------------------------------------------
// HeartbeatSlashingSlot (112 Bytes gem. docs, vereinfacht auf NodeId u16)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeartbeatSlashingSlot {
    pub node_id: NodeId,
    pub timestamp_unix: SimTime,
    #[serde(with = "crate::types::serde_bytes_64")]
    pub signature: [u8; 64],
}

impl HeartbeatSlashingSlot {
    pub fn from_heartbeat(hb: &Heartbeat) -> Self {
        Self {
            node_id: hb.node_id,
            timestamp_unix: hb.timestamp,
            signature: hb.signature,
        }
    }
}

// ---------------------------------------------------------------------------
// IngressEnvelopeEvidence (pillar 2: ingress counter collision)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IngressEnvelopeEvidence {
    pub gateway_pubkey: [u8; 32],
    pub epoch_day: u32,
    pub epoch_seq: u32,
    pub cumulative_micro_byte_years: u64,
    pub prev_day_final_bytes: u64,
    pub timestamp_ms: u64,
    pub lock_hash: [u8; 32],
    #[serde(with = "crate::types::serde_bytes_64")]
    pub signature: [u8; 64],
}

pub fn compute_ingress_envelope_digest(
    gateway_pubkey: &[u8; 32],
    epoch_day: u32,
    epoch_seq: u32,
    cumulative_micro_byte_years: u64,
    prev_day_final_bytes: u64,
    timestamp_ms: u64,
    lock_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = (DOMAIN_INGRESS_DECL.len() as u8).to_le_bytes();
    hasher.update(&tag_len);
    hasher.update(DOMAIN_INGRESS_DECL);
    hasher.update(gateway_pubkey);
    hasher.update(&epoch_day.to_le_bytes());
    hasher.update(&epoch_seq.to_le_bytes());
    hasher.update(&cumulative_micro_byte_years.to_le_bytes());
    hasher.update(&prev_day_final_bytes.to_le_bytes());
    hasher.update(&timestamp_ms.to_le_bytes());
    hasher.update(lock_hash);
    *hasher.finalize().as_bytes()
}

pub fn sign_ingress_envelope(
    gateway_pubkey: [u8; 32],
    epoch_day: u32,
    epoch_seq: u32,
    cumulative_micro_byte_years: u64,
    prev_day_final_bytes: u64,
    timestamp_ms: u64,
    lock_hash: [u8; 32],
) -> IngressEnvelopeEvidence {
    let digest = compute_ingress_envelope_digest(
        &gateway_pubkey,
        epoch_day,
        epoch_seq,
        cumulative_micro_byte_years,
        prev_day_final_bytes,
        timestamp_ms,
        &lock_hash,
    );
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&digest);
    signature[32..64].copy_from_slice(&gateway_pubkey);
    IngressEnvelopeEvidence {
        gateway_pubkey,
        epoch_day,
        epoch_seq,
        cumulative_micro_byte_years,
        prev_day_final_bytes,
        timestamp_ms,
        lock_hash,
        signature,
    }
}

pub fn encode_ingress_envelope(env: &IngressEnvelopeEvidence) -> Vec<u8> {
    bincode::serialize(env).unwrap_or_default()
}

pub fn decode_ingress_envelope(bytes: &[u8]) -> Option<IngressEnvelopeEvidence> {
    if bytes.is_empty() || bytes.len() >= 512 {
        return None;
    }
    bincode::deserialize(bytes).ok()
}

pub fn verify_ingress_envelope_signature(env: &IngressEnvelopeEvidence) -> bool {
    let digest = compute_ingress_envelope_digest(
        &env.gateway_pubkey,
        env.epoch_day,
        env.epoch_seq,
        env.cumulative_micro_byte_years,
        env.prev_day_final_bytes,
        env.timestamp_ms,
        &env.lock_hash,
    );
    env.signature[..32] == digest && env.signature[32..64] == env.gateway_pubkey
}

// ---------------------------------------------------------------------------
// FraudProofPayload / FraudProof
// ---------------------------------------------------------------------------

pub type FraudProof = FraudProofPayload;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FraudProofPayload {
    /// Perpetrator as 32-byte public key (first 2 bytes = NodeId LE for simulation)
    pub perpetrator_node_id: [u8; 32],
    pub proof_pillar: FraudProofPillar,
    /// 7-byte padding (only for wire compatibility, ignored)
    pub _padding: [u8; 7],
    pub evidence_packet_a: Vec<u8>,
    pub evidence_packet_b: Vec<u8>,
    pub reporter_node_id: [u8; 32],
    #[serde(with = "crate::types::serde_bytes_64")]
    pub reporter_signature: [u8; 64],
    /// Convenience: perpetrator as NodeId
    pub perpetrator: NodeId,
    /// Pillar alias (so tests can use both names)
    pub pillar: FraudProofPillar,
}

impl FraudProofPayload {
    fn pubkey_from_node_id(node_id: NodeId) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0..2].copy_from_slice(&node_id.to_le_bytes());
        // remaining bytes deterministically derived via blake3 for uniqueness
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"HUMOCO_NODE_PUBKEY");
        hasher.update(&node_id.to_le_bytes());
        let h = hasher.finalize();
        pk[2..].copy_from_slice(&h.as_bytes()[2..32]);
        pk
    }

    fn node_id_from_pubkey(pk: &[u8; 32]) -> NodeId {
        u16::from_le_bytes([pk[0], pk[1]])
    }

    /// Create pillar 1 proof from two attestations (L3A != L3B, same parent_lock)
    pub fn new_shard_equivocation(a: Attestation, b: Attestation) -> Self {
        assert_eq!(a.node_id, b.node_id, "equivocation requires same signer");
        let perpetrator = a.node_id;
        let perpetrator_node_id = Self::pubkey_from_node_id(perpetrator);
        let pillar = FraudProofPillar::ShardEquivocation;
        Self {
            perpetrator_node_id,
            proof_pillar: pillar,
            _padding: [0u8; 7],
            evidence_packet_a: encode_attestation(&a),
            evidence_packet_b: encode_attestation(&b),
            reporter_node_id: [0u8; 32],
            reporter_signature: [0u8; 64],
            perpetrator,
            pillar,
        }
    }

    /// Alternative constructor with explicit reporter
    pub fn new_shard_equivocation_with_reporter(
        a: Attestation,
        b: Attestation,
        reporter: NodeId,
    ) -> Self {
        let mut p = Self::new_shard_equivocation(a, b);
        p.reporter_node_id = Self::pubkey_from_node_id(reporter);
        p
    }

    /// Create pillar 3 proof from two heartbeats
    pub fn new_heartbeat_spam(a: Heartbeat, b: Heartbeat) -> Self {
        assert_eq!(a.node_id, b.node_id, "heartbeat spam requires same node");
        let perpetrator = a.node_id;
        let perpetrator_node_id = Self::pubkey_from_node_id(perpetrator);
        let pillar = FraudProofPillar::HeartbeatSpam;
        Self {
            perpetrator_node_id,
            proof_pillar: pillar,
            _padding: [0u8; 7],
            evidence_packet_a: encode_heartbeat(&a),
            evidence_packet_b: encode_heartbeat(&b),
            reporter_node_id: [0u8; 32],
            reporter_signature: [0u8; 64],
            perpetrator,
            pillar,
        }
    }

    pub fn new_heartbeat_spam_with_reporter(a: Heartbeat, b: Heartbeat, reporter: NodeId) -> Self {
        let mut p = Self::new_heartbeat_spam(a, b);
        p.reporter_node_id = Self::pubkey_from_node_id(reporter);
        p
    }

    /// Create pillar 2 proof from two ingress evidences (IngressCounterConflict)
    pub fn new_ingress_counter_conflict(
        a: IngressEnvelopeEvidence,
        b: IngressEnvelopeEvidence,
    ) -> Self {
        assert_eq!(
            a.gateway_pubkey, b.gateway_pubkey,
            "ingress counter conflict requires same gateway signer"
        );
        let perpetrator_node_id = a.gateway_pubkey;
        let perpetrator = Self::node_id_from_pubkey(&perpetrator_node_id);
        let pillar = FraudProofPillar::IngressCounterConflict;
        Self {
            perpetrator_node_id,
            proof_pillar: pillar,
            _padding: [0u8; 7],
            evidence_packet_a: encode_ingress_envelope(&a),
            evidence_packet_b: encode_ingress_envelope(&b),
            reporter_node_id: [0u8; 32],
            reporter_signature: [0u8; 64],
            perpetrator,
            pillar,
        }
    }

    pub fn new_ingress_counter_conflict_with_reporter(
        a: IngressEnvelopeEvidence,
        b: IngressEnvelopeEvidence,
        reporter: NodeId,
    ) -> Self {
        let mut p = Self::new_ingress_counter_conflict(a, b);
        p.reporter_node_id = Self::pubkey_from_node_id(reporter);
        p
    }

    /// Generic verify dispatcher
    pub fn verify(&self) -> bool {
        match self.proof_pillar {
            FraudProofPillar::ShardEquivocation => self.verify_shard_equivocation(),
            FraudProofPillar::HeartbeatSpam => self.verify_heartbeat_spam(),
            FraudProofPillar::IngressCounterConflict => self.verify_ingress_counter_conflict(),
        }
    }

    fn verify_shard_equivocation(&self) -> bool {
        let a = match decode_attestation(&self.evidence_packet_a) {
            Some(v) => v,
            None => return false,
        };
        let b = match decode_attestation(&self.evidence_packet_b) {
            Some(v) => v,
            None => return false,
        };
        // Same signer == perpetrator
        if a.node_id != b.node_id {
            return false;
        }
        let perp = Self::node_id_from_pubkey(&self.perpetrator_node_id);
        // perpetrator field alias check (allow either)
        if perp != a.node_id && self.perpetrator != a.node_id {
            // if mismatch, still check that stored perpetrator equals signer
            // we allow both representations to match
            return false;
        }
        // Must be same parent_lock (INV: double-spend on same voucher/parent)
        if a.parent_lock != b.parent_lock {
            return false;
        }
        // Must be different lock_ids (L3A != L3B)
        if a.lock_id == b.lock_id {
            return false;
        }
        // Both signatures must be valid
        if !verify_attestation(&a) || !verify_attestation(&b) {
            return false;
        }
        true
    }

    fn verify_heartbeat_spam(&self) -> bool {
        let a = match decode_heartbeat(&self.evidence_packet_a) {
            Some(v) => v,
            None => return false,
        };
        let b = match decode_heartbeat(&self.evidence_packet_b) {
            Some(v) => v,
            None => return false,
        };
        if a.node_id != b.node_id {
            return false;
        }
        let perp = Self::node_id_from_pubkey(&self.perpetrator_node_id);
        if perp != a.node_id && self.perpetrator != a.node_id {
            return false;
        }
        if !verify_heartbeat(&a) || !verify_heartbeat(&b) {
            return false;
        }
        let delta = a.timestamp.0.abs_diff(b.timestamp.0);
        delta < HEARTBEAT_SPAM_THRESHOLD_MS
    }

    pub fn verify_ingress_counter_conflict(&self) -> bool {
        let a = match decode_ingress_envelope(&self.evidence_packet_a) {
            Some(v) => v,
            None => return false,
        };
        let b = match decode_ingress_envelope(&self.evidence_packet_b) {
            Some(v) => v,
            None => return false,
        };

        // Verify signatures of both packets (anti-framing protection)
        if !verify_ingress_envelope_signature(&a) || !verify_ingress_envelope_signature(&b) {
            return false;
        }

        // Signer check: a.gateway_pubkey == b.gateway_pubkey
        if a.gateway_pubkey != b.gateway_pubkey {
            return false;
        }

        // Perpetrator check: must match self.perpetrator_node_id
        if self.perpetrator_node_id != a.gateway_pubkey {
            return false;
        }

        // Normalize without loss of generality so that p1 is the temporally/epoch-wise earlier packet:
        // If (a.epoch_day, a.epoch_seq, a.timestamp_ms) > (b.epoch_day, b.epoch_seq, b.timestamp_ms): swap p1 and p2
        let (p1, p2) = if (a.epoch_day, a.epoch_seq, a.timestamp_ms)
            > (b.epoch_day, b.epoch_seq, b.timestamp_ms)
        {
            (b, a)
        } else {
            (a, b)
        };

        // Mathematically proven 8-path trichotomy matrix:
        if p1.epoch_day == p2.epoch_day {
            // Case 1 (same day: p1.epoch_day == p2.epoch_day)
            if p1.epoch_seq == p2.epoch_seq {
                if p1.lock_hash != p2.lock_hash {
                    true // Path 2: sequence fork!
                } else {
                    false // Path 1: idempotent duplicate
                }
            } else {
                // Since normalized: p2.epoch_seq > p1.epoch_seq
                if p2.cumulative_micro_byte_years < p1.cumulative_micro_byte_years {
                    true // Path 4: counter rollback!
                } else {
                    false // Path 3: regular monotonic growth
                }
            }
        } else if p2.epoch_day == p1.epoch_day + 1 {
            // Case 2 (next day: p2.epoch_day == p1.epoch_day + 1)
            if p1.cumulative_micro_byte_years > p2.prev_day_final_bytes {
                true // Path 7: prior-day embezzlement!
            } else {
                false // Path 6: honest midnight transition (incl. path 5)
            }
        } else {
            // Case 3 (gap >= 2 days: p2.epoch_day > p1.epoch_day + 1)
            false // Path 8: rest day / gap >= 2 days, zero state bloat
        }
    }

    /// Alias for compatibility: proof_pillar vs pillar
    pub fn pillar_kind(&self) -> FraudProofPillar {
        self.proof_pillar
    }
}

// ---------------------------------------------------------------------------
// SlotDetector (128 bzw. 1024 Slots gem. docs/11 & C-05)
// ---------------------------------------------------------------------------

pub const NUM_SLASHING_SLOTS_128: usize = 128;
pub const NUM_SLASHING_SLOTS_1024: usize = 1024;

#[derive(Clone, Debug)]
pub struct SlotDetector<const N: usize> {
    slots: [Option<HeartbeatSlashingSlot>; N],
}

pub type SlotDetector128 = SlotDetector<128>;
pub type SlotDetector1024 = SlotDetector<1024>;

impl<const N: usize> Default for SlotDetector<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SlotDetector<N> {
    pub fn new() -> Self {
        Self {
            slots: [None; N],
        }
    }

    #[inline]
    pub fn slot_index(node_id: NodeId) -> usize {
        (node_id as usize) % N
    }

    /// Observe a heartbeat.
    /// On fraud (<50 min) immediately returns a FraudProofPayload and clears the slot.
    /// On stale (>75 min) or empty slot, stores the heartbeat.
    /// On a foreign fresh slot, does not store (tolerate collision).
    pub fn observe(&mut self, hb: Heartbeat) -> Option<FraudProofPayload> {
        // Optional freshness filter: heartbeat must have valid signature, otherwise ignore
        if !verify_heartbeat(&hb) {
            return None;
        }
        let idx = Self::slot_index(hb.node_id);
        match self.slots[idx] {
            None => {
                // Case 1: free -> store
                self.slots[idx] = Some(HeartbeatSlashingSlot::from_heartbeat(&hb));
                None
            }
            Some(existing) => {
                // Check staleness: if existing is older than 75 min vs new heartbeat
                let age = if hb.timestamp.0 > existing.timestamp_unix.0 {
                    hb.timestamp.0 - existing.timestamp_unix.0
                } else {
                    // if hb is older (clock skew), treat as stale? Use absolute diff for stale check
                    existing.timestamp_unix.0.saturating_sub(hb.timestamp.0)
                };
                if age > SLOT_STALE_THRESHOLD_MS {
                    // Slot free due to stale entry: overwrite
                    self.slots[idx] = Some(HeartbeatSlashingSlot::from_heartbeat(&hb));
                    return None;
                }
                // Fresh slot
                if existing.node_id != hb.node_id {
                    // Case 3: foreign fresh node occupies slot -> do not store
                    return None;
                }
                // Case 2: same NodeId
                let delta = hb.timestamp.0.abs_diff(existing.timestamp_unix.0);
                if delta < HEARTBEAT_SPAM_THRESHOLD_MS {
                    // FRAUD!
                    let prev_hb = Heartbeat {
                        node_id: existing.node_id,
                        timestamp: existing.timestamp_unix,
                        signature: existing.signature,
                    };
                    let proof = FraudProofPayload::new_heartbeat_spam(prev_hb, hb.clone());
                    // Free the slot again
                    self.slots[idx] = None;
                    Some(proof)
                } else {
                    // Honest: update
                    self.slots[idx] = Some(HeartbeatSlashingSlot::from_heartbeat(&hb));
                    None
                }
            }
        }
    }

    /// Direct variant that checks the heartbeat signature and yields the slot
    pub fn observe_raw(&mut self, node_id: NodeId, timestamp: SimTime, signature: [u8; 64]) -> Option<FraudProofPayload> {
        self.observe(Heartbeat {
            node_id,
            timestamp,
            signature,
        })
    }

    pub fn get_slot(&self, node_id: NodeId) -> Option<HeartbeatSlashingSlot> {
        self.slots[Self::slot_index(node_id)]
    }

    pub fn is_empty(&self, node_id: NodeId) -> bool {
        self.slots[Self::slot_index(node_id)].is_none()
    }

    pub fn clear(&mut self) {
        self.slots = [None; N];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pillar_values() {
        assert_eq!(FraudProofPillar::ShardEquivocation as u8, 1);
        assert_eq!(FraudProofPillar::IngressCounterConflict as u8, 2);
        assert_eq!(FraudProofPillar::HeartbeatSpam as u8, 3);
    }

    #[test]
    fn test_slot_detector_spam() {
        let mut det = SlotDetector128::new();
        let hb1 = sign_heartbeat(7, SimTime(0));
        assert!(det.observe(hb1.clone()).is_none());
        // 10 minutes later -> spam
        let hb2 = sign_heartbeat(7, SimTime(600_000));
        let proof = det.observe(hb2.clone());
        assert!(proof.is_some());
        let p = proof.unwrap();
        assert_eq!(p.proof_pillar, FraudProofPillar::HeartbeatSpam);
        assert!(p.verify());
    }

    #[test]
    fn test_slot_detector_honest_no_spam() {
        let mut det = SlotDetector128::new();
        let hb1 = sign_heartbeat(7, SimTime(0));
        assert!(det.observe(hb1).is_none());
        // 60 minutes later -> honest
        let hb2 = sign_heartbeat(7, SimTime(3_600_000));
        assert!(det.observe(hb2).is_none());
    }

    fn dummy_pubkey(id: u16) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0..2].copy_from_slice(&id.to_le_bytes());
        pk[2..].fill(0x55);
        pk
    }

    #[test]
    fn test_ingress_envelope_sign_decode_verify() {
        let pk = dummy_pubkey(42);
        let lock_hash = [0xAA; 32];
        let env = sign_ingress_envelope(pk, 10, 1, 100_000, 0, 1_000_000, lock_hash);

        assert!(verify_ingress_envelope_signature(&env));

        let bytes = encode_ingress_envelope(&env);
        assert!(bytes.len() < 512);

        let decoded = decode_ingress_envelope(&bytes).expect("must decode");
        assert_eq!(decoded, env);
        assert!(verify_ingress_envelope_signature(&decoded));

        // Test length boundaries:
        assert!(decode_ingress_envelope(&[]).is_none());
        let oversized = vec![0u8; 512];
        assert!(decode_ingress_envelope(&oversized).is_none());
        let huge = vec![0u8; 1024];
        assert!(decode_ingress_envelope(&huge).is_none());

        // Corrupted payload:
        let mut corrupted = bytes.clone();
        corrupted.truncate(10);
        assert!(decode_ingress_envelope(&corrupted).is_none());
    }

    #[test]
    fn test_ingress_counter_conflict_all_8_paths() {
        let pk = dummy_pubkey(99);
        let hash_a = [0x11; 32];
        let hash_b = [0x22; 32];

        // Path 1 (same day, p1.seq == p2.seq, p1.lock_hash == p2.lock_hash) -> idempotent duplicate -> false
        let p1 = sign_ingress_envelope(pk, 5, 10, 500, 0, 1000, hash_a);
        let p2_same = sign_ingress_envelope(pk, 5, 10, 500, 0, 1000, hash_a);
        let proof_path1 = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_same);
        assert!(!proof_path1.verify(), "Path 1 must be false");

        // Path 2 (same day, p1.seq == p2.seq, p1.lock_hash != p2.lock_hash) -> sequence fork! -> true
        let p2_fork = sign_ingress_envelope(pk, 5, 10, 500, 0, 1000, hash_b);
        let proof_path2 = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_fork);
        assert!(proof_path2.verify(), "Path 2 must be true (sequence fork)");

        // Path 3 (same day, p2.seq > p1.seq, p2.cumul >= p1.cumul) -> regular monotonic growth -> false
        let p2_growth = sign_ingress_envelope(pk, 5, 11, 600, 0, 2000, hash_b);
        let proof_path3 = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_growth);
        assert!(!proof_path3.verify(), "Path 3 must be false");

        // Path 4 (same day, p2.seq > p1.seq, p2.cumul < p1.cumul) -> counter rollback! -> true
        let p2_rollback = sign_ingress_envelope(pk, 5, 11, 400, 0, 2000, hash_b);
        let proof_path4 = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_rollback);
        assert!(proof_path4.verify(), "Path 4 must be true (counter rollback)");

        // Path 5 (next day, p1.cumul < p2.prev_day_final_bytes) -> honest midnight transition with later locks -> false
        let p2_next_day_honest_more = sign_ingress_envelope(pk, 6, 1, 50, 600, 3000, hash_b);
        let proof_path5 = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_next_day_honest_more);
        assert!(!proof_path5.verify(), "Path 5 must be false");

        // Path 6 (next day, p1.cumul == p2.prev_day_final_bytes) -> honest midnight transition, exact close -> false
        let p2_next_day_honest_exact = sign_ingress_envelope(pk, 6, 1, 50, 500, 3000, hash_b);
        let proof_path6 = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_next_day_honest_exact);
        assert!(!proof_path6.verify(), "Path 6 must be false");

        // Path 7 (next day, p1.cumul > p2.prev_day_final_bytes) -> prior-day embezzlement! -> true
        let p2_next_day_fraud = sign_ingress_envelope(pk, 6, 1, 50, 400, 3000, hash_b);
        let proof_path7 = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_next_day_fraud);
        assert!(proof_path7.verify(), "Path 7 must be true (prior-day embezzlement)");

        // Path 8 (gap >= 2 days: p2.epoch_day > p1.epoch_day + 1) -> rest day -> false
        let p2_gap_day = sign_ingress_envelope(pk, 8, 1, 50, 100, 5000, hash_b);
        let proof_path8 = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2_gap_day);
        assert!(!proof_path8.verify(), "Path 8 must be false (rest day)");
    }

    #[test]
    fn test_ingress_counter_conflict_reordering_symmetry() {
        let pk = dummy_pubkey(123);
        let hash_a = [0x11; 32];
        let hash_b = [0x22; 32];

        // Fraud path 4: (p1, p2) vs (p2, p1)
        let p1 = sign_ingress_envelope(pk, 10, 1, 1000, 0, 100, hash_a);
        let p2 = sign_ingress_envelope(pk, 10, 2, 800, 0, 200, hash_b);

        let proof_ordered = FraudProofPayload::new_ingress_counter_conflict(p1.clone(), p2.clone());
        let proof_reversed = FraudProofPayload::new_ingress_counter_conflict(p2.clone(), p1.clone());
        assert!(proof_ordered.verify());
        assert!(proof_reversed.verify());

        // Fraud path 7: next day (p1, p2) vs (p2, p1)
        let p_day1 = sign_ingress_envelope(pk, 10, 5, 2000, 0, 1000, hash_a);
        let p_day2_fraud = sign_ingress_envelope(pk, 11, 1, 100, 1500, 2000, hash_b);

        let proof_fwd = FraudProofPayload::new_ingress_counter_conflict(p_day1.clone(), p_day2_fraud.clone());
        let proof_rev = FraudProofPayload::new_ingress_counter_conflict(p_day2_fraud.clone(), p_day1.clone());
        assert!(proof_fwd.verify());
        assert!(proof_rev.verify());

        // Honest path 3: (p1, p2) vs (p2, p1)
        let p_growth = sign_ingress_envelope(pk, 10, 6, 2500, 0, 3000, hash_b);
        let proof_growth_fwd = FraudProofPayload::new_ingress_counter_conflict(p_day1.clone(), p_growth.clone());
        let proof_growth_rev = FraudProofPayload::new_ingress_counter_conflict(p_growth.clone(), p_day1.clone());
        assert!(!proof_growth_fwd.verify());
        assert!(!proof_growth_rev.verify());
    }

    #[test]
    fn test_ingress_counter_conflict_anti_framing() {
        let pk_victim = dummy_pubkey(1);
        let pk_attacker = dummy_pubkey(2);
        let hash = [0xAA; 32];

        let mut p1 = sign_ingress_envelope(pk_victim, 5, 1, 1000, 0, 100, hash);
        let p2 = sign_ingress_envelope(pk_victim, 5, 2, 500, 0, 200, [0xBB; 32]); // Betrug

        // Framing 1: tampered signature on packet 1
        p1.signature[0] ^= 0xFF;
        let mut proof_bad_sig_a = FraudProofPayload::new_ingress_counter_conflict(p2.clone(), p2.clone());
        proof_bad_sig_a.evidence_packet_a = encode_ingress_envelope(&p1);
        proof_bad_sig_a.evidence_packet_b = encode_ingress_envelope(&p2);
        assert!(!proof_bad_sig_a.verify(), "invalid signature on packet A must be rejected");

        // Framing 2: tampered signature on packet 2
        let mut p2_bad = p2.clone();
        p2_bad.signature[5] ^= 0xAA;
        let mut proof_bad_sig_b = FraudProofPayload::new_ingress_counter_conflict(p2.clone(), p2.clone());
        let p1_good = sign_ingress_envelope(pk_victim, 5, 1, 1000, 0, 100, hash);
        proof_bad_sig_b.evidence_packet_a = encode_ingress_envelope(&p1_good);
        proof_bad_sig_b.evidence_packet_b = encode_ingress_envelope(&p2_bad);
        assert!(!proof_bad_sig_b.verify(), "invalid signature on packet B must be rejected");

        // Framing 3: two different signers (attacker plants foreign packet)
        let p_foreign = sign_ingress_envelope(pk_attacker, 5, 2, 500, 0, 200, [0xBB; 32]);
        let mut proof_diff_signers = FraudProofPayload::new_ingress_counter_conflict(p1_good.clone(), p1_good.clone());
        proof_diff_signers.evidence_packet_a = encode_ingress_envelope(&p1_good);
        proof_diff_signers.evidence_packet_b = encode_ingress_envelope(&p_foreign);
        assert!(!proof_diff_signers.verify(), "different signers must never count as fraud");

        // Framing 4: wrong perpetrator_node_id declared
        let mut proof_wrong_perp = FraudProofPayload::new_ingress_counter_conflict(p1_good.clone(), p2.clone());
        proof_wrong_perp.perpetrator_node_id = pk_attacker;
        assert!(!proof_wrong_perp.verify(), "wrong perpetrator_node_id must be rejected");

        // Framing 5: corrupted evidence data
        let mut proof_corrupt = FraudProofPayload::new_ingress_counter_conflict(p1_good.clone(), p2.clone());
        proof_corrupt.evidence_packet_a = vec![0xFF; 20];
        assert!(!proof_corrupt.verify(), "corrupted evidence must yield false");
    }

    #[test]
    fn test_ingress_counter_conflict_fuzz_10k() {
        struct SimpleRng(u64);
        impl SimpleRng {
            fn new(seed: u64) -> Self { Self(seed.max(1)) }
            fn next_u64(&mut self) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
            fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
            fn gen_range(&mut self, min: u64, max: u64) -> u64 {
                min + (self.next_u64() % (max - min + 1))
            }
        }

        let mut rng = SimpleRng::new(0xDEAD_BEEF_CAFE_BABE);

        for _ in 0..10_000 {
            let nid = (rng.next_u32() % 1000) as u16;
            let pk = dummy_pubkey(nid);
            let path = (rng.next_u32() % 8) + 1; // 1..=8

            let base_day = rng.next_u32() % 100_000;
            let base_seq = (rng.next_u32() % 10_000) + 1;
            let base_cumul = rng.gen_range(10_000, 1_000_000);
            let ts1 = rng.gen_range(1_000, 100_000);

            let mut hash1 = [0u8; 32];
            hash1[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
            let mut hash2 = [0u8; 32];
            hash2[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
            if hash1 == hash2 {
                hash2[0] ^= 0xFF;
            }

            let (p1, p2, expected_fraud) = match path {
                // Path 1: same day, seq1 == seq2, hash1 == hash2 -> false
                1 => {
                    let a = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1, hash1);
                    let b = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1 + 10, hash1);
                    (a, b, false)
                }
                // Path 2: same day, seq1 == seq2, hash1 != hash2 -> true
                2 => {
                    let a = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1, hash1);
                    let b = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1 + 10, hash2);
                    (a, b, true)
                }
                // Path 3: same day, seq2 > seq1, cum2 >= cum1 -> false
                3 => {
                    let delta_cum = rng.gen_range(0, 100_000);
                    let a = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1, hash1);
                    let b = sign_ingress_envelope(pk, base_day, base_seq + 1, base_cumul + delta_cum, 0, ts1 + 50, hash2);
                    (a, b, false)
                }
                // Path 4: same day, seq2 > seq1, cum2 < cum1 -> true
                4 => {
                    let drop = rng.gen_range(1, base_cumul.min(50_000));
                    let a = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1, hash1);
                    let b = sign_ingress_envelope(pk, base_day, base_seq + 1, base_cumul - drop, 0, ts1 + 50, hash2);
                    (a, b, true)
                }
                // Path 5: next day, cum1 < prev_day_final_bytes -> false
                5 => {
                    let prev_final = base_cumul + rng.gen_range(1, 50_000);
                    let a = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1, hash1);
                    let b = sign_ingress_envelope(pk, base_day + 1, 1, 500, prev_final, ts1 + 86_400_000, hash2);
                    (a, b, false)
                }
                // Path 6: next day, cum1 == prev_day_final_bytes -> false
                6 => {
                    let prev_final = base_cumul;
                    let a = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1, hash1);
                    let b = sign_ingress_envelope(pk, base_day + 1, 1, 500, prev_final, ts1 + 86_400_000, hash2);
                    (a, b, false)
                }
                // Path 7: next day, cum1 > prev_day_final_bytes -> true
                7 => {
                    let prev_final = base_cumul.saturating_sub(rng.gen_range(1, 10_000));
                    let a = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1, hash1);
                    let b = sign_ingress_envelope(pk, base_day + 1, 1, 500, prev_final, ts1 + 86_400_000, hash2);
                    (a, b, true)
                }
                // Path 8: gap >= 2 days -> false
                8 => {
                    let gap = (rng.next_u32() % 50) + 2;
                    let a = sign_ingress_envelope(pk, base_day, base_seq, base_cumul, 0, ts1, hash1);
                    let b = sign_ingress_envelope(pk, base_day + gap, 1, 500, 100, ts1 + (gap as u64) * 86_400_000, hash2);
                    (a, b, false)
                }
                _ => unreachable!(),
            };

            // Random order (a, b) vs (b, a)
            let (packet_a, packet_b) = if rng.next_u32().is_multiple_of(2) {
                (p1, p2)
            } else {
                (p2, p1)
            };

            let proof = FraudProofPayload::new_ingress_counter_conflict(packet_a, packet_b);
            let verified = proof.verify();
            assert_eq!(
                verified,
                expected_fraud,
                "Fuzz failure on path {}: expected fraud={}, got={}",
                path,
                expected_fraud,
                verified
            );
        }
    }
}
