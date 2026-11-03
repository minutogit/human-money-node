pub use crate::crypto::DOMAIN_HB_ANNOUNCE;
use crate::crypto::{
    compute_attestation_payload_digest, compute_sig_digest, verify_attestation, DOMAIN_INGRESS_DECL,
};
use crate::types::{Attestation, NetworkId, NodeId, SimTime};

// ---------------------------------------------------------------------------
// FraudProofPillar
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FraudProofPillar {
    ShardEquivocation = 1,
    IngressCounterConflict = 2,
}

impl FraudProofPillar {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// Attestation serialisierung

fn encode_attestation(att: &Attestation) -> Vec<u8> {
    // lock_id 32 + parent_lock 32 + node_id 2 + timestamp 8 + signature 64 + shard_id 2 = 140
    let mut v = Vec::with_capacity(140);
    v.extend_from_slice(&att.lock_id);
    v.extend_from_slice(&att.parent_lock);
    v.extend_from_slice(&att.node_id.to_le_bytes());
    v.extend_from_slice(&att.timestamp.0.to_le_bytes());
    v.extend_from_slice(&att.signature);
    v.extend_from_slice(&att.shard_id.to_le_bytes());
    v
}

pub fn decode_attestation(bytes: &[u8]) -> Option<Attestation> {
    if bytes.len() != 138 && bytes.len() != 140 {
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
    let shard_id = if bytes.len() >= 140 {
        u16::from_le_bytes([bytes[138], bytes[139]])
    } else {
        crate::types::extract_shard_id(&parent_lock)
    };
    Some(Attestation {
        lock_id,
        parent_lock,
        node_id,
        timestamp: SimTime(ts),
        signature: sig,
        shard_id,
    })
}

// ---------------------------------------------------------------------------
// IngressEnvelopeEvidence (pillar 2: ingress counter collision)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IngressEnvelopeEvidence {
    pub gateway_pubkey: [u8; 32],
    #[serde(default)]
    pub epoch_day: u32,
    #[serde(default)]
    pub epoch_seq: u64,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub declared_write_ema_micro_bj: u64,
    #[serde(default)]
    pub declared_read_ema_credits: u64,
    #[serde(default)]
    pub footprint_micro_bj: u64,
    #[serde(default)]
    pub is_read: bool,
    #[serde(default)]
    pub op_hash: [u8; 32],
    #[serde(with = "crate::types::serde_bytes_64")]
    pub signature: [u8; 64],
}

impl Default for IngressEnvelopeEvidence {
    fn default() -> Self {
        Self {
            gateway_pubkey: [0u8; 32],
            epoch_day: 0,
            epoch_seq: 0,
            timestamp_ms: 0,
            declared_write_ema_micro_bj: 0,
            declared_read_ema_credits: 0,
            footprint_micro_bj: 0,
            is_read: false,
            op_hash: [0u8; 32],
            signature: [0u8; 64],
        }
    }
}

impl IngressEnvelopeEvidence {
    /// Epoch-bound constructor (Phase 1 P0): `epoch_day` / `epoch_seq` are part of
    /// the signed preimage so envelopes cannot be replayed across days or reordered
    /// within a day without invalidating the Ed25519 signature.
    #[allow(clippy::too_many_arguments)]
    pub fn new_v2(
        gateway_pubkey: [u8; 32],
        epoch_day: u32,
        epoch_seq: u64,
        timestamp_ms: u64,
        declared_write_ema_micro_bj: u64,
        declared_read_ema_credits: u64,
        footprint_micro_bj: u64,
        is_read: bool,
        op_hash: [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        Self {
            gateway_pubkey,
            epoch_day,
            epoch_seq,
            timestamp_ms,
            declared_write_ema_micro_bj,
            declared_read_ema_credits,
            footprint_micro_bj,
            is_read,
            op_hash,
            signature,
        }
    }
}

/// # Architectural Invariant: Epoch-Bound Ingress Envelope (Phase 1 P0)
///
/// `epoch_day` and `epoch_seq` are folded into the signed preimage so a captured
/// envelope cannot be replayed on a later day or reordered within the same day.
/// Verifiers must reconstruct the digest from the envelope's own
/// `(epoch_day, epoch_seq)` fields; envelopes with mismatched epochs fail
/// Ed25519 verification and never trigger quota-fraud slashing.
///
/// Digest = BLAKE3(len || DOMAIN_INGRESS_DECL || gateway_pubkey || epoch_day_le
///   || epoch_seq_le || timestamp_ms_le || write_ema_le || read_ema_le
///   || footprint_le || is_read || op_hash)
#[allow(clippy::too_many_arguments)]
pub fn compute_ingress_envelope_digest_v2(
    gateway_pubkey: &[u8; 32],
    epoch_day: u32,
    epoch_seq: u64,
    timestamp_ms: u64,
    declared_write_ema_micro_bj: u64,
    declared_read_ema_credits: u64,
    footprint_micro_bj: u64,
    is_read: bool,
    op_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = (DOMAIN_INGRESS_DECL.len() as u8).to_le_bytes();
    hasher.update(&tag_len);
    hasher.update(DOMAIN_INGRESS_DECL);
    hasher.update(gateway_pubkey);
    hasher.update(&epoch_day.to_le_bytes());
    hasher.update(&epoch_seq.to_le_bytes());
    hasher.update(&timestamp_ms.to_le_bytes());
    hasher.update(&declared_write_ema_micro_bj.to_le_bytes());
    hasher.update(&declared_read_ema_credits.to_le_bytes());
    hasher.update(&footprint_micro_bj.to_le_bytes());
    hasher.update(&[if is_read { 1u8 } else { 0u8 }]);
    hasher.update(op_hash);
    *hasher.finalize().as_bytes()
}

/// Computes the canonical announcement hash for an authentic node presence heartbeat.
///
/// Binds `(addr, pow_nonce, hrw_routing_id, ticket_epoch_t0)` under domain tag `HUMOCO_V1_HB_ANNOUNCE`.
/// Digest = BLAKE3(len || "HUMOCO_V1_HB_ANNOUNCE" || addr_bytes || pow_nonce_le || hrw_routing_id || ticket_epoch_t0_le)
pub fn compute_heartbeat_announcement_hash(
    addr: &std::net::SocketAddr,
    pow_nonce: u64,
    hrw_routing_id: &[u8; 32],
    ticket_epoch_t0: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = (DOMAIN_HB_ANNOUNCE.len() as u8).to_le_bytes();
    hasher.update(&tag_len);
    hasher.update(DOMAIN_HB_ANNOUNCE);
    match addr {
        std::net::SocketAddr::V4(v4) => {
            hasher.update(&[4u8]);
            hasher.update(&v4.ip().octets());
            hasher.update(&v4.port().to_le_bytes());
        }
        std::net::SocketAddr::V6(v6) => {
            hasher.update(&[6u8]);
            hasher.update(&v6.ip().octets());
            hasher.update(&v6.port().to_le_bytes());
        }
    }
    hasher.update(&pow_nonce.to_le_bytes());
    hasher.update(hrw_routing_id);
    hasher.update(&ticket_epoch_t0.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[allow(clippy::too_many_arguments)]
pub fn sign_ingress_evidence_with_key(
    signing_key: &ed25519_dalek::SigningKey,
    epoch_day: u32,
    epoch_seq: u64,
    timestamp_ms: u64,
    declared_write_ema_micro_bj: u64,
    declared_read_ema_credits: u64,
    footprint_micro_bj: u64,
    is_read: bool,
    op_hash: [u8; 32],
) -> IngressEnvelopeEvidence {
    use ed25519_dalek::Signer;
    let gateway_pubkey = signing_key.verifying_key().to_bytes();
    let digest = compute_ingress_envelope_digest_v2(
        &gateway_pubkey,
        epoch_day,
        epoch_seq,
        timestamp_ms,
        declared_write_ema_micro_bj,
        declared_read_ema_credits,
        footprint_micro_bj,
        is_read,
        &op_hash,
    );
    let signature = signing_key.sign(&digest).to_bytes();
    IngressEnvelopeEvidence {
        gateway_pubkey,
        epoch_day,
        epoch_seq,
        timestamp_ms,
        declared_write_ema_micro_bj,
        declared_read_ema_credits,
        footprint_micro_bj,
        is_read,
        op_hash,
        signature,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sign_ingress_evidence(
    gateway_key_or_seed: [u8; 32],
    epoch_day: u32,
    epoch_seq: u64,
    timestamp_ms: u64,
    declared_write_ema_micro_bj: u64,
    declared_read_ema_credits: u64,
    footprint_micro_bj: u64,
    is_read: bool,
    op_hash: [u8; 32],
) -> IngressEnvelopeEvidence {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&gateway_key_or_seed);
    sign_ingress_evidence_with_key(
        &signing_key,
        epoch_day,
        epoch_seq,
        timestamp_ms,
        declared_write_ema_micro_bj,
        declared_read_ema_credits,
        footprint_micro_bj,
        is_read,
        op_hash,
    )
}

pub fn encode_ingress_envelope(env: &IngressEnvelopeEvidence) -> Vec<u8> {
    bincode::serialize(env).unwrap_or_default()
}

pub fn decode_ingress_envelope(bytes: &[u8]) -> Option<IngressEnvelopeEvidence> {
    if bytes.is_empty() || bytes.len() >= 1024 {
        return None;
    }
    bincode::deserialize(bytes).ok()
}

pub fn verify_ingress_envelope_signature(env: &IngressEnvelopeEvidence) -> bool {
    let digest = compute_ingress_envelope_digest_v2(
        &env.gateway_pubkey,
        env.epoch_day,
        env.epoch_seq,
        env.timestamp_ms,
        env.declared_write_ema_micro_bj,
        env.declared_read_ema_credits,
        env.footprint_micro_bj,
        env.is_read,
        &env.op_hash,
    );

    if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&env.gateway_pubkey) {
        if let Ok(sig) = ed25519_dalek::Signature::from_slice(&env.signature) {
            return vk.verify_strict(&digest, &sig).is_ok();
        }
    }
    false
}

/// Computes the network-domain-separated BLAKE3 digest for an F2F presence heartbeat (INV-1106).
///
/// Digest = BLAKE3(len || domain_heartbeat(network_id) || gateway_pubkey || epoch_day_le || epoch_seq_le || ...)
#[allow(clippy::too_many_arguments)]
pub fn compute_heartbeat_digest(
    network_id: crate::types::NetworkId,
    gateway_pubkey: &[u8; 32],
    epoch_day: u32,
    epoch_seq: u64,
    timestamp_ms: u64,
    declared_write_ema_micro_bj: u64,
    declared_read_ema_credits: u64,
    footprint_micro_bj: u64,
    is_read: bool,
    op_hash: &[u8; 32],
) -> [u8; 32] {
    let domain = crate::crypto::domain_heartbeat(network_id);
    let mut hasher = blake3::Hasher::new();
    let tag_len = (domain.len() as u8).to_le_bytes();
    hasher.update(&tag_len);
    hasher.update(domain);
    hasher.update(gateway_pubkey);
    hasher.update(&epoch_day.to_le_bytes());
    hasher.update(&epoch_seq.to_le_bytes());
    hasher.update(&timestamp_ms.to_le_bytes());
    hasher.update(&declared_write_ema_micro_bj.to_le_bytes());
    hasher.update(&declared_read_ema_credits.to_le_bytes());
    hasher.update(&footprint_micro_bj.to_le_bytes());
    hasher.update(&[if is_read { 1u8 } else { 0u8 }]);
    hasher.update(op_hash);
    *hasher.finalize().as_bytes()
}

/// Verifies an F2F presence heartbeat signature against the expected network domain (INV-1106).
///
/// Ensures that a heartbeat originated from the identical network universe.
/// Heartbeats signed for `Testnet` will fail strictly under `Mainnet` (and vice-versa).
pub fn verify_heartbeat_signature(
    network_id: crate::types::NetworkId,
    env: &IngressEnvelopeEvidence,
) -> bool {
    verify_heartbeat_signature_strict(network_id, env)
}

/// Strict variant of heartbeat verification without backward-compatible fallback (INV-1106).
pub fn verify_heartbeat_signature_strict(
    network_id: crate::types::NetworkId,
    env: &IngressEnvelopeEvidence,
) -> bool {
    let digest = compute_heartbeat_digest(
        network_id,
        &env.gateway_pubkey,
        env.epoch_day,
        env.epoch_seq,
        env.timestamp_ms,
        env.declared_write_ema_micro_bj,
        env.declared_read_ema_credits,
        env.footprint_micro_bj,
        env.is_read,
        &env.op_hash,
    );

    if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&env.gateway_pubkey) {
        if let Ok(sig) = ed25519_dalek::Signature::from_slice(&env.signature) {
            return vk.verify_strict(&digest, &sig).is_ok();
        }
    }
    false
}

// ---------------------------------------------------------------------------
// FraudProofPayload / FraudProof
// ---------------------------------------------------------------------------

pub type FraudProof = FraudProofPayload;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FraudBuildError {
    #[error("Signer mismatch")]
    SignerMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FraudProofPayload {
    /// Perpetrator as 32-byte public key (first 2 bytes = NodeId LE for simulation)
    pub perpetrator_node_id: [u8; 32],
    pub proof_pillar: FraudProofPillar,
    pub evidence_packet_a: Vec<u8>,
    pub evidence_packet_b: Vec<u8>,
    pub reporter_node_id: [u8; 32],
    #[serde(with = "crate::types::serde_bytes_64")]
    pub reporter_signature: [u8; 64],
}

impl FraudProofPayload {
    pub fn pubkey_from_node_id(node_id: NodeId) -> [u8; 32] {
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

    pub fn node_id_from_pubkey(pk: &[u8; 32]) -> NodeId {
        u16::from_le_bytes([pk[0], pk[1]])
    }

    /// Try creating pillar 1 proof from two attestations (L3A != L3B, same parent_lock)
    pub fn try_new_shard_equivocation(
        a: Attestation,
        b: Attestation,
    ) -> Result<Self, FraudBuildError> {
        if a.node_id != b.node_id {
            return Err(FraudBuildError::SignerMismatch);
        }
        let perpetrator_node_id = Self::pubkey_from_node_id(a.node_id);
        let pillar = FraudProofPillar::ShardEquivocation;
        Ok(Self {
            perpetrator_node_id,
            proof_pillar: pillar,
            evidence_packet_a: encode_attestation(&a),
            evidence_packet_b: encode_attestation(&b),
            reporter_node_id: [0u8; 32],
            reporter_signature: [0u8; 64],
        })
    }

    /// Create pillar 1 proof from two attestations (L3A != L3B, same parent_lock)
    pub fn new_shard_equivocation(a: Attestation, b: Attestation) -> Self {
        Self::try_new_shard_equivocation(a.clone(), b.clone()).unwrap_or_else(|_| {
            let perpetrator_node_id = Self::pubkey_from_node_id(a.node_id);
            let pillar = FraudProofPillar::ShardEquivocation;
            Self {
                perpetrator_node_id,
                proof_pillar: pillar,
                evidence_packet_a: encode_attestation(&a),
                evidence_packet_b: encode_attestation(&b),
                reporter_node_id: [0u8; 32],
                reporter_signature: [0u8; 64],
            }
        })
    }

    /// Alternative constructor with explicit perpetrator pubkey
    pub fn try_new_shard_equivocation_with_pubkey(
        a: Attestation,
        b: Attestation,
        perpetrator_pubkey: [u8; 32],
    ) -> Result<Self, FraudBuildError> {
        let mut p = Self::try_new_shard_equivocation(a, b)?;
        p.perpetrator_node_id = perpetrator_pubkey;
        Ok(p)
    }

    pub fn new_shard_equivocation_with_pubkey(
        a: Attestation,
        b: Attestation,
        perpetrator_pubkey: [u8; 32],
    ) -> Self {
        let mut p = Self::new_shard_equivocation(a, b);
        p.perpetrator_node_id = perpetrator_pubkey;
        p
    }

    /// Alternative constructor with explicit reporter
    pub fn try_new_shard_equivocation_with_reporter(
        a: Attestation,
        b: Attestation,
        reporter: NodeId,
    ) -> Result<Self, FraudBuildError> {
        let mut p = Self::try_new_shard_equivocation(a, b)?;
        p.reporter_node_id = Self::pubkey_from_node_id(reporter);
        Ok(p)
    }

    pub fn new_shard_equivocation_with_reporter(
        a: Attestation,
        b: Attestation,
        reporter: NodeId,
    ) -> Self {
        let mut p = Self::new_shard_equivocation(a, b);
        p.reporter_node_id = Self::pubkey_from_node_id(reporter);
        p
    }

    /// Try creating pillar 2 proof from two ingress evidences (IngressCounterConflict)
    pub fn try_new_ingress_counter_conflict(
        a: IngressEnvelopeEvidence,
        b: IngressEnvelopeEvidence,
    ) -> Result<Self, FraudBuildError> {
        if a.gateway_pubkey != b.gateway_pubkey {
            return Err(FraudBuildError::SignerMismatch);
        }
        let perpetrator_node_id = a.gateway_pubkey;
        let pillar = FraudProofPillar::IngressCounterConflict;
        Ok(Self {
            perpetrator_node_id,
            proof_pillar: pillar,
            evidence_packet_a: encode_ingress_envelope(&a),
            evidence_packet_b: encode_ingress_envelope(&b),
            reporter_node_id: [0u8; 32],
            reporter_signature: [0u8; 64],
        })
    }

    /// Create pillar 2 proof from two ingress evidences (IngressCounterConflict)
    pub fn new_ingress_counter_conflict(
        a: IngressEnvelopeEvidence,
        b: IngressEnvelopeEvidence,
    ) -> Self {
        Self::try_new_ingress_counter_conflict(a.clone(), b.clone()).unwrap_or_else(|_| {
            let perpetrator_node_id = a.gateway_pubkey;
            let pillar = FraudProofPillar::IngressCounterConflict;
            Self {
                perpetrator_node_id,
                proof_pillar: pillar,
                evidence_packet_a: encode_ingress_envelope(&a),
                evidence_packet_b: encode_ingress_envelope(&b),
                reporter_node_id: [0u8; 32],
                reporter_signature: [0u8; 64],
            }
        })
    }

    pub fn try_new_ingress_counter_conflict_with_reporter(
        a: IngressEnvelopeEvidence,
        b: IngressEnvelopeEvidence,
        reporter: NodeId,
    ) -> Result<Self, FraudBuildError> {
        let mut p = Self::try_new_ingress_counter_conflict(a, b)?;
        p.reporter_node_id = Self::pubkey_from_node_id(reporter);
        Ok(p)
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

    /// Checks if two ingress evidences constitute an under-reporting or rollback fraud conflict.
    pub fn check_ingress_conflict(
        a: &IngressEnvelopeEvidence,
        b: &IngressEnvelopeEvidence,
    ) -> bool {
        let Ok(proof) = Self::try_new_ingress_counter_conflict(a.clone(), b.clone()) else {
            return false;
        };
        proof.verify_ingress_counter_conflict()
    }

    /// Generic verify dispatcher across known networks and simulator fallbacks.
    ///
    /// For simulation-mode test suites, this verifies shard equivocation across `Mainnet`
    /// or `Testnet`, and falls back to deterministic simulator signatures (`verify_attestation`).
    /// In production daemon hot-paths and P2P mesh validation, callers MUST use
    /// [`verify_shard_equivocation_network`] or [`verify_network`] with an explicit [`NetworkId`]
    /// to avoid cross-universe domain confusion.
    pub fn verify(&self) -> bool {
        match self.proof_pillar {
            FraudProofPillar::ShardEquivocation => self.verify_shard_equivocation(),
            FraudProofPillar::IngressCounterConflict => self.verify_ingress_counter_conflict(),
        }
    }

    /// Verifies the fraud proof under the designated network universe (A02-01).
    pub fn verify_network(&self, network_id: NetworkId) -> bool {
        match self.proof_pillar {
            FraudProofPillar::ShardEquivocation => {
                self.verify_shard_equivocation_network(network_id)
            }
            FraudProofPillar::IngressCounterConflict => self.verify_ingress_counter_conflict(),
        }
    }

    /// Verifies shard equivocation for a specific network (Testnet or Mainnet) (A02-01).
    ///
    /// # Architectural Invariant: A02-01 (Spec 10, Pillar 1)
    /// Both attestations MUST belong strictly to the specified network domain tag.
    /// Unlike simulation-only [`verify`], this method enforces strict Ed25519 signature
    /// verification and does NOT fall back to deterministic test keys.
    pub fn verify_shard_equivocation_network(&self, network_id: NetworkId) -> bool {
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
        // Must be same parent_lock (INV: double-spend on same voucher/parent)
        if a.parent_lock != b.parent_lock {
            return false;
        }
        // Must be different lock_ids (L3A != L3B)
        if a.lock_id == b.lock_id {
            return false;
        }

        let prov_domain = crate::crypto::domain_approve_prov(network_id);
        let final_domain = crate::crypto::domain_approve_final(network_id);

        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.perpetrator_node_id) {
            let verify_one = |att: &Attestation| -> bool {
                let sig = match ed25519_dalek::Signature::from_slice(&att.signature) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let shard_candidates = [
                    att.shard_id,
                    crate::types::extract_shard_id(&att.parent_lock),
                ];
                let payload_digest =
                    compute_attestation_payload_digest(&att.parent_lock, &att.lock_id);
                shard_candidates.iter().any(|&shard_id| {
                    let d_prov =
                        compute_sig_digest(prov_domain, 0, 0, 0, shard_id, 0, &payload_digest);
                    let d_final =
                        compute_sig_digest(final_domain, 0, 0, 0, shard_id, 1, &payload_digest);
                    vk.verify_strict(&d_prov, &sig).is_ok()
                        || vk.verify_strict(&d_final, &sig).is_ok()
                })
            };
            verify_one(&a) && verify_one(&b)
        } else {
            false
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
        // Must be same parent_lock (INV: double-spend on same voucher/parent)
        if a.parent_lock != b.parent_lock {
            return false;
        }
        // Must be different lock_ids (L3A != L3B)
        if a.lock_id == b.lock_id {
            return false;
        }

        // Verify signatures of both attestations using genuine Ed25519 if valid key.
        // Network-aware (A02-01): both attestations must belong to the SAME network universe.
        // Mixed-network pairs (one Mainnet, one Testnet) return false.
        let is_ed25519_valid = self.verify_shard_equivocation_network(NetworkId::Mainnet)
            || self.verify_shard_equivocation_network(NetworkId::Testnet);

        if is_ed25519_valid {
            return true;
        }

        // Fallback for simulation mode tests that use BLAKE3 deterministic simulator signatures
        let perp = Self::node_id_from_pubkey(&self.perpetrator_node_id);
        if perp != a.node_id {
            return false;
        }
        if !verify_attestation(&a) || !verify_attestation(&b) {
            return false;
        }
        true
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

        // Exact mathematical under-reporting fraud check in V2 mode:
        // Canonical normalization by (epoch_day, epoch_seq, timestamp_ms) ensures
        // arrival order (a, b) vs (b, a) produces identical results.
        let (p1, p2) = if (a.epoch_day, a.epoch_seq, a.timestamp_ms)
            <= (b.epoch_day, b.epoch_seq, b.timestamp_ms)
        {
            (a, b)
        } else {
            (b, a)
        };

        if p1.epoch_day > 0 || p2.epoch_day > 0 || p1.epoch_seq > 0 || p2.epoch_seq > 0 {
            if p1.epoch_day == p2.epoch_day {
                if p1.epoch_seq == p2.epoch_seq {
                    let is_exact_duplicate = p1.op_hash == p2.op_hash
                        && p1.timestamp_ms == p2.timestamp_ms
                        && p1.declared_write_ema_micro_bj == p2.declared_write_ema_micro_bj
                        && p1.declared_read_ema_credits == p2.declared_read_ema_credits
                        && p1.footprint_micro_bj == p2.footprint_micro_bj;
                    return !is_exact_duplicate;
                }

                // Since normalized by (epoch_day, epoch_seq): p2.epoch_seq > p1.epoch_seq
                // Counter rollback under sequence progression:
                if p1.declared_write_ema_micro_bj > 0
                    && p2.declared_write_ema_micro_bj > 0
                    && p2.declared_write_ema_micro_bj < p1.declared_write_ema_micro_bj
                {
                    return true;
                }
                if p1.declared_read_ema_credits > 0
                    && p2.declared_read_ema_credits > 0
                    && p2.declared_read_ema_credits < p1.declared_read_ema_credits
                {
                    return true;
                }
            }
            return false;
        } else if p1.timestamp_ms == p2.timestamp_ms {
            // Concurrent operations within the same millisecond are normal for independent
            // unsequenced reads/queries; an identical duplicate is not fraud.
            return false;
        }

        let delta_secs = (p2.timestamp_ms - p1.timestamp_ms) / 1000;
        if p2.is_read {
            // Unsequenced reads (seq = 0) have independent zero/ambient baselines;
            // independent reads for different locks or reordered queries never constitute
            // under-reporting fraud unless a non-zero sequence progression is declared.
            if p1.epoch_seq > 0 || p2.epoch_seq > 0 {
                let min_allowed =
                    crate::quota::decay_integer_ema(p1.declared_read_ema_credits, delta_secs)
                        .saturating_add(1);
                if p2.declared_read_ema_credits < min_allowed {
                    return true;
                }
            }
        } else if p1.declared_write_ema_micro_bj > 0 || p2.declared_write_ema_micro_bj > 0 {
            let min_allowed =
                crate::quota::decay_integer_ema(p1.declared_write_ema_micro_bj, delta_secs)
                    .saturating_add(p2.footprint_micro_bj);
            if p2.declared_write_ema_micro_bj < min_allowed {
                return true;
            }
        }
        false
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pillar_values() {
        assert_eq!(FraudProofPillar::ShardEquivocation as u8, 1);
        assert_eq!(FraudProofPillar::IngressCounterConflict as u8, 2);
    }

    fn test_signing_key(id: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[id; 32])
    }

    #[test]
    fn test_ingress_envelope_sign_decode_verify() {
        let sk = test_signing_key(42);
        let op_hash = [0xAA; 32];
        let env = sign_ingress_evidence_with_key(
            &sk, 10, 1, 100_000, 50_000, 10_000, 1_000, false, op_hash,
        );

        assert!(verify_ingress_envelope_signature(&env));

        let bytes = encode_ingress_envelope(&env);
        assert!(bytes.len() < 512);

        let decoded = decode_ingress_envelope(&bytes).expect("must decode");
        assert_eq!(decoded, env);
        assert!(verify_ingress_envelope_signature(&decoded));

        // Test length boundaries:
        assert!(decode_ingress_envelope(&[]).is_none());
        let oversized = vec![0u8; 1024];
        assert!(decode_ingress_envelope(&oversized).is_none());

        // Corrupted payload:
        let mut corrupted = bytes.clone();
        corrupted.truncate(10);
        assert!(decode_ingress_envelope(&corrupted).is_none());
    }

    #[test]
    fn test_ingress_counter_conflict_anti_framing() {
        let sk_victim = test_signing_key(1);
        let sk_attacker = test_signing_key(2);
        let hash = [0xAA; 32];

        let mut p1 = sign_ingress_evidence_with_key(
            &sk_victim, 5, 1, 100, 50_000, 10_000, 1_000, false, hash,
        );
        let p2 = sign_ingress_evidence_with_key(
            &sk_victim, 5, 1, 100, 50_000, 10_000, 1_000, false, [0xBB; 32],
        );

        // Framing 1: tampered signature on packet 1
        p1.signature[0] ^= 0xFF;
        let mut proof_bad_sig_a =
            FraudProofPayload::new_ingress_counter_conflict(p2.clone(), p2.clone());
        proof_bad_sig_a.evidence_packet_a = encode_ingress_envelope(&p1);
        proof_bad_sig_a.evidence_packet_b = encode_ingress_envelope(&p2);
        assert!(
            !proof_bad_sig_a.verify(),
            "invalid signature on packet A must be rejected"
        );

        // Framing 2: tampered signature on packet 2
        let mut p2_bad = p2.clone();
        p2_bad.signature[5] ^= 0xAA;
        let mut proof_bad_sig_b =
            FraudProofPayload::new_ingress_counter_conflict(p2.clone(), p2.clone());
        let p1_good = sign_ingress_evidence_with_key(
            &sk_victim, 5, 1, 100, 50_000, 10_000, 1_000, false, hash,
        );
        proof_bad_sig_b.evidence_packet_a = encode_ingress_envelope(&p1_good);
        proof_bad_sig_b.evidence_packet_b = encode_ingress_envelope(&p2_bad);
        assert!(
            !proof_bad_sig_b.verify(),
            "invalid signature on packet B must be rejected"
        );

        // Framing 3: two different signers (attacker plants foreign packet)
        let p_foreign = sign_ingress_evidence_with_key(
            &sk_attacker, 5, 1, 100, 50_000, 10_000, 1_000, false, [0xBB; 32],
        );
        let mut proof_diff_signers =
            FraudProofPayload::new_ingress_counter_conflict(p1_good.clone(), p1_good.clone());
        proof_diff_signers.evidence_packet_a = encode_ingress_envelope(&p1_good);
        proof_diff_signers.evidence_packet_b = encode_ingress_envelope(&p_foreign);
        assert!(
            !proof_diff_signers.verify(),
            "different signers must never count as fraud"
        );

        // Framing 4: wrong perpetrator_node_id declared
        let mut proof_wrong_perp =
            FraudProofPayload::new_ingress_counter_conflict(p1_good.clone(), p2.clone());
        proof_wrong_perp.perpetrator_node_id = sk_attacker.verifying_key().to_bytes();
        assert!(
            !proof_wrong_perp.verify(),
            "wrong perpetrator_node_id must be rejected"
        );

        // Framing 5: corrupted evidence data
        let mut proof_corrupt =
            FraudProofPayload::new_ingress_counter_conflict(p1_good.clone(), p2.clone());
        proof_corrupt.evidence_packet_a = vec![0xFF; 20];
        assert!(
            !proof_corrupt.verify(),
            "corrupted evidence must yield false"
        );
    }

    #[test]
    fn test_fallible_fraud_constructors_and_check_ingress_conflict() {
        let sk_a = test_signing_key(1);
        let sk_b = test_signing_key(2);
        let hash = [0xAA; 32];

        let env_a = sign_ingress_evidence_with_key(
            &sk_a, 5, 1, 100, 50_000, 10_000, 1_000, false, hash,
        );
        let env_b = sign_ingress_evidence_with_key(
            &sk_b, 5, 1, 100, 50_000, 10_000, 1_000, false, [0xBB; 32],
        );

        // try_new_ingress_counter_conflict with mismatched gateway pubkeys must return SignerMismatch
        assert_eq!(
            FraudProofPayload::try_new_ingress_counter_conflict(env_a.clone(), env_b.clone()),
            Err(FraudBuildError::SignerMismatch)
        );

        // check_ingress_conflict with mismatched gateway pubkeys must return false without panicking
        assert!(!FraudProofPayload::check_ingress_conflict(&env_a, &env_b));
        assert!(!FraudProofPayload::check_ingress_conflict(&env_b, &env_a));

        // try_new_shard_equivocation with mismatched node IDs must return SignerMismatch
        let att_a = Attestation {
            lock_id: [0x22; 32],
            parent_lock: [0x11; 32],
            node_id: 1,
            timestamp: SimTime(1000),
            signature: [0u8; 64],
            shard_id: 0,
        };
        let att_b = Attestation {
            lock_id: [0x33; 32],
            parent_lock: [0x11; 32],
            node_id: 2,
            timestamp: SimTime(1000),
            signature: [0u8; 64],
            shard_id: 0,
        };
        assert_eq!(
            FraudProofPayload::try_new_shard_equivocation(att_a, att_b),
            Err(FraudBuildError::SignerMismatch)
        );
    }

    #[test]
    fn test_compute_heartbeat_announcement_hash_determinism_and_domain() {
        let addr_v4: std::net::SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let addr_v4_other: std::net::SocketAddr = "127.0.0.1:9091".parse().unwrap();
        let addr_v6: std::net::SocketAddr = "[::1]:9090".parse().unwrap();
        let routing_id = [0x42u8; 32];
        let h1 = compute_heartbeat_announcement_hash(&addr_v4, 12345, &routing_id, 1_700_000_000);
        let h2 = compute_heartbeat_announcement_hash(&addr_v4, 12345, &routing_id, 1_700_000_000);
        assert_eq!(h1, h2, "Announcement hash must be deterministic");

        let h_diff_port =
            compute_heartbeat_announcement_hash(&addr_v4_other, 12345, &routing_id, 1_700_000_000);
        assert_ne!(
            h1, h_diff_port,
            "Changing address port must change announcement hash"
        );

        let h_v6 = compute_heartbeat_announcement_hash(&addr_v6, 12345, &routing_id, 1_700_000_000);
        assert_ne!(
            h1, h_v6,
            "IPv4 vs IPv6 must yield different announcement hash"
        );

        let h_diff_nonce =
            compute_heartbeat_announcement_hash(&addr_v4, 12346, &routing_id, 1_700_000_000);
        assert_ne!(
            h1, h_diff_nonce,
            "Different nonce must change announcement hash"
        );
    }
}
