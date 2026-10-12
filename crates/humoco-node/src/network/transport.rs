use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use humoco_sim_core::wire::{MsgType, WireHeader};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent QUIC stream handler tasks (DoS/OOM protection).
pub const STREAM_CONCURRENCY_LIMIT: usize = 1024;
/// Maximum number of concurrent QUIC handshake / connection handler tasks (DoS/OOM protection).
pub const CONNECTION_CONCURRENCY_LIMIT: usize = 256;


use crate::error::NodeError;
use crate::identity::NodeIdentity;
use crate::network::framing::{checked_payload_len, read_frame, write_frame};
use crate::network::manager::PeerManager;
use crate::network::tls::{
    build_quinn_client_config_with_identity, build_quinn_server_config,
    extract_peer_identity_from_connection,
};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Handler trait for processing incoming bi-directional and uni-directional requests.
pub trait RequestHandler: Send + Sync + 'static {
    fn handle(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        self.handle_authenticated(header, payload, None)
    }

    fn handle_authenticated(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
        peer_identity: Option<[u8; 32]>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        let _ = peer_identity;
        self.handle(header, payload)
    }

    fn handle_unidirectional(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(), NodeError>> {
        let _ = (header, payload);
        Box::pin(async { Ok(()) })
    }

    fn handle_unidirectional_authenticated(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
        peer_identity: Option<[u8; 32]>,
    ) -> BoxFuture<Result<(), NodeError>> {
        let _ = peer_identity;
        self.handle_unidirectional(header, payload)
    }
}

/// Default built-in request handler providing standard protocol acks/responses.
#[derive(Default, Clone)]
pub struct DefaultRequestHandler;

impl RequestHandler for DefaultRequestHandler {
    fn handle(
        &self,
        header: WireHeader,
        _payload: Vec<u8>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        Box::pin(async move {
            let msg_type = header.msg_type;
            let resp_type = match msg_type {
                x if x == MsgType::StatusQuery as u16 => MsgType::StatusResponse as u16,
                x if x == MsgType::LatencyProbe as u16 => MsgType::LatencyProbeAck as u16,
                x if x == MsgType::Heartbeat as u16 => MsgType::HeartbeatAck as u16,
                x if x == MsgType::LockVerifyRequest as u16 => MsgType::LockVerifyResponse as u16,
                x if x == MsgType::ActiveSyncRequest as u16 => MsgType::ActiveSyncDone as u16,
                x if x == MsgType::ShardDigestRequest as u16 => MsgType::ShardDigestResponse as u16,
                x if x == MsgType::EquivocationProof as u16 => MsgType::EquivocationAck as u16,
                _ => MsgType::StatusResponse as u16,
            };
            let resp_header =
                WireHeader::new(resp_type, header.session_seq, header.epoch_id, 0, 0);
            Ok((resp_header, Vec::new()))
        })
    }
}

/// Verifies the cryptographic authenticity of both evidence packets using Ed25519 (First-Party Evidence Doctrine, Spec 10).
pub fn verify_equivocation_first_party(
    vk: &ed25519_dalek::VerifyingKey,
    proof: &humoco_sim_core::fraud::FraudProofPayload,
) -> bool {
    match proof.proof_pillar {
        humoco_sim_core::fraud::FraudProofPillar::IngressCounterConflict => {
            proof.verify()
        }
        humoco_sim_core::fraud::FraudProofPillar::HeartbeatSpam => {
            proof.verify()
        }
        humoco_sim_core::fraud::FraudProofPillar::ShardEquivocation => {
            let a = match humoco_sim_core::fraud::decode_attestation(&proof.evidence_packet_a) {
                Some(att) => att,
                None => return false,
            };
            let b = match humoco_sim_core::fraud::decode_attestation(&proof.evidence_packet_b) {
                Some(att) => att,
                None => return false,
            };

            if a.parent_lock != b.parent_lock || a.lock_id == b.lock_id || a.node_id != b.node_id {
                return false;
            }

            let verify_att = |att: &humoco_sim_core::types::Attestation| -> bool {
                let sig = match ed25519_dalek::Signature::from_slice(&att.signature) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let shard_id = u16::from_be_bytes([att.parent_lock[0], att.parent_lock[1]]);
                let d_prov = humoco_sim_core::crypto::compute_sig_digest(
                    humoco_sim_core::crypto::DOMAIN_APPROVE_PROV,
                    0,
                    0,
                    0,
                    shard_id,
                    0,
                    &att.lock_id,
                );
                let d_final = humoco_sim_core::crypto::compute_sig_digest(
                    humoco_sim_core::crypto::DOMAIN_APPROVE_FINAL,
                    0,
                    0,
                    0,
                    shard_id,
                    1,
                    &att.lock_id,
                );

                vk.verify_strict(&d_prov, &sig).is_ok()
                    || vk.verify_strict(&d_final, &sig).is_ok()
            };

            verify_att(&a) && verify_att(&b)
        }
    }
}


/// Node daemon request handler with access to dual-tier storage for gossip and active sync.
#[derive(Clone)]
pub struct NodeRequestHandler {
    pub engine: crate::storage::DualTierEngine,
    pub storage: Arc<crate::storage::RedbStorage>,
    pub identity: NodeIdentity,
    pub peer_manager: Option<Arc<crate::network::PeerManager>>,
    pub tier_controller: Option<Arc<crate::ingress::TierController>>,
    pub is_sync_ready: Arc<std::sync::atomic::AtomicBool>,
}

impl NodeRequestHandler {
    pub fn new(
        engine: crate::storage::DualTierEngine,
        storage: Arc<crate::storage::RedbStorage>,
        identity: NodeIdentity,
    ) -> Self {
        Self {
            engine,
            storage,
            identity,
            peer_manager: None,
            tier_controller: None,
            is_sync_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    pub fn with_peer_manager(
        engine: crate::storage::DualTierEngine,
        storage: Arc<crate::storage::RedbStorage>,
        identity: NodeIdentity,
        peer_manager: Arc<crate::network::PeerManager>,
    ) -> Self {
        Self {
            engine,
            storage,
            identity,
            peer_manager: Some(peer_manager),
            tier_controller: None,
            is_sync_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    pub fn with_tier_controller(mut self, tier_controller: Arc<crate::ingress::TierController>) -> Self {
        self.tier_controller = Some(tier_controller);
        self
    }

    pub fn with_sync_ready(mut self, ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.is_sync_ready = ready;
        self
    }
}

impl RequestHandler for NodeRequestHandler {
    fn handle(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        self.handle_authenticated(header, payload, None)
    }

    fn handle_authenticated(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
        peer_identity: Option<[u8; 32]>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        let engine = self.engine.clone();
        let storage = self.storage.clone();
        let identity = self.identity.clone();
        let peer_manager = self.peer_manager.clone();
        let tier_controller = self.tier_controller.clone();
        let is_sync_ready = self.is_sync_ready.clone();
        Box::pin(async move {
            let msg_type = header.msg_type;

            if let Some(auth_peer) = peer_identity {
                if engine.is_node_banned(&auth_peer).await {
                    warn!(auth_peer = %hex::encode(auth_peer), "Rejected request from banned authenticated QUIC peer");
                    let resp_header = WireHeader::new(
                        MsgType::StatusResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_PEER_SUSPENDED,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                }
            }

            // --- Phase 4: Real slashing on EquivocationProof (Spec 10 Pillar 1) ---
            if msg_type == MsgType::EquivocationProof as u16 {
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0)
                    });
                match bincode::deserialize::<humoco_sim_core::fraud::FraudProofPayload>(&payload) {
                    Ok(proof) => {
                        let offender = proof.perpetrator_node_id;
                        let is_first_party_valid = if !proof.verify() {
                            false
                        } else if let Some(pm) = peer_manager.as_ref() {
                            if let Some(vk) = pm.get_peer_verifying_key_by_node_id(&offender).await {
                                verify_equivocation_first_party(&vk, &proof)
                            } else if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&offender) {
                                verify_equivocation_first_party(&vk, &proof)
                            } else {
                                verify_equivocation_first_party(identity.verifying_key(), &proof)
                            }
                        } else if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&offender) {
                            verify_equivocation_first_party(&vk, &proof)
                        } else {
                            verify_equivocation_first_party(identity.verifying_key(), &proof)
                        };

                        if !is_first_party_valid {
                            warn!(offender = %hex::encode(offender), "EquivocationProof rejected: cryptographic Ed25519 signature verification failed for perpetrator (framing prevented)");
                        } else {
                            // Persist raw evidence best-effort (bounded, never panic on external input)
                            let evidence_hash = *blake3::hash(&payload).as_bytes();
                            if let Err(e) = storage.put_evidence(&evidence_hash, &payload) {
                                warn!("Failed to persist slashing evidence: {}", e);
                            }
                            engine.ban_node(offender, now_ms).await;
                            if let Some(pm) = peer_manager.as_ref() {
                                let affected = pm.ban_node(&offender).await;
                                // Phase 10: dedup via LRU seen-set + echo protection —
                                // never send the proof back to the immediate sender.
                                pm.broadcast_fraud_proof_with_sender(proof, peer_identity);
                                info!(offender = %hex::encode(offender), affected, "Slashing: offender banned and peers disconnected");
                            } else {
                                info!(offender = %hex::encode(offender), "Slashing: offender banned (no peer_manager)");
                            }
                        }
                    }
                    Err(e) => {
                        warn!("EquivocationProof rejected: deserialize failed: {}", e);
                    }
                }
                let resp_header = WireHeader::new(MsgType::EquivocationAck as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, 0);
                return Ok((resp_header, Vec::new()));
            }
            if msg_type == MsgType::LockVerifyRequest as u16 {
                if !is_sync_ready.load(std::sync::atomic::Ordering::SeqCst) {
                    warn!("LockVerifyRequest rejected: node is booting and initial sync is not ready");
                    let resp_header = WireHeader::new(
                        MsgType::LockVerifyResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_NOT_READY,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                }

                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0)
                    });

                let ncb_eff = if let Some(tc) = &tier_controller {
                    tc.effective_ncb()
                } else {
                    humoco_sim_core::quota::HARD_FLOOR_BASELINE_DAILY
                };
                let write_limit = (5.0 * ncb_eff as f64).round() as u64;

                let wire_payload = match bincode::deserialize::<crate::network::framing::LockWirePayload>(&payload) {
                    Ok(p) => p,
                    Err(_) => {
                        if let Ok((record, root_valid_until)) = bincode::deserialize::<(humoco_sim_core::types::LockRecord, u64)>(&payload) {
                            crate::network::framing::LockWirePayload::Sim(record, root_valid_until)
                        } else {
                            warn!("LockVerifyRequest rejected: invalid payload framing");
                            let resp_header = WireHeader::new(
                                MsgType::LockVerifyResponse as u16,
                                header.session_seq.wrapping_add(1),
                                header.epoch_id,
                                humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                                0,
                            );
                            return Ok((resp_header, Vec::new()));
                        }
                    }
                };

                let shard_id = match &wire_payload {
                    crate::network::framing::LockWirePayload::Sim(record, _) => {
                        u16::from_be_bytes([record.parent_lock[0], record.parent_lock[1]])
                    }
                    crate::network::framing::LockWirePayload::Hmc { req, .. } => {
                        let tag = if req.is_genesis {
                            bs58::encode(&req.transaction_hash).into_string()
                        } else {
                            req.ds_tag.clone().unwrap_or_default()
                        };
                        let p_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
                        u16::from_be_bytes([p_bytes[0], p_bytes[1]])
                    }
                };

                let is_responsible = if let Some(pm) = peer_manager.as_ref() {
                    pm.is_local_responsible_for_shard(identity.hrw_routing_id(), shard_id, 20).await
                } else {
                    true
                };

                if !is_responsible {
                    warn!(shard_id, "LockVerifyRequest rejected: local node is not in top-20 for shard");
                    let resp_header = WireHeader::new(
                        MsgType::LockVerifyResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_NOT_IN_SHARD,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                }

                let sender_pubkey = wire_payload.sender_pubkey();
                let sender_signature = wire_payload.sender_signature();
                let timestamp_ms = wire_payload.timestamp_ms();
                let declared_write_ema = wire_payload.declared_write_ema_micro_bj();
                let declared_read_ema = wire_payload.declared_read_ema_credits();

                // 1. Cheap check first: declared write rate vs 5x whale brake limit
                let declared_daily_rate = humoco_sim_core::quota::ema_to_daily_rate(declared_write_ema) / 1_000_000;
                if declared_daily_rate > write_limit {
                    warn!(declared_daily_rate, write_limit, sender = %hex::encode(sender_pubkey), "LockVerifyRequest rejected: declared write load exceeds 5.0 * ncb_eff");
                    let resp_header = WireHeader::new(
                        MsgType::LockVerifyResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                }

                // 2. Check authenticated QUIC identity matches sender_pubkey
                if let Some(auth_peer) = peer_identity {
                    if sender_pubkey != [0u8; 32] && sender_pubkey != auth_peer {
                        warn!(
                            claimed = %hex::encode(sender_pubkey),
                            authenticated = %hex::encode(auth_peer),
                            "LockVerifyRequest rejected: claimed sender pubkey does not match authenticated QUIC identity"
                        );
                        let resp_header = WireHeader::new(
                            MsgType::LockVerifyResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                            0,
                        );
                        return Ok((resp_header, Vec::new()));
                    }
                }

                // 3. In production (Hmc payloads), reject null senders and null signatures
                if matches!(wire_payload, crate::network::framing::LockWirePayload::Hmc { .. }) {
                    if sender_pubkey == [0u8; 32] {
                        warn!("LockVerifyRequest rejected: null sender pubkey");
                        let resp_header = WireHeader::new(
                            MsgType::LockVerifyResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                            0,
                        );
                        return Ok((resp_header, Vec::new()));
                    }
                    if sender_signature == [0u8; 64] {
                        warn!("LockVerifyRequest rejected: null sender signature");
                        let resp_header = WireHeader::new(
                            MsgType::LockVerifyResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_SIGNATURE_INVALID,
                            0,
                        );
                        return Ok((resp_header, Vec::new()));
                    }
                }

                // 4. Check if sender is banned
                let is_banned = if sender_pubkey != [0u8; 32] {
                    if engine.is_node_banned(&sender_pubkey).await {
                        true
                    } else if let Some(pm) = peer_manager.as_ref() {
                        pm.is_banned(&sender_pubkey).await
                    } else {
                        false
                    }
                } else {
                    false
                };
                if is_banned {
                    warn!(sender = %hex::encode(sender_pubkey), "LockVerifyRequest rejected: sender is banned");
                    let resp_header = WireHeader::new(
                        MsgType::LockVerifyResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_PEER_SUSPENDED,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                }

                // 5. Compute operation hash and footprint (including multi-hop chain multiplier)
                let effective_ts = if timestamp_ms > 0 { timestamp_ms } else { now_ms };
                let (op_hash, footprint, total_by) = match &wire_payload {
                    crate::network::framing::LockWirePayload::Sim(record, root_valid_until) => {
                        let ttl_s = root_valid_until.saturating_sub(effective_ts) / 1000;
                        let fp = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
                        let by = humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl_s);
                        (record.id, fp, by)
                    }
                    crate::network::framing::LockWirePayload::Hmc { req, root_valid_until, chain, .. } => {
                        let ttl_s = root_valid_until.saturating_sub(effective_ts) / 1000;
                        let entry = crate::api::hmc::L2LockEntry::from(req);
                        let base_fp = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
                        let base_by = humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl_s);
                        let chain_len = chain.as_ref().map(|c| c.chain.len()).unwrap_or(1);
                        (entry.t_id, base_fp.saturating_mul(chain_len as u64), base_by.saturating_mul(chain_len as u64))
                    }
                };

                // 6. Signature verification and under-reporting check
                if sender_pubkey != [0u8; 32] && sender_signature != [0u8; 64] {
                    let curr = humoco_sim_core::fraud::IngressEnvelopeEvidence::new_v2(
                        sender_pubkey,
                        timestamp_ms,
                        declared_write_ema,
                        declared_read_ema,
                        footprint,
                        false,
                        op_hash,
                        sender_signature,
                    );

                    if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&curr) {
                        warn!(sender = %hex::encode(sender_pubkey), "LockVerifyRequest rejected: invalid ingress envelope signature");
                        let resp_header = WireHeader::new(
                            MsgType::LockVerifyResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_SIGNATURE_INVALID,
                            0,
                        );
                        return Ok((resp_header, Vec::new()));
                    }

                    if let Some(pm) = peer_manager.as_ref() {
                        if let Some(prev) = pm.get_node_write_evidence(&sender_pubkey).await {
                            if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(&prev, &curr) {
                                warn!(sender = %hex::encode(sender_pubkey), "CRITICAL FRAUD: under-reporting detected in LockVerifyRequest! Slashing perpetrator.");
                                let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, curr.clone());
                                let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                let _ = storage.put_evidence(&evidence_hash, &evidence_bytes);
                                engine.ban_node(sender_pubkey, now_ms).await;
                                pm.ban_node(&sender_pubkey).await;
                                pm.broadcast_fraud_proof(proof);

                                let resp_header = WireHeader::new(
                                    MsgType::LockVerifyResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED
                                        | humoco_sim_core::wire::FLAG_PEER_SUSPENDED
                                        | humoco_sim_core::wire::FLAG_QUOTA_FRAUD,
                                    0,
                                );
                                return Ok((resp_header, Vec::new()));
                            }
                        }
                        pm.update_node_write_evidence(&sender_pubkey, curr.clone()).await;
                        pm.record_observed_evidence(curr.clone()).await;
                    }
                }

                // 7. Recipient-side quota reservation check BEFORE mutating RAM index
                if let Some(tc) = &tier_controller {
                    if sender_pubkey != [0u8; 32] {
                        let epoch_day = tc.current_epoch_day_at(effective_ts);
                        if let Err(e) = tc.evaluate_node_write_quota(&sender_pubkey, total_by, epoch_day) {
                            warn!(error = ?e, sender = %hex::encode(sender_pubkey), "LockVerifyRequest rejected: node write quota exceeded");
                            let resp_header = WireHeader::new(
                                MsgType::LockVerifyResponse as u16,
                                header.session_seq.wrapping_add(1),
                                header.epoch_id,
                                humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED,
                                0,
                            );
                            return Ok((resp_header, Vec::new()));
                        }
                    }
                }

                // 8. Mutation of RAM index and attestation generation
                match wire_payload {
                    crate::network::framing::LockWirePayload::Sim(record, root_valid_until) => {
                        if engine.is_node_banned(&record.receiver_pub).await {
                            let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, humoco_sim_core::wire::FLAG_PEER_SUSPENDED, 0);
                            return Ok((resp_header, Vec::new()));
                        }

                        let ingress_res = engine.ingress_lock(
                            record.clone(),
                            humoco_sim_core::types::SimTime(now_ms),
                            humoco_sim_core::types::SimTime(root_valid_until),
                        ).await;

                        match ingress_res {
                            Ok(humoco_sim_core::storage::IngressVerdictLow::AcceptedNew)
                            | Ok(humoco_sim_core::storage::IngressVerdictLow::IdempotentReplay) => {
                                let requested_status = (header.flags & 0xFF) as u8;
                                let local_active_count = peer_manager.as_ref().map(|pm| pm.active_nodes_count()).unwrap_or(1);
                                let can_be_final = humoco_sim_core::types::required_quorum(local_active_count).1
                                    && peer_manager.as_ref().map(|pm| pm.is_network_stable_ge20_for_24h(now_ms)).unwrap_or(false);
                                let final_status = requested_status.min(if can_be_final { 1 } else { 0 });
                                let attestation = crate::api::routes::create_attestation(
                                    &identity,
                                    record.id,
                                    record.parent_lock,
                                    shard_id,
                                    final_status,
                                    now_ms,
                                );
                                let resp_bytes = bincode::serialize(&attestation).unwrap_or_default();
                                let payload_len = checked_payload_len(resp_bytes.len())?;
                                let resp_header = WireHeader::new(
                                    MsgType::LockVerifyResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    0,
                                    payload_len,
                                );
                                return Ok((resp_header, resp_bytes));
                            }
                            _ => {
                                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, 0);
                                return Ok((resp_header, Vec::new()));
                            }
                        }
                    }
                    crate::network::framing::LockWirePayload::Hmc { req, chain, .. } => {
                        if let Some(chain_req) = chain {
                            if chain_req.chain.is_empty() {
                                warn!("LockVerifyRequest rejected: empty chain");
                                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, 0);
                                return Ok((resp_header, Vec::new()));
                            }
                            if engine.is_node_banned(&chain_req.auth.ephemeral_pubkey).await {
                                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, humoco_sim_core::wire::FLAG_PEER_SUSPENDED, 0);
                                return Ok((resp_header, Vec::new()));
                            }
                            for hop in &chain_req.chain {
                                if engine.is_node_banned(&hop.sender_ephemeral_pub).await
                                    || engine.is_node_banned(&hop.auth.ephemeral_pubkey).await
                                {
                                    let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, humoco_sim_core::wire::FLAG_PEER_SUSPENDED, 0);
                                    return Ok((resp_header, Vec::new()));
                                }
                                if !crate::api::hmc::verify_l2_lock_signature(hop) {
                                    warn!("LockVerifyRequest rejected: invalid hop signature in chain");
                                    let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0);
                                    return Ok((resp_header, Vec::new()));
                                }
                            }
                            let (verdict, _is_new) = engine.ingress_hmc_chain_lock(chain_req.clone(), crate::storage::IngressOrigin::ClientApi, Some(now_ms)).await;
                            match verdict {
                                crate::api::hmc::L2Verdict::Conflict { .. } | crate::api::hmc::L2Verdict::Rejected { .. } => {
                                    let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, 0);
                                    return Ok((resp_header, Vec::new()));
                                }
                                _ => {
                                    let last_hop = chain_req.chain.last().unwrap();
                                    let lookup_tag = if last_hop.is_genesis {
                                        bs58::encode(&last_hop.transaction_hash).into_string()
                                    } else {
                                        last_hop.ds_tag.clone().unwrap_or_default()
                                    };
                                    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                                    let requested_status = (header.flags & 0xFF) as u8;
                                    let local_active_count = peer_manager.as_ref().map(|pm| pm.active_nodes_count()).unwrap_or(1);
                                    let can_be_final = humoco_sim_core::types::required_quorum(local_active_count).1
                                        && peer_manager.as_ref().map(|pm| pm.is_network_stable_ge20_for_24h(now_ms)).unwrap_or(false);
                                    let final_status = requested_status.min(if can_be_final { 1 } else { 0 });
                                    let attestation = crate::api::routes::create_attestation(
                                        &identity,
                                        op_hash,
                                        parent_bytes,
                                        shard_id,
                                        final_status,
                                        now_ms,
                                    );
                                    let resp_bytes = bincode::serialize(&attestation).unwrap_or_default();
                                    let payload_len = checked_payload_len(resp_bytes.len())?;
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        0,
                                        payload_len,
                                    );
                                    return Ok((resp_header, resp_bytes));
                                }
                            }
                        } else {
                            if engine.is_node_banned(&req.sender_ephemeral_pub).await
                                || engine.is_node_banned(&req.auth.ephemeral_pubkey).await
                            {
                                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, humoco_sim_core::wire::FLAG_PEER_SUSPENDED, 0);
                                return Ok((resp_header, Vec::new()));
                            }

                            if !crate::api::hmc::verify_l2_lock_signature(&req) {
                                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0);
                                return Ok((resp_header, Vec::new()));
                            }

                            let lookup_tag = if req.is_genesis {
                                bs58::encode(&req.transaction_hash).into_string()
                            } else {
                                match &req.ds_tag {
                                    Some(tag) if !tag.trim().is_empty() => tag.clone(),
                                    _ => {
                                        let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, 0);
                                        return Ok((resp_header, Vec::new()));
                                    }
                                }
                            };

                            let entry = crate::api::hmc::L2LockEntry::from(&req);
                            let (verdict, _is_new) = engine.ingress_hmc_lock(lookup_tag.clone(), entry.clone()).await;

                            match verdict {
                                crate::api::hmc::L2Verdict::Conflict { .. } | crate::api::hmc::L2Verdict::Rejected { .. } => {
                                    let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, 0);
                                    return Ok((resp_header, Vec::new()));
                                }
                                _ => {
                                    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                                    let requested_status = (header.flags & 0xFF) as u8;
                                    let local_active_count = peer_manager.as_ref().map(|pm| pm.active_nodes_count()).unwrap_or(1);
                                    let can_be_final = humoco_sim_core::types::required_quorum(local_active_count).1
                                        && peer_manager.as_ref().map(|pm| pm.is_network_stable_ge20_for_24h(now_ms)).unwrap_or(false);
                                    let final_status = requested_status.min(if can_be_final { 1 } else { 0 });
                                    let attestation = crate::api::routes::create_attestation(
                                        &identity,
                                        entry.t_id,
                                        parent_bytes,
                                        shard_id,
                                        final_status,
                                        now_ms,
                                    );
                                    let resp_bytes = bincode::serialize(&attestation).unwrap_or_default();
                                    let payload_len = checked_payload_len(resp_bytes.len())?;
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        0,
                                        payload_len,
                                    );
                                    return Ok((resp_header, resp_bytes));
                                }
                            }
                        }
                    }
                }
            } else if msg_type == MsgType::StatusQuery as u16 {
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0)
                    });

                let ncb_read_eff = if let Some(tc) = &tier_controller {
                    tc.effective_read_ncb()
                } else {
                    humoco_sim_core::quota::HARD_FLOOR_READ_BASELINE_DAILY
                };
                let read_limit = (5.0 * ncb_read_eff as f64).round() as u64;

                let (lock_id, parent_lock, shard_id, declared_write_ema, declared_read_ema, raw_sender_pubkey, timestamp_ms, sender_signature) =
                    if let Ok(sq) = bincode::deserialize::<crate::network::framing::StatusQueryPayload>(&payload) {
                        (sq.lock_id, sq.parent_lock, sq.shard_id, sq.declared_write_ema_micro_bj, sq.current_read_ema_credits, sq.sender_pubkey, sq.timestamp_ms, sq.sender_signature)
                    } else if let Ok((l_id, p_lock, s_id)) = bincode::deserialize::<([u8; 32], [u8; 32], u16)>(&payload) {
                        (l_id, p_lock, s_id, 0, 0, [0u8; 32], 0, [0u8; 64])
                    } else {
                        let resp_header = WireHeader::new(MsgType::StatusResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, 0);
                        return Ok((resp_header, Vec::new()));
                    };

                // 1. Cheap check: declared read rate vs 5x whale brake limit
                let declared_read_rate = humoco_sim_core::quota::ema_to_daily_rate(declared_read_ema);
                if declared_read_rate > read_limit {
                    warn!(declared_read_rate, read_limit, "StatusQuery rejected: declared read load exceeds 5.0 * ncb_read_eff");
                    let resp_header = WireHeader::new(
                        MsgType::StatusResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                }

                // 2. Check authenticated QUIC TLS peer matches claimed sender
                if let Some(auth_peer) = peer_identity {
                    if raw_sender_pubkey != [0u8; 32] && raw_sender_pubkey != auth_peer {
                        warn!(
                            claimed = %hex::encode(raw_sender_pubkey),
                            authenticated = %hex::encode(auth_peer),
                            "StatusQuery rejected: claimed sender pubkey does not match authenticated QUIC identity"
                        );
                        let resp_header = WireHeader::new(
                            MsgType::StatusResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                            0,
                        );
                        return Ok((resp_header, Vec::new()));
                    }
                }
                let sender_pubkey = if let Some(auth_peer) = peer_identity {
                    auth_peer
                } else {
                    raw_sender_pubkey
                };

                // 3. Reject null sender pubkey and signature if signed payload expected
                if raw_sender_pubkey != [0u8; 32] || sender_signature != [0u8; 64] {
                    if sender_pubkey == [0u8; 32] {
                        warn!("StatusQuery rejected: null sender pubkey");
                        let resp_header = WireHeader::new(
                            MsgType::StatusResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                            0,
                        );
                        return Ok((resp_header, Vec::new()));
                    }
                    if sender_signature == [0u8; 64] {
                        warn!("StatusQuery rejected: null sender signature");
                        let resp_header = WireHeader::new(
                            MsgType::StatusResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_SIGNATURE_INVALID,
                            0,
                        );
                        return Ok((resp_header, Vec::new()));
                    }

                    let curr = humoco_sim_core::fraud::IngressEnvelopeEvidence::new_v2(
                        sender_pubkey,
                        timestamp_ms,
                        declared_write_ema,
                        declared_read_ema,
                        0,
                        true,
                        lock_id,
                        sender_signature,
                    );

                    if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&curr) {
                        warn!(sender = %hex::encode(sender_pubkey), "StatusQuery rejected: invalid ingress envelope signature");
                        let resp_header = WireHeader::new(
                            MsgType::StatusResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_SIGNATURE_INVALID,
                            0,
                        );
                        return Ok((resp_header, Vec::new()));
                    }

                    if let Some(pm) = peer_manager.as_ref() {
                        if let Some(prev) = pm.get_node_read_evidence(&sender_pubkey).await {
                            if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(&prev, &curr) {
                                warn!(sender = %hex::encode(sender_pubkey), "CRITICAL FRAUD: read under-reporting detected in StatusQuery! Slashing perpetrator.");
                                let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, curr.clone());
                                let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                let _ = storage.put_evidence(&evidence_hash, &evidence_bytes);
                                engine.ban_node(sender_pubkey, now_ms).await;
                                pm.ban_node(&sender_pubkey).await;
                                pm.broadcast_fraud_proof(proof);

                                let resp_header = WireHeader::new(
                                    MsgType::StatusResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED
                                        | humoco_sim_core::wire::FLAG_PEER_SUSPENDED
                                        | humoco_sim_core::wire::FLAG_QUOTA_FRAUD,
                                    0,
                                );
                                return Ok((resp_header, Vec::new()));
                            }
                        }
                        pm.update_node_read_evidence(&sender_pubkey, curr.clone()).await;
                        pm.record_observed_evidence(curr.clone()).await;
                    }
                }

                // 4. Check banned
                let is_banned = if sender_pubkey != [0u8; 32] {
                    if engine.is_node_banned(&sender_pubkey).await {
                        true
                    } else if let Some(pm) = peer_manager.as_ref() {
                        pm.is_banned(&sender_pubkey).await
                    } else {
                        false
                    }
                } else {
                    false
                };
                if is_banned {
                    warn!(sender = %hex::encode(sender_pubkey), "StatusQuery rejected: sender is banned");
                    let resp_header = WireHeader::new(
                        MsgType::StatusResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_PEER_SUSPENDED,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                }

                // 5. Recipient-side read quota check
                if let Some(tc) = &tier_controller {
                    if sender_pubkey != [0u8; 32] {
                        let epoch_day = tc.current_epoch_day_at(if timestamp_ms > 0 { timestamp_ms } else { now_ms });
                        if let Err(e) = tc.evaluate_node_read_quota(&sender_pubkey, 1, epoch_day) {
                            warn!(error = ?e, sender = %hex::encode(sender_pubkey), "StatusQuery rejected: node read quota exceeded");
                            let resp_header = WireHeader::new(
                                MsgType::StatusResponse as u16,
                                header.session_seq.wrapping_add(1),
                                header.epoch_id,
                                humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED,
                                0,
                            );
                            return Ok((resp_header, Vec::new()));
                        }
                    }
                }

                // Strict Lock & Shard & Validity Verification (INV: Close StatusQuery Signature Hole)
                let matching_and_valid = {
                    let mut is_match = false;
                    // Check Pure L2 Lock in RAM or Disk
                    let ram_lock = engine.get_ram_lock(&parent_lock).await;
                    let stored = ram_lock.or_else(|| {
                        storage
                            .get_lock(&parent_lock)
                            .ok()
                            .flatten()
                            .map(|(rec, _)| rec)
                    });
                    if let Some(rec) = stored {
                        let expected_shard = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
                        if rec.id == lock_id
                            && rec.parent_lock == parent_lock
                            && shard_id == expected_shard
                            && rec.valid_until.0 >= now_ms
                        {
                            is_match = true;
                        }
                    }

                    // Check HMC lock in HMC RAM
                    if !is_match {
                        let hmc = engine.hmc_ram.read().await;
                        for (lookup_tag, entry) in &hmc.locks {
                            if entry.t_id == lock_id {
                                let tag_hash = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                                let parent_matches = tag_hash == parent_lock || lookup_tag.as_bytes() == &parent_lock[..];
                                if parent_matches {
                                    let v_hash = *blake3::hash(entry.layer2_voucher_id.as_bytes()).as_bytes();
                                    let v_shard = u16::from_be_bytes([v_hash[0], v_hash[1]]);
                                    let p_shard = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
                                    let shard_matches = shard_id == v_shard || shard_id == p_shard;
                                    let valid = entry
                                        .deletable_at
                                        .as_deref()
                                        .and_then(|s| s.parse::<u64>().ok())
                                        .map(|del| del >= now_ms)
                                        .unwrap_or(true);
                                    if shard_matches && valid {
                                        is_match = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    is_match
                };

                if matching_and_valid {
                    let target_status = (header.flags & 0xFF) as u8;
                    let attestation = crate::api::routes::create_attestation(
                        &identity,
                        lock_id,
                        parent_lock,
                        shard_id,
                        target_status,
                        now_ms,
                    );
                    let resp_bytes = bincode::serialize(&attestation).unwrap_or_default();
                    let payload_len = checked_payload_len(resp_bytes.len())?;
                    let resp_header = WireHeader::new(
                        MsgType::StatusResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        0,
                        payload_len,
                    );
                    return Ok((resp_header, resp_bytes));
                }
                let resp_header = WireHeader::new(MsgType::StatusResponse as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, 0);
                return Ok((resp_header, Vec::new()));
            } else if msg_type == MsgType::ShardDigestRequest as u16 {
                let shard_id = if payload.len() >= 2 {
                    u16::from_le_bytes([payload[0], payload[1]])
                } else {
                    0
                };
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0)
                    });
                let mut locks: Vec<humoco_sim_core::types::LockRecord> = storage
                    .all_valid_locks(now_ms)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(rec, _)| rec)
                    .collect();
                for (rec, _) in engine.ram.read().await.all_locks() {
                    if !locks.iter().any(|l| l.parent_lock == rec.parent_lock) {
                        locks.push(rec);
                    }
                }
                let mut hmc_locks_all = storage.all_valid_hmc_locks(now_ms).unwrap_or_default();
                for (tag, entry) in &engine.hmc_ram.read().await.locks {
                    if !hmc_locks_all.iter().any(|(t, _)| t == tag) {
                        hmc_locks_all.push((tag.clone(), entry.clone()));
                    }
                }
                for (tag, entry) in hmc_locks_all {
                    let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
                    if !locks.iter().any(|l| l.parent_lock == parent_bytes) {
                        let valid_until_ms = entry
                            .deletable_at
                            .as_deref()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or_else(|| now_ms + 365 * 24 * 3600 * 1000);
                        locks.push(humoco_sim_core::types::LockRecord::new(
                            parent_bytes,
                            entry.sender_ephemeral_pub,
                            entry.t_id.to_vec(),
                            humoco_sim_core::types::SimTime(0),
                            humoco_sim_core::types::SimTime(valid_until_ms),
                        ));
                    }
                }
                if let Some(pm) = peer_manager.as_ref() {
                    pm.register_active_shard(shard_id).await;
                }
                let shard_locks: Vec<humoco_sim_core::types::LockRecord> = locks
                    .into_iter()
                    .filter(|l| {
                        let sid = u16::from_be_bytes([l.parent_lock[0], l.parent_lock[1]]);
                        sid == shard_id && !l.status.is_void() && l.valid_until > humoco_sim_core::types::SimTime(now_ms)
                    })
                    .collect();
                let digest = humoco_sim_core::crypto::compute_shard_digest_at(
                    shard_id,
                    &shard_locks,
                    humoco_sim_core::types::SimTime(now_ms),
                );
                let lock_count = shard_locks.len() as u64;
                let resp_bytes = bincode::serialize(&(digest, lock_count)).unwrap_or_default();
                let payload_len = checked_payload_len(resp_bytes.len())?;
                let resp_header = WireHeader::new(
                    MsgType::ShardDigestResponse as u16,
                    header.session_seq.wrapping_add(1),
                    header.epoch_id,
                    0,
                    payload_len,
                );
                return Ok((resp_header, resp_bytes));
            } else if msg_type == MsgType::ActiveSyncRequest as u16 {
                let req = crate::network::framing::ActiveSyncRequest::from_bytes(&payload)
                    .unwrap_or(crate::network::framing::ActiveSyncRequest {
                        cursor: 0,
                        limit: 500,
                    });
                let mut locks = storage.all_valid_locks(0).unwrap_or_default();
                for (rec, rv) in engine.ram.read().await.all_locks() {
                    if !locks.iter().any(|(l, _)| l.parent_lock == rec.parent_lock) {
                        locks.push((rec, rv.0));
                    }
                }
                locks.sort_by(|a, b| a.0.parent_lock.cmp(&b.0.parent_lock));

                let mut hmc_locks = storage.all_valid_hmc_locks(0).unwrap_or_default();
                let hmc_ram = engine.hmc_ram.read().await;
                for (tag, entry) in &hmc_ram.locks {
                    if !hmc_locks.iter().any(|(t, _)| t == tag) {
                        hmc_locks.push((tag.clone(), entry.clone()));
                    }
                }
                hmc_locks.sort_by(|a, b| a.0.cmp(&b.0));

                let total_locks = locks.len();
                let total_hmc = hmc_locks.len();
                debug!(
                    total_locks,
                    total_hmc,
                    cursor = req.cursor,
                    limit = req.limit,
                    "NodeRequestHandler handling ActiveSyncRequest"
                );

                let total_locks = locks.len();
                let total_hmc = hmc_locks.len();
                let total_items = total_locks + total_hmc;
                let offset = req.cursor as usize;
                let limit = req.limit.clamp(1, 1000);

                let mut chunk_locks = Vec::new();
                let mut chunk_hmc = Vec::new();

                if offset < total_locks {
                    let end_locks = (offset + limit).min(total_locks);
                    chunk_locks.extend_from_slice(&locks[offset..end_locks]);
                    let taken = chunk_locks.len();
                    if taken < limit && total_hmc > 0 {
                        let hmc_needed = limit - taken;
                        let end_hmc = hmc_needed.min(total_hmc);
                        chunk_hmc.extend_from_slice(&hmc_locks[0..end_hmc]);
                    }
                } else if offset < total_items {
                    let hmc_offset = offset - total_locks;
                    let end_hmc = (hmc_offset + limit).min(total_hmc);
                    chunk_hmc.extend_from_slice(&hmc_locks[hmc_offset..end_hmc]);
                }

                let items_in_chunk = chunk_locks.len() + chunk_hmc.len();
                let next_offset = offset + items_in_chunk;
                let has_more = next_offset < total_items;
                let next_cursor = if has_more { Some(next_offset as u64) } else { None };

                let sync_resp = crate::network::framing::ActiveSyncResponse::new(
                    crate::network::framing::SyncPayload::new(chunk_locks, chunk_hmc),
                    has_more,
                    next_cursor,
                );
                let serialized = sync_resp.to_bytes().unwrap_or_default();
                let payload_len = checked_payload_len(serialized.len())?;
                let resp_header = WireHeader::new(MsgType::ActiveSyncDone as u16, header.session_seq.wrapping_add(1), header.epoch_id, 0, payload_len);
                return Ok((resp_header, serialized));
            }
            let default_h = DefaultRequestHandler;
            default_h.handle(header, payload).await
        })
    }

    fn handle_unidirectional(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(), NodeError>> {
        self.handle_unidirectional_authenticated(header, payload, None)
    }

    fn handle_unidirectional_authenticated(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
        sender: Option<[u8; 32]>,
    ) -> BoxFuture<Result<(), NodeError>> {
        let engine = self.engine.clone();
        let storage = self.storage.clone();
        let peer_manager = self.peer_manager.clone();
        let identity = self.identity.clone();
        Box::pin(async move {
            if header.msg_type == MsgType::HeartbeatAck as u16 {
                if (header.flags & humoco_sim_core::wire::FLAG_POW_OUTDATED) != 0 {
                    if let Some(pm) = peer_manager.as_ref() {
                        pm.set_ticket_outdated(true);
                    }
                }
                return Ok(());
            }
            if header.msg_type == MsgType::EquivocationProof as u16 {
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0)
                    });
                match bincode::deserialize::<humoco_sim_core::fraud::FraudProofPayload>(&payload) {
                    Ok(proof) => {
                        let offender = proof.perpetrator_node_id;
                        let is_first_party_valid = if !proof.verify() {
                            false
                        } else if let Some(pm) = peer_manager.as_ref() {
                            if let Some(vk) = pm.get_peer_verifying_key_by_node_id(&offender).await {
                                verify_equivocation_first_party(&vk, &proof)
                            } else if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&offender) {
                                verify_equivocation_first_party(&vk, &proof)
                            } else {
                                verify_equivocation_first_party(identity.verifying_key(), &proof)
                            }
                        } else if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&offender) {
                            verify_equivocation_first_party(&vk, &proof)
                        } else {
                            verify_equivocation_first_party(identity.verifying_key(), &proof)
                        };

                        if !is_first_party_valid {
                            warn!(offender = %hex::encode(offender), "EquivocationProof (uni) rejected: cryptographic Ed25519 verification failed (framing prevented)");
                        } else {
                            let evidence_hash = *blake3::hash(&payload).as_bytes();
                            if let Err(e) = storage.put_evidence(&evidence_hash, &payload) {
                                warn!("Failed to persist slashing evidence (uni): {}", e);
                            }
                            engine.ban_node(offender, now_ms).await;
                            if let Some(pm) = peer_manager.as_ref() {
                                let _ = pm.ban_node(&offender).await;
                                // Phase 10: dedup + echo protection (never back to sender).
                                pm.broadcast_fraud_proof_with_sender(proof, sender);
                            }
                            info!(offender = %hex::encode(offender), "Slashing (uni): offender banned and proof broadcast");
                        }
                    }
                    Err(e) => {
                        warn!("EquivocationProof (uni) rejected: deserialize failed: {}", e);
                    }
                }
                return Ok(());
            }
            if header.msg_type == MsgType::Heartbeat as u16 {
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0)
                    });
                if let Ok(hb) = crate::network::framing::HeartbeatWirePayload::from_bytes(&payload) {
                    if hb.signature != [0u8; 64] {
                        let ev_write = humoco_sim_core::fraud::IngressEnvelopeEvidence::new_v2(
                            hb.node_id,
                            hb.timestamp_ms,
                            hb.declared_write_ema_micro_bj,
                            hb.declared_read_ema_credits,
                            0,
                            false,
                            [0u8; 32],
                            hb.signature,
                        );
                        if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&ev_write) {
                            warn!(node = %hex::encode(hb.node_id), "Heartbeat rejected: invalid signature");
                            return Ok(());
                        }

                        if let Some(pm) = peer_manager.as_ref() {
                            if let Some(prev) = pm.get_node_write_evidence(&hb.node_id).await {
                                if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(&prev, &ev_write) {
                                    warn!(node = %hex::encode(hb.node_id), "CRITICAL FRAUD: under-reporting detected in Heartbeat! Slashing perpetrator.");
                                    let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, ev_write.clone());
                                    let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                    let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                    let _ = storage.put_evidence(&evidence_hash, &evidence_bytes);
                                    engine.ban_node(hb.node_id, now_ms).await;
                                    pm.ban_node(&hb.node_id).await;
                                    pm.broadcast_fraud_proof_with_sender(proof, sender);
                                    return Ok(());
                                }
                            }
                            pm.update_node_write_evidence(&hb.node_id, ev_write).await;

                            let ev_read = humoco_sim_core::fraud::IngressEnvelopeEvidence::new_v2(
                                hb.node_id,
                                hb.timestamp_ms,
                                hb.declared_write_ema_micro_bj,
                                hb.declared_read_ema_credits,
                                0,
                                true,
                                [0u8; 32],
                                hb.signature,
                            );
                            if let Some(prev) = pm.get_node_read_evidence(&hb.node_id).await {
                                if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(&prev, &ev_read) {
                                    warn!(node = %hex::encode(hb.node_id), "CRITICAL FRAUD: read under-reporting detected in Heartbeat! Slashing perpetrator.");
                                    let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, ev_read.clone());
                                    let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                    let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                    let _ = storage.put_evidence(&evidence_hash, &evidence_bytes);
                                    engine.ban_node(hb.node_id, now_ms).await;
                                    pm.ban_node(&hb.node_id).await;
                                    pm.broadcast_fraud_proof_with_sender(proof, sender);
                                    return Ok(());
                                }
                            }
                            pm.update_node_read_evidence(&hb.node_id, ev_read).await;
                        }
                    }

                    if let Some(pm) = peer_manager.as_ref() {
                        for ev in hb.piggyback_observations.into_iter().take(2) {
                            if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&ev) {
                                warn!(gateway = %hex::encode(ev.gateway_pubkey), "Piggybacked evidence ignored: invalid signature");
                                continue;
                            }
                            let gw_pub = ev.gateway_pubkey;

                            if ev.is_read {
                                if let Some(prev) = pm.get_node_read_evidence(&gw_pub).await {
                                    if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(&prev, &ev) {
                                        warn!(gateway = %hex::encode(gw_pub), "CRITICAL FRAUD: read under-reporting detected from piggyback observation! Slashing perpetrator.");
                                        let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, ev.clone());
                                        let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                        let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                        let _ = storage.put_evidence(&evidence_hash, &evidence_bytes);
                                        engine.ban_node(gw_pub, now_ms).await;
                                        pm.ban_node(&gw_pub).await;
                                        pm.broadcast_fraud_proof_with_sender(proof, sender);
                                        continue;
                                    }
                                    let is_newer = ev.timestamp_ms > prev.timestamp_ms;
                                    let is_higher = ev.declared_read_ema_credits > prev.declared_read_ema_credits;
                                    if is_newer || is_higher {
                                        pm.update_node_read_evidence(&gw_pub, ev).await;
                                    }
                                } else {
                                    pm.update_node_read_evidence(&gw_pub, ev).await;
                                }
                            } else {
                                if let Some(prev) = pm.get_node_write_evidence(&gw_pub).await {
                                    if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(&prev, &ev) {
                                        warn!(gateway = %hex::encode(gw_pub), "CRITICAL FRAUD: write under-reporting detected from piggyback observation! Slashing perpetrator.");
                                        let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, ev.clone());
                                        let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                        let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                        let _ = storage.put_evidence(&evidence_hash, &evidence_bytes);
                                        engine.ban_node(gw_pub, now_ms).await;
                                        pm.ban_node(&gw_pub).await;
                                        pm.broadcast_fraud_proof_with_sender(proof, sender);
                                        continue;
                                    }
                                    let is_newer = ev.timestamp_ms > prev.timestamp_ms;
                                    let is_higher = ev.declared_write_ema_micro_bj > prev.declared_write_ema_micro_bj;
                                    if is_newer || is_higher {
                                        pm.update_node_write_evidence(&gw_pub, ev).await;
                                    }
                                } else {
                                    pm.update_node_write_evidence(&gw_pub, ev).await;
                                }
                            }
                        }
                    }
                }
                return Ok(());
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct QuicTransport {
    endpoint: quinn::Endpoint,
    identity: NodeIdentity,
    peer_manager: Arc<PeerManager>,
    handler: Arc<dyn RequestHandler>,
    cancel_token: CancellationToken,
    stream_semaphore: Arc<Semaphore>,
    connection_semaphore: Arc<Semaphore>,
    is_sync_ready: Arc<std::sync::atomic::AtomicBool>,
}

/// Backwards-compatible alias for `QuicTransport` (task spec naming: `QuicP2pTransport`).
pub type QuicP2pTransport = QuicTransport;

impl QuicTransport {
    /// Returns true if the node is sync-ready after initial recovery.
    pub fn is_sync_ready(&self) -> bool {
        self.is_sync_ready.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sets the sync-ready state.
    pub fn set_sync_ready(&self, ready: bool) {
        self.is_sync_ready.store(ready, std::sync::atomic::Ordering::SeqCst);
    }

    /// Replaces the underlying sync-ready atomic handle.
    pub fn set_sync_ready_handle(&mut self, handle: Arc<std::sync::atomic::AtomicBool>) {
        self.is_sync_ready = handle;
    }

    /// Returns a clone of the sync-ready atomic handle.
    pub fn sync_ready_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.is_sync_ready.clone()
    }

    /// Binds a QUIC endpoint on the specified socket address using the NodeIdentity.
    pub fn bind(addr: SocketAddr, identity: &NodeIdentity) -> Result<Self, NodeError> {
        Self::bind_with_options(
            addr,
            identity,
            Arc::new(PeerManager::new(Vec::new())),
            Arc::new(DefaultRequestHandler),
            CancellationToken::new(),
        )
    }

    /// Binds a QUIC endpoint with full customization of peer manager, request handler, and cancellation.
    pub fn bind_with_options(
        addr: SocketAddr,
        identity: &NodeIdentity,
        peer_manager: Arc<PeerManager>,
        handler: Arc<dyn RequestHandler>,
        cancel_token: CancellationToken,
    ) -> Result<Self, NodeError> {
        let server_config = build_quinn_server_config(identity)?;
        let client_config = build_quinn_client_config_with_identity(identity)?;

        let mut endpoint = quinn::Endpoint::server(server_config, addr).map_err(|e| {
            NodeError::Network(format!("Failed to bind QUIC endpoint on {}: {}", addr, e))
        })?;

        endpoint.set_default_client_config(client_config);
        peer_manager.set_endpoint(endpoint.clone());

        let (fraud_tx, mut fraud_rx) = tokio::sync::mpsc::channel::<crate::network::manager::FraudProofForwardMsg>(100);
        let pm_for_channel = peer_manager.clone();
        tokio::spawn(async move {
            pm_for_channel.set_fraud_proof_tx(fraud_tx).await;
        });

        let transport = Self {
            endpoint,
            identity: identity.clone(),
            peer_manager,
            handler,
            cancel_token: cancel_token.clone(),
            stream_semaphore: Arc::new(Semaphore::new(STREAM_CONCURRENCY_LIMIT)),
            connection_semaphore: Arc::new(Semaphore::new(CONNECTION_CONCURRENCY_LIMIT)),
            is_sync_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };

        let transport_for_broadcast = transport.clone();
        let cancel = cancel_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    Some((proof, sender)) = fraud_rx.recv() => {
                        transport_for_broadcast.broadcast_equivocation_proof_to_f2f_except(&proof, sender).await;
                    }
                }
            }
        });

        Ok(transport)
    }

    /// Returns the local bound socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, NodeError> {
        self.endpoint
            .local_addr()
            .map_err(|e| NodeError::Network(format!("Failed to get local addr: {}", e)))
    }

    /// Returns a reference to the inner Quinn endpoint.
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// Returns a reference to the NodeIdentity.
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Returns a reference to the PeerManager.
    pub fn peer_manager(&self) -> &Arc<PeerManager> {
        &self.peer_manager
    }

    /// Returns a reference to the CancellationToken.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }

    /// Connects to a remote peer address via QUIC, reusing existing open connection if present.
    /// Iron rule / F2F: Permits direct connections only to F2F friends or nodes learned via F2F gossip.
    pub async fn connect_peer(&self, addr: SocketAddr) -> Result<quinn::Connection, NodeError> {
        if !self.peer_manager.can_authorize_direct_rpc(&addr, None).await {
            return Err(NodeError::Network(format!(
                "Direct connection to {} refused: peer is neither an F2F friend nor known via F2F gossip",
                addr
            )));
        }

        if let Some(conn) = self.peer_manager.get_connection(&addr).await {
            return Ok(conn);
        }

        // Apply exponential backoff with jitter if reconnecting to a failed or suspended peer (Spec 15 / INV-1502)
        if let Some(backoff) = self.peer_manager.get_reconnect_backoff(&addr).await {
            tokio::time::sleep(backoff).await;
        }

        let connecting = self
            .endpoint
            .connect(addr, "localhost")
            .map_err(NodeError::QuinnConnect)?;

        let connection = connecting.await.map_err(NodeError::QuinnConnection)?;
        let remote_node_id = extract_peer_identity_from_connection(&connection).map(|(nid, _)| nid);
        if let Some(nid) = remote_node_id {
            if self.peer_manager.is_banned(&nid).await {
                connection.close(0u32.into(), b"banned: equivocation proof");
                return Err(NodeError::Network(format!("Peer {} is banned", hex::encode(nid))));
            }
        }
        if let Some((nid, vk)) = extract_peer_identity_from_connection(&connection) {
            self.peer_manager.register_verifying_key(nid, vk).await;
        }

        self.peer_manager
            .record_success(addr, remote_node_id, Some(connection.clone()))
            .await;

        let conn_clone = connection.clone();
        let handler = self.handler.clone();
        let peer_manager = self.peer_manager.clone();
        let cancel_token = self.cancel_token.clone();
        let stream_semaphore = self.stream_semaphore.clone();
        let transport = self.clone();
        tokio::spawn(async move {
            Self::handle_connection(conn_clone, handler, peer_manager, cancel_token, remote_node_id, stream_semaphore, transport).await;
        });

        Ok(connection)
    }

    /// Explicit/unchecked connection to a peer address (useful for bootstrap / friend registration).
    pub async fn connect_peer_unchecked(&self, addr: SocketAddr) -> Result<quinn::Connection, NodeError> {
        if let Some(conn) = self.peer_manager.get_connection(&addr).await {
            return Ok(conn);
        }

        let connecting = self
            .endpoint
            .connect(addr, "localhost")
            .map_err(NodeError::QuinnConnect)?;

        let connection = connecting.await.map_err(NodeError::QuinnConnection)?;
        let remote_node_id = extract_peer_identity_from_connection(&connection).map(|(nid, _)| nid);
        if let Some(nid) = remote_node_id {
            if self.peer_manager.is_banned(&nid).await {
                connection.close(0u32.into(), b"banned: equivocation proof");
                return Err(NodeError::Network(format!("Peer {} is banned", hex::encode(nid))));
            }
        }
        if let Some((nid, vk)) = extract_peer_identity_from_connection(&connection) {
            self.peer_manager.register_verifying_key(nid, vk).await;
        }

        self.peer_manager
            .record_success(addr, remote_node_id, Some(connection.clone()))
            .await;

        let conn_clone = connection.clone();
        let handler = self.handler.clone();
        let peer_manager = self.peer_manager.clone();
        let cancel_token = self.cancel_token.clone();
        let stream_semaphore = self.stream_semaphore.clone();
        let transport = self.clone();
        tokio::spawn(async move {
            Self::handle_connection(conn_clone, handler, peer_manager, cancel_token, remote_node_id, stream_semaphore, transport).await;
        });

        Ok(connection)
    }

    /// Sends a bi-directional request frame and awaits the response frame.
    pub async fn send_request(
        &self,
        conn: &quinn::Connection,
        header: &WireHeader,
        payload: &[u8],
    ) -> Result<(WireHeader, Vec<u8>), NodeError> {
        let (mut send, mut recv) = conn.open_bi().await.map_err(NodeError::QuinnConnection)?;
        write_frame(&mut send, header, payload).await?;
        send.finish().map_err(NodeError::QuinnClosedStream)?;

        let (resp_hdr, resp_payload) = read_frame(&mut recv).await?;
        Ok((resp_hdr, resp_payload))
    }

    /// Sends a unidirectional frame over a dedicated unidirectional stream.
    pub async fn send_unidirectional(
        &self,
        conn: &quinn::Connection,
        header: &WireHeader,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        send_unidirectional_frame(conn, header, payload).await
    }
}

/// Freestanding helper to send a unidirectional frame over a dedicated QUIC stream.
pub async fn send_unidirectional_frame(
    conn: &quinn::Connection,
    header: &WireHeader,
    payload: &[u8],
) -> Result<(), NodeError> {
    let mut send = conn.open_uni().await.map_err(NodeError::QuinnConnection)?;
    write_frame(&mut send, header, payload).await?;
    send.finish().map_err(NodeError::QuinnClosedStream)?;
    Ok(())
}

impl QuicTransport {

    /// Sends a signed F2F heartbeat to a single peer (used by daemon heartbeat emitter).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_heartbeat_to(
        &self,
        addr: SocketAddr,
        node_id: [u8; 32],
        local_addr: SocketAddr,
        seq: u64,
        declared_write_ema_micro_bj: u64,
        declared_read_ema_credits: u64,
        signature: [u8; 64],
        timestamp_ms: u64,
        piggyback_observations: Vec<humoco_sim_core::fraud::IngressEnvelopeEvidence>,
    ) -> Result<(), NodeError> {
        let hb = crate::network::framing::HeartbeatWirePayload {
            node_id,
            addr: local_addr,
            timestamp_ms,
            declared_write_ema_micro_bj,
            declared_read_ema_credits,
            signature,
            supported_suites_mask: 0,
            piggyback_observations,
            pow_nonce: self.identity.nonce(),
            hrw_routing_id: *self.identity.hrw_routing_id(),
            ticket_epoch_t0: self.identity.t0(),
            ttl: 16,
        };
        let payload = bincode::serialize(&hb)
            .map_err(|e| NodeError::Network(format!("heartbeat serialize: {}", e)))?;
        let payload_len = checked_payload_len(payload.len())?;
        let header = WireHeader::new(MsgType::Heartbeat as u16, seq, 0, 0, payload_len);
        let conn = self.connect_peer_unchecked(addr).await?;
        self.send_unidirectional(&conn, &header, &payload).await
    }

    /// Forwards an authentic multi-hop presence heartbeat to a Dunbar fan-out subset of other F2F friends (Spec 11).
    pub async fn forward_heartbeat_gossip(
        &self,
        hb: &crate::network::framing::HeartbeatWirePayload,
        hops: u16,
        sender_addr: SocketAddr,
    ) {
        if hb.ttl <= 1 {
            return;
        }
        let forward_ttl = hb.ttl.saturating_sub(1);
        let next_hops = hops.saturating_add(1);
        if (next_hops as u32) >= crate::network::manager::MAX_GOSSIP_HOPS {
            return;
        }

        let all_targets = self.peer_manager.all_f2f_target_addrs().await;
        let mut candidates: Vec<SocketAddr> = all_targets
            .into_iter()
            .filter(|a| *a != sender_addr)
            .collect();

        // Also do not forward to the originator if known
        let originator_node_id = hb.node_id;
        let known_originator_addr = self.peer_manager.get_known_node_addr(&originator_node_id).await;
        if let Some(orig_addr) = known_originator_addr {
            candidates.retain(|a| *a != orig_addr);
        }

        let d = candidates.len();
        if d == 0 {
            return;
        }

        let k = crate::network::manager::calculate_fan_out(d);
        if candidates.len() > k {
            candidates.truncate(k);
        }

        let mut fwd_hb = hb.clone();
        fwd_hb.ttl = forward_ttl;

        let payload = match bincode::serialize(&fwd_hb) {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to serialize forwarded heartbeat: {}", e);
                return;
            }
        };
        let payload_len = match checked_payload_len(payload.len()) {
            Ok(l) => l,
            Err(_) => return,
        };
        let mut header = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload_len);
        header.reserved = next_hops;

        for target in candidates {
            let transport = self.clone();
            let hdr = header;
            let pld = payload.clone();
            tokio::spawn(async move {
                let _ = transport.send_unidirectional_to_peer(target, &hdr, &pld).await;
            });
        }
    }

    /// Sends a unidirectional frame to a target peer without prior authorization check (used for F2F gossip & fraud proofs).
    pub async fn send_unidirectional_to_peer(
        &self,
        addr: SocketAddr,
        header: &WireHeader,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let conn = self.connect_peer_unchecked(addr).await?;
        self.send_unidirectional(&conn, header, payload).await
    }

    /// Broadcasts an equivocation or under-reporting fraud proof to all F2F friends via unidirectional QUIC streams.
    pub async fn broadcast_equivocation_proof_to_f2f(
        &self,
        proof: &humoco_sim_core::fraud::FraudProofPayload,
    ) {
        self.broadcast_equivocation_proof_to_f2f_except(proof, None).await;
    }

    /// Phase 10: deduplicated fraud-proof forwarding with echo protection.
    /// - LRU seen-set suppresses re-broadcast storms (gossip loops).
    /// - `exclude` (the immediate sender we received the proof from) is
    ///   never sent the proof back.
    pub async fn broadcast_equivocation_proof_to_f2f_except(
        &self,
        proof: &humoco_sim_core::fraud::FraudProofPayload,
        exclude: Option<[u8; 32]>,
    ) {
        // Dedup: if already forwarded, stop the amplification loop here.
        let hash = PeerManager::fraud_proof_dedup_hash(proof);
        if !self.peer_manager.check_and_record_fraud_proof(&hash).await {
            return;
        }
        let payload = match bincode::serialize(proof) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to serialize FraudProofPayload for broadcast: {}", e);
                return;
            }
        };
        let payload_len = match checked_payload_len(payload.len()) {
            Ok(l) => l,
            Err(_) => return,
        };
        let header = WireHeader::new(MsgType::EquivocationProof as u16, 1, 0, 0, payload_len);
        let mut targets = self.peer_manager.all_f2f_target_addrs().await;
        // Echo protection: resolve all known addrs of the sender and exclude them,
        // plus belt-and-braces filtering by live peer node_id mapping.
        if let Some(sender_id) = exclude {
            let sender_addrs = self.peer_manager.addrs_for_node_id(&sender_id).await;
            targets.retain(|a| !sender_addrs.contains(a));
            if targets.is_empty() {
                return;
            }
        }
        for addr in targets {
            // Second line of echo defense: skip any target currently mapped
            // to the excluded sender identity (covers addr changes/races).
            if let Some(sender_id) = exclude {
                if let Some(peer) = self.peer_manager.get_peer(&addr).await {
                    if peer.node_id == Some(sender_id) {
                        continue;
                    }
                }
            }
            let transport = self.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                let _ = transport.send_unidirectional_to_peer(addr, &header, &payload).await;
            });
        }
    }

    /// Requests a shard digest from a peer (ShardDigestRequest -> ShardDigestResponse).
    pub async fn request_shard_digest(
        &self,
        conn: &quinn::Connection,
        shard_id: u16,
        seq: u64,
    ) -> Result<([u8; 32], u64), NodeError> {
        let payload = shard_id.to_le_bytes().to_vec();
        let payload_len = checked_payload_len(payload.len())?;
        let header = WireHeader::new(MsgType::ShardDigestRequest as u16, seq, 0, 0, payload_len);
        let (resp_hdr, resp_payload) = self.send_request(conn, &header, &payload).await?;
        if resp_hdr.msg_type != MsgType::ShardDigestResponse as u16 {
            return Err(NodeError::Network(format!(
                "Unexpected ShardDigest response msg_type {}",
                resp_hdr.msg_type
            )));
        }
        let (digest, count): ([u8; 32], u64) = bincode::deserialize(&resp_payload)
            .map_err(|e| NodeError::Network(format!("digest deserialize: {}", e)))?;
        Ok((digest, count))
    }

    /// Requests a single paginated active sync page from a peer.
    pub async fn request_active_sync_page(
        &self,
        conn: &quinn::Connection,
        seq: u64,
        cursor: u64,
        limit: usize,
    ) -> Result<crate::network::framing::ActiveSyncResponse, NodeError> {
        let req = crate::network::framing::ActiveSyncRequest::new(cursor, limit);
        let req_bytes = req.to_bytes().unwrap_or_default();
        let payload_len = checked_payload_len(req_bytes.len())?;
        let header = WireHeader::new(MsgType::ActiveSyncRequest as u16, seq, 0, 0, payload_len);
        let (resp_hdr, resp_payload) = self.send_request(conn, &header, &req_bytes).await?;
        if resp_hdr.msg_type != MsgType::ActiveSyncDone as u16 {
            return Err(NodeError::Network(format!(
                "Unexpected ActiveSync response {}",
                resp_hdr.msg_type
            )));
        }
        crate::network::framing::ActiveSyncResponse::from_bytes(&resp_payload)
            .map_err(|e| NodeError::Network(format!("active sync deserialize: {}", e)))
    }

    /// Requests full active sync data across all pages from a peer.
    pub async fn request_active_sync(
        &self,
        conn: &quinn::Connection,
        seq: u64,
    ) -> Result<crate::network::framing::SyncPayload, NodeError> {
        let mut all_locks = Vec::new();
        let mut all_hmc = Vec::new();
        let mut cursor = 0u64;
        let mut current_seq = seq;
        loop {
            let resp = self.request_active_sync_page(conn, current_seq, cursor, 500).await?;
            current_seq = current_seq.wrapping_add(1);
            all_locks.extend(resp.payload.locks);
            all_hmc.extend(resp.payload.hmc_locks);
            if !resp.has_more {
                break;
            }
            match resp.next_cursor {
                Some(next) if next > cursor => cursor = next,
                _ => break,
            }
        }
        Ok(crate::network::framing::SyncPayload::new(all_locks, all_hmc))
    }

    /// Spawns the incoming connection accept loop in the background.
    pub fn spawn_accept_loop(&self) -> tokio::task::JoinHandle<()> {
        let transport = self.clone();
        tokio::spawn(async move {
            transport.run_accept_loop().await;
        })
    }

    /// Runs the accept loop, dispatching incoming connections and streams.
    pub async fn run_accept_loop(&self) {
        debug!(
            local_addr = ?self.local_addr(),
            "Starting QUIC transport accept loop"
        );

        loop {
            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    info!("QUIC transport accept loop cancelled");
                    break;
                }
                incoming = self.endpoint.accept() => {
                    match incoming {
                        Some(incoming_conn) => {
                            let handler = self.handler.clone();
                            let peer_manager = self.peer_manager.clone();
                            let cancel_token = self.cancel_token.clone();
                            let stream_semaphore = self.stream_semaphore.clone();
                            let connection_semaphore = self.connection_semaphore.clone();
                            let permit = match connection_semaphore.try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!(
                                        "Connection concurrency limit {} reached, dropping incoming QUIC handshake (DoS protection)",
                                        CONNECTION_CONCURRENCY_LIMIT
                                    );
                                    continue;
                                }
                            };

                            let transport = self.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                match incoming_conn.await {
                                    Ok(conn) => {
                                        let remote_addr = conn.remote_address();
                                        let remote_node_id = extract_peer_identity_from_connection(&conn).map(|(nid, _)| nid);
                                        let is_authorized = peer_manager.can_accept_gossip(&remote_addr, remote_node_id.as_ref()).await
                                            || peer_manager.can_authorize_direct_rpc(&remote_addr, remote_node_id.as_ref()).await;

                                        if !is_authorized {
                                            // Phase 10: unauthorized QUIC connections are
                                            // actively terminated instead of being kept
                                            // half-open (resource exhaustion protection).
                                            warn!(
                                                remote = %remote_addr,
                                                node_id = ?remote_node_id.map(hex::encode),
                                                "Rejected unauthorized QUIC connection (neither F2F nor known via gossip): closing"
                                            );
                                            conn.close(0u32.into(), b"unauthorized: unknown peer");
                                            return;
                                        }
                                        if let Some((nid, vk)) = extract_peer_identity_from_connection(&conn) {
                                            peer_manager.register_verifying_key(nid, vk).await;
                                        }
                                        peer_manager
                                            .record_success(remote_addr, remote_node_id, Some(conn.clone()))
                                            .await;
                                        Self::handle_connection(conn, handler, peer_manager.clone(), cancel_token, remote_node_id, stream_semaphore, transport).await;
                                    }
                                    Err(err) => {
                                        debug!(error = %err, "Failed to establish incoming QUIC connection");
                                    }
                                }
                            });
                        }
                        None => {
                            debug!("QUIC endpoint closed");
                            break;
                        }
                    }
                }
            }
        }
    }

    fn handle_connection(
        conn: quinn::Connection,
        handler: Arc<dyn RequestHandler>,
        peer_manager: Arc<PeerManager>,
        cancel_token: CancellationToken,
        remote_node_id: Option<[u8; 32]>,
        stream_semaphore: Arc<Semaphore>,
        transport: QuicTransport,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            let remote_addr = conn.remote_address();
            if let Some(nid) = remote_node_id {
                if peer_manager.is_banned(&nid).await {
                    conn.close(0u32.into(), b"banned: equivocation proof");
                    return;
                }
            }
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                bi_res = conn.accept_bi() => {
                    if let Some(nid) = remote_node_id {
                        if peer_manager.is_banned(&nid).await {
                            conn.close(0u32.into(), b"banned: equivocation proof");
                            break;
                        }
                    }
                    match bi_res {
                        Ok((mut send, mut recv)) => {
                            let h = handler.clone();
                            let pm = peer_manager.clone();
                            let sem = stream_semaphore.clone();
                            tokio::spawn(async move {
                                let _permit = match sem.try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        warn!(
                                            remote = %remote_addr,
                                            "Stream concurrency limit {} reached, dropping incoming bi-stream (DoS protection)", STREAM_CONCURRENCY_LIMIT
                                        );
                                        return;
                                    }
                                };
                                match read_frame(&mut recv).await {
                                    Ok((header, payload)) => {
                                        // Shard-Direct RPC Authorization:
                                        // LockVerifyRequest, ActiveSyncRequest, and ShardDigestRequest are only allowed if peer is F2F friend or known via gossip
                                        let is_restricted_rpc = header.msg_type == MsgType::LockVerifyRequest as u16
                                            || header.msg_type == MsgType::StatusQuery as u16
                                            || header.msg_type == MsgType::ActiveSyncRequest as u16
                                            || header.msg_type == MsgType::ShardDigestRequest as u16;

                                        if is_restricted_rpc
                                            && !pm.can_authorize_direct_rpc(&remote_addr, remote_node_id.as_ref()).await
                                        {
                                            warn!(
                                                remote = %remote_addr,
                                                node_id = ?remote_node_id.map(hex::encode),
                                                msg_type = header.msg_type,
                                                "Rejected direct RPC from unauthorized peer (neither F2F nor known via gossip)"
                                            );
                                            // Phase 8 (Spec 15/19 Tit-for-Tat): locally suspended
                                            // or permanently banned peers are refused with
                                            // FLAG_PEER_SUSPENDED so the gateway applies
                                            // rank-21 replacement; unknown peers get a plain
                                            // unauthorized response without any malus effect.
                                            let suspended_or_banned = if let Some(nid) = remote_node_id {
                                                pm.is_banned(&nid).await
                                                    || pm.is_peer_suspended_by_id(&nid).await
                                                    || pm.is_peer_suspended_by_addr(&remote_addr).await
                                            } else {
                                                pm.is_peer_suspended_by_addr(&remote_addr).await
                                            };
                                            let resp_payload = b"unauthorized";
                                            let payload_len = checked_payload_len(resp_payload.len()).unwrap_or(0);
                                            let resp_flags = if suspended_or_banned {
                                                humoco_sim_core::wire::FLAG_PEER_SUSPENDED
                                            } else {
                                                humoco_sim_core::wire::FLAG_UNAUTHORIZED
                                            };
                                            let resp_header = WireHeader::new(
                                                MsgType::StatusResponse as u16,
                                                header.session_seq.wrapping_add(1),
                                                header.epoch_id,
                                                resp_flags,
                                                payload_len,
                                            );
                                            if let Err(e) = write_frame(&mut send, &resp_header, resp_payload).await {
                                                debug!(error = %e, "Failed to write unauthorized response frame");
                                            }
                                            let _ = send.finish();
                                            return;
                                        }

                                        match h.handle_authenticated(header, payload, remote_node_id).await {
                                            Ok((resp_header, resp_payload)) => {
                                                if let Err(e) = write_frame(&mut send, &resp_header, &resp_payload).await {
                                                    debug!(error = %e, "Failed to write frame response");
                                                }
                                                let _ = send.finish();
                                            }
                                            Err(e) => {
                                                error!(error = %e, "Request handler failed");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        debug!(error = %e, "Failed to read incoming bi-stream frame");
                                    }
                                }
                            });
                        }
                        Err(_) => {
                            // Phase 8 (Spec 15/19, TODO-ARCH-02): the QUIC session
                            // ended (orderly shutdown, graceful CONNECTION_CLOSE,
                            // or Tier-2 15s idle timeout = NORMAL state of the
                            // ephemeral LRU pool). This is NEVER a peer failure:
                            // clear the handle, preserve the Tit-for-Tat malus.
                            peer_manager.note_idle_close(&remote_addr).await;
                            break;
                        },
                    }
                }
                uni_res = conn.accept_uni() => {
                    match uni_res {
                        Ok(mut recv) => {
                            let h = handler.clone();
                            let pm = peer_manager.clone();
                            let sem = stream_semaphore.clone();
                            let conn_clone = conn.clone();
                            let transport_clone = transport.clone();
                            tokio::spawn(async move {
                                let _permit = match sem.try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        warn!(
                                            remote = %remote_addr,
                                            "Stream concurrency limit {} reached, dropping incoming uni-stream (DoS protection)", STREAM_CONCURRENCY_LIMIT
                                        );
                                        return;
                                    }
                                };
                                match read_frame(&mut recv).await {
                                    Ok((header, payload)) => {
                                        // GOSSIP BARRIER:
                                        // GOSSIP BARRIER:
                                        // Mesh Gossip (Heartbeat and EquivocationProof) is STRICTLY accepted from direct F2F friends only!
                                        let is_gossip = header.msg_type == MsgType::Heartbeat as u16
                                            || header.msg_type == MsgType::EquivocationProof as u16;

                                        if is_gossip && !pm.can_accept_gossip(&remote_addr, remote_node_id.as_ref()).await {
                                            warn!(
                                                remote = %remote_addr,
                                                node_id = ?remote_node_id.map(hex::encode),
                                                msg_type = header.msg_type,
                                                "GOSSIP BARRIER: Dropped gossip from non-F2F connection"
                                            );
                                            return;
                                        }

                                        // HeartbeatAck handling:
                                        if header.msg_type == MsgType::HeartbeatAck as u16
                                            && (header.flags & humoco_sim_core::wire::FLAG_POW_OUTDATED) != 0
                                        {
                                            pm.set_ticket_outdated(true);
                                            warn!("Received HeartbeatAck with FLAG_POW_OUTDATED from F2F peer: shard ticket is outdated");
                                        }

                                        // If an authentic Heartbeat is received from an F2F friend, update known_network_nodes and clock:
                                        if header.msg_type == MsgType::Heartbeat as u16 {
                                            let hops = header.reserved;
                                            if (hops as u32) >= crate::network::manager::MAX_GOSSIP_HOPS {
                                                warn!(hops, "GOSSIP BARRIER: Dropped gossip, max hops exceeded");
                                                return;
                                            }

                                            let is_f2f = if let Some(ref nid) = remote_node_id {
                                                pm.is_f2f_friend(nid).await
                                            } else {
                                                pm.is_f2f_addr(&remote_addr).await
                                            };
                                            let res1 = crate::network::framing::HeartbeatWirePayload::from_bytes(&payload);
                                            let res2 = bincode::deserialize::<([u8; 32], SocketAddr)>(&payload);

                                            if let Ok(hb) = res1 {
                                                // Check deduplication cache to prevent gossip loops (Spec 11)
                                                if !pm.check_and_record_heartbeat(&hb.node_id, hb.pow_nonce, hb.timestamp_ms).await {
                                                    debug!(node = %hex::encode(hb.node_id), "GOSSIP BARRIER: Dropped duplicate heartbeat (already seen)");
                                                    return;
                                                }

                                                // TTL drop check
                                                if hb.ttl == 0 {
                                                    debug!(node = %hex::encode(hb.node_id), "GOSSIP BARRIER: Dropped heartbeat with TTL == 0");
                                                    return;
                                                }

                                                if hb.signature != [0u8; 64] {
                                                    let ev_write = humoco_sim_core::fraud::IngressEnvelopeEvidence::new_v2(
                                                        hb.node_id,
                                                        hb.timestamp_ms,
                                                        hb.declared_write_ema_micro_bj,
                                                        hb.declared_read_ema_credits,
                                                        0,
                                                        false,
                                                        [0u8; 32],
                                                        hb.signature,
                                                    );
                                                    if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&ev_write) {
                                                        warn!(node = %hex::encode(hb.node_id), "GOSSIP BARRIER: Dropped heartbeat with invalid signature");
                                                        return;
                                                    }
                                                }

                                                let node_id = hb.node_id;
                                                if pm.is_banned(&node_id).await {
                                                    warn!(node = %hex::encode(node_id), "GOSSIP BARRIER: Dropped heartbeat from banned node");
                                                    return;
                                                }
                                                let is_direct = remote_node_id == Some(node_id);
                                                if is_direct && hops > 0 {
                                                    warn!("GOSSIP BARRIER: Hop-spoofing attempt by direct neighbor (hops > 0)");
                                                    return;
                                                }
                                                if !is_direct && hops == 0 {
                                                    warn!("GOSSIP BARRIER: Hop-spoofing attempt by forwarder (hops == 0)");
                                                    return;
                                                }

                                                // Verify Argon2d Shard Ticket PoW & HRW routing ID
                                                let (verified_hrw, work_score) = if hb.pow_nonce != 0 || hb.ticket_epoch_t0 != 0 {
                                                    let expected_hrw = crate::identity::compute_hrw_routing_id(&node_id, hb.pow_nonce, hb.ticket_epoch_t0);
                                                    if expected_hrw != hb.hrw_routing_id {
                                                        warn!(
                                                            node = %hex::encode(node_id),
                                                            "GOSSIP BARRIER: Invalid Argon2d shard ticket PoW (hrw_routing_id mismatch)"
                                                        );
                                                        return;
                                                    }
                                                    let w = crate::identity::compute_work_score(&node_id, hb.pow_nonce, hb.ticket_epoch_t0);
                                                    (expected_hrw, w)
                                                } else if hb.hrw_routing_id != [0u8; 32] {
                                                    // Fast-path / legacy BLAKE3
                                                    let expected_hrw = crate::identity::compute_hrw_routing_id(&node_id, 0, 0);
                                                    if expected_hrw != hb.hrw_routing_id && node_id != hb.hrw_routing_id {
                                                        warn!(
                                                            node = %hex::encode(node_id),
                                                            "GOSSIP BARRIER: Invalid fast-path shard ticket (hrw_routing_id mismatch)"
                                                        );
                                                        return;
                                                    }
                                                    (hb.hrw_routing_id, 1)
                                                } else {
                                                    (node_id, 1)
                                                };

                                                // Check ticket PoW validity against network median
                                                let (is_acceptable, _median) = pm.is_ticket_acceptable(work_score);
                                                if !is_acceptable {
                                                    if hops == 0 {
                                                        warn!(
                                                            node = %hex::encode(node_id),
                                                            "Direct F2F friend has outdated shard ticket; sending FLAG_POW_OUTDATED feedback"
                                                        );
                                                        let ack_hdr = WireHeader::new(
                                                            MsgType::HeartbeatAck as u16,
                                                            header.session_seq.wrapping_add(1),
                                                            header.epoch_id,
                                                            humoco_sim_core::wire::FLAG_POW_OUTDATED,
                                                            0,
                                                        );
                                                        let _ = send_unidirectional_frame(&conn_clone, &ack_hdr, &[]).await;
                                                    } else {
                                                        warn!(
                                                            node = %hex::encode(node_id),
                                                            hops,
                                                            "GOSSIP BARRIER: Dropped multi-hop gossip with outdated PoW"
                                                        );
                                                    }
                                                    return;
                                                }

                                                pm.learn_node_from_gossip_with_hrw_and_work(
                                                    node_id,
                                                    verified_hrw,
                                                    hb.addr,
                                                    hops as u8,
                                                    Some(remote_addr),
                                                    work_score,
                                                ).await;

                                                // Spec 07 / Spec 11: Clock samples fed to P2pClock must originate strictly from direct authenticated F2F peers,
                                                // never relayed third-party hops (Task 4: F2F-Only Clock Samples).
                                                if hops == 0 && is_f2f && is_direct {
                                                    pm.clock().record_heartbeat(true, hb.timestamp_ms);
                                                }

                                                // Multi-hop forwarding to Dunbar fan-out subset of F2F peers (Spec 11)
                                                if hb.ttl > 1 && (hops as u32) + 1 < crate::network::manager::MAX_GOSSIP_HOPS {
                                                    transport_clone.forward_heartbeat_gossip(&hb, hops, remote_addr).await;
                                                }
                                            } else if let Ok((adv_id, adv_addr)) = res2 {
                                                if pm.is_banned(&adv_id).await {
                                                    warn!(node = %hex::encode(adv_id), "GOSSIP BARRIER: Dropped heartbeat from banned node");
                                                    return;
                                                }
                                                let is_direct = remote_node_id == Some(adv_id);
                                                if is_direct && hops > 0 {
                                                    warn!("GOSSIP BARRIER: Hop-spoofing attempt by direct neighbor (hops > 0)");
                                                    return;
                                                }
                                                if !is_direct && hops == 0 {
                                                    warn!("GOSSIP BARRIER: Hop-spoofing attempt by forwarder (hops == 0)");
                                                    return;
                                                }
                                                pm.learn_node_from_gossip(adv_id, adv_addr, hops as u8, Some(remote_addr)).await;
                                            }
                                        }

                                        if let Err(e) = h.handle_unidirectional_authenticated(header, payload, remote_node_id).await {
                                            debug!(error = %e, "Failed to handle unidirectional frame");
                                        }
                                    }
                                    Err(e) => {
                                        debug!(error = %e, "Failed to read incoming uni-stream frame");
                                    }
                                }
                            });
                        }
                        Err(_) => {
                            // Phase 8 (Spec 15/19, TODO-ARCH-02): see bi-stream
                            // branch above — session end / Tier-2 15s idle timeout
                            // is normal and NEVER calls `record_failure`.
                            peer_manager.note_idle_close(&remote_addr).await;
                            break;
                        },
                    }
                }
            }
        }
        })
    }

    /// Closes the QUIC endpoint and all active connections.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"node shutdown");
    }
}
