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
/// Maximum number of concurrent background gossip forward tasks.
pub const GOSSIP_FORWARD_CONCURRENCY_LIMIT: usize = 64;

static GOSSIP_FORWARD_SEMAPHORE: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(GOSSIP_FORWARD_CONCURRENCY_LIMIT));

use crate::error::NodeError;
use crate::identity::NodeIdentity;
use crate::network::framing::{read_frame, write_frame};
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
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>>;

    fn handle_unidirectional(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(), NodeError>> {
        let _ = (header, payload);
        Box::pin(async { Ok(()) })
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
                x if x == MsgType::MergeLoserBroadcast as u16 => MsgType::MergeLoserAck as u16,
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
    let a = match humoco_sim_core::fraud::decode_attestation(&proof.evidence_packet_a) {
        Some(att) => att,
        None => return false,
    };
    let b = match humoco_sim_core::fraud::decode_attestation(&proof.evidence_packet_b) {
        Some(att) => att,
        None => return false,
    };

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
            || humoco_sim_core::crypto::verify_attestation(att)
    };

    verify_att(&a) && verify_att(&b)
}


/// Node daemon request handler with access to dual-tier storage for gossip and active sync.
#[derive(Clone)]
pub struct NodeRequestHandler {
    pub engine: crate::storage::DualTierEngine,
    pub storage: Arc<crate::storage::RedbStorage>,
    pub identity: NodeIdentity,
    pub peer_manager: Option<Arc<crate::network::PeerManager>>,
    pub seen_gossip_locks: Arc<parking_lot::Mutex<crate::network::manager::SeenGossipCache>>,
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
            seen_gossip_locks: Arc::new(parking_lot::Mutex::new(
                crate::network::manager::SeenGossipCache::default(),
            )),
        }
    }

    pub fn with_peer_manager(
        engine: crate::storage::DualTierEngine,
        storage: Arc<crate::storage::RedbStorage>,
        identity: NodeIdentity,
        peer_manager: Arc<crate::network::PeerManager>,
    ) -> Self {
        let seen_gossip_locks = peer_manager.seen_gossip_cache();
        Self {
            engine,
            storage,
            identity,
            peer_manager: Some(peer_manager),
            seen_gossip_locks,
        }
    }
}

impl RequestHandler for NodeRequestHandler {
    fn handle(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        let engine = self.engine.clone();
        let storage = self.storage.clone();
        let identity = self.identity.clone();
        let peer_manager = self.peer_manager.clone();
        Box::pin(async move {
            let msg_type = header.msg_type;
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
                let resp_header = WireHeader::new(MsgType::EquivocationAck as u16, header.session_seq + 1, header.epoch_id, 0, 0);
                return Ok((resp_header, Vec::new()));
            }
            if msg_type == MsgType::LockVerifyRequest as u16 {
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0)
                    });

                if let Ok(wire_payload) = bincode::deserialize::<crate::network::framing::LockWirePayload>(&payload) {
                    match wire_payload {
                        crate::network::framing::LockWirePayload::Sim(record, root_valid_until) => {
                            if engine.is_node_banned(&record.receiver_pub).await {
                                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq + 1, header.epoch_id, 0, 0);
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
                                    let shard_id = u16::from_be_bytes([record.parent_lock[0], record.parent_lock[1]]);
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
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq + 1,
                                        header.epoch_id,
                                        0,
                                        resp_bytes.len() as u32,
                                    );
                                    return Ok((resp_header, resp_bytes));
                                }
                                _ => {
                                    let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq + 1, header.epoch_id, 0, 0);
                                    return Ok((resp_header, Vec::new()));
                                }
                            }
                        }
                        crate::network::framing::LockWirePayload::Hmc { req, root_valid_until: _ } => {
                            if engine.is_node_banned(&req.sender_ephemeral_pub).await
                                || engine.is_node_banned(&req.auth.ephemeral_pubkey).await
                            {
                                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq + 1, header.epoch_id, 0, 0);
                                return Ok((resp_header, Vec::new()));
                            }

                            if !crate::api::hmc::verify_l2_lock_signature(&req) {
                                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq + 1, header.epoch_id, 0, 0);
                                return Ok((resp_header, Vec::new()));
                            }

                            let lookup_tag = if req.is_genesis {
                                bs58::encode(&req.transaction_hash).into_string()
                            } else {
                                match &req.ds_tag {
                                    Some(tag) if !tag.trim().is_empty() => tag.clone(),
                                    _ => {
                                        let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq + 1, header.epoch_id, 0, 0);
                                        return Ok((resp_header, Vec::new()));
                                    }
                                }
                            };

                            let entry = crate::api::hmc::L2LockEntry::from(&*req);
                            let (verdict, _is_new) = engine.ingress_hmc_lock(lookup_tag.clone(), entry.clone()).await;

                            match verdict {
                                crate::api::hmc::L2Verdict::Conflict { .. } | crate::api::hmc::L2Verdict::Rejected { .. } => {
                                    let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq + 1, header.epoch_id, 0, 0);
                                    return Ok((resp_header, Vec::new()));
                                }
                                _ => {
                                    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                                    let shard_id = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
                                    let attestation = crate::api::routes::create_attestation(
                                        &identity,
                                        entry.t_id,
                                        parent_bytes,
                                        shard_id,
                                        0,
                                        now_ms,
                                    );
                                    let resp_bytes = bincode::serialize(&attestation).unwrap_or_default();
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq + 1,
                                        header.epoch_id,
                                        0,
                                        resp_bytes.len() as u32,
                                    );
                                    return Ok((resp_header, resp_bytes));
                                }
                            }
                        }
                    }
                }

                if let Ok((record, root_valid_until)) = bincode::deserialize::<(humoco_sim_core::types::LockRecord, u64)>(&payload) {
                    let ingress_res = engine.ingress_lock(
                        record.clone(),
                        humoco_sim_core::types::SimTime(now_ms),
                        humoco_sim_core::types::SimTime(root_valid_until),
                    ).await;

                    match ingress_res {
                        Ok(humoco_sim_core::storage::IngressVerdictLow::AcceptedNew)
                        | Ok(humoco_sim_core::storage::IngressVerdictLow::IdempotentReplay) => {
                            let shard_id = u16::from_be_bytes([record.parent_lock[0], record.parent_lock[1]]);
                            let attestation = crate::api::routes::create_attestation(
                                &identity,
                                record.id,
                                record.parent_lock,
                                shard_id,
                                0,
                                now_ms,
                            );
                            let resp_bytes = bincode::serialize(&attestation).unwrap_or_default();
                            let resp_header = WireHeader::new(
                                MsgType::LockVerifyResponse as u16,
                                header.session_seq + 1,
                                header.epoch_id,
                                0,
                                resp_bytes.len() as u32,
                            );
                            return Ok((resp_header, resp_bytes));
                        }
                        _ => {
                            let resp_header = WireHeader::new(
                                MsgType::LockVerifyResponse as u16,
                                header.session_seq + 1,
                                header.epoch_id,
                                0,
                                0,
                            );
                            return Ok((resp_header, Vec::new()));
                        }
                    }
                }
                let resp_header = WireHeader::new(MsgType::LockVerifyResponse as u16, header.session_seq + 1, header.epoch_id, 0, 0);
                return Ok((resp_header, Vec::new()));
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

                if let Ok((lock_id, parent_lock, shard_id)) = bincode::deserialize::<([u8; 32], [u8; 32], u16)>(&payload) {
                    let known = {
                        let hmc = engine.hmc_ram.read().await;
                        hmc.locks.values().any(|e| e.t_id == lock_id)
                            || engine.get_ram_lock(&parent_lock).await.is_some()
                            || storage.get_lock(&parent_lock).map(|o| o.is_some()).unwrap_or(false)
                    };

                    if known {
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
                        let resp_header = WireHeader::new(
                            MsgType::StatusResponse as u16,
                            header.session_seq + 1,
                            header.epoch_id,
                            0,
                            resp_bytes.len() as u32,
                        );
                        return Ok((resp_header, resp_bytes));
                    }
                }
                let resp_header = WireHeader::new(MsgType::StatusResponse as u16, header.session_seq + 1, header.epoch_id, 0, 0);
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
                let digest = humoco_sim_core::crypto::compute_shard_digest_at(
                    shard_id,
                    &locks,
                    humoco_sim_core::types::SimTime(now_ms),
                );
                let lock_count = locks.len() as u64;
                let resp_bytes = bincode::serialize(&(digest, lock_count)).unwrap_or_default();
                let resp_header = WireHeader::new(
                    MsgType::ShardDigestResponse as u16,
                    header.session_seq + 1,
                    header.epoch_id,
                    0,
                    resp_bytes.len() as u32,
                );
                return Ok((resp_header, resp_bytes));
            } else if msg_type == MsgType::ActiveSyncRequest as u16 {
                let mut locks = storage.all_valid_locks(0).unwrap_or_default();
                for (rec, rv) in engine.ram.read().await.all_locks() {
                    if !locks.iter().any(|(l, _)| l.parent_lock == rec.parent_lock) {
                        locks.push((rec, rv.0));
                    }
                }
                let mut hmc_locks = storage.all_valid_hmc_locks(0).unwrap_or_default();
                let hmc_ram = engine.hmc_ram.read().await;
                for (tag, entry) in &hmc_ram.locks {
                    if !hmc_locks.iter().any(|(t, _)| t == tag) {
                        hmc_locks.push((tag.clone(), entry.clone()));
                    }
                }
                let sync_payload = crate::network::framing::SyncPayload::new(locks, hmc_locks);
                let serialized = bincode::serialize(&sync_payload).unwrap_or_default();
                let resp_header = WireHeader::new(MsgType::ActiveSyncDone as u16, header.session_seq + 1, header.epoch_id, 0, serialized.len() as u32);
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
        let engine = self.engine.clone();
        let storage = self.storage.clone();
        let peer_manager = self.peer_manager.clone();
        let seen_gossip_locks = self.seen_gossip_locks.clone();
        let identity = self.identity.clone();
        Box::pin(async move {
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
                            }
                            info!(offender = %hex::encode(offender), "Slashing (uni): offender banned");
                        }
                    }
                    Err(e) => {
                        warn!("EquivocationProof (uni) rejected: deserialize failed: {}", e);
                    }
                }
                return Ok(());
            }
            if header.msg_type == MsgType::GossipAnnounce as u16 {
                if let Ok((record, root_valid_until)) = bincode::deserialize::<(humoco_sim_core::types::LockRecord, u64)>(&payload) {
                    let expected_id = humoco_sim_core::types::LockRecord::new(
                        record.parent_lock,
                        record.receiver_pub,
                        record.nonce.clone(),
                        record.created_at,
                        record.valid_until,
                    ).id;
                    if record.id != expected_id {
                        warn!("GossipAnnounce dropped: lock ID integrity check failed");
                        return Ok(());
                    }

                    // Seen cache deduplication & echo-flooding protection (Spec 11):
                    // Pre-check against ring buffer of recently seen lock IDs
                    let is_new = seen_gossip_locks.lock().check_and_insert(&record.id);
                    if !is_new {
                        debug!(lock_id = %hex::encode(record.id), "GossipAnnounce dropped: already seen in gossip cache (echo suppression)");
                        return Ok(());
                    }

                    if engine.is_node_banned(&record.receiver_pub).await {
                        debug!("GossipAnnounce dropped: receiver is banned");
                        return Ok(());
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
                    let verdict = engine.ingress_lock(
                        record.clone(),
                        humoco_sim_core::types::SimTime(now_ms),
                        humoco_sim_core::types::SimTime(root_valid_until),
                    ).await;

                    // If the lock was accepted as new and valid in the RAM index:
                    // Forward to F2F friends according to Dunbar gossip and bio-mimetic fan-out (Spec 11)
                    if verdict == Ok(humoco_sim_core::storage::IngressVerdictLow::AcceptedNew) {
                        let hops = header.reserved;
                        if (hops as u32) < crate::network::manager::MAX_GOSSIP_HOPS {
                            if let Some(ref pm) = peer_manager {
                                let f2f_peers = pm.f2f_peer_addrs().await;
                                let d = f2f_peers.len();
                                if d > 0 {
                                    let k = crate::network::manager::calculate_fan_out(d);
                                    let mut selected_peers = f2f_peers;
                                    if k < d {
                                        use rand::seq::SliceRandom;
                                        let mut rng = rand::thread_rng();
                                        selected_peers.shuffle(&mut rng);
                                        selected_peers.truncate(k);
                                    }

                                    let mut fwd_header = header;
                                    fwd_header.reserved = hops + 1;
                                    fwd_header.session_seq = header.session_seq.saturating_add(1);

                                    let payload_clone = payload.clone();
                                    let pm_clone = pm.clone();

                                    // Pre-spawn semaphore check: zero allocations when saturated
                                    match GOSSIP_FORWARD_SEMAPHORE.try_acquire() {
                                        Err(_) => {
                                            tracing::warn!("Gossip forward dropped: concurrency limit reached (64)");
                                        }
                                        Ok(permit) => {
                                            tokio::spawn(async move {
                                                let _permit = permit;
                                                let ep_opt = pm_clone.get_endpoint();
                                                for peer_addr in selected_peers {
                                                    if let Some(conn) = pm_clone.get_connection(&peer_addr).await {
                                                        let _ = send_unidirectional_frame(&conn, &fwd_header, &payload_clone).await;
                                                    } else if let Some(ref ep) = ep_opt {
                                                        if let Ok(connecting) = ep.connect(peer_addr, "localhost") {
                                                            if let Ok(conn) = connecting.await {
                                                                pm_clone.record_success(peer_addr, None, Some(conn.clone())).await;
                                                                let _ = send_unidirectional_frame(&conn, &fwd_header, &payload_clone).await;
                                                            }
                                                        }
                                                    }
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
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
}

impl QuicTransport {
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

        Ok(Self {
            endpoint,
            identity: identity.clone(),
            peer_manager,
            handler,
            cancel_token,
            stream_semaphore: Arc::new(Semaphore::new(STREAM_CONCURRENCY_LIMIT)),
        })
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
        tokio::spawn(async move {
            Self::handle_connection(conn_clone, handler, peer_manager, cancel_token, remote_node_id, stream_semaphore).await;
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
        tokio::spawn(async move {
            Self::handle_connection(conn_clone, handler, peer_manager, cancel_token, remote_node_id, stream_semaphore).await;
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
    pub async fn send_heartbeat_to(
        &self,
        addr: SocketAddr,
        node_id: [u8; 32],
        local_addr: SocketAddr,
        seq: u64,
    ) -> Result<(), NodeError> {
        let timestamp_ms = self.peer_manager.net_time_ms();
        let hb = crate::network::framing::HeartbeatWirePayload {
            node_id,
            addr: local_addr,
            timestamp_ms,
            supported_suites_mask: 0,
        };
        let payload = bincode::serialize(&hb)
            .map_err(|e| NodeError::Network(format!("heartbeat serialize: {}", e)))?;
        let header = WireHeader::new(MsgType::Heartbeat as u16, seq, 0, 0, payload.len() as u32);
        let conn = self.connect_peer_unchecked(addr).await?;
        self.send_unidirectional(&conn, &header, &payload).await
    }

    /// Requests a shard digest from a peer (ShardDigestRequest -> ShardDigestResponse).
    pub async fn request_shard_digest(
        &self,
        conn: &quinn::Connection,
        shard_id: u16,
        seq: u64,
    ) -> Result<([u8; 32], u64), NodeError> {
        let payload = shard_id.to_le_bytes().to_vec();
        let header = WireHeader::new(MsgType::ShardDigestRequest as u16, seq, 0, 0, payload.len() as u32);
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

    /// Requests full active sync data (ActiveSyncRequest -> ActiveSyncDone) from a peer.
    pub async fn request_active_sync(
        &self,
        conn: &quinn::Connection,
        seq: u64,
    ) -> Result<crate::network::framing::SyncPayload, NodeError> {
        let header = WireHeader::new(MsgType::ActiveSyncRequest as u16, seq, 0, 0, 0);
        let (resp_hdr, resp_payload) = self.send_request(conn, &header, &[]).await?;
        if resp_hdr.msg_type != MsgType::ActiveSyncDone as u16 {
            return Err(NodeError::Network(format!(
                "Unexpected ActiveSync response {}",
                resp_hdr.msg_type
            )));
        }
        crate::network::framing::SyncPayload::from_bytes(&resp_payload)
            .map_err(|e| NodeError::Network(format!("active sync deserialize: {}", e)))
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

                            tokio::spawn(async move {
                                match incoming_conn.await {
                                    Ok(conn) => {
                                        let remote_addr = conn.remote_address();
                                        let remote_node_id = extract_peer_identity_from_connection(&conn).map(|(nid, _)| nid);
                                        let is_authorized = peer_manager.can_accept_gossip(&remote_addr, remote_node_id.as_ref()).await
                                            || peer_manager.can_authorize_direct_rpc(&remote_addr, remote_node_id.as_ref()).await;

                                        if is_authorized {
                                            if let Some((nid, vk)) = extract_peer_identity_from_connection(&conn) {
                                                peer_manager.register_verifying_key(nid, vk).await;
                                            }
                                            peer_manager
                                                .record_success(remote_addr, remote_node_id, Some(conn.clone()))
                                                .await;
                                        }
                                        Self::handle_connection(conn, handler, peer_manager.clone(), cancel_token, remote_node_id, stream_semaphore).await;
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

    async fn handle_connection(
        conn: quinn::Connection,
        handler: Arc<dyn RequestHandler>,
        peer_manager: Arc<PeerManager>,
        cancel_token: CancellationToken,
        remote_node_id: Option<[u8; 32]>,
        stream_semaphore: Arc<Semaphore>,
    ) {
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
                                            let resp_payload = b"unauthorized";
                                            let resp_header = WireHeader::new(
                                                MsgType::StatusResponse as u16,
                                                header.session_seq + 1,
                                                header.epoch_id,
                                                0,
                                                resp_payload.len() as u32,
                                            );
                                            if let Err(e) = write_frame(&mut send, &resp_header, resp_payload).await {
                                                debug!(error = %e, "Failed to write unauthorized response frame");
                                            }
                                            let _ = send.finish();
                                            return;
                                        }

                                        match h.handle(header, payload).await {
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
                        Err(_) => break,
                    }
                }
                uni_res = conn.accept_uni() => {
                    match uni_res {
                        Ok(mut recv) => {
                            let h = handler.clone();
                            let pm = peer_manager.clone();
                            let sem = stream_semaphore.clone();
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
                                        // GossipAnnounce and Heartbeat are STRICTLY accepted from direct F2F friends only!
                                        let is_gossip = header.msg_type == MsgType::GossipAnnounce as u16
                                            || header.msg_type == MsgType::Heartbeat as u16;

                                        if is_gossip && !pm.can_accept_gossip(&remote_addr, remote_node_id.as_ref()).await {
                                            warn!(
                                                remote = %remote_addr,
                                                node_id = ?remote_node_id.map(hex::encode),
                                                msg_type = header.msg_type,
                                                "GOSSIP BARRIER: Dropped gossip from non-F2F connection"
                                            );
                                            return;
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
                                            let res1 = bincode::deserialize::<crate::network::framing::HeartbeatWirePayload>(&payload);
                                            let res2 = bincode::deserialize::<([u8; 32], SocketAddr)>(&payload);

                                            if let Ok(hb) = res1 {
                                                let is_direct = remote_node_id == Some(hb.node_id);
                                                if is_direct && hops > 0 {
                                                    warn!("GOSSIP BARRIER: Hop-spoofing attempt by direct neighbor (hops > 0)");
                                                    return;
                                                }
                                                if !is_direct && hops == 0 {
                                                    warn!("GOSSIP BARRIER: Hop-spoofing attempt by forwarder (hops == 0)");
                                                    return;
                                                }
                                                pm.learn_node_from_gossip(hb.node_id, hb.addr, hops as u8, Some(remote_addr)).await;
                                                pm.clock().record_heartbeat(is_f2f, hb.timestamp_ms);
                                            } else if let Ok((adv_id, adv_addr)) = res2 {
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

                                        if let Err(e) = h.handle_unidirectional(header, payload).await {
                                            debug!(error = %e, "Failed to handle unidirectional frame");
                                        }
                                    }
                                    Err(e) => {
                                        debug!(error = %e, "Failed to read incoming uni-stream frame");
                                    }
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    /// Closes the QUIC endpoint and all active connections.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"node shutdown");
    }
}
