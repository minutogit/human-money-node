use humoco_sim_core::wire::{MsgType, WireHeader};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent QUIC bi-stream handler tasks (DoS/OOM protection).
pub const STREAM_CONCURRENCY_LIMIT: usize = 1024;
/// Maximum number of concurrent QUIC uni-stream handler tasks (DoS/OOM protection).
pub const UNI_STREAM_CONCURRENCY_LIMIT: usize = 1024;
/// Maximum number of concurrent outbound forwarder tasks for Heartbeat gossip.
pub const OUTBOUND_FORWARDER_LIMIT: usize = 256;
/// Maximum number of concurrent outbound forwarder tasks for Fraud/Equivocation gossip (Spec 10 priority).
pub const OUTBOUND_FRAUD_FORWARDER_LIMIT: usize = 256;
/// Default timeout for outbound unidirectional frame transmission (3 seconds).
pub const DEFAULT_UNI_STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Default timeout for outbound bi-directional request/response transactions (5 seconds).
pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Maximum number of concurrent QUIC handshake / connection handler tasks (DoS/OOM protection).
pub const CONNECTION_CONCURRENCY_LIMIT: usize = 256;
/// Spec 11 Freshness window for gossip heartbeats (+/- 60 seconds)
pub const HEARTBEAT_FRESHNESS_WINDOW_MS: u64 = 60_000;
/// Default timeout for incoming RPC request handlers (10 seconds)
pub const DEFAULT_HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Grace period given to handlers on cancellation during shutdown (100 ms)
pub const SHUTDOWN_HANDLER_GRACE: std::time::Duration = std::time::Duration::from_millis(100);
/// Canonical SNI used for P2P QUIC handshakes to prevent DPI firewalls from dropping external packets advertising "localhost".
pub const P2P_QUIC_SNI: &str = "p2p.humoco.internal";
/// Maximum number of 5-minute bucket digests allowed in a single ShardBucketRangeRequest.
/// Serialized bincode response size is 10 + N * 45 bytes: 1024 * 45 + 10 = 46,090 bytes,
/// strictly fitting within the 64 KiB (65,536 bytes) maximum frame payload cap.
pub const MAX_SHARD_BUCKET_RANGE_COUNT: u16 = 1024;

use ed25519_dalek::Signer;
use socket2::{Domain, Protocol, Socket, Type};

use crate::error::NodeError;
use crate::identity::NodeIdentity;
use crate::network::framing::{
    checked_payload_len, read_frame_with_timeout, write_frame,
};
use crate::network::manager::PeerManager;
use crate::network::tls::extract_peer_identity_from_connection;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Handler trait for processing incoming bi-directional and uni-directional requests.
pub trait RequestHandler: Send + Sync + 'static {
    fn gateway_advertisement(&self) -> Option<crate::network::discovery::GatewayAdvertisement> {
        None
    }
    fn signing_checkpoint(
        &self,
    ) -> BoxFuture<Result<Option<crate::network::framing::SigningCheckpoint>, NodeError>> {
        Box::pin(async { Ok(None) })
    }

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
                x if x == MsgType::ShardBucketRangeRequest as u16 => {
                    MsgType::ShardBucketRangeResponse as u16
                }
                x if x == MsgType::EquivocationProof as u16 => MsgType::EquivocationAck as u16,
                _ => MsgType::StatusResponse as u16,
            };
            let resp_header = WireHeader::new(resp_type, header.session_seq, header.epoch_id, 0, 0);
            Ok((resp_header, Vec::new()))
        })
    }
}

/// # Architectural Invariant: A02-01 / Spec 10 Pillar 1 — Network-Aware First-Party Verification & Anti-Framing
///
/// A node is slashed ONLY on irrefutable cryptographic self-proof: two genuine
/// Ed25519 signatures by the accused key within the same network universe (Testnet or Mainnet).
/// Simulator BLAKE3 mocks, hearsay gossip, or third-party claims NEVER trigger a ban. Each pillar enforces:
/// Network-aware strict first-party verifier (A02-01 / S07-11).
///
/// Restricts verification to the specified network domain. Both envelopes must match
/// `expected_network` and pass signature verification under that domain.
///
/// Supported proof types:
/// - ShardEquivocation: both attestations verify under `vk` against the
///   parent_lock-bound payload digest (`compute_attestation_payload_digest`).
///   - Anti-framing: `proof.perpetrator_node_id` MUST equal `vk.to_bytes()`.
///   - Network-awareness: both signatures must belong to the SAME network universe (Testnet or Mainnet).
/// - IngressCounterConflict: both envelopes verify under `vk`, and both
///   `gateway_pubkey` fields as well as `proof.perpetrator_node_id` MUST equal `vk` (framing with foreign packets fails).
pub fn verify_equivocation_first_party_network(
    expected_network: humoco_sim_core::types::NetworkId,
    vk: &ed25519_dalek::VerifyingKey,
    proof: &humoco_sim_core::fraud::FraudProofPayload,
) -> bool {
    let vk_bytes = vk.to_bytes();
    if proof.perpetrator_node_id != vk_bytes {
        return false;
    }

    match proof.proof_pillar {
        humoco_sim_core::fraud::FraudProofPillar::IngressCounterConflict => {
            // Anti-framing: never accept unsecured simulator mocks. Both envelopes
            // must be signed by the accused key itself.
            let a = match humoco_sim_core::fraud::decode_ingress_envelope(&proof.evidence_packet_a)
            {
                Some(e) => e,
                None => return false,
            };
            let b = match humoco_sim_core::fraud::decode_ingress_envelope(&proof.evidence_packet_b)
            {
                Some(e) => e,
                None => return false,
            };
            if a.gateway_pubkey != vk_bytes || b.gateway_pubkey != vk_bytes {
                return false;
            }
            if a.network_id != expected_network || b.network_id != expected_network {
                return false;
            }
            if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&a, expected_network)
                || !humoco_sim_core::fraud::verify_ingress_envelope_signature(&b, expected_network)
            {
                return false;
            }
            proof.verify_network(expected_network)
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

            if a.shard_id != b.shard_id {
                return false;
            }
            let shard = a.shard_id;
            let verify_att = |att: &humoco_sim_core::types::Attestation,
                              provisional: &[u8],
                              final_domain: &[u8]|
             -> bool {
                let sig = ed25519_dalek::Signature::from_bytes(&att.signature);
                let payload = humoco_sim_core::crypto::compute_attestation_payload_digest(
                    &att.parent_lock,
                    &att.lock_id,
                );
                // An original choice remains protected across a provisional to
                // final promotion. Live observations use a separate purpose and
                // cannot verify here. Domain and status must agree.
                [(provisional, 0u8), (final_domain, 1u8)]
                    .into_iter()
                    .any(|(domain, status)| {
                        let digest = humoco_sim_core::crypto::compute_sig_digest(
                            domain, 0, 0, 0, shard, status, &payload,
                        );
                        vk.verify_strict(&digest, &sig).is_ok()
                    })
            };

            // Both signatures must belong to ONE network. Independent existential
            // checks would combine lawful originals from unrelated networks.
            let networks: &[(&[u8], &[u8])] = match expected_network {
                humoco_sim_core::types::NetworkId::Mainnet => &[(
                    humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
                    humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
                )],
                humoco_sim_core::types::NetworkId::Testnet => &[(
                    humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_TESTNET,
                    humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_TESTNET,
                )],
            };

            networks.iter().any(|(provisional, final_domain)| {
                verify_att(&a, provisional, final_domain)
                    && verify_att(&b, provisional, final_domain)
            })
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
    pub clock: Arc<crate::network::NetworkClock>,
    pub tier_controller: Option<Arc<crate::ingress::TierController>>,
    pub is_sync_ready: Arc<std::sync::atomic::AtomicBool>,
    pub readiness_manager: Arc<crate::daemon::ShardReadinessManager>,
    pub network_id: humoco_sim_core::types::NetworkId,
    snapshot_cuts: Arc<crate::storage::db::snapshot::SnapshotCuts>,
    fraud_workers: Arc<Semaphore>,
    gateway_urls: Vec<String>,
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
            clock: Arc::new(crate::network::NetworkClock::new()),
            tier_controller: None,
            is_sync_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            readiness_manager: Arc::new(crate::daemon::ShardReadinessManager::new()),
            snapshot_cuts: Arc::new(crate::storage::db::snapshot::SnapshotCuts::default()),
            fraud_workers: Arc::new(Semaphore::new(4)),
            gateway_urls: Vec::new(),
            network_id: humoco_sim_core::types::NetworkId::default(),
        }
    }

    pub fn with_peer_manager(
        engine: crate::storage::DualTierEngine,
        storage: Arc<crate::storage::RedbStorage>,
        identity: NodeIdentity,
        peer_manager: Arc<crate::network::PeerManager>,
    ) -> Self {
        peer_manager.set_storage(Arc::downgrade(&storage));
        peer_manager.set_engine(&engine);
        peer_manager.set_local_node_pubkey(*identity.node_pubkey());
        let clock = peer_manager.clock().clone();
        Self {
            engine,
            storage,
            identity,
            peer_manager: Some(peer_manager),
            clock,
            tier_controller: None,
            is_sync_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            readiness_manager: Arc::new(crate::daemon::ShardReadinessManager::new()),
            snapshot_cuts: Arc::new(crate::storage::db::snapshot::SnapshotCuts::default()),
            fraud_workers: Arc::new(Semaphore::new(4)),
            gateway_urls: Vec::new(),
            network_id: humoco_sim_core::types::NetworkId::default(),
        }
    }

    pub fn with_clock(mut self, clock: Arc<crate::network::NetworkClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Returns the active P2P network-adjusted time in ms.
    /// Uses peer manager median clock if available, falling back to monotonic NetworkClock.
    pub fn net_time_ms(&self) -> u64 {
        if let Some(pm) = &self.peer_manager {
            pm.net_time_ms()
        } else {
            self.clock.net_time_ms()
        }
    }

    pub fn with_gateway_urls(mut self, urls: Vec<String>) -> Self {
        self.gateway_urls = urls;
        self
    }

    pub fn with_tier_controller(
        mut self,
        tier_controller: Arc<crate::ingress::TierController>,
    ) -> Self {
        self.tier_controller = Some(tier_controller);
        self
    }

    pub fn with_sync_ready(mut self, ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.is_sync_ready = ready;
        self
    }

    pub fn with_readiness_manager(
        mut self,
        manager: Arc<crate::daemon::ShardReadinessManager>,
    ) -> Self {
        self.readiness_manager = manager;
        self
    }

    pub fn with_network_id(mut self, network_id: humoco_sim_core::types::NetworkId) -> Self {
        self.network_id = network_id;
        self
    }

    /// Consolidated handler for both bidirectional and unidirectional incoming EquivocationProof messages.
    ///
    /// # Architectural Invariant: A02-01 & A20-01 (Spec 10, Spec 14, INV-1402)
    /// - Structural and cryptographic production verification: verifies Ed25519 self-proof of the
    ///   perpetrator directly, eliminating simulator fallbacks and illegal fallbacks to the node's own key.
    /// - Network-aware: requires a valid same-network proof (Testnet or Mainnet), rejecting mixed-network
    ///   or forged evidence without mutation.
    /// - Atomic persistence: commits evidence and ban in a single redb transaction before returning success.
    pub async fn handle_incoming_equivocation_proof(
        &self,
        payload: &[u8],
        peer_identity: Option<[u8; 32]>,
    ) -> Result<bool, NodeError> {
        let now_ms = self.net_time_ms();

        let proof = match bincode::deserialize::<humoco_sim_core::fraud::FraudProofPayload>(payload)
        {
            Ok(p) => p,
            Err(e) => {
                warn!("EquivocationProof rejected: deserialize failed: {}", e);
                return Ok(false);
            }
        };

        let offender = proof.perpetrator_node_id;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&offender) else {
            warn!(
                offender = %hex::encode(offender),
                "EquivocationProof rejected: perpetrator_node_id is not a valid Ed25519 key"
            );
            return Ok(false);
        };

        let is_first_party_valid =
            verify_equivocation_first_party_network(self.network_id, &vk, &proof);
        if !is_first_party_valid {
            warn!(
                offender = %hex::encode(offender),
                network_id = ?self.network_id,
                "EquivocationProof rejected: cryptographic Ed25519 signature or network domain verification failed for perpetrator (framing prevented)"
            );
            return Ok(false);
        }

        // Atomic persistence of evidence + ban in redb (A20-01 / INV-1402)
        let evidence_hash = *blake3::hash(payload).as_bytes();
        if let Err(e) = persist_fraud(
            self.fraud_workers.clone(),
            self.storage.clone(),
            evidence_hash,
            payload.to_vec(),
            offender,
            now_ms,
        )
        .await
        {
            warn!(
                offender = %hex::encode(offender),
                error = %e,
                "Failed to commit slashing evidence and ban atomically to redb"
            );
            // Local containment in RAM even if disk persistence fails
            self.engine.ban_node_ram(&offender).await;
            if let Some(pm) = self.peer_manager.as_ref() {
                let _ = pm.ban_node(&offender).await;
            }
            return Err(e);
        }

        // Apply in-memory bans and disconnect peers
        self.engine.ban_node_ram(&offender).await;
        if let Some(pm) = self.peer_manager.as_ref() {
            let affected = pm.ban_node(&offender).await;
            // Phase 10: dedup via LRU seen-set + echo protection —
            // never send the proof back to the immediate sender.
            pm.broadcast_fraud_proof_with_sender(proof, peer_identity);
            info!(
                offender = %hex::encode(offender),
                affected,
                "Slashing: offender banned and peers disconnected"
            );
        } else {
            info!(
                offender = %hex::encode(offender),
                "Slashing: offender banned (no peer_manager)"
            );
        }

        Ok(true)
    }
}

impl RequestHandler for NodeRequestHandler {
    fn gateway_advertisement(&self) -> Option<crate::network::discovery::GatewayAdvertisement> {
        let now = self.peer_manager.as_ref()?.net_time_ms();
        let network = match self.network_id {
            humoco_sim_core::types::NetworkId::Mainnet => 0,
            humoco_sim_core::types::NetworkId::Testnet => 1,
        };
        crate::network::discovery::GatewayAdvertisement::signed(
            &self.identity,
            network,
            self.gateway_urls.clone(),
            now,
        )
    }

    fn signing_checkpoint(
        &self,
    ) -> BoxFuture<Result<Option<crate::network::framing::SigningCheckpoint>, NodeError>> {
        let storage = self.storage.clone();
        let identity = self.identity.clone();
        let network = match self.network_id {
            humoco_sim_core::types::NetworkId::Mainnet => 0,
            humoco_sim_core::types::NetworkId::Testnet => 1,
        };
        Box::pin(async move {
            if !storage.is_signing_history_healthy() {
                return Ok(None);
            }
            let state = tokio::task::spawn_blocking(move || storage.signing_checkpoint())
                .await
                .map_err(|e| NodeError::Daemon(format!("checkpoint worker: {e}")))??;
            Ok(Some(crate::network::framing::SigningCheckpoint::signed(
                &identity, network, state.0, state.1,
            )))
        })
    }

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
        let clock = self.clock.clone();
        let network_id = self.network_id;
        let readiness_manager = self.readiness_manager.clone();
        let snapshot_cuts = self.snapshot_cuts.clone();
        let this = self.clone();
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

            // --- Phase 4: Real slashing on EquivocationProof (Spec 10 Pillar 1, A02-01, A20-01) ---
            if msg_type == MsgType::EquivocationProof as u16 {
                this.handle_incoming_equivocation_proof(&payload, peer_identity)
                    .await?;
                let resp_header = WireHeader::new(
                    MsgType::EquivocationAck as u16,
                    header.session_seq.wrapping_add(1),
                    header.epoch_id,
                    0,
                    0,
                );
                return Ok((resp_header, Vec::new()));
            }
            if msg_type == MsgType::LiveStateRequest as u16 {
                let vote = if payload.len() <= 8192 && peer_identity.is_some() {
                    if let Ok(context) =
                        serde_json::from_slice::<humoco_proto::live::LiveStateContext>(&payload)
                    {
                        crate::api::live::sign_current_state(
                            &engine,
                            &identity,
                            peer_manager.as_ref(),
                            &readiness_manager,
                            network_id,
                            &context,
                        )
                        .await
                    } else {
                        None
                    }
                } else {
                    None
                };
                let (flags, bytes) = match vote.and_then(|v| bincode::serialize(&v).ok()) {
                    Some(bytes) => (0, bytes),
                    None => (humoco_sim_core::wire::FLAG_NOT_READY, Vec::new()),
                };
                return Ok((
                    WireHeader::new(
                        MsgType::LiveStateResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        flags,
                        checked_payload_len(bytes.len())?,
                    ),
                    bytes,
                ));
            }
            if msg_type == MsgType::LockVerifyRequest as u16 {
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| clock.net_time_ms());

                let ncb_eff = if let Some(tc) = &tier_controller {
                    tc.effective_ncb()
                } else {
                    humoco_sim_core::quota::HARD_FLOOR_BASELINE_DAILY
                };
                let write_limit = (5.0 * ncb_eff as f64).round() as u64;

                let wire_payload = match bincode::deserialize::<
                    crate::network::framing::LockWirePayload,
                >(&payload)
                {
                    Ok(p) => p,
                    Err(_) => {
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
                };

                // # Architectural Invariant: Option A KISS Canonical Voucher Shard (Spec 03)
                //
                // The canonical shard of EVERY transaction of a voucher (genesis AND
                // follow-up spends) is derived deterministically from the voucher ID
                // itself via `voucher_shard_id(voucher_id)`. This guarantees that all
                // locks of a voucher route to the same shard without requiring genesis
                // parent lookups on the hot path. Hex-encoded voucher IDs use the
                // first 2 bytes (big-endian); all others fall back to BLAKE3.
                let shard_id = match &wire_payload {
                    crate::network::framing::LockWirePayload::Hmc { req, chain, .. } => {
                        let voucher_id = chain
                            .as_ref()
                            .map(|c| c.layer2_voucher_id.as_str())
                            .unwrap_or(req.layer2_voucher_id.as_str());
                        if let Some(genesis_parent) =
                            engine.get_hmc_voucher_genesis_parent(voucher_id).await
                        {
                            humoco_sim_core::types::canonical_voucher_shard(&genesis_parent)
                        } else if let Some(chain_req) = chain {
                            if let Some(genesis_hop) = chain_req.chain.iter().find(|h| h.is_genesis)
                            {
                                let genesis_tag =
                                    bs58::encode(&genesis_hop.transaction_hash).into_string();
                                let p_bytes = humoco_sim_core::types::genesis_parent_bytes_from_tag(
                                    &genesis_tag,
                                );
                                humoco_sim_core::types::canonical_voucher_shard(&p_bytes)
                            } else if req.is_genesis {
                                let tag = bs58::encode(&req.transaction_hash).into_string();
                                let p_bytes =
                                    humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
                                humoco_sim_core::types::canonical_voucher_shard(&p_bytes)
                            } else {
                                humoco_sim_core::types::voucher_shard_id(voucher_id)
                            }
                        } else if req.is_genesis {
                            let tag = bs58::encode(&req.transaction_hash).into_string();
                            let p_bytes =
                                humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
                            humoco_sim_core::types::canonical_voucher_shard(&p_bytes)
                        } else {
                            humoco_sim_core::types::voucher_shard_id(voucher_id)
                        }
                    }
                };

                // Write authorization is restricted to the canonical Top-20.
                // Local reachability never admits replacement ranks.
                let is_responsible = if let Some(pm) = peer_manager.as_ref() {
                    pm.is_local_committee_member(
                        *identity.node_pubkey(),
                        *identity.hrw_routing_id(),
                        shard_id,
                    )
                    .await
                } else {
                    true
                };
                if !is_responsible {
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
                let envelope_epoch_day = wire_payload.epoch_day();
                let envelope_epoch_seq = wire_payload.epoch_seq();

                // 1. Cheap checks first (Rule 9): stateless declared-rate filter before
                // any asymmetric crypto or state mutation. Over-quota senders are
                // rejected here even with null/invalid signatures.
                let declared_daily_rate =
                    humoco_sim_core::quota::ema_to_daily_rate(declared_write_ema) / 1_000_000;
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

                // 2. Strict null-sender rejection: anonymous writes bypass per-sender
                // quota accounting and first-party fraud attribution. No null sender
                // may proceed past this point.
                if sender_pubkey == [0u8; 32] {
                    warn!("LockVerifyRequest rejected: null sender pubkey (quota-bypass attempt)");
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

                // 3. Sender-timestamp freshness (max 30s drift vs. network time):
                // stale or futuristic envelopes are replay / time-warp attempts and
                // must not consume quota or RAM.
                const MAX_SENDER_CLOCK_DRIFT_MS: u64 = 30_000;
                if timestamp_ms == 0 || timestamp_ms.abs_diff(now_ms) > MAX_SENDER_CLOCK_DRIFT_MS {
                    warn!(
                        timestamp_ms,
                        now_ms,
                        "LockVerifyRequest rejected: sender timestamp outside 30s drift window"
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

                // DEC-061: a fresh gateway envelope cannot renew wallet T0.
                // Evaluate against the admission-time snapshot, before disk waits.
                if let crate::network::framing::LockWirePayload::Hmc {
                    req, chain: None, ..
                } = &wire_payload
                {
                    if !req.is_genesis
                        && (req.created_at_ms == 0
                            || req.created_at_ms.abs_diff(now_ms) > MAX_SENDER_CLOCK_DRIFT_MS)
                    {
                        return Ok((
                            WireHeader::new(
                                MsgType::LockVerifyResponse as u16,
                                header.session_seq.wrapping_add(1),
                                header.epoch_id,
                                humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                                0,
                            ),
                            Vec::new(),
                        ));
                    }
                }

                // Cheap validation: single-genesis chain wrapper and hop voucher identities must match
                if let crate::network::framing::LockWirePayload::Hmc {
                    req,
                    chain: Some(chain_req),
                    ..
                } = &wire_payload
                {
                    if chain_req.chain.len() == 1
                        && chain_req.chain[0].is_genesis
                        && (chain_req.chain[0].layer2_voucher_id != chain_req.layer2_voucher_id
                            || req.layer2_voucher_id != chain_req.layer2_voucher_id)
                    {
                        warn!(
                            wrapper_voucher = %chain_req.layer2_voucher_id,
                            hop_voucher = %chain_req.chain[0].layer2_voucher_id,
                            req_voucher = %req.layer2_voucher_id,
                            "LockVerifyRequest rejected: voucher identity mismatch between chain wrapper and genesis hop"
                        );
                        return Ok((
                            WireHeader::new(
                                MsgType::LockVerifyResponse as u16,
                                header.session_seq.wrapping_add(1),
                                header.epoch_id,
                                humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                                0,
                            ),
                            Vec::new(),
                        ));
                    }
                }

                // 4. Check authenticated QUIC identity matches sender_pubkey
                if let Some(auth_peer) = peer_identity {
                    if sender_pubkey != auth_peer {
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

                // 5. Check if sender is banned
                let is_banned = if engine.is_node_banned(&sender_pubkey).await {
                    true
                } else if let Some(pm) = peer_manager.as_ref() {
                    pm.is_banned(&sender_pubkey).await
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

                // The envelope digest commits to sender's timestamp_ms (fresh within 30s drift window)
                let effective_ts = timestamp_ms;
                let (op_hash, footprint, total_by) = match &wire_payload {
                    crate::network::framing::LockWirePayload::Hmc {
                        req,
                        root_valid_until,
                        chain,
                        ..
                    } => {
                        // A19-01: Authenticate root lifetime before computing signed envelope footprint and recipient reservation.
                        // Wire lifetime cannot undercharge or extend TTL.
                        let auth_root_valid = if req.is_genesis
                            && chain.as_ref().is_none_or(|c| c.chain.len() == 1)
                        {
                            let entry = crate::api::hmc::L2LockEntry::from(req);
                            if entry.deletable_at.is_some() {
                                match crate::storage::db::roots::root_valid_until(&entry) {
                                    Ok(v) => {
                                        if *root_valid_until != v {
                                            warn!(
                                                claimed = *root_valid_until,
                                                authenticated = v,
                                                "LockVerifyRequest rejected: wire root_valid_until mismatch with authenticated root"
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
                                        v
                                    }
                                    Err(_) => {
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
                            } else {
                                *root_valid_until
                            }
                        } else if let Some(chain_req) = chain {
                            if chain_req.chain.is_empty() {
                                let resp_header = WireHeader::new(
                                    MsgType::LockVerifyResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                                    0,
                                );
                                return Ok((resp_header, Vec::new()));
                            }
                            if chain_req.chain[0].is_genesis {
                                let entry = crate::api::hmc::L2LockEntry::from(&chain_req.chain[0]);
                                if entry.deletable_at.is_some() {
                                    match crate::storage::db::roots::root_valid_until(&entry) {
                                        Ok(v) => {
                                            if *root_valid_until != v {
                                                let resp_header = WireHeader::new(
                                                    MsgType::LockVerifyResponse as u16,
                                                    header.session_seq.wrapping_add(1),
                                                    header.epoch_id,
                                                    humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                                                    0,
                                                );
                                                return Ok((resp_header, Vec::new()));
                                            }
                                            v
                                        }
                                        Err(_) => {
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
                                } else {
                                    *root_valid_until
                                }
                            } else {
                                match engine
                                    .get_hmc_voucher_root_valid(&chain_req.layer2_voucher_id)
                                    .await
                                {
                                    Some(v) => {
                                        if *root_valid_until != v {
                                            let resp_header = WireHeader::new(
                                                MsgType::LockVerifyResponse as u16,
                                                header.session_seq.wrapping_add(1),
                                                header.epoch_id,
                                                humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                                                0,
                                            );
                                            return Ok((resp_header, Vec::new()));
                                        }
                                        v
                                    }
                                    None => {
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
                            }
                        } else {
                            match engine
                                .get_hmc_voucher_root_valid(&req.layer2_voucher_id)
                                .await
                            {
                                Some(v) => {
                                    if *root_valid_until != v {
                                        warn!(
                                            claimed = *root_valid_until,
                                            authenticated = v,
                                            "LockVerifyRequest rejected: wire root_valid_until mismatch with authenticated root"
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
                                    v
                                }
                                None => {
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

                        if auth_root_valid <= effective_ts {
                            warn!("LockVerifyRequest rejected: authenticated root is expired");
                            let resp_header = WireHeader::new(
                                MsgType::LockVerifyResponse as u16,
                                header.session_seq.wrapping_add(1),
                                header.epoch_id,
                                humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                                0,
                            );
                            return Ok((resp_header, Vec::new()));
                        }

                        let ttl_s = auth_root_valid.saturating_sub(effective_ts) / 1000;
                        let entry = crate::api::hmc::L2LockEntry::from(req);
                        let base_fp =
                            humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
                        let base_by = humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl_s);
                        let chain_len = chain.as_ref().map(|c| c.chain.len()).unwrap_or(1);
                        (
                            entry.t_id,
                            base_fp.saturating_mul(chain_len as u64),
                            base_by.saturating_mul(chain_len as u64),
                        )
                    }
                };

                // 7. Epoch-bound signature verification and under-reporting check.
                // The envelope digest commits to (epoch_day, epoch_seq), so replay
                // across days or reordering within a day invalidates the signature.
                let curr = humoco_sim_core::fraud::IngressEnvelopeEvidence::new(
                    this.network_id,
                    sender_pubkey,
                    envelope_epoch_day,
                    envelope_epoch_seq,
                    timestamp_ms,
                    declared_write_ema,
                    declared_read_ema,
                    footprint,
                    false,
                    op_hash,
                    sender_signature,
                );

                if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&curr, this.network_id) {
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

                if !readiness_manager.is_shard_ready(shard_id) {
                    readiness_manager.request_sync(shard_id);
                    return Ok((
                        WireHeader::new(
                            MsgType::LockVerifyResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            humoco_sim_core::wire::FLAG_NOT_READY,
                            0,
                        ),
                        Vec::new(),
                    ));
                }
                if let Some(pm) = peer_manager.as_ref() {
                    if let Some(prev) = pm.get_node_write_evidence(&sender_pubkey).await {
                        if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(
                            this.network_id,
                            &prev,
                            &curr,
                        ) {
                            warn!(sender = %hex::encode(sender_pubkey), "CRITICAL FRAUD: under-reporting detected in LockVerifyRequest! Slashing perpetrator.");
                            let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, curr.clone());
                            let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                            let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                            persist_fraud(
                                this.fraud_workers.clone(),
                                storage.clone(),
                                evidence_hash,
                                evidence_bytes,
                                sender_pubkey,
                                now_ms,
                            )
                            .await?;
                            engine.ban_node_ram(&sender_pubkey).await;
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
                    pm.update_node_write_evidence(&sender_pubkey, curr.clone())
                        .await;
                    pm.record_observed_evidence(curr.clone()).await;
                }

                // 8. Reservation-First backpressure (Rule 10): the sender quota MUST be
                // reserved BEFORE any RAM-index or persistence mutation. If the queue
                // is full the request is rejected here and RAM stays untouched.
                // A19-R2: Deduplicate storage-time charging for exact operations already durable
                // within root TTL. Retries of previously committed operations succeed idempotently
                // without exhausting the sender's daily budget.
                let is_exact_retry = match &wire_payload {
                    crate::network::framing::LockWirePayload::Hmc {
                        req,
                        root_valid_until,
                        chain,
                        ..
                    } => {
                        if req.is_genesis && chain.as_ref().is_none_or(|c| c.chain.len() == 1) {
                            let tag = bs58::encode(req.transaction_hash).into_string();
                            let entry = crate::api::hmc::L2LockEntry::from(req);
                            engine
                                .is_hmc_entry_durable(&tag, &entry, *root_valid_until)
                                .await
                        } else if chain.is_none() {
                            let lookup_tag = req.ds_tag.clone().unwrap_or_default();
                            if !lookup_tag.trim().is_empty() {
                                let entry = crate::api::hmc::L2LockEntry::from(req);
                                engine
                                    .is_hmc_entry_durable(&lookup_tag, &entry, *root_valid_until)
                                    .await
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                };

                if let Some(tc) = &tier_controller {
                    if !is_exact_retry {
                        if let Err(e) =
                            tc.evaluate_node_write_quota(&sender_pubkey, total_by, now_ms)
                        {
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

                // 9. Mutation of RAM index and attestation generation.
                // Reservation-First is complete at this point (quota reserved in step 8);
                // only now may RAM/persistence be touched.
                match wire_payload {
                    crate::network::framing::LockWirePayload::Hmc { req, chain, .. } => {
                        let is_single_genesis = req.is_genesis
                            && match &chain {
                                None => true,
                                Some(c) => {
                                    c.chain.len() == 1
                                        && c.chain[0].is_genesis
                                        && c.layer2_voucher_id == req.layer2_voucher_id
                                        && c.chain[0].layer2_voucher_id == c.layer2_voucher_id
                                }
                            };
                        if is_single_genesis
                        {
                            if !crate::api::hmc::verify_l2_lock_signature(&req) {
                                return Ok((
                                    WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        humoco_sim_core::wire::FLAG_SIGNATURE_INVALID,
                                        0,
                                    ),
                                    Vec::new(),
                                ));
                            }
                            let tag = bs58::encode(req.transaction_hash).into_string();
                            let (verdict, _) = engine
                                .ingress_hmc_lock_durable_internal(
                                    tag,
                                    crate::api::hmc::L2LockEntry::from(&req),
                                    crate::storage::IngressOrigin::ClientApi,
                                    Some(now_ms),
                                )
                                .await;
                            let bytes = serde_json::to_vec(&verdict)
                                .map_err(|e| NodeError::Network(e.to_string()))?;
                            return Ok((
                                WireHeader::new(
                                    MsgType::LockVerifyResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    0,
                                    checked_payload_len(bytes.len())?,
                                ),
                                bytes,
                            ));
                        }
                        if let Some(chain_req) = chain {
                            if chain_req.chain.is_empty() {
                                warn!("LockVerifyRequest rejected: empty chain");
                                let resp_header = WireHeader::new(
                                    MsgType::LockVerifyResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    0,
                                    0,
                                );
                                return Ok((resp_header, Vec::new()));
                            }
                            let (verdict, is_new) = engine
                                .ingress_hmc_chain_lock_durable(
                                    chain_req.clone(),
                                    crate::storage::IngressOrigin::ClientApi,
                                    Some(now_ms),
                                    crate::storage::PersistenceServiceClass::Internal,
                                )
                                .await;
                            match verdict {
                                crate::api::hmc::L2Verdict::Conflict { existing_lock } => {
                                    // True double-spend: report colliding lock payload so the
                                    // stateless gateway can return 409 Conflict (INV-0604).
                                    let colliding =
                                        bincode::serialize(&existing_lock).unwrap_or_default();
                                    let payload_len = checked_payload_len(colliding.len())?;
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        humoco_sim_core::wire::FLAG_COLLISION_DETECTED,
                                        payload_len,
                                    );
                                    return Ok((resp_header, colliding));
                                }
                                rejection @ crate::api::hmc::L2Verdict::Rejected { .. } => {
                                    let bytes = serde_json::to_vec(&rejection).map_err(|e| {
                                        NodeError::Network(format!(
                                            "chain rejection serialization: {e}"
                                        ))
                                    })?;
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        if engine.is_signing_healthy() {
                                            humoco_sim_core::wire::FLAG_UNAUTHORIZED
                                        } else {
                                            humoco_sim_core::wire::FLAG_NOT_READY
                                        },
                                        checked_payload_len(bytes.len())?,
                                    );
                                    return Ok((resp_header, bytes));
                                }
                                crate::api::hmc::L2Verdict::Verified {
                                    lock_entry: accepted_lock,
                                } => {
                                    let last_hop = match chain_req.chain.last() {
                                        Some(h) => h,
                                        None => {
                                            return Err(NodeError::Network(
                                                "Empty chain received on wire".into(),
                                            ))
                                        }
                                    };
                                    let lookup_tag = if last_hop.is_genesis {
                                        bs58::encode(&last_hop.transaction_hash).into_string()
                                    } else {
                                        last_hop.ds_tag.clone().unwrap_or_default()
                                    };
                                    let parent_bytes =
                                        *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                                    let requested_status = (header.flags & 0xFF) as u8;
                                    let local_active_count = peer_manager
                                        .as_ref()
                                        .map(|pm| pm.active_nodes_count())
                                        .unwrap_or(1);
                                    let can_be_final =
                                        humoco_sim_core::types::required_quorum(local_active_count)
                                            .1
                                            && peer_manager
                                                .as_ref()
                                                .map(|pm| pm.is_network_stable_ge20_for_24h(now_ms))
                                                .unwrap_or(false);
                                    let final_status =
                                        requested_status.min(if can_be_final { 1 } else { 0 });
                                    let attestation =
                                        crate::api::routes::create_attestation_for_network(
                                            &identity,
                                            accepted_lock.t_id,
                                            parent_bytes,
                                            shard_id,
                                            final_status,
                                            now_ms,
                                            network_id,
                                        );
                                    let candidate =
                                        bincode::serialize(&attestation).unwrap_or_default();
                                    let retained = engine
                                        .persist_original_approval(
                                            lookup_tag.clone(),
                                            accepted_lock,
                                            *identity.node_pubkey(),
                                            candidate,
                                            final_status,
                                            now_ms,
                                            crate::storage::PersistenceServiceClass::Internal,
                                        )
                                        .await;
                                    let resp_bytes = match retained {
                                        Ok(bytes) => bytes,
                                        Err(_) => {
                                            return Ok((
                                                WireHeader::new(
                                                    MsgType::LockVerifyResponse as u16,
                                                    header.session_seq.wrapping_add(1),
                                                    header.epoch_id,
                                                    humoco_sim_core::wire::FLAG_NOT_READY,
                                                    0,
                                                ),
                                                Vec::new(),
                                            ))
                                        }
                                    };
                                    let payload_len = checked_payload_len(resp_bytes.len())?;
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        if is_new {
                                            0
                                        } else {
                                            humoco_sim_core::wire::FLAG_REPLAY
                                        },
                                        payload_len,
                                    );
                                    return Ok((resp_header, resp_bytes));
                                }
                                _ => {
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
                        } else {
                            if !crate::api::hmc::verify_l2_lock_signature(&req) {
                                let resp_header = WireHeader::new(
                                    MsgType::LockVerifyResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    humoco_sim_core::wire::FLAG_SIGNATURE_INVALID,
                                    0,
                                );
                                return Ok((resp_header, Vec::new()));
                            }

                            let lookup_tag = if req.is_genesis {
                                bs58::encode(&req.transaction_hash).into_string()
                            } else {
                                match &req.ds_tag {
                                    Some(tag) if !tag.trim().is_empty() => tag.clone(),
                                    _ => {
                                        let resp_header = WireHeader::new(
                                            MsgType::LockVerifyResponse as u16,
                                            header.session_seq.wrapping_add(1),
                                            header.epoch_id,
                                            0,
                                            0,
                                        );
                                        return Ok((resp_header, Vec::new()));
                                    }
                                }
                            };

                            let entry = crate::api::hmc::L2LockEntry::from(&req);
                            // INV-1202: validate the ingress time window at the shard with
                            // the current network time (never blindly trust gateway time).
                            let (verdict, is_new) = engine
                                .ingress_hmc_lock_durable_internal(
                                    lookup_tag.clone(),
                                    entry.clone(),
                                    crate::storage::IngressOrigin::ClientApi,
                                    Some(now_ms),
                                )
                                .await;

                            match verdict {
                                crate::api::hmc::L2Verdict::Conflict { existing_lock } => {
                                    let colliding =
                                        bincode::serialize(&existing_lock).unwrap_or_default();
                                    let payload_len = checked_payload_len(colliding.len())?;
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        humoco_sim_core::wire::FLAG_COLLISION_DETECTED,
                                        payload_len,
                                    );
                                    return Ok((resp_header, colliding));
                                }
                                rejection @ crate::api::hmc::L2Verdict::Rejected { .. } => {
                                    let bytes = serde_json::to_vec(&rejection).map_err(|e| {
                                        NodeError::Network(format!(
                                            "chain rejection serialization: {e}"
                                        ))
                                    })?;
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        if engine.is_signing_healthy() {
                                            humoco_sim_core::wire::FLAG_UNAUTHORIZED
                                        } else {
                                            humoco_sim_core::wire::FLAG_NOT_READY
                                        },
                                        checked_payload_len(bytes.len())?,
                                    );
                                    return Ok((resp_header, bytes));
                                }
                                crate::api::hmc::L2Verdict::Verified {
                                    lock_entry: accepted_lock,
                                } => {
                                    let parent_bytes =
                                        *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                                    let requested_status = (header.flags & 0xFF) as u8;
                                    let local_active_count = peer_manager
                                        .as_ref()
                                        .map(|pm| pm.active_nodes_count())
                                        .unwrap_or(1);
                                    let can_be_final =
                                        humoco_sim_core::types::required_quorum(local_active_count)
                                            .1
                                            && peer_manager
                                                .as_ref()
                                                .map(|pm| pm.is_network_stable_ge20_for_24h(now_ms))
                                                .unwrap_or(false);
                                    let final_status =
                                        requested_status.min(if can_be_final { 1 } else { 0 });
                                    let attestation =
                                        crate::api::routes::create_attestation_for_network(
                                            &identity,
                                            accepted_lock.t_id,
                                            parent_bytes,
                                            shard_id,
                                            final_status,
                                            now_ms,
                                            network_id,
                                        );
                                    let candidate =
                                        bincode::serialize(&attestation).unwrap_or_default();
                                    let retained = engine
                                        .persist_original_approval(
                                            lookup_tag.clone(),
                                            accepted_lock,
                                            *identity.node_pubkey(),
                                            candidate,
                                            final_status,
                                            now_ms,
                                            crate::storage::PersistenceServiceClass::Internal,
                                        )
                                        .await;
                                    let resp_bytes = match retained {
                                        Ok(bytes) => bytes,
                                        Err(_) => {
                                            return Ok((
                                                WireHeader::new(
                                                    MsgType::LockVerifyResponse as u16,
                                                    header.session_seq.wrapping_add(1),
                                                    header.epoch_id,
                                                    humoco_sim_core::wire::FLAG_NOT_READY,
                                                    0,
                                                ),
                                                Vec::new(),
                                            ))
                                        }
                                    };
                                    let payload_len = checked_payload_len(resp_bytes.len())?;
                                    let resp_header = WireHeader::new(
                                        MsgType::LockVerifyResponse as u16,
                                        header.session_seq.wrapping_add(1),
                                        header.epoch_id,
                                        if is_new {
                                            0
                                        } else {
                                            humoco_sim_core::wire::FLAG_REPLAY
                                        },
                                        payload_len,
                                    );
                                    return Ok((resp_header, resp_bytes));
                                }
                                _ => {
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
                        }
                    }
                }
            } else if msg_type == MsgType::StatusQuery as u16 {
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| clock.net_time_ms());

                let ncb_read_eff = if let Some(tc) = &tier_controller {
                    tc.effective_read_ncb()
                } else {
                    humoco_sim_core::quota::HARD_FLOOR_READ_BASELINE_DAILY
                };
                let read_limit = (5.0 * ncb_read_eff as f64).round() as u64;

                let (
                    lock_id,
                    parent_lock,
                    shard_id,
                    declared_write_ema,
                    declared_read_ema,
                    raw_sender_pubkey,
                    timestamp_ms,
                    sender_signature,
                ) = if let Ok(sq) =
                    bincode::deserialize::<crate::network::framing::StatusQueryPayload>(&payload)
                {
                    (
                        sq.lock_id,
                        sq.parent_lock,
                        sq.shard_id,
                        sq.declared_write_ema_micro_bj,
                        sq.current_read_ema_credits,
                        sq.sender_pubkey,
                        sq.timestamp_ms,
                        sq.sender_signature,
                    )
                } else {
                    let resp_header = WireHeader::new(
                        MsgType::StatusResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                };

                // 1. Cheap check: declared read rate vs 5x whale brake limit
                let declared_read_rate =
                    humoco_sim_core::quota::ema_to_daily_rate(declared_read_ema);
                if declared_read_rate > read_limit {
                    warn!(
                        declared_read_rate,
                        read_limit,
                        "StatusQuery rejected: declared read load exceeds 5.0 * ncb_read_eff"
                    );
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
                    if raw_sender_pubkey != auth_peer {
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
                let sender_pubkey = raw_sender_pubkey;

                // 3. Every current query requires its own authenticated envelope.
                {
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

                    let curr = humoco_sim_core::fraud::IngressEnvelopeEvidence::new(
                        this.network_id,
                        sender_pubkey,
                        0,
                        0,
                        timestamp_ms,
                        declared_write_ema,
                        declared_read_ema,
                        0,
                        true,
                        lock_id,
                        sender_signature,
                    );

                    if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&curr, this.network_id) {
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
                            if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(
                                this.network_id,
                                &prev,
                                &curr,
                            ) {
                                warn!(sender = %hex::encode(sender_pubkey), "CRITICAL FRAUD: read under-reporting detected in StatusQuery! Slashing perpetrator.");
                                let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, curr.clone());
                                let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                persist_fraud(
                                    this.fraud_workers.clone(),
                                    storage.clone(),
                                    evidence_hash,
                                    evidence_bytes,
                                    sender_pubkey,
                                    now_ms,
                                )
                                .await?;
                                engine.ban_node_ram(&sender_pubkey).await;
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
                        pm.update_node_read_evidence(&sender_pubkey, curr.clone())
                            .await;
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
                        if let Err(e) = tc.evaluate_node_read_quota(&sender_pubkey, 1, now_ms) {
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

                // Diagnostic observations never create original approvals or live votes.
                // INV-0302: HMC shard matching uses the canonical genesis anchor when
                // known; tag-only queries (lock_id == [0;32], INV-0310 gateway
                // fallback) return the full L2LockEntry so a stateless gateway can
                // answer UnknownVoucher from 1 deterministic Top-20 node.
                let (matching_and_valid, tag_only_entry, tag_only_root) = {
                    let mut is_match = false;
                    let mut tag_entry: Option<crate::api::hmc::L2LockEntry> = None;
                    let mut tag_root: Option<u64> = None;

                    // Check HMC lock in HMC RAM
                    let hmc = engine.hmc_ram.read().await;
                    // Tag-only gateway fallback: lock_id zero means "any lock on
                    // this parent tag". Resolve to full entry below.
                    let is_tag_only = lock_id == [0u8; 32];
                    for (lookup_tag, entry) in &hmc.locks {
                        let tag_hash = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                        let parent_matches = tag_hash == parent_lock;
                        if !parent_matches {
                            continue;
                        }
                        if !is_tag_only && entry.t_id != lock_id {
                            continue;
                        }
                        // Canonical shard check (INV-0302): prefer genesis anchor.
                        let shard_ok = if let Some(genesis_parent) =
                            hmc.get_voucher_genesis_parent(&entry.layer2_voucher_id)
                        {
                            shard_id
                                == humoco_sim_core::types::canonical_voucher_shard(&genesis_parent)
                        } else {
                            let v_hash =
                                *blake3::hash(entry.layer2_voucher_id.as_bytes()).as_bytes();
                            let v_shard = u16::from_be_bytes([v_hash[0], v_hash[1]]);
                            let p_shard = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
                            shard_id == v_shard || shard_id == p_shard
                        };
                        let committed_root = hmc
                            .get_voucher_root_valid(&entry.layer2_voucher_id)
                            .filter(|&root| {
                                root > now_ms && hmc.is_entry_durable(lookup_tag, entry, root)
                            });

                        if shard_ok
                            && is_tag_only
                            && (committed_root.is_none()
                                || !engine.is_signing_healthy()
                                || !readiness_manager.is_shard_ready(shard_id))
                        {
                            return Ok((
                                WireHeader::new(
                                    MsgType::StatusResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    humoco_sim_core::wire::FLAG_NOT_READY,
                                    0,
                                ),
                                Vec::new(),
                            ));
                        }
                        let valid = entry
                            .deletable_at
                            .as_deref()
                            .and_then(|s| crate::storage::db::roots::parse_deletable_at_ms(s).ok())
                            .map(|del| del >= now_ms)
                            .unwrap_or(true);
                        if shard_ok && valid {
                            if is_tag_only {
                                tag_entry = Some(entry.clone());
                                tag_root = committed_root;
                            }
                            is_match = true;
                            break;
                        }
                    }
                    (is_match, tag_entry, tag_root)
                };

                // Tag-only fallback returns the full entry so the gateway can
                // build a diagnostic verdict with the existing sender signature.
                // It is neither a node original approval nor a current-state proof.
                if let Some(entry) = tag_only_entry {
                    if (header.flags & crate::network::framing::FLAG_AUTHENTICATED_DISCOVERY) != 0 {
                        let Some(root_valid_until) = tag_only_root else {
                            return Ok((
                                WireHeader::new(
                                    MsgType::StatusResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    humoco_sim_core::wire::FLAG_NOT_READY,
                                    0,
                                ),
                                Vec::new(),
                            ));
                        };
                        let entry_bytes = serde_json::to_vec(&entry)
                            .map_err(|e| NodeError::Network(e.to_string()))?;
                        let state_digest = *blake3::hash(&entry_bytes).as_bytes();
                        let network_byte = match network_id {
                            humoco_sim_core::types::NetworkId::Mainnet => 0,
                            humoco_sim_core::types::NetworkId::Testnet => 1,
                        };
                        let discovery_digest =
                            crate::network::framing::compute_slot_discovery_digest(
                                network_byte,
                                shard_id,
                                header.session_seq,
                                &parent_lock,
                                &entry.t_id,
                                &state_digest,
                                root_valid_until,
                                identity.node_pubkey(),
                            );
                        let custodian_signature =
                            identity.signing_key().sign(&discovery_digest).to_bytes();
                        let discovery = crate::network::framing::AuthenticatedSlotDiscovery {
                            entry,
                            root_valid_until,
                            custodian_pubkey: *identity.node_pubkey(),
                            custodian_signature,
                        };
                        let resp_bytes = serde_json::to_vec(&discovery)
                            .map_err(|e| NodeError::Network(e.to_string()))?;
                        if resp_bytes.len()
                            > crate::network::framing::MAX_AUTHENTICATED_DISCOVERY_BYTES
                        {
                            return Ok((
                                WireHeader::new(
                                    MsgType::StatusResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    header.epoch_id,
                                    humoco_sim_core::wire::FLAG_NOT_READY,
                                    0,
                                ),
                                Vec::new(),
                            ));
                        }
                        let payload_len = checked_payload_len(resp_bytes.len())?;
                        let resp_header = WireHeader::new(
                            MsgType::StatusResponse as u16,
                            header.session_seq.wrapping_add(1),
                            header.epoch_id,
                            crate::network::framing::FLAG_AUTHENTICATED_DISCOVERY,
                            payload_len,
                        );
                        return Ok((resp_header, resp_bytes));
                    }

                    // JSON preserves omitted optional DTO fields; positional
                    // bincode cannot round-trip skip_serializing_if fields.
                    let resp_bytes = serde_json::to_vec(&entry)
                        .map_err(|e| NodeError::Network(e.to_string()))?;
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

                if matching_and_valid {
                    let observation = crate::network::framing::StatusObservation {
                        version: 1,
                        lock_id,
                        parent_lock,
                        shard_id,
                    };
                    let resp_bytes = bincode::serialize(&observation)
                        .map_err(|e| NodeError::Network(e.to_string()))?;
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
                let resp_header = WireHeader::new(
                    MsgType::StatusResponse as u16,
                    header.session_seq.wrapping_add(1),
                    header.epoch_id,
                    0,
                    0,
                );
                return Ok((resp_header, Vec::new()));
            } else if msg_type == MsgType::ShardDigestRequest as u16 {
                // Versioned cold recovery fence shares the existing shard RPC.
                // Only a current authenticated committee member may pause this shard.
                if payload.len() != 2 {
                    if payload.len() != 20 || payload[0] != 1 || payload[1] > 1 {
                        return Err(NodeError::Network("invalid frozen-shard request".into()));
                    }
                    let shard = u16::from_le_bytes([payload[2], payload[3]]);
                    let token: [u8; 16] = payload[4..20]
                        .try_into()
                        .map_err(|_| NodeError::Network("invalid fence token".into()))?;
                    let owner = peer_identity.ok_or_else(|| {
                        NodeError::Network("source fence requires authenticated peer".into())
                    })?;
                    if payload[1] == 1 {
                        if !engine.release_source_shard(shard, owner, token) {
                            return Err(NodeError::Network("foreign source lease".into()));
                        }
                        return Ok((
                            WireHeader::new(
                                MsgType::ShardDigestResponse as u16,
                                header.session_seq.wrapping_add(1),
                                0,
                                0,
                                0,
                            ),
                            Vec::new(),
                        ));
                    }
                    let manager = peer_manager.as_ref().ok_or_else(|| {
                        NodeError::Network("source fence lacks mesh authority".into())
                    })?;
                    let (committee, _, _) = manager
                        .shard_committee(*identity.node_pubkey(), *identity.hrw_routing_id(), shard)
                        .await;
                    if !readiness_manager.is_shard_ready(shard)
                        || !engine.is_signing_healthy()
                        || !committee.iter().any(|member| member.node_pubkey == owner)
                        || !committee
                            .iter()
                            .any(|member| member.node_pubkey == *identity.node_pubkey())
                    {
                        return Ok((
                            WireHeader::new(
                                MsgType::ShardDigestResponse as u16,
                                header.session_seq.wrapping_add(1),
                                0,
                                humoco_sim_core::wire::FLAG_NOT_READY,
                                0,
                            ),
                            Vec::new(),
                        ));
                    }
                    let token = match engine.freeze_source_shard(shard, owner).await {
                        Ok(token) => token,
                        Err(error) => {
                            debug!(shard,error=%error,"Cold source fence unavailable");
                            return Ok((
                                WireHeader::new(
                                    MsgType::ShardDigestResponse as u16,
                                    header.session_seq.wrapping_add(1),
                                    0,
                                    humoco_sim_core::wire::FLAG_NOT_READY,
                                    0,
                                ),
                                Vec::new(),
                            ));
                        }
                    };
                    let now = manager.net_time_ms();
                    let db = storage.clone();
                    let digest_result = engine
                        .recovery_work
                        .spawn_blocking(move || {
                            let (digest, count) = db.committed_shard_digest(shard, now)?;
                            let support = db.inherited_support_digest(shard, now)?;
                            Ok::<_, crate::storage::StorageError>((digest, count, support))
                        })
                        .await
                        .map_err(|e| NodeError::Network(format!("frozen digest worker: {e}")))?;
                    let (digest, _, support_digest) = match digest_result {
                        Ok(value) => value,
                        Err(error) => {
                            engine.release_source_shard(shard, owner, token);
                            return Err(error.into());
                        }
                    };
                    if !engine.is_signing_healthy()
                        || !readiness_manager.is_shard_ready(shard)
                        || !engine.source_shard_lease_valid(shard, owner, token)
                    {
                        engine.release_source_shard(shard, owner, token);
                        return Ok((
                            WireHeader::new(
                                MsgType::ShardDigestResponse as u16,
                                header.session_seq.wrapping_add(1),
                                0,
                                humoco_sim_core::wire::FLAG_NOT_READY,
                                0,
                            ),
                            Vec::new(),
                        ));
                    }
                    let mut reply = crate::network::framing::FrozenShardReply {
                        version: 2,
                        token,
                        digest,
                        lease_ms: 25_000,
                        support_digest,
                        signature: Vec::new(),
                    };
                    use ed25519_dalek::Signer;
                    reply.signature = identity
                        .signing_key()
                        .sign(&reply.signing_digest(
                            network_id,
                            shard,
                            identity.node_pubkey(),
                            &owner,
                        ))
                        .to_bytes()
                        .to_vec();
                    let bytes = bincode::serialize(&reply)
                        .map_err(|e| NodeError::Network(format!("frozen reply: {e}")))?;
                    return Ok((
                        WireHeader::new(
                            MsgType::ShardDigestResponse as u16,
                            header.session_seq.wrapping_add(1),
                            0,
                            0,
                            checked_payload_len(bytes.len())?,
                        ),
                        bytes,
                    ));
                }
                let shard_id = if payload.len() >= 2 {
                    u16::from_le_bytes([payload[0], payload[1]])
                } else {
                    0
                };
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| clock.net_time_ms());
                // DEC-057 / F06: Storage read errors must never default to an empty witness.
                if !engine.is_signing_healthy() {
                    let resp_header = WireHeader::new(
                        MsgType::ShardDigestResponse as u16,
                        header.session_seq.wrapping_add(1),
                        header.epoch_id,
                        humoco_sim_core::wire::FLAG_NOT_READY,
                        0,
                    );
                    return Ok((resp_header, Vec::new()));
                }
                let db = storage.clone();
                let (digest, lock_count) = engine
                    .recovery_work
                    .spawn_blocking(move || db.committed_shard_digest(shard_id, now_ms))
                    .await
                    .map_err(|e| NodeError::Network(format!("digest worker: {e}")))??;
                if let Some(pm) = peer_manager.as_ref() {
                    pm.register_active_shard(shard_id).await;
                }
                let resp_bytes = bincode::serialize(&(digest, lock_count)).unwrap_or_default();
                let payload_len = checked_payload_len(resp_bytes.len())?;
                let is_ready = readiness_manager.is_shard_ready(shard_id);
                let flags = if is_ready {
                    0
                } else {
                    humoco_sim_core::wire::FLAG_NOT_READY
                };
                let resp_header = WireHeader::new(
                    MsgType::ShardDigestResponse as u16,
                    header.session_seq.wrapping_add(1),
                    header.epoch_id,
                    flags,
                    payload_len,
                );
                return Ok((resp_header, resp_bytes));
            } else if msg_type == MsgType::ShardBucketRangeRequest as u16 {
                let req: humoco_sim_core::types::ShardBucketRangeRequest =
                    bincode::deserialize(&payload).map_err(|e| {
                        NodeError::Network(format!("malformed ShardBucketRangeRequest: {e}"))
                    })?;

                if req.bucket_count == 0 {
                    return Err(NodeError::Network(
                        "ShardBucketRangeRequest bucket_count must be > 0".into(),
                    ));
                }
                if req.bucket_count > MAX_SHARD_BUCKET_RANGE_COUNT {
                    return Err(NodeError::Network(format!(
                        "ShardBucketRangeRequest bucket_count {} exceeds maximum limit {}",
                        req.bucket_count, MAX_SHARD_BUCKET_RANGE_COUNT
                    )));
                }
                let end_bucket = req
                    .start_bucket
                    .checked_add(req.bucket_count as u64)
                    .ok_or_else(|| {
                        NodeError::Network(
                            "ShardBucketRangeRequest start_bucket + bucket_count overflows u64"
                                .into(),
                        )
                    })?;

                let shard_id = req.shard_id;
                let start_bucket = req.start_bucket;
                let bucket_count = req.bucket_count as usize;
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| clock.net_time_ms());
                let db = storage.clone();

                let (resp_bytes, payload_len) = tokio::task::spawn_blocking(move || {
                    let locks = db.committed_shard_records(shard_id, now_ms).map_err(|e| {
                        NodeError::Network(format!("committed buckets unavailable: {e}"))
                    })?;

                    // Single O(N) partitioning pass for requested bucket range
                    let mut partitioned: std::collections::HashMap<
                        u64,
                        Vec<crate::storage::db::projection::CommittedShardRecord>,
                    > = std::collections::HashMap::with_capacity(bucket_count.min(locks.len()));
                    for lock in locks {
                        let b_id =
                            humoco_sim_core::types::timestamp_to_bucket_id(lock.created_at_ms);
                        if b_id >= start_bucket && b_id < end_bucket {
                            partitioned.entry(b_id).or_default().push(lock);
                        }
                    }

                    let mut buckets = Vec::with_capacity(bucket_count);
                    for b_id in start_bucket..end_bucket {
                        let (digest, count) =
                            if let Some(mut bucket_locks) = partitioned.remove(&b_id) {
                                bucket_locks.sort_by(|a, b| {
                                    a.parent_lock
                                        .cmp(&b.parent_lock)
                                        .then_with(|| a.id.cmp(&b.id))
                                });
                                let mut hasher = blake3::Hasher::new();
                                let tag = b"HUMOCO_V1_BUCKET_DIGEST";
                                hasher.update(&[tag.len() as u8]);
                                hasher.update(tag);
                                hasher.update(&shard_id.to_le_bytes());
                                hasher.update(&b_id.to_le_bytes());
                                hasher.update(&(bucket_locks.len() as u32).to_le_bytes());
                                for lock in &bucket_locks {
                                    hasher.update(&lock.parent_lock);
                                    hasher.update(&lock.receiver_pub);
                                    hasher.update(&lock.nonce);
                                    hasher.update(&lock.id);
                                }
                                (*hasher.finalize().as_bytes(), bucket_locks.len() as u32)
                            } else {
                                let mut hasher = blake3::Hasher::new();
                                let tag = b"HUMOCO_V1_BUCKET_DIGEST";
                                hasher.update(&[tag.len() as u8]);
                                hasher.update(tag);
                                hasher.update(&shard_id.to_le_bytes());
                                hasher.update(&b_id.to_le_bytes());
                                hasher.update(&0u32.to_le_bytes());
                                (*hasher.finalize().as_bytes(), 0u32)
                            };
                        let is_sealed = humoco_sim_core::types::is_bucket_sealed(b_id, now_ms);
                        buckets.push(humoco_sim_core::types::ShardBucketDigest {
                            bucket_id: b_id,
                            digest,
                            lock_count: count,
                            is_sealed,
                        });
                    }

                    let resp =
                        humoco_sim_core::types::ShardBucketRangeResponse { shard_id, buckets };
                    let resp_bytes = bincode::serialize(&resp)
                        .map_err(|e| NodeError::Network(format!("serialization failed: {e}")))?;
                    let payload_len = checked_payload_len(resp_bytes.len())?;
                    Ok::<_, NodeError>((resp_bytes, payload_len))
                })
                .await
                .map_err(|e| NodeError::Network(format!("bucket worker: {e}")))??;

                let resp_header = WireHeader::new(
                    MsgType::ShardBucketRangeResponse as u16,
                    header.session_seq.wrapping_add(1),
                    header.epoch_id,
                    0,
                    payload_len,
                );
                return Ok((resp_header, resp_bytes));
            } else if msg_type == MsgType::ActiveSyncRequest as u16 {
                let req = crate::network::framing::ActiveSyncRequest::from_bytes(&payload)
                    .map_err(|e| NodeError::Network(format!("invalid sync request: {e}")))?;
                let owner = peer_identity.ok_or_else(|| {
                    NodeError::Network("sync requires authenticated identity".into())
                })?;
                let page =
                    tokio::task::spawn_blocking(move || snapshot_cuts.page(&storage, req, owner))
                        .await
                        .map_err(|e| NodeError::Network(format!("snapshot worker: {e}")))??;
                let serialized = page
                    .to_bytes()
                    .map_err(|e| NodeError::Network(format!("snapshot serialization: {e}")))?;
                let response = WireHeader::new(
                    MsgType::ActiveSyncDone as u16,
                    header.session_seq.wrapping_add(1),
                    header.epoch_id,
                    0,
                    checked_payload_len(serialized.len())?,
                );
                return Ok((response, serialized));
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
        let clock = self.clock.clone();
        let identity = self.identity.clone();
        let readiness = self.readiness_manager.clone();
        let network = match self.network_id {
            humoco_sim_core::types::NetworkId::Mainnet => 0,
            humoco_sim_core::types::NetworkId::Testnet => 1,
        };
        let this = self.clone();
        Box::pin(async move {
            if header.msg_type == MsgType::HeartbeatAck as u16 {
                if (header.flags & humoco_sim_core::wire::FLAG_POW_OUTDATED) != 0 {
                    if let Some(pm) = peer_manager.as_ref() {
                        let is_f2f = match sender {
                            Some(ref nid) => pm.is_f2f_friend(nid).await,
                            None => false,
                        };
                        if is_f2f {
                            pm.set_ticket_outdated(true);
                            warn!("Received HeartbeatAck with FLAG_POW_OUTDATED from authenticated direct F2F friend: shard ticket is outdated");
                        } else {
                            warn!("Rejected HeartbeatAck with FLAG_POW_OUTDATED from unauthenticated or non-F2F peer");
                        }
                    }
                }
                return Ok(());
            }
            if header.msg_type == MsgType::EquivocationProof as u16 {
                let _ = this
                    .handle_incoming_equivocation_proof(&payload, sender)
                    .await;
                return Ok(());
            }
            if header.msg_type == MsgType::Heartbeat as u16 {
                let now_ms = peer_manager
                    .as_ref()
                    .map(|pm| pm.net_time_ms())
                    .unwrap_or_else(|| clock.net_time_ms());
                if let Ok(hb) = crate::network::framing::HeartbeatWirePayload::from_bytes(&payload)
                {
                    if !hb.verify_origin_signature(this.network_id) {
                        return Ok(());
                    }
                    if let (Some(pm), Some(advertisement)) =
                        (&peer_manager, &hb.gateway_advertisement)
                    {
                        pm.observe_gateway_advertisement(
                            advertisement.clone(),
                            &hb.node_id,
                            network,
                        )
                        .await;
                    }

                    if let Some(checkpoint) = &hb.signing_checkpoint {
                        if checkpoint.verify(identity.node_pubkey(), network) {
                            let db = storage.clone();
                            let checkpoint = checkpoint.clone();
                            let corrupt = tokio::task::spawn_blocking(move || {
                                db.observe_verified_own_checkpoint(
                                    checkpoint.generation,
                                    checkpoint.fingerprint,
                                )
                            })
                            .await
                            .map_err(|e| {
                                NodeError::Daemon(format!("checkpoint evidence worker: {e}"))
                            })??;
                            if corrupt {
                                readiness.set_storage_healthy(false);
                                engine
                                    .stats
                                    .signing_failed
                                    .store(true, std::sync::atomic::Ordering::Release);
                                return Ok(());
                            }
                        }
                    }

                    if hb.signature != [0u8; 64] {
                        let announcement_hash = hb.compute_announcement_hash(this.network_id);
                        let candidate_ev = humoco_sim_core::fraud::IngressEnvelopeEvidence::new(
                            this.network_id,
                            hb.node_id,
                            0,
                            0,
                            hb.timestamp_ms,
                            hb.declared_write_ema_micro_bj,
                            hb.declared_read_ema_credits,
                            0,
                            false,
                            announcement_hash,
                            hb.signature,
                        );
                        if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&candidate_ev, this.network_id)
                        {
                            warn!(node = %hex::encode(hb.node_id), "Heartbeat rejected: invalid signature");
                            return Ok(());
                        }
                        let ev_write = candidate_ev;

                        if let Some(pm) = peer_manager.as_ref() {
                            if let Some(prev) = pm.get_node_write_evidence(&hb.node_id).await {
                                if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(
                                    this.network_id,
                                    &prev,
                                    &ev_write,
                                ) {
                                    warn!(node = %hex::encode(hb.node_id), "CRITICAL FRAUD: under-reporting detected in Heartbeat! Slashing perpetrator.");
                                    let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, ev_write.clone());
                                    let evidence_bytes =
                                        bincode::serialize(&proof).unwrap_or_default();
                                    let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                    persist_fraud(
                                        this.fraud_workers.clone(),
                                        storage.clone(),
                                        evidence_hash,
                                        evidence_bytes,
                                        hb.node_id,
                                        now_ms,
                                    )
                                    .await?;
                                    engine.ban_node_ram(&hb.node_id).await;
                                    pm.ban_node(&hb.node_id).await;
                                    pm.broadcast_fraud_proof_with_sender(proof, sender);
                                    return Ok(());
                                }
                            }
                            pm.update_node_write_evidence(&hb.node_id, ev_write).await;

                            let ev_read = humoco_sim_core::fraud::IngressEnvelopeEvidence::new(
                                this.network_id,
                                hb.node_id,
                                0,
                                0,
                                hb.timestamp_ms,
                                hb.declared_write_ema_micro_bj,
                                hb.declared_read_ema_credits,
                                0,
                                true,
                                [0u8; 32],
                                hb.signature,
                            );
                            if let Some(prev) = pm.get_node_read_evidence(&hb.node_id).await {
                                if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(
                                    this.network_id,
                                    &prev,
                                    &ev_read,
                                ) {
                                    warn!(node = %hex::encode(hb.node_id), "CRITICAL FRAUD: read under-reporting detected in Heartbeat! Slashing perpetrator.");
                                    let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, ev_read.clone());
                                    let evidence_bytes =
                                        bincode::serialize(&proof).unwrap_or_default();
                                    let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                    persist_fraud(
                                        this.fraud_workers.clone(),
                                        storage.clone(),
                                        evidence_hash,
                                        evidence_bytes,
                                        hb.node_id,
                                        now_ms,
                                    )
                                    .await?;
                                    engine.ban_node_ram(&hb.node_id).await;
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
                            if !humoco_sim_core::fraud::verify_ingress_envelope_signature(&ev, this.network_id) {
                                warn!(gateway = %hex::encode(ev.gateway_pubkey), "Piggybacked evidence ignored: invalid signature");
                                continue;
                            }
                            let gw_pub = ev.gateway_pubkey;

                            if ev.is_read {
                                if let Some(prev) = pm.get_node_read_evidence(&gw_pub).await {
                                    if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(
                                        this.network_id,
                                        &prev,
                                        &ev,
                                    ) {
                                        warn!(gateway = %hex::encode(gw_pub), "CRITICAL FRAUD: read under-reporting detected from piggyback observation! Slashing perpetrator.");
                                        let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, ev.clone());
                                        let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                        let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                        persist_fraud(this.fraud_workers.clone(), storage.clone(), evidence_hash, evidence_bytes, gw_pub, now_ms).await?;
                                        engine.ban_node_ram(&gw_pub).await;
                                        pm.ban_node(&gw_pub).await;
                                        pm.broadcast_fraud_proof_with_sender(proof, sender);
                                        continue;
                                    }
                                    let is_newer = ev.timestamp_ms > prev.timestamp_ms;
                                    let is_higher = ev.declared_read_ema_credits
                                        > prev.declared_read_ema_credits;
                                    if is_newer || is_higher {
                                        pm.update_node_read_evidence(&gw_pub, ev).await;
                                    }
                                } else {
                                    pm.update_node_read_evidence(&gw_pub, ev).await;
                                }
                            } else {
                                if let Some(prev) = pm.get_node_write_evidence(&gw_pub).await {
                                    if humoco_sim_core::fraud::FraudProofPayload::check_ingress_conflict(
                                        this.network_id,
                                        &prev,
                                        &ev,
                                    ) {
                                        warn!(gateway = %hex::encode(gw_pub), "CRITICAL FRAUD: write under-reporting detected from piggyback observation! Slashing perpetrator.");
                                        let proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(prev, ev.clone());
                                        let evidence_bytes = bincode::serialize(&proof).unwrap_or_default();
                                        let evidence_hash = *blake3::hash(&evidence_bytes).as_bytes();
                                        persist_fraud(this.fraud_workers.clone(), storage.clone(), evidence_hash, evidence_bytes, gw_pub, now_ms).await?;
                                        engine.ban_node_ram(&gw_pub).await;
                                        pm.ban_node(&gw_pub).await;
                                        pm.broadcast_fraud_proof_with_sender(proof, sender);
                                        continue;
                                    }
                                    let is_newer = ev.timestamp_ms > prev.timestamp_ms;
                                    let is_higher = ev.declared_write_ema_micro_bj
                                        > prev.declared_write_ema_micro_bj;
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
    network_id: humoco_sim_core::types::NetworkId,
    identity: NodeIdentity,
    shared_identity: Option<Arc<parking_lot::RwLock<NodeIdentity>>>,
    peer_manager: Arc<PeerManager>,
    handler: Arc<dyn RequestHandler>,
    cancel_token: CancellationToken,
    tasks: tokio_util::task::TaskTracker,
    stream_semaphore: Arc<Semaphore>,
    uni_stream_semaphore: Arc<Semaphore>,
    sync_streams: Arc<Semaphore>,
    shard_streams: Arc<Semaphore>,
    connection_semaphore: Arc<Semaphore>,
    shard_pool: crate::network::pool::ShardConnectionPool,
    is_sync_ready: Arc<std::sync::atomic::AtomicBool>,
    outbound_forwarder_semaphore: Arc<Semaphore>,
    fraud_forwarder_semaphore: Arc<Semaphore>,
    handler_timeout: Arc<std::sync::atomic::AtomicU64>,
    stream_read_timeout: Arc<std::sync::atomic::AtomicU64>,
}

async fn persist_fraud(
    pool: Arc<Semaphore>,
    storage: Arc<crate::storage::RedbStorage>,
    hash: [u8; 32],
    bytes: Vec<u8>,
    offender: [u8; 32],
    now_ms: u64,
) -> Result<(), NodeError> {
    blocking_work_in_pool(pool, move || {
        storage
            .commit_slashing_evidence_and_ban(&hash, &bytes, &offender, now_ms)
            .map_err(NodeError::Storage)
    })
    .await
}

/// CPU ticket verification has a process-wide bound on Argon2 memory use.
async fn ticket_work<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, NodeError> + Send + 'static,
) -> Result<T, NodeError> {
    static CPU: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    blocking_work_in_pool(
        CPU.get_or_init(|| Arc::new(Semaphore::new(2))).clone(),
        work,
    )
    .await
}

/// Permits remain owned by running work even when its async caller is cancelled.
async fn blocking_work_in_pool<T: Send + 'static>(
    pool: Arc<Semaphore>,
    work: impl FnOnce() -> Result<T, NodeError> + Send + 'static,
) -> Result<T, NodeError> {
    let permit = pool
        .try_acquire_owned()
        .map_err(|_| NodeError::LocalCapacity("blocking worker capacity exhausted"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|e| NodeError::Network(format!("blocking worker failed: {e}")))?
}

/// Creates a Quinn server endpoint supporting dual-stack IPv6/IPv4 binding when requested.
fn create_server_endpoint(
    server_config: quinn::ServerConfig,
    addr: SocketAddr,
) -> Result<quinn::Endpoint, NodeError> {
    if let SocketAddr::V6(v6) = addr {
        if v6.ip().is_unspecified() {
            let dual_stack_res: Result<quinn::Endpoint, std::io::Error> = (|| {
                let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
                let _ = sock.set_only_v6(false);
                sock.bind(&socket2::SockAddr::from(addr))?;
                sock.set_nonblocking(true)?;
                let udp_sock = std::net::UdpSocket::from(sock);
                quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server_config.clone()),
                    udp_sock,
                    Arc::new(quinn::TokioRuntime),
                )
            })();

            match dual_stack_res {
                Ok(ep) => return Ok(ep),
                Err(err) => {
                    warn!(
                        "Dual-stack IPv6 socket binding on {} failed ({}); falling back to quinn::Endpoint::server",
                        addr, err
                    );
                }
            }
        }
    }

    quinn::Endpoint::server(server_config, addr)
        .map_err(|e| NodeError::Network(format!("Failed to bind QUIC endpoint on {}: {}", addr, e)))
}

/// Helper to map an IPv4 target address to an IPv4-mapped IPv6 address
/// when the local endpoint is bound to an IPv6 dual-stack socket.
fn prepare_dial_addr(local_addr: Option<SocketAddr>, remote_addr: SocketAddr) -> SocketAddr {
    match (remote_addr, local_addr) {
        (SocketAddr::V4(v4), Some(SocketAddr::V6(_))) => SocketAddr::V6(
            std::net::SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
        ),
        _ => remote_addr,
    }
}

impl QuicTransport {
    /// Returns true if the node is sync-ready after initial recovery.
    pub fn is_sync_ready(&self) -> bool {
        self.is_sync_ready.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sets the sync-ready state.
    pub fn set_sync_ready(&self, ready: bool) {
        self.is_sync_ready
            .store(ready, std::sync::atomic::Ordering::SeqCst);
    }

    /// Replaces the underlying sync-ready atomic handle.
    pub fn set_sync_ready_handle(&mut self, handle: Arc<std::sync::atomic::AtomicBool>) {
        self.is_sync_ready = handle;
    }

    /// Returns a clone of the sync-ready atomic handle.
    pub fn sync_ready_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.is_sync_ready.clone()
    }

    /// Sets the stream read timeout for testing (S04-17).
    #[doc(hidden)]
    pub fn set_stream_read_timeout_for_test(&self, dur: std::time::Duration) {
        self.stream_read_timeout
            .store(dur.as_millis() as u64, std::sync::atomic::Ordering::Release);
    }

    /// Returns the number of available shard stream permits for testing (S04-17).
    #[doc(hidden)]
    pub fn shard_streams_available_for_test(&self) -> usize {
        self.shard_streams.available_permits()
    }

    /// Returns the number of available sync stream permits for testing (S04-17).
    #[doc(hidden)]
    pub fn sync_streams_available_for_test(&self) -> usize {
        self.sync_streams.available_permits()
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
        Self::bind_with_options_for_network(
            addr,
            identity,
            peer_manager,
            handler,
            cancel_token,
            humoco_sim_core::types::NetworkId::Mainnet,
        )
    }

    /// Binds transport with the exact network TLS domain and role-specific keepalive.
    pub fn bind_with_options_for_network(
        addr: SocketAddr,
        identity: &NodeIdentity,
        peer_manager: Arc<PeerManager>,
        handler: Arc<dyn RequestHandler>,
        cancel_token: CancellationToken,
        network_id: humoco_sim_core::types::NetworkId,
    ) -> Result<Self, NodeError> {
        let server_config =
            crate::network::tls::build_quinn_server_config_with_network(identity, network_id)?;
        let client_config =
            crate::network::tls::build_quinn_client_config_with_identity_and_network(
                identity, network_id,
            )?;

        let mut endpoint = create_server_endpoint(server_config, addr)?;

        endpoint.set_default_client_config(client_config);
        peer_manager.set_endpoint(endpoint.clone());
        peer_manager.set_local_node_pubkey(*identity.node_pubkey());

        let (fraud_tx, mut fraud_rx) =
            tokio::sync::mpsc::channel::<crate::network::manager::FraudProofForwardMsg>(100);
        let pm_for_channel = peer_manager.clone();
        let tasks = tokio_util::task::TaskTracker::new();
        tasks.spawn(async move {
            pm_for_channel.set_fraud_proof_tx(fraud_tx).await;
        });

        let transport = Self {
            endpoint,
            network_id,
            tasks: tasks.clone(),
            identity: identity.clone(),
            shared_identity: None,
            peer_manager: peer_manager.clone(),
            handler,
            cancel_token: cancel_token.clone(),
            stream_semaphore: Arc::new(Semaphore::new(STREAM_CONCURRENCY_LIMIT)),
            uni_stream_semaphore: Arc::new(Semaphore::new(UNI_STREAM_CONCURRENCY_LIMIT)),
            sync_streams: Arc::new(Semaphore::new(32)),
            shard_streams: Arc::new(Semaphore::new(256)),
            connection_semaphore: Arc::new(Semaphore::new(CONNECTION_CONCURRENCY_LIMIT)),
            shard_pool: crate::network::pool::ShardConnectionPool::new(),
            is_sync_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            outbound_forwarder_semaphore: Arc::new(Semaphore::new(OUTBOUND_FORWARDER_LIMIT)),
            fraud_forwarder_semaphore: Arc::new(Semaphore::new(OUTBOUND_FRAUD_FORWARDER_LIMIT)),
            handler_timeout: Arc::new(std::sync::atomic::AtomicU64::new(
                DEFAULT_HANDLER_TIMEOUT.as_millis() as u64,
            )),
            stream_read_timeout: Arc::new(std::sync::atomic::AtomicU64::new(
                crate::network::framing::DEFAULT_STREAM_READ_TIMEOUT.as_millis() as u64,
            )),
        };

        let transport_for_broadcast = transport.clone();
        let cancel = cancel_token.clone();
        let is_sim = peer_manager.is_simulation_mode();
        let retry_interval_ms = if is_sim { 50 } else { 1000 };
        transport.tasks.spawn(async move {
            let mut retry_ticker =
                tokio::time::interval(tokio::time::Duration::from_millis(retry_interval_ms));
            retry_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        // Orderly shutdown handling: final flush attempt before shutdown completes (S06-15)
                        if let Err(err) = transport_for_broadcast.peer_manager.flush_pending_slashing_evidence().await {
                            warn!(error = %err, "Final flush of pending slashing evidence during shutdown failed");
                        }
                        break;
                    }
                    Some((proof, sender)) = fraud_rx.recv() => {
                        transport_for_broadcast.broadcast_equivocation_proof_to_f2f_except(&proof, sender).await;
                        // Forwarding pressure has eased (channel slot freed); flush any retained pending evidence
                        if transport_for_broadcast.peer_manager.has_unsettled_slashing_evidence() {
                            if let Err(err) = transport_for_broadcast.peer_manager.flush_pending_slashing_evidence().await {
                                warn!(error = %err, "Flush of pending slashing evidence after forward progress failed");
                            }
                        }
                    }
                    _ = retry_ticker.tick() => {
                        // Periodic retry lifecycle: check for any unsettled evidence from prior storage/forwarding faults
                        if transport_for_broadcast.peer_manager.has_unsettled_slashing_evidence() {
                            if let Err(err) = transport_for_broadcast.peer_manager.flush_pending_slashing_evidence().await {
                                warn!(error = %err, "Periodic flush of pending slashing evidence failed; will retry");
                            }
                        }
                    }
                }
            }
        });

        Ok(transport)
    }

    /// Waits for all tracked QUIC producers and handlers after ingress cancellation.
    pub async fn drain_tasks(&self) {
        self.tasks.close();
        self.tasks.wait().await;
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

    /// Attaches a shared dynamic identity handle that reflects background-mined tickets.
    pub fn with_shared_identity(
        mut self,
        shared_identity: Arc<parking_lot::RwLock<NodeIdentity>>,
    ) -> Self {
        self.shared_identity = Some(shared_identity);
        self
    }

    /// Returns the active identity snapshot (dynamic if shared handle attached, or fixed).
    pub fn current_identity(&self) -> NodeIdentity {
        if let Some(shared) = &self.shared_identity {
            shared.read().clone()
        } else {
            self.identity.clone()
        }
    }

    /// Returns a reference to the PeerManager.
    pub fn peer_manager(&self) -> &Arc<PeerManager> {
        &self.peer_manager
    }

    /// Returns a reference to the CancellationToken.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }

    /// Returns the outbound heartbeat gossip forwarder semaphore.
    pub fn outbound_forwarder_semaphore(&self) -> &Arc<Semaphore> {
        &self.outbound_forwarder_semaphore
    }

    /// Returns the dedicated outbound fraud proof forwarder semaphore (Spec 10).
    pub fn fraud_forwarder_semaphore(&self) -> &Arc<Semaphore> {
        &self.fraud_forwarder_semaphore
    }

    /// Test-only hook to set the handler timeout for deterministic deadline verification.
    #[doc(hidden)]
    pub fn set_handler_timeout_for_test(&self, timeout: std::time::Duration) {
        self.handler_timeout
            .store(timeout.as_millis().max(1) as u64, std::sync::atomic::Ordering::Release);
    }

    /// Test-only hook to inspect available bi-stream concurrency permits.
    #[doc(hidden)]
    pub fn stream_semaphore_available_for_test(&self) -> usize {
        self.stream_semaphore.available_permits()
    }

    /// Occupies the actual local admission budget without creating 256 sockets.
    #[cfg(test)]
    pub(crate) fn reserve_all_outbound_shard_slots_for_test(
        &self,
    ) -> tokio::sync::OwnedSemaphorePermit {
        self.shard_pool.occupy_all()
    }

    /// Connects to a remote peer address via QUIC, reusing existing open connection if present.
    /// Iron rule / F2F: Permits direct connections only to F2F friends or nodes learned via F2F gossip.
    pub async fn connect_peer(
        &self,
        addr: SocketAddr,
    ) -> Result<crate::network::pool::PeerConnectionLease, NodeError> {
        if !self
            .peer_manager
            .can_authorize_direct_rpc(&addr, None)
            .await
        {
            return Err(NodeError::Network(format!(
                "Direct connection to {} refused: peer is neither an F2F friend nor known via F2F gossip",
                addr
            )));
        }

        let expected_keys = self.peer_manager.expected_authorized_node_keys(&addr).await;
        if expected_keys.is_empty() {
            return Err(NodeError::Network(format!(
                "Direct connection to {} refused: no authorized identity currently bound to endpoint",
                addr
            )));
        }

        if let Some(conn) = self.peer_manager.get_connection(&addr).await {
            let cached_id = extract_peer_identity_from_connection(&conn).map(|(nid, _)| nid);
            let is_valid = match cached_id {
                Some(ref nid) => {
                    expected_keys.contains(nid) && !self.peer_manager.is_banned(nid).await
                }
                None => false,
            };
            if is_valid {
                return self.shard_pool.lease(conn);
            } else {
                self.peer_manager.evict_connection(&addr).await;
            }
        }

        // Apply exponential backoff with jitter if reconnecting to a failed or suspended peer (Spec 15 / INV-1502)
        if let Some(backoff) = self.peer_manager.get_reconnect_backoff(&addr).await {
            tokio::time::sleep(backoff).await;
        }

        // Reserve before dialing; only unleased idle sessions may be displaced.
        let shard_slot = if self.peer_manager.is_f2f_addr(&addr).await {
            None
        } else {
            Some(self.shard_pool.reserve()?)
        };
        let dial_addr = prepare_dial_addr(self.endpoint.local_addr().ok(), addr);
        let connecting = if self.peer_manager.is_f2f_addr(&addr).await {
            let config = crate::network::tls::build_quinn_friend_client_config(
                &self.identity,
                self.network_id,
            )?;
            self.endpoint.connect_with(config, dial_addr, P2P_QUIC_SNI)
        } else {
            self.endpoint.connect(dial_addr, P2P_QUIC_SNI)
        }
        .map_err(NodeError::QuinnConnect)?;

        let connection = connecting.await.map_err(NodeError::QuinnConnection)?;
        let remote_identity = extract_peer_identity_from_connection(&connection);
        let remote_node_id = remote_identity.as_ref().map(|(nid, _)| *nid);

        let authorized_node_id = match remote_node_id {
            Some(nid) => {
                if self.peer_manager.is_banned(&nid).await {
                    connection.close(0u32.into(), b"banned: equivocation proof");
                    return Err(NodeError::Network(format!(
                        "Peer {} is banned",
                        hex::encode(nid)
                    )));
                }
                if !expected_keys.contains(&nid) {
                    connection.close(0u32.into(), b"unauthorized identity mismatch");
                    return Err(NodeError::Network(format!(
                        "Connection to {} presented unauthorized identity {} (expected one of {:?})",
                        addr,
                        hex::encode(nid),
                        expected_keys.iter().map(hex::encode).collect::<Vec<_>>()
                    )));
                }
                nid
            }

            None => {
                connection.close(0u32.into(), b"missing TLS peer identity");
                return Err(NodeError::Network(format!(
                    "Connection to {} failed: missing or invalid TLS peer identity",
                    addr
                )));
            }
        };

        if let Some((_, vk)) = remote_identity {
            self.peer_manager
                .register_verifying_key(authorized_node_id, vk)
                .await;
        }

        // Pin before publishing the connection for reuse by concurrent callers.
        let lease = match shard_slot {
            Some(reservation) => reservation.commit(connection.clone()),
            None => self.shard_pool.lease(connection.clone())?,
        };
        self.peer_manager
            .record_success(addr, Some(authorized_node_id), Some(connection.clone()))
            .await;

        if self.peer_manager.is_f2f_friend(&authorized_node_id).await {
            let t_clone = self.clone();
            let c_clone = connection.clone();
            self.tasks.spawn(async move {
                t_clone
                    .sync_f2f_friend_session(authorized_node_id, c_clone)
                    .await;
            });
        }

        let conn_clone = connection.clone();
        let handler = self.handler.clone();
        let peer_manager = self.peer_manager.clone();
        let cancel_token = self.cancel_token.clone();
        let stream_semaphore = self.stream_semaphore.clone();
        let transport = self.clone();
        self.tasks.spawn(async move {
            Self::handle_connection(
                conn_clone,
                handler,
                peer_manager,
                cancel_token,
                Some(authorized_node_id),
                stream_semaphore,
                transport,
            )
            .await;
        });

        Ok(lease)
    }

    /// Explicit/unchecked connection to a peer address (useful for bootstrap / friend registration).
    pub async fn connect_peer_unchecked(
        &self,
        addr: SocketAddr,
    ) -> Result<crate::network::pool::PeerConnectionLease, NodeError> {
        let expected_keys = self.peer_manager.expected_authorized_node_keys(&addr).await;

        if let Some(conn) = self.peer_manager.get_connection(&addr).await {
            let cached_id = extract_peer_identity_from_connection(&conn).map(|(nid, _)| nid);
            let is_valid = match cached_id {
                Some(ref nid) => {
                    let not_banned = !self.peer_manager.is_banned(nid).await;
                    let matches_expected = expected_keys.is_empty() || expected_keys.contains(nid);
                    not_banned && matches_expected
                }
                None => false,
            };
            if is_valid {
                return self.shard_pool.lease(conn);
            } else {
                self.peer_manager.evict_connection(&addr).await;
            }
        }

        // Reserve before dialing; only unleased idle sessions may be displaced.
        let shard_slot = if self.peer_manager.is_f2f_addr(&addr).await {
            None
        } else {
            Some(self.shard_pool.reserve()?)
        };
        let dial_addr = prepare_dial_addr(self.endpoint.local_addr().ok(), addr);
        let connecting = if self.peer_manager.is_f2f_addr(&addr).await {
            let config = crate::network::tls::build_quinn_friend_client_config(
                &self.identity,
                self.network_id,
            )?;
            self.endpoint.connect_with(config, dial_addr, P2P_QUIC_SNI)
        } else {
            self.endpoint.connect(dial_addr, P2P_QUIC_SNI)
        }
        .map_err(NodeError::QuinnConnect)?;

        let connection = connecting.await.map_err(NodeError::QuinnConnection)?;
        let remote_identity = extract_peer_identity_from_connection(&connection);
        let remote_node_id = remote_identity.as_ref().map(|(nid, _)| *nid);

        let authorized_node_id = match remote_node_id {
            Some(nid) => {
                if self.peer_manager.is_banned(&nid).await {
                    connection.close(0u32.into(), b"banned: equivocation proof");
                    return Err(NodeError::Network(format!(
                        "Peer {} is banned",
                        hex::encode(nid)
                    )));
                }
                if !expected_keys.is_empty() && !expected_keys.contains(&nid) {
                    connection.close(0u32.into(), b"unauthorized identity mismatch");
                    return Err(NodeError::Network(format!(
                        "Connection to {} presented unauthorized identity {} (expected one of {:?})",
                        addr,
                        hex::encode(nid),
                        expected_keys.iter().map(hex::encode).collect::<Vec<_>>()
                    )));
                }
                nid
            }
            None => {
                connection.close(0u32.into(), b"missing TLS peer identity");
                return Err(NodeError::Network(format!(
                    "Connection to {} failed: missing or invalid TLS peer identity",
                    addr
                )));
            }
        };

        if let Some((_, vk)) = remote_identity {
            self.peer_manager
                .register_verifying_key(authorized_node_id, vk)
                .await;
        }

        // Pin before publishing the connection for reuse by concurrent callers.
        let lease = match shard_slot {
            Some(reservation) => reservation.commit(connection.clone()),
            None => self.shard_pool.lease(connection.clone())?,
        };
        self.peer_manager
            .record_success(addr, Some(authorized_node_id), Some(connection.clone()))
            .await;

        if self.peer_manager.is_f2f_friend(&authorized_node_id).await {
            let t_clone = self.clone();
            let c_clone = connection.clone();
            self.tasks.spawn(async move {
                t_clone
                    .sync_f2f_friend_session(authorized_node_id, c_clone)
                    .await;
            });
        }

        let conn_clone = connection.clone();
        let handler = self.handler.clone();
        let peer_manager = self.peer_manager.clone();
        let cancel_token = self.cancel_token.clone();
        let stream_semaphore = self.stream_semaphore.clone();
        let transport = self.clone();
        self.tasks.spawn(async move {
            Self::handle_connection(
                conn_clone,
                handler,
                peer_manager,
                cancel_token,
                Some(authorized_node_id),
                stream_semaphore,
                transport,
            )
            .await;
        });

        Ok(lease)
    }

    /// Sends a bi-directional request frame and awaits the response frame.
    /// Bounds the entire operation (stream acquisition, frame transmission, finish, and response read)
    /// under an absolute deadline and transport cancellation token.
    pub async fn send_request(
        &self,
        conn: &quinn::Connection,
        header: &WireHeader,
        payload: &[u8],
    ) -> Result<(WireHeader, Vec<u8>), NodeError> {
        self.send_request_timeout(conn, header, payload, DEFAULT_REQUEST_TIMEOUT)
            .await
    }

    /// Sends a bi-directional request frame and awaits the response frame with a custom timeout.
    pub async fn send_request_timeout(
        &self,
        conn: &quinn::Connection,
        header: &WireHeader,
        payload: &[u8],
        timeout_dur: std::time::Duration,
    ) -> Result<(WireHeader, Vec<u8>), NodeError> {
        send_request_bounded(
            conn,
            header,
            payload,
            timeout_dur,
            Some(&self.cancel_token),
        )
        .await
    }

    /// Sends a unidirectional frame over a dedicated unidirectional stream with transport cancellation and timeout.
    pub async fn send_unidirectional(
        &self,
        conn: &quinn::Connection,
        header: &WireHeader,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        send_unidirectional_frame_bounded(
            conn,
            header,
            payload,
            DEFAULT_UNI_STREAM_TIMEOUT,
            Some(&self.cancel_token),
        )
        .await
    }
}

/// Sends a bi-directional request frame and awaits the response frame over a dedicated QUIC stream
/// with an absolute deadline and optional cancellation covering stream opening, frame transmission,
/// stream finish, and response frame reception.
pub async fn send_request_bounded(
    conn: &quinn::Connection,
    header: &WireHeader,
    payload: &[u8],
    timeout_dur: std::time::Duration,
    cancel_token: Option<&CancellationToken>,
) -> Result<(WireHeader, Vec<u8>), NodeError> {
    let req_op = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(NodeError::QuinnConnection)?;
        write_frame(&mut send, header, payload).await?;
        send.finish().map_err(NodeError::QuinnClosedStream)?;

        let (resp_hdr, resp_payload) = read_frame_with_timeout(&mut recv, timeout_dur).await?;
        Ok((resp_hdr, resp_payload))
    };

    let with_timeout = async {
        match tokio::time::timeout(timeout_dur, req_op).await {
            Ok(res) => res,
            Err(_) => Err(NodeError::Network(
                "outbound request timeout".to_string(),
            )),
        }
    };

    if let Some(token) = cancel_token {
        tokio::select! {
            biased;
            _ = token.cancelled() => Err(NodeError::Network("operation cancelled".to_string())),
            res = with_timeout => res,
        }
    } else {
        with_timeout.await
    }
}

/// Freestanding helper to send a bi-directional request frame and await the response over a dedicated QUIC stream with a bounded timeout.
pub async fn send_request_frame(
    conn: &quinn::Connection,
    header: &WireHeader,
    payload: &[u8],
) -> Result<(WireHeader, Vec<u8>), NodeError> {
    send_request_bounded(conn, header, payload, DEFAULT_REQUEST_TIMEOUT, None).await
}

/// Sends a unidirectional frame over a dedicated QUIC stream with a bounded timeout and optional cancellation.
pub async fn send_unidirectional_frame_bounded(
    conn: &quinn::Connection,
    header: &WireHeader,
    payload: &[u8],
    timeout_dur: std::time::Duration,
    cancel_token: Option<&CancellationToken>,
) -> Result<(), NodeError> {
    let send_op = async {
        let mut send = conn.open_uni().await.map_err(NodeError::QuinnConnection)?;
        write_frame(&mut send, header, payload).await?;
        send.finish().map_err(NodeError::QuinnClosedStream)?;
        Ok(())
    };

    let with_timeout = async {
        match tokio::time::timeout(timeout_dur, send_op).await {
            Ok(res) => res,
            Err(_) => Err(NodeError::Network(
                "outbound unidirectional frame timeout".to_string(),
            )),
        }
    };

    if let Some(token) = cancel_token {
        tokio::select! {
            biased;
            _ = token.cancelled() => Err(NodeError::Network("operation cancelled".to_string())),
            res = with_timeout => res,
        }
    } else {
        with_timeout.await
    }
}

/// Freestanding helper to send a unidirectional frame over a dedicated QUIC stream with a bounded timeout.
pub async fn send_unidirectional_frame(
    conn: &quinn::Connection,
    header: &WireHeader,
    payload: &[u8],
) -> Result<(), NodeError> {
    send_unidirectional_frame_bounded(conn, header, payload, DEFAULT_UNI_STREAM_TIMEOUT, None).await
}

impl QuicTransport {
    /// Sends a signed F2F heartbeat to a single peer (used by daemon heartbeat emitter).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_heartbeat_to(
        &self,
        addr: SocketAddr,
        local_addr: SocketAddr,
        seq: u64,
        declared_write_ema_micro_bj: u64,
        declared_read_ema_credits: u64,
        timestamp_ms: u64,
        piggyback_observations: Vec<humoco_sim_core::fraud::IngressEnvelopeEvidence>,
    ) -> Result<(), NodeError> {
        let active_id = self.current_identity();
        let mut hb = crate::network::framing::HeartbeatWirePayload {
            gateway_advertisement: self.handler.gateway_advertisement(),
            signing_checkpoint: self.handler.signing_checkpoint().await?,
            node_id: *active_id.node_pubkey(),
            addr: local_addr,
            timestamp_ms,
            declared_write_ema_micro_bj,
            declared_read_ema_credits,
            signature: [0; 64],
            supported_suites_mask: 0,
            piggyback_observations,
            pow_nonce: active_id.nonce(),
            hrw_routing_id: *active_id.hrw_routing_id(),
            ticket_epoch_t0: active_id.t0(),
            ttl: 16,
        };
        hb.sign_origin(&active_id, timestamp_ms, self.network_id);
        let payload = bincode::serialize(&hb)
            .map_err(|e| NodeError::Network(format!("heartbeat serialize: {}", e)))?;
        let payload_len = checked_payload_len(payload.len())?;
        let header = WireHeader::new(MsgType::Heartbeat as u16, seq, 0, 0, payload_len);
        let conn = self.connect_peer_unchecked(addr).await?;
        let res = self.send_unidirectional(&conn, &header, &payload).await;
        if res.is_ok() {
            if let Some(friend_pk) = self.peer_manager.f2f_friend_pubkey_for_addr(&addr).await {
                let t_clone = self.clone();
                let c_clone = (*conn).clone();
                self.tasks.spawn(async move {
                    t_clone.sync_f2f_friend_session(friend_pk, c_clone).await;
                });
            }
        }
        res
    }

    /// Synchronizes Hop-2 neighbor roster and flushes 1-slot outbox messages to an authenticated F2F friend.
    pub async fn sync_f2f_friend_session(&self, friend_pk: [u8; 32], conn: quinn::Connection) {
        let roster = self
            .peer_manager
            .build_local_f2f_roster(self.identity.node_pubkey())
            .await;
        if let Ok(roster_bytes) = roster.to_bytes() {
            let header = WireHeader::new(
                MsgType::F2fNeighborRoster as u16,
                0,
                0,
                0,
                roster_bytes.len() as u32,
            );
            let _ = self
                .send_unidirectional(&conn, &header, &roster_bytes)
                .await;
        }

        let pending = self
            .peer_manager
            .f2f_collab()
            .lock()
            .inbox()
            .get_pending_outbox(&friend_pk)
            .cloned();

        if let Some(msg) = pending {
            if let Ok(msg_bytes) = msg.to_bytes() {
                let header = WireHeader::new(
                    MsgType::F2fOperatorMessage as u16,
                    0,
                    0,
                    0,
                    msg_bytes.len() as u32,
                );
                let _ = self.send_unidirectional(&conn, &header, &msg_bytes).await;
            }
        }
    }

    /// Queues and sends an F2F operator message to a direct F2F friend.
    pub async fn send_f2f_operator_message(
        &self,
        friend_pubkey: [u8; 32],
        text: String,
        trace_pubkeys: Vec<[u8; 32]>,
        reply_to_msg_id: Option<u64>,
    ) -> Result<crate::network::f2f_collab::F2fStoredMessage, String> {
        let msg_id = rand::random::<u64>();
        let self_pubkey = *self.identity.node_pubkey();
        let now_ms = self.peer_manager.net_time_ms();

        let payload = crate::network::framing::F2fOperatorMessagePayload {
            msg_id,
            sender_pubkey: self_pubkey,
            timestamp_ms: now_ms,
            text,
            trace_pubkeys,
            reply_to_msg_id,
        };

        let payload_bytes = payload
            .to_bytes()
            .map_err(|e| format!("Invalid F2F operator message: {}", e))?;

        // S04-19: Validate and publish pending/history state BEFORE connection lookup, await, or transmission.
        // Keeps pending state intact if connection lookup, dial, or transmission fails.
        let stored_init = self
            .peer_manager
            .f2f_collab()
            .lock()
            .inbox_mut()
            .queue_outbound(friend_pubkey, payload, false);

        let friend_addr = self.peer_manager.get_f2f_friend_addr(&friend_pubkey).await;
        let conn_opt = match friend_addr {
            Some(addr) => self.peer_manager.get_connection(&addr).await,
            None => None,
        };

        if let Some(conn) = conn_opt {
            let header = WireHeader::new(
                MsgType::F2fOperatorMessage as u16,
                0,
                0,
                0,
                payload_bytes.len() as u32,
            );
            let _ = self
                .send_unidirectional(&conn, &header, &payload_bytes)
                .await;
        }

        // Read back the current stored message state so if an authenticated ACK already arrived
        // during transmission, delivered=true is accurately returned, while preserving pending
        // state on transmission/lookup failure without requeueing a stale undelivered clone.
        let stored = self
            .peer_manager
            .f2f_collab()
            .lock()
            .inbox()
            .get_message(&friend_pubkey, msg_id)
            .unwrap_or(stored_init);

        Ok(stored)
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
        let known_originator_addr = self
            .peer_manager
            .get_known_node_addr(&originator_node_id)
            .await;
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
            let permit = match self
                .outbound_forwarder_semaphore
                .clone()
                .try_acquire_owned()
            {
                Ok(p) => p,
                Err(_) => {
                    debug!("Outbound forwarder capacity exhausted, dropping forwarded heartbeat");
                    continue;
                }
            };
            let transport = self.clone();
            let hdr = header;
            let pld = payload.clone();
            self.tasks.spawn(async move {
                let _permit = permit;
                let _ = transport
                    .send_unidirectional_to_peer(target, &hdr, &pld)
                    .await;
            });
        }
    }

    /// Sends a unidirectional frame to a target peer without prior authorization check (used for F2F gossip & fraud proofs).
    /// Bounds connection establishment and transmission together under a single deadline and transport cancellation token,
    /// ensuring stalled dials do not delay cancellation-based draining and deadlines are not restarted.
    pub async fn send_unidirectional_to_peer(
        &self,
        addr: SocketAddr,
        header: &WireHeader,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        self.send_unidirectional_to_peer_timeout(addr, header, payload, DEFAULT_UNI_STREAM_TIMEOUT)
            .await
    }

    /// Sends a unidirectional frame to a target peer with a custom timeout covering both connection establishment and transmission.
    pub async fn send_unidirectional_to_peer_timeout(
        &self,
        addr: SocketAddr,
        header: &WireHeader,
        payload: &[u8],
        timeout_dur: std::time::Duration,
    ) -> Result<(), NodeError> {
        let send_op = async {
            let conn = self.connect_peer_unchecked(addr).await?;
            let mut send = conn.open_uni().await.map_err(NodeError::QuinnConnection)?;
            write_frame(&mut send, header, payload).await?;
            send.finish().map_err(NodeError::QuinnClosedStream)?;
            Ok(())
        };

        let with_timeout = async {
            match tokio::time::timeout(timeout_dur, send_op).await {
                Ok(res) => res,
                Err(_) => Err(NodeError::Network(
                    "outbound unidirectional frame timeout".to_string(),
                )),
            }
        };

        tokio::select! {
            biased;
            _ = self.cancel_token.cancelled() => Err(NodeError::Network("operation cancelled".to_string())),
            res = with_timeout => res,
        }
    }

    /// Broadcasts an equivocation or under-reporting fraud proof to all F2F friends via unidirectional QUIC streams.
    pub async fn broadcast_equivocation_proof_to_f2f(
        &self,
        proof: &humoco_sim_core::fraud::FraudProofPayload,
    ) {
        self.broadcast_equivocation_proof_to_f2f_except(proof, None)
            .await;
    }

    /// Phase 10: deduplicated fraud-proof forwarding with echo protection and Spec 10 priority.
    /// - Dedicated bounded capacity (`fraud_forwarder_semaphore`) prevents starvation under heartbeat load.
    /// - LRU seen-set suppresses re-broadcast storms (gossip loops).
    /// - If 0 permits could be admitted due to capacity exhaustion, the proof is removed from the
    ///   dedup set to allow retry upon capacity recovery.
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
                self.peer_manager.remove_fraud_proof(&hash).await;
                return;
            }
        };
        let payload_len = match checked_payload_len(payload.len()) {
            Ok(l) => l,
            Err(_) => {
                self.peer_manager.remove_fraud_proof(&hash).await;
                return;
            }
        };
        let header = WireHeader::new(MsgType::EquivocationProof as u16, 1, 0, 0, payload_len);
        let mut targets = self.peer_manager.all_f2f_target_addrs().await;
        // Echo protection: resolve all known addrs of the sender and exclude them,
        // plus belt-and-braces filtering by live peer node_id mapping.
        if let Some(sender_id) = exclude {
            let sender_addrs = self.peer_manager.addrs_for_node_id(&sender_id).await;
            targets.retain(|a| !sender_addrs.contains(a));
        }

        let mut eligible_targets = Vec::with_capacity(targets.len());
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
            eligible_targets.push(addr);
        }

        if eligible_targets.is_empty() {
            return;
        }

        let mut admitted = 0usize;
        for addr in eligible_targets {
            let permit = match self
                .fraud_forwarder_semaphore
                .clone()
                .try_acquire_owned()
            {
                Ok(p) => p,
                Err(_) => {
                    debug!("Fraud forwarder capacity exhausted, dropping forwarded fraud proof for target {}", addr);
                    continue;
                }
            };
            admitted += 1;
            let transport = self.clone();
            let payload = payload.clone();
            self.tasks.spawn(async move {
                let _permit = permit;
                let _ = transport
                    .send_unidirectional_to_peer(addr, &header, &payload)
                    .await;
            });
        }

        if admitted == 0 {
            // All eligible targets were dropped because fraud forwarding capacity was exhausted.
            // Roll back the dedup record so retries after capacity recovers are not suppressed.
            self.peer_manager.remove_fraud_proof(&hash).await;
            warn!("Fraud forwarder capacity exhausted for all eligible targets; removed from dedup cache to allow retry");
        }
    }

    /// Network domain of this authenticated transport.
    pub(crate) fn network_id(&self) -> humoco_sim_core::types::NetworkId {
        self.network_id
    }

    /// Acquire a short absolute source fence before cold state transfer.
    pub async fn request_frozen_shard(
        &self,
        conn: &quinn::Connection,
        shard: u16,
        seq: u64,
    ) -> Result<crate::network::framing::FrozenShardReply, NodeError> {
        let payload = [vec![1, 0], shard.to_le_bytes().to_vec(), vec![0; 16]].concat();
        let header = WireHeader::new(MsgType::ShardDigestRequest as u16, seq, 0, 0, 20);
        let (header, bytes) = self.send_request(conn, &header, &payload).await?;
        if header.msg_type != MsgType::ShardDigestResponse as u16
            || header.flags != 0
            || bytes.len() != 161
        {
            return Err(NodeError::Network(
                "source is not ready for a no-gap cut".into(),
            ));
        }
        let reply: crate::network::framing::FrozenShardReply = bincode::deserialize(&bytes)
            .map_err(|e| NodeError::Network(format!("frozen reply: {e}")))?;
        if reply.version != 2 || reply.lease_ms != 25_000 {
            return Err(NodeError::Network("unsupported source fence".into()));
        }
        let (_, source) = crate::network::tls::extract_peer_identity_from_connection(conn)
            .ok_or_else(|| NodeError::Network("unauthenticated support source".into()))?;
        let signature = ed25519_dalek::Signature::from_slice(&reply.signature)
            .map_err(|_| NodeError::Network("invalid support signature".into()))?;
        source
            .verify_strict(
                &reply.signing_digest(
                    self.network_id,
                    shard,
                    &source.to_bytes(),
                    self.identity.node_pubkey(),
                ),
                &signature,
            )
            .map_err(|_| NodeError::Network("foreign or forged support assertion".into()))?;
        Ok(reply)
    }
    /// Release only the exact authenticated source lease; expiry is the fallback.
    pub async fn release_frozen_shard(
        &self,
        conn: &quinn::Connection,
        shard: u16,
        seq: u64,
        token: [u8; 16],
    ) -> Result<(), NodeError> {
        let payload = [vec![1, 1], shard.to_le_bytes().to_vec(), token.to_vec()].concat();
        let header = WireHeader::new(MsgType::ShardDigestRequest as u16, seq, 0, 0, 20);
        let (header, _) = self.send_request(conn, &header, &payload).await?;
        if header.msg_type != MsgType::ShardDigestResponse as u16 || header.flags != 0 {
            return Err(NodeError::Network("source release rejected".into()));
        }
        Ok(())
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
        if resp_hdr.flags & humoco_sim_core::wire::FLAG_NOT_READY != 0 {
            return Err(NodeError::Network(format!(
                "Peer reported FLAG_NOT_READY for shard {}",
                shard_id
            )));
        }
        let (digest, count): ([u8; 32], u64) = bincode::deserialize(&resp_payload)
            .map_err(|e| NodeError::Network(format!("digest deserialize: {}", e)))?;
        Ok((digest, count))
    }

    /// Requests bucket digests for a specific shard over a range of buckets (docs/03_statusabgleich_und_sync.md §5).
    pub async fn request_shard_bucket_range(
        &self,
        conn: &quinn::Connection,
        shard_id: u16,
        start_bucket: u64,
        bucket_count: u16,
        seq: u64,
    ) -> Result<humoco_sim_core::types::ShardBucketRangeResponse, NodeError> {
        let req = humoco_sim_core::types::ShardBucketRangeRequest {
            shard_id,
            start_bucket,
            bucket_count,
        };
        let payload = bincode::serialize(&req).unwrap_or_default();
        let payload_len = checked_payload_len(payload.len())?;
        let header = WireHeader::new(
            MsgType::ShardBucketRangeRequest as u16,
            seq,
            0,
            0,
            payload_len,
        );
        let (resp_hdr, resp_payload) = self.send_request(conn, &header, &payload).await?;
        if resp_hdr.msg_type != MsgType::ShardBucketRangeResponse as u16 {
            return Err(NodeError::Network(format!(
                "Unexpected ShardBucketRange response msg_type {}",
                resp_hdr.msg_type
            )));
        }
        bincode::deserialize(&resp_payload)
            .map_err(|e| NodeError::Network(format!("bucket range deserialize: {}", e)))
    }

    /// Requests a single paginated active sync page from a peer (optionally filtered by bucket).
    pub async fn request_active_sync_page_for_bucket(
        &self,
        conn: &quinn::Connection,
        seq: u64,
        cursor: u64,
        limit: usize,
        target_bucket_id: Option<u64>,
    ) -> Result<crate::network::framing::ActiveSyncResponse, NodeError> {
        self.request_active_sync_selected(conn, seq, cursor, limit, target_bucket_id, None)
            .await
    }

    /// Freeze a snapshot cut for one root shard, including its separate anchors.
    pub async fn request_active_sync_page_for_shard(
        &self,
        conn: &quinn::Connection,
        seq: u64,
        cursor: u64,
        limit: usize,
        shard: u16,
    ) -> Result<crate::network::framing::ActiveSyncResponse, NodeError> {
        self.request_active_sync_selected(conn, seq, cursor, limit, None, Some(shard))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_active_sync_selected(
        &self,
        conn: &quinn::Connection,
        seq: u64,
        cursor: u64,
        limit: usize,
        target_bucket_id: Option<u64>,
        target_shard: Option<u16>,
    ) -> Result<crate::network::framing::ActiveSyncResponse, NodeError> {
        let mut req = crate::network::framing::ActiveSyncRequest::with_bucket(
            cursor,
            limit,
            target_bucket_id,
        );
        req.target_shard = target_shard;
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

    /// Requests a single paginated active sync page from a peer.
    pub async fn request_active_sync_page(
        &self,
        conn: &quinn::Connection,
        seq: u64,
        cursor: u64,
        limit: usize,
    ) -> Result<crate::network::framing::ActiveSyncResponse, NodeError> {
        self.request_active_sync_page_for_bucket(conn, seq, cursor, limit, None)
            .await
    }

    /// Requests full active sync data across all pages from a peer.
    pub async fn request_active_sync(
        &self,
        conn: &quinn::Connection,
        seq: u64,
    ) -> Result<crate::network::framing::SyncPayload, NodeError> {
        let mut all_hmc = Vec::new();
        let mut cursor = 0u64;
        let mut current_seq = seq;
        let mut aggregate_bytes = 0u64;
        loop {
            let resp = self
                .request_active_sync_page(conn, current_seq, cursor, 500)
                .await?;
            current_seq = current_seq.wrapping_add(1);
            let count = all_hmc.len() + resp.payload.hmc_locks.len();
            if count > 10_000 {
                return Err(NodeError::LocalCapacity(
                    "active sync aggregate entry limit",
                ));
            }
            aggregate_bytes = aggregate_bytes
                .saturating_add(bincode::serialized_size(&resp.payload).unwrap_or(u64::MAX));
            if aggregate_bytes > 512 * 1024 {
                return Err(NodeError::LocalCapacity("active sync aggregate byte limit"));
            }
            all_hmc.extend(resp.payload.hmc_locks);
            if !resp.has_more {
                break;
            }
            match resp.next_cursor {
                Some(next) if next > cursor => cursor = next,
                _ => break,
            }
        }
        Ok(crate::network::framing::SyncPayload::new(all_hmc))
    }

    /// Spawns the incoming connection accept loop in the background.
    pub fn spawn_accept_loop(&self) -> tokio::task::JoinHandle<()> {
        let transport = self.clone();
        self.tasks.spawn(async move {
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
                            self.tasks.spawn(async move {
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
                                        if let Some(nid) = remote_node_id {
                                            if peer_manager.is_f2f_friend(&nid).await {
                                                let t_clone = transport.clone();
                                                let c_clone = conn.clone();
                                                tokio::spawn(async move {
                                                    t_clone.sync_f2f_friend_session(nid, c_clone).await;
                                                });
                                            }
                                        }
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
                                let lease = match transport.shard_pool.lease(conn.clone()) {
                                    Ok(lease) => lease, Err(_) => continue,
                                };
                                let h = handler.clone();
                                let pm = peer_manager.clone();
                                let sem = stream_semaphore.clone();
                                let sync_pool = transport.sync_streams.clone();
                                let shard_pool = transport.shard_streams.clone();
                                let cancel_token = transport.cancel_token.clone();
                                let handler_timeout_ref = transport.handler_timeout.clone();
                                let stream_read_timeout_ref = transport.stream_read_timeout.clone();
                                transport.tasks.spawn(async move {
                                    let _lease = lease;
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
                                    let stream_read_timeout = std::time::Duration::from_millis(
                                        stream_read_timeout_ref.load(std::sync::atomic::Ordering::Acquire),
                                    );
                                    let read_res = tokio::select! {
                                        biased;
                                        _ = cancel_token.cancelled() => return,
                                        res = crate::network::framing::read_frame_admitted(
                                            &mut recv,
                                            stream_read_timeout,
                                            Some((sync_pool, shard_pool))
                                        ) => res,
                                    };
                                    match read_res {
                                        Ok(((header, payload), _service_permit)) => {
                                            let handler_timeout = std::time::Duration::from_millis(
                                                handler_timeout_ref.load(std::sync::atomic::Ordering::Acquire),
                                            );
                                            let handler_fut = async {
                                                // GOSSIP BARRIER:
                                                // Mesh Gossip (Heartbeat and EquivocationProof) is STRICTLY accepted from direct F2F friends only!
                                                let is_gossip = header.msg_type == MsgType::Heartbeat as u16
                                                    || header.msg_type == MsgType::EquivocationProof as u16;

                                                if is_gossip
                                                    && !pm.can_accept_gossip(&remote_addr, remote_node_id.as_ref()).await
                                                {
                                                    warn!(
                                                        remote = %remote_addr,
                                                        node_id = ?remote_node_id.map(hex::encode),
                                                        msg_type = header.msg_type,
                                                        "GOSSIP BARRIER: Rejected gossip on bidirectional stream from non-F2F connection"
                                                    );
                                                    let resp_payload = b"unauthorized gossip: F2F only";
                                                    let payload_len = checked_payload_len(resp_payload.len()).unwrap_or(0);
                                                    let resp_header = WireHeader::new(
                                                        MsgType::StatusResponse as u16,
                                                        header.session_seq.wrapping_add(1),
                                                        header.epoch_id,
                                                        humoco_sim_core::wire::FLAG_UNAUTHORIZED,
                                                        payload_len,
                                                    );
                                                    if let Err(e) = write_frame(&mut send, &resp_header, resp_payload).await {
                                                        debug!(error = %e, "Failed to write unauthorized response frame");
                                                    }
                                                    let _ = send.finish();
                                                    return;
                                                }

                                                // Shard-Direct RPC Authorization:
                                                // LockVerifyRequest, ActiveSyncRequest, and ShardDigestRequest are only allowed if peer is F2F friend or known via gossip
                                                let is_restricted_rpc = header.msg_type == MsgType::LockVerifyRequest as u16
                                                    || header.msg_type == MsgType::StatusQuery as u16
                                                    || header.msg_type == MsgType::ActiveSyncRequest as u16
                                                    || header.msg_type == MsgType::ShardDigestRequest as u16
                                                    || header.msg_type == MsgType::ShardBucketRangeRequest as u16
                                                    || header.msg_type == MsgType::LiveStateRequest as u16;

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
                                                    // no checkout committee replacement is allowed; unknown peers get a plain
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
                                            };
                                            tokio::pin!(handler_fut);

                                            tokio::select! {
                                                biased;
                                                _ = cancel_token.cancelled() => {
                                                    tokio::select! {
                                                        _ = &mut handler_fut => {}
                                                        _ = tokio::time::sleep(SHUTDOWN_HANDLER_GRACE) => {
                                                            debug!("Bi-stream handler aborted due to shutdown grace expiry");
                                                        }
                                                    }
                                                }
                                                res = tokio::time::timeout(handler_timeout, &mut handler_fut) => {
                                                    if res.is_err() {
                                                        warn!(remote = %remote_addr, "Bi-stream request handler timed out after {:?}", handler_timeout);
                                                    }
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
                                peer_manager.note_connection_closed(&remote_addr, conn.stable_id()).await;
                                break;
                            },
                        }
                    }
                    uni_res = conn.accept_uni() => {
                        match uni_res {
                            Ok(mut recv) => {
                                let lease = match transport.shard_pool.lease(conn.clone()) {
                                    Ok(lease) => lease, Err(_) => continue,
                                };
                                let h = handler.clone();
                                let pm = peer_manager.clone();
                                let sem = transport.uni_stream_semaphore.clone();
                                let conn_clone = conn.clone();
                                let transport_clone = transport.clone();
                                let cancel_token = transport.cancel_token.clone();
                                let stream_read_timeout_ref = transport.stream_read_timeout.clone();
                                transport.tasks.spawn(async move {
                                    let _lease = lease;
                                    let _permit = match sem.try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            warn!(
                                                remote = %remote_addr,
                                                "Uni-stream concurrency limit {} reached, dropping incoming uni-stream (DoS protection)", UNI_STREAM_CONCURRENCY_LIMIT
                                            );
                                            return;
                                        }
                                    };
                                    let stream_read_timeout = std::time::Duration::from_millis(
                                        stream_read_timeout_ref.load(std::sync::atomic::Ordering::Acquire),
                                    );
                                    let read_res = tokio::select! {
                                        biased;
                                        _ = cancel_token.cancelled() => return,
                                        res = crate::network::framing::read_frame_with_timeout(&mut recv, stream_read_timeout) => res,
                                    };
                                    match read_res {
                                        Ok((header, payload)) => {
                                            let uni_fut = async {
                                                // GOSSIP BARRIER:
                                                // Mesh Gossip (Heartbeat and EquivocationProof) is STRICTLY accepted from direct F2F friends only!
                                                let is_f2f_exclusive = header.msg_type == MsgType::F2fOperatorMessage as u16
                                                    || header.msg_type == MsgType::F2fOperatorMessageAck as u16
                                                    || header.msg_type == MsgType::F2fNeighborRoster as u16;

                                                let is_gossip = header.msg_type == MsgType::Heartbeat as u16
                                                    || header.msg_type == MsgType::EquivocationProof as u16
                                                    || is_f2f_exclusive;

                                                if is_gossip && !pm.can_accept_gossip(&remote_addr, remote_node_id.as_ref()).await {
                                                    warn!(
                                                        remote = %remote_addr,
                                                        node_id = ?remote_node_id.map(hex::encode),
                                                        msg_type = header.msg_type,
                                                        "GOSSIP BARRIER: Dropped gossip from non-F2F connection"
                                                    );
                                                    return;
                                                }

                                                if is_f2f_exclusive {
                                                    let is_f2f = if let Some(ref nid) = remote_node_id {
                                                        pm.is_f2f_friend(nid).await
                                                    } else {
                                                        pm.is_f2f_addr(&remote_addr).await
                                                    };
                                                    if !is_f2f || header.reserved != 0 {
                                                        warn!("GOSSIP BARRIER: Rejected non-direct or non-F2F operator dialogue frame");
                                                        return;
                                                    }

                                                    if header.msg_type == MsgType::F2fOperatorMessage as u16 {
                                                        let Ok(op_msg) = crate::network::framing::F2fOperatorMessagePayload::from_bytes(&payload) else {
                                                            warn!("Dropped malformed F2fOperatorMessage");
                                                            return;
                                                        };
                                                        if remote_node_id != Some(op_msg.sender_pubkey) {
                                                            warn!("Spoofing attempt: F2fOperatorMessage sender_pubkey does not match TLS node identity");
                                                            return;
                                                        }
                                                        let res = pm.f2f_collab().lock().inbox_mut().record_inbound(op_msg.clone(), std::time::Instant::now());
                                                        if res.is_ok() {
                                                            let ack_payload = crate::network::framing::F2fOperatorMessageAckPayload {
                                                                msg_id: op_msg.msg_id,
                                                                receiver_pubkey: *transport_clone.identity.node_pubkey(),
                                                                timestamp_ms: pm.net_time_ms(),
                                                            };
                                                            if let Ok(ack_bytes) = ack_payload.to_bytes() {
                                                                let ack_hdr = WireHeader::new(
                                                                    MsgType::F2fOperatorMessageAck as u16,
                                                                    0,
                                                                    0,
                                                                    0,
                                                                    ack_bytes.len() as u32,
                                                                );
                                                                let _ = transport_clone.send_unidirectional(&conn_clone, &ack_hdr, &ack_bytes).await;
                                                            }
                                                            if let Some(dispatcher) = pm.alert_dispatcher() {
                                                                let text = op_msg.text.clone();
                                                                let sender_hex = hex::encode(op_msg.sender_pubkey);
                                                                tokio::spawn(async move {
                                                                    dispatcher
                                                                        .trigger_scoped(
                                                                            crate::alert::AlertKind::KnotenfreundMessageReceived,
                                                                            Some(&sender_hex),
                                                                            &format!("F2F operator message from {}: {}", sender_hex, text),
                                                                        )
                                                                        .await;
                                                                });
                                                            }
                                                        }
                                                        return;
                                                    }

                                                    if header.msg_type == MsgType::F2fOperatorMessageAck as u16 {
                                                        let Ok(ack) = crate::network::framing::F2fOperatorMessageAckPayload::from_bytes(&payload) else {
                                                            warn!("Dropped malformed F2fOperatorMessageAck");
                                                            return;
                                                        };
                                                        if remote_node_id != Some(ack.receiver_pubkey) {
                                                            warn!("Spoofing attempt: F2fOperatorMessageAck receiver_pubkey does not match TLS node identity");
                                                            return;
                                                        }
                                                        pm.f2f_collab().lock().inbox_mut().on_ack_received(ack.receiver_pubkey, ack.msg_id);
                                                        return;
                                                    }

                                                    if header.msg_type == MsgType::F2fNeighborRoster as u16 {
                                                        let Ok(roster) = crate::network::framing::F2fNeighborRosterPayload::from_bytes(&payload) else {
                                                            warn!("Dropped malformed F2fNeighborRoster");
                                                            return;
                                                        };
                                                        if remote_node_id != Some(roster.sender_pubkey) {
                                                            warn!("Spoofing attempt: F2fNeighborRoster sender_pubkey does not match TLS node identity");
                                                            return;
                                                        }
                                                        pm.f2f_collab().lock().roster_mut().record_roster(roster);
                                                        return;
                                                    }
                                                }

                                                // HeartbeatAck handling:
                                                if header.msg_type == MsgType::HeartbeatAck as u16 {
                                                    if (header.flags & humoco_sim_core::wire::FLAG_POW_OUTDATED) != 0 {
                                                        let is_f2f = match remote_node_id {
                                                            Some(ref nid) => pm.is_f2f_friend(nid).await,
                                                            None => false,
                                                        };
                                                        if is_f2f {
                                                            pm.set_ticket_outdated(true);
                                                            warn!("Received HeartbeatAck with FLAG_POW_OUTDATED from authenticated direct F2F friend: shard ticket is outdated");
                                                        } else {
                                                            warn!("Rejected HeartbeatAck with FLAG_POW_OUTDATED from unauthenticated or non-F2F peer");
                                                        }
                                                    }
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
                                                    if let Ok(hb) = crate::network::framing::HeartbeatWirePayload::from_bytes(&payload) {
                                                        // 1. TTL drop check
                                                        if hb.ttl == 0 {
                                                            debug!(node = %hex::encode(hb.node_id), "GOSSIP BARRIER: Dropped heartbeat with TTL == 0");
                                                            return;
                                                        }

                                                        let node_id = hb.node_id;
                                                        if node_id == *transport_clone.identity.node_pubkey() {
                                                            debug!(
                                                                node = %hex::encode(node_id),
                                                                "GOSSIP BARRIER: Ignored reflected self heartbeat"
                                                            );
                                                            return;
                                                        }
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

                                                        // Cryptographic origin signature check
                                                        if hops > 0 {
                                                            if !hb.verify_origin_address_binding(transport.network_id) {
                                                                warn!(
                                                                    node = %hex::encode(node_id),
                                                                    hops,
                                                                    "GOSSIP BARRIER: Dropped relayed heartbeat without valid origin address binding"
                                                                );
                                                                return;
                                                            }
                                                        } else if !hb.verify_origin_signature(transport.network_id) {
                                                            warn!(node = %hex::encode(node_id), "GOSSIP BARRIER: Dropped direct heartbeat with invalid signature");
                                                            return;
                                                        }

                                                        // Spec 11 Freshness Window (A11-01): when local clock has quorum or sync is ready,
                                                        // heartbeats deviating by > 60s from net_time_ms are dropped (no auto-ban).
                                                        let clock_ready = pm.is_local_sync_ready() || pm.clock().has_quorum_samples();
                                                        if clock_ready {
                                                            let diff = hb.timestamp_ms.abs_diff(pm.net_time_ms());
                                                            if diff > HEARTBEAT_FRESHNESS_WINDOW_MS {
                                                                debug!(
                                                                    node = %hex::encode(node_id),
                                                                    hb_timestamp = hb.timestamp_ms,
                                                                    net_time = pm.net_time_ms(),
                                                                    diff_ms = diff,
                                                                    "GOSSIP BARRIER: Dropped heartbeat outside +/-60s freshness window"
                                                                );
                                                                return;
                                                            }
                                                        }

                                                        // Check deduplication cache to prevent gossip loops (Spec 11) - ONLY AFTER signature & freshness
                                                        if !pm.check_and_record_heartbeat(&hb.node_id, hb.pow_nonce, hb.timestamp_ms).await {
                                                            if is_f2f {
                                                                let friend_pk = match remote_node_id {
                                                                    Some(pk) => Some(pk),
                                                                    None => pm.f2f_friend_pubkey_for_addr(&remote_addr).await,
                                                                };
                                                                if let Some(fpk) = friend_pk {
                                                                    pm.record_heartbeat_edge_observation(hb.node_id, fpk, hops as u8).await;
                                                                }
                                                            }
                                                            debug!(node = %hex::encode(hb.node_id), "GOSSIP BARRIER: Dropped duplicate heartbeat (already seen)");
                                                            return;
                                                        }

                                                        // Verify Argon2d Shard Ticket PoW & HRW routing ID
                                                        let (verified_hrw, work_score) = if hb.pow_nonce != 0 || hb.ticket_epoch_t0 != 0 {
                                                            let nonce = hb.pow_nonce;
                                                            let t0 = hb.ticket_epoch_t0;
                                                            let Ok((expected_hrw, w)) = ticket_work(move || {
                                                                let proof = crate::identity::compute_pow_proof(&node_id, nonce, t0)?;
                                                                Ok((humoco_sim_core::crypto::compute_whitened_hrw_id(&node_id, nonce, t0, &proof),
                                                                    humoco_sim_core::crypto::compute_work_from_hash(&proof)))
                                                            }).await else {
                                                                return;
                                                            };
                                                            if expected_hrw != hb.hrw_routing_id {
                                                                warn!(
                                                                    node = %hex::encode(node_id),
                                                                    "GOSSIP BARRIER: Invalid Argon2d shard ticket PoW (hrw_routing_id mismatch)"
                                                                );
                                                                return;
                                                            }
                                                            if w == 0 {
                                                                warn!(
                                                                    node = %hex::encode(node_id),
                                                                    "GOSSIP BARRIER: Invalid Argon2d shard ticket PoW (zero work score)"
                                                                );
                                                                return;
                                                            }
                                                            (expected_hrw, w)
                                                        } else if pm.is_simulation_mode() {
                                                            // Explicit unmined simulation ticket.
                                                            if hb.hrw_routing_id != [0u8; 32] {
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
                                                            }
                                                        } else {
                                                            // In production mode, unmined shortcut tickets are dropped.
                                                            // Nonvoting F2F peers can still contribute direct friend clock samples.
                                                            if hops == 0 && is_f2f && is_direct {
                                                                pm.clock().record_peer_heartbeat(node_id, true, hb.timestamp_ms);
                                                            }
                                                            warn!(
                                                                node = %hex::encode(node_id),
                                                                "GOSSIP BARRIER: Rejected unmined shortcut ticket in production (nonce=0, t0=0)"
                                                            );
                                                            return;
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
                                                                let _ = transport_clone.send_unidirectional(&conn_clone, &ack_hdr, &[]).await;
                                                            } else {
                                                                warn!(
                                                                    node = %hex::encode(node_id),
                                                                    hops,
                                                                    "GOSSIP BARRIER: Dropped multi-hop gossip with outdated PoW"
                                                                );
                                                            }
                                                            return;
                                                        }

                                                        pm.learn_node_from_gossip_with_hrw_work_and_auth(
                                                            node_id,
                                                            verified_hrw,
                                                            hb.addr,
                                                            hops as u8,
                                                            Some(remote_addr),
                                                            work_score,
                                                            true,
                                                        ).await;

                                                        if is_f2f {
                                                            let friend_pk = match remote_node_id {
                                                                Some(pk) => Some(pk),
                                                                None => pm.f2f_friend_pubkey_for_addr(&remote_addr).await,
                                                            };
                                                            if let Some(fpk) = friend_pk {
                                                                pm.record_heartbeat_edge_observation(node_id, fpk, hops as u8).await;
                                                            }
                                                        }

                                                        pm.record_heartbeat_hourly_observation(
                                                            node_id,
                                                            verified_hrw,
                                                            pm.net_time_ms(),
                                                        ).await;

                                                        // Spec 07 / Spec 11: Clock samples fed to P2pClock must originate strictly from direct authenticated F2F peers,
                                                        // never relayed third-party hops (Task 4: F2F-Only Clock Samples).
                                                        // Each authenticated direct F2F friend contributes at most 1 current sample to the median pool (A11-01).
                                                        if hops == 0 && is_f2f && is_direct {
                                                            pm.clock().record_peer_heartbeat(node_id, true, hb.timestamp_ms);
                                                        }

                                                        // Multi-hop forwarding to Dunbar fan-out subset of F2F peers (Spec 11)
                                                        if hb.ttl > 1 && (hops as u32) + 1 < crate::network::manager::MAX_GOSSIP_HOPS {
                                                            transport_clone.forward_heartbeat_gossip(&hb, hops, remote_addr).await;
                                                        }
                                                    }

                                                }

                                                if let Err(e) = h.handle_unidirectional_authenticated(header, payload, remote_node_id).await {
                                                    debug!(error = %e, "Failed to handle unidirectional frame");
                                                }
                                            };
                                            tokio::pin!(uni_fut);

                                            tokio::select! {
                                                biased;
                                                _ = cancel_token.cancelled() => {
                                                    tokio::select! {
                                                        _ = &mut uni_fut => {}
                                                        _ = tokio::time::sleep(SHUTDOWN_HANDLER_GRACE) => {
                                                            debug!("Uni-stream handler aborted due to shutdown grace expiry");
                                                        }
                                                    }
                                                }
                                                res = tokio::time::timeout(
                                                    std::time::Duration::from_millis(
                                                        transport_clone.handler_timeout.load(std::sync::atomic::Ordering::Acquire),
                                                    ),
                                                    &mut uni_fut,
                                                ) => {
                                                    if res.is_err() {
                                                        warn!(remote = %remote_addr, "Uni-stream handler timed out");
                                                    }
                                                }
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
                                peer_manager.note_connection_closed(&remote_addr, conn.stable_id()).await;
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

#[cfg(test)]
mod blocking_worker_tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_request_keeps_worker_capacity_until_actual_completion() {
        let pool = Arc::new(Semaphore::new(1));
        let worker_pool = pool.clone();
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let request = tokio::spawn(async move {
            blocking_work_in_pool(worker_pool, move || {
                let _ = started.send(());
                let _ = blocked.recv_timeout(std::time::Duration::from_secs(2));
                Ok(())
            })
            .await
        });
        entered.await.unwrap();
        request.abort();
        let _ = request.await;
        assert!(matches!(
            blocking_work_in_pool(pool.clone(), || Ok(())).await,
            Err(NodeError::LocalCapacity(_))
        ));
        release.send(()).unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        blocking_work_in_pool(pool, || Ok(())).await.unwrap();
    }
}
