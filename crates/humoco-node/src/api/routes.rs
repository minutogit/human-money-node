use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::Signer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;




use humoco_sim_core::types::SimTime;

use crate::api::dto::{
    AttestationDto, ErrorResponse, LockRecordDto,
    NodeStatusResponse, PeerEntryDto, PeersResponse, PowChallengeResponse,
    QuorumCertificateDto, SyncRequest, SyncResponse,
};
use crate::api::hmc::{
    verify_l2_lock_signature, wrap_and_sign_verdict, wrap_and_sign_verdict_with_quorum,
    L2ChainLockRequest, L2LockEntry, L2LockRequest, L2StatusQuery, L2Verdict,
};
use crate::identity::NodeIdentity;
use crate::ingress::{IngressError, PowEngine, TierController};
use crate::network::{PeerManager, QuicTransport};
use crate::storage::{DualTierEngine, IngressOrigin, RedbStorage};

#[derive(Clone)]
pub struct AppState {
    pub engine: DualTierEngine,
    pub storage: Arc<RedbStorage>,
    pub identity: NodeIdentity,
    pub tier_controller: Arc<TierController>,
    pub pow_engine: Arc<PowEngine>,
    pub peer_manager: Option<Arc<PeerManager>>,
    pub transport: Option<QuicTransport>,
    pub start_time: std::time::Instant,
    pub metrics: Arc<crate::api::metrics::NodeMetrics>,
    pub lifecycle: crate::config::LifecycleConfig,
    pub network_id: humoco_sim_core::types::NetworkId,
    pub shard_query_depth: usize,
}

impl AppState {
    pub fn new(
        engine: DualTierEngine,
        storage: Arc<RedbStorage>,
        identity: NodeIdentity,
        tier_controller: Arc<TierController>,
        pow_engine: Arc<PowEngine>,
    ) -> Self {
        Self {
            engine,
            storage,
            identity,
            tier_controller,
            pow_engine,
            peer_manager: None,
            transport: None,
            start_time: std::time::Instant::now(),
            metrics: Arc::new(crate::api::metrics::NodeMetrics::default()),
            lifecycle: crate::config::LifecycleConfig::default(),
            network_id: humoco_sim_core::types::NetworkId::default(),
            shard_query_depth: 3,
        }
    }

    pub fn with_lifecycle(mut self, lifecycle: crate::config::LifecycleConfig) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    pub fn with_network_id(mut self, network_id: humoco_sim_core::types::NetworkId) -> Self {
        self.network_id = network_id;
        self
    }

    pub fn with_shard_query_depth(mut self, depth: usize) -> Self {
        self.shard_query_depth = depth;
        self
    }

    /// Returns the P2P network-adjusted time (Spec 11) or falls back to SystemTime.
    pub fn net_time_ms(&self) -> u64 {
        if let Some(pm) = &self.peer_manager {
            pm.net_time_ms()
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let sync_router = Router::new()
        .route("/v1/sync", post(sync_locks))
        .layer(DefaultBodyLimit::max(1024 * 1024));

    Router::new()
        .route("/lock", post(submit_lock))
        .route("/v1/lock", post(submit_lock))
        .route("/v1/lock/chain", post(submit_hmc_chain_lock))
        .route("/status", post(query_status))
        .route("/v1/status", post(query_status))
        .merge(sync_router)
        .route("/v1/pow-challenge", get(get_pow_challenge))
        .route("/health", get(get_node_status))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/v1/node-status", get(get_node_status))
        .route("/peers", get(get_peers))
        .route("/api/v1/network/peers", get(get_peers))
        .route("/dashboard", get(crate::api::dashboard::render_dashboard))
        .route("/dashboard/data", get(crate::api::dashboard::dashboard_data))
        .route("/metrics", get(crate::api::metrics::prometheus_metrics))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[allow(clippy::large_enum_variant)]
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum IngressLockPayload {
    Chain(L2ChainLockRequest),
    Single(L2LockRequest),
}

/// Handler for POST /v1/lock and POST /lock
async fn submit_lock(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: bytes::Bytes,
) -> Response {
    let start = std::time::Instant::now();
    match serde_json::from_slice::<IngressLockPayload>(&body_bytes) {
        Ok(IngressLockPayload::Chain(chain_req)) => {
            return submit_hmc_chain_lock(State(state), headers, Json(chain_req)).await;
        }
        Ok(IngressLockPayload::Single(hmc_req)) => {
            return submit_hmc_lock(state, headers, hmc_req, start).await;
        }
        Err(_) => {}
    }

    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: "InvalidRequest".into(),
            message: "400 Bad Request: Invalid HMC Lock format".into(),
            challenge: None,
            difficulty: None,
            expires_at: None,
        }),
    )
        .into_response()
}

/// Handler for POST /v1/sync
async fn sync_locks(
    State(state): State<AppState>,
    Json(payload): Json<SyncRequest>,
) -> (StatusCode, Json<SyncResponse>) {
    let locators: HashSet<String> = payload.sparse_locators.into_iter().collect();

    let mut lock_map = std::collections::HashMap::new();

    // 1. Read from persistent disk storage
    if let Ok(disk_locks) = state.storage.all_valid_locks(0) {
        for (rec, rv) in disk_locks {
            lock_map.insert(rec.parent_lock, (rec, rv));
        }
    }

    // 2. Read from in-memory RAM index
    for (rec, rv) in state.engine.ram.read().await.all_locks() {
        lock_map.entry(rec.parent_lock).or_insert((rec, rv.0));
    }

    let mut locks = Vec::new();
    for (record, root_valid_until) in lock_map.into_values() {
        let parent_hex = hex::encode(record.parent_lock);
        let id_hex = hex::encode(record.id);
        if !locators.contains(&parent_hex) && !locators.contains(&id_hex) {
            locks.push(LockRecordDto::from_record(&record, root_valid_until));
        }
    }

    // Read HMC locks from persistent disk storage and in-memory RAM
    let mut hmc_map = std::collections::HashMap::new();
    if let Ok(disk_hmc_locks) = state.storage.all_valid_hmc_locks(0) {
        for (tag, entry) in disk_hmc_locks {
            hmc_map.insert(tag, entry);
        }
    }
    for (tag, entry) in state.engine.hmc_ram.read().await.locks.clone() {
        hmc_map.entry(tag).or_insert(entry);
    }

    for (tag, entry) in hmc_map {
        let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let parent_hex = hex::encode(parent_bytes);
        let id_hex = hex::encode(entry.t_id);
        if !locators.contains(&parent_hex) && !locators.contains(&tag) && !locators.contains(&id_hex) {
            let valid_until_ms = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let rec = humoco_sim_core::types::LockRecord {
                id: entry.t_id,
                parent_lock: parent_bytes,
                receiver_pub: entry.receiver_ephemeral_pub_hash.unwrap_or_default(),
                nonce: blake3::hash(entry.t_id.as_slice()).as_bytes().to_vec(),
                created_at: SimTime(entry.encrypted_timestamp as u64),
                valid_until: SimTime(valid_until_ms),
                status: humoco_sim_core::types::LockStatus::Final { sigs: 1 },
                signers: Default::default(),
            };
            locks.push(LockRecordDto::from_record(&rec, valid_until_ms));
        }
    }

    (StatusCode::OK, Json(SyncResponse { locks }))
}

/// Handler for GET /v1/pow-challenge
async fn get_pow_challenge(
    State(state): State<AppState>,
) -> (StatusCode, Json<PowChallengeResponse>) {
    let (challenge, difficulty, expires_at) = state.pow_engine.generate_challenge();
    (
        StatusCode::OK,
        Json(PowChallengeResponse {
            challenge,
            difficulty,
            expires_at,
        }),
    )
}

/// Handler for GET /health and GET /v1/status
async fn get_node_status(
    State(state): State<AppState>,
) -> (StatusCode, Json<NodeStatusResponse>) {
    let total_locks = state.engine.ram.read().await.len();
    let network = match state.network_id {
        humoco_sim_core::types::NetworkId::Mainnet => "mainnet".to_string(),
        humoco_sim_core::types::NetworkId::Testnet => "testnet".to_string(),
    };
    (
        StatusCode::OK,
        Json(NodeStatusResponse {
            status: "ok".into(),
            node_id: state.identity.node_id_hex(),
            public_key: state.identity.public_key_hex(),
            version: env!("CARGO_PKG_VERSION").into(),
            total_locks,
            network,
        }),
    )
}

/// Handler for GET /peers and GET /api/v1/network/peers (PEX Client Discovery)
async fn get_peers(
    State(state): State<AppState>,
) -> (StatusCode, Json<PeersResponse>) {
    let network = match state.network_id {
        humoco_sim_core::types::NetworkId::Mainnet => "mainnet".to_string(),
        humoco_sim_core::types::NetworkId::Testnet => "testnet".to_string(),
    };

    let (active_nodes_count, peers) = if let Some(ref pm) = state.peer_manager {
        let count = pm.active_nodes_count();
        let known_peers = pm.get_pex_peers().await;
        let mut peer_dtos = Vec::with_capacity(known_peers.len());
        for kinfo in known_peers {
            let last_seen_epoch = state.net_time_ms() / 1000;
            peer_dtos.push(PeerEntryDto {
                node_id: hex::encode(kinfo.node_pubkey),
                url: format!("https://{}", kinfo.addr),
                advertised_p2p: Some(kinfo.addr.to_string()),
                last_seen_epoch,
            });
        }
        (count, peer_dtos)
    } else {
        (1, Vec::new())
    };

    (
        StatusCode::OK,
        Json(PeersResponse {
            network,
            active_nodes_count,
            peers,
        }),
    )
}


/// Creates and signs an attestation for a lock ID with the NodeIdentity using canonical SigDigest with domain separation.
pub fn create_attestation_for_network(
    identity: &NodeIdentity,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
    status: u8,
    timestamp_ms: u64,
    network_id: humoco_sim_core::types::NetworkId,
) -> AttestationDto {
    let node_id_u16 = identity.node_id_u16();
    let domain_tag = if status == 1 {
        humoco_sim_core::crypto::domain_approve_final(network_id)
    } else {
        humoco_sim_core::crypto::domain_approve_prov(network_id)
    };
    let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
        domain_tag,
        0,
        0,
        0,
        shard_id,
        status,
        &lock_id,
    );
    let signature = identity.signing_key().sign(&sig_digest);
    AttestationDto {
        lock_id: hex::encode(lock_id),
        parent_lock: hex::encode(parent_lock),
        node_id: node_id_u16,
        timestamp: timestamp_ms,
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Creates and signs an attestation for a lock ID with the NodeIdentity (defaults to Mainnet).
pub fn create_attestation(
    identity: &NodeIdentity,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
    status: u8,
    timestamp_ms: u64,
) -> AttestationDto {
    create_attestation_for_network(
        identity,
        lock_id,
        parent_lock,
        shard_id,
        status,
        timestamp_ms,
        humoco_sim_core::types::NetworkId::Mainnet,
    )
}


// ---------------------------------------------------------------------------
// Shared quorum helpers — extracted from assemble_quorum_certificate and
// assemble_status_quorum_certificate to eliminate duplicated bitmap and
// JoinSet fanout / attestation verification logic.
// ---------------------------------------------------------------------------

/// Computes the 32-bit signer bitmap for a quorum certificate.
/// Ranks all active HRW ids plus self by HRW score, truncates to 32, and
/// maps each collected signature's node_id to its HRW rank bit position.
fn compute_signer_bitmap(
    active_for_bitmap: Vec<([u8; 32], std::net::SocketAddr)>,
    self_hrw: [u8; 32],
    shard_id: u16,
    collected_signatures: &[AttestationDto],
) -> u32 {
    let mut all_ids: Vec<[u8; 32]> = active_for_bitmap.into_iter().map(|(nid, _)| nid).collect();
    all_ids.push(self_hrw);
    all_ids.sort_by(|a, b| {
        let sa = humoco_sim_core::client_flow::compute_hrw_score_f64(a, shard_id);
        let sb = humoco_sim_core::client_flow::compute_hrw_score_f64(b, shard_id);
        sb.total_cmp(&sa)
    });
    all_ids.truncate(32);
    let mut bitmap: u32 = 0;
    for sig in collected_signatures {
        for (idx, nid) in all_ids.iter().enumerate() {
            let nid_u16 = u16::from_be_bytes([nid[0], nid[1]]);
            if nid_u16 == sig.node_id {
                bitmap |= 1u32 << idx;
                break;
            }
        }
    }
    bitmap
}

/// Verifies a peer attestation's cryptographic fields and HRW binding.
/// Checks verifying-key existence, signature/lock_id hex decoding, lock_id
/// equality, and Ed25519 `verify_strict` against the canonical sig digest.
/// Returns `true` only when fully valid; logs warnings otherwise.
async fn verify_peer_attestation(
    peer_mgr: &crate::network::PeerManager,
    att: &AttestationDto,
    expected_lock_id: [u8; 32],
    shard_id: u16,
    target_status: u8,
) -> bool {
    let vk = match peer_mgr.get_peer_verifying_key(att.node_id).await {
        Some(k) => k,
        None => {
            tracing::warn!(
                node_id = att.node_id,
                "Dropped attestation: peer verifying key not found in peer manager"
            );
            return false;
        }
    };

    let sig_bytes = match hex::decode(&att.signature) {
        Ok(b) if b.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            tracing::warn!(node_id = att.node_id, "Dropped attestation: invalid signature length");
            return false;
        }
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let att_lock_id_bytes = match hex::decode(&att.lock_id) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            tracing::warn!(node_id = att.node_id, "Dropped attestation: invalid lock_id hex");
            return false;
        }
    };

    if att_lock_id_bytes != expected_lock_id {
        tracing::warn!(node_id = att.node_id, "Dropped attestation: lock_id mismatch");
        return false;
    }

    let domain_tag = if target_status == 1 {
        humoco_sim_core::crypto::DOMAIN_APPROVE_FINAL
    } else {
        humoco_sim_core::crypto::DOMAIN_APPROVE_PROV
    };
    let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
        domain_tag, 0, 0, 0, shard_id, target_status, &expected_lock_id,
    );

    if let Err(e) = vk.verify_strict(&sig_digest, &sig) {
        tracing::warn!(
            node_id = att.node_id,
            error = %e,
            "Dropped attestation: cryptographic signature verification failed"
        );
        return false;
    }
    true
}

/// Parameters for querying peer attestations via QUIC.
struct PeerAttestationQuery<'a> {
    transport: &'a crate::network::QuicTransport,
    peer_mgr: &'a crate::network::PeerManager,
    candidate_nodes: &'a [([u8; 32], std::net::SocketAddr)],
    msg_type: humoco_sim_core::wire::MsgType,
    resp_msg_type: humoco_sim_core::wire::MsgType,
    payload: &'a [u8],
    target_status: u8,
    lock_id: [u8; 32],
    shard_id: u16,
    required_q: usize,
    shard_query_depth: usize,
}

/// Collects peer attestations across top HRW candidates with pipelined JoinSet fanout,
/// early-exit on required quorum, and DoS-resilient correlated timeout dampening (INV-1501).
async fn collect_peer_attestations(
    query: PeerAttestationQuery<'_>,
    collected_signatures: &mut Vec<AttestationDto>,
) {
    let header = humoco_sim_core::wire::WireHeader::new(
        query.msg_type as u16,
        1,
        0,
        query.target_status as u32,
        query.payload.len() as u32,
    );

    let mut timeout_addrs = Vec::new();
    let mut candidate_idx = 0;
    let mut total_queried = 0;
    let mut in_flight = std::collections::HashMap::new();

    let _ = tokio::time::timeout(std::time::Duration::from_millis(1000), async {
        let mut join_set = tokio::task::JoinSet::new();

        let spawn_next = |join_set: &mut tokio::task::JoinSet<_>, idx: &mut usize, t_queried: &mut usize, in_flight: &mut std::collections::HashMap<usize, (std::net::SocketAddr, usize)>| {
            if *idx < query.candidate_nodes.len() {
                let (nid, addr) = query.candidate_nodes[*idx];
                let rank_idx = *idx;
                *idx += 1;
                *t_queried += 1;

                in_flight.insert(rank_idx, (addr, rank_idx));

                let t = query.transport.clone();
                let h = header;
                let p = query.payload.to_vec();
                let exp_resp = query.resp_msg_type as u16;
                join_set.spawn(async move {
                    let query_peer = async {
                        let conn = t.connect_peer(addr).await.map_err(|_| ())?;
                        let (resp_header, resp_payload) = t.send_request(&conn, &h, &p).await.map_err(|_| ())?;
                        if resp_header.msg_type == exp_resp && !resp_payload.is_empty() {
                            if let Ok(att) = bincode::deserialize::<AttestationDto>(&resp_payload) {
                                return Ok(att);
                            }
                        }
                        Err(())
                    };
                    match query_peer.await {
                        Ok(att) => (nid, addr, rank_idx, Some(att)),
                        Err(_) => (nid, addr, rank_idx, None),
                    }
                });
            }
        };

        let needed = query.required_q.saturating_sub(collected_signatures.len());
        let initial_spawns = (needed + query.shard_query_depth).min(query.candidate_nodes.len());
        for _ in 0..initial_spawns {
            spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
        }

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((_nid, addr, rank_idx, Some(att))) => {
                    in_flight.remove(&rank_idx);

                    if collected_signatures.iter().any(|s| s.node_id == att.node_id) {
                        spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                        continue;
                    }

                    if !verify_peer_attestation(query.peer_mgr, &att, query.lock_id, query.shard_id, query.target_status).await {
                        if rank_idx < 20 {
                            query.peer_mgr.record_failure(addr).await;
                        }
                        spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                        continue;
                    }

                    query.peer_mgr.record_success(addr, None, None).await;
                    collected_signatures.push(att);

                    // Early return as soon as required quorum is reached
                    if collected_signatures.len() >= query.required_q {
                        join_set.abort_all();
                        in_flight.clear(); // Aborted stragglers must NEVER be counted as peer failures (AGENTS.md / INV-1501)
                        break;
                    }
                }
                Ok((_nid, addr, rank_idx, None)) => {
                    in_flight.remove(&rank_idx);
                    timeout_addrs.push((addr, rank_idx));
                    spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                }
                Err(_) => {
                    // Task cancelled/panicked
                }
            }
        }
    }).await;

    // Any in-flight tasks that didn't complete when global timeout hit are also timeouts
    for (_, (addr, rank_idx)) in in_flight {
        timeout_addrs.push((addr, rank_idx));
    }

    // 🛡️ Correlated failure protection (KISS / INV-1501):
    let total_queried_top20 = total_queried.min(20);
    let failed_top20 = timeout_addrs.iter().filter(|(_, rank)| *rank < 20).count();
    let is_correlated_failure = total_queried_top20 >= 2 && failed_top20 * 2 > total_queried_top20;

    if is_correlated_failure {
        tracing::warn!(
            failed = failed_top20,
            total = total_queried_top20,
            "Correlated timeout detected (>50% failed) - suppressing peer failure penalties (DoS protection)"
        );
    } else {
        for (addr, rank_idx) in timeout_addrs {
            if rank_idx < 20 {
                query.peer_mgr.record_failure(addr).await;
            }
        }
    }
}

/// Assembles a quorum certificate for a lock by collecting signatures from top-20 HRW nodes
/// or creating a local standalone certificate when N=1 or no peers are available.
async fn assemble_quorum_certificate(
    state: &AppState,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
    now_ms: u64,
    record_payload: Option<Vec<u8>>,
) -> QuorumCertificateDto {
    let local_attestation = create_attestation_for_network(&state.identity, lock_id, parent_lock, shard_id, 0, now_ms, state.network_id);
    let mut collected_signatures = Vec::new();

    let mut should_include_self = true;
    let self_hrw = *state.identity.hrw_routing_id();

    if let Some(peer_mgr) = &state.peer_manager {
        let active_nodes = peer_mgr.active_hrw_nodes().await;
        if !active_nodes.is_empty() {
            let self_score = humoco_sim_core::client_flow::compute_hrw_score_f64(&self_hrw, shard_id);
            let higher_nodes_count = active_nodes
                .iter()
                .filter(|(hrw_id, _)| {
                    if hrw_id == &self_hrw {
                        return false;
                    }
                    let score = humoco_sim_core::client_flow::compute_hrw_score_f64(hrw_id, shard_id);
                    score > self_score || (score == self_score && hrw_id > &self_hrw)
                })
                .count();

            let total_active = active_nodes.len() + 1; // include self
            let (required_q, is_final) = humoco_sim_core::types::required_quorum(total_active);
            let target_status: u8 = if is_final && peer_mgr.is_network_stable_ge20_for_24h(now_ms) { 1 } else { 0 };
            let local_attestation = create_attestation_for_network(&state.identity, lock_id, parent_lock, shard_id, target_status, now_ms, state.network_id);

            // Self rank is 1 + number of nodes with higher HRW score
            let self_rank = higher_nodes_count + 1;
            if self_rank > 20 {
                should_include_self = false;
            }

            if should_include_self {
                collected_signatures.push(local_attestation);
            }

            let active_for_bitmap = active_nodes.clone();
            let mut candidate_nodes = active_nodes;
            candidate_nodes.sort_by(|a, b| {
                let score_a = humoco_sim_core::client_flow::compute_hrw_score_f64(&a.0, shard_id);
                let score_b = humoco_sim_core::client_flow::compute_hrw_score_f64(&b.0, shard_id);
                score_b.total_cmp(&score_a)
            });

            if let (Some(transport), Some(payload)) = (&state.transport, record_payload) {
                collect_peer_attestations(
                    PeerAttestationQuery {
                        transport,
                        peer_mgr,
                        candidate_nodes: &candidate_nodes,
                        msg_type: humoco_sim_core::wire::MsgType::LockVerifyRequest,
                        resp_msg_type: humoco_sim_core::wire::MsgType::LockVerifyResponse,
                        payload: &payload,
                        target_status,
                        lock_id,
                        shard_id,
                        required_q,
                        shard_query_depth: state.shard_query_depth,
                    },
                    &mut collected_signatures,
                ).await;
            }

            let status = if collected_signatures.len() >= required_q && target_status == 1 {
                1
            } else {
                0
            };

            let signer_bitmap = compute_signer_bitmap(active_for_bitmap, self_hrw, shard_id, &collected_signatures);

            QuorumCertificateDto {
                lock_id: hex::encode(lock_id),
                shard_id,
                status,
                active_nodes_count: total_active,
                signer_count: collected_signatures.len(),
                signatures: collected_signatures,
                signer_bitmap,
            }
        } else {
            QuorumCertificateDto {
                lock_id: hex::encode(lock_id),
                shard_id,
                status: 0,
                active_nodes_count: 1,
                signer_count: 1,
                signatures: vec![local_attestation],
                signer_bitmap: 1,
            }
        }
    } else {
        QuorumCertificateDto {
            lock_id: hex::encode(lock_id),
            shard_id,
            status: 0,
            active_nodes_count: 1,
            signer_count: 1,
            signatures: vec![local_attestation],
            signer_bitmap: 1,
        }
    }
}

/// Assembles a quorum certificate for a status query by collecting signatures from active shard nodes
/// or creating a local standalone certificate when in village/bootstrap mode (N=1) or no peers are available.
/// Adaptive quorum logic caps the requested read_quorum by active_nodes_count.
async fn assemble_status_quorum_certificate(
    state: &AppState,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
    now_ms: u64,
    read_quorum: u8,
) -> QuorumCertificateDto {
    let mut collected_signatures = Vec::new();
    let mut should_include_self = true;
    let self_hrw = *state.identity.hrw_routing_id();

    if let Some(peer_mgr) = &state.peer_manager {
        let active_nodes = peer_mgr.active_hrw_nodes().await;
        if !active_nodes.is_empty() {
            let total_active = active_nodes.len() + 1;
            let required_q = (read_quorum as usize).min(total_active).max(1);
            let target_status: u8 = if required_q >= 20 || (total_active >= 20 && required_q >= 14) { 1 } else { 0 };

            let self_score = humoco_sim_core::client_flow::compute_hrw_score_f64(&self_hrw, shard_id);
            let higher_nodes_count = active_nodes
                .iter()
                .filter(|(hrw_id, _)| {
                    if hrw_id == &self_hrw {
                        return false;
                    }
                    let score = humoco_sim_core::client_flow::compute_hrw_score_f64(hrw_id, shard_id);
                    score > self_score || (score == self_score && hrw_id > &self_hrw)
                })
                .count();
            let self_rank = higher_nodes_count + 1;
            if self_rank > 20 {
                should_include_self = false;
            }

            let local_attestation = create_attestation(
                &state.identity,
                lock_id,
                parent_lock,
                shard_id,
                target_status,
                now_ms,
            );
            if should_include_self {
                collected_signatures.push(local_attestation);
            }

            let active_for_bitmap = active_nodes.clone();
            let mut candidate_nodes = active_nodes;
            candidate_nodes.sort_by(|a, b| {
                let score_a = humoco_sim_core::client_flow::compute_hrw_score_f64(&a.0, shard_id);
                let score_b = humoco_sim_core::client_flow::compute_hrw_score_f64(&b.0, shard_id);
                score_b.total_cmp(&score_a)
            });
            candidate_nodes.truncate(32);

            if collected_signatures.len() < required_q {
                if let Some(transport) = &state.transport {
                    let payload = bincode::serialize(&(lock_id, parent_lock, shard_id)).unwrap_or_default();
                    collect_peer_attestations(
                        PeerAttestationQuery {
                            transport,
                            peer_mgr,
                            candidate_nodes: &candidate_nodes,
                            msg_type: humoco_sim_core::wire::MsgType::StatusQuery,
                            resp_msg_type: humoco_sim_core::wire::MsgType::StatusResponse,
                            payload: &payload,
                            target_status,
                            lock_id,
                            shard_id,
                            required_q,
                            shard_query_depth: state.shard_query_depth,
                        },
                        &mut collected_signatures,
                    ).await;
                }
            }

            let status = if collected_signatures.len() >= required_q && target_status == 1 {
                1
            } else {
                0
            };

            let signer_bitmap = compute_signer_bitmap(active_for_bitmap, self_hrw, shard_id, &collected_signatures);

            QuorumCertificateDto {
                lock_id: hex::encode(lock_id),
                shard_id,
                status,
                active_nodes_count: total_active,
                signer_count: collected_signatures.len(),
                signatures: collected_signatures,
                signer_bitmap,
            }
        } else {
            let local_attestation = create_attestation(&state.identity, lock_id, parent_lock, shard_id, 0, now_ms);
            QuorumCertificateDto {
                lock_id: hex::encode(lock_id),
                shard_id,
                status: 0,
                active_nodes_count: 1,
                signer_count: 1,
                signatures: vec![local_attestation],
                signer_bitmap: 1,
            }
        }
    } else {
        let local_attestation = create_attestation(&state.identity, lock_id, parent_lock, shard_id, 0, now_ms);
        QuorumCertificateDto {
            lock_id: hex::encode(lock_id),
            shard_id,
            status: 0,
            active_nodes_count: 1,
            signer_count: 1,
            signatures: vec![local_attestation],
            signer_bitmap: 1,
        }
    }
}

/// Handler for POST /status and POST /v1/status
async fn query_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<L2StatusQuery>,
) -> Response {
    let epoch_day = state.tier_controller.current_epoch_day();
    let client_node_id: u16 = if let Some(auth) = headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        let tag = state.tier_controller.resolve_account_tag(auth).unwrap_or([0u8; 32]);
        u16::from_be_bytes([tag[0], tag[1]])
    } else if let Some(peer_token) = headers.get("X-Peer-Token").and_then(|h| h.to_str().ok()) {
        let hash = *blake3::hash(peer_token.as_bytes()).as_bytes();
        u16::from_be_bytes([hash[0], hash[1]])
    } else {
        let v_hash = *blake3::hash(payload.layer2_voucher_id.as_bytes()).as_bytes();
        u16::from_be_bytes([v_hash[0], v_hash[1]])
    };

    let read_credits = 1;
    if let Err(ingress_err) = state.tier_controller.evaluate_read_quota(client_node_id, read_credits, epoch_day, 1.0) {
        let reason = match ingress_err {
            IngressError::ReadQuotaExceeded { available, required } => {
                format!(
                    "429 Read quota exceeded: required {} reads, available {}",
                    required, available
                )
            }
            _ => "429 Read quota exceeded".into(),
        };
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected { reason },
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(envelope),
        )
            .into_response();
    }

    let hmc = state.engine.hmc_ram.read().await;
    let verdict = hmc.query_status(
        &payload.layer2_voucher_id,
        &payload.challenge_ds_tag,
        &payload.locator_prefixes,
    );
    drop(hmc);

    let quorum_certificate = if payload.read_quorum > 1 {
        let voucher_bytes = *blake3::hash(payload.layer2_voucher_id.as_bytes()).as_bytes();
        let shard_id = u16::from_be_bytes([voucher_bytes[0], voucher_bytes[1]]);
        let (lock_id, parent_lock) = match &verdict {
            L2Verdict::Verified { lock_entry } => {
                (lock_entry.t_id, *blake3::hash(payload.challenge_ds_tag.as_bytes()).as_bytes())
            }
            L2Verdict::Conflict { existing_lock } => {
                (existing_lock.t_id, *blake3::hash(payload.challenge_ds_tag.as_bytes()).as_bytes())
            }
            _ => {
                let ch_hash = *blake3::hash(payload.challenge_ds_tag.as_bytes()).as_bytes();
                (ch_hash, voucher_bytes)
            }
        };
        let now_ms = state.net_time_ms();
        Some(assemble_status_quorum_certificate(&state, lock_id, parent_lock, shard_id, now_ms, payload.read_quorum).await)
    } else {
        None
    };

    let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, quorum_certificate);
    (StatusCode::OK, Json(envelope)).into_response()
}

/// Dedicated handler for HMC L2LockRequest
async fn submit_hmc_lock(
    state: AppState,
    headers: HeaderMap,
    req: L2LockRequest,
    start: std::time::Instant,
) -> Response {
    // 0. Check if submitter or ephemeral key is banned/slashed
    if state.engine.is_node_banned(&req.sender_ephemeral_pub).await
        || state.engine.is_node_banned(&req.auth.ephemeral_pubkey).await
    {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "403 Forbidden: Signer is slashed and banned due to equivocation fraud".into(),
            },
        );
        return (StatusCode::FORBIDDEN, Json(envelope)).into_response();
    }

    // 1. Verify V3 signature
    if !verify_l2_lock_signature(&req) {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Invalid cryptographic signature".into(),
            },
        );
        return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
    }

    // Lifecycle sunset & bridge lock checks
    let suite_id = if req.privacy_guard.as_deref().is_some_and(|s| s.contains("suite2")) { 2 } else { 1 };

    if req.privacy_guard.as_deref() == Some("bridge_missing_pqc") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "InvalidBridgeLock".into(),
                message: "400 Bad Request: Quantum bridge lock requires pqc_receiver".into(),
                challenge: None,
                difficulty: None,
                expires_at: None,
            }),
        )
            .into_response();
    }

    if let Some(reject_time) = state.lifecycle.reject_deprecated_suite_after {
        if (state.net_time_ms() / 1000) >= reject_time && suite_id == 1 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "CryptoSuiteDeprecated".into(),
                    message: "400 Bad Request: Suite 1 (Ed25519) has reached final sunset".into(),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response();
        }
    }

    let should_warn = state
        .lifecycle
        .warn_deprecated_suite_after
        .is_some_and(|warn_time| (state.net_time_ms() / 1000) >= warn_time && suite_id == 1);
    let now_ms = state.net_time_ms();
    let stored_root_valid = state
        .engine
        .get_hmc_voucher_root_valid(&req.layer2_voucher_id)
        .await;

    let parsed_deletable = req
        .deletable_at
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok());

    let (valid_until, root_valid_until) = if req.is_genesis {
        // Genesis Lock: deletable_at is mandatory and defines the immutable root_valid_until
        let del = match parsed_deletable {
            Some(d) => d,
            None => {
                let envelope = wrap_and_sign_verdict(
                    &state.identity,
                    L2Verdict::Rejected {
                        reason: "Genesis lock requires valid deletable_at timestamp".into(),
                    },
                );
                return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
            }
        };
        (del, del)
    } else {
        // Follow-up Lock (Transfer / Split / Spend):
        // Must verify against the origin root lock! Gateway cannot falsify root validity or cheat byte-years.
        let root = match stored_root_valid {
            Some(r) => r,
            None => {
                let envelope = wrap_and_sign_verdict(
                    &state.identity,
                    L2Verdict::Rejected {
                        reason: "Unknown voucher root: genesis lock must be anchored first".into(),
                    },
                );
                return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
            }
        };
        let valid = parsed_deletable.unwrap_or(root);
        (valid, root)
    };

    if !humoco_sim_core::storage::ingress_time_window_valid(
        SimTime(now_ms),
        SimTime(valid_until),
        SimTime(root_valid_until),
    ) {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Invalid ingress time window: now + 30s < valid_until <= root.valid_until violated".into(),
            },
        );
        return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
    }

    // 3. Determine lookup tag
    // For genesis: bs58(transaction_hash), for spend: ds_tag
    let lookup_tag = if req.is_genesis {
        bs58::encode(&req.transaction_hash).into_string()
    } else {
        match &req.ds_tag {
            Some(tag) if !tag.trim().is_empty() => tag.clone(),
            _ => {
                let envelope = wrap_and_sign_verdict(
                    &state.identity,
                    L2Verdict::Rejected {
                        reason: "Missing or empty ds_tag for non-genesis spend".into(),
                    },
                );
                return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
            }
        }
    };

    let entry = L2LockEntry::from(&req);

    // 4. Fast-path idempotency check: if identical lock already verified in RAM, return 200 OK immediately
    if let Some(existing) = state.engine.hmc_ram.read().await.locks.get(&lookup_tag) {
        if existing.t_id == entry.t_id {
            let verdict = L2Verdict::Verified { lock_entry: existing.clone() };
            let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
            let shard_id = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
            let now_ms = state.net_time_ms();
            let wire_payload = bincode::serialize(&crate::network::framing::LockWirePayload::Hmc {
                req: Box::new(req.clone()),
                root_valid_until,
            }).ok();
            let quorum_certificate = Some(assemble_quorum_certificate(&state, entry.t_id, parent_bytes, shard_id, now_ms, wire_payload).await);
            let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, quorum_certificate);
            state.metrics.record_pos_latency(start.elapsed());
            return (StatusCode::OK, Json(envelope)).into_response();
        }
    }

    // 5. Perform 3-Tier Access Evaluation with exact Byte-Years based on root validity
    // Storage space is occupied until root_valid_until! Gateway cannot cheat byte-years.
    let ttl_seconds = (root_valid_until.saturating_sub(now_ms)) / 1000;

    let auth_token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.strip_prefix("Bearer ").unwrap_or(s));
    let peer_token = headers.get("X-Peer-Token").and_then(|h| h.to_str().ok());
    let pow_challenge = headers.get("X-PoW-Challenge").and_then(|h| h.to_str().ok());
    let pow_nonce = headers
        .get("X-PoW-Nonce")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    if let Err(err) = state
        .tier_controller
        .evaluate_and_charge(
            auth_token,
            peer_token,
            pow_challenge,
            pow_nonce,
            ttl_seconds,
            None,
        )
        .await
    {
        let mut required_diff_hdr = None;
        let (status, reason) = match err {
            IngressError::PoWRequired { .. } => (
                StatusCode::UNAUTHORIZED,
                "Proof-of-Work challenge response required".into(),
            ),
            IngressError::InvalidPoW(err) => {
                if let crate::ingress::pow::PowError::InsufficientDifficulty { required, provided } = err {
                    required_diff_hdr = Some(required);
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("Gateway under load: insufficient PoW difficulty (provided: {}, required: {})", provided, required),
                    )
                } else {
                    (
                        StatusCode::UNAUTHORIZED,
                        format!("Invalid Proof of Work: {}", err),
                    )
                }
            }
            IngressError::QuotaExceeded { available, required } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "VIP Quota exceeded: required {} byte-years, available {}",
                    required, available
                ),
            ),
            IngressError::ReadQuotaExceeded { available, required } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Read quota exceeded: required {} reads, available {}",
                    required, available
                ),
            ),
            IngressError::InvalidAuthToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid VIP authentication token".into(),
            ),
            IngressError::InvalidPeerToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid F2F peer token".into(),
            ),
            IngressError::Storage(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            ),
        };
        if status == StatusCode::TOO_MANY_REQUESTS {
            state.metrics.record_lock_rejected();
        }
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected { reason },
        );
        let mut resp = (status, Json(envelope)).into_response();
        if let Some(req_diff) = required_diff_hdr {
            if let Ok(hdr_val) = axum::http::HeaderValue::from_str(&req_diff.to_string()) {
                resp.headers_mut().insert(
                    axum::http::HeaderName::from_static("x-required-difficulty"),
                    hdr_val,
                );
            }
        }
        return resp;
    }

    // 4. Ingress into DualTierEngine (ClientApi origin) with ingress window enforcement
    let (verdict, is_new) = state
        .engine
        .ingress_hmc_lock_with_origin(lookup_tag.clone(), entry.clone(), IngressOrigin::ClientApi, Some(now_ms))
        .await;

    // 5. Assemble QuorumCertificate for successful verdicts
    let quorum_certificate = match &verdict {
        L2Verdict::Conflict { .. } | L2Verdict::Rejected { .. } => None,
        _ => {
            let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
            let shard_id = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
            let now_ms = state.net_time_ms();
            let wire_payload = bincode::serialize(&crate::network::framing::LockWirePayload::Hmc {
                req: Box::new(req.clone()),
                root_valid_until,
            }).ok();
            Some(assemble_quorum_certificate(&state, entry.t_id, parent_bytes, shard_id, now_ms, wire_payload).await)
        }
    };

    // 6. Wrap and sign response envelope with appropriate HTTP status
    let status = match &verdict {
        L2Verdict::Conflict { .. } => {
            state.metrics.record_lock_rejected();
            StatusCode::CONFLICT
        }
        _ if is_new => {
            state.metrics.record_pos_latency(start.elapsed());
            StatusCode::CREATED
        }
        _ => {
            state.metrics.record_pos_latency(start.elapsed());
            StatusCode::OK
        }
    };
    let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, quorum_certificate);
    let mut resp = (status, Json(envelope)).into_response();
    if should_warn {
        resp.headers_mut().insert(
            axum::http::HeaderName::from_static("x-deprecation-warning"),
            axum::http::HeaderValue::from_static(
                "Suite 1 (Ed25519) deprecated - migrate to suite 2",
            ),
        );
    }
    resp
}

/// Handler for POST /v1/lock/chain – atomares Ketten-Locking
async fn submit_hmc_chain_lock(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(chain_req): Json<L2ChainLockRequest>,
) -> Response {
    let start = std::time::Instant::now();
    // Banned check for batch auth and each hop
    if state.engine.is_node_banned(&chain_req.auth.ephemeral_pubkey).await {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "403 Forbidden: Signer is slashed and banned due to equivocation fraud".into(),
            },
        );
        return (StatusCode::FORBIDDEN, Json(envelope)).into_response();
    }
    for hop in &chain_req.chain {
        if state.engine.is_node_banned(&hop.sender_ephemeral_pub).await
            || state.engine.is_node_banned(&hop.auth.ephemeral_pubkey).await
        {
            let envelope = wrap_and_sign_verdict(
                &state.identity,
                L2Verdict::Rejected {
                    reason: "403 Forbidden: Signer is slashed and banned due to equivocation fraud".into(),
                },
            );
            return (StatusCode::FORBIDDEN, Json(envelope)).into_response();
        }
    }

    let now_ms = state.net_time_ms();

    // Derive root_valid_until for Byte-Years accounting (same logic as engine)
    let stored_root = state
        .engine
        .get_hmc_voucher_root_valid(&chain_req.layer2_voucher_id)
        .await;
    let chain_genesis_root = chain_req
        .chain
        .iter()
        .find(|h| h.is_genesis)
        .and_then(|h| h.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()));
    let root_valid_until = stored_root.or(chain_genesis_root).unwrap_or(now_ms + 600_000);
    let ttl_seconds = root_valid_until.saturating_sub(now_ms) / 1000;

    // 3-Tier Access Evaluation (single charge for whole batch)
    let auth_token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.strip_prefix("Bearer ").unwrap_or(s));
    let peer_token = headers.get("X-Peer-Token").and_then(|h| h.to_str().ok());
    let pow_challenge = headers.get("X-PoW-Challenge").and_then(|h| h.to_str().ok());
    let pow_nonce = headers
        .get("X-PoW-Nonce")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    if let Err(err) = state
        .tier_controller
        .evaluate_and_charge(auth_token, peer_token, pow_challenge, pow_nonce, ttl_seconds, None)
        .await
    {
        let (status, reason) = match err {
            IngressError::PoWRequired { .. } => (
                StatusCode::UNAUTHORIZED,
                "Proof-of-Work challenge response required".into(),
            ),
            IngressError::InvalidPoW(e) => {
                if let crate::ingress::pow::PowError::InsufficientDifficulty { required, provided } = e {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("Gateway under load: insufficient PoW difficulty (provided: {}, required: {})", provided, required),
                    )
                } else {
                    (StatusCode::UNAUTHORIZED, format!("Invalid Proof of Work: {}", e))
                }
            }
            IngressError::QuotaExceeded { available, required } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!("VIP Quota exceeded: required {} byte-years, available {}", required, available),
            ),
            IngressError::ReadQuotaExceeded { available, required } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!("Read quota exceeded: required {} reads, available {}", required, available),
            ),
            IngressError::InvalidAuthToken => (StatusCode::UNAUTHORIZED, "Invalid VIP authentication token".into()),
            IngressError::InvalidPeerToken => (StatusCode::UNAUTHORIZED, "Invalid F2F peer token".into()),
            IngressError::Storage(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage error: {}", e)),
        };
        if status == StatusCode::TOO_MANY_REQUESTS {
            state.metrics.record_lock_rejected();
        }
        let envelope = wrap_and_sign_verdict(&state.identity, L2Verdict::Rejected { reason });
        return (status, Json(envelope)).into_response();
    }

    // Atomares Ketten-Locking via engine
    let (verdict, is_new) = state
        .engine
        .ingress_hmc_chain_lock(chain_req.clone(), IngressOrigin::ClientApi, Some(now_ms))
        .await;

    let quorum_certificate = match &verdict {
        L2Verdict::Verified { lock_entry } => {
            // Last hop lookup for shard derivation
            let last_hop = chain_req.chain.last().unwrap();
            let lookup_tag = if last_hop.is_genesis {
                bs58::encode(&last_hop.transaction_hash).into_string()
            } else {
                last_hop.ds_tag.clone().unwrap_or_default()
            };
            let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
            let shard_id = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
            let wire_payload = bincode::serialize(&crate::network::framing::LockWirePayload::Hmc {
                req: Box::new(last_hop.clone()),
                root_valid_until,
            })
            .ok();
            Some(
                assemble_quorum_certificate(
                    &state,
                    lock_entry.t_id,
                    parent_bytes,
                    shard_id,
                    now_ms,
                    wire_payload,
                )
                .await,
            )
        }
        _ => None,
    };

    let status = match &verdict {
        L2Verdict::Conflict { .. } => {
            state.metrics.record_lock_rejected();
            StatusCode::CONFLICT
        }
        L2Verdict::Rejected { reason } if reason.contains("backpressure") || reason.contains("congested") => {
            state.metrics.record_lock_rejected();
            StatusCode::TOO_MANY_REQUESTS
        }
        L2Verdict::Rejected { .. } => StatusCode::BAD_REQUEST,
        L2Verdict::Verified { .. } if is_new => {
            state.metrics.record_pos_latency(start.elapsed());
            StatusCode::CREATED
        }
        L2Verdict::Verified { .. } => {
            state.metrics.record_pos_latency(start.elapsed());
            StatusCode::OK
        }
        _ => {
            state.metrics.record_pos_latency(start.elapsed());
            StatusCode::OK
        }
    };
    let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, quorum_certificate);
    (status, Json(envelope)).into_response()
}

/// Handler for GET /health/live (Kubernetes/Systemd liveness probe)
async fn health_live() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({"status": "alive"})))
}

/// Handler for GET /health/ready (Readiness probe)
async fn health_ready(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let storage_ok = state.storage.all_banned_nodes().is_ok();
    let peers_ok = if let Some(ref pm) = state.peer_manager {
        let all_addrs = pm.all_peer_addrs().await;
        if all_addrs.is_empty() {
            true // Village mode N=1
        } else {
            pm.connected_peer_count().await > 0 || !pm.active_known_nodes().await.is_empty()
        }
    } else {
        true // Village mode N=1
    };

    if storage_ok && peers_ok {
        (StatusCode::OK, Json(serde_json::json!({"status": "ready"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not_ready",
                "storage_ok": storage_ok,
                "peers_ok": peers_ok
            })),
        )
    }
}
