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

static GOSSIP_SPAWN_SEMAPHORE: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(64));


use humoco_sim_core::storage::IngressVerdictLow;
use humoco_sim_core::types::{LockRecord, SimTime};

use crate::api::dto::{
    AttestationDto, ErrorResponse, LockRecordDto, LockSubmitRequest, LockSubmitResponse,
    NodeStatusResponse, PeerEntryDto, PeersResponse, PowChallengeResponse, QuorumCertificateDto,
    SyncRequest, SyncResponse,
};
use crate::api::hmc::{
    verify_l2_lock_signature, wrap_and_sign_verdict, wrap_and_sign_verdict_with_quorum,
    L2ChainLockRequest, L2LockEntry, L2LockRequest, L2StatusQuery, L2Verdict,
};
use crate::identity::NodeIdentity;
use crate::ingress::{IngressError, PowEngine, PowError, TierController};
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

/// Handler for POST /v1/lock and POST /lock
async fn submit_lock(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: bytes::Bytes,
) -> Response {
    let start = std::time::Instant::now();
    // Check if this is an HMC L2ChainLockRequest (batch) – must try before single lock
    if let Ok(chain_req) = serde_json::from_slice::<crate::api::hmc::L2ChainLockRequest>(&body_bytes) {
        return submit_hmc_chain_lock(State(state), headers, Json(chain_req)).await;
    }
    // Check if this is an HMC L2LockRequest
    if let Ok(hmc_req) = serde_json::from_slice::<L2LockRequest>(&body_bytes) {
        return submit_hmc_lock(state, headers, hmc_req, start).await;
    }

    // Otherwise try parsing as legacy/internal LockSubmitRequest
    let payload: LockSubmitRequest = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "InvalidRequest".into(),
                    message: format!("Failed to parse request JSON: {}", e),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response();
        }
    };

    // Step 3: Dual-stack / Sunset enforcement
    let suite_id = payload.crypto_suite.unwrap_or(1);

    // Sunset reject enforcement
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

    // Quantum-Bridge-Lock validation
    if payload.is_bridge_lock == Some(true) && payload.pqc_receiver.is_none() {
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

    let should_warn = state
        .lifecycle
        .warn_deprecated_suite_after
        .is_some_and(|warn_time| (state.net_time_ms() / 1000) >= warn_time && suite_id == 1);

    // 1. Parse parent_lock and receiver_pub hex
    let parent_lock_bytes = match hex::decode(&payload.parent_lock) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "InvalidParentLock".into(),
                    message: "parent_lock must be 32-byte hex string".into(),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response();
        }
    };

    let receiver_pub_bytes = match hex::decode(&payload.receiver_pub) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "InvalidReceiverPub".into(),
                    message: "receiver_pub must be 32-byte hex string".into(),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response();
        }
    };

    // 1.5 Check if sender is slashed/banned
    if state.engine.is_node_banned(&receiver_pub_bytes).await {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Forbidden".into(),
                message: "403 Forbidden: Signer is slashed and banned due to equivocation fraud".into(),
                challenge: None,
                difficulty: None,
                expires_at: None,
            }),
        )
            .into_response();
    }

    // Nonce
    let nonce_bytes = if let Ok(bytes) = hex::decode(&payload.nonce) {
        bytes
    } else {
        payload.nonce.as_bytes().to_vec()
    };

    // Extract auth credentials (headers or json fields)
    let auth_token = payload.auth_token.as_deref().or_else(|| {
        headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.strip_prefix("Bearer ").unwrap_or(s))
    });

    let peer_token = payload
        .peer_token
        .as_deref()
        .or_else(|| headers.get("X-Peer-Token").and_then(|h| h.to_str().ok()));

    let pow_challenge = payload
        .pow_challenge
        .as_deref()
        .or_else(|| headers.get("X-PoW-Challenge").and_then(|h| h.to_str().ok()));

    let pow_nonce = payload.pow_nonce.or_else(|| {
        headers
            .get("X-PoW-Nonce")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
    });

    // Determine reference time (Spec 11: net_time_ms):
    let real_now_ms = state.net_time_ms();

    if let Some(created_at) = payload.created_at {
        if created_at > real_now_ms.saturating_add(30_000) || real_now_ms.saturating_sub(created_at) > 86_400_000 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "ClockDriftExceeded".into(),
                    message: "created_at clock drift exceeds allowed window".into(),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response();
        }
    }

    let now_ms = payload.created_at.unwrap_or(real_now_ms);

    let ttl_seconds = (payload.root_valid_until.saturating_sub(now_ms)) / 1000;

    let existing_ram_lock = state.engine.get_ram_lock(&parent_lock_bytes).await;

    // 2. Perform 3-Tier Access Evaluation
    if let Err(ingress_err) = state.tier_controller.evaluate_and_charge(
        auth_token,
        peer_token,
        pow_challenge,
        pow_nonce,
        ttl_seconds,
        Some(&parent_lock_bytes),
    ).await {
        // Idempotency protection: Before rejecting a replay, check if the lock already exists in the RAM index.
        let is_idempotent_replay = if let IngressError::InvalidPoW(PowError::ReplayDetected) = &ingress_err {
            if let Some(ref existing) = existing_ram_lock {
                let candidate_created_at = payload.created_at.unwrap_or(existing.created_at.0);
                let candidate_record = LockRecord::new(
                    parent_lock_bytes,
                    receiver_pub_bytes,
                    nonce_bytes.clone(),
                    SimTime(candidate_created_at),
                    SimTime(payload.valid_until),
                );
                existing.id == candidate_record.id
            } else {
                false
            }
        } else {
            false
        };

        if !is_idempotent_replay {
            return match ingress_err {
                IngressError::PoWRequired {
                    challenge,
                    difficulty,
                    expires_at,
                } => (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "PoWRequired".into(),
                        message: "Proof-of-Work challenge response required".into(),
                        challenge: Some(challenge),
                        difficulty: Some(difficulty),
                        expires_at: Some(expires_at),
                    }),
                )
                    .into_response(),
                IngressError::InvalidPoW(err) => {
                    if let crate::ingress::pow::PowError::InsufficientDifficulty { required, provided } = err {
                        state.metrics.record_lock_rejected();
                        let (challenge, _, expires_at) = state.pow_engine.generate_challenge_for_parent(&parent_lock_bytes);
                        (
                            StatusCode::TOO_MANY_REQUESTS,
                            [
                                (axum::http::header::HeaderName::from_static("x-required-difficulty"), required.to_string()),
                            ],
                            Json(ErrorResponse {
                                error: "UnderLoad".into(),
                                message: format!(
                                    "Gateway under load: insufficient PoW difficulty (provided: {}, required: {})",
                                    provided, required
                                ),
                                challenge: Some(challenge),
                                difficulty: Some(required),
                                expires_at: Some(expires_at),
                            }),
                        )
                            .into_response()
                    } else {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(ErrorResponse {
                                error: "InvalidPoW".into(),
                                message: format!("Invalid Proof of Work: {}", err),
                                challenge: None,
                                difficulty: None,
                                expires_at: None,
                            }),
                        )
                            .into_response()
                    }
                }
            IngressError::QuotaExceeded {
                available,
                required,
            } => {
                state.metrics.record_lock_rejected();
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: "QuotaExceeded".into(),
                        message: format!(
                            "VIP Quota exceeded: required {} byte-years, available {}",
                            required, available
                        ),
                        challenge: None,
                        difficulty: None,
                        expires_at: None,
                    }),
                )
                    .into_response()
            }
            IngressError::ReadQuotaExceeded {
                available,
                required,
            } => {
                state.metrics.record_lock_rejected();
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: "ReadQuotaExceeded".into(),
                        message: format!(
                            "Read quota exceeded: required {} reads, available {}",
                            required, available
                        ),
                        challenge: None,
                        difficulty: None,
                        expires_at: None,
                    }),
                )
                    .into_response()
            }
            IngressError::InvalidAuthToken => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "InvalidAuthToken".into(),
                    message: "Invalid VIP authentication token".into(),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response(),
            IngressError::InvalidPeerToken => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "InvalidPeerToken".into(),
                    message: "Invalid F2F peer token".into(),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response(),
            IngressError::Storage(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "StorageError".into(),
                    message: format!("Storage error during ingress: {}", err),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response(),
            };
        }
    }

    // 3. Construct LockRecord
    let fallback_created_at = existing_ram_lock.as_ref().map(|ex| ex.created_at.0).unwrap_or(now_ms);
    let created_at_ms = payload.created_at.unwrap_or(fallback_created_at);
    let record = LockRecord::new(
        parent_lock_bytes,
        receiver_pub_bytes,
        nonce_bytes,
        SimTime(created_at_ms),
        SimTime(payload.valid_until),
    );
    let lock_id_hex = hex::encode(record.id);

    // 4. Ingress into DualTierEngine (ClientApi origin)
    let verdict = state
        .engine
        .ingress_lock_with_origin(
            record.clone(),
            SimTime(real_now_ms),
            SimTime(payload.root_valid_until),
            IngressOrigin::ClientApi,
        )
        .await;

    let shard_id = u16::from_be_bytes([record.parent_lock[0], record.parent_lock[1]]);
    let payload_bytes = bincode::serialize(&crate::network::framing::LockWirePayload::Sim(
        record.clone(),
        payload.root_valid_until,
    )).ok();
    let quorum_certificate = if matches!(
        verdict,
        Ok(IngressVerdictLow::AcceptedNew) | Ok(IngressVerdictLow::IdempotentReplay)
    ) {
        Some(
            assemble_quorum_certificate(
                &state,
                record.id,
                record.parent_lock,
                shard_id,
                now_ms,
                payload_bytes,
            )
            .await,
        )
    } else {
        None
    };

    match verdict {
        Ok(IngressVerdictLow::AcceptedNew) => {
            let attestation = create_attestation_for_network(&state.identity, record.id, record.parent_lock, shard_id, 0, now_ms, state.network_id);

            // Gossip newly accepted lock to F2F peers via QUIC transport if available
            if let Some(ref transport) = state.transport {
                if let Some(ref peer_mgr) = state.peer_manager {
                    peer_mgr.check_and_record_seen_gossip(&record.id);
                    // Pre-spawn semaphore check: zero allocations when saturated
                    match GOSSIP_SPAWN_SEMAPHORE.try_acquire() {
                        Err(_) => {
                            tracing::warn!("Outgoing gossip spawn dropped: limit reached (64)");
                        }
                        Ok(permit) => {
                            let transport = transport.clone();
                            let peer_mgr = peer_mgr.clone();
                            let record_clone = record.clone();
                            let root_valid_until = payload.root_valid_until;
                            let cancel_token = transport.cancel_token().clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                if cancel_token.is_cancelled() {
                                    return;
                                }
                        tokio::select! {
                            _ = cancel_token.cancelled() => {}
                            _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                                let peers = peer_mgr.f2f_peer_addrs().await;
                                let d = peers.len();
                                if d > 0 {
                                    let k = crate::network::manager::calculate_fan_out(d);
                                    let mut selected_peers = peers;
                                    if k < d {
                                        use rand::seq::SliceRandom;
                                        let mut rng = rand::thread_rng();
                                        selected_peers.shuffle(&mut rng);
                                        selected_peers.truncate(k);
                                    }
                                    if let Ok(bytes) = bincode::serialize(&(record_clone, root_valid_until)) {
                                        let header = humoco_sim_core::wire::WireHeader::new(
                                            humoco_sim_core::wire::MsgType::GossipAnnounce as u16,
                                            1,
                                            0,
                                            0,
                                            bytes.len() as u32,
                                        );
                                        for peer_addr in selected_peers {
                                            if cancel_token.is_cancelled() {
                                                break;
                                            }
                                            if let Ok(Ok(conn)) = tokio::time::timeout(
                                                std::time::Duration::from_millis(500),
                                                transport.connect_peer(peer_addr),
                                            )
                                            .await
                                            {
                                                let _ = tokio::time::timeout(
                                                    std::time::Duration::from_millis(500),
                                                    transport.send_unidirectional(&conn, &header, &bytes),
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                }
                            }) => {}
                                };
                            });
                        }
                    }
                }
            }

            state.metrics.record_pos_latency(start.elapsed());
            let mut resp = (
                StatusCode::CREATED,
                Json(LockSubmitResponse {
                    status: "ACCEPTED".into(),
                    lock_id: lock_id_hex,
                    attestation: Some(attestation),
                    quorum_certificate,
                    reason: None,
                }),
            )
                .into_response();
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
        Ok(IngressVerdictLow::IdempotentReplay) => {
            state.metrics.record_pos_latency(start.elapsed());
            let attestation = create_attestation_for_network(&state.identity, record.id, record.parent_lock, shard_id, 0, now_ms, state.network_id);
            let mut resp = (
                StatusCode::OK,
                Json(LockSubmitResponse {
                    status: "IDEMPOTENT".into(),
                    lock_id: lock_id_hex,
                    attestation: Some(attestation),
                    quorum_certificate,
                    reason: None,
                }),
            )
                .into_response();
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
        Ok(IngressVerdictLow::RejectedCollision) | Err(IngressVerdictLow::RejectedCollision) => {
            state.metrics.record_lock_rejected();
            (
                StatusCode::CONFLICT,
                Json(LockSubmitResponse {
                    status: "REJECTED".into(),
                    lock_id: lock_id_hex,
                    attestation: None,
                    quorum_certificate: None,
                    reason: Some("Double-spend collision detected on parent lock".into()),
                }),
            )
                .into_response()
        }
        Ok(IngressVerdictLow::RejectedWindow) | Err(IngressVerdictLow::RejectedWindow) => (
            StatusCode::BAD_REQUEST,
            Json(LockSubmitResponse {
                status: "REJECTED".into(),
                lock_id: lock_id_hex,
                attestation: None,
                quorum_certificate: None,
                reason: Some("Invalid ingress time window".into()),
            }),
        )
            .into_response(),
        Ok(IngressVerdictLow::RejectedCapacity) | Err(IngressVerdictLow::RejectedCapacity) => {
            state.metrics.record_lock_rejected();
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(LockSubmitResponse {
                    status: "REJECTED".into(),
                    lock_id: lock_id_hex,
                    attestation: None,
                    quorum_certificate: None,
                    reason: Some("Persistence queue congested (backpressure)".into()),
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(LockSubmitResponse {
                status: "REJECTED".into(),
                lock_id: lock_id_hex,
                attestation: None,
                quorum_certificate: None,
                reason: Some(format!("Lock rejected by engine: {:?}", e)),
            }),
        )
            .into_response(),
    }
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

    if let (Some(transport), Some(peer_mgr)) = (&state.transport, &state.peer_manager) {
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

            if let Some(payload) = record_payload {
                let header = humoco_sim_core::wire::WireHeader::new(
                    humoco_sim_core::wire::MsgType::LockVerifyRequest as u16,
                    1,
                    0,
                    target_status as u32,
                    payload.len() as u32,
                );

                let mut timeout_addrs = Vec::new();
                let mut candidate_idx = 0;
                let mut total_queried = 0;
                let mut in_flight = std::collections::HashMap::new();

                let _ = tokio::time::timeout(std::time::Duration::from_millis(1000), async {
                    let mut join_set = tokio::task::JoinSet::new();

                    let spawn_next = |join_set: &mut tokio::task::JoinSet<_>, idx: &mut usize, t_queried: &mut usize, in_flight: &mut std::collections::HashMap<usize, (std::net::SocketAddr, usize)>| {
                        if *idx < candidate_nodes.len() {
                            let (nid, addr) = candidate_nodes[*idx];
                            let rank_idx = *idx;
                            *idx += 1;
                            *t_queried += 1;
                            
                            in_flight.insert(rank_idx, (addr, rank_idx));

                            let t = transport.clone();
                            let h = header;
                            let p = payload.clone();
                            join_set.spawn(async move {
                                let query_peer = async {
                                    let conn = t.connect_peer(addr).await.map_err(|_| ())?;
                                    let (resp_header, resp_payload) = t.send_request(&conn, &h, &p).await.map_err(|_| ())?;
                                    if resp_header.msg_type == humoco_sim_core::wire::MsgType::LockVerifyResponse as u16
                                        && !resp_payload.is_empty()
                                    {
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

                    let needed = required_q.saturating_sub(collected_signatures.len());
                    let initial_spawns = (needed + state.shard_query_depth).min(candidate_nodes.len());
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

                                // Cryptographically verify peer attestation via peer_manager
                                let vk = match peer_mgr.get_peer_verifying_key(att.node_id).await {
                                    Some(k) => k,
                                    None => {
                                        tracing::warn!(
                                            node_id = att.node_id,
                                            "Dropped attestation: peer verifying key not found in peer manager"
                                        );
                                        if rank_idx < 20 {
                                            peer_mgr.record_failure(addr).await;
                                        }
                                        spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                                        continue;
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
                                        if rank_idx < 20 {
                                            peer_mgr.record_failure(addr).await;
                                        }
                                        spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                                        continue;
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
                                        if rank_idx < 20 {
                                            peer_mgr.record_failure(addr).await;
                                        }
                                        spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                                        continue;
                                    }
                                };

                                if att_lock_id_bytes != lock_id {
                                    tracing::warn!(node_id = att.node_id, "Dropped attestation: lock_id mismatch");
                                    if rank_idx < 20 {
                                        peer_mgr.record_failure(addr).await;
                                    }
                                    spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                                    continue;
                                }

                                let domain_tag = if target_status == 1 {
                                    humoco_sim_core::crypto::DOMAIN_APPROVE_FINAL
                                } else {
                                    humoco_sim_core::crypto::DOMAIN_APPROVE_PROV
                                };
                                let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
                                    domain_tag,
                                    0,
                                    0,
                                    0,
                                    shard_id,
                                    target_status,
                                    &lock_id,
                                );

                                if let Err(e) = vk.verify_strict(&sig_digest, &sig) {
                                    tracing::warn!(
                                        node_id = att.node_id,
                                        error = %e,
                                        "Dropped attestation: cryptographic signature verification failed"
                                    );
                                    if rank_idx < 20 {
                                        peer_mgr.record_failure(addr).await;
                                    }
                                    spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                                    continue;
                                }

                                peer_mgr.record_success(addr, None, None).await;
                                collected_signatures.push(att);

                                // Early return as soon as required quorum is reached
                                if collected_signatures.len() >= required_q {
                                    join_set.abort_all();
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
                            peer_mgr.record_failure(addr).await;
                        }
                    }
                }
            }

            let status = if collected_signatures.len() >= required_q && target_status == 1 {
                1
            } else {
                0
            };

            let signer_bitmap = {
                let mut all_ids: Vec<[u8; 32]> = active_for_bitmap.into_iter().map(|(nid, _)| nid).collect();
                all_ids.push(self_hrw);
                all_ids.sort_by(|a, b| {
                    let sa = humoco_sim_core::client_flow::compute_hrw_score_f64(a, shard_id);
                    let sb = humoco_sim_core::client_flow::compute_hrw_score_f64(b, shard_id);
                    sb.total_cmp(&sa)
                });
                all_ids.truncate(32);
                let mut bitmap: u32 = 0;
                for sig in &collected_signatures {
                    for (idx, nid) in all_ids.iter().enumerate() {
                        let nid_u16 = u16::from_be_bytes([nid[0], nid[1]]);
                        if nid_u16 == sig.node_id {
                            bitmap |= 1u32 << idx;
                            break;
                        }
                    }
                }
                bitmap
            };

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
            candidate_nodes.truncate(20);

            if collected_signatures.len() < required_q {
                if let Some(transport) = &state.transport {
                    let payload = bincode::serialize(&(lock_id, parent_lock, shard_id)).unwrap_or_default();
                    let header = humoco_sim_core::wire::WireHeader::new(
                        humoco_sim_core::wire::MsgType::StatusQuery as u16,
                        1,
                        0,
                        target_status as u32,
                        payload.len() as u32,
                    );

                    let total_queried = candidate_nodes.len();
                    let mut timeout_addrs = Vec::new();
                    let mut join_set = tokio::task::JoinSet::new();
                    for (nid, addr) in candidate_nodes {
                        let t = transport.clone();
                        let h = header;
                        let p = payload.clone();
                        join_set.spawn(async move {
                            let query_peer = async {
                                let conn = t.connect_peer(addr).await.map_err(|_| ())?;
                                let (resp_header, resp_payload) = t.send_request(&conn, &h, &p).await.map_err(|_| ())?;
                                if resp_header.msg_type == humoco_sim_core::wire::MsgType::StatusResponse as u16
                                    && !resp_payload.is_empty()
                                {
                                    if let Ok(att) = bincode::deserialize::<AttestationDto>(&resp_payload) {
                                        return Ok(att);
                                    }
                                }
                                Err(())
                            };

                            match tokio::time::timeout(std::time::Duration::from_millis(1000), query_peer).await {
                                Ok(Ok(att)) => (nid, addr, Some(att)),
                                _ => (nid, addr, None),
                            }
                        });
                    }

                while let Some(res) = join_set.join_next().await {
                    match res {
                        Ok((_nid, addr, Some(att))) => {
                            if collected_signatures.iter().any(|s| s.node_id == att.node_id) {
                                continue;
                            }

                            let vk = match peer_mgr.get_peer_verifying_key(att.node_id).await {
                                Some(k) => k,
                                None => {
                                    peer_mgr.record_failure(addr).await;
                                    continue;
                                }
                            };

                            let sig_bytes = match hex::decode(&att.signature) {
                                Ok(b) if b.len() == 64 => {
                                    let mut arr = [0u8; 64];
                                    arr.copy_from_slice(&b);
                                    arr
                                }
                                _ => {
                                    peer_mgr.record_failure(addr).await;
                                    continue;
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
                                    peer_mgr.record_failure(addr).await;
                                    continue;
                                }
                            };

                            if att_lock_id_bytes != lock_id {
                                peer_mgr.record_failure(addr).await;
                                continue;
                            }

                            let domain_tag = if target_status == 1 {
                                humoco_sim_core::crypto::DOMAIN_APPROVE_FINAL
                            } else {
                                humoco_sim_core::crypto::DOMAIN_APPROVE_PROV
                            };
                            let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
                                domain_tag,
                                0,
                                0,
                                0,
                                shard_id,
                                target_status,
                                &lock_id,
                            );

                            if vk.verify_strict(&sig_digest, &sig).is_err() {
                                peer_mgr.record_failure(addr).await;
                                continue;
                            }

                            peer_mgr.record_success(addr, None, None).await;
                            collected_signatures.push(att);

                            if collected_signatures.len() >= required_q {
                                join_set.abort_all();
                                break;
                            }
                        }
                        Ok((_nid, addr, None)) => {
                            timeout_addrs.push(addr);
                        }
                        Err(_) => {}
                    }
                }

                // 🛡️ Correlated failure protection (KISS / INV-1501):
                // If more than 50% of candidates timed out, suppress peer failure penalties.
                let is_correlated_failure = total_queried >= 2 && timeout_addrs.len() * 2 > total_queried;
                if is_correlated_failure {
                    tracing::warn!(
                        failed = timeout_addrs.len(),
                        total = total_queried,
                        "Correlated timeout detected in status query (>50% failed) - suppressing peer failure penalties"
                    );
                } else {
                    for addr in timeout_addrs {
                        peer_mgr.record_failure(addr).await;
                    }
                }
            }
        }

            let status = if collected_signatures.len() >= required_q && target_status == 1 {
                1
            } else {
                0
            };

            let signer_bitmap = {
                let mut all_ids: Vec<[u8; 32]> = active_for_bitmap.into_iter().map(|(nid, _)| nid).collect();
                all_ids.push(self_hrw);
                all_ids.sort_by(|a, b| {
                    let sa = humoco_sim_core::client_flow::compute_hrw_score_f64(a, shard_id);
                    let sb = humoco_sim_core::client_flow::compute_hrw_score_f64(b, shard_id);
                    sb.total_cmp(&sa)
                });
                all_ids.truncate(32);
                let mut bitmap: u32 = 0;
                for sig in &collected_signatures {
                    for (idx, nid) in all_ids.iter().enumerate() {
                        let nid_u16 = u16::from_be_bytes([nid[0], nid[1]]);
                        if nid_u16 == sig.node_id {
                            bitmap |= 1u32 << idx;
                            break;
                        }
                    }
                }
                bitmap
            };

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

    // 2. Validate Origin Root Lock & Ingress Time Window
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

    // 3. Perform 3-Tier Access Evaluation with exact Byte-Years based on root validity
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
        let (status, reason) = match err {
            IngressError::PoWRequired { .. } => (
                StatusCode::UNAUTHORIZED,
                "Proof-of-Work challenge response required".into(),
            ),
            IngressError::InvalidPoW(err) => {
                if let crate::ingress::pow::PowError::InsufficientDifficulty { required, provided } = err {
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
        return (status, Json(envelope)).into_response();
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
    (status, Json(envelope)).into_response()
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
