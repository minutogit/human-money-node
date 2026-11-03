//! HTTP API routes for `humoco-node`.
//!
//! # Architectural Invariant: Pure Blind Service & No Client-Side Fraud Reporting (KISS Principle)
//!
//! Under the HuMoCo Layer-2 architecture and the "Subtraction before Construction" doctrine:
//! 1. **No `/v1/report-fraud` on Tier-1 HTTP Ingress:**
//!    In accordance with the Anti-Hearsay Principle (Spec 10/11) and DEC-020/DEC-081, node slashing
//!    and network bans require irrefutable first-party cryptographic self-proof of equivocation
//!    (`HUMOCO_V1_EQUIVOCATION`) exchanged directly across the Tier-2 QUIC mesh among authenticated peers.
//!    Accepting unauthenticated third-party fraud complaints from anonymous clients over HTTP
//!    is an anti-pattern that would introduce massive DDoS amplification and spam vectors.
//! 2. **No Live Multi-Gateway Cross-Checks on Hot-Path:**
//!    PoS terminals and clients verify Quorum Certificates locally and deterministically against
//!    their background-synchronized known peer roster via local HRW committee calculation.
//!    Because Ed25519 signatures are mathematically unforgeable, any rogue gateway fabricating
//!    a roster or forging signatures is rejected fail-closed locally (< 1 ms) without needing
//!    redundant live HTTP cross-checks against secondary gateways on the checkout hot-path.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use ed25519_dalek::Signer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use humoco_sim_core::types::SimTime;

use crate::api::dto::{
    AttestationDto, ErrorResponse, NodeStatusResponse, PeerEntryDto, PeersResponse,
    PowChallengeResponse, QuorumCertificateDto, SyncRequest, SyncResponse,
};
use crate::api::hmc::{
    verify_l2_lock_signature, wrap_and_sign_verdict, wrap_and_sign_verdict_with_quorum,
    L2ChainLockRequest, L2CheckoutRequest, L2CheckoutResponse, L2LockEntry, L2LockRequest,
    L2ResponseEnvelope, L2StatusQuery, L2Verdict,
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
    pub system_stats: Arc<crate::api::system_stats::SystemStatsCollector>,
    pub auth: Arc<crate::api::auth::AdminTokenManager>,
    pub is_simulation: bool,
    pub config: Arc<crate::config::NodeConfig>,
    pub history_sampler: Arc<crate::api::history::HistorySampler>,
    pub event_log: Arc<crate::api::events::EventLog>,
    pub health_tracker: Arc<crate::api::health::HealthStateTracker>,
    pub readiness_manager: Arc<crate::daemon::ShardReadinessManager>,
    /// Bound exceptional disk reads independently of checkout persistence.
    pub retained_choice_reads: Arc<tokio::sync::Semaphore>,
    /// Bound fallback disk reads for voucher roots independently of hot-path (A05-01).
    pub voucher_root_reads: Arc<tokio::sync::Semaphore>,
    /// Bound concurrent blocking /v1/sync snapshot workers to protect memory (S01-03).
    pub sync_reads: Arc<tokio::sync::Semaphore>,
    /// In-memory cache for regional mesh views (5-second TTL).
    pub mesh_view_cache: Arc<parking_lot::RwLock<Option<(u64, humoco_proto::mesh::RegionalMeshView)>>>,
}

impl AppState {
    pub fn new(
        engine: DualTierEngine,
        storage: Arc<RedbStorage>,
        identity: NodeIdentity,
        tier_controller: Arc<TierController>,
        pow_engine: Arc<PowEngine>,
    ) -> Self {
        let metrics = Arc::new(crate::api::metrics::NodeMetrics::default());
        let system_stats = Arc::new(crate::api::system_stats::SystemStatsCollector::new("."));
        let auth = Arc::new(crate::api::auth::AdminTokenManager::with_token(
            "hmc_adm_dev",
            true,
        ));
        let config = Arc::new(crate::config::NodeConfig::default());
        let history_sampler = Arc::new(crate::api::history::HistorySampler::default());
        let event_log = Arc::new(crate::api::events::EventLog::default());
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if let Ok(loaded) = storage.load_recent_audit_events(100) {
                if !loaded.is_empty() {
                    event_log.populate(loaded);
                }
            }
            let (audit_tx, mut audit_rx) =
                tokio::sync::mpsc::channel::<crate::api::events::EventItem>(100);
            event_log.set_persister(audit_tx);
            let persister_storage = storage.clone();
            handle.spawn(async move {
                while let Some(event) = audit_rx.recv().await {
                    if let Err(err) = persister_storage.insert_audit_event(&event) {
                        tracing::warn!("Failed to persist audit event #{}: {}", event.id, err);
                    }
                }
            });
        }
        let health_tracker = Arc::new(crate::api::health::HealthStateTracker::default());
        let readiness_manager = Arc::new(crate::daemon::ShardReadinessManager::new());
        Self {
            engine,
            storage,
            identity,
            tier_controller,
            pow_engine,
            peer_manager: None,
            transport: None,
            start_time: std::time::Instant::now(),
            metrics,
            lifecycle: crate::config::LifecycleConfig::default(),
            network_id: humoco_sim_core::types::NetworkId::default(),
            shard_query_depth: 3,
            system_stats,
            auth,
            is_simulation: false,
            config,
            history_sampler,
            event_log,
            health_tracker,
            readiness_manager,
            retained_choice_reads: Arc::new(tokio::sync::Semaphore::new(8)),
            voucher_root_reads: Arc::new(tokio::sync::Semaphore::new(16)),
            sync_reads: Arc::new(tokio::sync::Semaphore::new(4)),
            mesh_view_cache: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    pub fn with_readiness_manager(
        mut self,
        readiness_manager: Arc<crate::daemon::ShardReadinessManager>,
    ) -> Self {
        self.readiness_manager = readiness_manager;
        self
    }

    pub fn with_health_tracker(
        mut self,
        health_tracker: Arc<crate::api::health::HealthStateTracker>,
    ) -> Self {
        self.health_tracker = health_tracker;
        self
    }

    pub fn with_history_sampler(
        mut self,
        history_sampler: Arc<crate::api::history::HistorySampler>,
    ) -> Self {
        self.history_sampler = history_sampler;
        self
    }

    pub fn with_event_log(mut self, event_log: Arc<crate::api::events::EventLog>) -> Self {
        self.event_log = event_log;
        self
    }

    pub fn with_config(mut self, config: Arc<crate::config::NodeConfig>) -> Self {
        self.config = config;
        self
    }

    pub fn with_simulation_mode(mut self, is_simulation: bool) -> Self {
        self.is_simulation = is_simulation;
        self
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

    pub fn with_system_stats(
        mut self,
        system_stats: Arc<crate::api::system_stats::SystemStatsCollector>,
    ) -> Self {
        self.system_stats = system_stats;
        self
    }

    pub fn with_auth(mut self, auth: Arc<crate::api::auth::AdminTokenManager>) -> Self {
        self.auth = auth;
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

/// Public permissionless client ingress. Operator diagnostics have a separate listener.
///
/// # Ingress Boundaries & KISS Principle
/// - Tier-1 HTTP ingress does NOT implement `/v1/report-fraud` or live cross-check proxies.
/// - Slashing occurs strictly via Tier-2 QUIC P2P equivocation gossip (`HUMOCO_V1_EQUIVOCATION`).
/// - PoS checkout trust is achieved entirely offline by clients computing HRW committees against
///   their cold-path synchronized peer roster and verifying Ed25519 threshold signatures.
pub async fn live_deadline_middleware(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let deadline = tokio::time::Instant::now() + crate::api::live::LIVE_PROOF_SERVER_BUDGET;
    req.extensions_mut()
        .insert(crate::api::live::LiveDeadline(deadline));
    match tokio::time::timeout_at(deadline, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

pub fn public_router(state: AppState) -> Router {
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
        .route("/healthz", get(health_ok))
        .route("/v1/node-status", get(public_node_status))
        .route(
            "/v1/verify-current",
            post(crate::api::live::verify_current)
                .layer(axum::middleware::from_fn(live_deadline_middleware)),
        )
        .route("/v1/regional-mesh-view", get(public_regional_mesh_view))
        .route("/v1/checkout", post(checkout))
        .route("/v1/gateways", get(public_gateways))
        .route("/v1/retained-choice/:tag", get(get_retained_choice))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Private operator endpoints; bind only to the configured local operator listener.
pub fn build_operator_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/operator/regional-mesh-view",
            get(operator_regional_mesh_view),
        )
        .route("/health", get(get_node_status))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/peers", get(get_peers))
        .route("/api/v1/network/peers", get(get_peers))
        .route("/api/v1/retained-choice/:tag", get(get_retained_choice))
        .route("/dashboard", get(crate::api::dashboard::render_dashboard))
        .route(
            "/dashboard/data",
            get(crate::api::dashboard::dashboard_data),
        )
        .route(
            "/dashboard/vouchers",
            get(crate::api::dashboard::dashboard_vouchers),
        )
        .route(
            "/dashboard/voucher/:voucher_id",
            get(crate::api::dashboard::dashboard_voucher_detail),
        )
        .route(
            "/dashboard/lock/:lookup_tag",
            get(crate::api::dashboard::dashboard_lock_raw),
        )
        .route(
            "/dashboard/admin/verify-token",
            post(crate::api::dashboard::admin_verify_token),
        )
        .route(
            "/dashboard/admin/friends",
            post(crate::api::dashboard::admin_add_friend),
        )
        .route(
            "/dashboard/admin/friends/:key",
            delete(crate::api::dashboard::admin_remove_friend),
        )
        .route(
            "/dashboard/admin/mesh/peers",
            post(crate::api::dashboard::admin_add_mesh_peer),
        )
        .route(
            "/dashboard/admin/mesh/peers/:key",
            delete(crate::api::dashboard::admin_remove_mesh_peer),
        )
        .route(
            "/dashboard/admin/ingress/clients",
            post(crate::api::dashboard::admin_add_ingress_client),
        )
        .route(
            "/dashboard/admin/ingress/clients/:token_hash",
            delete(crate::api::dashboard::admin_remove_ingress_client),
        )
        .route(
            "/dashboard/admin/quota",
            post(crate::api::dashboard::admin_topup_quota),
        )
        .route(
            "/dashboard/admin/peers/:addr/reset",
            post(crate::api::dashboard::admin_reset_peer),
        )
        .route(
            "/dashboard/admin/peers/:addr/ping",
            post(crate::api::dashboard::admin_ping_peer),
        )
        .route("/dashboard/history", get(get_dashboard_history))
        .route("/dashboard/history/hourly", get(private_hourly_history))
        .route("/dashboard/events", get(get_dashboard_events))
        .route("/metrics", get(crate::api::metrics::prometheus_metrics))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::from_fn(
            crate::api::operator_boundary::enforce_operator_browser_boundary,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Compatibility entry point for public ingress.
pub fn build_router(state: AppState) -> Router {
    public_router(state)
}

#[derive(serde::Deserialize)]
struct HistoryQuery {
    window: Option<String>,
}

#[derive(serde::Serialize)]
struct HistoryResponse {
    points: Vec<crate::api::history::HistoryPoint>,
}

async fn get_dashboard_history(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> Json<HistoryResponse> {
    let window = query.window.as_deref().unwrap_or("24h");
    let points = state.history_sampler.query(window);
    Json(HistoryResponse { points })
}

#[derive(serde::Deserialize)]
struct EventsQuery {
    since_id: Option<u64>,
    limit: Option<usize>,
}

#[derive(serde::Serialize)]
struct EventsResponse {
    events: Vec<crate::api::events::EventItem>,
}

async fn get_dashboard_events(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<EventsQuery>,
) -> Json<EventsResponse> {
    let events = state.event_log.query(query.since_id, query.limit);
    Json(EventsResponse { events })
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
            return submit_hmc_chain_lock_inner(state, headers, chain_req, start).await;
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

/// ARCHITECTURAL INVARIANT / AUDIT NOTE (Spec 03, 11, Rule 1):
/// - Hot-Path Durable Ingress (< 20ms Durable Node SLA) & Read Ingress (< 1µs RAM):
///   Read requests (status queries) query a deterministic or uniform-random shard node
///   from the Top-20 active set. They NEVER hold disk write locks or trigger P2P gossip.
/// - Sync Limits: Max 10,000 items per sync response with strictly validated net_time_ms.
/// - Objective Lock State vs. Signature Hoarding (KISS Principle):
///   Locks returned via `/v1/sync` are serialized strictly as `HmcSyncRow`
///   representing the pure objective collision state (`tag`, `entry`).
///   No legacy node attestations or historical 896-byte quorum signature bundles are transferred,
///   preventing network bloat and ghost-node dependencies.
///
/// Handler for POST /v1/sync
async fn sync_locks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SyncRequest>,
) -> Response {
    state.metrics.record_read();
    let now_ms = state.net_time_ms();
    let epoch_day = state.tier_controller.current_epoch_day_at(now_ms);

    // Rate-limiting / quota protection for heavy sync queries (A09 & Rule 9)
    let client_node_id: u16 =
        if let Some(auth) = headers.get("Authorization").and_then(|h| h.to_str().ok()) {
            let tag = state
                .tier_controller
                .resolve_account_tag(auth)
                .unwrap_or([0u8; 32]);
            u16::from_be_bytes([tag[0], tag[1]])
        } else if let Some(peer_token) = headers.get("X-Peer-Token").and_then(|h| h.to_str().ok()) {
            let hash = *blake3::hash(peer_token.as_bytes()).as_bytes();
            u16::from_be_bytes([hash[0], hash[1]])
        } else {
            let first_loc = payload
                .sparse_locators
                .first()
                .map(|s| s.as_bytes())
                .unwrap_or(b"sync_anonymous");
            let hash = *blake3::hash(first_loc).as_bytes();
            u16::from_be_bytes([hash[0], hash[1]])
        };

    let sync_read_credits = 5;
    if let Err(ingress_err) = state.tier_controller.evaluate_read_quota_with_time(
        client_node_id,
        sync_read_credits,
        epoch_day,
        1.0,
        Some(now_ms),
    ) {
        let reason = match ingress_err {
            IngressError::ReadQuotaExceeded {
                available,
                required,
            } => {
                format!(
                    "429 Read quota exceeded: required {} credits, available {}",
                    required, available
                )
            }
            _ => "429 Read quota exceeded".into(),
        };
        let err_resp = ErrorResponse {
            error: "ReadQuotaExceeded".into(),
            message: reason,
            challenge: None,
            difficulty: None,
            expires_at: None,
        };
        return (StatusCode::TOO_MANY_REQUESTS, Json(err_resp)).into_response();
    }

    // Bounded locators (INV-0310 & Rule 9): Max 256 locators of max 128 bytes to prevent Read-DoS memory bloat
    const MAX_SYNC_LOCATORS: usize = 256;
    const MAX_SYNC_LOCATOR_LEN: usize = 128;
    let locators: HashSet<String> = payload
        .sparse_locators
        .into_iter()
        .take(MAX_SYNC_LOCATORS)
        .filter(|l| l.len() <= MAX_SYNC_LOCATOR_LEN)
        .collect();

    // Bound concurrent blocking snapshot readers (S01-03)
    let Ok(permit) = state.sync_reads.clone().try_acquire_owned() else {
        tracing::warn!("Sync snapshot worker capacity exhausted");
        let err_resp = ErrorResponse {
            error: "SyncBusy".into(),
            message: "Sync snapshot reader capacity exhausted; retry shortly".into(),
            challenge: None,
            difficulty: None,
            expires_at: None,
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(err_resp)).into_response();
    };

    let storage = state.storage.clone();
    let hmc_locks = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        storage.read_committed_sync_snapshot_bounded(
            now_ms,
            &locators,
            MAX_SYNC_LOCKS,
            MAX_SYNC_RESPONSE_BYTES,
        )
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(err)) => {
            let err_resp = ErrorResponse {
                error: "StorageError".into(),
                message: err.to_string(),
                challenge: None,
                difficulty: None,
                expires_at: None,
            };
            return (StatusCode::SERVICE_UNAVAILABLE, Json(err_resp)).into_response();
        }
        Err(err) => {
            let err_resp = ErrorResponse {
                error: "StorageError".into(),
                message: err.to_string(),
                challenge: None,
                difficulty: None,
                expires_at: None,
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(err_resp)).into_response();
        }
    };

    (StatusCode::OK, Json(SyncResponse { hmc_locks })).into_response()
}

pub const MAX_SYNC_LOCKS: usize = crate::storage::db::DEFAULT_MAX_SYNC_LOCKS;
pub const MAX_SYNC_RESPONSE_BYTES: usize = crate::storage::db::DEFAULT_MAX_SYNC_RESPONSE_BYTES;

/// Handler for GET /v1/pow-challenge
async fn get_pow_challenge(
    State(state): State<AppState>,
) -> (StatusCode, Json<PowChallengeResponse>) {
    state.metrics.record_read();
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
async fn get_node_status(State(state): State<AppState>) -> (StatusCode, Json<NodeStatusResponse>) {
    state.metrics.record_read();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let (active_byte_years, _) = state.engine.get_active_footprint_byte_years(now_ms).await;
    let total_locks = state.engine.hmc_ram.read().await.locks.len();
    let daily_write_quota_byte_years = state.tier_controller.calculate_daily_quota(1.0, 1.0);
    let daily_read_quota = state.tier_controller.calculate_daily_read_quota(1.0, 1.0);
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
            free_tier_enabled: true,
            active_byte_years,
            daily_write_quota_byte_years,
            daily_read_quota,
        }),
    )
}

/// Handler for GET /peers and GET /api/v1/network/peers (PEX Client Discovery)
async fn get_peers(State(state): State<AppState>) -> (StatusCode, Json<PeersResponse>) {
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

/// # Architectural Invariant: parent_lock-Bound Attestations (Phase 1 P0)
///
/// Creates and signs an attestation for a lock ID with the NodeIdentity using the
/// canonical SigDigest with domain separation. The signed preimage is NOT the bare
/// `lock_id`: it is `compute_attestation_payload_digest(parent_lock, lock_id)`, so
/// the Ed25519 signature transitively commits to the voucher lineage. A signature
/// replayed onto a divergent `parent_lock` fails verification.
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
    // Pillar 3: Cryptographic Identity Trumps Network Topology — bind the full
    // 32-byte NodePubKey; `node_id` stays only for backward compatibility.
    let node_pubkey_hex = hex::encode(identity.node_pubkey());
    let domain_tag = if status == 1 {
        humoco_sim_core::crypto::domain_approve_final(network_id)
    } else {
        humoco_sim_core::crypto::domain_approve_prov(network_id)
    };
    let payload_digest =
        humoco_sim_core::crypto::compute_attestation_payload_digest(&parent_lock, &lock_id);
    let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
        domain_tag,
        0,
        0,
        0,
        shard_id,
        status,
        &payload_digest,
    );
    let signature = identity.signing_key().sign(&sig_digest);
    AttestationDto {
        lock_id: hex::encode(lock_id),
        parent_lock: hex::encode(parent_lock),
        node_id: node_id_u16,
        node_pubkey: node_pubkey_hex,
        timestamp: timestamp_ms,
        signature: hex::encode(signature.to_bytes()),
        shard_id,
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

/// # Architectural Invariant: Non-Blocking Hot-Path Voucher Root Resolution (A05-01)
///
/// Under the PoS checkout hot-path (`POST /v1/lock`), checking voucher root validity
/// must never stall Tokio runtime worker threads on synchronous redb I/O.
/// 1. Fast-Path: Checks the in-memory RAM index first (`<1 µs`).
/// 2. Slow-Path: If missing in RAM, falls back to disk via `tokio::task::spawn_blocking`
///    governed by a bounded permit semaphore (`voucher_root_reads`) to prevent disk
///    saturation or thread starvation under mass ingress.
pub async fn lookup_local_voucher_root(state: &AppState, voucher_id: &str) -> Option<u64> {
    // 1. Fast-path: Check in-memory RAM index first (<1µs)
    if let Some(valid_until) = state.engine.get_hmc_voucher_root_valid(voucher_id).await {
        return Some(valid_until);
    }

    // 2. Slow-path: Bounded non-blocking disk fallback via spawn_blocking (A05-01)
    let Ok(permit) = state.voucher_root_reads.clone().try_acquire_owned() else {
        tracing::warn!(voucher_id, "Voucher root read permit saturated");
        return None;
    };
    let storage = state.storage.clone();
    let vid = voucher_id.to_string();
    let read_res = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        storage.voucher_root(&vid)
    })
    .await;

    if let Ok(Ok(Some(root))) = read_res {
        return crate::storage::db::roots::root_valid_until(&root).ok();
    }
    None
}

/// Maps each full signer identity to its immutable committee position.
fn compute_committee_bitmap(
    committee: &[humoco_sim_core::types::CommitteeMember],
    signatures: &[AttestationDto],
) -> u32 {
    signatures.iter().fold(0, |bitmap, att| {
        committee
            .iter()
            .position(|member| Some(member.node_pubkey) == att.node_pubkey_bytes())
            .map(|index| bitmap | (1 << index))
            .unwrap_or(bitmap)
    })
}

/// Verifies a peer attestation's cryptographic fields and HRW binding.
///
/// # Architectural Invariant: Pillar 3 — Cryptographic Identity Trumps Network Topology
///
/// Key resolution is STRICTLY via the full 32-byte `NodePubKey`
/// (`att.node_pubkey`); the legacy 16-bit `node_id` is only a fallback and
/// fails closed on prefix collisions. The claimed signer is additionally
/// checked against the actual QUIC TLS certificate key of the queried peer
/// (`expected_tls_pubkey`): a transplanted signature from a different node is
/// rejected even if cryptographically valid under its own key. Domain tags are
/// derived from the passed `NetworkId` — Mainnet is never hardcoded.
async fn verify_peer_attestation(
    peer_mgr: &crate::network::PeerManager,
    att: &AttestationDto,
    expected_lock: ([u8; 32], [u8; 32]),
    shard_id: u16,
    target_status: u8,
    network_id: humoco_sim_core::types::NetworkId,
    expected_tls_pubkey: Option<[u8; 32]>,
) -> bool {
    let (expected_lock_id, expected_parent_lock) = expected_lock;
    if att.shard_id != shard_id {
        return false;
    }
    // Strict 32-byte signer resolution first.
    let signer_pubkey: Option<[u8; 32]> = att.node_pubkey_bytes();
    let vk = if let Some(pk) = signer_pubkey {
        // TLS binding: the attestation signer MUST be the peer we actually
        // queried over QUIC (prevents signature-transplant across peers).
        if let Some(tls_pk) = expected_tls_pubkey {
            if pk != tls_pk {
                tracing::warn!(
                    node_id = att.node_id,
                    "Dropped attestation: signer NodePubKey does not match TLS certificate key of queried peer"
                );
                return false;
            }
        }
        match peer_mgr.get_peer_verifying_key_by_node_id(&pk).await {
            Some(k) => k,
            None => {
                // Unknown but well-formed pubkey: derive vk directly so new
                // F2F peers without prior gossip registration still verify.
                match ed25519_dalek::VerifyingKey::from_bytes(&pk) {
                    Ok(k) => k,
                    Err(_) => {
                        tracing::warn!(
                            node_id = att.node_id,
                            "Dropped attestation: invalid 32-byte NodePubKey"
                        );
                        return false;
                    }
                }
            }
        }
    } else {
        // Legacy fallback: 16-bit prefix, fails closed on collisions.
        match peer_mgr.get_peer_verifying_key(att.node_id).await {
            Some(k) => k,
            None => {
                tracing::warn!(
                    node_id = att.node_id,
                    "Dropped attestation: peer verifying key not found (or 16-bit prefix ambiguous)"
                );
                return false;
            }
        }
    };

    let sig_bytes = match hex::decode(&att.signature) {
        Ok(b) if b.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            tracing::warn!(
                node_id = att.node_id,
                "Dropped attestation: invalid signature length"
            );
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
            tracing::warn!(
                node_id = att.node_id,
                "Dropped attestation: invalid lock_id hex"
            );
            return false;
        }
    };

    if att_lock_id_bytes != expected_lock_id {
        tracing::warn!(
            node_id = att.node_id,
            "Dropped attestation: lock_id mismatch"
        );
        return false;
    }

    let att_parent_lock_bytes = match hex::decode(&att.parent_lock) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            tracing::warn!(
                node_id = att.node_id,
                "Dropped attestation: invalid parent_lock hex"
            );
            return false;
        }
    };

    if att_parent_lock_bytes != expected_parent_lock {
        return false;
    }

    let domain_tag = if target_status == 1 {
        humoco_sim_core::crypto::domain_approve_final(network_id)
    } else {
        humoco_sim_core::crypto::domain_approve_prov(network_id)
    };
    // Parent-lock binding (Phase 1 P0): the signature commits to
    // (parent_lock, lock_id); transplanted signatures fail here.
    let payload_digest = humoco_sim_core::crypto::compute_attestation_payload_digest(
        &att_parent_lock_bytes,
        &expected_lock_id,
    );
    let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
        domain_tag,
        0,
        0,
        0,
        shard_id,
        target_status,
        &payload_digest,
    );

    if let Err(e) = vk.verify_strict(&sig_digest, &sig) {
        tracing::warn!(
            node_id = att.node_id,
            error = %e,
            "Dropped attestation: cryptographic signature verification failed"
        );
        return false;
    }

    // A10-02: Bounded original-vote observation for automatic ShardEquivocation detection.
    if let Some(signer_pk) = att.node_pubkey_bytes() {
        if let Some(core_att) = att.to_core() {
            if peer_mgr
                .observe_verified_original_attestation(signer_pk, core_att, network_id)
                .is_some()
            {
                tracing::warn!(
                    node_id = att.node_id,
                    offender = %hex::encode(signer_pk),
                    "Dropped attestation: detected conflicting original attestation (ShardEquivocation)! Perpetrator slashed."
                );
                return false;
            }
        }
    }

    true
}

/// Parameters for querying peer attestations via QUIC.
pub struct PeerAttestationQuery<'a> {
    pub transport: &'a crate::network::QuicTransport,
    pub peer_mgr: &'a crate::network::PeerManager,
    pub candidate_nodes: &'a [([u8; 32], std::net::SocketAddr)],
    pub expected_members: Option<&'a [[u8; 32]]>,
    pub parent_lock: [u8; 32],
    pub lookup_tag: Option<&'a str>,
    pub voucher_id: Option<&'a str>,
    pub msg_type: humoco_sim_core::wire::MsgType,
    pub resp_msg_type: humoco_sim_core::wire::MsgType,
    pub payload: &'a [u8],
    pub target_status: u8,
    pub lock_id: [u8; 32],
    pub shard_id: u16,
    pub required_q: usize,
    pub shard_query_depth: usize,
    pub my_load: u64,
    pub quota_limit: u64,
    pub network_id: humoco_sim_core::types::NetworkId,
    pub checkout_deadline: Option<tokio::time::Instant>,
}

enum PeerQueryError {
    LocalCapacity,
    QuotaExceeded,
    NotInShard,
    Collision(humoco_sim_core::wire::WireHeader, Vec<u8>, Option<[u8; 32]>),
    Generic,
}

enum PeerQueryResult {
    LocalCapacity,
    Success(AttestationDto, Option<[u8; 32]>),
    QuotaExceeded,
    NotInShard,
    Collision(humoco_sim_core::wire::WireHeader, Vec<u8>, Option<[u8; 32]>),
    Failure,
}

impl From<crate::error::NodeError> for PeerQueryError {
    fn from(error: crate::error::NodeError) -> Self {
        if error.is_local_capacity() {
            Self::LocalCapacity
        } else {
            Self::Generic
        }
    }
}

/// Validates that a remote collision response genuinely proves a diverging double-spend
/// for the exact request context before granting work credit or returning HTTP 409.
fn validate_remote_collision(
    header: &humoco_sim_core::wire::WireHeader,
    payload: &[u8],
    tls_pubkey: Option<[u8; 32]>,
    expected_member: Option<[u8; 32]>,
    query: &PeerAttestationQuery<'_>,
) -> Option<crate::api::hmc::L2LockEntry> {
    if header.msg_type != query.resp_msg_type as u16
        || (header.flags & humoco_sim_core::wire::FLAG_COLLISION_DETECTED) == 0
        || payload.is_empty()
        || payload.len() > 64 * 1024
    {
        return None;
    }

    // Require TLS identity of queried frozen member
    if expected_member.is_some() && tls_pubkey != expected_member {
        return None;
    }

    let lookup_tag = query.lookup_tag?;
    let voucher_id = query.voucher_id?;

    // Parent lock binding to lookup tag
    if *blake3::hash(lookup_tag.as_bytes()).as_bytes() != query.parent_lock {
        return None;
    }

    // Bounded decode: bincode with JSON fallback
    let entry = bincode::deserialize::<crate::api::hmc::L2LockEntry>(payload)
        .ok()
        .or_else(|| serde_json::from_slice::<crate::api::hmc::L2LockEntry>(payload).ok())?;

    // Validate voucher consistency
    if entry.layer2_voucher_id != voucher_id {
        return None;
    }

    // Require a DIFFERENT child (diverging transaction id)
    if entry.t_id == query.lock_id {
        return None;
    }

    // Verify client's lock signature against the exact lookup tag
    if !crate::api::hmc::verify_l2_lock_entry_signature(&entry, lookup_tag) {
        return None;
    }

    Some(entry)
}

/// # Architectural Invariant: Zero-Copy Request-Payload Quorum Fan-Out (A05-03)
///
/// In the parallel checkout fan-out across up to 20 committee nodes, the serialized
/// request payload is wrapped in an `Arc<[u8]>` once and shared across all spawned tasks.
/// Tasks borrow the slice (`&p[..]`) when sending wire frames via QUIC without cloning
/// or reallocating up to 20 * 64 KiB = 1.28 MiB per request.
///
/// Collects only the immutable write committee in parallel, with an 800ms
/// deadline and fast exit once quorum is met or cannot be reached. Cancelled
/// stragglers and explicit readiness refusals never count as peer failures.
/// Status reads retain their existing timeout and query depth.
pub async fn collect_peer_attestations(
    query: PeerAttestationQuery<'_>,
    collected_signatures: &mut Vec<AttestationDto>,
) -> Option<crate::api::hmc::L2LockEntry> {
    let header = humoco_sim_core::wire::WireHeader::new(
        query.msg_type as u16,
        1,
        0,
        query.target_status as u32,
        query.payload.len() as u32,
    );

    // Wrap payload in an Arc<[u8]> once for zero-copy sharing across all committee tasks (A05-03)
    let shared_payload: Arc<[u8]> = Arc::from(query.payload);

    let mut timeout_addrs = Vec::new();
    let mut candidate_idx = 0;
    let mut total_queried = 0;
    let mut in_flight = std::collections::HashMap::new();
    // First genuine HMC conflict evidence (FLAG_COLLISION_DETECTED) for 409.
    let mut collision_entry: Option<crate::api::hmc::L2LockEntry> = None;

    let is_write = query.msg_type == humoco_sim_core::wire::MsgType::LockVerifyRequest;
    let peer_work = async {
        let mut join_set = tokio::task::JoinSet::new();

        let spawn_next = |join_set: &mut tokio::task::JoinSet<_>,
                          idx: &mut usize,
                          t_queried: &mut usize,
                          in_flight: &mut std::collections::HashMap<
            usize,
            (std::net::SocketAddr, usize),
        >| {
            if *idx < query.candidate_nodes.len() {
                let (nid, addr) = query.candidate_nodes[*idx];
                let rank_idx = *idx;
                *idx += 1;
                *t_queried += 1;

                in_flight.insert(rank_idx, (addr, rank_idx));

                let t = query.transport.clone();
                let h = header;
                let p = shared_payload.clone();
                let exp_resp = query.resp_msg_type as u16;
                join_set.spawn(async move {
                    let query_peer = async {
                        let conn = t.connect_peer(addr).await.map_err(PeerQueryError::from)?;
                        // Pillar 3: capture the actual TLS certificate key of the
                        // queried peer so the attestation signer can be bound to it.
                        let tls_pubkey =
                            crate::network::tls::extract_peer_identity_from_connection(&conn)
                                .map(|(nid, _)| nid);

                        // Bounded attempt loop: writes attempt at most 3 sends on transport failures;
                        // reads perform a single attempt. Any successful response stops retries.
                        let max_attempts = if is_write { 3 } else { 1 };
                        let mut last_error = PeerQueryError::Generic;
                        let mut response_pair = None;

                        for _ in 0..max_attempts {
                            match t.send_request(&conn, &h, &p).await {
                                Ok(pair) => {
                                    response_pair = Some(pair);
                                    break;
                                }
                                Err(error) if error.is_local_capacity() => {
                                    return Err(PeerQueryError::LocalCapacity);
                                }
                                Err(error) => {
                                    last_error = error.into();
                                }
                            }
                        }

                        let (resp_header, resp_payload) = match response_pair {
                            Some(pair) => pair,
                            None => return Err(last_error),
                        };

                        // Phase 2 P1 (INV-0604): genuine HMC double-spend carries
                        // FLAG_COLLISION_DETECTED + colliding lock payload for 409.
                        if (resp_header.flags & humoco_sim_core::wire::FLAG_COLLISION_DETECTED) != 0
                        {
                            return Err(PeerQueryError::Collision(
                                resp_header,
                                resp_payload,
                                tls_pubkey,
                            ));
                        }
                        if (resp_header.flags & humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED) != 0 {
                            return Err(PeerQueryError::QuotaExceeded);
                        }
                        // Phase 8 (Spec 15/19 Tit-for-Tat): a locally suspended
                        // or banned peer answers with FLAG_PEER_SUSPENDED.
                        // Treat explicit unavailability as neutral abstention.
                        // Never replace committee members or apply a malus.
                        if (resp_header.flags & humoco_sim_core::wire::FLAG_NOT_IN_SHARD) != 0
                            || (resp_header.flags & humoco_sim_core::wire::FLAG_PEER_SUSPENDED) != 0
                            || (resp_header.flags & humoco_sim_core::wire::FLAG_NOT_READY) != 0
                        {
                            return Err(PeerQueryError::NotInShard);
                        }
                        if resp_header.msg_type == exp_resp && !resp_payload.is_empty() {
                            if let Some(att) = AttestationDto::from_wire_bytes(&resp_payload) {
                                return Ok((att, tls_pubkey));
                            }
                        }
                        Err(PeerQueryError::Generic)
                    };
                    match query_peer.await {
                        Ok((att, tls_pubkey)) => (
                            nid,
                            addr,
                            rank_idx,
                            PeerQueryResult::Success(att, tls_pubkey),
                        ),
                        Err(PeerQueryError::LocalCapacity) => {
                            (nid, addr, rank_idx, PeerQueryResult::LocalCapacity)
                        }
                        Err(PeerQueryError::QuotaExceeded) => {
                            (nid, addr, rank_idx, PeerQueryResult::QuotaExceeded)
                        }
                        Err(PeerQueryError::NotInShard) => {
                            (nid, addr, rank_idx, PeerQueryResult::NotInShard)
                        }
                        Err(PeerQueryError::Collision(hdr, payload, tls_pk)) => (
                            nid,
                            addr,
                            rank_idx,
                            PeerQueryResult::Collision(hdr, payload, tls_pk),
                        ),
                        Err(PeerQueryError::Generic) => {
                            (nid, addr, rank_idx, PeerQueryResult::Failure)
                        }
                    }
                });
            }
        };

        let needed = query.required_q.saturating_sub(collected_signatures.len());
        let initial_spawns = if is_write {
            query.candidate_nodes.len()
        } else {
            (needed + query.shard_query_depth)
                .min(query.candidate_nodes.len())
                .min(20)
        };
        for _ in 0..initial_spawns {
            spawn_next(
                &mut join_set,
                &mut candidate_idx,
                &mut total_queried,
                &mut in_flight,
            );
        }
        loop {
            if is_write
                && collected_signatures.len()
                    + join_set.len()
                    + query.candidate_nodes.len().saturating_sub(candidate_idx)
                    < query.required_q
            {
                join_set.abort_all();
                in_flight.clear();
                break;
            }
            if collected_signatures.len() >= query.required_q {
                join_set.abort_all();
                in_flight.clear();
                break;
            }
            if join_set.is_empty() {
                if candidate_idx >= query.candidate_nodes.len() {
                    break;
                }
                spawn_next(
                    &mut join_set,
                    &mut candidate_idx,
                    &mut total_queried,
                    &mut in_flight,
                );
                continue;
            }
            match tokio::time::timeout(std::time::Duration::from_millis(50), join_set.join_next())
                .await
            {
                Ok(Some(res)) => match res {
                    Ok((_nid, addr, rank_idx, PeerQueryResult::Success(att, tls_pubkey))) => {
                        in_flight.remove(&rank_idx);

                        // Pillar 3: dedup strictly via 32-byte NodePubKey when
                        // present; legacy 16-bit prefix only as fallback.
                        let is_duplicate = match att.node_pubkey_bytes() {
                            Some(pk) => collected_signatures
                                .iter()
                                .any(|s| s.node_pubkey_bytes().map(|p| p == pk).unwrap_or(false)),
                            None => collected_signatures
                                .iter()
                                .any(|s| s.node_id == att.node_id),
                        };
                        if is_duplicate {
                            spawn_next(
                                &mut join_set,
                                &mut candidate_idx,
                                &mut total_queried,
                                &mut in_flight,
                            );
                            continue;
                        }

                        let expected_member = query
                            .expected_members
                            .and_then(|members| members.get(rank_idx))
                            .copied();
                        if expected_member
                            .map(|pk| Some(pk) != att.node_pubkey_bytes() || Some(pk) != tls_pubkey)
                            .unwrap_or(false)
                            || !verify_peer_attestation(
                                query.peer_mgr,
                                &att,
                                (query.lock_id, query.parent_lock),
                                query.shard_id,
                                query.target_status,
                                query.network_id,
                                tls_pubkey,
                            )
                            .await
                        {
                            if rank_idx < 20 {
                                query.peer_mgr.record_failure(addr).await;
                            }
                            spawn_next(
                                &mut join_set,
                                &mut candidate_idx,
                                &mut total_queried,
                                &mut in_flight,
                            );
                            continue;
                        }

                        // Phase 8 (Spec 15/19): only genuinely performed shard
                        // work (verified attestation) decays the Tit-for-Tat
                        // malus — a pure handshake never does.
                        query.peer_mgr.record_shard_work(addr).await;
                        collected_signatures.push(att);

                        // Early return as soon as required quorum is reached
                        if collected_signatures.len() >= query.required_q {
                            join_set.abort_all();
                            in_flight.clear(); // Aborted stragglers must NEVER be counted as peer failures (AGENTS.md / INV-1501)
                            break;
                        }
                    }
                    Ok((_nid, _addr, rank_idx, PeerQueryResult::LocalCapacity)) => {
                        in_flight.remove(&rank_idx);
                        // Our own full socket budget says nothing about this peer.
                        // Do not expand a read search while local admission is full.
                        candidate_idx = query.candidate_nodes.len();
                    }
                    Ok((_nid, _addr, rank_idx, PeerQueryResult::NotInShard)) => {
                        in_flight.remove(&rank_idx);
                        spawn_next(
                            &mut join_set,
                            &mut candidate_idx,
                            &mut total_queried,
                            &mut in_flight,
                        );
                    }
                    Ok((
                        _nid,
                        addr,
                        rank_idx,
                        PeerQueryResult::Collision(hdr, payload, tls_pk),
                    )) => {
                        in_flight.remove(&rank_idx);
                        let expected_member = query
                            .expected_members
                            .and_then(|members| members.get(rank_idx))
                            .copied();
                        if let Some(entry) = validate_remote_collision(
                            &hdr,
                            &payload,
                            tls_pk,
                            expected_member,
                            &query,
                        ) {
                            // Genuine shard work (verified conflict lookup) decays malus; the
                            // colliding lock is first-party double-spend evidence.
                            query.peer_mgr.record_shard_work(addr).await;
                            if collision_entry.is_none() {
                                collision_entry = Some(entry);
                            }
                        }
                        spawn_next(
                            &mut join_set,
                            &mut candidate_idx,
                            &mut total_queried,
                            &mut in_flight,
                        );
                    }
                    Ok((_nid, addr, rank_idx, PeerQueryResult::QuotaExceeded)) => {
                        in_flight.remove(&rank_idx);
                        // =========================================================================
                        // ARCHITECTURE GUARD: Spec 09 §5.2 / INV-0909 / INV-1701 / INV-1703
                        // (Non-Authoritative Telemetry, Quota Isolation & Strict Neutral Feedback)
                        //
                        // 1. NEUTRAL PROTOCOL FEEDBACK: `FLAG_QUOTA_EXCEEDED` is a cooperative capacity
                        //    and overload signal, NOT a transport error, crash, or Byzantine equivocation.
                        // 2. NON-AUTHORITATIVE TELEMETRY (INV-1701): Local load and thermometer estimates
                        //    are subjective observations. Subjective load discrepancies must NEVER trigger
                        //    automated bans or peer failure penalties (`record_failure` is strictly forbidden).
                        // 3. THREE-ZONE IMMUNITY (Spec 09 §5.2 / INV-0909):
                        //    - Zone 1 (FraudulentRejection / apparent load divergence): Even if our local
                        //      load estimate appears lower than the peer's declared limit, dynamic network
                        //      jitter or regional traffic bursts prevent proving malicious intent.
                        //    - Zone 2 (BoundaryCutoff 75%..125%): Expected boundary fluctuation band.
                        //    - Zone 3 (LegitimateOverload > 125%): Acknowledged network-wide saturation.
                        // 4. 24H MERGE MORATORIUM (INV-0908): After a partition merge (Village Merge),
                        //    divergent regional thermometers are reconciled; no quota malus may be applied.
                        // 5. FIRST-PARTY EVIDENCE DOCTRINE: Sanctions require irrefutable cryptographic
                        //    self-proof (EquivocationProof). Quota exhaustion never affects `missing_count`.
                        // =========================================================================
                        let in_moratorium = query
                            .peer_mgr
                            .is_in_merge_hysteresis(query.peer_mgr.net_time_ms());
                        let verdict = humoco_sim_core::quota::evaluate_quota_exceeded_claim(
                            query.my_load,
                            query.quota_limit,
                        );
                        match verdict {
                        humoco_sim_core::quota::QuotaPlausibilityVerdict::FraudulentRejection { .. } => {
                            if in_moratorium {
                                tracing::info!(
                                    %addr,
                                    rank_idx,
                                    my_load = query.my_load,
                                    quota_limit = query.quota_limit,
                                    "Shard peer quota rejection during 24h merge moratorium - neutral feedback (INV-0908)"
                                );
                            } else {
                                tracing::info!(
                                    %addr,
                                    rank_idx,
                                    my_load = query.my_load,
                                    quota_limit = query.quota_limit,
                                    "Shard peer claimed FLAG_QUOTA_EXCEEDED (Zone 1) - neutral feedback (Spec 09 §5.2)"
                                );
                            }
                        }
                        humoco_sim_core::quota::QuotaPlausibilityVerdict::BoundaryCutoff { .. }
                        | humoco_sim_core::quota::QuotaPlausibilityVerdict::LegitimateOverload { .. } => {
                            tracing::info!(
                                %addr,
                                rank_idx,
                                my_load = query.my_load,
                                quota_limit = query.quota_limit,
                                "Shard peer legitimately returned FLAG_QUOTA_EXCEEDED (Zone 2/3) - no peer penalty"
                            );
                        }
                    }
                        spawn_next(
                            &mut join_set,
                            &mut candidate_idx,
                            &mut total_queried,
                            &mut in_flight,
                        );
                    }
                    Ok((_nid, addr, rank_idx, PeerQueryResult::Failure)) => {
                        in_flight.remove(&rank_idx);
                        timeout_addrs.push((addr, rank_idx));
                        spawn_next(
                            &mut join_set,
                            &mut candidate_idx,
                            &mut total_queried,
                            &mut in_flight,
                        );
                    }
                    Err(_) => {
                        // Task cancelled/panicked
                    }
                },
                Ok(None) => break,
                Err(_) => continue,
            }
        }
    };

    let timeout_res = if let Some(deadline) = query.checkout_deadline {
        tokio::time::timeout_at(deadline, peer_work).await
    } else {
        let dur = if is_write {
            std::time::Duration::from_millis(800)
        } else {
            crate::network::manager::QUORUM_GLOBAL_TIMEOUT
        };
        tokio::time::timeout(dur, peer_work).await
    };

    // Any in-flight tasks that didn't complete when a non-deadline timeout hit are timeouts.
    // When the overall checkout deadline aborts the query, in-flight tasks are cleanly cancelled
    // without peer penalties (AGENTS.md / Spec 11).
    if timeout_res.is_ok() {
        for (_, (addr, rank_idx)) in in_flight {
            timeout_addrs.push((addr, rank_idx));
        }
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
    collision_entry
}

/// Assembles a quorum certificate for a lock by collecting signatures from top-20 HRW nodes
/// or creating a local standalone certificate when N=1 or no peers are available.
/// Returns the certificate plus the first genuine HMC conflict evidence
/// (`FLAG_COLLISION_DETECTED`) when any shard reports a diverging lock on the
/// same parent tag, so the stateless gateway can return `409 Conflict`.
pub async fn assemble_quorum_certificate(
    state: &AppState,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
    now_ms: u64,
    record_payload: Option<Vec<u8>>,
) -> (QuorumCertificateDto, Option<crate::api::hmc::L2LockEntry>) {
    assemble_quorum_certificate_with_deadline(
        state,
        lock_id,
        parent_lock,
        shard_id,
        now_ms,
        record_payload,
        None,
        None,
    )
    .await
}

pub async fn assemble_quorum_certificate_with_override(
    state: &AppState,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
    now_ms: u64,
    record_payload: Option<Vec<u8>>,
    quorum_override: Option<usize>,
) -> (QuorumCertificateDto, Option<crate::api::hmc::L2LockEntry>) {
    assemble_quorum_certificate_with_deadline(
        state,
        lock_id,
        parent_lock,
        shard_id,
        now_ms,
        record_payload,
        quorum_override,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn assemble_quorum_certificate_with_deadline(
    state: &AppState,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
    now_ms: u64,
    record_payload: Option<Vec<u8>>,
    quorum_override: Option<usize>,
    checkout_deadline: Option<tokio::time::Instant>,
) -> (QuorumCertificateDto, Option<crate::api::hmc::L2LockEntry>) {
    use humoco_sim_core::types::CommitteeMember;
    let self_pubkey = *state.identity.node_pubkey();
    let self_hrw = *state.identity.hrw_routing_id();
    let (committee, remote, total_active) = if let Some(pm) = &state.peer_manager {
        pm.shard_committee(self_pubkey, self_hrw, shard_id).await
    } else {
        (
            vec![CommitteeMember {
                node_pubkey: self_pubkey,
                hrw_routing_id: self_hrw,
            }],
            Vec::new(),
            1,
        )
    };
    let (base_q, final_size) = humoco_sim_core::types::required_quorum(total_active);
    let required_q = quorum_override
        .unwrap_or(base_q)
        .min(total_active)
        .max(base_q);
    let target_status = u8::from(
        final_size
            && state
                .peer_manager
                .as_ref()
                .map(|pm| pm.is_network_stable_ge20_for_24h(now_ms))
                .unwrap_or(false),
    );
    let mut collected_signatures = Vec::new();
    // A local signature requires the same authoritative, accepted RAM lock
    // as remote shard work. Membership alone is insufficient.
    let sync_ready = state.readiness_manager.is_shard_ready(shard_id);
    if sync_ready
        && committee
            .iter()
            .any(|member| member.node_pubkey == self_pubkey)
    {
        let attestation = create_attestation_for_network(
            &state.identity,
            lock_id,
            parent_lock,
            shard_id,
            target_status,
            now_ms,
            state.network_id,
        );
        if let Ok(bytes) = bincode::serialize(&attestation) {
            let mut retained = None;
            if let Some(payload) = record_payload.as_deref() {
                if let Ok(crate::network::framing::LockWirePayload::Hmc { req, .. }) =
                    bincode::deserialize(payload)
                {
                    let tag = if req.is_genesis {
                        Some(bs58::encode(req.transaction_hash).into_string())
                    } else {
                        req.ds_tag.clone()
                    };
                    if let Some(tag) = tag {
                        if *blake3::hash(tag.as_bytes()).as_bytes() == parent_lock {
                            if let Some(entry) =
                                state.engine.get_hmc_ram_lock(&tag).await.filter(|e| {
                                    e.t_id == lock_id
                                        && e.layer2_voucher_id == req.layer2_voucher_id
                                        && e.sender_ephemeral_pub == req.sender_ephemeral_pub
                                })
                            {
                                let fut = state.engine.persist_original_approval(
                                    tag,
                                    entry,
                                    self_pubkey,
                                    bytes.clone(),
                                    target_status,
                                    now_ms,
                                );
                                retained = if let Some(dl) = checkout_deadline {
                                    match tokio::time::timeout_at(dl, fut).await {
                                        Ok(res) => res.ok(),
                                        Err(_) => None,
                                    }
                                } else {
                                    fut.await.ok()
                                };
                            }
                        }
                    }
                }
            }
            if let Some(att) = retained.and_then(|bytes| AttestationDto::from_wire_bytes(&bytes)) {
                collected_signatures.push(att);
            }
        }
    }
    let candidates: Vec<_> = remote
        .iter()
        .map(|(member, addr)| (member.hrw_routing_id, *addr))
        .collect();
    let expected_members: Vec<_> = remote
        .iter()
        .map(|(member, _)| member.node_pubkey)
        .collect();
    let (query_lookup_tag, query_voucher_id) = if let Some(payload) = record_payload.as_deref() {
        if let Ok(crate::network::framing::LockWirePayload::Hmc { req, .. }) =
            bincode::deserialize(payload)
        {
            let tag = if req.is_genesis {
                Some(bs58::encode(req.transaction_hash).into_string())
            } else {
                req.ds_tag.clone()
            };
            (tag, Some(req.layer2_voucher_id.clone()))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };
    let mut collision = None;
    if collected_signatures.len() < required_q {
        if let (Some(transport), Some(pm), Some(payload)) = (
            &state.transport,
            &state.peer_manager,
            record_payload.as_deref(),
        ) {
            collision = collect_peer_attestations(
                PeerAttestationQuery {
                    transport,
                    peer_mgr: pm,
                    candidate_nodes: &candidates,
                    expected_members: Some(&expected_members),
                    parent_lock,
                    lookup_tag: query_lookup_tag.as_deref(),
                    voucher_id: query_voucher_id.as_deref(),
                    msg_type: humoco_sim_core::wire::MsgType::LockVerifyRequest,
                    resp_msg_type: humoco_sim_core::wire::MsgType::LockVerifyResponse,
                    payload,
                    target_status,
                    lock_id,
                    shard_id,
                    required_q,
                    shard_query_depth: state.shard_query_depth,
                    my_load: state.tier_controller.rolling_24h_average(),
                    quota_limit: (5.0 * state.tier_controller.effective_ncb() as f64).round()
                        as u64,
                    network_id: state.network_id,
                    checkout_deadline,
                },
                &mut collected_signatures,
            )
            .await;
        }
    }
    let signer_bitmap = compute_committee_bitmap(&committee, &collected_signatures);
    let cert = QuorumCertificateDto {
        lock_id: hex::encode(lock_id),
        shard_id,
        status: if collected_signatures.len() >= required_q {
            target_status
        } else {
            0
        },
        active_nodes_count: total_active,
        signer_count: collected_signatures.len(),
        signatures: collected_signatures,
        signer_bitmap,
    };
    // Only an independently verified current committee quorum can promote the
    // local active lock. A local original approval alone remains class zero.
    if cert.is_quorum_reached() {
        if let Some(payload) = record_payload.as_deref() {
            if let Ok(crate::network::framing::LockWirePayload::Hmc { req, .. }) =
                bincode::deserialize(payload)
            {
                let tag = if req.is_genesis {
                    bs58::encode(req.transaction_hash).into_string()
                } else {
                    req.ds_tag.unwrap_or_default()
                };
                if state.engine.get_hmc_ram_lock(&tag).await.is_some() {
                    if let Err(error) = state
                        .engine
                        .persist_confirmation_support_with_deadline(
                            tag,
                            cert.clone(),
                            &state.identity,
                            now_ms,
                            state.network_id,
                            state.peer_manager.clone(),
                            checkout_deadline,
                        )
                        .await
                    {
                        tracing::warn!(%error, "Quorum support was not durably admitted");
                        return (
                            QuorumCertificateDto {
                                status: 0,
                                signatures: Vec::new(),
                                signer_count: 0,
                                signer_bitmap: 0,
                                ..cert
                            },
                            collision,
                        );
                    }
                }
            }
        }
    }
    (cert, collision)
}

/// Handler for POST /status and POST /v1/status.
///
/// 📜 ARCHITECTURAL INVARIANT:
/// Status checks are live queries against the in-RAM collision index (< 1 µs).
/// An old quorum certificate cannot prove that a voucher is currently unspent, because a spend
/// could have occurred at any point afterwards. Therefore, every recipient performs a fresh live status check.
/// Clients and merchants do NOT hoard or chain historical quorum certificates; live status is the single source of truth.
///
/// The current node acknowledges and signs the status verdict directly from its synchronized
/// local state using its own active key (`wrap_and_sign_verdict*`). It does not rely on or verify
/// stale attestation bundles from historical or departed predecessor nodes (Living Mesh vs. ghost nodes).
async fn query_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<L2StatusQuery>,
) -> Response {
    if payload.read_quorum > 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "RecipientChallengeRequired", "verification_endpoint": "/v1/verify-current"
            })),
        )
            .into_response();
    }
    state.metrics.record_read();
    let now_ms = state.net_time_ms();
    let epoch_day = state.tier_controller.current_epoch_day_at(now_ms);
    let client_node_id: u16 =
        if let Some(auth) = headers.get("Authorization").and_then(|h| h.to_str().ok()) {
            let tag = state
                .tier_controller
                .resolve_account_tag(auth)
                .unwrap_or([0u8; 32]);
            u16::from_be_bytes([tag[0], tag[1]])
        } else if let Some(peer_token) = headers.get("X-Peer-Token").and_then(|h| h.to_str().ok()) {
            let hash = *blake3::hash(peer_token.as_bytes()).as_bytes();
            u16::from_be_bytes([hash[0], hash[1]])
        } else {
            let v_hash = *blake3::hash(payload.layer2_voucher_id.as_bytes()).as_bytes();
            u16::from_be_bytes([v_hash[0], v_hash[1]])
        };

    let read_credits = 1;
    if let Err(ingress_err) = state.tier_controller.evaluate_read_quota_with_time(
        client_node_id,
        read_credits,
        epoch_day,
        1.0,
        Some(now_ms),
    ) {
        let reason = match ingress_err {
            IngressError::ReadQuotaExceeded {
                available,
                required,
            } => {
                format!(
                    "429 Read quota exceeded: required {} reads, available {}",
                    required, available
                )
            }
            _ => "429 Read quota exceeded".into(),
        };
        let envelope = wrap_and_sign_verdict(&state.identity, L2Verdict::Rejected { reason });
        return (StatusCode::TOO_MANY_REQUESTS, Json(envelope)).into_response();
    }

    if !state.engine.is_signing_healthy() {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Storage signing unavailable".into(),
            },
        );
        return (StatusCode::SERVICE_UNAVAILABLE, Json(envelope)).into_response();
    }

    let (supplied_shard, supplied_root) = match payload.authenticated_root_shard(now_ms) {
        Ok(Some((shard, root))) => {
            if state
                .engine
                .is_node_banned(&root.sender_ephemeral_pub)
                .await
            {
                let envelope = wrap_and_sign_verdict(
                    &state.identity,
                    L2Verdict::Rejected {
                        reason:
                            "403 Forbidden: Signer is slashed and banned due to equivocation fraud"
                                .into(),
                    },
                );
                return (StatusCode::FORBIDDEN, Json(envelope)).into_response();
            }
            (Some(shard), Some(root))
        }
        Ok(None) => (None, None),
        Err(reason) => {
            let envelope = wrap_and_sign_verdict(
                &state.identity,
                L2Verdict::Rejected {
                    reason: reason.into(),
                },
            );
            return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
        }
    };

    let (mut verdict, ram_genesis_shard, root_conflict) = {
        let hmc = state.engine.hmc_ram.read().await;
        let conflict = match (
            supplied_root,
            hmc.root_anchors.get(&payload.layer2_voucher_id),
        ) {
            (Some(sr), Some(local_root)) => {
                !crate::storage::db::roots::same_root_deed(local_root, sr)
            }
            _ => false,
        };
        let v = hmc.query_status(
            &payload.layer2_voucher_id,
            &payload.challenge_ds_tag,
            &payload.locator_prefixes,
        );
        let sid = hmc
            .get_voucher_genesis_parent(&payload.layer2_voucher_id)
            .map(|p| humoco_sim_core::types::canonical_voucher_shard(&p));
        (v, sid, conflict)
    };
    if root_conflict {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Immutable root proof conflict".into(),
            },
        );
        return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
    }

    if matches!(
        verdict,
        L2Verdict::UnknownVoucher | L2Verdict::MissingLocks { .. }
    ) {
        if let (Some(peer_mgr), Some(transport)) =
            (state.peer_manager.as_ref(), state.transport.as_ref())
        {
            let mut resolved_shard = ram_genesis_shard;
            if resolved_shard.is_none() {
                if let Ok(permit) = state.voucher_root_reads.clone().try_acquire_owned() {
                    let storage = state.storage.clone();
                    let vid = payload.layer2_voucher_id.clone();
                    let read_res = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        storage.voucher_root(&vid)
                    })
                    .await;
                    if let Ok(Ok(Some(disk_root))) = read_res {
                        if let Some(sr) = supplied_root {
                            if !crate::storage::db::roots::same_root_deed(&disk_root, sr) {
                                let envelope = wrap_and_sign_verdict(
                                    &state.identity,
                                    L2Verdict::Rejected {
                                        reason: "Immutable root proof conflict".into(),
                                    },
                                );
                                return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
                            }
                        }
                        if crate::storage::db::roots::root_valid_until(&disk_root)
                            .is_ok_and(|v| v > now_ms)
                        {
                            let root_tag = bs58::encode(disk_root.t_id).into_string();
                            let gp =
                                humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag);
                            resolved_shard =
                                Some(humoco_sim_core::types::canonical_voucher_shard(&gp));
                        }
                    }
                }
            }
            if resolved_shard.is_none() {
                resolved_shard = supplied_shard;
            }

            let self_pubkey = *state.identity.node_pubkey();
            let self_hrw = *state.identity.hrw_routing_id();

            if let Some(shard_id) = resolved_shard {
                let (committee, remote_custodians, _) = peer_mgr
                    .shard_committee(self_pubkey, self_hrw, shard_id)
                    .await;
                let local_is_authoritative = committee.iter().any(|m| m.node_pubkey == self_pubkey)
                    && state.readiness_manager.is_shard_ready(shard_id);

                if !local_is_authoritative {
                    if remote_custodians.is_empty() {
                        verdict = L2Verdict::Rejected {
                            reason: "No eligible shard custodians available".into(),
                        };
                    } else {
                        // Deterministic 1-of-20 (INV-0310): per-lock index from BLAKE3(tag).
                        let tag_hash =
                            *blake3::hash(payload.challenge_ds_tag.as_bytes()).as_bytes();
                        let idx = (tag_hash[0] as usize) % remote_custodians.len();
                        let (_, addr) = remote_custodians[idx];
                        let parent_lock = tag_hash;
                        let declared_read_ema = state.tier_controller.current_read_ema_credits();
                        let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
                        let sender_pubkey = self_pubkey;
                        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
                            &sender_pubkey,
                            0,
                            0,
                            now_ms,
                            declared_write_ema,
                            declared_read_ema,
                            0,
                            true,
                            &[0u8; 32],
                        );
                        let sender_signature =
                            state.identity.signing_key().sign(&digest).to_bytes();
                        let status_query = crate::network::framing::StatusQueryPayload {
                            lock_id: [0u8; 32],
                            parent_lock,
                            shard_id,
                            sender_pubkey,
                            declared_write_ema_micro_bj: declared_write_ema,
                            current_read_ema_credits: declared_read_ema,
                            timestamp_ms: now_ms,
                            sender_signature,
                        };
                        let payload_bytes = bincode::serialize(&status_query).unwrap_or_default();
                        let header = humoco_sim_core::wire::WireHeader::new(
                            humoco_sim_core::wire::MsgType::StatusQuery as u16,
                            1,
                            0,
                            0,
                            payload_bytes.len() as u32,
                        );
                        let remote_verdict: Option<L2Verdict> = async {
                            let conn = transport.connect_peer(addr).await.ok()?;
                            let fut = transport.send_request(&conn, &header, &payload_bytes);
                            let (resp_header, resp_payload) =
                                tokio::time::timeout(std::time::Duration::from_millis(1000), fut)
                                    .await
                                    .ok()?
                                    .ok()?;
                            if resp_header.msg_type
                                != humoco_sim_core::wire::MsgType::StatusResponse as u16
                            {
                                return None;
                            }
                            if (resp_header.flags & humoco_sim_core::wire::FLAG_NOT_READY) != 0 {
                                return Some(L2Verdict::Rejected {
                                    reason: "Remote durable state pending".into(),
                                });
                            }
                            if resp_payload.is_empty()
                                || (resp_header.flags & humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED)
                                    != 0
                                || (resp_header.flags & humoco_sim_core::wire::FLAG_PEER_SUSPENDED)
                                    != 0
                            {
                                return None;
                            }
                            if let Some(entry) = serde_json::from_slice::<
                                crate::api::hmc::L2LockEntry,
                            >(&resp_payload)
                            .ok()
                            .or_else(|| bincode::deserialize(&resp_payload).ok())
                            {
                                if entry.layer2_voucher_id == payload.layer2_voucher_id {
                                    return Some(L2Verdict::Verified { lock_entry: entry });
                                }
                            }
                            None
                        }
                        .await;
                        if let Some(remote) = remote_verdict {
                            verdict = remote;
                        }
                    }
                }
            } else {
                let (committee, remote_peers, _) =
                    peer_mgr.shard_committee(self_pubkey, self_hrw, 0).await;
                let sole_ready_island = remote_peers.is_empty()
                    && committee.iter().any(|m| m.node_pubkey == self_pubkey)
                    && state.readiness_manager.is_shard_ready(0);
                if !sole_ready_island {
                    verdict = L2Verdict::Rejected {
                        reason: "Voucher root routing context unavailable".into(),
                    };
                }
            }
        }
    }

    if !state.engine.is_signing_healthy() {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Storage signing unavailable".into(),
            },
        );
        return (StatusCode::SERVICE_UNAVAILABLE, Json(envelope)).into_response();
    }

    // Legacy lookup never manufactures a write approval as fresh read evidence.
    let status = if matches!(&verdict, L2Verdict::Rejected { .. }) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    let quorum_certificate = None;
    let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, quorum_certificate);
    (status, Json(envelope)).into_response()
}

fn map_ingress_error(state: &AppState, err: IngressError, has_auth_token: bool) -> Response {
    let mut required_diff_hdr = None;
    let mut challenge_opt = None;
    let mut expires_at_opt = None;

    let (status, reason) = match &err {
        IngressError::PoWRequired {
            challenge,
            difficulty,
            expires_at,
        } => {
            required_diff_hdr = Some(*difficulty);
            challenge_opt = Some(challenge.clone());
            expires_at_opt = Some(*expires_at);
            (
                StatusCode::UNAUTHORIZED,
                "Proof-of-Work challenge response required".into(),
            )
        }
        IngressError::InvalidPoW(err) => {
            if let crate::ingress::pow::PowError::InsufficientDifficulty { required, provided } =
                err
            {
                required_diff_hdr = Some(*required);
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    format!(
                        "Gateway under load: insufficient PoW difficulty (provided: {}, required: {})",
                        provided, required
                    ),
                )
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid Proof of Work: {}", err),
                )
            }
        }
        IngressError::QuotaExceeded {
            available,
            required,
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "VIP Quota exceeded: required {} byte-years, available {}",
                required, available
            ),
        ),
        IngressError::ReadQuotaExceeded {
            available,
            required,
        } => (
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
        IngressError::InvalidPeerToken => {
            (StatusCode::UNAUTHORIZED, "Invalid F2F peer token".into())
        }
        IngressError::Storage(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        ),
        IngressError::QuotaPersistenceUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "VIP Quota persistence queue is full or closed".into(),
        ),
    };

    match &err {
        IngressError::QuotaExceeded { .. } | IngressError::ReadQuotaExceeded { .. } => {
            state.metrics.record_rejected_quota_429();
        }
        IngressError::InvalidPoW(..) | IngressError::PoWRequired { .. } => {
            state.metrics.record_rejected_bad_pow_400();
        }
        _ => {
            if status == StatusCode::TOO_MANY_REQUESTS {
                state.metrics.record_rejected_capacity_429();
            }
        }
    }

    if matches!(err, IngressError::QuotaExceeded { .. }) && has_auth_token {
        let envelope = wrap_and_sign_verdict(&state.identity, L2Verdict::Rejected { reason });
        return (status, Json(envelope)).into_response();
    }

    let err_resp = ErrorResponse {
        error: match &err {
            IngressError::QuotaExceeded { .. } => "QuotaExceeded".to_string(),
            IngressError::ReadQuotaExceeded { .. } => "ReadQuotaExceeded".to_string(),
            IngressError::InvalidPoW(..) => "InvalidPoW".to_string(),
            IngressError::PoWRequired { .. } => "PoWRequired".to_string(),
            IngressError::InvalidAuthToken => "InvalidAuthToken".to_string(),
            IngressError::InvalidPeerToken => "InvalidPeerToken".to_string(),
            IngressError::QuotaPersistenceUnavailable => "QuotaPersistenceUnavailable".to_string(),
            _ => "AdmissionDenied".to_string(),
        },
        message: reason,
        challenge: challenge_opt,
        difficulty: required_diff_hdr,
        expires_at: expires_at_opt,
    };
    let mut resp = (status, Json(err_resp)).into_response();
    if let Some(req_diff) = required_diff_hdr {
        if let Ok(hdr_val) = axum::http::HeaderValue::from_str(&req_diff.to_string()) {
            resp.headers_mut().insert(
                axum::http::HeaderName::from_static("x-required-difficulty"),
                hdr_val,
            );
        }
    }
    resp
}

/// Dedicated handler for HMC L2LockRequest.
///
/// 📜 ARCHITECTURAL INVARIANT:
/// The merchant/cash register has received the Layer-1 Voucher deed (`ProofChain`) directly from the customer.
/// This handler merely registers the auxiliary collision lock (`parent_lock -> child_lock`) in the blind
/// L2 Collision Lock Registry to prevent double-spends. The returned Attestation / Quorum Certificate is an
/// auxiliary clearance receipt ("Unbedenklichkeitsbescheinigung"), NOT the money/deed itself.
async fn submit_hmc_lock(
    state: AppState,
    headers: HeaderMap,
    req: L2LockRequest,
    start: std::time::Instant,
) -> Response {
    let checkout_deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(780);
    submit_hmc_lock_with_deadline(state, headers, req, start, checkout_deadline).await
}

async fn submit_hmc_lock_with_deadline(
    state: AppState,
    headers: HeaderMap,
    req: L2LockRequest,
    start: std::time::Instant,
    checkout_deadline: tokio::time::Instant,
) -> Response {
    state.metrics.record_write();
    // 0. Check if submitter or ephemeral key is banned/slashed
    if state.engine.is_node_banned(&req.sender_ephemeral_pub).await
        || state
            .engine
            .is_node_banned(&req.auth.ephemeral_pubkey)
            .await
    {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "403 Forbidden: Signer is slashed and banned due to equivocation fraud"
                    .into(),
            },
        );
        return (StatusCode::FORBIDDEN, Json(envelope)).into_response();
    }

    // Lifecycle sunset & bridge lock checks
    let suite_id = if req
        .privacy_guard
        .as_deref()
        .is_some_and(|s| s.contains("suite2"))
    {
        2
    } else {
        1
    };

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

    const MAX_SENDER_CLOCK_DRIFT_MS: u64 = 30_000;
    if !req.is_genesis
        && (req.created_at_ms == 0
            || req.created_at_ms > now_ms.saturating_add(MAX_SENDER_CLOCK_DRIFT_MS))
    {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Sender timestamp outside 30s clock drift window".into(),
            },
        );
        return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
    }

    // # Early Inexpensive Ingress Admission (A25-04 / Rule 9):
    // Validate credentials presence before any disk lookups (get_hmc_voucher_root_valid)
    // or asymmetric signing operations.
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
    let req_q_override = headers
        .get("X-Required-Quorum")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());

    let parent_for_pow_val = if req.is_genesis {
        None
    } else {
        let tag = req.ds_tag.as_deref().unwrap_or_default();
        Some(*blake3::hash(tag.as_bytes()).as_bytes())
    };
    let parent_for_pow = parent_for_pow_val.as_ref();

    let has_credentials = auth_token.is_some()
        || peer_token.is_some()
        || (pow_challenge.is_some() && pow_nonce.is_some());

    if !has_credentials && state.pow_engine.default_difficulty() > 0 {
        let (challenge, difficulty, expires_at) = state
            .pow_engine
            .generate_challenge_for_parent(parent_for_pow.unwrap_or(&[0u8; 32]));
        return map_ingress_error(
            &state,
            IngressError::PoWRequired {
                challenge,
                difficulty,
                expires_at,
            },
            false,
        );
    }

    let (valid_until, root_valid_until) = if req.is_genesis {
        // Genesis is only a Root Anchor; its signed validity is immutable.
        let raw_del = match req.deletable_at.as_deref() {
            Some(raw) => raw,
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
        if crate::storage::db::roots::parse_deletable_at_ms(raw_del).is_err() {
            let envelope = wrap_and_sign_verdict(
                &state.identity,
                L2Verdict::Rejected {
                    reason: "Genesis lock requires valid deletable_at timestamp".into(),
                },
            );
            return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
        }
        let root_valid_until_ms =
            match crate::storage::db::roots::root_valid_until(&L2LockEntry::from(&req)) {
                Ok(v) => v,
                Err(e) => {
                    let envelope = wrap_and_sign_verdict(
                        &state.identity,
                        L2Verdict::Rejected {
                            reason: format!("Invalid genesis root TTL: {e}"),
                        },
                    );
                    return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
                }
            };
        (root_valid_until_ms, root_valid_until_ms)
    } else {
        // Follow-up Lock (Transfer / Split / Spend):
        // The separate genesis Root Anchor must be registered first.
        // Without a known root (locally or from the client-supplied TTL),
        // there is no immutable TTL to inherit — reject with 400 Bad Request.
        let stored_root_valid = state
            .engine
            .get_hmc_voucher_root_valid(&req.layer2_voucher_id)
            .await;
        let parsed_deletable = req
            .causal_output
            .as_ref()
            .filter(|proof| proof.is_root)
            .map(|proof| proof.root_valid_until_ms)
            .or_else(|| {
                req.deletable_at
                    .as_deref()
                    .and_then(|raw| crate::storage::db::roots::parse_deletable_at_ms(raw).ok())
            });
        let root = match stored_root_valid {
            Some(r) => r,
            None => {
                if let Some(del) = parsed_deletable {
                    del
                } else if let Some(disk_root) =
                    lookup_local_voucher_root(&state, &req.layer2_voucher_id).await
                {
                    disk_root
                } else {
                    let envelope = wrap_and_sign_verdict(
                        &state.identity,
                        L2Verdict::Rejected {
                            reason: "Unknown voucher root: genesis lock must be anchored first"
                                .into(),
                        },
                    );
                    return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
                }
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
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
    let shard_id = if req.is_genesis {
        // Do not mutate root routing before authentication and durable anchor
        // admission. The engine publishes the root only after validation.
        humoco_sim_core::types::extract_shard_id(&parent_bytes)
    } else if let Some(sid) = state
        .engine
        .get_hmc_voucher_genesis_shard(&req.layer2_voucher_id)
        .await
    {
        sid
    } else {
        humoco_sim_core::types::voucher_shard_id(&req.layer2_voucher_id)
    };
    let is_responsible = if let Some(pm) = &state.peer_manager {
        pm.is_local_committee_member(
            *state.identity.node_pubkey(),
            *state.identity.hrw_routing_id(),
            shard_id,
        )
        .await
    } else {
        true
    };

    if state.transport.is_some()
        && is_responsible
        && !req.is_genesis
        && !state.readiness_manager.is_shard_ready(shard_id)
    {
        state.readiness_manager.request_sync(shard_id);
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: format!("FLAG_NOT_READY: Shard {} syncing", shard_id),
            },
        );
        return (StatusCode::SERVICE_UNAVAILABLE, Json(envelope)).into_response();
    }

    // # Architectural Invariant (Rule 9 / A09): Cheap-Checks-First
    let ttl_seconds = (root_valid_until.saturating_sub(now_ms)) / 1000;

    // A root retry is metadata idempotency, not a new PoW purchase or vote.
    // Await an exact durable acknowledgment even if its first commit is pending.
    let is_root_retry = if req.is_genesis {
        let hmc = state.engine.hmc_ram.read().await;
        hmc.root_anchors
            .get(&req.layer2_voucher_id)
            .is_some_and(|existing| {
                crate::storage::db::roots::same_root_deed(existing, &entry)
                    && hmc.voucher_roots.get(&req.layer2_voucher_id).copied()
                        == Some(root_valid_until)
            })
    } else {
        false
    };

    let existing_spend_retry = if is_responsible {
        let hmc = state.engine.hmc_ram.read().await;
        hmc.locks.get(&lookup_tag).and_then(|existing| {
            if existing.t_id == entry.t_id
                && existing.layer2_voucher_id == entry.layer2_voucher_id
                && existing.sender_ephemeral_pub == entry.sender_ephemeral_pub
            {
                Some(existing.clone())
            } else {
                None
            }
        })
    } else {
        None
    };

    let is_spend_retry = existing_spend_retry.is_some();
    let is_retry = is_root_retry || is_spend_retry;

    // Validate token/work and rate admission before both retry branches (S01-02).
    // Duplicate storage quota is not charged on idempotent retries.
    let ingress_tier = match state
        .tier_controller
        .evaluate_and_charge_with_time_and_retry(
            auth_token,
            peer_token,
            pow_challenge,
            pow_nonce,
            ttl_seconds,
            parent_for_pow,
            Some(now_ms),
            is_retry,
        )
        .await
    {
        Ok(tier) => tier,
        Err(err) => {
            return map_ingress_error(&state, err, auth_token.is_some());
        }
    };

    if is_root_retry {
        if !verify_l2_lock_signature(&req) {
            return (
                StatusCode::BAD_REQUEST,
                Json(wrap_and_sign_verdict(
                    &state.identity,
                    L2Verdict::Rejected {
                        reason: "Invalid cryptographic signature".into(),
                    },
                )),
            )
                .into_response();
        }
        return commit_root_registration(
            &state,
            lookup_tag,
            entry,
            now_ms,
            ("Idempotent", 0),
            should_warn,
        )
        .await;
    }

    // 4. Fast-path idempotency check: if identical lock already verified in RAM, return 200 OK immediately
    // Phase 10 (Hot-Path-Locks): the RAM read guard is cloned and dropped
    // BEFORE any network await (`assemble_quorum_certificate`), so writers
    // are never blocked while this gateway waits for quorum.
    if let Some(existing) = existing_spend_retry {
        // Verify signature on idempotent retry so caller cannot forge verdicts with invalid signatures
        if !verify_l2_lock_signature(&req) {
            let envelope = wrap_and_sign_verdict(
                &state.identity,
                L2Verdict::Rejected {
                    reason: "Invalid cryptographic signature".into(),
                },
            );
            return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
        }

        let verdict = L2Verdict::Verified {
            lock_entry: existing,
        };
        let now_ms = state.net_time_ms();
        let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
        let declared_read_ema = state.tier_controller.current_read_ema_credits();
        let sender_pubkey = *state.identity.node_pubkey();
        let ttl_sec = (root_valid_until.saturating_sub(now_ms)) / 1000;
        let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_sec);
        let op_hash = entry.t_id;
        // Epoch-bound envelope (Phase 1 P0): reserve epoch first so the
        // signed digest and the wire payload commit to the same
        // (epoch_day, epoch_seq).
        let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) = state
            .tier_controller
            .record_declared_usage(now_ms, footprint);
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            &sender_pubkey,
            epoch_day,
            epoch_seq,
            now_ms,
            declared_write_ema,
            declared_read_ema,
            footprint,
            false,
            &op_hash,
        );
        let sender_signature = state.identity.signing_key().sign(&digest).to_bytes();
        let current_anl_24h = declared_write_ema;
        let wire_payload = bincode::serialize(&crate::network::framing::LockWirePayload::Hmc {
            req: req.clone(),
            chain: None,
            root_valid_until,
            epoch_day,
            epoch_seq,
            cumulative_micro_byte_years,
            prev_day_final_bytes,
            current_anl_24h,
            declared_write_ema_micro_bj: declared_write_ema,
            declared_read_ema_credits: declared_read_ema,
            sender_pubkey,
            sender_signature,
            timestamp_ms: now_ms,
        })
        .ok();
        let start_quorum = std::time::Instant::now();
        let (cert, remote_collision) = assemble_quorum_certificate_with_deadline(
            &state,
            entry.t_id,
            parent_bytes,
            shard_id,
            now_ms,
            wire_payload,
            req_q_override,
            Some(checkout_deadline),
        )
        .await;
        state.metrics.record_quorum_latency(start_quorum.elapsed());
        state
            .metrics
            .record_local_latency(std::time::Duration::from_micros(1));

        // Remote double-spend evidence overrides idempotent fast-path.
        if let Some(existing_lock) = remote_collision.filter(|_| !cert.is_quorum_reached()) {
            let verdict = L2Verdict::Conflict { existing_lock };
            let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, Some(cert));
            state.metrics.record_rejected_conflict_409();
            state.metrics.record_e2e_latency(start.elapsed());
            return (StatusCode::CONFLICT, Json(envelope)).into_response();
        }

        if !cert.is_quorum_reached() {
            let reason = format!(
                "Quorum not reached: required {} signatures, collected {}",
                cert.required_quorum(),
                cert.signatures.len()
            );
            let rej_verdict = L2Verdict::Rejected { reason };
            let envelope =
                wrap_and_sign_verdict_with_quorum(&state.identity, rej_verdict, Some(cert));
            state.metrics.record_e2e_latency(start.elapsed());
            let mut resp = (StatusCode::SERVICE_UNAVAILABLE, Json(envelope)).into_response();
            if should_warn {
                resp.headers_mut().insert(
                    axum::http::HeaderName::from_static("x-deprecation-warning"),
                    axum::http::HeaderValue::from_static(
                        "Suite 1 (Ed25519) deprecated - migrate to suite 2",
                    ),
                );
            }
            return resp;
        }

        let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, Some(cert));
        state.metrics.record_e2e_latency(start.elapsed());
        let mut resp = (StatusCode::OK, Json(envelope)).into_response();
        if should_warn {
            resp.headers_mut().insert(
                axum::http::HeaderName::from_static("x-deprecation-warning"),
                axum::http::HeaderValue::from_static(
                    "Suite 1 (Ed25519) deprecated - migrate to suite 2",
                ),
            );
        }
        return resp;
    }

    // 2. Verify V3 signature: only executed after cheap credential check passes!
    if !verify_l2_lock_signature(&req) {
        if let crate::ingress::IngressTier::Tier1Vip = ingress_tier {
            if let Some(token) = auth_token {
                if let Ok(account_tag) = state.tier_controller.resolve_account_tag(token) {
                    let required_byte_years =
                        humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl_seconds);
                    let _ = state
                        .tier_controller
                        .topup_vip_quota(account_tag, required_byte_years);
                }
            }
        }
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Invalid cryptographic signature".into(),
            },
        );
        return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
    }

    let tier_str = match ingress_tier {
        crate::ingress::IngressTier::Tier1Vip => "VIP",
        crate::ingress::IngressTier::Tier2F2F => "F2F",
        crate::ingress::IngressTier::Tier3Public => "Free",
    };
    let byte_years = humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl_seconds);

    // Genesis is only a durable Root Anchor. No exclusion is inserted, no
    // original spend approval or quorum certificate may be minted for it.
    if req.is_genesis {
        return commit_root_registration(
            &state,
            lookup_tag,
            entry,
            now_ms,
            (tier_str, byte_years),
            should_warn,
        )
        .await;
    }

    // 4. Ingress: Local shard storage vs. Stateless Gateway routing
    let (verdict, is_new, quorum_certificate) = if is_responsible {
        let start_local = std::time::Instant::now();
        let (local_verdict, local_is_new) = match tokio::time::timeout_at(
            checkout_deadline,
            state.engine.ingress_hmc_lock_durable(
                lookup_tag.clone(),
                entry.clone(),
                IngressOrigin::ClientApi,
                Some(now_ms),
                Some(tier_str),
                Some(byte_years),
                Some(req.layer2_voucher_id.clone()),
            ),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => {
                let reason =
                    "504 Gateway Timeout: Local durable persistence exceeded checkout budget"
                        .to_string();
                let rej_verdict = L2Verdict::Rejected { reason };
                let envelope = wrap_and_sign_verdict(&state.identity, rej_verdict);
                return (StatusCode::GATEWAY_TIMEOUT, Json(envelope)).into_response();
            }
        };
        state.metrics.record_local_latency(start_local.elapsed());

        let (q_cert, remote_collision) = match &local_verdict {
            L2Verdict::Conflict { .. } | L2Verdict::Rejected { .. } => (None, None),
            _ => {
                let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
                let declared_read_ema = state.tier_controller.current_read_ema_credits();
                let sender_pubkey = *state.identity.node_pubkey();
                let footprint =
                    humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_seconds);
                let op_hash = entry.t_id;
                // Epoch-bound envelope (Phase 1 P0): reserve epoch first so the
                // signed digest and the wire payload commit to the same
                // (epoch_day, epoch_seq).
                let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
                    state
                        .tier_controller
                        .record_declared_usage(now_ms, footprint);
                let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
                    &sender_pubkey,
                    epoch_day,
                    epoch_seq,
                    now_ms,
                    declared_write_ema,
                    declared_read_ema,
                    footprint,
                    false,
                    &op_hash,
                );
                let sender_signature = state.identity.signing_key().sign(&digest).to_bytes();
                let current_anl_24h = declared_write_ema;
                let wire_payload =
                    bincode::serialize(&crate::network::framing::LockWirePayload::Hmc {
                        req: req.clone(),
                        chain: None,
                        root_valid_until,
                        epoch_day,
                        epoch_seq,
                        cumulative_micro_byte_years,
                        prev_day_final_bytes,
                        current_anl_24h,
                        declared_write_ema_micro_bj: declared_write_ema,
                        declared_read_ema_credits: declared_read_ema,
                        sender_pubkey,
                        sender_signature,
                        timestamp_ms: now_ms,
                    })
                    .ok();
                let start_quorum = std::time::Instant::now();
                let (cert, remote_collision) = assemble_quorum_certificate_with_deadline(
                    &state,
                    entry.t_id,
                    parent_bytes,
                    shard_id,
                    now_ms,
                    wire_payload,
                    req_q_override,
                    Some(checkout_deadline),
                )
                .await;
                state.metrics.record_quorum_latency(start_quorum.elapsed());
                (Some(cert), remote_collision)
            }
        };
        // Remote genuine conflict overrides local Verified (split-brain).
        if let Some(existing_lock) = remote_collision.filter(|_| {
            !q_cert
                .as_ref()
                .map(|c| c.is_quorum_reached())
                .unwrap_or(false)
        }) {
            (L2Verdict::Conflict { existing_lock }, false, q_cert)
        } else {
            (local_verdict, local_is_new, q_cert)
        }
    } else {
        // Stateless routing Gateway: DO NOT write to local engine or redb!
        // Instead, route and collect P2P shard attestations from the responsible shard nodes.
        let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
        let declared_read_ema = state.tier_controller.current_read_ema_credits();
        let sender_pubkey = *state.identity.node_pubkey();
        let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_seconds);
        let op_hash = entry.t_id;
        // Epoch-bound envelope (Phase 1 P0).
        let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) = state
            .tier_controller
            .record_declared_usage(now_ms, footprint);
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            &sender_pubkey,
            epoch_day,
            epoch_seq,
            now_ms,
            declared_write_ema,
            declared_read_ema,
            footprint,
            false,
            &op_hash,
        );
        let sender_signature = state.identity.signing_key().sign(&digest).to_bytes();
        let current_anl_24h = declared_write_ema;
        let wire_payload = bincode::serialize(&crate::network::framing::LockWirePayload::Hmc {
            req: req.clone(),
            chain: None,
            root_valid_until,
            epoch_day,
            epoch_seq,
            cumulative_micro_byte_years,
            prev_day_final_bytes,
            current_anl_24h,
            declared_write_ema_micro_bj: declared_write_ema,
            declared_read_ema_credits: declared_read_ema,
            sender_pubkey,
            sender_signature,
            timestamp_ms: now_ms,
        })
        .ok();
        let start_quorum = std::time::Instant::now();
        let (cert, remote_collision) = assemble_quorum_certificate_with_deadline(
            &state,
            entry.t_id,
            parent_bytes,
            shard_id,
            now_ms,
            wire_payload,
            req_q_override,
            Some(checkout_deadline),
        )
        .await;
        state.metrics.record_quorum_latency(start_quorum.elapsed());
        // FLAG_COLLISION_DETECTED from any shard proves double-spend: 409.
        if let Some(existing_lock) = remote_collision.filter(|_| !cert.is_quorum_reached()) {
            let verdict = L2Verdict::Conflict { existing_lock };
            (verdict, false, Some(cert))
        } else {
            let verdict = L2Verdict::Verified {
                lock_entry: entry.clone(),
            };
            (verdict, true, Some(cert))
        }
    };

    // 5. Quorum-Gating: No HTTP 200/201 without reaching quorum.
    // Apply quorum gating to successful Verified outcomes; validated Conflict returns 409.
    if matches!(&verdict, L2Verdict::Verified { .. }) {
        if let Some(ref cert) = quorum_certificate {
            if !cert.is_quorum_reached() {
                let reason = format!(
                    "Quorum not reached: required {} signatures, collected {}",
                    cert.required_quorum(),
                    cert.signatures.len()
                );
                let rej_verdict = L2Verdict::Rejected { reason };
                let envelope = wrap_and_sign_verdict_with_quorum(
                    &state.identity,
                    rej_verdict,
                    Some(cert.clone()),
                );
                state.metrics.record_e2e_latency(start.elapsed());
                let mut resp = (StatusCode::SERVICE_UNAVAILABLE, Json(envelope)).into_response();
                if should_warn {
                    resp.headers_mut().insert(
                        axum::http::HeaderName::from_static("x-deprecation-warning"),
                        axum::http::HeaderValue::from_static(
                            "Suite 1 (Ed25519) deprecated - migrate to suite 2",
                        ),
                    );
                }
                return resp;
            }
        }
    }

    // A rejected durable write is never an HTTP success or an idempotent replay.
    let status = match &verdict {
        L2Verdict::Conflict { .. } => {
            state.metrics.record_rejected_conflict_409();
            StatusCode::CONFLICT
        }
        L2Verdict::Rejected { reason } => {
            let code = write_rejection_status(reason);
            if code == StatusCode::TOO_MANY_REQUESTS {
                state.metrics.record_rejected_capacity_429();
            } else {
                state.metrics.record_lock_rejected();
            }
            code
        }
        L2Verdict::Verified { .. } if is_new => StatusCode::CREATED,
        L2Verdict::Verified { .. } => StatusCode::OK,
        _ => StatusCode::BAD_REQUEST,
    };
    state.metrics.record_e2e_latency(start.elapsed());
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

/// Ordered durable-prefix registration for POST /v1/lock/chain.
async fn submit_hmc_chain_lock(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(chain_req): Json<L2ChainLockRequest>,
) -> Response {
    let start = std::time::Instant::now();
    submit_hmc_chain_lock_inner(state, headers, chain_req, start).await
}

async fn submit_hmc_chain_lock_inner(
    state: AppState,
    headers: HeaderMap,
    chain_req: L2ChainLockRequest,
    start: std::time::Instant,
) -> Response {
    let checkout_deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(780);
    state.metrics.record_write();
    if chain_req.chain.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "InvalidRequest".into(),
                message: "Empty chain: at least one lock required".into(),
                challenge: None,
                difficulty: None,
                expires_at: None,
            }),
        )
            .into_response();
    }

    if chain_req.chain.len() == 1 && chain_req.chain[0].is_genesis {
        return submit_hmc_lock_with_deadline(
            state,
            headers,
            chain_req.chain[0].clone(),
            start,
            checkout_deadline,
        )
        .await;
    }

    let last_hop = match chain_req.chain.last() {
        Some(h) => h,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "InvalidRequest".into(),
                    message: "Empty chain: at least one lock required".into(),
                    challenge: None,
                    difficulty: None,
                    expires_at: None,
                }),
            )
                .into_response();
        }
    };
    let terminal_parent_for_pow_val = if last_hop.is_genesis {
        None
    } else {
        let tag = last_hop.ds_tag.as_deref().unwrap_or_default();
        Some(*blake3::hash(tag.as_bytes()).as_bytes())
    };
    let terminal_parent_for_pow = terminal_parent_for_pow_val.as_ref();

    // Cheap filters first (A25-04 / A25-R3 / Rule 9):
    // Validate credentials presence before any disk lookups (get_hmc_voucher_root_valid)
    // or asymmetric signing operations.
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

    let has_credentials = auth_token.is_some()
        || peer_token.is_some()
        || (pow_challenge.is_some() && pow_nonce.is_some());

    let now_ms = state.net_time_ms();

    if !has_credentials {
        let (status, reason, req_diff, chal, exp) = match state
            .tier_controller
            .evaluate_and_charge_with_time(
                None,
                None,
                None,
                None,
                0,
                terminal_parent_for_pow,
                Some(now_ms),
            )
            .await
        {
            Err(IngressError::PoWRequired {
                challenge,
                difficulty,
                expires_at,
            }) => {
                state.metrics.record_rejected_bad_pow_400();
                (
                    StatusCode::UNAUTHORIZED,
                    "Proof-of-Work challenge response required".to_string(),
                    Some(difficulty),
                    Some(challenge),
                    Some(expires_at),
                )
            }
            _ => (
                StatusCode::UNAUTHORIZED,
                "Unauthorized: credentials or PoW required".to_string(),
                None,
                None,
                None,
            ),
        };
        let err_resp = ErrorResponse {
            error: "PoWRequired".into(),
            message: reason,
            challenge: chal,
            difficulty: req_diff,
            expires_at: exp,
        };
        let mut resp = (status, Json(err_resp)).into_response();
        if let Some(req_diff) = req_diff {
            if let Ok(hdr_val) = axum::http::HeaderValue::from_str(&req_diff.to_string()) {
                resp.headers_mut().insert(
                    axum::http::HeaderName::from_static("x-required-difficulty"),
                    hdr_val,
                );
            }
        }
        return resp;
    }

    // Verify PoW in RAM before any disk lookup (A25-04 / A25-R3 / Rule 9)
    if let (Some(challenge), Some(nonce)) = (pow_challenge, pow_nonce) {
        let load_factor = (state.tier_controller.rolling_24h_average_at(now_ms / 1000) as f64
            / state.tier_controller.effective_ncb().max(1) as f64)
            .clamp(0.0, 1.0);
        let dynamic_difficulty = state.pow_engine.required_difficulty_for_load(load_factor);

        if let Err(err) = state
            .pow_engine
            .verify_pow_for_parent(
                challenge,
                nonce,
                dynamic_difficulty,
                terminal_parent_for_pow,
            )
            .await
        {
            state.metrics.record_rejected_bad_pow_400();
            let (status, reason) = if let crate::ingress::pow::PowError::InsufficientDifficulty {
                required,
                provided,
            } = err
            {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    format!(
                        "Gateway under load: insufficient PoW difficulty (provided: {}, required: {})",
                        provided, required
                    ),
                )
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid Proof of Work: {}", err),
                )
            };
            return (
                status,
                Json(ErrorResponse {
                    error: "InvalidPoW".into(),
                    message: reason,
                    challenge: None,
                    difficulty: Some(dynamic_difficulty),
                    expires_at: None,
                }),
            )
                .into_response();
        }
    }

    // Banned check for batch auth and each hop
    if state
        .engine
        .is_node_banned(&chain_req.auth.ephemeral_pubkey)
        .await
    {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "403 Forbidden: Signer is slashed and banned due to equivocation fraud"
                    .into(),
            },
        );
        return (StatusCode::FORBIDDEN, Json(envelope)).into_response();
    }

    // Derive root_valid_until for Byte-Years accounting (same logic as engine)
    let mut chain_genesis_root = None;
    for hop in &chain_req.chain {
        if hop.is_genesis {
            match crate::storage::db::roots::root_valid_until(&L2LockEntry::from(hop)) {
                Ok(valid_ms) => chain_genesis_root = Some(valid_ms),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "InvalidRequest".into(),
                            message: format!("Invalid genesis root TTL: {e}"),
                            challenge: None,
                            difficulty: None,
                            expires_at: None,
                        }),
                    )
                        .into_response();
                }
            }
        }
    }
    let stored_root = state
        .engine
        .get_hmc_voucher_root_valid(&chain_req.layer2_voucher_id)
        .await;
    let Some(root_valid_until) = stored_root.or(chain_genesis_root) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "InvalidRequest".into(),
                message: "Unknown voucher root: signed Root Anchor required".into(),
                challenge: None,
                difficulty: None,
                expires_at: None,
            }),
        )
            .into_response();
    };
    let ttl_seconds = root_valid_until.saturating_sub(now_ms) / 1000;

    // 3-Tier Access Evaluation (single charge for whole batch, bound to terminal parent: A25-R2)
    let ingress_tier = match state
        .tier_controller
        .evaluate_and_charge_with_time(
            auth_token,
            peer_token,
            pow_challenge,
            pow_nonce,
            ttl_seconds,
            terminal_parent_for_pow,
            Some(now_ms),
        )
        .await
    {
        Ok(tier) => tier,
        Err(err) => {
            let (status, reason) = match &err {
                IngressError::PoWRequired { .. } => (
                    StatusCode::UNAUTHORIZED,
                    "Proof-of-Work challenge response required".into(),
                ),
                IngressError::InvalidPoW(e) => {
                    if let crate::ingress::pow::PowError::InsufficientDifficulty {
                        required,
                        provided,
                    } = e
                    {
                        (
                            StatusCode::TOO_MANY_REQUESTS,
                            format!(
                                "Gateway under load: insufficient PoW difficulty (provided: {}, required: {})",
                                provided, required
                            ),
                        )
                    } else {
                        (
                            StatusCode::UNAUTHORIZED,
                            format!("Invalid Proof of Work: {}", e),
                        )
                    }
                }
                IngressError::QuotaExceeded {
                    available,
                    required,
                } => (
                    StatusCode::TOO_MANY_REQUESTS,
                    format!(
                        "VIP Quota exceeded: required {} byte-years, available {}",
                        required, available
                    ),
                ),
                IngressError::ReadQuotaExceeded {
                    available,
                    required,
                } => (
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
                IngressError::InvalidPeerToken => {
                    (StatusCode::UNAUTHORIZED, "Invalid F2F peer token".into())
                }
                IngressError::Storage(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Storage error: {}", e),
                ),
                IngressError::QuotaPersistenceUnavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "VIP Quota persistence queue is full or closed".into(),
                ),
            };
            match &err {
                IngressError::QuotaExceeded { .. } | IngressError::ReadQuotaExceeded { .. } => {
                    state.metrics.record_rejected_quota_429();
                }
                IngressError::InvalidPoW(..) | IngressError::PoWRequired { .. } => {
                    state.metrics.record_rejected_bad_pow_400();
                }
                _ => {
                    if status == StatusCode::TOO_MANY_REQUESTS {
                        state.metrics.record_rejected_capacity_429();
                    }
                }
            }
            if matches!(err, IngressError::QuotaExceeded { .. }) && auth_token.is_some() {
                let envelope =
                    wrap_and_sign_verdict(&state.identity, L2Verdict::Rejected { reason });
                return (status, Json(envelope)).into_response();
            }
            let err_resp = ErrorResponse {
                error: match &err {
                    IngressError::QuotaExceeded { .. } => "QuotaExceeded".to_string(),
                    IngressError::ReadQuotaExceeded { .. } => "ReadQuotaExceeded".to_string(),
                    IngressError::InvalidPoW(..) => "InvalidPoW".to_string(),
                    IngressError::PoWRequired { .. } => "PoWRequired".to_string(),
                    IngressError::InvalidAuthToken => "InvalidAuthToken".to_string(),
                    IngressError::InvalidPeerToken => "InvalidPeerToken".to_string(),
                    IngressError::QuotaPersistenceUnavailable => {
                        "QuotaPersistenceUnavailable".to_string()
                    }
                    _ => "AdmissionDenied".to_string(),
                },
                message: reason,
                challenge: None,
                difficulty: None,
                expires_at: None,
            };
            return (status, Json(err_resp)).into_response();
        }
    };

    let tier_str = match ingress_tier {
        crate::ingress::IngressTier::Tier1Vip => "VIP",
        crate::ingress::IngressTier::Tier2F2F => "F2F",
        crate::ingress::IngressTier::Tier3Public => "Free",
    };
    let byte_years = humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl_seconds);

    let first_hop = match chain_req.chain.first() {
        Some(hop) => hop,
        None => {
            let envelope = wrap_and_sign_verdict(
                &state.identity,
                L2Verdict::Rejected {
                    reason: "Chain cannot be empty".into(),
                },
            );
            return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
        }
    };
    let genesis_tag = if first_hop.is_genesis {
        bs58::encode(&first_hop.transaction_hash).into_string()
    } else {
        first_hop.ds_tag.clone().unwrap_or_default()
    };
    let _genesis_parent_bytes = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let shard_id = if let Some(root) = chain_req.chain.first().filter(|hop| hop.is_genesis) {
        let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
            &bs58::encode(root.transaction_hash).into_string(),
        );
        humoco_sim_core::types::canonical_voucher_shard(&parent)
    } else if let Some(shard) = state
        .engine
        .get_hmc_voucher_genesis_shard(&chain_req.layer2_voucher_id)
        .await
    {
        shard
    } else {
        return (StatusCode::BAD_REQUEST, "unknown voucher root").into_response();
    };

    let last_hop = match chain_req.chain.last() {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST, "empty chain").into_response(),
    };
    let lookup_tag = if last_hop.is_genesis {
        bs58::encode(&last_hop.transaction_hash).into_string()
    } else {
        last_hop.ds_tag.clone().unwrap_or_default()
    };
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
    let is_responsible = if let Some(pm) = &state.peer_manager {
        pm.is_local_committee_member(
            *state.identity.node_pubkey(),
            *state.identity.hrw_routing_id(),
            shard_id,
        )
        .await
    } else {
        true
    };

    if state.transport.is_some()
        && is_responsible
        && !state.readiness_manager.is_shard_ready(shard_id)
    {
        state.readiness_manager.request_sync(shard_id);
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: format!("FLAG_NOT_READY: Shard {} syncing", shard_id),
            },
        );
        return (StatusCode::SERVICE_UNAVAILABLE, Json(envelope)).into_response();
    }

    let (verdict, is_new, quorum_certificate) = if is_responsible {
        // Atomares Ketten-Locking via engine
        let start_local = std::time::Instant::now();
        let (local_verdict, local_is_new) = match tokio::time::timeout_at(
            checkout_deadline,
            state.engine.ingress_hmc_chain_lock_durable_with_tier(
                chain_req.clone(),
                IngressOrigin::ClientApi,
                Some(now_ms),
                Some(tier_str),
                Some(byte_years),
            ),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => {
                let reason =
                    "504 Gateway Timeout: Chain persistence exceeded checkout budget".to_string();
                let rej_verdict = L2Verdict::Rejected { reason };
                let envelope = wrap_and_sign_verdict(&state.identity, rej_verdict);
                return (StatusCode::GATEWAY_TIMEOUT, Json(envelope)).into_response();
            }
        };
        state.metrics.record_local_latency(start_local.elapsed());

        let (q_cert, remote_collision) = match &local_verdict {
            L2Verdict::Verified { lock_entry } => {
                let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
                let declared_read_ema = state.tier_controller.current_read_ema_credits();
                let sender_pubkey = *state.identity.node_pubkey();
                let footprint =
                    humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_seconds)
                        .saturating_mul(chain_req.chain.len() as u64);
                let op_hash = lock_entry.t_id;
                // Epoch-bound envelope (Phase 1 P0).
                let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
                    state
                        .tier_controller
                        .record_declared_usage(now_ms, footprint);
                let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
                    &sender_pubkey,
                    epoch_day,
                    epoch_seq,
                    now_ms,
                    declared_write_ema,
                    declared_read_ema,
                    footprint,
                    false,
                    &op_hash,
                );
                let sender_signature = state.identity.signing_key().sign(&digest).to_bytes();
                let current_anl_24h = declared_write_ema;
                let wire_payload =
                    bincode::serialize(&crate::network::framing::LockWirePayload::Hmc {
                        req: last_hop.clone(),
                        chain: Some(chain_req.clone()),
                        root_valid_until,
                        epoch_day,
                        epoch_seq,
                        cumulative_micro_byte_years,
                        prev_day_final_bytes,
                        current_anl_24h,
                        declared_write_ema_micro_bj: declared_write_ema,
                        declared_read_ema_credits: declared_read_ema,
                        sender_pubkey,
                        sender_signature,
                        timestamp_ms: now_ms,
                    })
                    .ok();
                let start_quorum = std::time::Instant::now();
                let (cert, remote_collision) = assemble_quorum_certificate_with_deadline(
                    &state,
                    lock_entry.t_id,
                    parent_bytes,
                    shard_id,
                    now_ms,
                    wire_payload,
                    None,
                    Some(checkout_deadline),
                )
                .await;
                state.metrics.record_quorum_latency(start_quorum.elapsed());
                (Some(cert), remote_collision)
            }
            _ => (None, None),
        };
        if let Some(existing_lock) = remote_collision.filter(|_| {
            !q_cert
                .as_ref()
                .map(|c| c.is_quorum_reached())
                .unwrap_or(false)
        }) {
            (L2Verdict::Conflict { existing_lock }, false, q_cert)
        } else {
            (local_verdict, local_is_new, q_cert)
        }
    } else {
        // Stateless Gateway: do not write to local engine/redb
        let entry = L2LockEntry::from(last_hop);
        let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
        let declared_read_ema = state.tier_controller.current_read_ema_credits();
        let sender_pubkey = *state.identity.node_pubkey();
        let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_seconds)
            .saturating_mul(chain_req.chain.len() as u64);
        let op_hash = entry.t_id;
        // Epoch-bound envelope (Phase 1 P0).
        let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) = state
            .tier_controller
            .record_declared_usage(now_ms, footprint);
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            &sender_pubkey,
            epoch_day,
            epoch_seq,
            now_ms,
            declared_write_ema,
            declared_read_ema,
            footprint,
            false,
            &op_hash,
        );
        let sender_signature = state.identity.signing_key().sign(&digest).to_bytes();
        let current_anl_24h = declared_write_ema;
        let wire_payload = bincode::serialize(&crate::network::framing::LockWirePayload::Hmc {
            req: last_hop.clone(),
            chain: Some(chain_req.clone()),
            root_valid_until,
            epoch_day,
            epoch_seq,
            cumulative_micro_byte_years,
            prev_day_final_bytes,
            current_anl_24h,
            declared_write_ema_micro_bj: declared_write_ema,
            declared_read_ema_credits: declared_read_ema,
            sender_pubkey,
            sender_signature,
            timestamp_ms: now_ms,
        })
        .ok();
        let start_quorum = std::time::Instant::now();
        let (cert, remote_collision) = assemble_quorum_certificate_with_deadline(
            &state,
            entry.t_id,
            parent_bytes,
            shard_id,
            now_ms,
            wire_payload,
            None,
            Some(checkout_deadline),
        )
        .await;
        state.metrics.record_quorum_latency(start_quorum.elapsed());
        if let Some(existing_lock) = remote_collision.filter(|_| !cert.is_quorum_reached()) {
            let verdict = L2Verdict::Conflict { existing_lock };
            (verdict, false, Some(cert))
        } else {
            let verdict = L2Verdict::Verified { lock_entry: entry };
            (verdict, true, Some(cert))
        }
    };

    // Quorum-Gating: No HTTP 200/201 without reaching quorum.
    // Apply quorum gating to successful Verified outcomes; validated Conflict returns 409.
    if matches!(&verdict, L2Verdict::Verified { .. }) {
        if let Some(ref cert) = quorum_certificate {
            if !cert.is_quorum_reached() {
                let reason = format!(
                    "Quorum not reached: required {} signatures, collected {}",
                    cert.required_quorum(),
                    cert.signatures.len()
                );
                let rej_verdict = L2Verdict::Rejected { reason };
                let envelope = wrap_and_sign_verdict_with_quorum(
                    &state.identity,
                    rej_verdict,
                    Some(cert.clone()),
                );
                state.metrics.record_e2e_latency(start.elapsed());
                return (StatusCode::SERVICE_UNAVAILABLE, Json(envelope)).into_response();
            }
        }
    }

    let status = match &verdict {
        L2Verdict::Conflict { .. } => {
            state.metrics.record_rejected_conflict_409();
            StatusCode::CONFLICT
        }
        L2Verdict::Rejected { reason } => {
            let code = write_rejection_status(reason);
            if code == StatusCode::TOO_MANY_REQUESTS {
                state.metrics.record_rejected_capacity_429();
            } else {
                state.metrics.record_lock_rejected();
            }
            code
        }
        L2Verdict::Verified { .. } if is_new => StatusCode::CREATED,
        L2Verdict::Verified { .. } => StatusCode::OK,
        _ => StatusCode::BAD_REQUEST,
    };
    state.metrics.record_e2e_latency(start.elapsed());
    let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, quorum_certificate);
    (status, Json(envelope)).into_response()
}

/// Handler for GET /healthz (Kubernetes/L2 basic health check)
async fn health_ok() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
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
    let sync_ok = if let Some(ref tr) = state.transport {
        tr.is_sync_ready()
    } else {
        true
    };

    if storage_ok && peers_ok && sync_ok {
        (StatusCode::OK, Json(serde_json::json!({"status": "ready"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not_ready",
                "storage_ok": storage_ok,
                "peers_ok": peers_ok,
                "sync_ok": sync_ok
            })),
        )
    }
}

/// Minimal public service metadata; topology and operator metrics remain private.
async fn public_node_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({"service":"humoco-node", "protocol_version":1}))
}

/// Explicit HTTP publications and configured bootstrap candidates only;
/// cached-address fallback and private topology remain client-side concerns.
async fn public_gateways(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut gateways = collect_public_gateways(&state.config.discovery);
    if let Some(manager) = &state.peer_manager {
        for url in manager.advertised_gateway_urls().await {
            if gateways.len() >= crate::config::MAX_PUBLIC_GATEWAY_ENTRIES {
                break;
            }
            if !gateways.contains(&url) {
                gateways.push(url);
            }
        }
    }
    Json(serde_json::json!({ "gateways": gateways }))
}

/// Merges the operator publication and the configured bootstrap list into one
/// bounded, deduplicated candidate set. Malformed or credentialed entries are
/// dropped instead of being published on a public endpoint.
fn collect_public_gateways(discovery: &crate::config::DiscoveryConfig) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut gateways: Vec<String> = Vec::new();
    for raw in discovery
        .public_gateway_urls
        .iter()
        .chain(discovery.bootstrap_gateways.iter())
    {
        let candidate = raw.trim();
        if candidate.is_empty() || !crate::config::is_publishable_gateway_url(candidate) {
            continue;
        }
        if seen.insert(candidate.to_string()) {
            gateways.push(candidate.to_string());
        }
        if gateways.len() >= crate::config::MAX_PUBLIC_GATEWAY_ENTRIES {
            break;
        }
    }
    gateways
}

/// Bounded read-only retrieval of exact retained own approvals for uncertain originals (R5 / DEC-083/089).
/// Pure read-only lookup into redb TABLE_OWN_CHOICES; does not mutate state or issue new votes.
async fn get_retained_choice(State(state): State<AppState>, Path(tag): Path<String>) -> Response {
    if tag.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "tag too long"})),
        )
            .into_response();
    }
    let Ok(permit) = state.retained_choice_reads.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "retrieval capacity exhausted"})),
        )
            .into_response();
    };
    let node_pub = *state.identity.node_pubkey();
    let storage = state.storage.clone();
    let lookup_tag = tag.clone();
    // A timeout cannot stop a running redb read. Keep the permit in the worker
    // until it actually exits so repeated timeouts cannot create unbounded work.
    let read = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        storage.own_signing_choice(&node_pub, &lookup_tag)
    });
    let result = match tokio::time::timeout(std::time::Duration::from_millis(250), read).await {
        Ok(Ok(result)) => result,
        failure => {
            tracing::warn!(?failure, "Retained choice read unavailable");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "retrieval unavailable"})),
            )
                .into_response();
        }
    };
    match result {
        Ok(Some(choice)) => {
            // Exact retained approval bytes, so a client can verify the original
            // decision offline. No new vote is issued and no state is mutated.
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "found": true,
                    "node_pubkey": hex::encode(node_pub),
                    "lookup_tag": tag,
                    "network": match state.network_id {
                        humoco_sim_core::types::NetworkId::Mainnet => 0,
                        humoco_sim_core::types::NetworkId::Testnet => 1,
                    },
                    "purpose": "original_approval",
                    "version": 1,
                    "child": hex::encode(choice.child),
                    "valid_until_ms": choice.valid_until_ms,
                    "has_provisional": choice.approvals[0].is_some(),
                    "has_final": choice.approvals[1].is_some(),
                    "provisional_approval": choice.approvals[0].as_ref().map(hex::encode),
                    "final_approval": choice.approvals[1].as_ref().map(hex::encode),
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "found": false,
                "reason": "no retained choice for this tag"
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Retained choice storage read failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "storage unavailable"
                })),
            )
                .into_response()
        }
    }
}

async fn private_hourly_history(
    State(state): State<AppState>,
) -> Json<Vec<super::history_retention::HourSummary>> {
    Json(state.history_sampler.hourly.query())
}

/// Translates existing engine rejection reasons without turning uncertain durable work into success.
fn write_rejection_status(reason: &str) -> StatusCode {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("backpressure") || reason.contains("congested") {
        StatusCode::TOO_MANY_REQUESTS
    } else if reason.contains("durable")
        || reason.contains("storage signing")
        || reason.contains("worker unavailable")
        || reason.contains("chain deadline")
    {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    }
}

#[cfg(test)]
mod local_capacity_collector_tests {
    use super::*;
    use crate::network::transport::DefaultRequestHandler;

    #[tokio::test]
    async fn exhausted_256_slot_admission_is_neutral_for_write_and_read_collectors() {
        let identity = NodeIdentity::generate();
        let peer = NodeIdentity::generate();
        let addr: std::net::SocketAddr = "127.0.0.1:9909".parse().unwrap();
        let manager = Arc::new(crate::network::PeerManager::new(Vec::new()));
        manager.set_simulation_mode(true);
        manager
            .learn_node_from_gossip(*peer.node_pubkey(), addr, 0, None)
            .await;
        let cancel = tokio_util::sync::CancellationToken::new();
        let transport = crate::network::QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &identity,
            manager.clone(),
            Arc::new(DefaultRequestHandler),
            cancel.clone(),
        )
        .unwrap();
        // Exercise the production 256-slot semaphore, not a string-classifier mock.
        let occupied = transport.reserve_all_outbound_shard_slots_for_test();
        assert!(matches!(
            transport.connect_peer(addr).await,
            Err(crate::error::NodeError::LocalCapacity(_))
        ));
        assert!(matches!(
            transport.connect_peer_unchecked(addr).await,
            Err(crate::error::NodeError::LocalCapacity(_))
        ));
        assert!(manager.get_peer(&addr).await.is_none());
        let candidates = [(*peer.node_pubkey(), addr)];
        for (msg_type, resp_msg_type) in [
            (
                humoco_sim_core::wire::MsgType::LockVerifyRequest,
                humoco_sim_core::wire::MsgType::LockVerifyResponse,
            ),
            (
                humoco_sim_core::wire::MsgType::StatusQuery,
                humoco_sim_core::wire::MsgType::StatusResponse,
            ),
        ] {
            let mut signatures = Vec::new();
            let conflict = collect_peer_attestations(
                PeerAttestationQuery {
                    transport: &transport,
                    peer_mgr: &manager,
                    candidate_nodes: &candidates,
                    expected_members: None,
                    parent_lock: [1; 32],
                    lookup_tag: None,
                    voucher_id: None,
                    msg_type,
                    resp_msg_type,
                    payload: &[],
                    target_status: 1,
                    lock_id: [2; 32],
                    shard_id: 3,
                    required_q: 1,
                    shard_query_depth: 0,
                    my_load: 0,
                    quota_limit: 1,
                    network_id: humoco_sim_core::types::NetworkId::Mainnet,
                    checkout_deadline: None,
                },
                &mut signatures,
            )
            .await;
            assert!(conflict.is_none());
            assert!(signatures.is_empty());
            assert!(
                manager.get_peer(&addr).await.is_none(),
                "Local backpressure must not create a peer failure/malus record"
            );
        }
        drop(occupied);
        cancel.cancel();
        transport.close();
        transport.drain_tasks().await;
    }
}

#[cfg(test)]
mod public_retained_evidence_tests {
    use super::*;
    use crate::ingress::{PowEngine, TierController};
    use crate::storage::DualTierEngine;
    use http_body_util::BodyExt;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn test_state() -> (tempfile::TempDir, AppState, Arc<RedbStorage>, NodeIdentity) {
        let temp = tempdir().expect("tempdir");
        let storage =
            Arc::new(RedbStorage::open(&temp.path().join("unit.redb")).expect("open redb"));
        let (engine, _worker) = DualTierEngine::new(storage.clone());
        let identity = NodeIdentity::generate();
        let pow = Arc::new(PowEngine::new(*identity.node_id(), 8));
        let tiers = Arc::new(TierController::new(storage.clone(), pow.clone()));
        let state = AppState::new(engine, storage.clone(), identity.clone(), tiers, pow);
        (temp, state, storage, identity)
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn retained_choice_returns_exact_approval_bytes_and_validity() {
        let (_temp, state, storage, identity) = test_state();
        let entry = crate::api::hmc::L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "test-voucher-choice".into(),
            t_id: [8u8; 32],
            sender_ephemeral_pub: [7u8; 32],
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 1,
            created_at_ms: 1_000,
            deletable_at: Some("600000".into()),
            privacy_guard: None,
        };
        let tag = "spend-tag-choice".to_string();
        storage
            .commit_original_approval(
                &tag,
                &entry,
                identity.node_pubkey(),
                b"sig_prov",
                0,
                600_000,
            )
            .expect("commit provisional approval");
        storage
            .commit_original_approval(
                &tag,
                &entry,
                identity.node_pubkey(),
                b"sig_final",
                1,
                600_000,
            )
            .expect("commit final approval");

        let response = get_retained_choice(State(state), Path(tag)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["found"], true);
        assert_eq!(body["child"], hex::encode(entry.t_id));
        assert_eq!(body["valid_until_ms"], 600_000u64);
        assert_eq!(body["provisional_approval"], hex::encode(b"sig_prov"));
        assert_eq!(body["final_approval"], hex::encode(b"sig_final"));
        assert_eq!(body["has_provisional"], true);
        assert_eq!(body["has_final"], true);
    }

    #[tokio::test]
    async fn retained_choice_reports_missing_class_without_inventing_bytes() {
        let (_temp, state, storage, identity) = test_state();
        let entry = crate::api::hmc::L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "test-voucher-choice".into(),
            t_id: [10u8; 32],
            sender_ephemeral_pub: [7u8; 32],
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 1,
            created_at_ms: 1_000,
            deletable_at: Some("600000".into()),
            privacy_guard: None,
        };
        let tag = "spend-tag-choice-2".to_string();
        storage
            .commit_original_approval(
                &tag,
                &entry,
                identity.node_pubkey(),
                b"sig_prov",
                0,
                600_000,
            )
            .expect("commit provisional approval");

        let response = get_retained_choice(State(state), Path(tag)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["provisional_approval"], hex::encode(b"sig_prov"));
        assert_eq!(body["final_approval"], serde_json::Value::Null);
        assert_eq!(body["has_final"], false);
    }

    #[tokio::test]
    async fn gateway_directory_exposes_public_and_bootstrap_entries_once() {
        let (_temp, state, _storage, _identity) = test_state();
        let mut config = crate::config::NodeConfig::default();
        config.discovery.public_gateway_urls =
            vec!["https://a.example".into(), "https://shared.example".into()];
        config.discovery.bootstrap_gateways =
            vec!["https://shared.example".into(), "https://b.example".into()];
        let app = public_router(state.with_config(Arc::new(config)));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/v1/gateways")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        let gateways: Vec<String> =
            serde_json::from_value(body["gateways"].clone()).expect("gateway list");
        assert_eq!(
            gateways,
            vec![
                "https://a.example".to_string(),
                "https://shared.example".to_string(),
                "https://b.example".to_string(),
            ]
        );
    }

    #[test]
    fn gateway_directory_drops_credentialed_and_malformed_entries() {
        let discovery = crate::config::DiscoveryConfig {
            public_gateway_urls: vec![
                "https://a.example".into(),
                "https://user:secret@b.example".into(),
            ],
            bootstrap_gateways: vec!["not-a-url".into(), "http://c.example".into()],
        };
        let gateways = collect_public_gateways(&discovery);
        assert_eq!(
            gateways,
            vec![
                "https://a.example".to_string(),
                "http://c.example".to_string()
            ]
        );
    }
}

/// Public cached regional mesh view (5-second cache TTL).
async fn public_regional_mesh_view(State(state): State<AppState>) -> Response {
    state.metrics.record_read();
    let now_ms = state.net_time_ms();
    {
        let cache = state.mesh_view_cache.read();
        if let Some((cached_at_ms, ref view)) = *cache {
            if now_ms.saturating_sub(cached_at_ms) < 5_000 && view.valid_until_ms > now_ms + 15_000 {
                return Json(view.clone()).into_response();
            }
        }
    }

    if !state.engine.is_signing_healthy() {
        return (StatusCode::SERVICE_UNAVAILABLE, "signing unavailable").into_response();
    }
    let Some(manager) = &state.peer_manager else {
        return (StatusCode::SERVICE_UNAVAILABLE, "mesh unavailable").into_response();
    };
    let network = match state.network_id {
        humoco_sim_core::types::NetworkId::Mainnet => 0,
        humoco_sim_core::types::NetworkId::Testnet => 1,
    };
    match manager.regional_mesh_view(&state.identity, network).await {
        Ok(view) if state.engine.is_signing_healthy() => {
            *state.mesh_view_cache.write() = Some((now_ms, view.clone()));
            Json(view).into_response()
        }
        _ => (StatusCode::SERVICE_UNAVAILABLE, "mesh view unavailable").into_response(),
    }
}

/// 1-RTT PoS Checkout endpoint for offline buyers.
/// Anchors buyer's lock chain and returns a 14/20 LiveStateProof in a single roundtrip.
async fn checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<L2CheckoutRequest>,
) -> Response {
    let checkout_deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(780);

    if let Err(e) = humoco_proto::live::live_state_digest(&req.live_context) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    let mut conflicting_lock: Option<L2LockEntry> = None;

    if let Some(chain_req) = req.lock_chain {
        let is_already_anchored = {
            let ram = state.engine.hmc_ram.read().await;
            if let Some(existing) = ram.locks.get(&req.live_context.lookup_tag) {
                existing.t_id == req.live_context.child_lock
                    && existing.layer2_voucher_id == req.live_context.voucher_id
            } else {
                false
            }
        };

        if !is_already_anchored {
            let start = std::time::Instant::now();
            let chain_resp =
                submit_hmc_chain_lock_inner(state.clone(), headers, chain_req, start).await;
            let status = chain_resp.status();
            if status == StatusCode::CONFLICT {
                let body_bytes = axum::body::to_bytes(chain_resp.into_body(), 64 * 1024)
                    .await
                    .unwrap_or_default();
                if let Ok(env) = serde_json::from_slice::<L2ResponseEnvelope>(&body_bytes) {
                    if let L2Verdict::Conflict { existing_lock } = env.verdict {
                        conflicting_lock = Some(existing_lock);
                    }
                }
            } else if !status.is_success() {
                return chain_resp;
            }
        }
    }

    match crate::api::live::collect_live_state_proof(
        &state,
        req.live_context,
        checkout_deadline,
    )
    .await
    {
        Ok(proof) => (
            StatusCode::OK,
            Json(L2CheckoutResponse {
                proof,
                conflicting_lock,
            }),
        )
            .into_response(),
        Err((status, msg)) => {
            if conflicting_lock.is_some() && status == StatusCode::CONFLICT {
                StatusCode::CONFLICT.into_response()
            } else {
                (status, msg).into_response()
            }
        }
    }
}

/// Signed regional observations are private operator data, never public discovery.
async fn operator_regional_mesh_view(State(state): State<AppState>) -> Response {
    if !state.engine.is_signing_healthy() {
        return (StatusCode::SERVICE_UNAVAILABLE, "signing unavailable").into_response();
    }
    let Some(manager) = &state.peer_manager else {
        return (StatusCode::SERVICE_UNAVAILABLE, "mesh unavailable").into_response();
    };
    let network = match state.network_id {
        humoco_sim_core::types::NetworkId::Mainnet => 0,
        humoco_sim_core::types::NetworkId::Testnet => 1,
    };
    match manager.regional_mesh_view(&state.identity, network).await {
        Ok(view) if state.engine.is_signing_healthy() => Json(view).into_response(),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "mesh view unavailable").into_response(),
    }
}

/// Root registration publishes metadata only after the exact redb commit.
/// Never route this result through original-spend or quorum-vote assembly.
async fn commit_root_registration(
    state: &AppState,
    tag: String,
    entry: L2LockEntry,
    now_ms: u64,
    accounting: (&str, u64),
    should_warn: bool,
) -> Response {
    let (verdict, is_new) = state
        .engine
        .ingress_hmc_lock_durable(
            tag,
            entry,
            IngressOrigin::ClientApi,
            Some(now_ms),
            Some(accounting.0),
            Some(accounting.1),
            None,
        )
        .await;
    let status = match &verdict {
        L2Verdict::Verified { .. } if is_new => StatusCode::CREATED,
        L2Verdict::Verified { .. } => StatusCode::OK,
        L2Verdict::Rejected { reason } => write_rejection_status(reason),
        _ => StatusCode::BAD_REQUEST,
    };
    let mut response = (
        status,
        Json(wrap_and_sign_verdict(&state.identity, verdict)),
    )
        .into_response();
    if should_warn {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static("x-deprecation-warning"),
            axum::http::HeaderValue::from_static(
                "Suite 1 (Ed25519) deprecated - migrate to suite 2",
            ),
        );
    }
    response
}
