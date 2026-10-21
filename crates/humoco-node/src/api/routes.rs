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
    pub system_stats: Arc<crate::api::system_stats::SystemStatsCollector>,
    pub auth: Arc<crate::api::auth::AdminTokenManager>,
    pub is_simulation: bool,
    pub config: Arc<crate::config::NodeConfig>,
    pub history_sampler: Arc<crate::api::history::HistorySampler>,
    pub event_log: Arc<crate::api::events::EventLog>,
    pub health_tracker: Arc<crate::api::health::HealthStateTracker>,
    pub readiness_manager: Arc<crate::daemon::ShardReadinessManager>,
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
        let auth = Arc::new(crate::api::auth::AdminTokenManager::with_token("hmc_adm_dev", true));
        let config = Arc::new(crate::config::NodeConfig::default());
        let history_sampler = Arc::new(crate::api::history::HistorySampler::default());
        let event_log = Arc::new(crate::api::events::EventLog::default());
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if let Ok(loaded) = storage.load_recent_audit_events(100) {
                if !loaded.is_empty() {
                    event_log.populate(loaded);
                }
            }
            let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel::<crate::api::events::EventItem>(100);
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

    pub fn with_event_log(
        mut self,
        event_log: Arc<crate::api::events::EventLog>,
    ) -> Self {
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
        .route("/v1/verify-current", post(crate::api::live::verify_current))
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
        .route("/health", get(get_node_status))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/peers", get(get_peers))
        .route("/api/v1/network/peers", get(get_peers))
        .route("/api/v1/retained-choice/:tag", get(get_retained_choice))
        .route("/dashboard", get(crate::api::dashboard::render_dashboard))
        .route("/dashboard/data", get(crate::api::dashboard::dashboard_data))
        .route("/dashboard/vouchers", get(crate::api::dashboard::dashboard_vouchers))
        .route("/dashboard/voucher/:voucher_id", get(crate::api::dashboard::dashboard_voucher_detail))
        .route("/dashboard/lock/:lookup_tag", get(crate::api::dashboard::dashboard_lock_raw))
        .route("/dashboard/admin/verify-token", post(crate::api::dashboard::admin_verify_token))
        .route("/dashboard/admin/friends", post(crate::api::dashboard::admin_add_friend))
        .route("/dashboard/admin/friends/:key", delete(crate::api::dashboard::admin_remove_friend))
        .route("/dashboard/admin/mesh/peers", post(crate::api::dashboard::admin_add_mesh_peer))
        .route("/dashboard/admin/mesh/peers/:key", delete(crate::api::dashboard::admin_remove_mesh_peer))
        .route("/dashboard/admin/ingress/clients", post(crate::api::dashboard::admin_add_ingress_client))
        .route("/dashboard/admin/ingress/clients/:token_hash", delete(crate::api::dashboard::admin_remove_ingress_client))
        .route("/dashboard/admin/quota", post(crate::api::dashboard::admin_topup_quota))
        .route("/dashboard/admin/peers/:addr/reset", post(crate::api::dashboard::admin_reset_peer))
        .route("/dashboard/admin/peers/:addr/ping", post(crate::api::dashboard::admin_ping_peer))
        .route("/dashboard/history", get(get_dashboard_history))
        .route("/dashboard/history/hourly", get(private_hourly_history))
        .route("/dashboard/events", get(get_dashboard_events))
        .route("/metrics", get(crate::api::metrics::prometheus_metrics))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::from_fn(crate::api::operator_boundary::enforce_operator_browser_boundary))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Compatibility entry point for public ingress.
pub fn build_router(state: AppState) -> Router { public_router(state) }

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
///   Locks returned via `/v1/sync` are serialized strictly as `LockRecordDto`
///   representing the pure objective collision state (`parent_lock`, `receiver_pub`, `nonce`, `id`).
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
    let client_node_id: u16 = if let Some(auth) = headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        let tag = state.tier_controller.resolve_account_tag(auth).unwrap_or([0u8; 32]);
        u16::from_be_bytes([tag[0], tag[1]])
    } else if let Some(peer_token) = headers.get("X-Peer-Token").and_then(|h| h.to_str().ok()) {
        let hash = *blake3::hash(peer_token.as_bytes()).as_bytes();
        u16::from_be_bytes([hash[0], hash[1]])
    } else {
        let first_loc = payload.sparse_locators.first().map(|s| s.as_bytes()).unwrap_or(b"sync_anonymous");
        let hash = *blake3::hash(first_loc).as_bytes();
        u16::from_be_bytes([hash[0], hash[1]])
    };

    let sync_read_credits = 5;
    if let Err(ingress_err) = state.tier_controller.evaluate_read_quota(client_node_id, sync_read_credits, epoch_day, 1.0) {
        let reason = match ingress_err {
            IngressError::ReadQuotaExceeded { available, required } => {
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

    let mut lock_map = std::collections::HashMap::new();

    // 1. Read from persistent disk storage
    if let Ok(disk_locks) = state.storage.all_valid_locks(now_ms) {
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
    const MAX_SYNC_LOCKS: usize = 10_000;
    locks.truncate(MAX_SYNC_LOCKS);

    // Read HMC locks from persistent disk storage and in-memory RAM
    let mut hmc_map = std::collections::HashMap::new();
    if let Ok(disk_hmc_locks) = state.storage.all_valid_hmc_locks(now_ms) {
        for (tag, entry) in disk_hmc_locks {
            hmc_map.insert(tag, entry);
        }
    }
    {
        let hmc_guard = state.engine.hmc_ram.read().await;
        for (tag, entry) in &hmc_guard.locks {
            hmc_map.entry(tag.clone()).or_insert_with(|| entry.clone());
        }
    }

    for (tag, entry) in hmc_map {
        let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let parent_hex = hex::encode(parent_bytes);
        let id_hex = hex::encode(entry.t_id);
        if !locators.contains(&parent_hex) && !locators.contains(&tag) && !locators.contains(&id_hex) {
            let valid_until_ms = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let created_at_ms = if entry.created_at_ms > 0 { entry.created_at_ms } else { entry.encrypted_timestamp as u64 };
            let rec = humoco_sim_core::types::LockRecord {
                id: entry.t_id,
                parent_lock: parent_bytes,
                receiver_pub: entry.receiver_ephemeral_pub_hash.unwrap_or_default(),
                nonce: blake3::hash(entry.t_id.as_slice()).as_bytes().to_vec(),
                created_at: SimTime(created_at_ms),
                valid_until: SimTime(valid_until_ms),
                status: humoco_sim_core::types::LockStatus::Final { sigs: 1 },
                signers: Default::default(),
            };
            locks.push(LockRecordDto::from_record(&rec, valid_until_ms));
        }
    }

    (StatusCode::OK, Json(SyncResponse { locks })).into_response()
}

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
async fn get_node_status(
    State(state): State<AppState>,
) -> (StatusCode, Json<NodeStatusResponse>) {
    state.metrics.record_read();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let (active_byte_years, _) = state.engine.get_active_footprint_byte_years(now_ms).await;
    let total_locks = state.engine.ram.read().await.len() + state.engine.hmc_ram.read().await.locks.len();
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

/// Resolves a voucher root for a stateless gateway (Phase 2 P1):
/// RAM already missed; check persistent disk for the signed genesis TTL
/// before falling back to provisional forwarding. Returns the immutable
/// `root.valid_until` in ms when the genesis lock is known on disk.
async fn fetch_remote_voucher_root(state: &AppState, voucher_id: &str) -> Option<u64> {
    if let Ok(locks) = state.storage.get_hmc_locks_for_voucher(voucher_id) {
        for (_, entry) in locks {
            if let Some(del) = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                return Some(del);
            }
        }
    }
    // The authoritative shard check happens during the subsequent quorum
    // fanout (LockVerifyRequest); the shard enforces INV-1202 on `now_ms`.
    None
}

/// Maps each full signer identity to its immutable committee position.
fn compute_committee_bitmap(committee: &[humoco_sim_core::types::CommitteeMember], signatures: &[AttestationDto]) -> u32 {
    signatures.iter().fold(0, |bitmap, att| {
        committee.iter().position(|member| Some(member.node_pubkey) == att.node_pubkey_bytes())
            .map(|index| bitmap | (1 << index)).unwrap_or(bitmap)
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
    if att.shard_id != shard_id { return false; }
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

    let att_parent_lock_bytes = match hex::decode(&att.parent_lock) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            tracing::warn!(node_id = att.node_id, "Dropped attestation: invalid parent_lock hex");
            return false;
        }
    };

    if att_parent_lock_bytes != expected_parent_lock { return false; }

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
        domain_tag, 0, 0, 0, shard_id, target_status, &payload_digest,
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
    expected_members: Option<&'a [[u8; 32]]>,
    parent_lock: [u8; 32],
    msg_type: humoco_sim_core::wire::MsgType,
    resp_msg_type: humoco_sim_core::wire::MsgType,
    payload: &'a [u8],
    target_status: u8,
    lock_id: [u8; 32],
    shard_id: u16,
    required_q: usize,
    shard_query_depth: usize,
    my_load: u64,
    quota_limit: u64,
    network_id: humoco_sim_core::types::NetworkId,
}

enum PeerQueryError {
    LocalCapacity,
    QuotaExceeded,
    NotInShard,
    Collision(Vec<u8>),
    Generic,
}

enum PeerQueryResult {
    LocalCapacity,
    Success(AttestationDto, Option<[u8; 32]>),
    QuotaExceeded,
    NotInShard,
    Collision(Vec<u8>),
    Failure,
}

impl From<crate::error::NodeError> for PeerQueryError {
    fn from(error: crate::error::NodeError) -> Self {
        if error.is_local_capacity() { Self::LocalCapacity } else { Self::Generic }
    }
}

/// Collects only the immutable write committee in parallel, with an 800ms
/// deadline and fast exit once quorum is met or cannot be reached. Cancelled
/// stragglers and explicit readiness refusals never count as peer failures.
/// Status reads retain their existing timeout and query depth.
async fn collect_peer_attestations(
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

    let mut timeout_addrs = Vec::new();
    let mut candidate_idx = 0;
    let mut total_queried = 0;
    let mut in_flight = std::collections::HashMap::new();
    // First genuine HMC conflict evidence (FLAG_COLLISION_DETECTED) for 409.
    let mut collision_entry: Option<crate::api::hmc::L2LockEntry> = None;

    let is_write = query.msg_type == humoco_sim_core::wire::MsgType::LockVerifyRequest;
    let deadline = if is_write { std::time::Duration::from_millis(800) } else { crate::network::manager::QUORUM_GLOBAL_TIMEOUT };
    let _ = tokio::time::timeout(deadline, async {
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
                        let conn = t.connect_peer(addr).await.map_err(PeerQueryError::from)?;
                        // Pillar 3: capture the actual TLS certificate key of the
                        // queried peer so the attestation signer can be bound to it.
                        let tls_pubkey = crate::network::tls::extract_peer_identity_from_connection(&conn).map(|(nid, _)| nid);
                        
                        // 1. Initial Send
                        let res = t.send_request(&conn, &h, &p).await;
                        
                        // Triple-Send Heuristik für Schreibpfade (docs/PLAN_BUCKETED_SHARD_SYNC.md):
                        // Falls der 1. Versuch fehlschlägt, erfolgt ein 2. synchroner Retry mit identischem Payload (T_0)
                        let (resp_header, resp_payload) = match res {
                            Ok(pair) => pair,
                            Err(error) if error.is_local_capacity() => return Err(PeerQueryError::LocalCapacity),
                            Err(_) if is_write => {
                                // 2. Versuch: Sofortiger Retry mit bitgenau identischem Byte-Paket
                                let retry_res = t.send_request(&conn, &h, &p).await;
                                match retry_res {
                                    Ok(pair) => pair,
                                    Err(error) if error.is_local_capacity() => return Err(PeerQueryError::LocalCapacity),
                                    Err(_) => {
                                        // 3. Versuch: Asynchroner Fire-and-Forget Versand ohne Warten auf ACK,
                                        // um UDP-Paketverlust auf 0.0001% (1 zu 1.000.000) zu drücken.
                                        // The final identical attempt belongs to this bounded
                                        // collector task and is cancelled on quorum/deadline.
                                        if let Err(error) = t.send_request(&conn, &h, &p).await {
                                            return Err(error.into());
                                        }
                                        return Err(PeerQueryError::Generic);
                                    }
                                }
                            }
                            Err(_) => return Err(PeerQueryError::Generic),
                        };

                        // Phase 2 P1 (INV-0604): genuine HMC double-spend carries
                        // FLAG_COLLISION_DETECTED + colliding lock payload for 409.
                        if (resp_header.flags & humoco_sim_core::wire::FLAG_COLLISION_DETECTED) != 0 {
                            return Err(PeerQueryError::Collision(resp_payload));
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
                        Ok((att, tls_pubkey)) => (nid, addr, rank_idx, PeerQueryResult::Success(att, tls_pubkey)),
                        Err(PeerQueryError::LocalCapacity) => (nid, addr, rank_idx, PeerQueryResult::LocalCapacity),
                        Err(PeerQueryError::QuotaExceeded) => (nid, addr, rank_idx, PeerQueryResult::QuotaExceeded),
                        Err(PeerQueryError::NotInShard) => (nid, addr, rank_idx, PeerQueryResult::NotInShard),
                        Err(PeerQueryError::Collision(payload)) => (nid, addr, rank_idx, PeerQueryResult::Collision(payload)),
                        Err(PeerQueryError::Generic) => (nid, addr, rank_idx, PeerQueryResult::Failure),
                    }
                });
            }
        };

        let needed = query.required_q.saturating_sub(collected_signatures.len());
        let initial_spawns = if is_write { query.candidate_nodes.len() } else {
            (needed + query.shard_query_depth).min(query.candidate_nodes.len()).min(20)
        };
        for _ in 0..initial_spawns {
            spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
        }
        loop {
            if is_write && collected_signatures.len() + join_set.len()
                + query.candidate_nodes.len().saturating_sub(candidate_idx) < query.required_q {
                join_set.abort_all();
                in_flight.clear();
                break;
            }
            if collected_signatures.len() >= query.required_q {
                break;
            }
            if join_set.is_empty() {
                if candidate_idx >= query.candidate_nodes.len() {
                    break;
                }
                spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                continue;
            }
            match tokio::time::timeout(std::time::Duration::from_millis(50), join_set.join_next()).await {
                Ok(Some(res)) => match res {
                Ok((_nid, addr, rank_idx, PeerQueryResult::Success(att, tls_pubkey))) => {
                    in_flight.remove(&rank_idx);

                    // Pillar 3: dedup strictly via 32-byte NodePubKey when
                    // present; legacy 16-bit prefix only as fallback.
                    let is_duplicate = match att.node_pubkey_bytes() {
                        Some(pk) => collected_signatures.iter().any(|s| {
                            s.node_pubkey_bytes().map(|p| p == pk).unwrap_or(false)
                        }),
                        None => collected_signatures.iter().any(|s| s.node_id == att.node_id),
                    };
                    if is_duplicate {
                        spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                        continue;
                    }

                    let expected_member = query.expected_members.and_then(|members| members.get(rank_idx)).copied();
                    if expected_member.map(|pk| Some(pk) != att.node_pubkey_bytes() || Some(pk) != tls_pubkey).unwrap_or(false)
                        || !verify_peer_attestation(query.peer_mgr, &att, (query.lock_id, query.parent_lock), query.shard_id, query.target_status, query.network_id, tls_pubkey).await {
                        if rank_idx < 20 {
                            query.peer_mgr.record_failure(addr).await;
                        }
                        spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
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
                    spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                }
                Ok((_nid, addr, rank_idx, PeerQueryResult::Collision(payload))) => {
                    in_flight.remove(&rank_idx);
                    // Genuine shard work (conflict lookup) decays malus; the
                    // colliding lock is first-party double-spend evidence.
                    query.peer_mgr.record_shard_work(addr).await;
                    if collision_entry.is_none() {
                        if let Ok(entry) = bincode::deserialize::<crate::api::hmc::L2LockEntry>(&payload) {
                            collision_entry = Some(entry);
                        }
                    }
                    spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                }
                Ok((_nid, addr, rank_idx, PeerQueryResult::QuotaExceeded)) => {
                    in_flight.remove(&rank_idx);
                    // Phase 9 P1 (Spec 09 INV-0908): 24h quota moratorium after a partition merge.
                    // During merge hysteresis no quota-driven peer penalty may be applied,
                    // preventing cascade bans from divergent thermometers.
                    let in_moratorium = query.peer_mgr.is_in_merge_hysteresis(query.peer_mgr.net_time_ms());
                    let verdict = humoco_sim_core::quota::evaluate_quota_exceeded_claim(query.my_load, query.quota_limit);
                    match verdict {
                        humoco_sim_core::quota::QuotaPlausibilityVerdict::FraudulentRejection { .. } => {
                            if in_moratorium {
                                tracing::info!(
                                    %addr,
                                    rank_idx,
                                    my_load = query.my_load,
                                    quota_limit = query.quota_limit,
                                    "Shard peer quota rejection during 24h merge moratorium - penalty suppressed (INV-0908)"
                                );
                            } else {
                                tracing::warn!(
                                    %addr,
                                    rank_idx,
                                    my_load = query.my_load,
                                    quota_limit = query.quota_limit,
                                    "Shard peer fraudulently claimed FLAG_QUOTA_EXCEEDED (Zone 1) - recording peer failure"
                                );
                                if rank_idx < 20 {
                                    query.peer_mgr.record_failure(addr).await;
                                }
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
                    spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                }
                Ok((_nid, addr, rank_idx, PeerQueryResult::Failure)) => {
                    in_flight.remove(&rank_idx);
                    timeout_addrs.push((addr, rank_idx));
                    spawn_next(&mut join_set, &mut candidate_idx, &mut total_queried, &mut in_flight);
                }
                Err(_) => {
                    // Task cancelled/panicked
                }
                },
                Ok(None) => break,
                Err(_) => continue,
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
    assemble_quorum_certificate_with_override(state, lock_id, parent_lock, shard_id, now_ms, record_payload, None).await
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
    use humoco_sim_core::types::CommitteeMember;
    let self_pubkey = *state.identity.node_pubkey();
    let self_hrw = *state.identity.hrw_routing_id();
    let (committee, remote, total_active) = if let Some(pm) = &state.peer_manager {
        pm.shard_committee(self_pubkey, self_hrw, shard_id).await
    } else {
        (vec![CommitteeMember { node_pubkey: self_pubkey, hrw_routing_id: self_hrw }], Vec::new(), 1)
    };
    let (base_q, final_size) = humoco_sim_core::types::required_quorum(total_active);
    let required_q = quorum_override.unwrap_or(base_q).min(total_active).max(base_q);
    let target_status = u8::from(final_size && state.peer_manager.as_ref()
        .map(|pm| pm.is_network_stable_ge20_for_24h(now_ms)).unwrap_or(false));
    let mut collected_signatures = Vec::new();
    // A local signature requires the same authoritative, accepted RAM lock
    // as remote shard work. Membership alone is insufficient.
    let sync_ready = state.readiness_manager.is_shard_ready(shard_id);
    if sync_ready && committee.iter().any(|member| member.node_pubkey == self_pubkey) {
        let attestation = create_attestation_for_network(&state.identity, lock_id, parent_lock, shard_id, target_status, now_ms, state.network_id);
        if let Ok(bytes) = bincode::serialize(&attestation) {
            let mut retained = None;
            if let Some(payload) = record_payload.as_deref() {
                if let Ok(crate::network::framing::LockWirePayload::Hmc { req, .. }) = bincode::deserialize(payload) {
                    let tag = if req.is_genesis { Some(bs58::encode(req.transaction_hash).into_string()) } else { req.ds_tag.clone() };
                    if let Some(tag) = tag {
                        if *blake3::hash(tag.as_bytes()).as_bytes() == parent_lock {
                            if let Some(entry) = state.engine.get_hmc_ram_lock(&tag).await.filter(|e| e.t_id == lock_id) {
                                retained = state.engine.persist_original_approval(tag, entry, self_pubkey, bytes.clone(), target_status, now_ms).await.ok();
                            }
                        }
                    }
                }
            } else if let Some(record) = state.engine.get_ram_lock(&parent_lock).await.filter(|r| r.id == lock_id) {
                retained = state.engine.persist_original_record_approval(record.clone(), record.valid_until, self_pubkey, bytes, target_status, now_ms).await.ok();
            }
            if let Some(att) = retained.and_then(|bytes| AttestationDto::from_wire_bytes(&bytes)) { collected_signatures.push(att); }
        }
    }
    let candidates: Vec<_> = remote.iter().map(|(member, addr)| (member.hrw_routing_id, *addr)).collect();
    let expected_members: Vec<_> = remote.iter().map(|(member, _)| member.node_pubkey).collect();
    let mut collision = None;
    if collected_signatures.len() < required_q {
        if let (Some(transport), Some(pm), Some(payload)) = (&state.transport, &state.peer_manager, record_payload.as_deref()) {
            collision = collect_peer_attestations(PeerAttestationQuery {
                transport, peer_mgr: pm, candidate_nodes: &candidates,
                expected_members: Some(&expected_members), parent_lock,
                msg_type: humoco_sim_core::wire::MsgType::LockVerifyRequest,
                resp_msg_type: humoco_sim_core::wire::MsgType::LockVerifyResponse,
                payload, target_status, lock_id, shard_id, required_q,
                shard_query_depth: state.shard_query_depth,
                my_load: state.tier_controller.rolling_24h_average(),
                quota_limit: (5.0 * state.tier_controller.effective_ncb() as f64).round() as u64,
                network_id: state.network_id,
            }, &mut collected_signatures).await;
        }
    }
    let signer_bitmap = compute_committee_bitmap(&committee, &collected_signatures);
    let cert = QuorumCertificateDto {
        lock_id: hex::encode(lock_id), shard_id,
        status: if collected_signatures.len() >= required_q { target_status } else { 0 },
        active_nodes_count: total_active, signer_count: collected_signatures.len(),
        signatures: collected_signatures, signer_bitmap,
    };
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
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "RecipientChallengeRequired", "verification_endpoint": "/v1/verify-current"
        }))).into_response();
    }
    state.metrics.record_read();
    let now_ms = state.net_time_ms();
    let epoch_day = state.tier_controller.current_epoch_day_at(now_ms);
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
    let mut verdict = hmc.query_status(
        &payload.layer2_voucher_id,
        &payload.challenge_ds_tag,
        &payload.locator_prefixes,
    );
    drop(hmc);

    // # Architectural Invariant: Smart Client, Dumb Server & Hydra Resilience
    // (Phase 2 P1, Spec 06 / INV-0310)
    //
    // The gateway is a stateless messenger without own shard state: if the lock
    // is unknown locally it MUST NOT blindly answer UnknownVoucher. It queries
    // exactly 1 deterministic node from the Top-20 shard custodians via QUIC
    // (deterministic per-lock index, no hotspot on rank 1) and returns the
    // remote result. If the public gateway IP fails, wallets rotate to the next
    // gateway (Hydra resilience); shard state lives only on shard custodians.
    if matches!(verdict, L2Verdict::UnknownVoucher) {
        if let (Some(peer_mgr), Some(transport)) = (state.peer_manager.as_ref(), state.transport.as_ref()) {
            let shard_id = if let Some(sid) = state.engine.get_hmc_voucher_genesis_shard(&payload.layer2_voucher_id).await {
                sid
            } else {
                humoco_sim_core::types::voucher_shard_id(&payload.layer2_voucher_id)
            };
            let candidates = peer_mgr.get_top_n_shards_for_lock(shard_id, 20).await;
            if !candidates.is_empty() {
                // Deterministic 1-of-20: per-lock index from BLAKE3(tag).
                let tag_hash = *blake3::hash(payload.challenge_ds_tag.as_bytes()).as_bytes();
                let idx = (tag_hash[0] as usize) % candidates.len();
                let (_, addr) = candidates[idx];
                let parent_lock = *blake3::hash(payload.challenge_ds_tag.as_bytes()).as_bytes();
                let declared_read_ema = state.tier_controller.current_read_ema_credits();
                let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
                let sender_pubkey = *state.identity.node_pubkey();
                let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
                    &sender_pubkey, 0, 0, now_ms,
                    declared_write_ema, declared_read_ema, 0, true, &[0u8; 32],
                );
                let sender_signature = state.identity.signing_key().sign(&digest).to_bytes();
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
                    humoco_sim_core::wire::MsgType::StatusQuery as u16, 1, 0, 0,
                    payload_bytes.len() as u32,
                );
                let remote_verdict: Option<L2Verdict> = async {
                    let conn = transport.connect_peer(addr).await.ok()?;
                    let fut = transport.send_request(&conn, &header, &payload_bytes);
                    let (resp_header, resp_payload) = tokio::time::timeout(std::time::Duration::from_millis(1000), fut).await.ok()?.ok()?;
                    if resp_header.msg_type != humoco_sim_core::wire::MsgType::StatusResponse as u16
                        || resp_payload.is_empty()
                        || (resp_header.flags & humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED) != 0
                        || (resp_header.flags & humoco_sim_core::wire::FLAG_PEER_SUSPENDED) != 0
                            || (resp_header.flags & humoco_sim_core::wire::FLAG_NOT_READY) != 0
                    {
                        return None;
                    }
                    // Tag-only fallback returns the full L2LockEntry with
                    // first-party signature evidence.
                    if let Ok(entry) = bincode::deserialize::<crate::api::hmc::L2LockEntry>(&resp_payload) {
                        if entry.layer2_voucher_id == payload.layer2_voucher_id {
                            return Some(L2Verdict::Verified { lock_entry: entry });
                        }
                    }
                    // Standard path returns an attestation; existence proves the
                    // lock lives on the shard (full entry sync via digest-pull).
                    if let Ok(att) = bincode::deserialize::<crate::api::dto::AttestationDto>(&resp_payload) {
                        // Attestation alone proves shard custody; report as
                        // MissingLocks would hide it, so surface as Verified
                        // with a minimal entry carrying the proven t_id. The
                        // client cross-checks t_id for double-spend (Spec 06).
                        let lock_id_bytes = hex::decode(&att.lock_id).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())?;
                        let minimal = crate::api::hmc::L2LockEntry {
                            layer2_voucher_id: payload.layer2_voucher_id.clone(),
                            t_id: lock_id_bytes,
                            sender_ephemeral_pub: [0u8; 32],
                            receiver_ephemeral_pub_hash: None,
                            change_ephemeral_pub_hash: None,
                            layer2_signature: [0u8; 64],
                            trap_r: None,
                            trap_s: None,
                            encrypted_timestamp: 0,
                            created_at_ms: 0,
                            deletable_at: None,
                            privacy_guard: None,
                        };
                        return Some(L2Verdict::Verified { lock_entry: minimal });
                    }
                    None
                }.await;
                if let Some(remote) = remote_verdict {
                    verdict = remote;
                }
            }
        }
    }

    // Legacy lookup never manufactures a write approval as fresh read evidence.
    let quorum_certificate = None;
    let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, verdict, quorum_certificate);
    (StatusCode::OK, Json(envelope)).into_response()
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
    mut req: L2LockRequest,
    start: std::time::Instant,
) -> Response {
    state.metrics.record_write();
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

    const MAX_SENDER_CLOCK_DRIFT_MS: u64 = 30_000;
    if req.created_at_ms == 0 {
        req.created_at_ms = now_ms;
    } else if req.created_at_ms.abs_diff(now_ms) > MAX_SENDER_CLOCK_DRIFT_MS {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Sender timestamp outside 30s clock drift window".into(),
            },
        );
        return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
    }

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
        // Origin-Lock Mandate: the genesis lock must be anchored first.
        // Without a known root (locally or from the client-supplied TTL),
        // there is no immutable TTL to inherit — reject with 400 Bad Request.
        let root = match stored_root_valid {
            Some(r) => r,
            None => {
                if let Some(del) = parsed_deletable {
                    del
                } else if let Some(disk_root) = fetch_remote_voucher_root(&state, &req.layer2_voucher_id).await {
                    disk_root
                } else {
                    let envelope = wrap_and_sign_verdict(
                        &state.identity,
                        L2Verdict::Rejected {
                            reason: "Unknown voucher root: genesis lock must be anchored first".into(),
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
        let sid = humoco_sim_core::types::extract_shard_id(&parent_bytes);
        state.engine.record_hmc_voucher_genesis_parent(&req.layer2_voucher_id, parent_bytes).await;
        sid
    } else if let Some(sid) = state.engine.get_hmc_voucher_genesis_shard(&req.layer2_voucher_id).await {
        sid
    } else {
        humoco_sim_core::types::voucher_shard_id(&req.layer2_voucher_id)
    };
    let is_responsible = if let Some(pm) = &state.peer_manager {
        pm.is_local_committee_member(*state.identity.node_pubkey(), *state.identity.hrw_routing_id(), shard_id).await
    } else {
        true
    };

    if state.transport.is_some() && is_responsible && !state.readiness_manager.is_shard_ready(shard_id) {
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
    // 1. Validate credentials presence in RAM (< 1 µs) BEFORE expensive Ed25519 verification.
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
    let req_q_override = headers
        .get("X-Required-Quorum")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());

    let parent_for_pow = if req.is_genesis {
        None
    } else {
        Some(&parent_bytes)
    };

    let has_credentials = auth_token.is_some()
        || peer_token.is_some()
        || (pow_challenge.is_some() && pow_nonce.is_some());

    if !has_credentials {
        let (status, reason, req_diff) = match state
            .tier_controller
            .evaluate_and_charge_with_time(
                None,
                None,
                None,
                None,
                ttl_seconds,
                parent_for_pow,
                Some(now_ms),
            )
            .await
        {
            Err(IngressError::PoWRequired { difficulty, .. }) => {
                state.metrics.record_rejected_bad_pow_400();
                (
                    StatusCode::UNAUTHORIZED,
                    "Proof-of-Work challenge response required".to_string(),
                    Some(difficulty),
                )
            }
            _ => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string(), None),
        };
        let envelope = wrap_and_sign_verdict(&state.identity, L2Verdict::Rejected { reason });
        let mut resp = (status, Json(envelope)).into_response();
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

    // 4. Fast-path idempotency check: if identical lock already verified in RAM, return 200 OK immediately
    // Phase 10 (Hot-Path-Locks): the RAM read guard is cloned and dropped
    // BEFORE any network await (`assemble_quorum_certificate`), so writers
    // are never blocked while this gateway waits for quorum.
    if is_responsible {
        let existing_opt = {
            let hmc = state.engine.hmc_ram.read().await;
            hmc.locks.get(&lookup_tag).cloned()
        };
        if let Some(existing) = existing_opt {
            if existing.t_id == entry.t_id {
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

                let verdict = L2Verdict::Verified { lock_entry: existing.clone() };
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
                let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
                    state.tier_controller.record_declared_usage(now_ms, footprint);
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
                }).ok();
                let start_quorum = std::time::Instant::now();
                let (cert, remote_collision) = assemble_quorum_certificate_with_override(&state, entry.t_id, parent_bytes, shard_id, now_ms, wire_payload, req_q_override).await;
                state.metrics.record_quorum_latency(start_quorum.elapsed());
                state.metrics.record_local_latency(std::time::Duration::from_micros(1));

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
                        cert.required_quorum(), cert.signatures.len()
                    );
                    let rej_verdict = L2Verdict::Rejected { reason };
                    let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, rej_verdict, Some(cert));
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
        }
    }

    let ingress_tier = match state
        .tier_controller
        .evaluate_and_charge_with_time(
            auth_token,
            peer_token,
            pow_challenge,
            pow_nonce,
            ttl_seconds,
            parent_for_pow,
            Some(now_ms),
        )
        .await
    {
        Ok(tier) => tier,
        Err(err) => {
            let mut required_diff_hdr = None;
            let (status, reason) = match &err {
                IngressError::PoWRequired { .. } => (
                    StatusCode::UNAUTHORIZED,
                    "Proof-of-Work challenge response required".into(),
                ),
                IngressError::InvalidPoW(err) => {
                    if let crate::ingress::pow::PowError::InsufficientDifficulty { required, provided } = err {
                        required_diff_hdr = Some(*required);
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
            let envelope = wrap_and_sign_verdict(&state.identity, L2Verdict::Rejected { reason });
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
    };

    // 2. Verify V3 signature: only executed after cheap credential check passes!
    if !verify_l2_lock_signature(&req) {
        if let crate::ingress::IngressTier::Tier1Vip = ingress_tier {
            if let Some(token) = auth_token {
                if let Ok(account_tag) = state.tier_controller.resolve_account_tag(token) {
                    let required_byte_years = humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl_seconds);
                    let _ = state.tier_controller.topup_vip_quota(account_tag, required_byte_years);
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

    // 4. Ingress: Local shard storage vs. Stateless Gateway routing
    let (verdict, is_new, quorum_certificate) = if is_responsible {
        let start_local = std::time::Instant::now();
        let (local_verdict, local_is_new) = state
            .engine
            .ingress_hmc_lock_durable(
                lookup_tag.clone(),
                entry.clone(),
                IngressOrigin::ClientApi,
                Some(now_ms),
                Some(tier_str),
                Some(byte_years),
                Some(req.layer2_voucher_id.clone()),
            )
            .await;
        state.metrics.record_local_latency(start_local.elapsed());

        let (q_cert, remote_collision) = match &local_verdict {
            L2Verdict::Conflict { .. } | L2Verdict::Rejected { .. } => (None, None),
            _ => {
                let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
                let declared_read_ema = state.tier_controller.current_read_ema_credits();
                let sender_pubkey = *state.identity.node_pubkey();
                let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_seconds);
                let op_hash = entry.t_id;
                // Epoch-bound envelope (Phase 1 P0): reserve epoch first so the
                // signed digest and the wire payload commit to the same
                // (epoch_day, epoch_seq).
                let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
                    state.tier_controller.record_declared_usage(now_ms, footprint);
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
                }).ok();
                let start_quorum = std::time::Instant::now();
                let (cert, remote_collision) = assemble_quorum_certificate_with_override(&state, entry.t_id, parent_bytes, shard_id, now_ms, wire_payload, req_q_override).await;
                state.metrics.record_quorum_latency(start_quorum.elapsed());
                (Some(cert), remote_collision)
            }
        };
        // Remote genuine conflict overrides local Verified (split-brain).
        if let Some(existing_lock) = remote_collision.filter(|_| !q_cert.as_ref().map(|c| c.is_quorum_reached()).unwrap_or(false)) {
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
        let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
            state.tier_controller.record_declared_usage(now_ms, footprint);
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
        }).ok();
        let start_quorum = std::time::Instant::now();
        let (cert, remote_collision) = assemble_quorum_certificate_with_override(&state, entry.t_id, parent_bytes, shard_id, now_ms, wire_payload, req_q_override).await;
        state.metrics.record_quorum_latency(start_quorum.elapsed());
        // FLAG_COLLISION_DETECTED from any shard proves double-spend: 409.
        if let Some(existing_lock) = remote_collision.filter(|_| !cert.is_quorum_reached()) {
            let verdict = L2Verdict::Conflict { existing_lock };
            (verdict, false, Some(cert))
        } else {
            let verdict = L2Verdict::Verified { lock_entry: entry.clone() };
            (verdict, true, Some(cert))
        }
    };

    // 5. Quorum-Gating: No HTTP 200/201 without reaching quorum
    if let Some(ref cert) = quorum_certificate {
        if !cert.is_quorum_reached() {
            let reason = format!(
                "Quorum not reached: required {} signatures, collected {}",
                cert.required_quorum(), cert.signatures.len()
            );
            let rej_verdict = L2Verdict::Rejected { reason };
            let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, rej_verdict, Some(cert.clone()));
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

/// Handler for POST /v1/lock/chain – atomares Ketten-Locking
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
    mut chain_req: L2ChainLockRequest,
    start: std::time::Instant,
) -> Response {

    state.metrics.record_write();
    if chain_req.chain.is_empty() {
        let envelope = wrap_and_sign_verdict(
            &state.identity,
            L2Verdict::Rejected {
                reason: "Empty chain: at least one lock required".into(),
            },
        );
        return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
    }

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

    const MAX_SENDER_CLOCK_DRIFT_MS: u64 = 30_000;
    for hop in &mut chain_req.chain {
        if hop.created_at_ms == 0 {
            hop.created_at_ms = now_ms;
        } else if hop.created_at_ms.abs_diff(now_ms) > MAX_SENDER_CLOCK_DRIFT_MS {
            let envelope = wrap_and_sign_verdict(
                &state.identity,
                L2Verdict::Rejected {
                    reason: "Sender timestamp outside 30s clock drift window".into(),
                },
            );
            return (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
        }
    }

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

    let ingress_tier = match state
        .tier_controller
        .evaluate_and_charge_with_time(auth_token, peer_token, pow_challenge, pow_nonce, ttl_seconds, None, Some(now_ms))
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
            let envelope = wrap_and_sign_verdict(&state.identity, L2Verdict::Rejected { reason });
            return (status, Json(envelope)).into_response();
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
    let shard_id = humoco_sim_core::types::voucher_shard_id(&chain_req.layer2_voucher_id);

    let last_hop = chain_req.chain.last().unwrap();
    let lookup_tag = if last_hop.is_genesis {
        bs58::encode(&last_hop.transaction_hash).into_string()
    } else {
        last_hop.ds_tag.clone().unwrap_or_default()
    };
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
    let is_responsible = if let Some(pm) = &state.peer_manager {
        pm.is_local_committee_member(*state.identity.node_pubkey(), *state.identity.hrw_routing_id(), shard_id).await
    } else {
        true
    };

    if state.transport.is_some() && is_responsible && !state.readiness_manager.is_shard_ready(shard_id) {
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
        let (local_verdict, local_is_new) = state
            .engine
            .ingress_hmc_chain_lock_durable_with_tier(
                chain_req.clone(),
                IngressOrigin::ClientApi,
                Some(now_ms),
                Some(tier_str),
                Some(byte_years),
            )
            .await;
        state.metrics.record_local_latency(start_local.elapsed());

        let (q_cert, remote_collision) = match &local_verdict {
            L2Verdict::Verified { lock_entry } => {
                let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
                let declared_read_ema = state.tier_controller.current_read_ema_credits();
                let sender_pubkey = *state.identity.node_pubkey();
                let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_seconds).saturating_mul(chain_req.chain.len() as u64);
                let op_hash = lock_entry.t_id;
                // Epoch-bound envelope (Phase 1 P0).
                let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
                    state.tier_controller.record_declared_usage(now_ms, footprint);
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
                let (cert, remote_collision) = assemble_quorum_certificate(
                    &state,
                    lock_entry.t_id,
                    parent_bytes,
                    shard_id,
                    now_ms,
                    wire_payload,
                )
                .await;
                state.metrics.record_quorum_latency(start_quorum.elapsed());
                (Some(cert), remote_collision)
            }
            _ => (None, None),
        };
        if let Some(existing_lock) = remote_collision.filter(|_| !q_cert.as_ref().map(|c| c.is_quorum_reached()).unwrap_or(false)) {
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
        let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_seconds).saturating_mul(chain_req.chain.len() as u64);
        let op_hash = entry.t_id;
        // Epoch-bound envelope (Phase 1 P0).
        let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
            state.tier_controller.record_declared_usage(now_ms, footprint);
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
        let (cert, remote_collision) = assemble_quorum_certificate(
            &state,
            entry.t_id,
            parent_bytes,
            shard_id,
            now_ms,
            wire_payload,
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

    // Quorum-Gating: No HTTP 200/201 without reaching quorum
    if let Some(ref cert) = quorum_certificate {
        if !cert.is_quorum_reached() {
            let reason = format!(
                "Quorum not reached: required {} signatures, collected {}",
                cert.required_quorum(), cert.signatures.len()
            );
            let rej_verdict = L2Verdict::Rejected { reason };
            let envelope = wrap_and_sign_verdict_with_quorum(&state.identity, rej_verdict, Some(cert.clone()));
            state.metrics.record_e2e_latency(start.elapsed());
            return (StatusCode::SERVICE_UNAVAILABLE, Json(envelope)).into_response();
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
    Json(serde_json::json!({
        "gateways": collect_public_gateways(&state.config.discovery),
    }))
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
async fn get_retained_choice(
    State(state): State<AppState>,
    Path(tag): Path<String>,
) -> Response {
    if tag.len() > 128 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "tag too long"}))).into_response();
    }
    let node_pub = state.identity.node_pubkey();
    match state.storage.own_signing_choice(node_pub, &tag) {
        Ok(Some(choice)) => {
            // Exact retained approval bytes, so a client can verify the original
            // decision offline. No new vote is issued and no state is mutated.
            (StatusCode::OK, Json(serde_json::json!({
                "found": true,
                "child": hex::encode(choice.child),
                "valid_until_ms": choice.valid_until_ms,
                "has_provisional": choice.approvals[0].is_some(),
                "has_final": choice.approvals[1].is_some(),
                "provisional_approval": choice.approvals[0].as_ref().map(hex::encode),
                "final_approval": choice.approvals[1].as_ref().map(hex::encode),
            }))).into_response()
        }
        Ok(None) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "found": false,
                "reason": "no retained choice for this tag"
            }))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("storage error: {e}")
            }))).into_response()
        }
    }
}

async fn private_hourly_history(State(state): State<AppState>) -> Json<Vec<super::history_retention::HourSummary>> { Json(state.history_sampler.hourly.query()) }

/// Translates existing engine rejection reasons without turning uncertain durable work into success.
fn write_rejection_status(reason: &str) -> StatusCode {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("backpressure") || reason.contains("congested") {
        StatusCode::TOO_MANY_REQUESTS
    } else if reason.contains("durable") || reason.contains("storage signing")
        || reason.contains("worker unavailable") || reason.contains("chain deadline") {
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
        manager.learn_node_from_gossip(*peer.node_pubkey(), addr, 0, None).await;
        let cancel = tokio_util::sync::CancellationToken::new();
        let transport = crate::network::QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(), &identity, manager.clone(),
            Arc::new(DefaultRequestHandler), cancel.clone(),
        ).unwrap();
        // Exercise the production 256-slot semaphore, not a string-classifier mock.
        let occupied = transport.reserve_all_outbound_shard_slots_for_test();
        assert!(matches!(transport.connect_peer(addr).await,
            Err(crate::error::NodeError::LocalCapacity(_))));
        assert!(matches!(transport.connect_peer_unchecked(addr).await,
            Err(crate::error::NodeError::LocalCapacity(_))));
        assert!(manager.get_peer(&addr).await.is_none());
        let candidates = [(*peer.node_pubkey(), addr)];
        for (msg_type, resp_msg_type) in [
            (humoco_sim_core::wire::MsgType::LockVerifyRequest, humoco_sim_core::wire::MsgType::LockVerifyResponse),
            (humoco_sim_core::wire::MsgType::StatusQuery, humoco_sim_core::wire::MsgType::StatusResponse),
        ] {
            let mut signatures = Vec::new();
            let conflict = collect_peer_attestations(PeerAttestationQuery {
                transport: &transport, peer_mgr: &manager, candidate_nodes: &candidates,
                expected_members: None, parent_lock: [1; 32], msg_type, resp_msg_type,
                payload: &[], target_status: 1, lock_id: [2; 32], shard_id: 3,
                required_q: 1, shard_query_depth: 0, my_load: 0, quota_limit: 1,
                network_id: humoco_sim_core::types::NetworkId::Mainnet,
            }, &mut signatures).await;
            assert!(conflict.is_none());
            assert!(signatures.is_empty());
            assert!(manager.get_peer(&addr).await.is_none(),
                "Local backpressure must not create a peer failure/malus record");
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
        let storage = Arc::new(RedbStorage::open(&temp.path().join("unit.redb")).expect("open redb"));
        let (engine, _worker) = DualTierEngine::new(storage.clone());
        let identity = NodeIdentity::generate();
        let pow = Arc::new(PowEngine::new(*identity.node_id(), 8));
        let tiers = Arc::new(TierController::new(storage.clone(), pow.clone()));
        let state = AppState::new(engine, storage.clone(), identity.clone(), tiers, pow);
        (temp, state, storage, identity)
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.expect("body").to_bytes();
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn retained_choice_returns_exact_approval_bytes_and_validity() {
        let (_temp, state, storage, identity) = test_state();
        let parent = [7u8; 32];
        let record = humoco_sim_core::types::LockRecord::new(
            parent,
            [8u8; 32],
            vec![1, 2, 3],
            humoco_sim_core::types::SimTime(1_000),
            humoco_sim_core::types::SimTime(600_000),
        );
        let tag = hex::encode(parent);
        storage
            .commit_original_record_approval(&record, 600_000, identity.node_pubkey(), b"sig_prov", 0)
            .expect("commit provisional approval");
        storage
            .commit_original_record_approval(&record, 600_000, identity.node_pubkey(), b"sig_final", 1)
            .expect("commit final approval");

        let response = get_retained_choice(State(state), Path(tag)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["found"], true);
        assert_eq!(body["child"], hex::encode(record.id));
        assert_eq!(body["valid_until_ms"], 600_000u64);
        assert_eq!(body["provisional_approval"], hex::encode(b"sig_prov"));
        assert_eq!(body["final_approval"], hex::encode(b"sig_final"));
        assert_eq!(body["has_provisional"], true);
        assert_eq!(body["has_final"], true);
    }

    #[tokio::test]
    async fn retained_choice_reports_missing_class_without_inventing_bytes() {
        let (_temp, state, storage, identity) = test_state();
        let parent = [9u8; 32];
        let record = humoco_sim_core::types::LockRecord::new(
            parent,
            [10u8; 32],
            vec![4, 5, 6],
            humoco_sim_core::types::SimTime(1_000),
            humoco_sim_core::types::SimTime(600_000),
        );
        let tag = hex::encode(parent);
        storage
            .commit_original_record_approval(&record, 600_000, identity.node_pubkey(), b"sig_prov", 0)
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
        config.discovery.public_gateway_urls = vec!["https://a.example".into(), "https://shared.example".into()];
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
            vec!["https://a.example".to_string(), "http://c.example".to_string()]
        );
    }
}
