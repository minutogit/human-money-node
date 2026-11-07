use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock as StdRwLock,
};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

use crate::network::peer::{PeerConnectionType, PeerInfo, PeerStatus, FAILURE_THRESHOLD_SUSPENDED};
use crate::network::quarantine::{
    decide_algo3v2, CandidateEdge, QuarantineDecision, QuarantineEvent, QuarantinePolicy,
    QuarantinedEdgeState,
};

/// Thread-safe state tracking for F2F edge quarantine and ShadowEdgeWindow.
#[derive(Debug, Clone)]
pub struct QuarantineState {
    pub quarantined_f2f_edges: HashMap<[u8; 32], QuarantinedEdgeState>,
    pub last_quarantine_step_at: Option<Instant>,
    pub quarantine_policy: QuarantinePolicy,
}

pub const DEFAULT_BASE_BACKOFF_MS: u64 = 500;
pub const DEFAULT_MAX_BACKOFF_MS: u64 = 30_000;
pub const MAX_GOSSIP_HOPS: u32 = 16;

/// Tier-2 (Shard-Direct) ephemeral LRU pool idle timeout (TODO-ARCH-02, Spec 15/19).
/// A 15s idle close is the NORMAL state of a Tier-2 connection (no keep-alive)
/// and must NEVER be counted as a peer failure (`record_failure`).
pub const TIER2_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Global PoS shard verification timeout (Spec 03/15).
pub const QUORUM_GLOBAL_TIMEOUT: Duration = Duration::from_millis(1000);

/// 24h Incubation period for re-mining / routing ticket updates and newcomers (Spec 07 & 11).
pub const HRW_INCUBATION_SECS: u64 = 24 * 60 * 60;
pub const HRW_INCUBATION_DURATION: Duration = Duration::from_secs(HRW_INCUBATION_SECS);
/// Accelerated incubation window used exclusively when `network.simulation_mode = true`.
pub const SIM_HRW_INCUBATION_DURATION: Duration = Duration::from_secs(2);

/// Production minimum work floor for HRW shard tickets (Spec 07 §1.1).
/// Requires on average 256 Argon2d (64 MiB, t=3) hashes (~12s on PC, ~38s on Raspberry Pi 4).
pub const W_MIN_FLOOR_PRODUCTION: u64 = 256;
/// Simulation/test minimum work floor allowing instant bootstrapping (1 hash).
pub const W_MIN_FLOOR_SIMULATION: u64 = 1;

/// Presence freshness window for phase-transition counting (Spec 08/11 Phase 9 P1, DEC-056).
/// A gossip-learned node counts toward `N_active` only while its last heartbeat
/// is fresh. Three consecutive missing hourly heartbeats (3 * max 65m = 3h 15m) exclude
/// the identity from future snapshots. RPC failures do not change this passive presence clock.
pub const PRESENCE_FRESHNESS_SECS: u64 = (3 * 60 + 15) * 60; // 3h 15m (11,700s)
pub const PRESENCE_FRESHNESS_TIMEOUT: Duration = Duration::from_secs(PRESENCE_FRESHNESS_SECS);

/// 24h merge/quota moratorium after a partition merge (Spec 09 INV-0908 / Spec 08 INV-0802).
pub const MERGE_HYSTERESIS_SECS: u64 = 24 * 60 * 60;
pub const MERGE_HYSTERESIS_MS: u64 = MERGE_HYSTERESIS_SECS * 1000;

/// Bio-mimetic fan-out k(d) = min(d, ceil(sqrt(d)) + 1) according to Spec 11.
pub fn calculate_fan_out(d: usize) -> usize {
    if d == 0 {
        return 0;
    }
    let sqrt_ceil = (d as f64).sqrt().ceil() as usize;
    std::cmp::min(d, sqrt_ceil + 1)
}

/// Public DTO representing a network node in the Node Explorer dashboard.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetworkNodeDto {
    pub node_id: String,
    pub public_key: String,
    pub address: String,
    pub is_f2f: bool,
    pub is_local: bool,
    pub connection_status: String,
    pub min_hops: u8,
    pub hrw_routing_id: String,
    pub work_score: u64,
    pub is_immature: bool,
    pub pending_ticket: Option<String>,
    pub incubation_remaining_sec: Option<u64>,
    #[serde(default)]
    pub missing_count: u32,
    #[serde(default)]
    pub last_failure_sec: Option<u64>,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default)]
    pub best_ingress_peer: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HopBand {
    Hop0,
    Hop1,
    Hop2Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum SectorSeverity {
    Ok,
    Warn,
    Crit,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnotenfreundSectorReport {
    pub friend_pubkey: String,
    pub friend_addr: Option<SocketAddr>,
    pub is_connected: bool,
    pub active_non_responder_30m: bool,
    pub n_seen: usize,
    pub n_tested: usize,
    pub n_bad: usize,
    pub bad_ratio_tested_bps: u16,
    pub avg_min_hops: f32,
    pub hop_band: HopBand,
    pub exclusive_bad_count: usize,
    pub immature_subnet_burst_max: usize,
    pub unlisted_hop1_count: usize,
    pub hop2_shares_roster: Option<bool>,
    pub hop2_visible_neighbors: Vec<String>,
    pub hop2_hidden_count: u16,
    pub is_mega_hub: bool,
    pub severity: SectorSeverity,
    pub sample_unreachable_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceDirectionHit {
    pub friend_pubkey: String,
    pub hit_count: usize,
    pub min_hops: u8,
    pub exclusive_count: usize,
    pub dominant_subnet: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceAnalysisReport {
    pub total_queried: usize,
    pub locally_tested_healthy_count: usize,
    pub locally_unreachable_count: usize,
    pub unknown_count: usize,
    pub by_knotenfreund: Vec<TraceDirectionHit>,
}

/// Multi-Path directional observation TTL (6 hours).
pub const EDGE_OBSERVATION_TTL: Duration = Duration::from_secs(6 * 3600);

/// Semantically decoupled node information:
/// - `node_pubkey` / `node_id` = stored node identity and its compatibility alias;
///   do not conflate the full `NodePubKey` with `NodeIdentity::node_id()` (a BLAKE3 fingerprint)
/// - `hrw_routing_id` = Argon2d Shard Ticket for HRW routing, may change via re-mining (24h incubation)
/// - `pending_hrw_routing_id` + `pending_since` = 24h incubation buffer for new ticket
/// - `first_seen` + `pre_boot_age` + `last_seen` = 24h IMMATURE threshold for newcomers
#[derive(Clone, Debug)]
pub struct KnownNodeInfo {
    pub(crate) addr: SocketAddr,
    /// Stored node identity bytes, supplied by the discovery caller as `node_pubkey`.
    /// A BLAKE3 fingerprint is not interchangeable with an Ed25519 verifying key.
    pub(crate) node_pubkey: [u8; 32],
    /// Active HRW routing ticket (Argon2d) — sole source for HRW scoring.
    pub(crate) hrw_routing_id: [u8; 32],
    /// Achieved PoW work score for active shard ticket.
    pub(crate) work_score: u64,
    /// Pending new shard ticket during 24h incubation.
    pub(crate) pending_hrw_routing_id: Option<[u8; 32]>,
    /// Achieved PoW work score for pending shard ticket during incubation.
    pub(crate) pending_work_score: Option<u64>,
    /// Timestamp of ticket switch (start of incubation).
    pub(crate) pending_since: Option<Instant>,
    /// Incubation deadline (pending_since + incubation_duration) — explicit field for Spec 07.
    pub(crate) incubated_until: Option<Instant>,
    /// First seen timestamp in the current daemon process.
    pub(crate) first_seen: Instant,
    /// Accumulated maturation duration observed prior to the current OS/daemon boot.
    pub(crate) pre_boot_age: Duration,
    /// Effective incubation requirement (`24h` in production, `2s` in `simulation_mode`).
    pub(crate) incubation_duration: Duration,
    pub(crate) last_seen: Instant,
    pub(crate) min_hops: u8,
    pub(crate) edge_observations: HashMap<[u8; 32], (u8, Instant)>,
    pub(crate) best_ingress_peer: Option<SocketAddr>,
    pub(crate) ingress_diversity_mask: u32,
    pub(crate) latest_obs_hour: Option<u64>,
    pub(crate) obs_24h_mask: u32,
    pub(crate) initial_admission_qualified: bool,
    pub last_write_evidence: Option<humoco_sim_core::fraud::IngressEnvelopeEvidence>,
    pub last_read_evidence: Option<humoco_sim_core::fraud::IngressEnvelopeEvidence>,
}

impl KnownNodeInfo {
    /// Creates new entry with immediately active ticket and IMMATURE start.
    pub fn new(addr: SocketAddr, node_pubkey: [u8; 32], hrw_routing_id: [u8; 32]) -> Self {
        Self::with_work(addr, node_pubkey, hrw_routing_id, 1)
    }

    pub fn with_work(
        addr: SocketAddr,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        work_score: u64,
    ) -> Self {
        let now = Instant::now();
        Self {
            addr,
            node_pubkey,
            hrw_routing_id,
            work_score,
            pending_hrw_routing_id: None,
            pending_work_score: None,
            pending_since: None,
            incubated_until: None,
            first_seen: now,
            pre_boot_age: Duration::ZERO,
            incubation_duration: HRW_INCUBATION_DURATION,
            last_seen: now,
            min_hops: 255,
            edge_observations: HashMap::new(),
            best_ingress_peer: None,
            ingress_diversity_mask: 0,
            latest_obs_hour: None,
            obs_24h_mask: 0,
            initial_admission_qualified: false,
            last_write_evidence: None,
            last_read_evidence: None,
        }
    }

    pub fn with_times(
        addr: SocketAddr,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        first_seen: Instant,
        last_seen: Instant,
    ) -> Self {
        Self {
            addr,
            node_pubkey,
            hrw_routing_id,
            work_score: 1,
            pending_hrw_routing_id: None,
            pending_work_score: None,
            pending_since: None,
            incubated_until: None,
            first_seen,
            pre_boot_age: Duration::ZERO,
            incubation_duration: HRW_INCUBATION_DURATION,
            last_seen,
            min_hops: 255,
            edge_observations: HashMap::new(),
            best_ingress_peer: None,
            ingress_diversity_mask: 0,
            latest_obs_hour: None,
            obs_24h_mask: 0,
            initial_admission_qualified: false,
            last_write_evidence: None,
            last_read_evidence: None,
        }
    }

    pub fn prune_edge_observations(&mut self, now: Instant) {
        self.edge_observations
            .retain(|_, (_, ts)| now.duration_since(*ts) < EDGE_OBSERVATION_TTL);
        if !self.edge_observations.is_empty() {
            self.min_hops = self
                .edge_observations
                .values()
                .map(|&(h, _)| h)
                .min()
                .unwrap_or(255);
        }
    }

    pub fn record_edge_observation(&mut self, friend_pk: [u8; 32], hops: u8, now: Instant) {
        self.prune_edge_observations(now);
        if self.edge_observations.len() >= 64 && !self.edge_observations.contains_key(&friend_pk) {
            if let Some((&oldest_k, _)) = self
                .edge_observations
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
            {
                self.edge_observations.remove(&oldest_k);
            }
        }
        self.edge_observations.insert(friend_pk, (hops, now));
        self.min_hops = self
            .edge_observations
            .values()
            .map(|&(h, _)| h)
            .min()
            .unwrap_or(self.min_hops);
    }

    pub fn update_write_evidence(&mut self, ev: humoco_sim_core::fraud::IngressEnvelopeEvidence) {
        self.last_write_evidence = Some(ev);
    }

    pub fn update_read_evidence(&mut self, ev: humoco_sim_core::fraud::IngressEnvelopeEvidence) {
        self.last_read_evidence = Some(ev);
    }

    /// Returns the work score of this node.
    pub fn work_score(&self) -> u64 {
        self.work_score
    }

    /// Returns the minimum hop distance observed for this node.
    pub fn min_hops(&self) -> u8 {
        let now = Instant::now();
        let valid_min = self
            .edge_observations
            .values()
            .filter(|(_, ts)| now.duration_since(*ts) < EDGE_OBSERVATION_TTL)
            .map(|&(h, _)| h)
            .min();
        valid_min.unwrap_or(self.min_hops)
    }

    /// Total maturation age combining persisted pre-boot observation age and live uptime.
    pub fn observed_age(&self) -> Duration {
        self.pre_boot_age.saturating_add(self.first_seen.elapsed())
    }

    /// Effective HRW for scoring: active ticket, as long as pending is not mature.
    pub fn effective_hrw(&self) -> [u8; 32] {
        // If pending is mature (>=24h), it would have been promoted already — return active here.
        // Caller should check `is_pending_mature()` or trigger promotion beforehand.
        self.hrw_routing_id
    }

    /// Checks if pending ticket is mature.
    pub fn is_pending_mature(&self) -> bool {
        if let Some(since) = self.pending_since {
            since.elapsed() >= self.incubation_duration
        } else {
            false
        }
    }

    /// Remaining incubation time until pending becomes active.
    pub fn pending_remaining(&self) -> Option<Duration> {
        self.pending_since.map(|since| {
            let elapsed = since.elapsed();
            if elapsed >= self.incubation_duration {
                Duration::from_secs(0)
            } else {
                self.incubation_duration - elapsed
            }
        })
    }

    /// Is node still IMMATURE (< incubation_duration since first contact)?
    pub fn is_immature(&self) -> bool {
        self.observed_age() < self.incubation_duration
    }

    /// Records an authenticated hourly observation using approved network time.
    /// Canonical hour slot = obs_ms / 3_600_000.
    pub fn record_hourly_observation(&mut self, obs_ms: u64, is_simulation: bool) {
        let hour = obs_ms / 3_600_000;
        match self.latest_obs_hour {
            None => {
                self.latest_obs_hour = Some(hour);
                self.obs_24h_mask = 1;
            }
            Some(latest) => {
                if hour > latest {
                    let delta = hour - latest;
                    if delta >= 24 {
                        self.obs_24h_mask = 1;
                    } else {
                        self.obs_24h_mask = ((self.obs_24h_mask << delta) | 1) & 0x00FF_FFFF;
                    }
                    self.latest_obs_hour = Some(hour);
                } else if hour < latest {
                    let delta = latest - hour;
                    if delta < 24 {
                        self.obs_24h_mask |= 1 << delta;
                        self.obs_24h_mask &= 0x00FF_FFFF;
                    }
                }
            }
        }

        if is_simulation {
            if self.observed_age() >= self.incubation_duration {
                self.initial_admission_qualified = true;
            }
        } else if self.observed_age() >= self.incubation_duration
            && self.obs_24h_mask.count_ones() >= 8
        {
            self.initial_admission_qualified = true;
        }
    }

    /// Checks if initial admission has been qualified (latched per active hrw_routing_id).
    pub fn is_initial_admission_qualified(&self) -> bool {
        if self.incubation_duration <= SIM_HRW_INCUBATION_DURATION {
            return self.observed_age() >= self.incubation_duration;
        }
        if self.initial_admission_qualified {
            return true;
        }
        if self.pre_boot_age >= self.incubation_duration {
            return true;
        }
        if self.observed_age() >= self.incubation_duration && self.obs_24h_mask.count_ones() >= 8 {
            return true;
        }
        false
    }

    /// Is gossip presence still fresh (heartbeat seen within `PRESENCE_FRESHNESS_TIMEOUT`)?
    /// Stale ghosts must not inflate `N_active` for the Provisional -> Final transition.
    pub fn is_presence_fresh(&self) -> bool {
        self.last_seen.elapsed() < PRESENCE_FRESHNESS_TIMEOUT
    }

    /// May node be used for HRW scoring? (ACTIVE, not IMMATURE, and qualified for initial admission)
    pub fn is_hrw_eligible(&self) -> bool {
        !self.is_immature() && self.is_initial_admission_qualified()
    }
}

#[derive(Clone, Debug)]
pub struct DnsPeerState {
    pub entry: crate::config::PeerConfigEntry,
    pub current_addr: Option<SocketAddr>,
}

/// Phase 10: queued fraud-proof forward message — the payload plus the
/// immediate sender to exclude on forward (echo protection). `None` means
/// locally detected (broadcast to all F2F friends).
pub type FraudProofForwardMsg = (humoco_sim_core::fraud::FraudProofPayload, Option<[u8; 32]>);

pub type EngineBannedNodesHandle = Arc<tokio::sync::RwLock<std::collections::HashSet<[u8; 32]>>>;

pub const MAX_HEARTBEATS_PER_MINUTE_SLOT: usize = 10;

/// Bounded LRU-style deduplication cache for seen heartbeats (Spec 11).
#[derive(Debug)]
pub struct HeartbeatDedupCache {
    set: HashSet<[u8; 32]>,
    queue: std::collections::VecDeque<[u8; 32]>,
    capacity: usize,
    slot_counts: HashMap<([u8; 32], u64), usize>,
    slot_queue: std::collections::VecDeque<([u8; 32], u64)>,
}

impl HeartbeatDedupCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            set: HashSet::with_capacity(capacity.min(4096)),
            queue: std::collections::VecDeque::with_capacity(capacity.min(4096)),
            capacity,
            slot_counts: HashMap::with_capacity(capacity.min(4096)),
            slot_queue: std::collections::VecDeque::with_capacity(capacity.min(4096)),
        }
    }

    pub fn check_and_insert(&mut self, id: [u8; 32]) -> bool {
        if self.set.contains(&id) {
            return false;
        }
        if self.queue.len() >= self.capacity {
            if let Some(oldest) = self.queue.pop_front() {
                self.set.remove(&oldest);
            }
        }
        self.set.insert(id);
        self.queue.push_back(id);
        true
    }

    pub fn check_and_insert_slotted(
        &mut self,
        id: [u8; 32],
        node_id: [u8; 32],
        timestamp_ms: u64,
    ) -> bool {
        if self.set.contains(&id) {
            return false;
        }

        let slot = timestamp_ms / 60_000;
        let slot_key = (node_id, slot);
        let count = self.slot_counts.entry(slot_key).or_insert(0);
        if *count >= MAX_HEARTBEATS_PER_MINUTE_SLOT {
            return false;
        }
        *count += 1;

        if self.slot_queue.len() >= self.capacity {
            if let Some(oldest_slot) = self.slot_queue.pop_front() {
                if let Some(c) = self.slot_counts.get_mut(&oldest_slot) {
                    if *c > 1 {
                        *c -= 1;
                    } else {
                        self.slot_counts.remove(&oldest_slot);
                    }
                }
            }
        }
        self.slot_queue.push_back(slot_key);

        if self.queue.len() >= self.capacity {
            if let Some(oldest) = self.queue.pop_front() {
                self.set.remove(&oldest);
            }
        }
        self.set.insert(id);
        self.queue.push_back(id);
        true
    }
}

/// Bounded LRU cache of observed original shard attestations for equivocation detection (A10-02).
#[derive(Debug)]
pub struct ObservedVoteCache {
    map: HashMap<([u8; 32], [u8; 32]), humoco_sim_core::types::Attestation>,
    queue: std::collections::VecDeque<([u8; 32], [u8; 32])>,
    capacity: usize,
}

impl ObservedVoteCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity.min(4096)),
            queue: std::collections::VecDeque::with_capacity(capacity.min(4096)),
            capacity,
        }
    }

    /// Inserts an original vote for `(signer_pubkey, parent_lock)`.
    /// Returns `Err(prev_att)` if an existing attestation on the same parent_lock
    /// has a DIFFERENT `lock_id` (double-signing equivocation).
    #[allow(clippy::result_large_err)]
    pub fn insert_or_detect_equivocation(
        &mut self,
        signer_pubkey: [u8; 32],
        att: humoco_sim_core::types::Attestation,
    ) -> Result<(), humoco_sim_core::types::Attestation> {
        let key = (signer_pubkey, att.parent_lock);
        if let Some(prev) = self.map.get(&key) {
            if prev.lock_id != att.lock_id {
                return Err(prev.clone());
            }
            return Ok(());
        }
        if self.queue.len() >= self.capacity {
            if let Some(oldest) = self.queue.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(key, att);
        self.queue.push_back(key);
        Ok(())
    }
}

type LocalTicketObservation =
    Arc<std::sync::Mutex<Option<([u8; 32], [u8; 32], Instant, Duration)>>>;
type PersistedTicketAges = Arc<parking_lot::Mutex<HashMap<([u8; 32], [u8; 32]), Duration>>>;

#[derive(Clone)]
pub struct PeerManager {
    gateway_advertisements: Arc<
        parking_lot::RwLock<
            std::collections::BTreeMap<[u8; 32], crate::network::discovery::GatewayAdvertisement>,
        >,
    >,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    f2f_friends: Arc<RwLock<HashMap<[u8; 32], Option<SocketAddr>>>>,
    dns_peers: Arc<RwLock<Vec<DnsPeerState>>>,
    known_network_nodes: Arc<RwLock<HashMap<[u8; 32], KnownNodeInfo>>>,
    /// Strict 32-byte NodePubKey -> VerifyingKey resolution (Pillar 3:
    /// Cryptographic Identity Trumps Network Topology). There is deliberately
    /// NO `u16 -> VerifyingKey` map: the 16-bit prefix collides across nodes
    /// and previously allowed silent `u16_to_vk` overwrite attacks.
    verifying_keys: Arc<RwLock<HashMap<[u8; 32], ed25519_dalek::VerifyingKey>>>,
    banned_nodes: Arc<RwLock<HashSet<[u8; 32]>>>,
    endpoint: Arc<StdRwLock<Option<quinn::Endpoint>>>,
    clock: Arc<crate::network::NetworkClock>,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
    ge20_first_reached_ms: Arc<AtomicU64>,
    sync_notify: Arc<tokio::sync::Notify>,
    ticket_outdated: Arc<std::sync::atomic::AtomicBool>,
    local_sync_ready: Arc<std::sync::atomic::AtomicBool>,
    simulation_mode: Arc<std::sync::atomic::AtomicBool>,
    override_min_work_floor: Arc<std::sync::atomic::AtomicU64>,
    merge_hysteresis_until_ms: Arc<AtomicU64>,
    fraud_proof_tx:
        Arc<tokio::sync::RwLock<Option<tokio::sync::mpsc::Sender<FraudProofForwardMsg>>>>,
    recent_observed_evidences: Arc<
        tokio::sync::RwLock<
            std::collections::VecDeque<humoco_sim_core::fraud::IngressEnvelopeEvidence>,
        >,
    >,
    seen_heartbeats: Arc<tokio::sync::RwLock<HeartbeatDedupCache>>,
    /// Phase 10: bounded LRU seen-set for fraud-proof forwarding dedup
    /// (prevents gossip amplification loops) + echo protection basis.
    seen_fraud_proofs: Arc<tokio::sync::RwLock<HeartbeatDedupCache>>,
    known_active_shards: Arc<RwLock<std::collections::BTreeSet<u16>>>,
    local_ticket_observation: LocalTicketObservation,
    persisted_ticket_ages: PersistedTicketAges,
    observed_votes: Arc<parking_lot::Mutex<ObservedVoteCache>>,
    storage: Arc<parking_lot::RwLock<Option<std::sync::Weak<crate::storage::RedbStorage>>>>,
    engine_banned_nodes: Arc<parking_lot::RwLock<Option<EngineBannedNodesHandle>>>,
    f2f_collab: Arc<parking_lot::Mutex<crate::network::f2f_collab::F2fCollabManager>>,
    sector_anomaly_since: Arc<parking_lot::Mutex<HashMap<[u8; 32], Instant>>>,
    alert_dispatcher: Arc<parking_lot::RwLock<Option<Arc<crate::alert::AlertDispatcher>>>>,
    quarantine_state: Arc<parking_lot::RwLock<QuarantineState>>,
}

impl std::fmt::Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("base_backoff_ms", &self.base_backoff_ms)
            .field("max_backoff_ms", &self.max_backoff_ms)
            .finish()
    }
}

impl PeerManager {
    /// Creates a new PeerManager pre-populated with configured peer addresses.
    pub fn new(configured_peers: Vec<SocketAddr>) -> Self {
        let entries = configured_peers
            .into_iter()
            .map(|addr| (None, addr))
            .collect();
        Self::with_f2f(entries, Vec::new())
    }

    /// Creates a new PeerManager with configured F2F friends and endpoints.
    pub fn with_f2f(
        configured_peers: Vec<(Option<[u8; 32]>, SocketAddr)>,
        trusted_pubkeys: Vec<[u8; 32]>,
    ) -> Self {
        Self::with_f2f_and_dns(configured_peers, trusted_pubkeys, Vec::new())
    }

    /// Creates a new PeerManager with configured F2F friends, endpoints, and DNS hostname peers.
    pub fn with_f2f_and_dns(
        configured_peers: Vec<(Option<[u8; 32]>, SocketAddr)>,
        trusted_pubkeys: Vec<[u8; 32]>,
        dns_peers: Vec<crate::config::PeerConfigEntry>,
    ) -> Self {
        let mut peer_map = HashMap::new();
        let mut friend_map = HashMap::new();
        let mut vk_map = HashMap::new();

        for key in &trusted_pubkeys {
            friend_map.insert(*key, None);
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key) {
                vk_map.insert(*key, vk);
            }
        }

        for (opt_key, addr) in &configured_peers {
            let mut info = PeerInfo::with_type(*addr, PeerConnectionType::FriendToFriend);
            if let Some(key) = opt_key {
                info.node_id = Some(*key);
                friend_map.insert(*key, Some(*addr));
                if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key) {
                    vk_map.insert(*key, vk);
                }
            }
            peer_map.insert(*addr, info);
        }

        let mut dns_state_list = Vec::new();
        for entry in dns_peers {
            let current_addr = configured_peers
                .iter()
                .find(|(opt_key, addr)| {
                    if entry.pubkey.is_some() && *opt_key == entry.pubkey {
                        true
                    } else if let Ok(sa) = entry.raw_endpoint.parse::<SocketAddr>() {
                        sa == *addr
                    } else {
                        false
                    }
                })
                .map(|(_, addr)| *addr);

            dns_state_list.push(DnsPeerState {
                entry,
                current_addr,
            });
        }

        Self {
            peers: Arc::new(RwLock::new(peer_map)),
            f2f_friends: Arc::new(RwLock::new(friend_map)),
            dns_peers: Arc::new(RwLock::new(dns_state_list)),
            known_network_nodes: Arc::new(RwLock::new(HashMap::new())),
            gateway_advertisements: Arc::new(parking_lot::RwLock::new(
                std::collections::BTreeMap::new(),
            )),
            verifying_keys: Arc::new(RwLock::new(vk_map)),
            banned_nodes: Arc::new(RwLock::new(HashSet::new())),
            endpoint: Arc::new(StdRwLock::new(None)),
            clock: Arc::new(crate::network::NetworkClock::new()),
            base_backoff_ms: DEFAULT_BASE_BACKOFF_MS,
            max_backoff_ms: DEFAULT_MAX_BACKOFF_MS,
            ge20_first_reached_ms: Arc::new(AtomicU64::new(0)),
            sync_notify: Arc::new(tokio::sync::Notify::new()),
            ticket_outdated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            local_sync_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            simulation_mode: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            override_min_work_floor: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            merge_hysteresis_until_ms: Arc::new(AtomicU64::new(0)),
            fraud_proof_tx: Arc::new(tokio::sync::RwLock::new(None)),
            recent_observed_evidences: Arc::new(tokio::sync::RwLock::new(
                std::collections::VecDeque::with_capacity(16),
            )),
            seen_heartbeats: Arc::new(tokio::sync::RwLock::new(HeartbeatDedupCache::new(10_000))),
            seen_fraud_proofs: Arc::new(tokio::sync::RwLock::new(HeartbeatDedupCache::new(1024))),
            local_ticket_observation: Arc::new(std::sync::Mutex::new(None)),
            persisted_ticket_ages: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            known_active_shards: Arc::new(RwLock::new(std::collections::BTreeSet::new())),
            observed_votes: Arc::new(parking_lot::Mutex::new(ObservedVoteCache::new(4096))),
            storage: Arc::new(parking_lot::RwLock::new(None)),
            engine_banned_nodes: Arc::new(parking_lot::RwLock::new(None)),
            f2f_collab: Arc::new(parking_lot::Mutex::new(
                crate::network::f2f_collab::F2fCollabManager::new(None, true),
            )),
            sector_anomaly_since: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            alert_dispatcher: Arc::new(parking_lot::RwLock::new(None)),
            quarantine_state: Arc::new(parking_lot::RwLock::new(QuarantineState {
                quarantined_f2f_edges: HashMap::new(),
                last_quarantine_step_at: None,
                quarantine_policy: QuarantinePolicy::default(),
            })),
        }
    }

    /// Enables or disables accelerated incubation timing for `network.simulation_mode = true`.
    pub fn set_simulation_mode(&self, enabled: bool) {
        self.simulation_mode
            .store(enabled, std::sync::atomic::Ordering::Release);
    }

    /// Returns true if simulation mode is active.
    pub fn is_simulation_mode(&self) -> bool {
        self.simulation_mode
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Returns the active HRW ticket incubation window (`24h` in production, `2s` in simulation_mode).
    pub fn effective_incubation_duration(&self) -> Duration {
        if self
            .simulation_mode
            .load(std::sync::atomic::Ordering::Acquire)
        {
            SIM_HRW_INCUBATION_DURATION
        } else {
            HRW_INCUBATION_DURATION
        }
    }

    /// Returns the minimum work floor for HRW shard tickets (256 in production, 1 in simulation_mode).
    pub fn effective_min_work_floor(&self) -> u64 {
        let overridden = self
            .override_min_work_floor
            .load(std::sync::atomic::Ordering::Relaxed);
        if overridden > 0 {
            return overridden;
        }
        if self.is_simulation_mode() {
            W_MIN_FLOOR_SIMULATION
        } else {
            W_MIN_FLOOR_PRODUCTION
        }
    }

    /// Sets an explicit work floor override for unit/integration tests without altering incubation duration.
    pub fn set_min_work_floor_for_test(&self, floor: u64) {
        self.override_min_work_floor
            .store(floor, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn configure_f2f_collab(
        &self,
        data_dir: Option<std::path::PathBuf>,
        share_neighbor_roster: bool,
    ) {
        *self.f2f_collab.lock() =
            crate::network::f2f_collab::F2fCollabManager::new(data_dir, share_neighbor_roster);
    }

    pub fn f2f_collab(
        &self,
    ) -> &Arc<parking_lot::Mutex<crate::network::f2f_collab::F2fCollabManager>> {
        &self.f2f_collab
    }

    pub fn set_alert_dispatcher(&self, dispatcher: Arc<crate::alert::AlertDispatcher>) {
        *self.alert_dispatcher.write() = Some(dispatcher);
    }

    pub fn alert_dispatcher(&self) -> Option<Arc<crate::alert::AlertDispatcher>> {
        self.alert_dispatcher.read().clone()
    }

    pub async fn get_f2f_friend_addr(&self, friend_pk: &[u8; 32]) -> Option<SocketAddr> {
        self.f2f_friends
            .read()
            .await
            .get(friend_pk)
            .copied()
            .flatten()
    }

    pub async fn f2f_friend_endpoints(&self) -> Vec<([u8; 32], Option<SocketAddr>)> {
        self.f2f_friends
            .read()
            .await
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect()
    }

    pub async fn f2f_friend_pubkey_for_addr(&self, addr: &SocketAddr) -> Option<[u8; 32]> {
        {
            let friends = self.f2f_friends.read().await;
            for (&pk, opt_addr) in friends.iter() {
                if opt_addr.as_ref() == Some(addr) {
                    return Some(pk);
                }
            }
        }
        let peers = self.peers.read().await;
        peers.get(addr).and_then(|p| {
            if p.conn_type == PeerConnectionType::FriendToFriend {
                p.node_id
            } else {
                None
            }
        })
    }

    /// Records a multi-path edge observation from an authenticated direct F2F friend (0 Argon2d cost).
    pub async fn record_heartbeat_edge_observation(
        &self,
        node_id: [u8; 32],
        friend_pk: [u8; 32],
        hops: u8,
    ) {
        let now = Instant::now();
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(&node_id) {
            entry.record_edge_observation(friend_pk, hops, now);
        }
    }

    /// Constructs our canonical local roster for direct 1-hop exchange obeying mutual consent.
    pub async fn build_local_f2f_roster(
        &self,
        self_pubkey: &[u8; 32],
    ) -> crate::network::framing::F2fNeighborRosterPayload {
        let friends: Vec<[u8; 32]> = self.f2f_friends.read().await.keys().cloned().collect();
        let collab = self.f2f_collab.lock();
        collab
            .roster()
            .build_local_roster(self_pubkey, &friends, self.net_time_ms())
    }

    /// Evaluates whether the local node is trapped in an isolated closed triangle bubble.
    pub async fn is_closed_triangle_bubble(&self, self_pubkey: &[u8; 32]) -> bool {
        let friends: Vec<[u8; 32]> = self.f2f_friends.read().await.keys().cloned().collect();
        let collab = self.f2f_collab.lock();
        collab.roster().is_closed_triangle_bubble(self_pubkey, &friends)
    }

    /// Returns whether this node shares its direct neighbor roster with direct F2F friends.
    pub fn share_neighbor_roster(&self) -> bool {
        self.f2f_collab.lock().roster().share_neighbor_roster()
    }

    pub fn subnet_prefix(addr: &SocketAddr) -> String {
        match addr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                let o = ipv4.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            }
            std::net::IpAddr::V6(ipv6) => {
                let s = ipv6.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        }
    }

    /// Computes directional sector analysis for all direct F2F friends without holding nested locks (Phase 10 deadlock freedom).
    pub async fn compute_knotenfreund_sectors(&self) -> Vec<KnotenfreundSectorReport> {
        let now = Instant::now();
        let friends = self.f2f_friends.read().await.clone();
        let peers = self.peers.read().await.clone();
        let nodes = self.known_network_nodes.read().await.clone();
        let rosters = {
            let collab = self.f2f_collab.lock();
            collab.roster().friend_rosters().clone()
        };

        // Precompute valid observations and shortest path observers per known node
        let mut node_shortest_observers: HashMap<[u8; 32], (u8, Vec<[u8; 32]>)> = HashMap::new();
        for (&pk, info) in &nodes {
            let mut valid_obs: Vec<([u8; 32], u8)> = Vec::new();
            for (&friend_pk, &(hops, ts)) in &info.edge_observations {
                if now.duration_since(ts) < EDGE_OBSERVATION_TTL {
                    valid_obs.push((friend_pk, hops));
                }
            }
            if !valid_obs.is_empty() {
                let min_h = valid_obs.iter().map(|(_, h)| *h).min().unwrap_or(255);
                let shortest: Vec<[u8; 32]> = valid_obs
                    .into_iter()
                    .filter(|(_, h)| *h == min_h)
                    .map(|(f_pk, _)| f_pk)
                    .collect();
                node_shortest_observers.insert(pk, (min_h, shortest));
            }
        }

        let mut reports = Vec::new();

        for (&friend_pk, &friend_addr) in &friends {
            let friend_hex = hex::encode(friend_pk);
            let peer_opt = friend_addr.and_then(|addr| peers.get(&addr));
            let is_connected = peer_opt.is_some_and(|p| p.is_connected());
            let active_non_responder_30m = peer_opt.is_some_and(|p| {
                p.is_active_non_responder(now, Duration::from_secs(30 * 60))
            });

            // Domain D(F) = nodes where friend is among the shortest observers within 6h
            let mut domain_nodes = Vec::new();
            let mut total_hops: u64 = 0;

            for (&k_pk, (min_h, shortest_list)) in &node_shortest_observers {
                if shortest_list.contains(&friend_pk) {
                    domain_nodes.push((k_pk, *min_h));
                    total_hops = total_hops.saturating_add(*min_h as u64);
                }
            }

            let n_seen = domain_nodes.len();
            let avg_min_hops = if n_seen > 0 {
                total_hops as f32 / n_seen as f32
            } else {
                0.0
            };

            let mut tested_count = 0;
            let mut bad_nodes: Vec<([u8; 32], u8)> = Vec::new();
            let mut immature_subnet_counts: HashMap<String, usize> = HashMap::new();

            for &(k_pk, hops) in &domain_nodes {
                let Some(k_info) = nodes.get(&k_pk) else {
                    continue;
                };

                // Track immature subnets in D(F)
                if k_info.is_immature() {
                    let subnet = Self::subnet_prefix(&k_info.addr);
                    *immature_subnet_counts.entry(subnet).or_default() += 1;
                }

                // Check if tested within 6h
                let k_peer = peers.values().find(|p| p.node_id == Some(k_pk)).or_else(|| {
                    peers.get(&k_info.addr)
                });

                let was_tested_within_6h = k_peer
                    .and_then(|p| p.last_rpc_tested_at)
                    .is_some_and(|ts| now.duration_since(ts) < Duration::from_secs(6 * 3600));

                if was_tested_within_6h {
                    tested_count += 1;
                    if k_peer.is_some_and(|p| p.missing_count >= 3) && k_info.is_presence_fresh() {
                        bad_nodes.push((k_pk, hops));
                    }
                }
            }

            let n_tested = tested_count;
            let n_bad = bad_nodes.len();
            let bad_ratio_tested_bps = if n_tested > 0 {
                ((n_bad as u64 * 10000) / (n_tested as u64)) as u16
            } else {
                0
            };

            // Exclusive bad count: bad nodes in D(F) that have friend_pk as unique observer within 6h
            let mut exclusive_bad_count = 0;
            for &(bad_pk, _) in &bad_nodes {
                if let Some(bad_info) = nodes.get(&bad_pk) {
                    let active_obs_count = bad_info
                        .edge_observations
                        .values()
                        .filter(|(_, ts)| now.duration_since(*ts) < EDGE_OBSERVATION_TTL)
                        .count();
                    if active_obs_count == 1 {
                        exclusive_bad_count += 1;
                    }
                }
            }

            let immature_subnet_burst_max =
                immature_subnet_counts.values().cloned().max().unwrap_or(0);

            // Hop band determination
            let hop_band = if active_non_responder_30m {
                HopBand::Hop0
            } else if n_bad > 0 {
                let bad_hops_avg =
                    bad_nodes.iter().map(|(_, h)| *h as f32).sum::<f32>() / n_bad as f32;
                if bad_hops_avg < 1.5 {
                    HopBand::Hop1
                } else {
                    HopBand::Hop2Plus
                }
            } else if avg_min_hops < 1.5 {
                HopBand::Hop1
            } else {
                HopBand::Hop2Plus
            };

            // Roster details
            let roster_opt = rosters.get(&friend_pk);
            let hop2_shares_roster = roster_opt.map(|r| r.shares_roster);
            let hop2_visible_neighbors = roster_opt
                .map(|r| r.visible_neighbors.iter().map(hex::encode).collect())
                .unwrap_or_default();
            let hop2_hidden_count = roster_opt.map(|r| r.hidden_neighbor_count).unwrap_or(0);
            let is_mega_hub = roster_opt.is_some_and(|r| {
                r.visible_neighbors
                    .len()
                    .saturating_add(r.hidden_neighbor_count as usize)
                    > 32
            });

            // Unlisted hop1 count (Liar check):
            // nodes observed with hops == 1 from friend_pk that are NOT in friend's visible_neighbors
            // when friend explicitly has shares_roster == true and hidden_neighbor_count == 0
            let mut unlisted_hop1_count = 0;
            if let Some(roster) = roster_opt {
                if roster.shares_roster && roster.hidden_neighbor_count == 0 {
                    for (&k_pk, k_info) in &nodes {
                        if k_pk == friend_pk {
                            continue;
                        }
                        if let Some(&(1, ts)) = k_info.edge_observations.get(&friend_pk) {
                            if now.duration_since(ts) < EDGE_OBSERVATION_TTL
                                && !roster.visible_neighbors.contains(&k_pk)
                            {
                                unlisted_hop1_count += 1;
                            }
                        }
                    }
                }
            }

            // Severity calculation
            let mut raw_crit = false;
            let mut raw_warn = false;

            if active_non_responder_30m {
                raw_crit = true;
            } else if (5..15).contains(&n_tested) {
                if bad_ratio_tested_bps >= 6500 && n_bad >= 5 {
                    raw_crit = true;
                } else if bad_ratio_tested_bps >= 4000 && n_bad >= 3 {
                    raw_warn = true;
                }
            } else if (15..50).contains(&n_tested) {
                if bad_ratio_tested_bps >= 4000 && n_bad >= 8 {
                    raw_crit = true;
                } else if bad_ratio_tested_bps >= 2500 && n_bad >= 5 {
                    raw_warn = true;
                }
            } else if n_tested >= 50 {
                if bad_ratio_tested_bps >= 2500 || n_bad >= 15 {
                    raw_crit = true;
                } else if bad_ratio_tested_bps >= 1500 {
                    raw_warn = true;
                }
            }

            if immature_subnet_burst_max > 15 || unlisted_hop1_count > 0 {
                raw_warn = true;
            }

            // 30-min stability hysteresis for Crit
            let severity = if raw_crit {
                let mut hysteresis = self.sector_anomaly_since.lock();
                let since = hysteresis.entry(friend_pk).or_insert(now);
                if now.duration_since(*since) >= Duration::from_secs(30 * 60) {
                    SectorSeverity::Crit
                } else {
                    SectorSeverity::Warn
                }
            } else {
                self.sector_anomaly_since.lock().remove(&friend_pk);
                if raw_warn {
                    SectorSeverity::Warn
                } else {
                    SectorSeverity::Ok
                }
            };

            let sample_unreachable_pubkeys: Vec<String> = bad_nodes
                .iter()
                .take(32)
                .map(|(pk, _)| hex::encode(pk))
                .collect();

            reports.push(KnotenfreundSectorReport {
                friend_pubkey: friend_hex,
                friend_addr,
                is_connected,
                active_non_responder_30m,
                n_seen,
                n_tested,
                n_bad,
                bad_ratio_tested_bps,
                avg_min_hops,
                hop_band,
                exclusive_bad_count,
                immature_subnet_burst_max,
                unlisted_hop1_count,
                hop2_shares_roster,
                hop2_visible_neighbors,
                hop2_hidden_count,
                is_mega_hub,
                severity,
                sample_unreachable_pubkeys,
            });
        }

        reports
    }

    /// Analyzes an attached machine-readable trace (list of pubkeys) against local routing and health state.
    pub async fn analyze_trace_pubkeys(&self, pubkeys: &[[u8; 32]]) -> TraceAnalysisReport {
        let now = Instant::now();
        let friends = self.f2f_friends.read().await.clone();
        let peers = self.peers.read().await.clone();
        let nodes = self.known_network_nodes.read().await.clone();

        let total_queried = pubkeys.len();
        let mut locally_tested_healthy_count = 0;
        let mut locally_unreachable_count = 0;
        let mut unknown_count = 0;

        type TraceHopHit = ([u8; 32], u8, SocketAddr);
        let mut friend_hits: HashMap<[u8; 32], Vec<TraceHopHit>> = HashMap::new();

        for &pk in pubkeys {
            let Some(node_info) = nodes.get(&pk) else {
                unknown_count += 1;
                continue;
            };

            let peer_opt = peers.values().find(|p| p.node_id == Some(pk)).or_else(|| {
                peers.get(&node_info.addr)
            });

            if let Some(peer) = peer_opt {
                if peer
                    .last_rpc_tested_at
                    .is_some_and(|ts| now.duration_since(ts) < Duration::from_secs(6 * 3600))
                    && peer.missing_count == 0
                {
                    locally_tested_healthy_count += 1;
                }
                if peer.missing_count >= 3 {
                    locally_unreachable_count += 1;
                }
            }

            // Find valid observations for pk
            let valid_obs: Vec<([u8; 32], u8)> = node_info
                .edge_observations
                .iter()
                .filter(|(_, (_, ts))| now.duration_since(*ts) < EDGE_OBSERVATION_TTL)
                .map(|(&f_pk, &(hops, _))| (f_pk, hops))
                .collect();

            if !valid_obs.is_empty() {
                let min_h = valid_obs.iter().map(|(_, h)| *h).min().unwrap_or(255);
                for (f_pk, h) in valid_obs {
                    if h == min_h && friends.contains_key(&f_pk) {
                        friend_hits
                            .entry(f_pk)
                            .or_default()
                            .push((pk, h, node_info.addr));
                    }
                }
            }
        }

        let mut by_knotenfreund = Vec::new();
        for (friend_pk, hit_list) in friend_hits {
            let hit_count = hit_list.len();
            let min_hops = hit_list.iter().map(|(_, h, _)| *h).min().unwrap_or(255);

            let mut exclusive_count = 0;
            let mut subnets: HashMap<String, usize> = HashMap::new();

            for &(pk, _, addr) in &hit_list {
                if let Some(info) = nodes.get(&pk) {
                    let active_obs_count = info
                        .edge_observations
                        .values()
                        .filter(|(_, ts)| now.duration_since(*ts) < EDGE_OBSERVATION_TTL)
                        .count();
                    if active_obs_count == 1 {
                        exclusive_count += 1;
                    }
                }
                *subnets.entry(Self::subnet_prefix(&addr)).or_default() += 1;
            }

            let dominant_subnet = subnets
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(sub, _)| sub);

            by_knotenfreund.push(TraceDirectionHit {
                friend_pubkey: hex::encode(friend_pk),
                hit_count,
                min_hops,
                exclusive_count,
                dominant_subnet,
            });
        }

        by_knotenfreund.sort_by_key(|h| std::cmp::Reverse(h.hit_count));

        TraceAnalysisReport {
            total_queried,
            locally_tested_healthy_count,
            locally_unreachable_count,
            unknown_count,
            by_knotenfreund,
        }
    }

    /// Restores a previously persisted maturation age for `(node_pubkey, hrw_routing_id)` on daemon boot.
    pub fn seed_persisted_ticket_age(
        &self,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        prior_age: Duration,
    ) {
        let is_shortcut = hrw_routing_id == *blake3::hash(&node_pubkey).as_bytes()
            || hrw_routing_id == node_pubkey
            || hrw_routing_id == [0u8; 32];
        if !self.is_simulation_mode() && is_shortcut {
            return;
        }
        self.persisted_ticket_ages
            .lock()
            .insert((node_pubkey, hrw_routing_id), prior_age);
    }

    /// Restores or initializes the local node's own ticket observation age on daemon boot.
    pub fn seed_local_ticket_age(
        &self,
        local_pubkey: [u8; 32],
        local_hrw: [u8; 32],
        prior_age: Duration,
    ) {
        let is_shortcut = local_hrw == *blake3::hash(&local_pubkey).as_bytes()
            || local_hrw == local_pubkey
            || local_hrw == [0u8; 32];
        if !self.is_simulation_mode() && is_shortcut {
            return;
        }
        if let Ok(mut guard) = self.local_ticket_observation.lock() {
            *guard = Some((local_pubkey, local_hrw, Instant::now(), prior_age));
        }
    }

    /// Snapshots active remote `(node_pubkey, hrw_routing_id)` pairs for periodic persistence.
    pub async fn snapshot_active_tickets(&self) -> Vec<([u8; 32], [u8; 32])> {
        let known = self.known_network_nodes.read().await;
        known
            .iter()
            .filter(|(_, info)| info.addr.port() != 0)
            .map(|(pk, info)| (*pk, info.hrw_routing_id))
            .collect()
    }

    /// Sets the persistent storage handle for atomic slashing evidence and ban commits.
    pub fn set_storage(&self, storage: std::sync::Weak<crate::storage::RedbStorage>) {
        let mut guard = self.storage.write();
        *guard = Some(storage);
    }

    /// Sets the dual-tier engine handle for immediate in-RAM ban containment.
    pub fn set_engine(&self, engine: &crate::storage::DualTierEngine) {
        let mut guard = self.engine_banned_nodes.write();
        *guard = Some(engine.banned_nodes.clone());
    }

    /// Observes a verified original attestation for equivocation / cartel detection (A10-02).
    ///
    /// If a differing original vote (`lock_a != lock_b`) is detected for the same `(signer_pubkey, parent_lock)`
    /// under `expected_network`, this automatically constructs `FraudProofPayload::new_shard_equivocation_with_pubkey`,
    /// atomically commits the slashing evidence and ban to storage (if available), bans the peer in RAM and PeerManager,
    /// broadcasts the fraud proof to all F2F friends, and returns `Some(proof)`.
    pub fn observe_verified_original_attestation(
        &self,
        signer_pubkey: [u8; 32],
        att: humoco_sim_core::types::Attestation,
        expected_network: humoco_sim_core::types::NetworkId,
    ) -> Option<humoco_sim_core::fraud::FraudProofPayload> {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&signer_pubkey) else {
            return None;
        };
        let shard = att.shard_id;
        let payload = humoco_sim_core::crypto::compute_attestation_payload_digest(
            &att.parent_lock,
            &att.lock_id,
        );
        let sig = match ed25519_dalek::Signature::from_slice(&att.signature) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let prov_domain = humoco_sim_core::crypto::domain_approve_prov(expected_network);
        let final_domain = humoco_sim_core::crypto::domain_approve_final(expected_network);
        let is_valid =
            [(prov_domain, 0u8), (final_domain, 1u8)]
                .into_iter()
                .any(|(domain, status)| {
                    let digest = humoco_sim_core::crypto::compute_sig_digest(
                        domain, 0, 0, 0, shard, status, &payload,
                    );
                    vk.verify_strict(&digest, &sig).is_ok()
                });
        if !is_valid {
            return None;
        }

        let mut cache = self.observed_votes.lock();
        match cache.insert_or_detect_equivocation(signer_pubkey, att.clone()) {
            Ok(()) => None,
            Err(prev_att) => {
                warn!(
                    offender = %hex::encode(signer_pubkey),
                    parent_lock = %hex::encode(att.parent_lock),
                    lock_a = %hex::encode(prev_att.lock_id),
                    lock_b = %hex::encode(att.lock_id),
                    "CRITICAL FRAUD: Conflicting original shard attestations detected! Automatic ShardEquivocation proof generated."
                );
                let proof =
                    humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
                        prev_att,
                        att,
                        signer_pubkey,
                    );
                if !crate::network::transport::verify_equivocation_first_party_network(
                    Some(expected_network),
                    &vk,
                    &proof,
                ) {
                    warn!("Generated ShardEquivocation self-proof failed first-party verification");
                    return None;
                }

                let proof_bytes = bincode::serialize(&proof).unwrap_or_default();
                let evidence_hash = *blake3::hash(&proof_bytes).as_bytes();
                let now_ms = self.net_time_ms();

                if let Some(storage) = self.storage.read().as_ref().and_then(|w| w.upgrade()) {
                    if let Err(e) = storage.commit_slashing_evidence_and_ban(
                        &evidence_hash,
                        &proof_bytes,
                        &signer_pubkey,
                        now_ms,
                    ) {
                        warn!("Failed to atomically commit slashing evidence and ban in redb: {e}");
                    }
                }

                if let Some(engine_banned) = self.engine_banned_nodes.read().as_ref().cloned() {
                    let pk = signer_pubkey;
                    tokio::spawn(async move {
                        engine_banned.write().await.insert(pk);
                    });
                }

                let pm = self.clone();
                let pk = signer_pubkey;
                tokio::spawn(async move {
                    pm.ban_node(&pk).await;
                });

                self.broadcast_fraud_proof(proof.clone());
                Some(proof)
            }
        }
    }

    /// Registers an active shard ID into the known shard inventory.
    pub async fn register_active_shard(&self, shard_id: u16) {
        let mut shards = self.known_active_shards.write().await;
        shards.insert(shard_id);
    }

    /// Returns a list of all known active shard IDs.
    pub async fn get_active_shards(&self) -> Vec<u16> {
        let shards = self.known_active_shards.read().await;
        shards.iter().copied().collect()
    }

    /// Checks if a heartbeat has already been seen; if not, records it. Returns true if new, false if duplicate or flooded.
    pub async fn check_and_record_heartbeat(
        &self,
        node_id: &[u8; 32],
        nonce: u64,
        timestamp_ms: u64,
    ) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(node_id);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&timestamp_ms.to_le_bytes());
        let id = *hasher.finalize().as_bytes();
        let mut guard = self.seen_heartbeats.write().await;
        guard.check_and_insert_slotted(id, *node_id, timestamp_ms)
    }

    /// Resolves all known socket addresses for a node identity (F2F slot,
    /// gossip-learned entry, and live peer entries). Used for fraud-proof
    /// echo protection: the immediate sender is never sent its own proof
    /// back. Sequential snapshots only — never holds two locks at once.
    pub async fn addrs_for_node_id(&self, node_id: &[u8; 32]) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        let friend_addr = {
            let friends = self.f2f_friends.read().await;
            friends.get(node_id).copied().flatten()
        };
        if let Some(a) = friend_addr {
            out.push(a);
        }
        let known_addr = {
            let known = self.known_network_nodes.read().await;
            known.get(node_id).map(|info| info.addr)
        };
        if let Some(a) = known_addr {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        let peer_addrs: Vec<SocketAddr> = {
            let peers = self.peers.read().await;
            peers
                .values()
                .filter(|p| p.node_id.as_ref() == Some(node_id))
                .map(|p| p.addr)
                .collect()
        };
        for a in peer_addrs {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }

    pub async fn set_fraud_proof_tx(&self, tx: tokio::sync::mpsc::Sender<FraudProofForwardMsg>) {
        let mut slot = self.fraud_proof_tx.write().await;
        *slot = Some(tx);
    }

    /// Computes the stable dedup hash for a fraud proof (BLAKE3 over the
    /// canonical bincode encoding, length-prefixed domain separation is
    /// provided by the payload structure itself).
    pub fn fraud_proof_dedup_hash(proof: &humoco_sim_core::fraud::FraudProofPayload) -> [u8; 32] {
        let bytes = bincode::serialize(proof).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Checks if a fraud proof was already forwarded; if not, records it.
    /// Returns true if new (should be forwarded), false if duplicate.
    pub async fn check_and_record_fraud_proof(&self, hash: &[u8; 32]) -> bool {
        let mut guard = self.seen_fraud_proofs.write().await;
        guard.check_and_insert(*hash)
    }

    /// Sync (non-blocking) variant for hot-path broadcast call sites that
    /// cannot await. Uses `try_write`; on contention the proof is treated
    /// as new (forwarded) to never suppress slashing under load.
    pub fn check_and_record_fraud_proof_sync(&self, hash: &[u8; 32]) -> bool {
        if let Ok(mut guard) = self.seen_fraud_proofs.try_write() {
            guard.check_and_insert(*hash)
        } else {
            true
        }
    }

    pub fn broadcast_fraud_proof(&self, proof: humoco_sim_core::fraud::FraudProofPayload) {
        self.broadcast_fraud_proof_with_sender(proof, None);
    }

    /// Queues a fraud proof for F2F broadcast, deduplicated via the LRU
    /// seen-set. `sender` is the immediate peer we received the proof from
    /// (if any) and is excluded on forward (echo protection happens in
    /// `QuicTransport::broadcast_equivocation_proof_to_f2f_except`).
    ///
    /// Phase 10: queueing itself never drops proofs (slashing must not be
    /// suppressed under lock contention). Dedup happens exactly once at the
    /// forward point (`broadcast_equivocation_proof_to_f2f_except`), so a
    /// pre-insert here would wrongly suppress every forward.
    pub fn broadcast_fraud_proof_with_sender(
        &self,
        proof: humoco_sim_core::fraud::FraudProofPayload,
        sender: Option<[u8; 32]>,
    ) {
        if let Ok(slot) = self.fraud_proof_tx.try_read() {
            if let Some(tx) = slot.as_ref() {
                let _ = tx.try_send((proof, sender));
            }
        }
    }

    /// Returns the shared Notify handle for triggering bootstrap/shard sync runs.
    pub fn sync_notifier(&self) -> Arc<tokio::sync::Notify> {
        self.sync_notify.clone()
    }

    /// Triggers an immediate or debounced sync run across listeners.
    pub fn notify_sync_trigger(&self) {
        self.sync_notify.notify_waiters();
    }

    /// Periodically re-resolves configured DNS hostname peers (every 10 minutes)
    /// and updates peer endpoints if the IP changed without disconnecting healthy peers unless suspended.
    ///
    /// Phase 10: lock decoupling — the `dns_peers` guard is never held
    /// across DNS I/O awaits nor while acquiring `peers`/`f2f_friends`.
    /// Snapshots are resolved first, mutations applied afterwards one lock
    /// at a time.
    pub async fn check_and_resolve_dns_peers(&self) {
        // Snapshot DNS entries without holding the guard across I/O.
        let snapshot: Vec<crate::config::PeerConfigEntry> = {
            let dns_guard = self.dns_peers.read().await;
            dns_guard.iter().map(|s| s.entry.clone()).collect()
        };
        // Resolve all hostnames without holding any manager lock.
        let mut resolved: Vec<(crate::config::PeerConfigEntry, Option<SocketAddr>)> =
            Vec::with_capacity(snapshot.len());
        for entry in snapshot {
            let endpoint = if entry.raw_endpoint.contains(':') {
                entry.raw_endpoint.clone()
            } else {
                format!("{}:9090", entry.raw_endpoint)
            };
            let new_addr_opt = match tokio::net::lookup_host(&endpoint).await {
                Ok(mut addrs) => addrs.next(),
                Err(err) => {
                    tracing::warn!(
                        endpoint = %entry.raw_endpoint,
                        error = %err,
                        "DNS re-resolution failed for peer; keeping existing address"
                    );
                    None
                }
            };
            resolved.push((entry, new_addr_opt));
        }
        // Apply mutations sequentially, one lock at a time.
        let mut changed = false;
        for (entry, new_addr_opt) in resolved {
            let Some(new_addr) = new_addr_opt else {
                continue;
            };
            let old_addr_opt = {
                let dns_guard = self.dns_peers.read().await;
                dns_guard
                    .iter()
                    .find(|s| {
                        s.entry.raw_endpoint == entry.raw_endpoint && s.entry.pubkey == entry.pubkey
                    })
                    .and_then(|s| s.current_addr)
            };
            if Some(new_addr) == old_addr_opt {
                continue;
            }
            tracing::info!(
                endpoint = %entry.raw_endpoint,
                old_addr = ?old_addr_opt,
                new_addr = %new_addr,
                "DNS peer address updated"
            );

            // If old address exists and is suspended, remove it; healthy peers remain connected
            if let Some(old_addr) = old_addr_opt {
                let is_suspended = {
                    let peers_guard = self.peers.read().await;
                    peers_guard
                        .get(&old_addr)
                        .map(|p| p.is_suspended())
                        .unwrap_or(false)
                };
                if is_suspended {
                    let mut peers_guard = self.peers.write().await;
                    peers_guard.remove(&old_addr);
                }
            }

            // Register/update new address as FriendToFriend peer
            {
                let mut peers_guard = self.peers.write().await;
                let info = peers_guard.entry(new_addr).or_insert_with(|| {
                    let mut p = PeerInfo::with_type(new_addr, PeerConnectionType::FriendToFriend);
                    p.node_id = entry.pubkey;
                    p
                });
                if info.node_id.is_none() && entry.pubkey.is_some() {
                    info.node_id = entry.pubkey;
                }
            }

            // Update f2f_friends mapping if pubkey is present
            if let Some(key) = entry.pubkey {
                {
                    let mut friends_guard = self.f2f_friends.write().await;
                    friends_guard.insert(key, Some(new_addr));
                }
                if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key) {
                    {
                        let mut keys = self.verifying_keys.write().await;
                        keys.insert(key, vk);
                    }
                }
            }

            {
                let mut dns_guard = self.dns_peers.write().await;
                if let Some(state) = dns_guard.iter_mut().find(|s| {
                    s.entry.raw_endpoint == entry.raw_endpoint && s.entry.pubkey == entry.pubkey
                }) {
                    state.current_addr = Some(new_addr);
                }
            }
            changed = true;
        }
        if changed {
            self.notify_sync_trigger();
        }
    }

    /// Returns a snapshot list of configured DNS peers with their current resolved addresses.
    pub async fn list_dns_peers(&self) -> Vec<DnsPeerState> {
        self.dns_peers.read().await.clone()
    }

    /// Dynamically registers a DNS peer entry for periodic re-resolution.
    pub async fn add_dns_peer(&self, entry: crate::config::PeerConfigEntry) {
        let mut dns_guard = self.dns_peers.write().await;
        dns_guard.push(DnsPeerState {
            entry,
            current_addr: None,
        });
        self.notify_sync_trigger();
    }

    /// Adds or registers a peer address if not already present.
    pub async fn add_peer(&self, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        let was_absent = !peers.contains_key(&addr);
        peers.entry(addr).or_insert_with(|| PeerInfo::new(addr));
        drop(peers);
        if was_absent {
            self.notify_sync_trigger();
        }
    }

    /// Removes a peer address from management.
    pub async fn remove_peer(&self, addr: &SocketAddr) -> bool {
        let mut peers = self.peers.write().await;
        if let Some(mut p) = peers.remove(addr) {
            if let Some(conn) = p.connection.take() {
                conn.close(0u32.into(), b"peer removed");
            }
            true
        } else {
            false
        }
    }

    /// Removes a peer by public key or address/hostname.
    /// Returns the pubkey in hex if available, or the removed address representation.
    pub async fn remove_peer_by_spec(
        &self,
        key_opt: Option<[u8; 32]>,
        endpoint_opt: Option<&str>,
    ) -> Option<String> {
        let mut removed_pubkey = None;

        // 1. If key is known, remove from f2f_friends and known_network_nodes
        // Phase 10: decoupled — never hold both write guards at once.
        if let Some(ref key) = key_opt {
            removed_pubkey = Some(hex::encode(key));
            {
                let mut friends = self.f2f_friends.write().await;
                friends.remove(key);
            }
            {
                let mut known = self.known_network_nodes.write().await;
                known.remove(key);
            }
        }

        // 2. Remove matching peer from peers map
        let mut target_addrs = Vec::new();
        if let Some(endpoint) = endpoint_opt {
            if let Ok(addr) = endpoint.parse::<SocketAddr>() {
                target_addrs.push(addr);
            }
        }

        {
            let mut peers = self.peers.write().await;
            // Also find addrs by key
            if let Some(ref key) = key_opt {
                for (addr, p) in peers.iter() {
                    if p.node_id.as_ref() == Some(key) && !target_addrs.contains(addr) {
                        target_addrs.push(*addr);
                    }
                }
            }

            for addr in target_addrs {
                if let Some(mut p) = peers.remove(&addr) {
                    if let Some(conn) = p.connection.take() {
                        conn.close(0u32.into(), b"peer removed");
                    }
                    if removed_pubkey.is_none() {
                        if let Some(nid) = p.node_id {
                            removed_pubkey = Some(hex::encode(nid));
                        }
                    }
                }
            }
        }

        // 3. Remove from dns_peers
        {
            let mut dns = self.dns_peers.write().await;
            dns.retain(|entry| {
                if let Some(ref key) = key_opt {
                    if entry.entry.pubkey.as_ref() == Some(key) {
                        return false;
                    }
                }
                if let Some(endpoint) = endpoint_opt {
                    if entry.entry.raw_endpoint == endpoint {
                        return false;
                    }
                }
                true
            });
        }

        // 4. Revoke clock sample for removed key
        if let Some(ref key) = key_opt {
            self.clock.revoke_peer_sample(key);
        } else if let Some(ref hex_key) = removed_pubkey {
            if let Ok(bytes) = hex::decode(hex_key) {
                if let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    let mut friends = self.f2f_friends.write().await;
                    friends.remove(&array);
                    drop(friends);
                    self.clock.revoke_peer_sample(&array);
                }
            }
        }

        removed_pubkey
    }

    /// Gets a snapshot copy of a peer's info.
    pub async fn get_peer(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.get(addr).cloned()
    }

    /// Returns a list of snapshots for all registered peers.
    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Records a successful QUIC/TLS handshake with a peer.
    ///
    /// Phase 8 (Spec 15/19): a pure handshake MUST NOT reset the Tit-for-Tat
    /// error malus (`missing_count`). It only refreshes identity, connection
    /// handle and last-seen timestamp. The malus decays exclusively via
    /// genuinely performed shard work (`record_shard_work`) or the hourly
    /// autonomous healing (`decay_all_peers`).
    pub async fn record_success(
        &self,
        addr: SocketAddr,
        node_id: Option<[u8; 32]>,
        conn: Option<quinn::Connection>,
    ) {
        let is_friend = if let Some(ref id) = node_id {
            self.is_f2f_friend(id).await
        } else {
            self.is_f2f_addr(&addr).await
        };

        let conn_type = if is_friend {
            PeerConnectionType::FriendToFriend
        } else if let Some(ref id) = node_id {
            if self.is_known_node(id).await {
                PeerConnectionType::ShardDirect
            } else {
                PeerConnectionType::Untrusted
            }
        } else if self.is_known_addr(&addr).await {
            PeerConnectionType::ShardDirect
        } else {
            PeerConnectionType::Untrusted
        };

        let was_connected = {
            let peers = self.peers.read().await;
            peers.get(&addr).map(|p| p.is_connected()).unwrap_or(false)
        };

        let mut peers = self.peers.write().await;
        let entry = peers
            .entry(addr)
            .or_insert_with(|| PeerInfo::with_type(addr, conn_type));
        entry.conn_type = conn_type;
        entry.mark_success(node_id, conn);
        drop(peers);

        if !was_connected {
            self.notify_sync_trigger();
        }
    }

    /// Records genuinely performed shard work (valid attestation, sync payload,
    /// verified lock) for a peer. This is the ONLY interaction path (besides
    /// hourly `decay_all_peers`) that decays the Tit-for-Tat error malus
    /// (`missing_count -1`, activity-locked healing per Spec 19).
    pub async fn record_shard_work(&self, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(&addr) {
            peer.mark_shard_work_success();
        }
    }

    /// Records genuinely performed shard work by permanent node identity.
    /// Resolves all peer entries carrying this `node_id` (address-agnostic,
    /// NAT-safe) and decays each malus by 1. Returns the number of entries.
    pub async fn record_shard_work_by_id(&self, node_id: &[u8; 32]) -> usize {
        let mut peers = self.peers.write().await;
        let mut count = 0usize;
        for peer in peers.values_mut() {
            if peer.node_id.as_ref() == Some(node_id) {
                peer.mark_shard_work_success();
                count += 1;
            }
        }
        count
    }

    /// Notes a graceful / idle connection close (Tier-2 15s idle timeout,
    /// QUIC `CONNECTION_CLOSE`, orderly shutdown) WITHOUT touching the
    /// Tit-for-Tat malus. Idle timeouts are the normal state of the ephemeral
    /// Tier-2 LRU pool (TODO-ARCH-02) and must NEVER call `record_failure`.
    pub async fn note_idle_close(&self, addr: &SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(addr) {
            peer.clear_connection_preserve_malus();
        }
    }

    /// Clears only the exact session that ended, preserving a replacement and malus.
    pub async fn note_connection_closed(&self, addr: &SocketAddr, stable_id: usize) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(addr) {
            if peer
                .connection
                .as_ref()
                .is_some_and(|conn| conn.stable_id() == stable_id)
            {
                peer.clear_connection_preserve_malus();
            }
        }
    }

    /// Bulk-imports permanently banned node identities (e.g. persisted bans
    /// from redb at boot). Insert-only: never touches connections or gossip
    /// state beyond the ban set. Returns the number of newly added bans.
    pub async fn import_persisted_bans(&self, banned: &[[u8; 32]]) -> usize {
        if banned.is_empty() {
            return 0;
        }
        let mut guard = self.banned_nodes.write().await;
        let mut added = 0usize;
        for key in banned {
            if guard.insert(*key) {
                added += 1;
            }
        }
        added
    }

    /// Checks whether a peer address is currently under local temporary work
    /// suspension (Tit-for-Tat, `missing_count >= 3`). Suspended peers are
    /// refused on Shard-Direct RPC until genuine shard work or hourly decay
    /// rehabilitates them.
    pub async fn is_peer_suspended_by_addr(&self, addr: &SocketAddr) -> bool {
        let peers = self.peers.read().await;
        peers.get(addr).map(|p| p.is_suspended()).unwrap_or(false)
    }

    /// Checks whether a permanent node identity is currently under local
    /// temporary work suspension (address-agnostic, NAT-safe).
    pub async fn is_peer_suspended_by_id(&self, node_id: &[u8; 32]) -> bool {
        let peers = self.peers.read().await;
        peers
            .values()
            .any(|p| p.node_id.as_ref() == Some(node_id) && p.is_suspended())
    }

    /// Registers an explicit direct F2F friend.
    /// F2F friendship is strictly bound to permanent Ed25519 NodePubKey.
    ///
    /// Phase 10 (Deadlock-Fix): strict lock hierarchy — each map lock is
    /// acquired, mutated, and dropped before the next one is taken. Never
    /// holds `f2f_friends` while acquiring `peers`/`verifying_keys`.
    pub async fn register_f2f_friend(&self, node_id: [u8; 32], addr: Option<SocketAddr>) {
        {
            let mut friends = self.f2f_friends.write().await;
            friends.insert(node_id, addr);
        }
        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&node_id) {
            {
                let mut keys = self.verifying_keys.write().await;
                keys.insert(node_id, vk);
            }
        }
        if let Some(a) = addr {
            let mut peers = self.peers.write().await;
            let entry = peers
                .entry(a)
                .or_insert_with(|| PeerInfo::with_type(a, PeerConnectionType::FriendToFriend));
            entry.node_id = Some(node_id);
            entry.conn_type = PeerConnectionType::FriendToFriend;
        }
        self.notify_sync_trigger();
    }

    /// Adds a trusted F2F peer by its Ed25519 public key.
    /// Inserts into trusted F2F friends and updates peer connection status if already known.
    ///
    /// Phase 10 (Deadlock-Fix): lock decoupling — snapshot what is needed,
    /// drop each guard before taking the next lock. No nested holding.
    pub async fn add_trusted_f2f_peer(&self, pubkey: [u8; 32]) {
        let existing_addr = {
            let friends = self.f2f_friends.read().await;
            friends.get(&pubkey).copied().flatten()
        };
        {
            let mut friends = self.f2f_friends.write().await;
            friends.entry(pubkey).or_insert(existing_addr);
        }

        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pubkey) {
            {
                let mut keys = self.verifying_keys.write().await;
                keys.insert(pubkey, vk);
            }
        }

        // If this node is known in known_network_nodes, resolve its address
        let known_addr = {
            let known = self.known_network_nodes.read().await;
            known.get(&pubkey).map(|info| info.addr)
        };

        if let Some(addr) = known_addr.or(existing_addr) {
            {
                let mut friends = self.f2f_friends.write().await;
                friends.insert(pubkey, Some(addr));
            }
            {
                let mut peers = self.peers.write().await;
                let entry = peers.entry(addr).or_insert_with(|| {
                    PeerInfo::with_type(addr, PeerConnectionType::FriendToFriend)
                });
                entry.node_id = Some(pubkey);
                entry.conn_type = PeerConnectionType::FriendToFriend;
            }
        } else {
            // Check if any peer has matching node_id — collect first, mutate after.
            let matched_addr = {
                let peers = self.peers.read().await;
                peers
                    .iter()
                    .find(|(_, peer)| peer.node_id == Some(pubkey))
                    .map(|(addr, _)| *addr)
            };
            if let Some(addr) = matched_addr {
                {
                    let mut peers = self.peers.write().await;
                    if let Some(peer) = peers.get_mut(&addr) {
                        peer.conn_type = PeerConnectionType::FriendToFriend;
                    }
                }
                {
                    let mut friends = self.f2f_friends.write().await;
                    friends.insert(pubkey, Some(addr));
                }
            }
        }
        self.notify_sync_trigger();
    }

    /// Removes a trusted F2F peer by its Ed25519 public key.
    ///
    /// Phase 10 (Deadlock-Fix): sequential lock acquisition, never nested.
    pub async fn remove_trusted_f2f_peer(&self, pubkey: &[u8; 32]) {
        {
            let mut friends = self.f2f_friends.write().await;
            friends.remove(pubkey);
        }

        if ed25519_dalek::VerifyingKey::from_bytes(pubkey).is_ok() {
            {
                let mut keys = self.verifying_keys.write().await;
                keys.remove(pubkey);
            }
        }

        let mut peers = self.peers.write().await;
        for peer in peers.values_mut() {
            if peer.node_id.as_ref() == Some(pubkey) {
                peer.conn_type = PeerConnectionType::ShardDirect;
            }
        }
        drop(peers);
        self.clock.revoke_peer_sample(pubkey);
        self.notify_sync_trigger();
    }

    /// Checks if a given node_id is an authorized direct F2F friend.
    /// Based strictly on permanent NodePubKey / NodeId, not on HRW ticket.
    pub async fn is_f2f_friend(&self, node_id: &[u8; 32]) -> bool {
        let friends = self.f2f_friends.read().await;
        friends.contains_key(node_id)
    }

    /// Checks if a socket address belongs to a configured direct F2F friend.
    ///
    /// Phase 10 (Deadlock-Fix): strict lock decoupling — the `peers` read
    /// guard is always dropped before `f2f_friends` is acquired. No nested
    /// lock holding, so the AB-BA inversion vs `register_f2f_friend`
    /// (`f2f_friends` -> `peers`) is impossible.
    pub async fn is_f2f_addr(&self, addr: &SocketAddr) -> bool {
        let is_friend_peer = {
            let peers = self.peers.read().await;
            peers
                .get(addr)
                .map(|peer| peer.conn_type == PeerConnectionType::FriendToFriend)
                .unwrap_or(false)
        };
        if is_friend_peer {
            return true;
        }
        let friends = self.f2f_friends.read().await;
        for opt_addr in friends.values() {
            if opt_addr.as_ref() == Some(addr) {
                return true;
            }
        }
        false
    }

    /// Returns true if the node's own shard ticket was reported as outdated by an F2F peer.
    pub fn is_ticket_outdated(&self) -> bool {
        self.ticket_outdated
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Sets the outdated status of the node's own shard ticket.
    pub fn set_ticket_outdated(&self, outdated: bool) {
        self.ticket_outdated
            .store(outdated, std::sync::atomic::Ordering::Relaxed);
    }

    /// Calculates the decentralized median PoW work score across all active (mature) known nodes.
    /// Defaults to W_min_floor (256 in production, 1 in simulation) if no active nodes are known (Bootstrap N <= 1).
    pub fn calculate_network_median_work(&self) -> u64 {
        let mut works = Vec::new();
        if let Ok(known) = self.known_network_nodes.try_read() {
            for entry in known.values() {
                if !entry.is_immature() {
                    works.push(entry.work_score);
                }
            }
        }
        let floor = self.effective_min_work_floor();
        if works.is_empty() {
            return floor;
        }
        works.sort_unstable();
        let n = works.len();
        let median = if n % 2 == 1 {
            works[n / 2]
        } else {
            (works[n / 2 - 1] + works[n / 2]) / 2
        };
        median.max(floor)
    }

    /// Evaluates if a given work score satisfies the network admission threshold (1/8 = 12.5% of median).
    /// Returns (is_acceptable, current_median).
    pub fn is_ticket_acceptable(&self, work: u64) -> (bool, u64) {
        let median = self.calculate_network_median_work();
        let floor = self.effective_min_work_floor();
        let min_admission = floor.max(median >> 3);
        let is_valid = work >= min_admission;
        (is_valid, median)
    }

    // -------------------------------------------------------------------------
    // Semantic Decoupling & 24h Incubation (Spec 07)
    // -------------------------------------------------------------------------

    /// Internal promotion check: If pending >= incubation_duration, it becomes active.
    async fn maybe_promote_pending(&self, node_pubkey: &[u8; 32]) {
        let incubation = self.effective_incubation_duration();
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(node_pubkey) {
            entry.incubation_duration = incubation;
            if let (Some(pending), Some(since)) =
                (entry.pending_hrw_routing_id, entry.pending_since)
            {
                if since.elapsed() >= incubation {
                    entry.hrw_routing_id = pending;
                    if let Some(pw) = entry.pending_work_score {
                        entry.work_score = pw;
                    }
                    entry.pending_hrw_routing_id = None;
                    entry.pending_work_score = None;
                    entry.pending_since = None;
                    entry.incubated_until = None;
                }
            }
        }
    }

    /// Learns or updates a node discovered through F2F gossip.
    /// Legacy wrapper: hrw_routing_id == node_pubkey (fast-path) for backward compatibility.
    pub async fn learn_node_from_gossip(
        &self,
        node_id: [u8; 32],
        addr: SocketAddr,
        hops: u8,
        ingress_peer: Option<SocketAddr>,
    ) {
        self.learn_node_from_gossip_with_hrw(node_id, node_id, addr, hops, ingress_peer)
            .await;
    }

    /// Semantically decoupled learning method with explicit HRW routing ticket (defaults to work_score = 1).
    pub async fn learn_node_from_gossip_with_hrw(
        &self,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        addr: SocketAddr,
        hops: u8,
        ingress_peer: Option<SocketAddr>,
    ) {
        self.learn_node_from_gossip_with_hrw_and_work(
            node_pubkey,
            hrw_routing_id,
            addr,
            hops,
            ingress_peer,
            1,
        )
        .await;
    }

    /// Semantically decoupled learning method with explicit HRW routing ticket and work score.
    /// Enforces:
    /// 1. Minimum admission threshold: work_score >= max(W_min_floor, W_median >> 3).
    /// 2. Monotonicity Ratchet: On existing nodes, work_score MUST be strictly greater than max(W_active, W_pending).
    pub async fn learn_node_from_gossip_with_hrw_and_work(
        &self,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        addr: SocketAddr,
        hops: u8,
        ingress_peer: Option<SocketAddr>,
        work_score: u64,
    ) {
        self.learn_node_from_gossip_with_hrw_work_and_auth(
            node_pubkey,
            hrw_routing_id,
            addr,
            hops,
            ingress_peer,
            work_score,
            hops == 0,
        )
        .await;
    }

    /// Extended variant that accepts an explicit origin authorization flag.
    /// Relayed gossip (`hops > 0`) cannot overwrite an existing address unless `origin_authorized` is true.
    #[allow(clippy::too_many_arguments)]
    pub async fn learn_node_from_gossip_with_hrw_work_and_auth(
        &self,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        addr: SocketAddr,
        hops: u8,
        ingress_peer: Option<SocketAddr>,
        work_score: u64,
        origin_authorized: bool,
    ) {
        let (is_acceptable, _median) = self.is_ticket_acceptable(work_score);
        if !is_acceptable {
            return;
        }

        let is_shortcut = hrw_routing_id == *blake3::hash(&node_pubkey).as_bytes()
            || hrw_routing_id == node_pubkey
            || hrw_routing_id == [0u8; 32]
            || work_score == 0;
        if !self.is_simulation_mode() && is_shortcut {
            warn!(
                node = %hex::encode(node_pubkey),
                "GOSSIP BARRIER: Rejected unmined shortcut ticket in production"
            );
            return;
        }

        let incubation = self.effective_incubation_duration();
        let prior_age = self
            .persisted_ticket_ages
            .lock()
            .get(&(node_pubkey, hrw_routing_id))
            .copied()
            .unwrap_or(Duration::ZERO);

        let now = Instant::now();
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(&node_pubkey) {
            entry.incubation_duration = incubation;
            if entry.addr.port() == 0 && entry.work_score == 0 {
                // Upgrade evidence-only placeholder to real gossiped ticket
                entry.hrw_routing_id = hrw_routing_id;
                entry.work_score = work_score;
                entry.pre_boot_age = prior_age;
                entry.first_seen = now;
                entry.latest_obs_hour = None;
                entry.obs_24h_mask = 0;
                entry.initial_admission_qualified = false;
            }
            // Promotion if due, before inspecting new value
            if let (Some(pending), Some(since)) =
                (entry.pending_hrw_routing_id, entry.pending_since)
            {
                if since.elapsed() >= incubation {
                    entry.hrw_routing_id = pending;
                    if let Some(pw) = entry.pending_work_score {
                        entry.work_score = pw;
                    }
                    entry.pending_hrw_routing_id = None;
                    entry.pending_work_score = None;
                    entry.pending_since = None;
                    entry.incubated_until = None;
                    entry.latest_obs_hour = None;
                    entry.obs_24h_mask = 0;
                    entry.initial_admission_qualified = false;
                }
            }
            // Protect direct or stronger addresses from unauthorized relay downgrade:
            // An address overwrite from a relay (hops > 0) is only permitted if origin_authorized is true.
            if entry.addr != addr {
                if hops > 0 && !origin_authorized {
                    warn!(
                        node = %hex::encode(node_pubkey),
                        hops,
                        existing = %entry.addr,
                        attempted = %addr,
                        "GOSSIP BARRIER: Rejected unauthorized address overwrite from relay"
                    );
                } else {
                    entry.addr = addr;
                    if hops <= entry.min_hops || origin_authorized {
                        entry.min_hops = hops;
                    }
                }
            }
            entry.last_seen = now;

            if entry.hrw_routing_id != hrw_routing_id {
                // Monotonicity Ratchet: W_new MUST be strictly greater than max(W_active, W_pending)
                let current_max = entry.work_score.max(entry.pending_work_score.unwrap_or(0));
                if work_score > current_max {
                    entry.pending_hrw_routing_id = Some(hrw_routing_id);
                    entry.pending_work_score = Some(work_score);
                    entry.pending_since = Some(now);
                    entry.incubated_until = Some(now + incubation);
                }
                // If work_score <= current_max: Downgrade or lateral hop -> REJECTED, old active & pending remain!
            }
            if hops < entry.min_hops {
                entry.min_hops = hops;
                if let Some(peer) = ingress_peer {
                    entry.best_ingress_peer = Some(peer);
                }
            }
            if let Some(peer) = ingress_peer {
                let hash = blake3::hash(peer.to_string().as_bytes());
                let hb = hash.as_bytes();
                let val = u32::from_le_bytes([hb[0], hb[1], hb[2], hb[3]]);
                let bit = 1 << (val % 32);
                entry.ingress_diversity_mask |= bit;
            }
        } else {
            let mut mask = 0;
            if let Some(peer) = ingress_peer {
                let hash = blake3::hash(peer.to_string().as_bytes());
                let hb = hash.as_bytes();
                let val = u32::from_le_bytes([hb[0], hb[1], hb[2], hb[3]]);
                mask = 1 << (val % 32);
            }
            // Newcomer: IMMATURE phase starts unless restored from persisted maturation history
            nodes.insert(
                node_pubkey,
                KnownNodeInfo {
                    addr,
                    node_pubkey,
                    hrw_routing_id,
                    work_score,
                    pending_hrw_routing_id: None,
                    pending_work_score: None,
                    pending_since: None,
                    incubated_until: None,
                    first_seen: now,
                    pre_boot_age: prior_age,
                    incubation_duration: incubation,
                    last_seen: now,
                    min_hops: hops,
                    edge_observations: HashMap::new(),
                    best_ingress_peer: ingress_peer,
                    ingress_diversity_mask: mask,
                    latest_obs_hour: None,
                    obs_24h_mask: 0,
                    initial_admission_qualified: prior_age >= incubation,
                    last_write_evidence: None,
                    last_read_evidence: None,
                },
            );
            drop(nodes);
            self.notify_sync_trigger();
        }
    }

    /// Alias for re-mining / routing ticket update (Spec 07: `HrwRoutingIdMigrationNotice`).
    /// Semantics identical to `learn_node_from_gossip_with_hrw` — new tickets incubate for 24h.
    pub async fn update_routing_ticket(
        &self,
        node_pubkey: [u8; 32],
        new_hrw_routing_id: [u8; 32],
        addr: SocketAddr,
    ) {
        self.learn_node_from_gossip_with_hrw_and_work(
            node_pubkey,
            new_hrw_routing_id,
            addr,
            0,
            None,
            1,
        )
        .await;
    }

    /// Re-mining ticket update with explicit work score.
    pub async fn update_routing_ticket_with_work(
        &self,
        node_pubkey: [u8; 32],
        new_hrw_routing_id: [u8; 32],
        addr: SocketAddr,
        work_score: u64,
    ) {
        self.learn_node_from_gossip_with_hrw_and_work(
            node_pubkey,
            new_hrw_routing_id,
            addr,
            0,
            None,
            work_score,
        )
        .await;
    }

    /// Alias: upsert_known_node — for evaluator compatibility.
    pub async fn upsert_known_node(
        &self,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        addr: SocketAddr,
    ) {
        self.learn_node_from_gossip_with_hrw(node_pubkey, hrw_routing_id, addr, 0, None)
            .await;
    }

    /// Alias: handle_migration / on_node_id_migration
    pub async fn handle_node_id_migration(
        &self,
        node_pubkey: [u8; 32],
        new_hrw_routing_id: [u8; 32],
        addr: SocketAddr,
    ) {
        self.learn_node_from_gossip_with_hrw(node_pubkey, new_hrw_routing_id, addr, 0, None)
            .await;
    }

    /// Returns the effective HRW routing ticket for HRW scoring.
    /// During 24h incubation, the old ticket is used; thereafter the new one.
    /// For IMMATURE (<24h since first_seen), the active ticket is still returned,
    /// but `is_hrw_eligible` signals IMMATURE (no voting weight).
    pub async fn get_effective_hrw_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.maybe_promote_pending(node_pubkey).await;
        let nodes = self.known_network_nodes.read().await;
        nodes.get(node_pubkey).map(|e| e.hrw_routing_id)
    }

    /// Alias shorthand forms for evaluator compatibility
    pub async fn get_hrw_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }
    pub async fn get_active_hrw_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }
    pub async fn hrw_for_node(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }

    pub async fn get_ingress_diversity_data(&self) -> Vec<(Option<SocketAddr>, u32)> {
        let nodes = self.known_network_nodes.read().await;
        nodes
            .values()
            .map(|n| (n.best_ingress_peer, n.ingress_diversity_mask))
            .collect()
    }
    pub async fn effective_hrw_for_scoring(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }
    pub async fn get_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }

    /// Finds a node's permanent NodePubKey given its active HRW routing ticket.
    pub async fn get_pubkey_by_hrw_routing_id(&self, hrw_id: &[u8; 32]) -> Option<[u8; 32]> {
        {
            let nodes = self.known_network_nodes.read().await;
            if let Some(pk) = nodes
                .values()
                .find(|info| &info.hrw_routing_id == hrw_id)
                .map(|info| info.node_pubkey)
            {
                return Some(pk);
            }
            // A known identity with another ticket must not regain the
            // bootstrap routing id through the friendship fallback.
            if nodes.contains_key(hrw_id) {
                return None;
            }
        }
        // Direct authenticated friends bootstrap with routing id = public
        // key before their first topology announcement. Preserve read/sync
        // targets without accepting arbitrary unknown routing ids.
        self.f2f_friends
            .read()
            .await
            .contains_key(hrw_id)
            .then_some(*hrw_id)
    }

    /// Returns pending ticket if present (still incubating).
    pub async fn get_pending_hrw_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        let nodes = self.known_network_nodes.read().await;
        nodes
            .get(node_pubkey)
            .and_then(|e| e.pending_hrw_routing_id)
    }

    /// Checks if node is still IMMATURE (<24h since first contact).
    pub async fn is_immature(&self, node_pubkey: &[u8; 32]) -> bool {
        let nodes = self.known_network_nodes.read().await;
        if let Some(entry) = nodes.get(node_pubkey) {
            entry.is_immature()
        } else {
            false
        }
    }

    /// Checks if node is HRW-eligible (ACTIVE, not IMMATURE).
    pub async fn is_hrw_eligible(&self, node_pubkey: &[u8; 32]) -> bool {
        let nodes = self.known_network_nodes.read().await;
        if let Some(entry) = nodes.get(node_pubkey) {
            entry.is_hrw_eligible()
        } else {
            false
        }
    }

    pub async fn hrw_eligible(&self, node_pubkey: &[u8; 32]) -> bool {
        self.is_hrw_eligible(node_pubkey).await
    }

    /// Remaining incubation time until pending active (or IMMATURE end).
    pub async fn hrw_incubation_remaining(&self, node_pubkey: &[u8; 32]) -> Option<Duration> {
        let nodes = self.known_network_nodes.read().await;
        if let Some(entry) = nodes.get(node_pubkey) {
            if entry.pending_since.is_some() {
                return entry.pending_remaining();
            }
            if entry.is_immature() {
                let elapsed = entry.observed_age();
                if elapsed < entry.incubation_duration {
                    return Some(entry.incubation_duration - elapsed);
                }
            }
        }
        None
    }

    /// Returns full KnownNodeInfo (including 24h state) for inspection / telemetry.
    pub async fn get_known_node_info(&self, node_pubkey: &[u8; 32]) -> Option<KnownNodeInfo> {
        let nodes = self.known_network_nodes.read().await;
        nodes.get(node_pubkey).cloned()
    }

    /// Alias for get_known_node_info
    pub async fn known_node_info(&self, node_pubkey: &[u8; 32]) -> Option<KnownNodeInfo> {
        self.get_known_node_info(node_pubkey).await
    }

    /// Manual promotion of all mature pending tickets (e.g., periodically from daemon).
    pub async fn promote_mature_pending_hrw(&self) -> usize {
        let incubation = self.effective_incubation_duration();
        let mut promoted = 0usize;
        let mut nodes = self.known_network_nodes.write().await;
        let now = Instant::now();
        for entry in nodes.values_mut() {
            entry.incubation_duration = incubation;
            if let (Some(pending), Some(since)) =
                (entry.pending_hrw_routing_id, entry.pending_since)
            {
                if now.duration_since(since) >= incubation {
                    entry.hrw_routing_id = pending;
                    if let Some(pw) = entry.pending_work_score {
                        entry.work_score = pw;
                    }
                    entry.pending_hrw_routing_id = None;
                    entry.pending_work_score = None;
                    entry.pending_since = None;
                    entry.incubated_until = None;
                    promoted += 1;
                }
            }
        }
        promoted
    }

    /// For tests: set work_score manually.
    pub async fn set_work_score_for_test(&self, node_pubkey: &[u8; 32], work_score: u64) {
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(node_pubkey) {
            entry.work_score = work_score;
        }
    }

    /// For tests: set first_seen / pending_since manually (simulates 24h head start).
    pub async fn set_first_seen_for_test(&self, node_pubkey: &[u8; 32], first_seen: Instant) {
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(node_pubkey) {
            entry.first_seen = first_seen;
        }
    }

    pub async fn set_pending_since_for_test(&self, node_pubkey: &[u8; 32], since: Instant) {
        let incubation = self.effective_incubation_duration();
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(node_pubkey) {
            entry.pending_since = Some(since);
            entry.incubated_until = Some(since + incubation);
        }
    }

    /// Checks if a node_id is known (either as an F2F friend or learned via F2F gossip).
    /// F2F check is strictly based on the permanent NodePubKey / NodeId, not the HRW ticket.
    pub async fn is_known_node(&self, node_id: &[u8; 32]) -> bool {
        if self.is_f2f_friend(node_id).await {
            return true;
        }
        let nodes = self.known_network_nodes.read().await;
        nodes.contains_key(node_id)
    }

    /// Checks if a socket address belongs to a node known via F2F gossip.
    pub async fn is_known_addr(&self, addr: &SocketAddr) -> bool {
        let nodes = self.known_network_nodes.read().await;
        nodes.values().any(|k| &k.addr == addr)
    }

    /// Resolves the socket address of a known node (F2F or gossip-learned).
    pub async fn get_known_node_addr(&self, node_id: &[u8; 32]) -> Option<SocketAddr> {
        {
            let friends = self.f2f_friends.read().await;
            if let Some(Some(addr)) = friends.get(node_id) {
                return Some(*addr);
            }
        }
        let nodes = self.known_network_nodes.read().await;
        nodes.get(node_id).map(|k| k.addr)
    }

    /// Collects a comprehensive list of all known nodes in the network for the Node Explorer dashboard.
    pub async fn get_network_nodes_explorer(
        &self,
        local_pubkey: &[u8; 32],
        local_addr: Option<SocketAddr>,
        local_hrw: [u8; 32],
    ) -> Vec<NetworkNodeDto> {
        let mut map: HashMap<[u8; 32], NetworkNodeDto> = HashMap::new();
        // Phase 10: snapshot each map sequentially and drop the guard before
        // taking the next lock — never holds 4 read guards at once.
        let banned: HashSet<[u8; 32]> = self.banned_nodes.read().await.clone();
        let friends: HashMap<[u8; 32], Option<SocketAddr>> = self.f2f_friends.read().await.clone();
        let peers: HashMap<SocketAddr, PeerInfo> = self.peers.read().await.clone();
        let known: HashMap<[u8; 32], KnownNodeInfo> = self.known_network_nodes.read().await.clone();

        // 1. Add Local Node
        let local_addr_str = local_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "127.0.0.1:9090".to_string());
        map.insert(
            *local_pubkey,
            NetworkNodeDto {
                node_id: bs58::encode(local_pubkey).into_string(),
                public_key: bs58::encode(local_pubkey).into_string(),
                address: local_addr_str,
                is_f2f: false,
                is_local: true,
                connection_status: "Local Node (Self)".to_string(),
                min_hops: 0,
                hrw_routing_id: bs58::encode(local_hrw).into_string(),
                work_score: 1,
                is_immature: false,
                pending_ticket: None,
                incubation_remaining_sec: None,
                missing_count: 0,
                last_failure_sec: None,
                rtt_ms: Some(0),
                best_ingress_peer: None,
            },
        );

        // 2. Add F2F Friends & configured peers
        for (friend_id, friend_addr_opt) in friends.iter() {
            if friend_id == local_pubkey {
                continue;
            }
            let is_banned = banned.contains(friend_id);
            let info_opt = known.get(friend_id);

            let resolved_addr = friend_addr_opt.or_else(|| info_opt.map(|k| k.addr));
            let addr_str = resolved_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            let peer_opt = resolved_addr.and_then(|addr| peers.get(&addr));
            let missing_count = peer_opt.map(|p| p.missing_count).unwrap_or(0);
            let last_failure_sec =
                peer_opt.and_then(|p| p.last_failure.map(|t| t.elapsed().as_secs()));
            let rtt_ms =
                peer_opt.and_then(|p| p.connection.as_ref().map(|c| c.rtt().as_millis() as u32));

            let status_str = if is_banned {
                "Banned (Equivocation)".to_string()
            } else if let Some(p) = peer_opt {
                match p.status {
                    PeerStatus::Connected => "Connected (F2F Friend)".to_string(),
                    PeerStatus::Degrading => format!("Degrading ({}/3)", p.missing_count),
                    PeerStatus::Suspended => "Suspended (3/3)".to_string(),
                }
            } else {
                "Configured (F2F Friend)".to_string()
            };

            let hrw = info_opt.map(|k| k.hrw_routing_id).unwrap_or(*friend_id);
            let work = info_opt.map(|k| k.work_score).unwrap_or(1);
            let is_im = info_opt.map(|k| k.is_immature()).unwrap_or(false);
            let pending_bs58 = info_opt.and_then(|k| {
                k.pending_hrw_routing_id
                    .map(|t| bs58::encode(&t).into_string())
            });
            let rem_sec = info_opt.and_then(|k| k.pending_remaining().map(|d| d.as_secs()));
            let min_hops = info_opt.map(|k| k.min_hops.max(1)).unwrap_or(1);
            let best_ingress_peer =
                info_opt.and_then(|k| k.best_ingress_peer.map(|a| a.to_string()));

            map.insert(
                *friend_id,
                NetworkNodeDto {
                    node_id: bs58::encode(friend_id).into_string(),
                    public_key: bs58::encode(friend_id).into_string(),
                    address: addr_str,
                    is_f2f: true,
                    is_local: false,
                    connection_status: status_str,
                    min_hops,
                    hrw_routing_id: bs58::encode(&hrw).into_string(),
                    work_score: work,
                    is_immature: is_im,
                    pending_ticket: pending_bs58,
                    incubation_remaining_sec: rem_sec,
                    missing_count,
                    last_failure_sec,
                    rtt_ms,
                    best_ingress_peer,
                },
            );
        }

        // 3. Add Gossip-learned Known Nodes (non-friends)
        for (node_pubkey, info) in known.iter() {
            if node_pubkey == local_pubkey || friends.contains_key(node_pubkey) {
                continue;
            }
            let is_banned = banned.contains(node_pubkey);
            let peer_opt = peers.get(&info.addr);
            let missing_count = peer_opt.map(|p| p.missing_count).unwrap_or(0);
            let last_failure_sec =
                peer_opt.and_then(|p| p.last_failure.map(|t| t.elapsed().as_secs()));
            let rtt_ms =
                peer_opt.and_then(|p| p.connection.as_ref().map(|c| c.rtt().as_millis() as u32));

            let status_str = if is_banned {
                "Banned (Equivocation)".to_string()
            } else if let Some(p) = peer_opt {
                match p.status {
                    PeerStatus::Connected => "Connected (Shard Direct)".to_string(),
                    PeerStatus::Degrading => format!("Degrading ({}/3)", p.missing_count),
                    PeerStatus::Suspended => "Suspended (3/3)".to_string(),
                }
            } else {
                "Learned via Gossip".to_string()
            };

            let pending_bs58 = info
                .pending_hrw_routing_id
                .map(|t| bs58::encode(&t).into_string());
            let rem_sec = info.pending_remaining().map(|d| d.as_secs());
            let is_immature = info.is_immature();
            let best_ingress_peer = info.best_ingress_peer.map(|a| a.to_string());

            map.insert(
                *node_pubkey,
                NetworkNodeDto {
                    node_id: bs58::encode(node_pubkey).into_string(),
                    public_key: bs58::encode(node_pubkey).into_string(),
                    address: info.addr.to_string(),
                    is_f2f: false,
                    is_local: false,
                    connection_status: status_str,
                    min_hops: info.min_hops,
                    hrw_routing_id: bs58::encode(&info.hrw_routing_id).into_string(),
                    work_score: info.work_score,
                    is_immature,
                    pending_ticket: pending_bs58,
                    incubation_remaining_sec: rem_sec,
                    missing_count,
                    last_failure_sec,
                    rtt_ms,
                    best_ingress_peer,
                },
            );
        }

        let mut list: Vec<NetworkNodeDto> = map.into_values().collect();
        // Sort: Local node first, then F2F friends, then by min_hops, then address
        list.sort_by(|a, b| match (a.is_local, b.is_local) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => match (a.is_f2f, b.is_f2f) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a
                    .min_hops
                    .cmp(&b.min_hops)
                    .then_with(|| a.address.cmp(&b.address)),
            },
        });
        list
    }

    /// Registers a peer's Ed25519 verifying key associated with its 32-byte Node ID.
    /// TLS & F2F strictly on NodePubKey / NodeId (permanent), never on HRW ticket.
    /// Pillar 3: Cryptographic Identity Trumps Network Topology — strict 32-byte
    /// resolution only; no 16-bit alias map (collision overwrites eliminated).
    pub async fn register_verifying_key(&self, node_id: [u8; 32], vk: ed25519_dalek::VerifyingKey) {
        {
            let mut keys = self.verifying_keys.write().await;
            keys.insert(node_id, vk);
        }
    }



    /// Retrieves an Ed25519 verifying key by the full 32-byte Node ID.
    pub async fn get_peer_verifying_key_by_node_id(
        &self,
        node_id: &[u8; 32],
    ) -> Option<ed25519_dalek::VerifyingKey> {
        let keys = self.verifying_keys.read().await;
        keys.get(node_id).copied()
    }

    /// Enforces the Gossip Barrier:
    /// Gossip (Heartbeats and Equivocation Proofs) is ONLY accepted from direct F2F friends.
    /// Cryptographic identity (verified remote_node_id) is primarily used for authorization.
    /// Strictly based on permanent NodePubKey / NodeId, not HRW.
    pub async fn can_accept_gossip(
        &self,
        remote_addr: &SocketAddr,
        remote_node_id: Option<&[u8; 32]>,
    ) -> bool {
        if let Some(node_id) = remote_node_id {
            if self.is_banned(node_id).await {
                return false;
            }
            return self.is_f2f_friend(node_id).await;
        }
        self.is_f2f_addr(remote_addr).await
    }

    /// Enforces Shard-Direct Contact Authorization:
    /// A direct Shard-RPC is allowed if and only if the remote node is either an F2F friend
    /// or was previously learned via F2F gossip (exists in known_network_nodes).
    /// Cryptographic identity (verified remote_node_id) is primarily used for authorization.
    /// F2F check strictly on NodePubKey, HRW only for sharding scoring.
    ///
    /// Local RPC reliability diagnostics do not revoke identity authorization.
    /// Permanent verified equivocation bans are refused.
    pub async fn can_authorize_direct_rpc(
        &self,
        remote_addr: &SocketAddr,
        remote_node_id: Option<&[u8; 32]>,
    ) -> bool {
        if let Some(node_id) = remote_node_id {
            if self.is_banned(node_id).await {
                return false;
            }
            return self.is_known_node(node_id).await;
        }
        self.is_f2f_addr(remote_addr).await || self.is_known_addr(remote_addr).await
    }

    /// Resolves the set of expected permanent NodePubKeys authorized at this endpoint.
    ///
    /// Includes non-banned direct F2F friends bound to `addr` and non-banned nodes
    /// learned via gossip currently bound to `addr`.
    /// Lock acquisitions are fully decoupled (snapshots taken sequentially) to prevent AB-BA deadlocks.
    pub async fn expected_authorized_node_keys(&self, addr: &SocketAddr) -> HashSet<[u8; 32]> {
        let mut expected = HashSet::new();
        let banned = self.banned_nodes.read().await.clone();

        // 1. Direct F2F friends bound to addr
        {
            let friends = self.f2f_friends.read().await.clone();
            for (node_id, opt_addr) in friends {
                if opt_addr.as_ref() == Some(addr) && !banned.contains(&node_id) {
                    expected.insert(node_id);
                }
            }
        }
        {
            let peers = self.peers.read().await.clone();
            if let Some(peer) = peers.get(addr) {
                if peer.conn_type == PeerConnectionType::FriendToFriend {
                    if let Some(ref nid) = peer.node_id {
                        if !banned.contains(nid) {
                            expected.insert(*nid);
                        }
                    }
                }
            }
        }

        // 2. Gossip-learned nodes bound to addr
        {
            let known = self.known_network_nodes.read().await.clone();
            for (node_id, info) in known {
                if &info.addr == addr && !banned.contains(&node_id) {
                    expected.insert(node_id);
                }
            }
        }

        expected
    }

    /// Evicts any active connection for `addr` (e.g. on TLS identity mismatch or stale connection).
    pub async fn evict_connection(&self, addr: &SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(addr) {
            if let Some(conn) = peer.connection.take() {
                conn.close(0u32.into(), b"connection identity mismatch");
            }
        }
    }


    /// Checks if a node is banned due to proven equivocation/slashing.
    pub async fn is_banned(&self, node_id: &[u8; 32]) -> bool {
        let banned = self.banned_nodes.read().await;
        banned.contains(node_id)
    }

    /// Permanently bans a node by its 32-byte pubkey, disconnects its QUIC connection and suspends it.
    /// Returns the number of peer entries affected.
    pub async fn ban_node(&self, node_id: &[u8; 32]) -> usize {
        {
            let mut banned = self.banned_nodes.write().await;
            banned.insert(*node_id);
        }
        let mut affected = 0usize;
        {
            let mut peers = self.peers.write().await;
            for peer in peers.values_mut() {
                if let Some(nid) = peer.node_id {
                    if &nid == node_id {
                        if let Some(conn) = peer.connection.take() {
                            tokio::spawn(async move {
                                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                                conn.close(0u32.into(), b"banned: equivocation proof");
                            });
                        }
                        peer.status = PeerStatus::Suspended;
                        peer.missing_count = crate::network::peer::FAILURE_THRESHOLD_SUSPENDED;
                        affected += 1;
                    }
                }
            }
        }
        {
            let mut known = self.known_network_nodes.write().await;
            if known.remove(node_id).is_some() {
                affected += 1;
            }
        }
        {
            let mut friends = self.f2f_friends.write().await;
            if friends.remove(node_id).is_some() {
                affected += 1;
            }
        }
        self.clock.revoke_peer_sample(node_id);
        affected
    }

    /// Sets the QUIC endpoint for outbound peer connections.
    pub fn set_endpoint(&self, endpoint: quinn::Endpoint) {
        if let Ok(mut ep) = self.endpoint.write() {
            *ep = Some(endpoint);
        }
    }

    /// Retrieves the QUIC endpoint if configured.
    pub fn get_endpoint(&self) -> Option<quinn::Endpoint> {
        self.endpoint.read().ok().and_then(|ep| ep.clone())
    }

    /// Records a failed interaction with a peer (debounced to at most once per 10s).
    pub async fn record_failure(&self, addr: SocketAddr) {
        self.record_failure_at(addr, Instant::now()).await;
    }

    /// Records a failed interaction with a peer at a specific timestamp (for debounce verification).
    pub async fn record_failure_at(&self, addr: SocketAddr, now: Instant) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(&addr) {
            peer.mark_failure_at(now);
        } else {
            let mut info = PeerInfo::with_type(addr, PeerConnectionType::ShardDirect);
            info.mark_failure_at(now);
            peers.insert(addr, info);
        }
    }

    /// Resets failure counters and suspension state for a peer.
    /// Returns Ok(true) if reset was applied, Ok(false) if peer is unknown,
    /// or Err if the peer is permanently banned due to proven equivocation fraud.
    ///
    /// Phase 10: `banned` is checked BEFORE taking the `peers` write guard
    /// (peers -> banned inversion vs `ban_node` banned -> peers eliminated).
    pub async fn reset_peer_suspension(&self, addr: SocketAddr) -> Result<bool, &'static str> {
        let nid_opt = {
            let peers = self.peers.read().await;
            peers.get(&addr).map(|p| p.node_id)
        };
        let Some(nid_opt) = nid_opt else {
            return Ok(false);
        };
        if let Some(nid) = nid_opt {
            if self.is_banned(&nid).await {
                return Err("Peer is permanently banned due to equivocation fraud");
            }
        }
        {
            let mut peers = self.peers.write().await;
            if let Some(peer) = peers.get_mut(&addr) {
                peer.reset_suspension();
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    /// Retrieves the current round-trip time (RTT) in milliseconds for an active peer connection.
    pub async fn get_peer_rtt(&self, addr: SocketAddr) -> Option<u32> {
        let peers = self.peers.read().await;
        peers
            .get(&addr)
            .and_then(|p| p.connection.as_ref().map(|c| c.rtt().as_millis() as u32))
    }

    /// Retrieves an active QUIC connection for a peer, if present, open, and authorized.
    pub async fn get_connection(&self, addr: &SocketAddr) -> Option<quinn::Connection> {
        let peers = self.peers.read().await;
        peers.get(addr).and_then(|p| {
            if p.conn_type == PeerConnectionType::Untrusted {
                return None;
            }
            if let Some(ref conn) = p.connection {
                if conn.close_reason().is_none() {
                    return Some(conn.clone());
                }
            }
            None
        })
    }

    /// Sets or replaces the QUIC connection for a peer.
    pub async fn set_connection(&self, addr: SocketAddr, conn: quinn::Connection) {
        let mut peers = self.peers.write().await;
        let entry = peers.entry(addr).or_insert_with(|| PeerInfo::new(addr));
        entry.connection = Some(conn);
        entry.status = PeerStatus::Connected;
        drop(peers);
        self.notify_sync_trigger();
    }

    /// Returns the number of currently connected peers.
    pub async fn connected_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.values().filter(|p| p.is_connected()).count()
    }

    /// Returns all configured peer socket addresses.
    pub async fn all_peer_addrs(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers.keys().copied().collect()
    }

    /// Returns all configured peer socket addresses that are not currently suspended.
    pub async fn non_suspended_peer_addrs(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| !p.is_suspended())
            .map(|p| p.addr)
            .collect()
    }

    /// Mature, passively present admitted identities. RPC malus is diagnostic.
    pub async fn active_known_nodes(&self) -> Vec<([u8; 32], SocketAddr)> {
        let known = self.known_network_nodes.read().await.clone();
        let banned = self.banned_nodes.read().await.clone();
        known
            .into_iter()
            .filter(|(pk, info)| {
                info.is_hrw_eligible() && info.is_presence_fresh() && !banned.contains(pk)
            })
            .map(|(pk, info)| (pk, info.addr))
            .collect()
    }

    /// HRW tickets of the same qualified identity set used for committee selection.
    pub async fn active_hrw_nodes(&self) -> Vec<([u8; 32], SocketAddr)> {
        let known = self.known_network_nodes.read().await.clone();
        let banned = self.banned_nodes.read().await.clone();
        known
            .into_iter()
            .filter(|(pk, info)| {
                info.is_hrw_eligible() && info.is_presence_fresh() && !banned.contains(pk)
            })
            .map(|(_, info)| (info.hrw_routing_id, info.addr))
            .collect()
    }

    fn local_ticket_is_mature(&self) -> bool {
        let required = self.effective_incubation_duration();
        self.local_ticket_observation
            .lock()
            .map(|value| {
                value.as_ref().is_some_and(|(pk, hrw, since, prior_age)| {
                    let valid_ticket = self.is_simulation_mode()
                        || (*hrw != *blake3::hash(pk).as_bytes()
                            && *hrw != *pk
                            && *hrw != [0u8; 32]);
                    valid_ticket && prior_age.saturating_add(since.elapsed()) >= required
                })
            })
            .unwrap_or(false)
    }

    /// Local ticket view for write authorization. Reachability and suspension
    /// affect routing, never committee membership. Incubation remains based on
    /// first observation; this view does not establish global agreement.
    pub async fn shard_committee(
        &self,
        self_pubkey: [u8; 32],
        self_hrw: [u8; 32],
        shard_id: u16,
    ) -> (
        Vec<humoco_sim_core::types::CommitteeMember>,
        Vec<(humoco_sim_core::types::CommitteeMember, SocketAddr)>,
        usize,
    ) {
        use humoco_sim_core::types::{select_shard_committee, CommitteeMember};
        let known = self.known_network_nodes.read().await.clone();
        let banned = self.banned_nodes.read().await.clone();
        let mut endpoints = HashMap::new();
        for (pk, info) in &known {
            if *pk != self_pubkey
                && info.is_hrw_eligible()
                && info.is_presence_fresh()
                && !banned.contains(pk)
            {
                endpoints.insert(*pk, (info.hrw_routing_id, info.addr));
            }
        }
        // A transport connection authenticates identity, not a mined mature ticket.
        // Never synthesize a routing ticket from an unknown peer's public key.
        let mut members: Vec<_> = endpoints
            .iter()
            .map(|(pk, (hrw, _))| CommitteeMember {
                node_pubkey: *pk,
                hrw_routing_id: *hrw,
            })
            .collect();
        let required_incubation = self.effective_incubation_duration();
        let self_has_valid_ticket = self.is_simulation_mode()
            || (self_hrw != *blake3::hash(&self_pubkey).as_bytes()
                && self_hrw != self_pubkey
                && self_hrw != [0u8; 32]);
        let self_mature = if !self_has_valid_ticket {
            false
        } else if let Some(info) = known.get(&self_pubkey) {
            info.hrw_routing_id == self_hrw && info.is_hrw_eligible()
        } else if let Ok(mut observation) = self.local_ticket_observation.lock() {
            match *observation {
                Some((pk, hrw, since, prior_age)) if pk == self_pubkey && hrw == self_hrw => {
                    prior_age.saturating_add(since.elapsed()) >= required_incubation
                }
                _ => {
                    let prior_age = self
                        .persisted_ticket_ages
                        .lock()
                        .get(&(self_pubkey, self_hrw))
                        .copied()
                        .unwrap_or(Duration::ZERO);
                    *observation = Some((self_pubkey, self_hrw, Instant::now(), prior_age));
                    prior_age >= required_incubation
                }
            }
        } else {
            false
        };
        if self_mature && !banned.contains(&self_pubkey) {
            members.push(CommitteeMember {
                node_pubkey: self_pubkey,
                hrw_routing_id: self_hrw,
            });
        }
        let total = members.len();
        let committee = select_shard_committee(shard_id, &members);
        let remote = committee
            .iter()
            .filter_map(|member| {
                endpoints
                    .get(&member.node_pubkey)
                    .map(|(_, addr)| (*member, *addr))
            })
            .collect();
        (committee, remote, total)
    }

    pub async fn observe_gateway_advertisement(
        &self,
        advertisement: crate::network::discovery::GatewayAdvertisement,
        expected: &[u8; 32],
        network: u8,
    ) {
        let now = self.net_time_ms();
        if !advertisement.verify(expected, network, now) || self.is_banned(expected).await {
            return;
        }
        let mut cache = self.gateway_advertisements.write();
        cache.retain(|_, ad| ad.valid_until_ms > now);
        if cache
            .get(expected)
            .is_some_and(|old| old.issued_at_ms >= advertisement.issued_at_ms)
        {
            return;
        }
        if cache.len() >= 256 && !cache.contains_key(expected) {
            return;
        }
        cache.insert(*expected, advertisement);
    }

    pub async fn advertised_gateway_urls(&self) -> Vec<String> {
        let banned = self.banned_nodes.read().await;
        let cache = self.gateway_advertisements.read();
        let now = self.net_time_ms();
        let mut urls = std::collections::BTreeSet::new();
        for (key, ad) in cache.iter() {
            if !banned.contains(key) && ad.valid_until_ms > now {
                for url in &ad.urls {
                    urls.insert(url.clone());
                    if urls.len() >= crate::config::MAX_PUBLIC_GATEWAY_ENTRIES {
                        return urls.into_iter().collect();
                    }
                }
            }
        }
        urls.into_iter().collect()
    }

    /// Operator-only export of this node's qualified regional view. Source
    /// authentication delegates these observations, never the Byzantine bound.
    pub async fn regional_mesh_view(
        &self,
        identity: &crate::identity::NodeIdentity,
        network: u8,
    ) -> Result<humoco_proto::mesh::RegionalMeshView, crate::error::NodeError> {
        use ed25519_dalek::Signer;
        let known = self.known_network_nodes.read().await;
        let banned = self.banned_nodes.read().await;
        let local = *identity.node_pubkey();
        let local_has_valid_ticket = self.is_simulation_mode()
            || (*identity.hrw_routing_id() != *blake3::hash(&local).as_bytes()
                && *identity.hrw_routing_id() != local
                && *identity.hrw_routing_id() != [0u8; 32]);
        let mut members = Vec::new();
        for (key, info) in known.iter() {
            let eligible = if *key == local {
                local_has_valid_ticket
                    && info.hrw_routing_id == *identity.hrw_routing_id()
                    && info.is_hrw_eligible()
            } else {
                info.is_hrw_eligible() && info.is_presence_fresh()
            };
            if eligible && !banned.contains(key) {
                if members.len() >= humoco_proto::mesh::MAX_MESH_MEMBERS {
                    return Err(crate::error::NodeError::LocalCapacity(
                        "regional view exceeds bounded export",
                    ));
                }
                members.push(humoco_proto::mesh::RegionalMeshMember {
                    node_pubkey: *key,
                    hrw_routing_id: info.hrw_routing_id,
                });
            }
        }
        if local_has_valid_ticket
            && !known.contains_key(&local)
            && self.local_ticket_is_mature()
            && !banned.contains(&local)
        {
            if members.len() >= humoco_proto::mesh::MAX_MESH_MEMBERS {
                return Err(crate::error::NodeError::LocalCapacity(
                    "regional view exceeds bounded export",
                ));
            }
            members.push(humoco_proto::mesh::RegionalMeshMember {
                node_pubkey: local,
                hrw_routing_id: *identity.hrw_routing_id(),
            });
        }
        drop(banned);
        drop(known);
        members.sort_by_key(|member| member.node_pubkey);
        let issued_at_ms = self.net_time_ms();
        let mut view = humoco_proto::mesh::RegionalMeshView {
            version: 1,
            network,
            source_key: local,
            issued_at_ms,
            valid_until_ms: issued_at_ms.saturating_add(humoco_proto::mesh::MAX_VIEW_LIFETIME_MS),
            members,
            signature: [0; 64],
        };
        let digest = view
            .digest()
            .map_err(|reason| crate::error::NodeError::Network(reason.into()))?;
        view.signature = identity.signing_key().sign(&digest).to_bytes();
        Ok(view)
    }

    pub async fn is_local_committee_member(
        &self,
        self_pubkey: [u8; 32],
        self_hrw: [u8; 32],
        shard_id: u16,
    ) -> bool {
        let (committee, _, _) = self.shard_committee(self_pubkey, self_hrw, shard_id).await;
        committee
            .iter()
            .any(|member| member.node_pubkey == self_pubkey)
    }

    /// Checks whether the local node is among the responsible Top-N (default 20) shard nodes
    /// for the given shard_id according to HRW score.
    pub async fn is_local_responsible_for_shard(
        &self,
        self_hrw: &[u8; 32],
        shard_id: u16,
        top_n: usize,
    ) -> bool {
        self.local_shard_rank(self_hrw, shard_id)
            .await
            .map(|r| r <= top_n)
            .unwrap_or(true)
    }

    /// Legacy rank inspection using full 256-bit scores. Runtime write
    /// authorization uses `shard_committee` with complete public keys.
    pub async fn local_shard_rank(&self, self_hrw: &[u8; 32], shard_id: u16) -> Option<usize> {
        let active_nodes = self.active_hrw_nodes().await;
        if active_nodes.is_empty() {
            return None;
        }
        let self_score = humoco_sim_core::types::hrw_score_32(self_hrw, shard_id);
        let higher_nodes_count = active_nodes
            .iter()
            .filter(|(hrw_id, _)| {
                if hrw_id == self_hrw {
                    return false;
                }
                let score = humoco_sim_core::types::hrw_score_32(hrw_id, shard_id);
                score > self_score || (score == self_score && hrw_id > self_hrw)
            })
            .count();
        Some(higher_nodes_count + 1)
    }

    /// Returns the top-N candidate nodes for a given shard_id according to HRW ranking.
    pub async fn get_top_n_shards_for_lock(
        &self,
        shard_id: u16,
        n: usize,
    ) -> Vec<([u8; 32], SocketAddr)> {
        let active = self.active_hrw_nodes().await;
        let mut members = Vec::new();
        let mut endpoints = HashMap::new();
        for (hrw, addr) in active {
            if let Some(pk) = self.get_pubkey_by_hrw_routing_id(&hrw).await {
                members.push(humoco_sim_core::types::CommitteeMember {
                    node_pubkey: pk,
                    hrw_routing_id: hrw,
                });
                endpoints.insert(pk, addr);
            }
        }
        humoco_sim_core::types::select_shard_committee(shard_id, &members)
            .into_iter()
            .take(n)
            .filter_map(|member| {
                endpoints
                    .get(&member.node_pubkey)
                    .map(|addr| (member.hrw_routing_id, *addr))
            })
            .collect()
    }

    pub async fn record_observed_evidence(
        &self,
        ev: humoco_sim_core::fraud::IngressEnvelopeEvidence,
    ) {
        let mut guard = self.recent_observed_evidences.write().await;
        if guard.len() >= 16 {
            guard.pop_front();
        }
        guard.push_back(ev);
    }

    pub async fn sample_piggyback_evidences(
        &self,
        max_count: usize,
    ) -> Vec<humoco_sim_core::fraud::IngressEnvelopeEvidence> {
        let guard = self.recent_observed_evidences.read().await;
        guard.iter().rev().take(max_count).cloned().collect()
    }

    pub async fn update_node_write_evidence(
        &self,
        node_id: &[u8; 32],
        ev: humoco_sim_core::fraud::IngressEnvelopeEvidence,
    ) {
        let mut known = self.known_network_nodes.write().await;
        if let Some(info) = known.get_mut(node_id) {
            info.update_write_evidence(ev);
        } else {
            let dummy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let mut info = KnownNodeInfo::new(dummy_addr, *node_id, *node_id);
            info.work_score = 0;
            info.incubation_duration = self.effective_incubation_duration();
            info.update_write_evidence(ev);
            known.insert(*node_id, info);
        }
    }

    pub async fn update_node_read_evidence(
        &self,
        node_id: &[u8; 32],
        ev: humoco_sim_core::fraud::IngressEnvelopeEvidence,
    ) {
        let mut known = self.known_network_nodes.write().await;
        if let Some(info) = known.get_mut(node_id) {
            info.update_read_evidence(ev);
        } else {
            let dummy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let mut info = KnownNodeInfo::new(dummy_addr, *node_id, *node_id);
            info.work_score = 0;
            info.incubation_duration = self.effective_incubation_duration();
            info.update_read_evidence(ev);
            known.insert(*node_id, info);
        }
    }

    pub async fn get_node_write_evidence(
        &self,
        node_id: &[u8; 32],
    ) -> Option<humoco_sim_core::fraud::IngressEnvelopeEvidence> {
        let known = self.known_network_nodes.read().await;
        known
            .get(node_id)
            .and_then(|info| info.last_write_evidence.clone())
    }

    pub async fn get_node_read_evidence(
        &self,
        node_id: &[u8; 32],
    ) -> Option<humoco_sim_core::fraud::IngressEnvelopeEvidence> {
        let known = self.known_network_nodes.read().await;
        known
            .get(node_id)
            .and_then(|info| info.last_read_evidence.clone())
    }

    /// Computes decentralized network median write daily rate and read daily rate across mature known nodes.
    pub async fn effective_network_medians(&self, now_sec: u64) -> (u64, u64) {
        let known = self.known_network_nodes.read().await;
        let mut write_rates = Vec::new();
        let mut read_rates = Vec::new();

        for kinfo in known.values() {
            if kinfo.is_immature() {
                continue;
            }
            if let Some(ref w_ev) = kinfo.last_write_evidence {
                let ev_sec = w_ev.timestamp_ms / 1000;
                let delta_secs = now_sec.saturating_sub(ev_sec);
                let decayed_ema = humoco_sim_core::quota::decay_integer_ema(
                    w_ev.declared_write_ema_micro_bj,
                    delta_secs,
                );
                let daily_rate = humoco_sim_core::quota::ema_to_daily_rate(decayed_ema) / 1_000_000;
                write_rates.push(daily_rate);
            }
            if let Some(ref r_ev) = kinfo.last_read_evidence {
                let ev_sec = r_ev.timestamp_ms / 1000;
                let delta_secs = now_sec.saturating_sub(ev_sec);
                let decayed_ema = humoco_sim_core::quota::decay_integer_ema(
                    r_ev.declared_read_ema_credits,
                    delta_secs,
                );
                let daily_rate = humoco_sim_core::quota::ema_to_daily_rate(decayed_ema);
                read_rates.push(daily_rate);
            }
        }

        let write_median = if write_rates.is_empty() {
            humoco_sim_core::quota::HARD_FLOOR_BASELINE_DAILY
        } else {
            humoco_sim_core::quota::QuartileStats::calculate(&write_rates).median
        };

        let read_median = if read_rates.is_empty() {
            humoco_sim_core::quota::HARD_FLOOR_READ_BASELINE_DAILY
        } else {
            humoco_sim_core::quota::QuartileStats::calculate(&read_rates).median
        };

        (write_median, read_median)
    }

    /// Best-effort nonblocking size using mature passive presence, never RPC malus.
    pub fn active_nodes_count(&self) -> usize {
        let Ok(known) = self.known_network_nodes.try_read() else {
            return 0;
        };
        let Ok(banned) = self.banned_nodes.try_read() else {
            return 0;
        };
        let remote_count = known
            .iter()
            .filter(|(pk, info)| {
                info.is_hrw_eligible() && info.is_presence_fresh() && !banned.contains(*pk)
            })
            .count();
        remote_count + usize::from(self.local_ticket_is_mature())
    }

    /// Same eligibility policy as the frozen committee; connectivity is not a ticket.
    pub async fn mature_network_size(&self) -> usize {
        self.active_known_nodes().await.len() + usize::from(self.local_ticket_is_mature())
    }

    /// Diagnostic merge detection includes immature identities with fresh gossip.
    /// Anonymous socket addresses are not additional cryptographic identities.
    pub async fn total_network_size(&self) -> usize {
        let known = self.known_network_nodes.read().await.clone();
        let banned = self.banned_nodes.read().await.clone();
        known
            .iter()
            .filter(|(pk, info)| info.is_presence_fresh() && !banned.contains(*pk))
            .count()
            + 1
    }

    /// Pure merge-jump predicate (Spec 09 INV-0908): abrupt growth detection.
    /// Triggers on doubling (`N_new >= 2 * N_old`) or absolute jump (`ΔN >= 20`).
    pub fn is_merge_jump(old_count: usize, new_count: usize) -> bool {
        if new_count <= old_count {
            return false;
        }
        if old_count == 0 {
            return new_count >= 20;
        }
        new_count >= old_count.saturating_mul(2) || new_count.saturating_sub(old_count) >= 20
    }

    /// Marks a detected partition merge: arms the 24h quota moratorium window.
    pub fn note_merge_detected(&self, now_ms: u64) {
        self.merge_hysteresis_until_ms.store(
            now_ms.saturating_add(MERGE_HYSTERESIS_MS),
            Ordering::Relaxed,
        );
    }

    /// Checks whether the node is inside the 24h post-merge quota moratorium.
    /// During this window no quota-driven peer penalties may be applied (INV-0908).
    pub fn is_in_merge_hysteresis(&self, now_ms: u64) -> bool {
        now_ms < self.merge_hysteresis_until_ms.load(Ordering::Relaxed)
    }

    /// Remaining merge-moratorium time in seconds (0 when outside the window).
    pub fn merge_hysteresis_remaining_sec(&self, now_ms: u64) -> u64 {
        self.merge_hysteresis_until_ms
            .load(Ordering::Relaxed)
            .saturating_sub(now_ms)
            / 1000
    }

    /// Sets local shard-sync readiness (mirrored from the daemon digest-pull motor).
    /// The Provisional -> Final transition requires Sync-Readiness (Spec 08 Phase 9 P1).
    pub fn set_local_sync_ready(&self, ready: bool) {
        self.local_sync_ready.store(ready, Ordering::Relaxed);
    }

    /// Returns local shard-sync readiness.
    pub fn is_local_sync_ready(&self) -> bool {
        self.local_sync_ready.load(Ordering::Relaxed)
    }

    /// 24h finality hysteresis: FINAL status only if network has been stable with >=20 mature nodes for 24h.
    /// Tracks mature, passively present membership. Each signature independently
    /// requires its own safely installed shard state, never a global sync bit.
    pub fn is_network_stable_ge20_for_24h(&self, now_ms: u64) -> bool {
        if self.active_nodes_count() >= 20 {
            let start = self.ge20_first_reached_ms.load(Ordering::Relaxed);
            if start == 0 {
                self.ge20_first_reached_ms.store(now_ms, Ordering::Relaxed);
                return false;
            }
            now_ms.saturating_sub(start) >= 86_400_000
        } else {
            self.ge20_first_reached_ms.store(0, Ordering::Relaxed);
            false
        }
    }

    /// Test helper: overrides the 24h-stability anchor (simulates long-stable N >= 20).
    pub fn set_ge20_anchor_for_test(&self, anchor_ms: u64) {
        self.ge20_first_reached_ms
            .store(anchor_ms, Ordering::Relaxed);
    }

    /// Test helper: overrides last_seen to simulate stale presence ghosts.
    pub async fn set_last_seen_for_test(&self, node_pubkey: &[u8; 32], last_seen: Instant) {
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(node_pubkey) {
            entry.last_seen = last_seen;
        }
    }

    /// Autonomous healing: decrements penalty counter of all registered peers by 1.
    pub async fn decay_all_peers(&self) {
        let _ = self.decay_all_peers_at(Instant::now()).await;
    }

    /// Autonomous healing with explicit evaluation timestamp (for simulation and testing).
    pub async fn decay_all_peers_at(&self, now: Instant) -> Vec<QuarantineEvent> {
        {
            let mut peers = self.peers.write().await;
            for peer in peers.values_mut() {
                peer.decay_malus();
            }
        }
        self.evaluate_f2f_quarantine(now).await
    }

    /// Returns all F2F friend addresses for the periodic heartbeat emitter.
    pub async fn f2f_peer_addrs(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.conn_type == PeerConnectionType::FriendToFriend)
            .map(|p| p.addr)
            .collect()
    }

    /// Returns all configured and connected F2F friend addresses for gossip broadcast.
    pub async fn all_f2f_target_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = self.f2f_peer_addrs().await;
        let friends = self.f2f_friends.read().await;
        for a in friends.values().flatten() {
            if !addrs.contains(a) {
                addrs.push(*a);
            }
        }
        addrs
    }

    /// Checks whether a direct F2F friend public key is currently quarantined.
    pub fn is_f2f_quarantined(&self, friend_pk: &[u8; 32]) -> bool {
        self.quarantine_state
            .read()
            .quarantined_f2f_edges
            .contains_key(friend_pk)
    }

    /// Checks whether a given peer socket address belongs to a currently quarantined F2F friend.
    pub async fn is_f2f_addr_quarantined(&self, addr: &SocketAddr) -> bool {
        if let Some(fpk) = self.f2f_friend_pubkey_for_addr(addr).await {
            self.is_f2f_quarantined(&fpk)
        } else {
            false
        }
    }

    /// Returns the currently active (non-quarantined) F2F target addresses for multi-hop gossip forwarding.
    pub async fn active_f2f_target_addrs(&self) -> Vec<SocketAddr> {
        let all = self.all_f2f_target_addrs().await;
        let mut active = Vec::with_capacity(all.len());
        for addr in all {
            if !self.is_f2f_addr_quarantined(&addr).await {
                active.push(addr);
            }
        }
        active
    }

    /// Returns a copy of the current quarantine policy.
    pub fn quarantine_policy(&self) -> QuarantinePolicy {
        self.quarantine_state.read().quarantine_policy.clone()
    }

    /// Sets a new quarantine policy (e.g. fast timings for simulation/tests).
    pub fn set_quarantine_policy(&self, policy: QuarantinePolicy) {
        self.quarantine_state.write().quarantine_policy = policy;
    }

    /// Returns a snapshot of all currently quarantined F2F edges and their shadow states.
    pub fn quarantined_f2f_edges(&self) -> HashMap<[u8; 32], QuarantinedEdgeState> {
        self.quarantine_state.read().quarantined_f2f_edges.clone()
    }

    /// Records an authentic heartbeat received over a quarantined F2F friend edge in its ShadowEdgeWindow.
    ///
    /// If the origin node has a local `zombie_since.is_some()`, this heartbeat is considered a zombie heartbeat,
    /// resetting the edge's clean window timer. Otherwise, it increments the count of clean heartbeats.
    pub async fn record_shadow_heartbeat(
        &self,
        friend_pk: [u8; 32],
        origin_node_id: [u8; 32],
        _hops: u8,
        now: Instant,
    ) {
        let known_addr = {
            let known = self.known_network_nodes.read().await;
            known.get(&origin_node_id).map(|info| info.addr)
        };
        let friend_addr = {
            let friends = self.f2f_friends.read().await;
            friends.get(&origin_node_id).copied().flatten()
        };
        let is_zombie = {
            let peers = self.peers.read().await;
            let by_known = known_addr
                .and_then(|a| peers.get(&a))
                .is_some_and(|p| p.zombie_since.is_some());
            let by_friend = friend_addr
                .and_then(|a| peers.get(&a))
                .is_some_and(|p| p.zombie_since.is_some());
            let by_id = peers
                .values()
                .any(|p| p.node_id == Some(origin_node_id) && p.zombie_since.is_some());
            by_known || by_friend || by_id
        };
        let mut state = self.quarantine_state.write();
        if let Some(edge) = state.quarantined_f2f_edges.get_mut(&friend_pk) {
            edge.record_shadow_heartbeat(is_zombie, now);
        }
    }

    /// Synchronous variant of `record_shadow_heartbeat` with explicit zombie flag (for unit tests / simulation).
    pub fn record_shadow_heartbeat_sync(
        &self,
        friend_pk: [u8; 32],
        is_zombie: bool,
        now: Instant,
    ) {
        let mut state = self.quarantine_state.write();
        if let Some(edge) = state.quarantined_f2f_edges.get_mut(&friend_pk) {
            edge.record_shadow_heartbeat(is_zombie, now);
        }
    }

    /// Evaluates the Hop-invariant KISS F2F Quarantine (Algo 3v2) and ShadowEdgeWindow.
    ///
    /// 1. Self-healing check: Any quarantined edge with `now - last_zombie_shadow_seen >= shadow_clean_window`
    ///    heals autonomously and is restored to active status.
    /// 2. Cadence check: If `now - last_quarantine_step_at < min_step_interval`, no new quarantine/preemption
    ///    action is performed in this step.
    /// 3. Candidate evaluation: For all currently active F2F friends, evaluates mature zombies (h = 0 for direct
    ///    friends with missing_count >= 3; h >= 1 for known nodes with missing_count >= 3 whose zombie age >= T(h)),
    ///    calculates exclusive and healthy community sizes, and applies `decide_algo3v2`.
    pub async fn evaluate_f2f_quarantine(&self, now: Instant) -> Vec<QuarantineEvent> {
        let mut events = Vec::new();

        // 1. Autonomous self-healing check on currently quarantined edges
        let (healed, policy, min_step_ok) = {
            let mut state = self.quarantine_state.write();
            let policy = state.quarantine_policy.clone();
            let mut healed = Vec::new();
            for (&friend_pk, edge_state) in state.quarantined_f2f_edges.iter() {
                if edge_state.is_healed(now, &policy) {
                    healed.push(friend_pk);
                }
            }
            for pk in &healed {
                state.quarantined_f2f_edges.remove(pk);
            }

            let min_step_ok = match state.last_quarantine_step_at {
                Some(last) => now.saturating_duration_since(last) >= policy.min_step_interval,
                None => true,
            };

            (healed, policy, min_step_ok)
        };

        for pk in &healed {
            events.push(QuarantineEvent::Healed { friend_pk: *pk });
        }

        // 2. Calm cadence check (Rule 3)
        if !min_step_ok {
            return events;
        }

        // 3. Active F2F friends collection (sequential snapshot)
        let f2f_friends_map = {
            let friends = self.f2f_friends.read().await;
            friends.clone()
        };
        let quarantined_edges = {
            let state = self.quarantine_state.read();
            state.quarantined_f2f_edges.clone()
        };

        let active_friends: HashSet<[u8; 32]> = f2f_friends_map
            .keys()
            .copied()
            .filter(|pk| !quarantined_edges.contains_key(pk))
            .collect();

        let active_friends_count = active_friends.len();
        if active_friends_count == 0 {
            return events;
        }

        // 4. Gather health status and edge observations (sequential snapshots to prevent lock inversion)
        let known_nodes = {
            let kn = self.known_network_nodes.read().await;
            kn.clone()
        };
        let peers = {
            let p = self.peers.read().await;
            p.clone()
        };

        let mut healthy_counts: HashMap<[u8; 32], usize> = HashMap::new();
        let mut exclusive_healthy_counts: HashMap<[u8; 32], usize> = HashMap::new();
        let mut exclusive_strictly_healthy_counts: HashMap<[u8; 32], usize> = HashMap::new();
        let mut min_mature_hops: HashMap<[u8; 32], u8> = HashMap::new();

        for (&k_pk, k_info) in known_nodes.iter() {
            let k_peer = peers
                .values()
                .find(|p| p.node_id == Some(k_pk))
                .or_else(|| peers.get(&k_info.addr));

            let missing_count = k_peer.map(|p| p.missing_count).unwrap_or(0);
            let zombie_since = k_peer.and_then(|p| p.zombie_since);
            let is_strictly_healthy = missing_count == 0 && zombie_since.is_none();
            let is_healthy = missing_count < FAILURE_THRESHOLD_SUSPENDED && zombie_since.is_none();
            let is_zombie = zombie_since.is_some();

            let active_obs: Vec<([u8; 32], u8)> = k_info
                .edge_observations
                .iter()
                .filter(|(f_pk, (_, ts))| {
                    active_friends.contains(*f_pk)
                        && now.saturating_duration_since(*ts) <= EDGE_OBSERVATION_TTL
                })
                .map(|(&f_pk, &(hops, _))| (f_pk, hops))
                .collect();

            if active_obs.is_empty() {
                continue;
            }

            for &(f_pk, _) in &active_obs {
                if is_healthy {
                    *healthy_counts.entry(f_pk).or_insert(0) += 1;
                }
            }

            if active_obs.len() == 1 {
                let (f_pk, _) = active_obs[0];
                if is_healthy {
                    *exclusive_healthy_counts.entry(f_pk).or_insert(0) += 1;
                }
                if is_strictly_healthy {
                    *exclusive_strictly_healthy_counts.entry(f_pk).or_insert(0) += 1;
                }
            }

            if is_zombie {
                let z_age = zombie_since
                    .map(|ts| now.saturating_duration_since(ts))
                    .unwrap_or(Duration::ZERO);

                for &(f_pk, hops) in &active_obs {
                    let wait_dur = policy.hop_wait_duration(hops);
                    if z_age >= wait_dur {
                        let entry = min_mature_hops.entry(f_pk).or_insert(hops);
                        if hops < *entry {
                            *entry = hops;
                        }
                    }
                }
            }
        }

        // Direct F2F friend defects (h = 0)
        for &f_pk in &active_friends {
            if healed.contains(&f_pk) {
                continue;
            }
            let f_peer = peers.values().find(|p| p.node_id == Some(f_pk)).or_else(|| {
                f2f_friends_map
                    .get(&f_pk)
                    .copied()
                    .flatten()
                    .and_then(|a| peers.get(&a))
            });

            if f_peer.is_some_and(|p| p.zombie_since.is_some()) {
                // T(0) = 0 -> immediately mature candidate with h = 0
                min_mature_hops.insert(f_pk, 0);
            }
        }

        // 5. Build CandidateEdge list
        let mut mature_candidates = Vec::new();
        for &f_pk in &active_friends {
            if healed.contains(&f_pk) {
                continue;
            }
            if let Some(&h) = min_mature_hops.get(&f_pk) {
                mature_candidates.push(CandidateEdge {
                    friend_pk: f_pk,
                    h,
                    n_exclusive_strictly_healthy: exclusive_strictly_healthy_counts
                        .get(&f_pk)
                        .copied()
                        .unwrap_or(0),
                    n_exclusive_healthy: exclusive_healthy_counts
                        .get(&f_pk)
                        .copied()
                        .unwrap_or(0),
                    n_healthy: healthy_counts.get(&f_pk).copied().unwrap_or(0),
                });
            }
        }

        // 6. Execute Algo 3v2 decision
        if let Some(decision) = decide_algo3v2(
            &mature_candidates,
            active_friends_count,
            &quarantined_edges,
            &policy,
        ) {
            match decision {
                QuarantineDecision::Quarantine {
                    friend_pk,
                    trigger_hops,
                } => {
                    let mut state = self.quarantine_state.write();
                    state.quarantined_f2f_edges.insert(
                        friend_pk,
                        QuarantinedEdgeState::new(now, trigger_hops),
                    );
                    state.last_quarantine_step_at = Some(now);
                    events.push(QuarantineEvent::Quarantined {
                        friend_pk,
                        trigger_hops,
                    });
                }
                QuarantineDecision::Preempt {
                    release_friend_pk,
                    target_friend_pk,
                    trigger_hops,
                } => {
                    let mut state = self.quarantine_state.write();
                    state.quarantined_f2f_edges.remove(&release_friend_pk);
                    state.quarantined_f2f_edges.insert(
                        target_friend_pk,
                        QuarantinedEdgeState::new(now, trigger_hops),
                    );
                    state.last_quarantine_step_at = Some(now);
                    events.push(QuarantineEvent::Preempted {
                        released_friend_pk: release_friend_pk,
                        quarantined_friend_pk: target_friend_pk,
                        trigger_hops,
                    });
                }
            }
        }

        events
    }

    /// Returns shard sync candidates for digest pull (non-suspended peers).
    pub async fn shard_sync_addrs(&self) -> Vec<SocketAddr> {
        self.non_suspended_peer_addrs().await
    }

    /// Returns active peers for PEX discovery endpoint, filtered against banned and suspended status.
    ///
    /// Phase 10: sequential snapshots, never nested.
    pub async fn get_pex_peers(&self) -> Vec<KnownNodeInfo> {
        let banned: HashSet<[u8; 32]> = self.banned_nodes.read().await.clone();
        let suspended_addrs: HashSet<SocketAddr> = {
            let peers = self.peers.read().await;
            peers
                .values()
                .filter(|p| p.is_suspended())
                .map(|p| p.addr)
                .collect()
        };
        let known: Vec<([u8; 32], KnownNodeInfo)> = {
            let known = self.known_network_nodes.read().await;
            known.iter().map(|(k, v)| (*k, v.clone())).collect()
        };

        let mut result = Vec::new();
        for (nid, kinfo) in &known {
            if banned.contains(nid) {
                continue;
            }
            if !suspended_addrs.contains(&kinfo.addr) {
                result.push(kinfo.clone());
            }
        }
        result
    }

    /// Computes an hourly jitter interval (55min + 0..10min = avg 60min).
    /// Enforces a >= 5 minute (300s) safety margin over the 50-minute (3000s) heartbeat spam threshold.
    pub fn heartbeat_jitter_secs() -> u64 {
        let base: u64 = 3300; // 55 minutes
        let max_jitter: u64 = 600; // 0..10 minutes
        let jitter: u64 = rand::thread_rng().gen_range(0..=max_jitter);
        base + jitter
    }

    /// Returns a reference to the NetworkClock (Spec 11).
    pub fn clock(&self) -> &Arc<crate::network::NetworkClock> {
        &self.clock
    }

    /// Returns the P2P Network-Adjusted Time (`net_time`) in ms (< 1µs, lock-free).
    pub fn net_time_ms(&self) -> u64 {
        self.clock.net_time_ms()
    }

    /// Alias for net_time_ms.
    #[inline]
    pub fn now_ms(&self) -> u64 {
        self.net_time_ms()
    }

    /// Records an authenticated hourly heartbeat observation for initial admission tracking.
    pub async fn record_heartbeat_hourly_observation(
        &self,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        obs_ms: u64,
    ) {
        let is_sim = self.effective_incubation_duration() <= SIM_HRW_INCUBATION_DURATION;
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(&node_pubkey) {
            if entry.hrw_routing_id == hrw_routing_id {
                entry.record_hourly_observation(obs_ms, is_sim);
            }
        }
    }

    /// Computes backoff duration with symmetric random jitter (+/-25%) and dormant cap according to Spec 15 / Spec 19.
    pub fn compute_backoff(&self, attempt: u32) -> Duration {
        if attempt >= 12 {
            return Duration::from_secs(3600); // 1h Dormant Cap for permanently unreachable nodes
        }
        let shift = attempt.min(6);
        let factor = 1u64 << shift;
        let base = self.base_backoff_ms.saturating_mul(factor);
        let capped = base.min(self.max_backoff_ms);

        let quarter = capped / 4;
        let jittered = if quarter > 0 {
            let delta = rand::thread_rng().gen_range(0..=(2 * quarter));
            capped.saturating_sub(quarter).saturating_add(delta)
        } else {
            capped
        };

        Duration::from_millis(jittered)
    }

    /// Returns the backoff duration for reconnecting to a peer if it has failed attempts or is suspended.
    pub async fn get_reconnect_backoff(&self, addr: &SocketAddr) -> Option<Duration> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(addr) {
            if peer.missing_count > 0 || peer.status == PeerStatus::Suspended {
                let attempts = peer.missing_count.max(1);
                return Some(self.compute_backoff(attempts));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_friend_without_ticket_is_a_sync_source_not_a_committee_member() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 9901));
        let manager = PeerManager::new(Vec::new());
        let pk = [42; 32];
        manager.register_f2f_friend(pk, Some(addr)).await;
        assert!(manager.known_network_nodes.read().await.is_empty());
        assert_eq!(manager.get_pubkey_by_hrw_routing_id(&pk).await, Some(pk));
        assert!(manager.shard_sync_addrs().await.contains(&addr));
        assert!(manager.get_top_n_shards_for_lock(17, 20).await.is_empty());
        assert_eq!(manager.get_pubkey_by_hrw_routing_id(&[43; 32]).await, None);
    }

    #[tokio::test]
    async fn test_peer_manager_operations() {
        let addr1: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9092".parse().unwrap();

        let manager = PeerManager::new(vec![addr1]);
        assert_eq!(manager.list_peers().await.len(), 1);

        manager.add_peer(addr2).await;
        assert_eq!(manager.list_peers().await.len(), 2);

        manager.record_failure(addr1).await;
        let p1 = manager.get_peer(&addr1).await.unwrap();
        assert_eq!(p1.missing_count, 1);

        // Phase 8: pure handshake preserves the malus, refreshes identity
        manager.record_success(addr1, Some([7u8; 32]), None).await;
        let p1_handshake = manager.get_peer(&addr1).await.unwrap();
        assert_eq!(p1_handshake.missing_count, 1);
        assert_eq!(p1_handshake.node_id, Some([7u8; 32]));

        // Only genuine shard work decays the malus
        manager.record_shard_work(addr1).await;
        let p1_recovered = manager.get_peer(&addr1).await.unwrap();
        assert_eq!(p1_recovered.missing_count, 0);
        assert_eq!(p1_recovered.node_id, Some([7u8; 32]));
    }

    #[tokio::test]
    async fn test_handshake_preserves_diagnostic_malus_without_revoking_rpc() {
        let addr: SocketAddr = "127.0.0.1:9098".parse().unwrap();
        let manager = PeerManager::new(vec![addr]);
        let nid = [9u8; 32];
        manager.register_f2f_friend(nid, Some(addr)).await;
        manager.record_success(addr, Some(nid), None).await;
        assert!(manager.can_authorize_direct_rpc(&addr, Some(&nid)).await);

        // Drive peer into suspension (debounced: space failures >= 60s apart)
        let t0 = Instant::now();
        manager.record_failure_at(addr, t0).await;
        manager
            .record_failure_at(addr, t0 + Duration::from_secs(61))
            .await;
        manager
            .record_failure_at(addr, t0 + Duration::from_secs(122))
            .await;
        assert!(manager.is_peer_suspended_by_addr(&addr).await);
        assert!(manager.is_peer_suspended_by_id(&nid).await);

        // RPC failure scores are diagnostic and never revoke admitted service.
        assert!(manager.can_authorize_direct_rpc(&addr, Some(&nid)).await);

        // Handshake does not lift diagnostic suspension or revoke authorization.
        manager.record_success(addr, Some(nid), None).await;
        assert!(manager.can_authorize_direct_rpc(&addr, Some(&nid)).await);

        // Genuine shard work rehabilitates step by step (3 -> 2, Degrading)
        manager.record_shard_work(addr).await;
        assert!(!manager.is_peer_suspended_by_addr(&addr).await);
        assert!(manager.can_authorize_direct_rpc(&addr, Some(&nid)).await);

        // Idle close preserves malus accounting without penalizing
        let before = manager.get_peer(&addr).await.unwrap().missing_count;
        manager.note_idle_close(&addr).await;
        let after = manager.get_peer(&addr).await.unwrap().missing_count;
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn test_import_persisted_bans() {
        let manager = PeerManager::new(vec![]);
        let banned = [[1u8; 32], [2u8; 32]];
        assert_eq!(manager.import_persisted_bans(&banned).await, 2);
        assert!(manager.is_banned(&banned[0]).await);
        // Re-import is idempotent
        assert_eq!(manager.import_persisted_bans(&banned).await, 0);
    }

    #[test]
    fn test_backoff_computation() {
        let manager = PeerManager::new(vec![]);
        let b0 = manager.compute_backoff(0);
        let b1 = manager.compute_backoff(1);
        let b6 = manager.compute_backoff(6);
        let b12 = manager.compute_backoff(12);

        // Symmetric jitter +/-25%: [0.75 * base ..= 1.25 * base]
        assert!(b0.as_millis() >= (DEFAULT_BASE_BACKOFF_MS * 3 / 4) as u128);
        assert!(b0.as_millis() <= (DEFAULT_BASE_BACKOFF_MS * 5 / 4) as u128);
        assert!(b1.as_millis() >= (DEFAULT_BASE_BACKOFF_MS * 2 * 3 / 4) as u128);
        assert!(b1.as_millis() <= (DEFAULT_BASE_BACKOFF_MS * 2 * 5 / 4) as u128);
        assert!(b6.as_millis() <= (DEFAULT_MAX_BACKOFF_MS * 5 / 4) as u128);
        assert_eq!(
            b12.as_secs(),
            3600,
            "Attempt >= 12 must trigger 1h dormant cap"
        );
    }

    #[tokio::test]
    async fn test_debounced_record_failure() {
        let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let manager = PeerManager::new(vec![addr]);

        let t0 = Instant::now();
        manager.record_failure_at(addr, t0).await;
        assert_eq!(manager.get_peer(&addr).await.unwrap().missing_count, 1);

        // Rapid failures within 60s must not increase missing_count
        manager
            .record_failure_at(addr, t0 + Duration::from_secs(1))
            .await;
        manager
            .record_failure_at(addr, t0 + Duration::from_secs(15))
            .await;
        manager
            .record_failure_at(addr, t0 + Duration::from_secs(59))
            .await;
        assert_eq!(manager.get_peer(&addr).await.unwrap().missing_count, 1);

        // Failure after 60s increases missing_count to 2
        manager
            .record_failure_at(addr, t0 + Duration::from_secs(60))
            .await;
        assert_eq!(manager.get_peer(&addr).await.unwrap().missing_count, 2);
    }

    #[test]
    fn test_calculate_fan_out_biomimetic() {
        // Dorf: d=1 -> k=1
        assert_eq!(calculate_fan_out(0), 0);
        assert_eq!(calculate_fan_out(1), 1);
        assert_eq!(calculate_fan_out(2), 2);
        assert_eq!(calculate_fan_out(3), 3);
        // Standard-Node: d=16 -> k=5
        assert_eq!(calculate_fan_out(16), 5);
        // Large mesh hub: d=64 -> k=9
        assert_eq!(calculate_fan_out(64), 9);
    }

    #[tokio::test]
    async fn test_reset_peer_suspension_and_get_peer_rtt() {
        let addr: SocketAddr = "127.0.0.1:9095".parse().unwrap();
        let unknown_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let manager = PeerManager::new(vec![addr]);

        // Unknown peer returns Ok(false)
        assert_eq!(manager.reset_peer_suspension(unknown_addr).await, Ok(false));
        assert_eq!(manager.get_peer_rtt(unknown_addr).await, None);

        // Degrade peer
        let t0 = Instant::now();
        manager.record_failure_at(addr, t0).await;
        manager
            .record_failure_at(addr, t0 + Duration::from_secs(65))
            .await;
        manager
            .record_failure_at(addr, t0 + Duration::from_secs(130))
            .await;
        let peer = manager.get_peer(&addr).await.unwrap();
        assert_eq!(peer.missing_count, 3);
        assert_eq!(peer.status, PeerStatus::Suspended);

        // Reset suspension
        let res = manager.reset_peer_suspension(addr).await;
        assert_eq!(res, Ok(true));
        let peer_reset = manager.get_peer(&addr).await.unwrap();
        assert_eq!(peer_reset.missing_count, 0);
        assert_eq!(peer_reset.last_failure, None);
        // Connection is None, so status becomes Degrading
        assert_eq!(peer_reset.status, PeerStatus::Degrading);

        // Test with banned peer
        let banned_id = [42u8; 32];
        let banned_addr: SocketAddr = "127.0.0.1:9096".parse().unwrap();
        manager.add_peer(banned_addr).await;
        manager
            .record_success(banned_addr, Some(banned_id), None)
            .await;
        manager.ban_node(&banned_id).await;

        let banned_res = manager.reset_peer_suspension(banned_addr).await;
        assert!(banned_res.is_err());
        assert_eq!(
            banned_res.unwrap_err(),
            "Peer is permanently banned due to equivocation fraud"
        );
    }

    #[test]
    fn test_heartbeat_jitter_secs_safety_bounds() {
        // Enforces that heartbeat interval is in [3300, 3900] seconds (55..=65 min),
        // guaranteeing at least 300s (5 minutes) safety buffer above the 3000s (50 min)
        // heartbeat spam threshold (Fraud Pillar 3 / Spec 10 & 11).
        for _ in 0..1000 {
            let secs = PeerManager::heartbeat_jitter_secs();
            assert!(
                secs >= 3300,
                "Heartbeat interval must be >= 55 minutes (3300s), got {}",
                secs
            );
            assert!(
                secs <= 3900,
                "Heartbeat interval must be <= 65 minutes (3900s), got {}",
                secs
            );
        }
    }

    #[test]
    fn test_presence_freshness_timeout_exceeds_three_max_jitter_intervals() {
        // DEC-056: 3 consecutive missed hourly heartbeats lead to suspension.
        // With max jitter (65 min per interval = 3900s), 3 intervals take 3 * 3900s = 11,700s (3h 15m).
        // PRESENCE_FRESHNESS_SECS must be >= 11,700s to avoid prematurely marking honest nodes as stale.
        let three_max_jitter_intervals = 3 * 3900;
        assert!(
            PRESENCE_FRESHNESS_SECS >= three_max_jitter_intervals,
            "PRESENCE_FRESHNESS_SECS ({}) must accommodate 3 max-jitter intervals ({})",
            PRESENCE_FRESHNESS_SECS,
            three_max_jitter_intervals
        );
    }

    #[test]
    fn test_heartbeat_dedup_slotted_rate_limiting() {
        let mut cache = HeartbeatDedupCache::new(100);
        let node_a = [0x11u8; 32];
        let base_timestamp = 1_700_000_000_000u64; // arbitrary ms

        // Send 10 distinct heartbeats for node_a in the same minute slot (base_timestamp + 0..10)
        for i in 0..10 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            assert!(
                cache.check_and_insert_slotted(id, node_a, base_timestamp + i * 100),
                "Heartbeat {i} within burst limit of 10 should be accepted"
            );
        }

        // 11th heartbeat in the same minute slot from node_a must be dropped (flood protection)
        let mut id_11 = [0u8; 32];
        id_11[0] = 11;
        assert!(
            !cache.check_and_insert_slotted(id_11, node_a, base_timestamp + 1100),
            "11th heartbeat from same node in same minute slot must be dropped"
        );

        // A different node in the same minute slot can still send
        let node_b = [0x22u8; 32];
        assert!(
            cache.check_and_insert_slotted(id_11, node_b, base_timestamp + 1100),
            "Different node should not be affected by node_a rate limit"
        );

        // In the next minute slot (+60_000 ms), node_a can send again
        let next_minute = base_timestamp + 60_000;
        let mut id_next = [0u8; 32];
        id_next[0] = 12;
        assert!(
            cache.check_and_insert_slotted(id_next, node_a, next_minute),
            "Next minute slot must allow new heartbeats for node_a"
        );
    }

    #[tokio::test]
    async fn test_observe_verified_original_attestation_detects_equivocation() {
        use crate::identity::NodeIdentity;
        use ed25519_dalek::Signer;
        use humoco_sim_core::crypto::{
            compute_attestation_payload_digest, compute_sig_digest, HUMOCO_V1_APPROVE_PROV_MAINNET,
        };
        use humoco_sim_core::types::{Attestation, NetworkId, SimTime};

        let temp = tempfile::tempdir().unwrap();
        let db =
            Arc::new(crate::storage::RedbStorage::open(&temp.path().join("equiv.redb")).unwrap());
        let (engine, worker) = crate::storage::DualTierEngine::new(db.clone());
        let pm = Arc::new(PeerManager::new(vec![]));
        pm.set_storage(Arc::downgrade(&db));
        pm.set_engine(&engine);

        let signer = NodeIdentity::generate();
        let parent_lock = [0x55u8; 32];
        let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
        let node_id = signer.node_id_u16();

        let sign_vote = |lock_id: [u8; 32]| -> Attestation {
            let payload = compute_attestation_payload_digest(&parent_lock, &lock_id);
            let digest = compute_sig_digest(
                HUMOCO_V1_APPROVE_PROV_MAINNET,
                0,
                0,
                0,
                shard_id,
                0,
                &payload,
            );
            Attestation {
                lock_id,
                parent_lock,
                node_id,
                timestamp: SimTime(1000),
                signature: signer.signing_key().sign(&digest).to_bytes(),
                shard_id,
            }
        };

        let att1 = sign_vote([1u8; 32]);
        let att1_retry = sign_vote([1u8; 32]);
        let att2_conflict = sign_vote([2u8; 32]);

        // First vote: accepted, no fraud
        assert!(pm
            .observe_verified_original_attestation(*signer.node_pubkey(), att1, NetworkId::Mainnet,)
            .is_none());
        assert!(!db.is_node_banned(signer.node_pubkey()).unwrap());

        // Identical retry: accepted without fraud
        assert!(pm
            .observe_verified_original_attestation(
                *signer.node_pubkey(),
                att1_retry,
                NetworkId::Mainnet,
            )
            .is_none());
        assert!(!db.is_node_banned(signer.node_pubkey()).unwrap());

        // Conflicting vote on same parent_lock: detected as equivocation!
        let proof = pm
            .observe_verified_original_attestation(
                *signer.node_pubkey(),
                att2_conflict,
                NetworkId::Mainnet,
            )
            .expect("must detect equivocation");

        assert_eq!(proof.perpetrator_node_id, *signer.node_pubkey());
        assert!(db.is_node_banned(signer.node_pubkey()).unwrap());

        worker.abort();
        let _ = worker.await;
    }

    #[tokio::test]
    async fn test_multipath_edge_observations_and_df_domain() {
        let pm = PeerManager::new(Vec::new());
        let f1 = [10u8; 32];
        let f2 = [20u8; 32];
        let f1_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let f2_addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        pm.register_f2f_friend(f1, Some(f1_addr)).await;
        pm.register_f2f_friend(f2, Some(f2_addr)).await;

        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        let n1_addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let n2_addr: SocketAddr = "127.0.0.1:8002".parse().unwrap();

        let mut node1 = KnownNodeInfo::new(n1_addr, n1, n1);
        let mut node2 = KnownNodeInfo::new(n2_addr, n2, n2);
        let now = Instant::now();

        // Equal-distance: both F1 and F2 observe N1 at hops = 2
        node1.record_edge_observation(f1, 2, now);
        node1.record_edge_observation(f2, 2, now);

        // F1 observes N2 at hops = 1, F2 observes N2 at hops = 3 (F1 strictly shorter)
        node2.record_edge_observation(f1, 1, now);
        node2.record_edge_observation(f2, 3, now);

        {
            let mut nodes = pm.known_network_nodes.write().await;
            nodes.insert(n1, node1);
            nodes.insert(n2, node2);
        }

        let sectors = pm.compute_knotenfreund_sectors().await;
        let s_f1 = sectors
            .iter()
            .find(|s| s.friend_pubkey == hex::encode(f1))
            .unwrap();
        let s_f2 = sectors
            .iter()
            .find(|s| s.friend_pubkey == hex::encode(f2))
            .unwrap();

        // D(F1) contains N1 and N2 (both shortest observer)
        assert_eq!(s_f1.n_seen, 2);
        // D(F2) contains N1 (tied for shortest at hops=2), but not N2 (since F1 was shorter)
        assert_eq!(s_f2.n_seen, 1);
    }

    #[tokio::test]
    async fn test_sector_severity_bands_and_hysteresis() {
        let pm = PeerManager::new(Vec::new());
        let f1 = [99u8; 32];
        let f1_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        pm.register_f2f_friend(f1, Some(f1_addr)).await;

        let now = Instant::now();

        // Setup 10 tested nodes in D(F1) where 7 are bad (70% >= 6500 bps and bad >= 5)
        // This triggers raw_crit in the 5..15 band.
        {
            let mut nodes = pm.known_network_nodes.write().await;
            let mut peers = pm.peers.write().await;

            for i in 1..=10 {
                let pk = [i as u8; 32];
                let addr: SocketAddr = format!("127.0.0.{}:8000", i).parse().unwrap();
                let mut node = KnownNodeInfo::new(addr, pk, pk);
                node.record_edge_observation(f1, 2, now);
                nodes.insert(pk, node);

                let mut peer = PeerInfo::new(addr);
                peer.node_id = Some(pk);
                peer.last_rpc_tested_at = Some(now);
                if i <= 7 {
                    peer.missing_count = 3; // bad
                } else {
                    peer.missing_count = 0; // healthy
                }
                peers.insert(addr, peer);
            }
        }

        // First evaluation: raw_crit is true, but 30-min stability hysteresis suppresses to Warn
        let sectors1 = pm.compute_knotenfreund_sectors().await;
        let s1 = sectors1
            .iter()
            .find(|s| s.friend_pubkey == hex::encode(f1))
            .unwrap();
        assert_eq!(s1.n_tested, 10);
        assert_eq!(s1.n_bad, 7);
        assert_eq!(s1.severity, SectorSeverity::Warn);

        // Advance hysteresis timer by setting sector_anomaly_since 31 minutes ago
        {
            let mut hyst = pm.sector_anomaly_since.lock();
            hyst.insert(f1, now - Duration::from_secs(31 * 60));
        }

        // Second evaluation: hysteresis expired (>= 30 min) -> promotes to Crit
        let sectors2 = pm.compute_knotenfreund_sectors().await;
        let s2 = sectors2
            .iter()
            .find(|s| s.friend_pubkey == hex::encode(f1))
            .unwrap();
        assert_eq!(s2.severity, SectorSeverity::Crit);

        // Nodes recover (bad count drops to 0) -> severity drops to Ok and hysteresis clears
        {
            let mut peers = pm.peers.write().await;
            for peer in peers.values_mut() {
                peer.missing_count = 0;
            }
        }

        let sectors3 = pm.compute_knotenfreund_sectors().await;
        let s3 = sectors3
            .iter()
            .find(|s| s.friend_pubkey == hex::encode(f1))
            .unwrap();
        assert_eq!(s3.n_bad, 0);
        assert_eq!(s3.severity, SectorSeverity::Ok);
        assert!(!pm.sector_anomaly_since.lock().contains_key(&f1));
    }

    #[tokio::test]
    async fn test_liar_consistency_check_unlisted_hop1() {
        let pm = PeerManager::new(Vec::new());
        let f1 = [10u8; 32];
        let f1_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        pm.register_f2f_friend(f1, Some(f1_addr)).await;

        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        let n1_addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let n2_addr: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        let now = Instant::now();

        // Node 1 and Node 2 both observed with hops=1 from F1
        let mut node1 = KnownNodeInfo::new(n1_addr, n1, n1);
        node1.record_edge_observation(f1, 1, now);
        let mut node2 = KnownNodeInfo::new(n2_addr, n2, n2);
        node2.record_edge_observation(f1, 1, now);

        {
            let mut nodes = pm.known_network_nodes.write().await;
            nodes.insert(n1, node1);
            nodes.insert(n2, node2);
        }

        // Friend F1 shares roster claiming only N1 is a neighbor, with hidden_neighbor_count == 0
        let roster = crate::network::framing::F2fNeighborRosterPayload {
            sender_pubkey: f1,
            shares_roster: true,
            visible_neighbors: vec![n1],
            hidden_neighbor_count: 0,
            timestamp_ms: 1000,
        };
        pm.f2f_collab()
            .lock()
            .roster_mut()
            .record_roster(roster);

        let sectors = pm.compute_knotenfreund_sectors().await;
        let s = sectors
            .iter()
            .find(|s| s.friend_pubkey == hex::encode(f1))
            .unwrap();

        // N2 was observed at hop 1 from F1, but omitted from F1's visible_neighbors -> unlisted_hop1_count == 1
        assert_eq!(s.unlisted_hop1_count, 1);
        assert!(s.severity >= SectorSeverity::Warn);
    }

    #[tokio::test]
    async fn test_trace_analysis_pubkeys_counter_fact() {
        let pm = PeerManager::new(Vec::new());
        let f1 = [10u8; 32];
        let f1_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        pm.register_f2f_friend(f1, Some(f1_addr)).await;

        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        let n3 = [3u8; 32]; // unknown node
        let n1_addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let n2_addr: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        let now = Instant::now();

        let mut node1 = KnownNodeInfo::new(n1_addr, n1, n1);
        node1.record_edge_observation(f1, 1, now);
        let mut node2 = KnownNodeInfo::new(n2_addr, n2, n2);
        node2.record_edge_observation(f1, 2, now);

        {
            let mut nodes = pm.known_network_nodes.write().await;
            nodes.insert(n1, node1);
            nodes.insert(n2, node2);

            let mut peers = pm.peers.write().await;
            let mut p1 = PeerInfo::new(n1_addr);
            p1.node_id = Some(n1);
            p1.last_rpc_tested_at = Some(now);
            p1.missing_count = 0; // healthy
            peers.insert(n1_addr, p1);

            let mut p2 = PeerInfo::new(n2_addr);
            p2.node_id = Some(n2);
            p2.last_rpc_tested_at = Some(now);
            p2.missing_count = 3; // bad
            peers.insert(n2_addr, p2);
        }

        let report = pm.analyze_trace_pubkeys(&[n1, n2, n3]).await;
        assert_eq!(report.total_queried, 3);
        assert_eq!(report.unknown_count, 1);
        assert_eq!(report.locally_tested_healthy_count, 1);
        assert_eq!(report.locally_unreachable_count, 1);

        assert_eq!(report.by_knotenfreund.len(), 1);
        let hit = &report.by_knotenfreund[0];
        assert_eq!(hit.friend_pubkey, hex::encode(f1));
        assert_eq!(hit.hit_count, 2);
        assert_eq!(hit.min_hops, 1);
        assert_eq!(hit.exclusive_count, 2);
    }

    #[tokio::test]
    async fn test_quarantine_scenario_1_direct_defect_and_self_healing() {
        let f1 = [1u8; 32];
        let f2 = [2u8; 32];
        let f3 = [3u8; 32];
        let addr1: SocketAddr = "127.0.0.1:9101".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9102".parse().unwrap();
        let addr3: SocketAddr = "127.0.0.1:9103".parse().unwrap();

        let pm = PeerManager::with_f2f(
            vec![
                (Some(f1), addr1),
                (Some(f2), addr2),
                (Some(f3), addr3),
            ],
            vec![f1, f2, f3],
        );

        let t0 = Instant::now();
        pm.set_quarantine_policy(QuarantinePolicy {
            hop_wait_per_hop: Duration::from_secs(10),
            shadow_clean_window: Duration::from_secs(10),
            min_step_interval: Duration::from_secs(5),
            min_remaining_active_friends: 2,
            max_exclusive_strictly_healthy: 2,
        });

        // 1. Direct F2F friend f1 reaches missing_count == 3
        {
            let mut peers = pm.peers.write().await;
            let p1 = peers.get_mut(&addr1).unwrap();
            p1.missing_count = 3;
            p1.zombie_since = Some(t0);
            p1.status = PeerStatus::Suspended;
        }

        // 2. Evaluate quarantine at t0 -> immediately quarantines f1 (h = 0)
        let events = pm.evaluate_f2f_quarantine(t0).await;
        assert_eq!(
            events,
            vec![QuarantineEvent::Quarantined {
                friend_pk: f1,
                trigger_hops: 0,
            }]
        );
        assert!(pm.is_f2f_quarantined(&f1));
        assert!(!pm.is_f2f_quarantined(&f2));
        assert!(!pm.is_f2f_quarantined(&f3));

        // Active forwarding targets exclude f1
        let active_targets = pm.active_f2f_target_addrs().await;
        assert!(!active_targets.contains(&addr1));
        assert!(active_targets.contains(&addr2));
        assert!(active_targets.contains(&addr3));

        // 3. Shadow edge window: f1 recovers (peer decays/resets) and sends clean heartbeats at +3s and +6s
        {
            let mut peers = pm.peers.write().await;
            let p1 = peers.get_mut(&addr1).unwrap();
            p1.reset_suspension();
        }
        pm.record_shadow_heartbeat_sync(f1, false, t0 + Duration::from_secs(3));
        pm.record_shadow_heartbeat_sync(f1, false, t0 + Duration::from_secs(6));

        // At +8s (only 8s since quarantine), not yet healed
        let mid_events = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(8)).await;
        assert!(mid_events.is_empty());
        assert!(pm.is_f2f_quarantined(&f1));

        // 4. At +11s (>= 10s of clean window since t0), heals automatically!
        let heal_events = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(11)).await;
        assert_eq!(heal_events, vec![QuarantineEvent::Healed { friend_pk: f1 }]);
        assert!(!pm.is_f2f_quarantined(&f1));

        // Once healed, f1 is included back into active forward targets
        let restored_targets = pm.active_f2f_target_addrs().await;
        assert!(restored_targets.contains(&addr1));
    }

    #[tokio::test]
    async fn test_quarantine_scenario_2_double_neighbor_trap_s3() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let m1 = [3u8; 32];
        let m2 = [4u8; 32];
        let addr_h1: SocketAddr = "127.0.0.1:9201".parse().unwrap();
        let addr_h2: SocketAddr = "127.0.0.1:9202".parse().unwrap();
        let addr_m1: SocketAddr = "127.0.0.1:9203".parse().unwrap();
        let addr_m2: SocketAddr = "127.0.0.1:9204".parse().unwrap();

        let pm = PeerManager::with_f2f(
            vec![
                (Some(h1), addr_h1),
                (Some(h2), addr_h2),
                (Some(m1), addr_m1),
                (Some(m2), addr_m2),
            ],
            vec![h1, h2, m1, m2],
        );

        let t0 = Instant::now();
        pm.set_quarantine_policy(QuarantinePolicy {
            hop_wait_per_hop: Duration::from_secs(10),
            shadow_clean_window: Duration::from_secs(100),
            min_step_interval: Duration::from_secs(5),
            min_remaining_active_friends: 2,
            max_exclusive_strictly_healthy: 2,
        });

        // Malicious feeder m1 observes zombie Z1 at hop 1
        // Malicious feeder m2 observes zombie Z2 at hop 1
        let z1 = [11u8; 32];
        let z2 = [12u8; 32];
        let z1_addr: SocketAddr = "127.0.0.1:9211".parse().unwrap();
        let z2_addr: SocketAddr = "127.0.0.1:9212".parse().unwrap();

        {
            let mut nodes = pm.known_network_nodes.write().await;
            let mut info1 = KnownNodeInfo::new(z1_addr, z1, z1);
            info1.record_edge_observation(m1, 1, t0);
            nodes.insert(z1, info1);

            let mut info2 = KnownNodeInfo::new(z2_addr, z2, z2);
            info2.record_edge_observation(m2, 1, t0);
            nodes.insert(z2, info2);

            let mut peers = pm.peers.write().await;
            let mut p_z1 = PeerInfo::new(z1_addr);
            p_z1.node_id = Some(z1);
            p_z1.missing_count = 3;
            p_z1.zombie_since = Some(t0);
            peers.insert(z1_addr, p_z1);

            let mut p_z2 = PeerInfo::new(z2_addr);
            p_z2.node_id = Some(z2);
            p_z2.missing_count = 3;
            p_z2.zombie_since = Some(t0);
            peers.insert(z2_addr, p_z2);
        }

        // Before maturation (t0 + 5s < 10s wait): no quarantine
        let ev0 = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(5)).await;
        assert!(ev0.is_empty());

        // Step 1: At t0 + 10s (mature at h = 1), active = 4 -> quarantines first feeder
        let ev1 = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(10)).await;
        assert_eq!(ev1.len(), 1);
        let first_quarantined = match &ev1[0] {
            QuarantineEvent::Quarantined { friend_pk, trigger_hops } => {
                assert_eq!(*trigger_hops, 1);
                *friend_pk
            }
            _ => panic!("Expected Quarantined event"),
        };
        assert!(first_quarantined == m1 || first_quarantined == m2);

        // Before min_step_interval (t0 + 12s < 10s + 5s): calm cadence throttles step 2
        let ev_throttled = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(12)).await;
        assert!(ev_throttled.is_empty());

        // Step 2: At t0 + 16s (past min_step_interval), active = 3 -> quarantines second feeder
        let ev2 = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(16)).await;
        assert_eq!(ev2.len(), 1);
        let second_quarantined = match &ev2[0] {
            QuarantineEvent::Quarantined { friend_pk, trigger_hops } => {
                assert_eq!(*trigger_hops, 1);
                *friend_pk
            }
            _ => panic!("Expected Quarantined event"),
        };
        assert!(second_quarantined == m1 || second_quarantined == m2);
        assert_ne!(first_quarantined, second_quarantined);

        // Both feeders are now quarantined!
        assert!(pm.is_f2f_quarantined(&m1));
        assert!(pm.is_f2f_quarantined(&m2));

        // Active friends count is now 2 (the honest friends h1, h2).
        // At t0 + 25s: active == 2 == min_remaining_active_friends -> honest friends are NEVER cut!
        let ev3 = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(25)).await;
        assert!(ev3.is_empty());
        assert!(!pm.is_f2f_quarantined(&h1));
        assert!(!pm.is_f2f_quarantined(&h2));
    }

    #[tokio::test]
    async fn test_quarantine_scenario_3_hop_inflation_resistance() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let a1 = [3u8; 32];
        let a2 = [4u8; 32];
        let addr_h1: SocketAddr = "127.0.0.1:9301".parse().unwrap();
        let addr_h2: SocketAddr = "127.0.0.1:9302".parse().unwrap();
        let addr_a1: SocketAddr = "127.0.0.1:9303".parse().unwrap();
        let addr_a2: SocketAddr = "127.0.0.1:9304".parse().unwrap();

        let pm = PeerManager::with_f2f(
            vec![
                (Some(h1), addr_h1),
                (Some(h2), addr_h2),
                (Some(a1), addr_a1),
                (Some(a2), addr_a2),
            ],
            vec![h1, h2, a1, a2],
        );

        let t0 = Instant::now();
        pm.set_quarantine_policy(QuarantinePolicy {
            hop_wait_per_hop: Duration::from_secs(10), // T(5) = 50s, T(12) = 120s
            shadow_clean_window: Duration::from_secs(1000),
            min_step_interval: Duration::from_secs(5),
            min_remaining_active_friends: 2,
            max_exclusive_strictly_healthy: 2,
        });

        // a1 feeds zombie z1 spoofed at hop 5
        // a2 feeds zombie z2 spoofed at hop 12
        let z1 = [21u8; 32];
        let z2 = [22u8; 32];
        let z1_addr: SocketAddr = "127.0.0.1:9321".parse().unwrap();
        let z2_addr: SocketAddr = "127.0.0.1:9322".parse().unwrap();

        {
            let mut nodes = pm.known_network_nodes.write().await;
            let mut info1 = KnownNodeInfo::new(z1_addr, z1, z1);
            info1.record_edge_observation(a1, 5, t0);
            nodes.insert(z1, info1);

            let mut info2 = KnownNodeInfo::new(z2_addr, z2, z2);
            info2.record_edge_observation(a2, 12, t0);
            nodes.insert(z2, info2);

            let mut peers = pm.peers.write().await;
            let mut p_z1 = PeerInfo::new(z1_addr);
            p_z1.node_id = Some(z1);
            p_z1.missing_count = 3;
            p_z1.zombie_since = Some(t0);
            peers.insert(z1_addr, p_z1);

            let mut p_z2 = PeerInfo::new(z2_addr);
            p_z2.node_id = Some(z2);
            p_z2.missing_count = 3;
            p_z2.zombie_since = Some(t0);
            peers.insert(z2_addr, p_z2);
        }

        // At +30s: neither is mature (30s < 50s and 30s < 120s)
        assert!(pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(30)).await.is_empty());

        // At +55s: z1 (hop 5) is mature (55s >= 50s), z2 (hop 12) is not (55s < 120s)
        let ev1 = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(55)).await;
        assert_eq!(
            ev1,
            vec![QuarantineEvent::Quarantined {
                friend_pk: a1,
                trigger_hops: 5,
            }]
        );
        assert!(pm.is_f2f_quarantined(&a1));
        assert!(!pm.is_f2f_quarantined(&a2));

        // At +125s: z2 (hop 12) is now mature (125s >= 120s)
        let ev2 = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(125)).await;
        assert_eq!(
            ev2,
            vec![QuarantineEvent::Quarantined {
                friend_pk: a2,
                trigger_hops: 12,
            }]
        );
        assert!(pm.is_f2f_quarantined(&a2));

        // 100% quarantined despite extreme hop inflation!
        assert!(!pm.is_f2f_quarantined(&h1));
        assert!(!pm.is_f2f_quarantined(&h2));
    }

    #[tokio::test]
    async fn test_quarantine_scenario_4_bridge_protection() {
        let f_bridge = [1u8; 32];
        let f2 = [2u8; 32];
        let f3 = [3u8; 32];
        let addr_b: SocketAddr = "127.0.0.1:9401".parse().unwrap();
        let addr_2: SocketAddr = "127.0.0.1:9402".parse().unwrap();
        let addr_3: SocketAddr = "127.0.0.1:9403".parse().unwrap();

        let pm = PeerManager::with_f2f(
            vec![
                (Some(f_bridge), addr_b),
                (Some(f2), addr_2),
                (Some(f3), addr_3),
            ],
            vec![f_bridge, f2, f3],
        );

        let t0 = Instant::now();
        pm.set_quarantine_policy(QuarantinePolicy {
            hop_wait_per_hop: Duration::from_secs(10),
            shadow_clean_window: Duration::from_secs(100),
            min_step_interval: Duration::from_secs(5),
            min_remaining_active_friends: 2,
            max_exclusive_strictly_healthy: 2, // Bridge protection threshold
        });

        // Over f_bridge, there is a mature zombie at hop 1
        let z = [9u8; 32];
        let z_addr: SocketAddr = "127.0.0.1:9409".parse().unwrap();
        {
            let mut nodes = pm.known_network_nodes.write().await;
            let mut info_z = KnownNodeInfo::new(z_addr, z, z);
            info_z.record_edge_observation(f_bridge, 1, t0);
            nodes.insert(z, info_z);

            // And 3 strictly healthy nodes exclusively reachable via f_bridge
            for i in 1..=3 {
                let k_pk = [10 + i; 32];
                let k_addr: SocketAddr = format!("127.0.0.1:941{i}").parse().unwrap();
                let mut info_k = KnownNodeInfo::new(k_addr, k_pk, k_pk);
                info_k.record_edge_observation(f_bridge, 1, t0);
                nodes.insert(k_pk, info_k);
            }

            let mut peers = pm.peers.write().await;
            let mut p_z = PeerInfo::new(z_addr);
            p_z.node_id = Some(z);
            p_z.missing_count = 3;
            p_z.zombie_since = Some(t0);
            peers.insert(z_addr, p_z);
            // Notice: the 3 strictly healthy nodes have no failure entries in peers (missing_count == 0)
        }

        // At +15s (past maturation of hop 1):
        // f_bridge has n_exclusive_strictly_healthy = 3 (> max 2).
        // Bridge protection kicks in: f_bridge is NEVER quarantined!
        let ev = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(15)).await;
        assert!(ev.is_empty());
        assert!(!pm.is_f2f_quarantined(&f_bridge));
    }

    #[tokio::test]
    async fn test_quarantine_scenario_5_preemption_at_limit() {
        let f1 = [1u8; 32];
        let f2 = [2u8; 32];
        let f_far = [3u8; 32];
        let addr1: SocketAddr = "127.0.0.1:9501".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9502".parse().unwrap();
        let addr_far: SocketAddr = "127.0.0.1:9503".parse().unwrap();

        let pm = PeerManager::with_f2f(
            vec![
                (Some(f1), addr1),
                (Some(f2), addr2),
                (Some(f_far), addr_far),
            ],
            vec![f1, f2, f_far],
        );

        let t0 = Instant::now();
        pm.set_quarantine_policy(QuarantinePolicy {
            hop_wait_per_hop: Duration::from_secs(10),
            shadow_clean_window: Duration::from_secs(100),
            min_step_interval: Duration::from_secs(5),
            min_remaining_active_friends: 2, // Limit is 2
            max_exclusive_strictly_healthy: 2,
        });

        // Suppose f_far is currently quarantined with trigger_hops = 3
        {
            let mut state = pm.quarantine_state.write();
            state.quarantined_f2f_edges.insert(
                f_far,
                QuarantinedEdgeState::new(t0, 3),
            );
            state.last_quarantine_step_at = Some(t0);
        }
        assert!(pm.is_f2f_quarantined(&f_far));
        // Active friends count is currently 2 (f1 and f2)

        // Now f1 has a mature zombie at hop 1
        let z = [88u8; 32];
        let z_addr: SocketAddr = "127.0.0.1:9588".parse().unwrap();
        {
            let mut nodes = pm.known_network_nodes.write().await;
            let mut info_z = KnownNodeInfo::new(z_addr, z, z);
            info_z.record_edge_observation(f1, 1, t0);
            nodes.insert(z, info_z);

            let mut peers = pm.peers.write().await;
            let mut p_z = PeerInfo::new(z_addr);
            p_z.node_id = Some(z);
            p_z.missing_count = 3;
            p_z.zombie_since = Some(t0);
            peers.insert(z_addr, p_z);
        }

        // At +15s (past min_step_interval and mature):
        // active == 2, so cannot quarantine without dropping to 1.
        // But f_far has trigger_hops = 3 > 1!
        // Preemption executes: releases f_far, quarantines f1!
        let ev = pm.evaluate_f2f_quarantine(t0 + Duration::from_secs(15)).await;
        assert_eq!(
            ev,
            vec![QuarantineEvent::Preempted {
                released_friend_pk: f_far,
                quarantined_friend_pk: f1,
                trigger_hops: 1,
            }]
        );

        assert!(!pm.is_f2f_quarantined(&f_far));
        assert!(pm.is_f2f_quarantined(&f1));
        assert!(!pm.is_f2f_quarantined(&f2));
    }

    #[tokio::test]
    async fn test_quarantine_scenario_6_ingress_dedup_poisoning_protection() {
        let f_quarantined = [1u8; 32];
        let f_honest = [2u8; 32];
        let addr_q: SocketAddr = "127.0.0.1:9601".parse().unwrap();
        let addr_h: SocketAddr = "127.0.0.1:9602".parse().unwrap();

        let pm = PeerManager::with_f2f(
            vec![
                (Some(f_quarantined), addr_q),
                (Some(f_honest), addr_h),
            ],
            vec![f_quarantined, f_honest],
        );

        let t0 = Instant::now();
        // Mark f_quarantined as quarantined
        {
            let mut state = pm.quarantine_state.write();
            state.quarantined_f2f_edges.insert(
                f_quarantined,
                QuarantinedEdgeState::new(t0, 1),
            );
        }
        assert!(pm.is_f2f_quarantined(&f_quarantined));

        let attacker_hb_origin = [99u8; 32];

        // When a heartbeat arrives over f_quarantined, transport routes it to record_shadow_heartbeat
        // instead of check_and_record_heartbeat!
        // Here we verify the invariant:
        pm.record_shadow_heartbeat(f_quarantined, attacker_hb_origin, 1, t0).await;

        // 1. Quarantined edge shadow window received the heartbeat
        let edges = pm.quarantined_f2f_edges();
        let q_state = edges.get(&f_quarantined).unwrap();
        assert_eq!(q_state.shadow_last_seen, Some(t0));

        // 2. The active deduplication cache was NOT touched by the quarantined edge!
        // When honest friend f_honest delivers the authentic heartbeat for attacker_hb_origin,
        // it is NOT considered duplicate and passes successfully!
        let is_fresh = pm.check_and_record_heartbeat(&attacker_hb_origin, 12345, 1000).await;
        assert!(is_fresh, "Honest delivery must NOT be blocked by quarantined peer attempt");

        // 3. Forward targets strictly exclude f_quarantined
        let forward_targets = pm.active_f2f_target_addrs().await;
        assert!(!forward_targets.contains(&addr_q));
        assert!(forward_targets.contains(&addr_h));
    }

    #[tokio::test]
    async fn test_quarantine_scenario_7_shadow_heartbeat_zombie_detection() {
        let f_quarantined = [10u8; 32];
        let addr_q: SocketAddr = "127.0.0.1:9701".parse().unwrap();
        let z_direct_f2f = [20u8; 32];
        let addr_z_f2f: SocketAddr = "127.0.0.1:9702".parse().unwrap();
        let z_network = [30u8; 32];
        let addr_z_net: SocketAddr = "127.0.0.1:9703".parse().unwrap();
        let clean_node = [40u8; 32];
        let addr_clean: SocketAddr = "127.0.0.1:9704".parse().unwrap();

        let pm = PeerManager::with_f2f(
            vec![
                (Some(f_quarantined), addr_q),
                (Some(z_direct_f2f), addr_z_f2f),
            ],
            vec![f_quarantined, z_direct_f2f],
        );

        let t0 = Instant::now();
        {
            let mut state = pm.quarantine_state.write();
            state.quarantined_f2f_edges.insert(
                f_quarantined,
                QuarantinedEdgeState::new(t0, 1),
            );
        }

        // Direct F2F zombie: peer at addr_z_f2f has zombie_since set (node_id not set on peer struct directly)
        {
            let mut peers = pm.peers.write().await;
            let mut p_f2f = PeerInfo::new(addr_z_f2f);
            p_f2f.missing_count = 3;
            p_f2f.zombie_since = Some(t0);
            peers.insert(addr_z_f2f, p_f2f);

            // Network zombie: known_network_nodes maps z_network -> addr_z_net
            let mut p_net = PeerInfo::new(addr_z_net);
            p_net.missing_count = 3;
            p_net.zombie_since = Some(t0);
            peers.insert(addr_z_net, p_net);

            // Clean node
            let mut p_clean = PeerInfo::new(addr_clean);
            p_clean.missing_count = 0;
            peers.insert(addr_clean, p_clean);
        }
        {
            let mut known = pm.known_network_nodes.write().await;
            known.insert(z_network, KnownNodeInfo::new(addr_z_net, z_network, z_network));
            known.insert(clean_node, KnownNodeInfo::new(addr_clean, clean_node, clean_node));
        }

        // 1. Clean heartbeat arrives at +2s
        let t1 = t0 + Duration::from_secs(2);
        pm.record_shadow_heartbeat(f_quarantined, clean_node, 1, t1).await;
        {
            let q_state = pm.quarantined_f2f_edges().get(&f_quarantined).cloned().unwrap();
            assert_eq!(q_state.clean_heartbeats_seen, 1);
            assert_eq!(q_state.last_zombie_shadow_seen, t0); // unchanged
        }

        // 2. Direct F2F zombie heartbeat arrives at +4s (resolved via f2f_friends -> addr -> peers)
        let t2 = t0 + Duration::from_secs(4);
        pm.record_shadow_heartbeat(f_quarantined, z_direct_f2f, 1, t2).await;
        {
            let q_state = pm.quarantined_f2f_edges().get(&f_quarantined).cloned().unwrap();
            assert_eq!(q_state.clean_heartbeats_seen, 1);
            assert_eq!(q_state.last_zombie_shadow_seen, t2); // updated to t2!
        }

        // 3. Known network zombie heartbeat arrives at +7s (resolved via known_network_nodes -> addr -> peers)
        let t3 = t0 + Duration::from_secs(7);
        pm.record_shadow_heartbeat(f_quarantined, z_network, 1, t3).await;
        {
            let q_state = pm.quarantined_f2f_edges().get(&f_quarantined).cloned().unwrap();
            assert_eq!(q_state.clean_heartbeats_seen, 1);
            assert_eq!(q_state.last_zombie_shadow_seen, t3); // updated to t3!
        }
    }

    #[tokio::test]
    async fn test_quarantine_scenario_8_hourly_decay_preserves_conviction_and_prevents_oscillation() {
        // Setup a node with 2 honest friends (h1, h2) + 1 malicious feeder M
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let m = [3u8; 32];
        let addr_h1: SocketAddr = "127.0.0.1:9301".parse().unwrap();
        let addr_h2: SocketAddr = "127.0.0.1:9302".parse().unwrap();
        let addr_m: SocketAddr = "127.0.0.1:9303".parse().unwrap();

        let pm = PeerManager::with_f2f(
            vec![
                (Some(h1), addr_h1),
                (Some(h2), addr_h2),
                (Some(m), addr_m),
            ],
            vec![h1, h2, m],
        );

        // QuarantinePolicy defaults:
        // hop_wait_per_hop = 3h -> T(2) = 6h maturation delay
        // shadow_clean_window = 3h
        // min_step_interval = 1h
        // min_remaining_active_friends = 2
        let policy = pm.quarantine_policy();
        assert_eq!(policy.hop_wait_duration(2), Duration::from_secs(6 * 3600));
        assert_eq!(policy.shadow_clean_window, Duration::from_secs(3 * 3600));

        // Behind M sits zombie Z at distance h = 2
        let z = [99u8; 32];
        let z_addr: SocketAddr = "127.0.0.1:9399".parse().unwrap();

        let t0 = Instant::now();

        // At t0: Z reaches 3 failures and is convicted as a zombie (zombie_since = Some(t0))
        {
            let mut nodes = pm.known_network_nodes.write().await;
            let mut info_z = KnownNodeInfo::new(z_addr, z, z);
            info_z.record_edge_observation(m, 2, t0);
            nodes.insert(z, info_z);

            let mut peers = pm.peers.write().await;
            let mut p_z = PeerInfo::new(z_addr);
            p_z.node_id = Some(z);
            p_z.missing_count = 3;
            p_z.zombie_since = Some(t0);
            p_z.status = PeerStatus::Suspended;
            peers.insert(z_addr, p_z);
        }

        // Simulate realistically each hour t = 1h, 2h, 3h, 4h, 5h, 6h:
        // Hourly decay_all_peers_at(t0 + h) decrements missing_count (dropping to 0 by hour 3),
        // but zombie_since remains active because Z never performed authentic shard work!
        for h in 1..=5 {
            let t = t0 + Duration::from_secs(h * 3600);
            let events = pm.decay_all_peers_at(t).await;
            assert!(events.is_empty(), "Hour {}: should not quarantine before 6h maturation", h);
            assert!(!pm.is_f2f_quarantined(&m));
        }

        // At hour 5, verify that Z.missing_count is 0 but Z.zombie_since is still Some(t0)
        {
            let peers = pm.peers.read().await;
            let p_z = peers.get(&z_addr).unwrap();
            assert_eq!(p_z.missing_count, 0);
            assert_eq!(p_z.zombie_since, Some(t0));
        }

        // At t = 6h: Maturation delay T(2) = 6h is reached -> M is reliably quarantined!
        let t6 = t0 + Duration::from_secs(6 * 3600);
        let events6 = pm.decay_all_peers_at(t6).await;
        assert_eq!(
            events6,
            vec![QuarantineEvent::Quarantined {
                friend_pk: m,
                trigger_hops: 2,
            }]
        );
        assert!(pm.is_f2f_quarantined(&m));

        // Simulate further hours t = 7h .. 14h (8 additional hours with hourly decay_all_peers_at
        // + hourly record_shadow_heartbeat of Z via M):
        // M must stay continuously quarantined with ZERO oscillation or spurious healing alarms!
        for h in 7..=14 {
            let t = t0 + Duration::from_secs(h * 3600);
            pm.record_shadow_heartbeat(m, z, 2, t).await;
            let events = pm.decay_all_peers_at(t).await;
            assert!(
                events.is_empty(),
                "Hour {}: M must not trigger events or spurious healing while Z remains a zombie",
                h
            );
            assert!(
                pm.is_f2f_quarantined(&m),
                "Hour {}: M must remain continuously quarantined",
                h
            );
        }

        // Counter-test: Honest peer Z proves authentic shard work via mark_shard_work_success()
        {
            let mut peers = pm.peers.write().await;
            let p_z = peers.get_mut(&z_addr).unwrap();
            p_z.mark_shard_work_success();
            assert_eq!(p_z.zombie_since, None);
        }

        // Now simulate 3 clean shadow hours without zombie defects:
        // Hour 15 (1h clean): not yet healed (1h < 3h clean window)
        let t15 = t0 + Duration::from_secs(15 * 3600);
        pm.record_shadow_heartbeat(m, z, 2, t15).await;
        let events15 = pm.decay_all_peers_at(t15).await;
        assert!(events15.is_empty());
        assert!(pm.is_f2f_quarantined(&m));

        // Hour 16 (2h clean): not yet healed (2h < 3h clean window)
        let t16 = t0 + Duration::from_secs(16 * 3600);
        pm.record_shadow_heartbeat(m, z, 2, t16).await;
        let events16 = pm.decay_all_peers_at(t16).await;
        assert!(events16.is_empty());
        assert!(pm.is_f2f_quarantined(&m));

        // Hour 17 (3h clean): reached shadow_clean_window (3h >= 3h) -> heals back to Active!
        let t17 = t0 + Duration::from_secs(17 * 3600);
        pm.record_shadow_heartbeat(m, z, 2, t17).await;
        let events17 = pm.decay_all_peers_at(t17).await;
        assert_eq!(
            events17,
            vec![QuarantineEvent::Healed { friend_pk: m }]
        );
        assert!(!pm.is_f2f_quarantined(&m));

        // Restored to active target addresses
        let targets = pm.active_f2f_target_addrs().await;
        assert!(targets.contains(&addr_m));
    }
}
