use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fmt;
use std::ops::{Add, AddAssign, Sub};

/// 32-Byte Hash (BLAKE3 Digest)
pub type Hash256 = [u8; 32];

/// Unique identifier of a lock entry (32-byte hash)
pub type LockId = Hash256;

/// Node identifier for lightweight simulation (0..65535)
pub type NodeId = u16;

/// Shard Identifier (0..65535)
pub type ShardId = u16;

/// Ed25519 public key — permanent identity of a node (32 bytes)
pub type NodePubKey = [u8; 32];

/// Argon2d shard ticket — HRW routing identifier of a node (32 bytes, mined via Argon2d)
pub type HrwRoutingId = [u8; 32];

/// Network identifier for domain separation (Mainnet vs Testnet)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
pub enum NetworkId {
    #[default]
    Mainnet,
    Testnet,
}

/// Crypto suite identifier for backward-compatible wire headers & LockEnvelope
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoSuiteId {
    Ed25519Blake3 = 1,
    HybridEd25519MlDsa = 2,
    PureMlDsa = 3,
}

impl CryptoSuiteId {
    /// 0x00 is transparently interpreted as suite 1 (Ed25519/BLAKE3) (backward-compatible)
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Ed25519Blake3,
            1 => Self::Ed25519Blake3,
            2 => Self::HybridEd25519MlDsa,
            3 => Self::PureMlDsa,
            _ => Self::Ed25519Blake3,
        }
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// 4-byte piggyback bitmask: bit i indicates response from the i-th candidate (among top-20)
pub type SignersBitmask = u32;

/// Failure threshold: after how many consecutive failures a node is suspended
pub const MISSING_COUNT_THRESHOLD: u32 = 3;

pub const FLAG_INBOUND_ACTIVE: u8 = 1 << 0;
pub const FLAG_LAST_FAILED: u8 = 1 << 1;

/// Deterministic discrete simulation time in milliseconds
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, serde::Serialize, serde::Deserialize)]
pub struct SimTime(pub u64);

impl SimTime {
    pub const ZERO: SimTime = SimTime(0);

    pub fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    pub fn as_millis(&self) -> u64 {
        self.0
    }
}

impl Add<u64> for SimTime {
    type Output = SimTime;
    fn add(self, rhs: u64) -> Self::Output {
        SimTime(self.0 + rhs)
    }
}

impl AddAssign<u64> for SimTime {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Sub for SimTime {
    type Output = u64;
    fn sub(self, rhs: Self) -> Self::Output {
        self.0.saturating_sub(rhs.0)
    }
}

impl fmt::Display for SimTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// ARCHITECTURAL INVARIANT / AUDIT NOTE (Spec 02, 08):
/// Consensus Finality Thresholds:
/// - N < 20: Provisional (yellow, Q = floor(2R/3) + 1).
/// - N >= 20: Final (green, 14/20 BFT threshold after 24h hysteresis).
/// - High-Assurance (16/20 @ N>=100) was evaluated in `spec_widerspruchs_analyse.md`
///   and INTENTIONALLY OMITTED to keep POS terminals and wallets simple (KISS).
///
/// Maturity traffic light & lifecycle states of a lock entry
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LockStatus {
    /// Initial ingress state (no quorum reached yet)
    Pending,
    /// Yellow: local island quorum reached (N < 20)
    Provisional { sigs: usize, required: usize },
    /// Green: global quorum reached (N >= 20 with >= 14 signatures)
    Final { sigs: usize },
    /// Red / neutralized: loser in split-brain or equivocation
    Void { reason: String },
    /// Validity expired (valid_until reached)
    Expired,
}

impl LockStatus {
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            LockStatus::Provisional { .. } | LockStatus::Final { .. }
        )
    }

    pub fn is_final(&self) -> bool {
        matches!(self, LockStatus::Final { .. })
    }

    pub fn is_void(&self) -> bool {
        matches!(self, LockStatus::Void { .. })
    }
}

/// The universal lock entry in HuMoCo Layer-2
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockRecord {
    pub id: LockId,
    pub parent_lock: Hash256,
    pub receiver_pub: Hash256,
    pub nonce: Vec<u8>,
    pub created_at: SimTime,
    pub valid_until: SimTime,
    pub status: LockStatus,
    pub signers: BTreeSet<NodeId>,
}

impl LockRecord {
    pub fn new(
        parent_lock: Hash256,
        receiver_pub: Hash256,
        nonce: Vec<u8>,
        created_at: SimTime,
        valid_until: SimTime,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        let tag = b"HUMOCO_V1_LOCK_ID";
        hasher.update(&[tag.len() as u8]);
        hasher.update(tag);
        hasher.update(&parent_lock);
        hasher.update(&receiver_pub);
        hasher.update(&nonce);
        hasher.update(&created_at.0.to_le_bytes());
        hasher.update(&valid_until.0.to_le_bytes());
        let id: Hash256 = *hasher.finalize().as_bytes();

        Self {
            id,
            parent_lock,
            receiver_pub,
            nonce,
            created_at,
            valid_until,
            status: LockStatus::Pending,
            signers: BTreeSet::new(),
        }
    }
}

/// Signed attestation from a shard node for a lock
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attestation {
    pub lock_id: LockId,
    pub parent_lock: Hash256,
    pub node_id: NodeId,
    pub timestamp: SimTime,
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

pub mod serde_bytes_64 {
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array of length 64")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v.len() == 64 {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(v);
                    Ok(arr)
                } else {
                    Err(E::custom(format!("expected 64 bytes, got {}", v.len())))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for item in &mut arr {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| Error::custom("expected 64 elements"))?;
                }
                Ok(arr)
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

/// Computes the required quorum based on the number of active nodes N
/// Formel (docs/02 & docs/08):
/// - N < 20: Q(N) = floor(2/3 * N) + 1  -> Status PROVISIONAL
/// - N >= 20: Q(N) = 14                 -> Status FINAL
pub fn required_quorum(active_nodes: usize) -> (usize, bool) {
    if active_nodes == 0 {
        return (0, false);
    }
    if active_nodes < 20 {
        let q = (2 * active_nodes) / 3 + 1;
        (q, false)
    } else {
        (14, true)
    }
}

/// Synchronization state of a node with respect to global network knowledge (docs/07)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeSyncStatus {
    /// Knowledge deficit (gossip lag or initial sync)
    Syncing,
    /// Fully synchronized for sharding quorums
    InSync,
}

/// New term: topological horizon status of a node (docs/07:3 & docs/08)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeHorizonStatus {
    /// Horizon expanding (gossip lag or initial sync) -> lock = PROVISIONAL
    Expanding,
    /// Horizon converged with median (>= 95%) -> lock = FINAL
    Converged,
}

impl From<NodeSyncStatus> for NodeHorizonStatus {
    fn from(s: NodeSyncStatus) -> Self {
        match s {
            NodeSyncStatus::Syncing => NodeHorizonStatus::Expanding,
            NodeSyncStatus::InSync => NodeHorizonStatus::Converged,
        }
    }
}

/// Peer presence state of a remote node in 24h gossip (docs/07:3)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerPresenceState {
    /// Newcomer in 24h incubation phase (< 24h or < 8/24 heartbeats)
    Immature,
    /// Fully active consensus node (>= 8/24 heartbeats)
    Active,
    /// Failed / offline for > 21-24h (popcount <= 3 of 24)
    Dormant,
}

/// 16-byte compact RAM index entry for known peers (docs/11:pillar 3)
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerPresenceEntry {
    pub node_id_prefix: u64,
    pub hourly_bitmask: u32,
    pub malus_score: u8,
    pub maturity_hours: u8,
    pub flags: u8,
    pub backoff_level: u8,
}

impl PeerPresenceEntry {
    pub fn new(prefix: u64, current_epoch: u16) -> Self {
        let _ = current_epoch;
        Self {
            node_id_prefix: prefix,
            hourly_bitmask: 1, // Erstes Bit gesetzt
            malus_score: 0,
            maturity_hours: 0,
            flags: 0,
            backoff_level: 0,
        }
    }

    /// Records inbound service activity (e.g. Ingress Lock, Read query, Sync request) – sets FLAG_INBOUND_ACTIVE.
    pub fn record_inbound_activity(&mut self) {
        self.flags |= FLAG_INBOUND_ACTIVE;
    }

    /// Records an outbound failure / timeout:
    /// - Normal mode (`is_under_stress == false`): `+2` malus points (`backoff_level = (malus / 2).min(17)`).
    /// - Stress mode (`is_under_stress == true`): `+1` malus point (halved penalty for reflexive negative feedback cooling).
    ///
    /// ### 🛡️ Circuit Breaker & 40% Homeostasis:
    /// When the entire network is under heavy DDoS/stress and >= 40% of responses are choked,
    /// nodes switch to the damped `+1 / -2` mode. In this mode, forgiveness dominates:
    /// `E[ΔMalus] < 0` for failure rates up to 66.7%, causing peer accusations to cool down
    /// and stabilizing the network around the 40% equilibrium without cascading death spirals.
    ///
    /// Symmetrical `+2 / -2` tit-for-tat with activity escalation lock when offline/DDoS.
    pub fn record_outbound_failure_damped(&mut self, is_under_stress: bool) -> u8 {
        self.flags |= FLAG_LAST_FAILED;
        let increment = if is_under_stress { 1 } else { 2 };
        // Escalation only if inbound was active OR first failure (backoff == 0)
        if (self.flags & FLAG_INBOUND_ACTIVE) != 0 || self.backoff_level == 0 {
            self.malus_score = self.malus_score.saturating_add(increment);
            self.backoff_level = (self.malus_score / 2).min(17);
            self.flags &= !FLAG_INBOUND_ACTIVE;
        } else {
            // Escalation lock: malus and backoff remain unchanged when offline/DDoS
        }
        self.backoff_level
    }

    /// Records an outbound failure in normal (non-stressed) mode.
    pub fn record_outbound_failure(&mut self) -> u8 {
        self.record_outbound_failure_damped(false)
    }

    /// Records a successful outbound interaction (symmetrical -2 malus points -> 1:1 healing with normal failures).
    pub fn record_outbound_success(&mut self) {
        self.flags &= !FLAG_LAST_FAILED;
        self.malus_score = self.malus_score.saturating_sub(2);
        self.backoff_level = (self.malus_score / 2).min(17);
    }

    /// Alias for backwards compatibility
    pub fn record_missing(&mut self) -> u8 {
        self.record_outbound_failure()
    }

    /// Alias for backwards compatibility
    pub fn record_success(&mut self) {
        self.record_outbound_success()
    }

    /// Advances the hourly sliding window and records whether an HB was received in this hour.
    /// Note: Penalty decay is service/interaction-based (-2 per success) to prevent free-riders from
    /// sitting out penalties in low-traffic shards without contributing work.
    /// On DORMANT, backoff_level, malus_score, and flags are reset so the node can be probed directly on re-entry.
    pub fn record_hour(&mut self, current_epoch: u16, received_heartbeat: bool) -> PeerPresenceState {
        let _ = current_epoch;
        let bit = if received_heartbeat { 1u32 } else { 0u32 };
        self.hourly_bitmask = (self.hourly_bitmask << 1) | bit;
        self.maturity_hours = self.maturity_hours.saturating_add(1);

        let state = self.evaluate_state();

        // 🎯 INVARIANT: On DORMANT, reset for clean re-entry probation.
        if state == PeerPresenceState::Dormant {
            self.backoff_level = 0;
            self.malus_score = 0;
            self.flags = 0;
        }

        state
    }

    /// Is the peer currently suspended (Tit-for-Tat: backoff > 0 && last interaction failed)?
    pub fn is_suspended(&self) -> bool {
        self.backoff_level > 0 && (self.flags & FLAG_LAST_FAILED != 0)
    }

    /// Alias for backwards compatibility
    pub fn is_service_choked(&self) -> bool {
        self.is_suspended()
    }

    /// May the node participate in HRW quorums? (active AND not suspended)
    pub fn is_hrw_eligible(&self) -> bool {
        self.evaluate_state() == PeerPresenceState::Active && !self.is_suspended()
    }

    /// May gossips / heartbeats from this node be forwarded?
    ///
    /// ### 🧹 Anti-Free-Rider Gossip Gating:
    /// Suspended nodes have their heartbeat forwarding temporarily gated so chronic free-riders
    /// (who consume service while refusing shard verifications) starve into `DORMANT` after 21-24h
    /// and are cleanly evicted from HRW and P2P connection pools.
    ///
    /// Honest nodes under temporary DDoS are protected by the reflexive stress circuit breaker
    /// and activity escalation lock, keeping suspensions brief (<= 60s) so no hourly presence bits are lost.
    pub fn should_forward_gossip(&self) -> bool {
        !self.is_suspended()
    }

    /// Determines the current presence state of the peer
    pub fn evaluate_state(&self) -> PeerPresenceState {
        let active_hours_24h = (self.hourly_bitmask & 0x00FF_FFFF).count_ones();

        // 1. First contact / incubation (< 24h)
        if self.maturity_hours < 24 || active_hours_24h < 8 {
            // Fast re-entry check for known peers: 2 consecutive hours
            if self.maturity_hours >= 24 && (self.hourly_bitmask & 0b11) == 0b11 {
                return PeerPresenceState::Active;
            }
            if self.maturity_hours < 24 {
                return PeerPresenceState::Immature;
            }
            return PeerPresenceState::Dormant;
        }

        // 2. Regular active state
        if active_hours_24h >= 8 {
            PeerPresenceState::Active
        } else if active_hours_24h <= 3 {
            PeerPresenceState::Dormant
        } else {
            // Hysteresis intermediate zone: remains as before
            PeerPresenceState::Active
        }
    }
}

/// 🛡️ Time-decayed network stress thermometer (The Ultimate Anti-Death-Spiral Safety Fuse).
///
/// ### 🏛️ System Role & Homeostasis:
/// This component acts as the supreme circuit breaker for the entire P2P network against
/// cascading gossip starvation.
///
/// In a decentralized mesh, if a large-scale coordinated attack or widespread flapping occurs,
/// nodes could misdiagnose honest peers as faulty and suspend their heartbeats.
///
/// The `NetworkStressThermometer` continuously tracks the ratio of inbound `429 PeerSuspended`
/// feedbacks via a 2-hour continuous integer EMA:
/// 1. **Below 40% (0% .. 39.99%):** Normal operation. Full `+2 / -2` Tit-for-Tat rigor.
///    Chronic free-riders are ruthlessly suspended and starved into `DORMANT`.
/// 2. **At/Above 40% (>= 40.00%):** Stress Circuit Breaker trips. Accusations are halved (`+1` penalty),
///    while healing remains full (`-2`). The mathematical expectation flips to forgiveness dominance
///    (`E[ΔMalus] < 0` for up to 66.7% failure rate).
/// 3. **Self-Cooling Equilibrium:** As nodes forgive each other faster under stress, mutual suspensions
///    drop, cooling the entire network back down and oscillating safely around the 40% threshold.
///    A collective network wipeout via gossip blocking is mathematically impossible.
///
/// - **Window:** 7,200 seconds (2 hours) continuous integer decay.
/// - **Threshold:** 4,000 bps (40.00%) suspension pressure.
/// - **Alpha:** 100 bps (1.00%) weight per event -> burst- and order-independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkStressThermometer {
    pub stress_level_bps: u16,
    pub last_update_sec: u64,
}

impl NetworkStressThermometer {
    pub const WINDOW_SECS: u64 = 7_200; // 2 hours
    pub const STRESS_THRESHOLD_BPS: u16 = 4_000; // 40.00%
    pub const EVENT_ALPHA_BPS: u32 = 100; // 1.00% weight per event

    pub const fn new() -> Self {
        Self {
            stress_level_bps: 0,
            last_update_sec: 0,
        }
    }

    /// Updates the suspension pressure EMA based on time decay and a new shard response.
    /// Returns whether the node is currently under systemic network stress (>= 40%).
    pub fn update(&mut self, now_sec: u64, is_suspended: bool) -> bool {
        let delta_secs = now_sec.saturating_sub(self.last_update_sec);
        self.last_update_sec = now_sec;

        let elapsed = delta_secs.min(Self::WINDOW_SECS) as u32;
        let decay = ((self.stress_level_bps as u32 * elapsed) / Self::WINDOW_SECS as u32) as u16;
        let decayed = self.stress_level_bps.saturating_sub(decay);

        let target = if is_suspended { 10_000u32 } else { 0u32 };

        let updated = ((decayed as u32 * (10_000 - Self::EVENT_ALPHA_BPS)) + (target * Self::EVENT_ALPHA_BPS)) / 10_000;
        self.stress_level_bps = updated.min(10_000) as u16;

        self.is_under_stress()
    }

    #[inline(always)]
    pub fn is_under_stress(&self) -> bool {
        self.stress_level_bps >= Self::STRESS_THRESHOLD_BPS
    }
}

impl Default for NetworkStressThermometer {
    fn default() -> Self {
        Self::new()
    }
}

/// Lifecycle state of a shard replacement on rank > 20 (docs/03:3.1)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplacementLifecycleState {
    /// 100% passive, no open shard streams, purely reactive waiting
    IdleStandby,
    /// Active in shard mesh, pull sync executed, co-signing
    ActiveReplacement,
}

/// Checks whether a replacement may accept an invitation / request (docs/03:3.1)
/// A node on rank my_rank accepts ONLY requests from ranks caller_rank < my_rank!
pub fn should_accept_replacement_invite(caller_rank: usize, my_rank: usize) -> bool {
    caller_rank < my_rank
}

/// Extracts the 16-bit shard ID from a genesis root (docs/04:308, INV-0302)
/// 2-byte big-endian: u16::from_be_bytes([genesis_root[0], genesis_root[1]])
pub fn extract_shard_id(genesis_root: &[u8; 32]) -> ShardId {
    u16::from_be_bytes([genesis_root[0], genesis_root[1]])
}

/// Minimum stability duration (in seconds) for predecessor ranks to retire an active shard node / replacement (24 hours, docs/03:150)
pub const STABLE_PREDECESSOR_MIN_UPTIME_SECONDS: u64 = 24 * 3600;

/// Reconnect grace period (in seconds): brief disconnections (e.g. IP change, router reset < 120s)
/// lead to degrading instead of suspension and do not clear the accumulated stability history.
pub const RECONNECT_GRACE_PERIOD_SECONDS: u64 = 120;

/// Status information of a predecessor rank for replacement and shard retirement checks (docs/03:3.1 & INV-0307)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardPredecessorStatus {
    /// Cumulative stable uptime in seconds (not cleared on reconnects within the 120s grace period)
    pub quic_uptime_seconds: u64,
    /// True if the node is locally suspended due to timeouts (> grace period) or lack of cooperation
    pub is_suspended: bool,
}

impl ShardPredecessorStatus {
    pub fn is_healthy_and_stable(&self) -> bool {
        self.quic_uptime_seconds >= STABLE_PREDECESSOR_MIN_UPTIME_SECONDS && !self.is_suspended
    }
}

/// Counts how many predecessor ranks are both >= 24h QUIC-stable and cooperative (!is_suspended)
pub fn count_healthy_predecessors(predecessors: &[ShardPredecessorStatus]) -> usize {
    predecessors.iter().filter(|p| p.is_healthy_and_stable()).count()
}

/// Checks whether an active shard node or replacement may safely retire to IdleStandby (docs/03:3.1 & INV-0307)
/// Invariant: no retreat without physical proof ("proof-of-active-presence").
/// An active node only vacates its duty when at least 20 ranks ahead of it have been stable and cooperative for >= 24h.
pub fn can_active_node_retire_to_standby(healthy_predecessors_count: usize) -> bool {
    healthy_predecessors_count >= 20
}

/// Alias for `can_active_node_retire_to_standby` for backward compatibility
pub fn can_replacement_retire_to_standby(healthy_predecessors_count: usize) -> bool {
    can_active_node_retire_to_standby(healthy_predecessors_count)
}

/// Evaluates the synchronization state of a node based on the median of its F2F friends
/// with hysteresis against oscillation / flapping:
/// - N_median < 20: InSync from N-2, fallback below N-3
/// - N_median >= 20: InSync from 95%, fallback below 90%
pub fn evaluate_sync_status(
    n_local: usize,
    n_median: usize,
    current: NodeSyncStatus,
) -> NodeSyncStatus {
    if n_median == 0 {
        return NodeSyncStatus::InSync;
    }

    let in_sync_threshold = if n_median < 20 {
        n_median.saturating_sub(2).max(1)
    } else {
        (95 * n_median) / 100
    };

    let fallback_threshold = if n_median < 20 {
        n_median.saturating_sub(3).max(1)
    } else {
        (90 * n_median) / 100
    };

    match current {
        NodeSyncStatus::Syncing => {
            if n_local >= in_sync_threshold {
                NodeSyncStatus::InSync
            } else {
                NodeSyncStatus::Syncing
            }
        }
        NodeSyncStatus::InSync => {
            if n_local < fallback_threshold {
                NodeSyncStatus::Syncing
            } else {
                NodeSyncStatus::InSync
            }
        }
    }
}

// ---------------------------------------------------------------------------
// [INV-1104] First-Seen Neulings-Pacing (Tropfenweiser Kanten-Ingress)
// ---------------------------------------------------------------------------

/// Decision for forwarding a node gossip (INV-1104)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeGossipForwardDecision {
    /// Node is already known: immediate forwarding on the hot path (0 ms)
    ForwardImmediate,
    /// Node is completely new (first-seen): queued, forwarding delayed
    ForwardDelayed { delay_seconds: u64 },
    /// Duplicate within the queue / ignore
    DuplicatePending,
}

/// First-seen newcomer pacer & edge throttle (INV-1104 / docs/11:pillar 4)
///
/// Prevents compromised nodes from suddenly flooding the shard mesh with thousands of fake Argon2 identities.
/// New nodes are registered locally immediately, but forwarded only in a trickle (e.g. 1 node / hour).
#[derive(Clone, Debug)]
pub struct FirstSeenPacer {
    /// Locally known node IDs
    known_nodes: HashSet<NodeId>,
    /// Queue for newcomer forwards: (NodeId, enqueue_time)
    pending_queue: VecDeque<(NodeId, u64)>,
    /// Last timestamp when a newcomer was forwarded to friends
    last_forward_timestamp: Option<u64>,
    /// Minimum interval between newcomer forwards per edge (default: 3600s = 1 hour)
    pacing_interval_seconds: u64,
}

impl FirstSeenPacer {
    /// Creates a new pacer with an empty node list and fixed interval
    pub fn new(pacing_interval_seconds: u64) -> Self {
        Self {
            known_nodes: HashSet::new(),
            pending_queue: VecDeque::new(),
            last_forward_timestamp: None,
            pacing_interval_seconds,
        }
    }

    /// Creates a pacer with pre-known nodes (e.g. local village / genesis)
    pub fn with_known_nodes(
        known: impl IntoIterator<Item = NodeId>,
        pacing_interval_seconds: u64,
    ) -> Self {
        Self {
            known_nodes: known.into_iter().collect(),
            pending_queue: VecDeque::new(),
            last_forward_timestamp: None,
            pacing_interval_seconds,
        }
    }

    /// Handles the arrival of a node gossip per INV-1104
    pub fn handle_incoming_node_gossip(
        &mut self,
        node_id: NodeId,
        now_seconds: u64,
    ) -> NodeGossipForwardDecision {
        if self.known_nodes.contains(&node_id) {
            // 🟢 1. Node is already known -> immediate hot path (0 ms)
            NodeGossipForwardDecision::ForwardImmediate
        } else {
            // 🟡 2. Node is completely new (first-seen)
            self.known_nodes.insert(node_id);

            // Check for duplicates in the queue
            if self.pending_queue.iter().any(|(nid, _)| *nid == node_id) {
                return NodeGossipForwardDecision::DuplicatePending;
            }

            self.pending_queue.push_back((node_id, now_seconds));
            NodeGossipForwardDecision::ForwardDelayed {
                delay_seconds: self.pacing_interval_seconds,
            }
        }
    }

    /// Checks and dequeues the next newcomer due for forwarding to friends
    pub fn poll_next_ready_forward(&mut self, now_seconds: u64) -> Option<NodeId> {
        self.poll_next_ready_forward_with_probe(now_seconds, |_| true)
    }

    /// Checks and dequeues the next newcomer with integrated liveness sampling (docs/11:pillar 4)
    ///
    /// From a queue depth >= `PROBE_THRESHOLD_QUEUE_DEPTH` (default: 4), the node
    /// performs a liveness check (`probe_fn`) before release.
    /// If the health check fails (e.g. fake phantom / NAT without listening port / timeout),
    /// the node is immediately discarded, removed from `known_nodes`, and the next entry is checked.
    pub fn poll_next_ready_forward_with_probe<F>(
        &mut self,
        now_seconds: u64,
        mut probe_fn: F,
    ) -> Option<NodeId>
    where
        F: FnMut(NodeId) -> bool,
    {
        if self.pending_queue.is_empty() {
            return None;
        }

        // Throttle check: has the pacing interval since the last forward elapsed?
        if let Some(last_ts) = self.last_forward_timestamp {
            let time_since_last = now_seconds.saturating_sub(last_ts);
            if time_since_last < self.pacing_interval_seconds {
                return None;
            }
        }

        const PROBE_THRESHOLD_QUEUE_DEPTH: usize = 4;
        let queue_depth_at_start = self.pending_queue.len();

        while let Some((node_id, _enqueue_time)) = self.pending_queue.pop_front() {
            // If at dequeue time the queue was >= 4 (suspected flood), run liveness probe:
            if queue_depth_at_start >= PROBE_THRESHOLD_QUEUE_DEPTH {
                let is_alive = probe_fn(node_id);
                if !is_alive {
                    // 🔴 Phantom exposed! Remove from known_nodes and immediately check next
                    self.known_nodes.remove(&node_id);
                    continue;
                }
            }

            // 🟢 Live node or unsuspicious queue (depth < 4)
            self.last_forward_timestamp = Some(now_seconds);
            return Some(node_id);
        }

        None
    }

    /// Computes a stochastically scattered pacing interval with jitter (default: 50 min + 0..20 min = avg 60 min)
    pub fn calculate_jittered_interval(base_seconds: u64, max_jitter_seconds: u64, seed: u64) -> u64 {
        if max_jitter_seconds == 0 {
            return base_seconds;
        }
        let jitter = seed % (max_jitter_seconds + 1);
        base_seconds + jitter
    }

    /// Returns whether a node is locally known
    pub fn is_known(&self, node_id: NodeId) -> bool {
        self.known_nodes.contains(&node_id)
    }

    /// Number of locally known nodes
    pub fn known_count(&self) -> usize {
        self.known_nodes.len()
    }

    /// Number of newcomers still waiting in the pacing queue
    pub fn pending_count(&self) -> usize {
        self.pending_queue.len()
    }
}

/// Simulation-only helper computing HRW score from integer `NodeId` (0..N).
/// Score(Node_i, S) = BLAKE3(NodeID_i || Shard_ID)
///
/// NOTE: For all production routing, client verification, and network decisions, use
/// `compute_hrw_score_f64` / `hrw_score_32` with the 32-byte cryptographic `HrwRoutingId` (Spec 03, INV-0301).
pub fn hrw_score(node_id: NodeId, shard_id: ShardId) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&node_id.to_le_bytes());
    hasher.update(&shard_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the normalized HRW score in the interval [0.0, 1.0)
pub fn hrw_score_normalized(node_id: NodeId, shard_id: ShardId) -> f64 {
    let hash = hrw_score(node_id, shard_id);
    let val = u128::from_be_bytes(hash[0..16].try_into().unwrap());
    val as f64 / u128::MAX as f64
}

/// Computes the HRW score for a 32-byte routing key (Argon2d shard ticket) and a shard.
/// Semantically decoupled: routing decision is based solely on HrwRoutingId, not on NodePubKey.
/// Score(RoutingId_i, S) = BLAKE3(routing_id || shard_id.to_le_bytes())
pub fn hrw_score_32(routing_id: &HrwRoutingId, shard_id: ShardId) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(routing_id);
    hasher.update(&shard_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the normalized HRW score for HrwRoutingId in the interval [0.0, 1.0)
pub fn hrw_score_32_normalized(routing_id: &HrwRoutingId, shard_id: ShardId) -> f64 {
    let hash = hrw_score_32(routing_id, shard_id);
    let val = u128::from_be_bytes(hash[0..16].try_into().unwrap());
    val as f64 / u128::MAX as f64
}

/// Alias for HRW routing: semantically identical to hrw_score_32, but with explicit routing name
pub fn hrw_score_for_routing(routing_id: &HrwRoutingId, shard_id: ShardId) -> Hash256 {
    hrw_score_32(routing_id, shard_id)
}

pub fn hrw_score_for_routing_normalized(routing_id: &HrwRoutingId, shard_id: ShardId) -> f64 {
    hrw_score_32_normalized(routing_id, shard_id)
}

/// Computes the continuous order-statistics threshold for N active nodes and horizon K_max.
/// Formula: max(0.0, 1.0 - K_max / N)
pub fn order_statistics_threshold(active_nodes_count: usize, k_max: f64) -> f64 {
    if active_nodes_count == 0 {
        return 0.0;
    }
    (1.0 - (k_max / active_nodes_count as f64)).max(0.0)
}

/// Fractal, continuous quorum and order-statistics verification for gateway and client.
/// Applies to all N_active from 1 to 1,000,000 without special-case branches.
/// Returns: (is_valid, is_final)
pub fn verify_order_statistics_quorum(
    signer_node_ids: &[NodeId],
    shard_id: ShardId,
    active_nodes_count: usize,
    k_max: f64,
) -> (bool, bool) {
    if active_nodes_count == 0 || signer_node_ids.is_empty() {
        return (false, false);
    }

    let (required_q, is_final) = required_quorum(active_nodes_count);
    if required_q == 0 {
        return (false, false);
    }

    // 1. Compute scores for all distinct signers
    let mut unique_signers = std::collections::HashSet::new();
    let mut scores = Vec::new();
    for &nid in signer_node_ids {
        if unique_signers.insert(nid) {
            scores.push(hrw_score_normalized(nid, shard_id));
        }
    }

    // Not even the minimum number of distinct signers present
    if scores.len() < required_q {
        return (false, false);
    }

    // 2. Sort descending by score (best HRW rank first)
    scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

    // 3. Check the threshold exactly at the Q-th best signer (index required_q - 1)
    let threshold = order_statistics_threshold(active_nodes_count, k_max);
    let q_th_best_score = scores[required_q - 1];

    let is_valid = q_th_best_score >= threshold;
    (is_valid, is_final && is_valid)
}

/// Ranking of all active nodes for a shard by HRW score (descending: highest score = rank 1)
pub fn hrw_rank_nodes(active_nodes: &[NodeId], shard_id: ShardId) -> Vec<(NodeId, Hash256)> {
    let mut ranked: Vec<_> = active_nodes
        .iter()
        .map(|&nid| (nid, hrw_score(nid, shard_id)))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    ranked
}

/// Selects the top-N candidates for a shard based on HRW ranking.
pub fn select_shard_candidates(active_nodes: &[NodeId], shard_id: ShardId, n: usize) -> Vec<NodeId> {
    let mut ranked = hrw_rank_nodes(active_nodes, shard_id);
    ranked.truncate(n);
    ranked.into_iter().map(|(nid, _)| nid).collect()
}

/// Top-20 candidates + rank 21 as deterministic replacement for a shard.
/// Returns: (top-20 vector, Option<rank-21 node>)
pub fn select_quorum_with_backup(
    active_nodes: &[NodeId],
    shard_id: ShardId,
) -> (Vec<NodeId>, Option<NodeId>) {
    let ranked = hrw_rank_nodes(active_nodes, shard_id);
    let top20: Vec<NodeId> = ranked.iter().take(20).map(|(nid, _)| *nid).collect();
    let rank21 = ranked.get(20).map(|(nid, _)| *nid);
    (top20, rank21)
}

/// Checks whether a bit is set in the bitmask for the given index.
pub fn bitmask_has_bit(bitmask: SignersBitmask, index: u32) -> bool {
    if index >= 32 {
        return false;
    }
    (bitmask & (1u32 << index)) != 0
}

/// Counts the number of set bits in the bitmask.
pub fn bitmask_count(bitmask: SignersBitmask) -> u32 {
    bitmask.count_ones()
}

// ---------------------------------------------------------------------------
// Scenario 1: Digest-first pull sync (spec_03)
// ---------------------------------------------------------------------------

/// 32-byte fingerprint response from a shard peer (simplified for simulation)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardDigestResponse {
    pub peer_id: NodeId,
    pub digest: Hash256,
    pub lock_count: u32,
}

/// Result of BFT majority clustering over top-20 digest responses
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClusterResult {
    DominantQuorum {
        digest: Hash256,
        votes: usize,
        peers: Vec<NodeId>,
    },
    InsufficientQuorum {
        max_votes: usize,
        backoff_ms: u64,
    },
}

/// Groups digest responses by BFT quorum (dynamically via required_quorum, otherwise 500ms backoff)
pub fn evaluate_digest_clusters(
    responses: &[ShardDigestResponse],
    total_top20: usize,
) -> ClusterResult {
    use std::collections::HashMap;
    let (needed_votes, _) = required_quorum(total_top20);
    let mut groups: HashMap<Hash256, Vec<NodeId>> = HashMap::new();
    for r in responses {
        groups.entry(r.digest).or_default().push(r.peer_id);
    }
    let mut best_digest: Option<Hash256> = None;
    let mut best_peers: Vec<NodeId> = Vec::new();
    let mut best_votes: usize = 0;
    for (digest, peers) in groups {
        if peers.len() > best_votes {
            best_votes = peers.len();
            best_digest = Some(digest);
            best_peers = peers;
        }
    }
    if best_votes >= needed_votes && needed_votes != 0 {
        ClusterResult::DominantQuorum {
            digest: best_digest.unwrap(),
            votes: best_votes,
            peers: best_peers,
        }
    } else {
        ClusterResult::InsufficientQuorum {
            max_votes: best_votes,
            backoff_ms: 500,
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario 3: Gaslighting defense via F2F median (spec_07)
// ---------------------------------------------------------------------------

/// Robust median of F2F N values (resistant to extreme outliers)
pub fn compute_f2f_median(peer_reports: &[usize]) -> usize {
    if peer_reports.is_empty() {
        return 0;
    }
    let mut sorted = peer_reports.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        let a = sorted[n / 2 - 1];
        let b = sorted[n / 2];
        (a + b) / 2
    }
}

/// F2F presence report from a friend (for SimNetwork gaslighting tests)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct F2FPresenceReport {
    pub peer_id: NodeId,
    pub reported_network_size: usize,
    pub timestamp: SimTime,
}

/// Helper: median from F2FPresenceReport slice
pub fn compute_f2f_median_from_reports(reports: &[F2FPresenceReport]) -> usize {
    let values: Vec<usize> = reports.iter().map(|r| r.reported_network_size).collect();
    compute_f2f_median(&values)
}

// ---------------------------------------------------------------------------
// Scenario 4: Lazy ingestion causality chain (spec_02 / spec_04)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofChainHop {
    pub prev_hash: Hash256,
    pub next_hash: Hash256,
    pub owner_pub: Hash256,
    pub quorum_signatures: Vec<Attestation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalityProofChain {
    pub genesis_root: Hash256,
    pub hops: Vec<ProofChainHop>,
    pub target_lock: LockRecord,
    pub client_signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CausalityError {
    InvalidGenesisRoot,
    BrokenChainLink { hop_index: usize },
    InvalidQuorumCertificate { hop_index: usize },
    InvalidClientSignature,
    ParentAlreadyLocked { parent_lock: Hash256 },
}

impl std::fmt::Display for CausalityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CausalityError::InvalidGenesisRoot => write!(f, "Invalid genesis root"),
            CausalityError::BrokenChainLink { hop_index } => {
                write!(f, "Broken chain link at hop {}", hop_index)
            }
            CausalityError::InvalidQuorumCertificate { hop_index } => {
                write!(f, "Invalid quorum certificate at hop {}", hop_index)
            }
            CausalityError::InvalidClientSignature => write!(f, "Invalid client signature"),
            CausalityError::ParentAlreadyLocked { parent_lock } => {
                write!(f, "Parent already locked: {:?}", parent_lock)
            }
        }
    }
}
impl std::error::Error for CausalityError {}

const CAUSALITY_CLIENT_DOMAIN: &[u8] = b"HUMOCO_V1_CLIENT_SIG";

/// Creates a deterministic client signature for a causality chain (for tests)
pub fn sign_causality_client_signature(
    target_lock: &LockRecord,
    genesis_root: &Hash256,
) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAUSALITY_CLIENT_DOMAIN);
    hasher.update(&target_lock.id);
    hasher.update(genesis_root);
    hasher.update(&target_lock.parent_lock);
    let digest = hasher.finalize();
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(digest.as_bytes());
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(b"HUMOCO_V1_CLIENT_SIG2");
    hasher2.update(digest.as_bytes());
    let digest2 = hasher2.finalize();
    sig[32..64].copy_from_slice(digest2.as_bytes());
    sig
}

fn verify_client_signature(chain: &CausalityProofChain) -> bool {
    let expected = sign_causality_client_signature(&chain.target_lock, &chain.genesis_root);
    chain.client_signature == expected
}

pub const MAX_PROOFCHAIN_HOPS: usize = 1024;
pub const MAX_NONCE_BYTES: usize = 1024;
pub const MAX_QUORUM_SIGS_PER_HOP: usize = 20;

/// Verifies a causality chain statelessly on-the-fly (<2ms, lazy ingestion)
pub fn verify_causality_proof_chain_stateless(
    chain: &CausalityProofChain,
    allowed_genesis_roots: &HashSet<Hash256>,
) -> Result<(), CausalityError> {
    // Defense-in-depth: limit maximum hops and nonce bytes to fend off CPU amplification DoS
    if chain.hops.len() > MAX_PROOFCHAIN_HOPS {
        return Err(CausalityError::BrokenChainLink { hop_index: chain.hops.len() });
    }
    if chain.target_lock.nonce.len() > MAX_NONCE_BYTES {
        return Err(CausalityError::BrokenChainLink { hop_index: 0 });
    }

    // 1. Genesis root check
    if !allowed_genesis_roots.contains(&chain.genesis_root) {
        return Err(CausalityError::InvalidGenesisRoot);
    }
    // 2. Client signature
    if !verify_client_signature(chain) {
        return Err(CausalityError::InvalidClientSignature);
    }
    // 3. Hop chain continuity
    for (i, hop) in chain.hops.iter().enumerate() {
        if hop.quorum_signatures.len() > MAX_QUORUM_SIGS_PER_HOP {
            return Err(CausalityError::InvalidQuorumCertificate { hop_index: i });
        }
        let expected_prev = if i == 0 {
            chain.genesis_root
        } else {
            chain.hops[i - 1].next_hash
        };
        if hop.prev_hash != expected_prev {
            return Err(CausalityError::BrokenChainLink { hop_index: i });
        }
        // Quorum certificate check: must have at least one valid attestation
        if hop.quorum_signatures.is_empty() {
            return Err(CausalityError::InvalidQuorumCertificate { hop_index: i });
        }
        for att in &hop.quorum_signatures {
            if !crate::crypto::verify_attestation(att) {
                return Err(CausalityError::InvalidQuorumCertificate { hop_index: i });
            }
            if att.lock_id != hop.next_hash || att.parent_lock != hop.prev_hash {
                return Err(CausalityError::InvalidQuorumCertificate { hop_index: i });
            }
        }
    }
    // 4. Final link: target_lock.parent_lock must equal last hop next_hash (or genesis if no hops)
    let expected_parent = if chain.hops.is_empty() {
        chain.genesis_root
    } else {
        chain.hops.last().unwrap().next_hash
    };
    if chain.target_lock.parent_lock != expected_parent {
        return Err(CausalityError::BrokenChainLink {
            hop_index: chain.hops.len(),
        });
    }
    Ok(())
}

/// Verifies a causality chain and checks/updates the local first-seen collision index
pub fn verify_causality_proof_chain(
    chain: &CausalityProofChain,
    allowed_genesis_roots: &HashSet<Hash256>,
    seen_parents: &mut HashSet<Hash256>,
) -> Result<(), CausalityError> {
    verify_causality_proof_chain_stateless(chain, allowed_genesis_roots)?;
    if seen_parents.contains(&chain.target_lock.parent_lock) {
        return Err(CausalityError::ParentAlreadyLocked {
            parent_lock: chain.target_lock.parent_lock,
        });
    }
    seen_parents.insert(chain.target_lock.parent_lock);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_calculations() {
        assert_eq!(required_quorum(1), (1, false));
        assert_eq!(required_quorum(2), (2, false));
        assert_eq!(required_quorum(3), (3, false));
        assert_eq!(required_quorum(7), (5, false));
        assert_eq!(required_quorum(10), (7, false));
        assert_eq!(required_quorum(19), (13, false));
        assert_eq!(required_quorum(20), (14, true));
        assert_eq!(required_quorum(100), (14, true));
    }

    #[test]
    fn test_sim_time_arithmetic() {
        let mut t1 = SimTime(100);
        t1 += 50;
        assert_eq!(t1.as_millis(), 150);
        let t2 = t1 + 50;
        assert_eq!(t2.as_millis(), 200);
        assert_eq!(t2 - t1, 50);
    }

    #[test]
    fn test_evaluate_sync_status_village_and_global() {
        // Village (N=5): entry from 3, fallback below 2
        assert_eq!(
            evaluate_sync_status(2, 5, NodeSyncStatus::Syncing),
            NodeSyncStatus::Syncing
        );
        assert_eq!(
            evaluate_sync_status(3, 5, NodeSyncStatus::Syncing),
            NodeSyncStatus::InSync
        );
        assert_eq!(
            evaluate_sync_status(5, 5, NodeSyncStatus::Syncing),
            NodeSyncStatus::InSync
        );
        // Hysteresis in village: at 2, InSync remains InSync (fallback only below 2)
        assert_eq!(
            evaluate_sync_status(2, 5, NodeSyncStatus::InSync),
            NodeSyncStatus::InSync
        );
        assert_eq!(
            evaluate_sync_status(1, 5, NodeSyncStatus::InSync),
            NodeSyncStatus::Syncing
        );

        // Global mesh (N=10,000): entry from 9,500 (95%), fallback below 9,000 (90%)
        assert_eq!(
            evaluate_sync_status(9400, 10_000, NodeSyncStatus::Syncing),
            NodeSyncStatus::Syncing
        );
        assert_eq!(
            evaluate_sync_status(9500, 10_000, NodeSyncStatus::Syncing),
            NodeSyncStatus::InSync
        );
        assert_eq!(
            evaluate_sync_status(9800, 10_000, NodeSyncStatus::Syncing),
            NodeSyncStatus::InSync
        );

        // Hysteresis in global mesh: between 9,000 and 9,499, InSync is retained
        assert_eq!(
            evaluate_sync_status(9200, 10_000, NodeSyncStatus::InSync),
            NodeSyncStatus::InSync
        );
        assert_eq!(
            evaluate_sync_status(8999, 10_000, NodeSyncStatus::InSync),
            NodeSyncStatus::Syncing
        );
    }

    #[test]
    fn test_peer_presence_entry_lifecycle_and_backoff_reset() {
        assert_eq!(std::mem::size_of::<PeerPresenceEntry>(), 16, "Must be exactly 16 bytes");
        assert_eq!(std::mem::align_of::<PeerPresenceEntry>(), 8, "Must be 8-byte aligned");
        assert_eq!(FLAG_INBOUND_ACTIVE, 1, "FLAG_INBOUND_ACTIVE must be 1<<0");
        assert_eq!(FLAG_LAST_FAILED, 2, "FLAG_LAST_FAILED must be 1<<1");

        let mut entry = PeerPresenceEntry::new(0x1234_5678, 100);
        assert_eq!(entry.evaluate_state(), PeerPresenceState::Immature);
        assert!(!entry.is_hrw_eligible());
        assert_eq!(entry.malus_score, 0);
        assert_eq!(entry.backoff_level, 0);
        assert_eq!(entry.flags, 0);

        // After 10 hours with 1 HB each -> still Immature (age < 24h)
        for ep in 101..=110 {
            entry.record_hour(ep, true);
        }
        assert_eq!(entry.evaluate_state(), PeerPresenceState::Immature);

        // After 24 hours with continuous HB -> ACTIVE
        for ep in 111..=124 {
            entry.record_hour(ep, true);
        }
        assert_eq!(entry.evaluate_state(), PeerPresenceState::Active);
        assert!(entry.is_hrw_eligible());
        assert!(entry.should_forward_gossip());
        assert_eq!(entry.backoff_level, 0);

        // Activity-coupled +2/-2 Tit-for-Tat: inbound + failure -> malus +2, backoff 1, choked
        entry.record_inbound_activity();
        assert!(entry.flags & FLAG_INBOUND_ACTIVE != 0);
        let bl = entry.record_outbound_failure();
        assert_eq!(bl, 1, "First failure with inbound => backoff 1 (malus 2 / 2)");
        assert_eq!(entry.malus_score, 2);
        assert_eq!(entry.backoff_level, 1);
        assert_eq!(entry.flags & FLAG_INBOUND_ACTIVE, 0, "Inbound flag cleared after escalation");
        assert!(entry.flags & FLAG_LAST_FAILED != 0);
        assert!(entry.is_suspended());
        assert!(entry.is_service_choked());
        assert!(!entry.is_hrw_eligible(), "Choked peer not HRW eligible");
        assert!(!entry.should_forward_gossip(), "Gossip is suppressed while service is choked");

        // Eskalationssperre: second failure WITHOUT inbound -> no escalation (offline/DDoS protection)
        let bl2 = entry.record_outbound_failure();
        assert_eq!(bl2, 1, "Without inbound and backoff>0, no escalation");
        assert_eq!(entry.malus_score, 2, "Malus unchanged due to escalation lock");
        assert_eq!(entry.backoff_level, 1);
        assert!(entry.is_suspended());

        // Service-based healing (no hourly decay): 1 hour passes -> malus remains until worked off
        entry.record_hour(125, true);
        assert_eq!(entry.backoff_level, 1, "No automatic hourly decay (anti-free-rider)");
        assert_eq!(entry.malus_score, 2, "Malus persists until worked off via successful interactions");
        assert!(entry.is_suspended());
        assert!(!entry.is_hrw_eligible());
        assert!(!entry.should_forward_gossip());
        assert!(entry.is_service_choked());

        // Inbound + failure again -> second escalation (malus 2 + 2 = 4, backoff = 2)
        entry.record_inbound_activity();
        let bl3 = entry.record_outbound_failure();
        assert_eq!(entry.malus_score, 4);
        assert_eq!(bl3, 2);
        assert_eq!(entry.backoff_level, 2);
        assert!(entry.is_suspended());

        entry.record_inbound_activity();
        let bl4 = entry.record_outbound_failure();
        assert_eq!(entry.malus_score, 6);
        assert_eq!(bl4, 3);
        assert_eq!(entry.backoff_level, 3);

        // Success: clears LAST_FAILED, malus -2 (symmetrical), backoff updates
        entry.record_outbound_success();
        assert_eq!(entry.malus_score, 4);
        assert_eq!(entry.backoff_level, 2);
        assert_eq!(entry.flags & FLAG_LAST_FAILED, 0, "Success clears LAST_FAILED");
        assert!(!entry.is_service_choked(), "Not choked after success (flag cleared)");
        assert!(entry.should_forward_gossip());
        assert!(entry.is_hrw_eligible());

        // 2 more successes drain malus from 4 to 0 -> backoff 0
        entry.record_outbound_success();
        assert_eq!(entry.malus_score, 2);
        assert_eq!(entry.backoff_level, 1);
        entry.record_outbound_success();
        assert_eq!(entry.malus_score, 0);
        assert_eq!(entry.backoff_level, 0, "When malus 0, backoff resets to 0");
        assert!(!entry.is_suspended());

        // Re-create choking for dormant test: inbound + failure => malus 2 backoff 1
        entry.record_inbound_activity();
        entry.record_outbound_failure();
        assert_eq!(entry.malus_score, 2);
        assert_eq!(entry.backoff_level, 1);
        assert!(entry.is_suspended());

        // 22 hours without HB -> DORMANT (only 2 bits left in 24h window) -> backoff & flags reset
        for ep in 126..=146 {
            entry.record_hour(ep, false);
        }
        assert_eq!(entry.evaluate_state(), PeerPresenceState::Dormant);
        assert_eq!(entry.backoff_level, 0, "Dormant transition resets backoff to 0 for re-entry probation");
        assert_eq!(entry.malus_score, 0, "Dormant transition resets malus to 0");
        assert_eq!(entry.flags, 0, "Dormant clears flags");
        assert!(!entry.is_suspended());

        // Fast re-entry: 2 consecutive HBs bring it back to ACTIVE
        entry.record_hour(147, true);
        assert_eq!(entry.evaluate_state(), PeerPresenceState::Dormant);
        assert_eq!(entry.backoff_level, 0);
        entry.record_hour(148, true);
        assert_eq!(entry.evaluate_state(), PeerPresenceState::Active);
        assert!(entry.is_hrw_eligible(), "Active node with backoff 0 immediately eligible for quorums");
        assert!(entry.should_forward_gossip());

        // Alias checks
        entry.record_inbound_activity();
        let alias_bl = entry.record_missing();
        assert_eq!(alias_bl, entry.backoff_level);
        entry.record_success();
        assert_eq!(entry.flags & FLAG_LAST_FAILED, 0);
    }

    #[test]
    fn test_stress_damped_failure_and_persistence() {
        let mut entry = PeerPresenceEntry::new(0xDEAD_BEEF, 1);

        // Initial state
        assert_eq!(entry.malus_score, 0);
        assert_eq!(entry.backoff_level, 0);
        assert!(!entry.is_suspended());
        assert!(entry.should_forward_gossip());

        // Normal mode failure: +2 malus
        entry.record_inbound_activity();
        entry.record_outbound_failure_damped(false);
        assert_eq!(entry.malus_score, 2);
        assert_eq!(entry.backoff_level, 1);
        assert!(!entry.should_forward_gossip(), "Choked -> gossip suppressed");

        // Stress mode failure: +1 malus (damped!)
        entry.record_inbound_activity();
        entry.record_outbound_failure_damped(true);
        assert_eq!(entry.malus_score, 3);
        assert_eq!(entry.backoff_level, 1); // 3 / 2 = 1

        // Another stress mode failure: +1 malus -> 4 -> backoff 2
        entry.record_inbound_activity();
        entry.record_outbound_failure_damped(true);
        assert_eq!(entry.malus_score, 4);
        assert_eq!(entry.backoff_level, 2);

        // Successful interaction heals full -2 points!
        entry.record_outbound_success();
        assert_eq!(entry.malus_score, 2);
        assert_eq!(entry.backoff_level, 1);
        assert!(entry.should_forward_gossip(), "Success unchokes node");

        // Malus persists across hours without activity (no decay)
        for ep in 2..=10 {
            entry.record_hour(ep, true);
        }
        assert_eq!(entry.malus_score, 2, "Malus persists across hours");
        assert_eq!(entry.backoff_level, 1);

        // Final success heals completely
        entry.record_outbound_success();
        assert_eq!(entry.malus_score, 0);
        assert_eq!(entry.backoff_level, 0);
    }

    #[test]
    fn test_network_stress_thermometer_ema_and_burst_robustness() {
        let mut thermo = NetworkStressThermometer::new();
        assert_eq!(thermo.stress_level_bps, 0);
        assert!(!thermo.is_under_stress());

        // 1. Single choke after 1h idle: minimal rise (order independent)
        thermo.update(3600, true);
        assert_eq!(thermo.stress_level_bps, 100, "1 choke adds 100 bps (1%)");
        assert!(!thermo.is_under_stress());

        // 2. 19 OK responses in same second:
        for _ in 0..19 {
            thermo.update(3600, false);
        }
        assert!(thermo.stress_level_bps < 100, "19 OK responses dampen down to < 1%");
        assert!(!thermo.is_under_stress());

        // 3. Sustained DoS attack (e.g. 80 consecutive chokes over 30-40 minutes)
        for i in 1..=80 {
            thermo.update(3600 + i * 25, true);
        }
        assert!(thermo.stress_level_bps >= 4000, "Sustained attack crosses 40% threshold");
        assert!(thermo.is_under_stress());

        // 4. Attack stops -> 2 hours pass -> decays back below threshold
        thermo.update(3600 + 80 * 25 + 7200, false);
        assert!(!thermo.is_under_stress(), "2h decay clears stress state");
    }

    #[test]
    fn test_replacement_node_rank_filter_and_retirement() {
        let my_rank = 21;
        // Only accept invitations from better ranks (caller < 21)
        assert!(should_accept_replacement_invite(1, my_rank));
        assert!(should_accept_replacement_invite(7, my_rank));
        assert!(should_accept_replacement_invite(20, my_rank));
        assert!(!should_accept_replacement_invite(21, my_rank));
        assert!(!should_accept_replacement_invite(22, my_rank));
        assert!(!should_accept_replacement_invite(500, my_rank));

        // Retirement: only when at least 20 ranks ahead have been stable for 24h
        assert!(!can_replacement_retire_to_standby(18));
        assert!(!can_replacement_retire_to_standby(19));
        assert!(can_replacement_retire_to_standby(20));
        assert!(can_replacement_retire_to_standby(21));
    }
}
