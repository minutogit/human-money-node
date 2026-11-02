use parking_lot::RwLock as PlRwLock;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;

use crate::ingress::pow::{PowEngine, PowError};
use crate::storage::{RedbStorage, StorageError};
use humoco_sim_core::quota::{ByteYears, NetworkThermometer, MAX_WHALE_MULTIPLIER};
use humoco_sim_core::types::NodeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IngressTier {
    Tier1Vip,
    Tier2F2F,
    Tier3Public,
}

/// DTO for registered F2F ingress client credentials.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct F2fClientDto {
    pub token_hash: String,
    pub label: String,
    pub writes_today: u64,
    pub daily_limit: u64,
    pub whale_brake_active: bool,
    pub last_active_sec: Option<u64>,
    #[serde(default)]
    pub token: Option<String>,
}

/// Internal metadata stored for registered F2F client tokens.
#[derive(Debug, Clone)]
pub struct F2fClientMeta {
    pub token: String,
    pub token_hash: String,
    pub label: String,
    pub registered_at_ms: u64,
    pub last_active_ms: Option<u64>,
}

/// Returns true if the token matches the required random 128-bit secret format `f2f_<32 hex digits>` (AGENTS.md / A25-R4).
pub fn is_valid_client_token(token: &str) -> bool {
    let t = token.trim();
    if !t.starts_with("f2f_") {
        return false;
    }
    let suffix = &t[4..];
    suffix.len() == 32 && suffix.chars().all(|c| c.is_ascii_hexdigit())
}

#[derive(Debug, Error)]
pub enum IngressError {
    #[error("Invalid or unknown VIP auth token")]
    InvalidAuthToken,

    #[error("VIP Quota exceeded: required {required} byte-years, available {available}")]
    QuotaExceeded { available: u64, required: u64 },

    #[error("Invalid or unknown F2F peer token")]
    InvalidPeerToken,

    #[error("Proof of Work required")]
    PoWRequired {
        challenge: String,
        difficulty: u32,
        expires_at: u64,
    },

    #[error("Invalid or expired Proof of Work: {0}")]
    InvalidPoW(#[from] PowError),

    #[error("Storage error during quota verification: {0}")]
    Storage(#[from] StorageError),

    #[error("Read quota exceeded: required {required} reads, available {available}")]
    ReadQuotaExceeded { available: u64, required: u64 },

    #[error("VIP Quota persistence queue is full or closed")]
    QuotaPersistenceUnavailable,
}

/// # Architectural Invariant: Reservation-First VIP Quota Durability & Lock Elimination (A02-02 & A05-01)
///
/// Ingress admission control on the PoS checkout hot-path (`POST /v1/lock`) must satisfy:
/// 1. Sub-microsecond RAM operations: Cache write locks MUST NEVER perform blocking storage
///    I/O (`A05-01`). Cold quota misses are hydrated asynchronously before acquiring write locks.
/// 2. Reservation-First Capacity: Before decrementing or mutating in-memory quota balances,
///    the persistence channel capacity MUST be reserved via `try_reserve()`. If the queue is
///    full or closed, admission is rejected immediately with `IngressError::QuotaPersistenceUnavailable`
///    WITHOUT deducting credit (`A02-02`). No unpersisted debits are ever accepted.
/// 3. Strict FIFO Serialization: The reserved permit MUST be sent (`permit.send(...)`) BEFORE
///    releasing the in-memory cache write lock. This guarantees that concurrent top-up and debit
///    operations enqueue their absolute balances into the FIFO persistence worker in the exact same
///    order as their memory mutations, preventing out-of-order state overwrites.
///
/// # Architectural Invariant: Ingress vs. Peer Telemetry Decoupling (INV-1701 & Spec 13/17)
///
/// `TierController` is intentionally **not** coupled to `PeerManager` or peer telemetry
/// (connection quality, latency histograms, failure counters). Ingress admission control
/// (VIP quota, F2F token check, BLAKE3 Hashcash PoW) runs on the PoS checkout hot-path
/// (`POST /v1/lock`) and must stay deterministic, constant-time and self-contained.
///
/// Rationale (INV-1701 — Non-Authoritative Telemetry):
/// Telemetry is operator-facing diagnosis only (`triggers_auto_ban() == false`). If ingress
/// decisions consumed peer health signals, a degraded peer or a telemetry spike would
/// feed back into admission control, throttling or rejecting legitimate PoS payments and
/// creating a **self-induced DoS** on the checkout path. By decoupling ingress from
/// subjective peer observations, the hot-path guarantees liveness even when the P2P mesh
/// is under stress, gossip is delayed, or `NetworkThermometer` is recalibrating. Peer
/// failures are handled exclusively inside `PeerManager` via local TTL pruning / circuit
/// breaker, never via ingress denial (cf. `AGENTS.md` — Local Node Perspective / First-Party
/// Evidence doctrine).
/// FIFO-sequenced VIP quota persist operation.
#[derive(Debug, Clone, Copy)]
struct VipQuotaPersistOp {
    account_tag: [u8; 32],
    remaining: u64,
}

type DailyUsageMap = (u64, HashMap<[u8; 32], u64>);

#[derive(Debug, Default)]
struct IngressAccountingState {
    current_day: u64,
    epoch_seq: u64,
    cumulative_micro_byte_years: u64,
    prev_day_final_bytes: u64,
}

#[derive(Clone)]
pub struct TierController {
    storage: Arc<RedbStorage>,
    pow_engine: Arc<PowEngine>,
    vip_tokens: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    vip_tags: Arc<RwLock<HashSet<[u8; 32]>>>,
    f2f_tokens: Arc<RwLock<HashSet<String>>>,
    f2f_clients: Arc<RwLock<HashMap<String, F2fClientMeta>>>,
    thermometer: Arc<RwLock<NetworkThermometer>>,
    vip_quota_cache: Arc<PlRwLock<HashMap<[u8; 32], u64>>>,
    vip_writes_today: Arc<AtomicU64>,
    f2f_writes_today: Arc<AtomicU64>,
    free_writes_today: Arc<AtomicU64>,
    accounting_state: Arc<parking_lot::Mutex<IngressAccountingState>>,
    last_thermometer_day: Arc<AtomicU64>,
    vip_persist_tx: tokio::sync::mpsc::Sender<VipQuotaPersistOp>,
    vip_persist_worker: tokio::task::AbortHandle,
    vip_persist_failed: Arc<AtomicBool>,
    vip_daily_usage: Arc<RwLock<DailyUsageMap>>,
    f2f_daily_usage: Arc<RwLock<DailyUsageMap>>,
    free_daily_usage: Arc<RwLock<DailyUsageMap>>,
    p2p_node_usage: Arc<RwLock<DailyUsageMap>>,
    p2p_node_read_usage: Arc<RwLock<DailyUsageMap>>,
}

/// Derives a deterministic opaque diagnostic identifier for a VIP account tag.
/// This identifier is safe to display in operator dashboards, telemetry, and event logs,
/// as it reveals zero information about the bearer secret and cannot be used for authentication.
pub fn vip_diagnostic_id(account_tag: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("HUMOCO_V1_VIP_DIAG_ID");
    hasher.update(account_tag);
    let hash = hasher.finalize();
    format!("vip_{}", &hex::encode(hash.as_bytes())[..16])
}

impl TierController {
    pub fn new(storage: Arc<RedbStorage>, pow_engine: Arc<PowEngine>) -> Self {
        Self::new_with_persist_capacity(storage, pow_engine, 1_024)
    }

    /// Creates a new TierController with storage, PoW engine, and specified persist queue capacity.
    ///
    /// Spawns a FIFO-sequenced VIP quota persist worker that processes write operations
    /// in strict order, preventing out-of-order write races from unsequenced `tokio::spawn`.
    pub fn new_with_persist_capacity(
        storage: Arc<RedbStorage>,
        pow_engine: Arc<PowEngine>,
        persist_channel_capacity: usize,
    ) -> Self {
        let (vip_persist_tx, mut vip_persist_rx) =
            tokio::sync::mpsc::channel::<VipQuotaPersistOp>(persist_channel_capacity.max(1));
        let persist_storage = storage.clone();
        let vip_persist_failed = Arc::new(AtomicBool::new(false));
        let worker_failed = vip_persist_failed.clone();
        let worker = tokio::spawn(async move {
            while let Some(first_op) = vip_persist_rx.recv().await {
                let mut latest_balances: HashMap<[u8; 32], u64> = HashMap::new();
                latest_balances.insert(first_op.account_tag, first_op.remaining);
                while let Ok(next_op) = vip_persist_rx.try_recv() {
                    latest_balances.insert(next_op.account_tag, next_op.remaining);
                }
                let batch: Vec<([u8; 32], u64)> = latest_balances.into_iter().collect();
                let storage = persist_storage.clone();
                let res =
                    tokio::task::spawn_blocking(move || storage.set_quotas_batch(&batch)).await;
                if !matches!(res, Ok(Ok(()))) {
                    worker_failed.store(true, Ordering::Release);
                    tracing::warn!(?res, "FIFO VIP quota persistence batch failed");
                }
            }
        });

        let mut initial_cache = HashMap::new();
        if let Ok(all) = storage.all_quotas() {
            for (tag, bal) in all {
                initial_cache.insert(tag, bal);
            }
        }

        Self {
            storage,
            pow_engine,
            vip_tokens: Arc::new(RwLock::new(HashMap::new())),
            vip_tags: Arc::new(RwLock::new(HashSet::new())),
            f2f_tokens: Arc::new(RwLock::new(HashSet::new())),
            f2f_clients: Arc::new(RwLock::new(HashMap::new())),
            thermometer: Arc::new(RwLock::new(NetworkThermometer::new())),
            vip_quota_cache: Arc::new(PlRwLock::new(initial_cache)),
            vip_writes_today: Arc::new(AtomicU64::new(0)),
            f2f_writes_today: Arc::new(AtomicU64::new(0)),
            free_writes_today: Arc::new(AtomicU64::new(0)),
            accounting_state: Arc::new(parking_lot::Mutex::new(IngressAccountingState::default())),
            last_thermometer_day: Arc::new(AtomicU64::new(0)),
            vip_persist_tx,
            vip_persist_worker: worker.abort_handle(),
            vip_persist_failed,
            vip_daily_usage: Arc::new(RwLock::new((0, HashMap::new()))),
            f2f_daily_usage: Arc::new(RwLock::new((0, HashMap::new()))),
            free_daily_usage: Arc::new(RwLock::new((0, HashMap::new()))),
            p2p_node_usage: Arc::new(RwLock::new((0, HashMap::new()))),
            p2p_node_read_usage: Arc::new(RwLock::new((0, HashMap::new()))),
        }
    }

    /// Registers natural FIFO quota-worker completion with daemon teardown.
    /// All controller senders must be dropped before waiting for this handle.
    pub fn quota_worker_abort_handle(&self) -> tokio::task::AbortHandle {
        self.vip_persist_worker.clone()
    }

    /// Local persistence failure evidence for truthful daemon completion, never peer punishment.
    pub fn quota_worker_failure_handle(&self) -> Arc<AtomicBool> {
        self.vip_persist_failed.clone()
    }

    /// Increments and returns the next epoch_seq for Spec 10 Signed Ingress Envelopes.
    pub fn next_epoch_seq(&self) -> u64 {
        let mut state = self.accounting_state.lock();
        state.epoch_seq = state.epoch_seq.saturating_add(1);
        state.epoch_seq
    }

    /// Records gateway declared usage, advancing day roll-over if needed, and returns:
    /// `(epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes)`.
    ///
    /// Uses a single short-held mutex covering day selection/rollover, sequence allocation,
    /// and cumulative usage. Delayed requests carrying slightly older timestamps across a
    /// rollover are monotonically clamped to `state.current_day` to prevent sequence forks.
    pub fn record_declared_usage(
        &self,
        now_ms: u64,
        footprint_micro_bj: u64,
    ) -> (u32, u64, u64, u64) {
        let incoming_day = self.current_epoch_day_at(now_ms);
        let mut state = self.accounting_state.lock();
        if state.current_day == 0 {
            state.current_day = incoming_day;
        } else if incoming_day > state.current_day {
            state.prev_day_final_bytes = state.cumulative_micro_byte_years;
            state.cumulative_micro_byte_years = 0;
            state.epoch_seq = 0;
            state.current_day = incoming_day;
        }
        let effective_day = state.current_day;
        let seq = state.epoch_seq.saturating_add(1);
        state.epoch_seq = seq;
        state.cumulative_micro_byte_years = state
            .cumulative_micro_byte_years
            .saturating_add(footprint_micro_bj);
        let cum = state.cumulative_micro_byte_years;
        let prev = state.prev_day_final_bytes;
        (effective_day as u32, seq, cum, prev)
    }

    /// Returns the tier write counters: (vip, f2f, free).
    pub fn tier_counters(&self) -> (u64, u64, u64) {
        (
            self.vip_writes_today.load(Ordering::Relaxed),
            self.f2f_writes_today.load(Ordering::Relaxed),
            self.free_writes_today.load(Ordering::Relaxed),
        )
    }

    /// Returns the cached VIP quota for an account, if present in the in-memory cache.
    pub fn get_cached_vip_quota(&self, account_tag: &[u8; 32]) -> Option<u64> {
        self.vip_quota_cache.read().get(account_tag).copied()
    }

    /// Sets the cached VIP quota directly (e.g. after top-up via control plane).
    pub fn set_cached_vip_quota(&self, account_tag: [u8; 32], balance: u64) {
        self.vip_quota_cache.write().insert(account_tag, balance);
    }

    /// Tops up VIP quota for an account, updating cache and persisting with strict FIFO ordering (A02-02).
    /// Resolves cold misses outside the write lock, reserves persistence capacity, and sends
    /// the updated balance before releasing the cache write lock.
    pub fn topup_vip_quota(
        &self,
        account_tag: [u8; 32],
        byte_years: u64,
    ) -> Result<u64, IngressError> {
        let pre_bal = if !self.vip_quota_cache.read().contains_key(&account_tag) {
            Some(self.storage.get_quota(&account_tag).unwrap_or(0))
        } else {
            None
        };

        let mut cache = self.vip_quota_cache.write();
        if let Some(bal) = pre_bal {
            cache.entry(account_tag).or_insert(bal);
        }
        let permit = self
            .vip_persist_tx
            .try_reserve()
            .map_err(|_| IngressError::QuotaPersistenceUnavailable)?;
        let bal = cache.entry(account_tag).or_insert(0);
        *bal = bal.saturating_add(byte_years);
        let new_balance = *bal;
        permit.send(VipQuotaPersistOp {
            account_tag,
            remaining: new_balance,
        });
        drop(cache);
        Ok(new_balance)
    }

    /// Returns all cached VIP quota balances.
    pub fn list_cached_vip_quotas(&self) -> Vec<([u8; 32], u64)> {
        self.vip_quota_cache
            .read()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    /// Returns all VIP accounts with deterministic opaque diagnostic identifiers.
    /// Never returns raw bearer secrets or authenticatable credentials.
    pub fn list_vip_accounts(&self) -> Vec<(String, u64)> {
        let cache = self.vip_quota_cache.read();
        let mut list = Vec::with_capacity(cache.len());
        for (tag, balance) in cache.iter() {
            list.push((vip_diagnostic_id(tag), *balance));
        }
        list.sort_by(|a, b| a.0.cmp(&b.0));
        list
    }

    /// Hydrates the in-memory cache from durable storage (read-only, no fsync).
    /// Idempotent with respect to cached balance: preserves an already-initialized or mutated balance.
    pub fn hydrate_vip_quota(&self, account_tag: &[u8; 32]) -> Result<u64, StorageError> {
        if let Some(existing) = self.vip_quota_cache.read().get(account_tag).copied() {
            return Ok(existing);
        }
        let bal = self.storage.get_quota(account_tag)?;
        let mut cache = self.vip_quota_cache.write();
        let current = *cache.entry(*account_tag).or_insert(bal);
        Ok(current)
    }

    /// Ensures that the specified VIP account tag is hydrated in the in-memory cache.
    /// If not present (cold miss), loads it asynchronously from durable storage via spawn_blocking,
    /// avoiding synchronous disk I/O under the cache write lock (A05-01).
    /// Uses `entry().or_insert()` to ensure concurrent mutations are never overwritten.
    pub async fn ensure_vip_quota_cached(
        &self,
        account_tag: &[u8; 32],
    ) -> Result<(), IngressError> {
        if self.vip_quota_cache.read().contains_key(account_tag) {
            return Ok(());
        }
        let storage = self.storage.clone();
        let tag = *account_tag;
        let bal = tokio::task::spawn_blocking(move || storage.get_quota(&tag))
            .await
            .map_err(|e| {
                IngressError::Storage(StorageError::Io(std::io::Error::other(e.to_string())))
            })?
            .map_err(IngressError::Storage)?;
        self.vip_quota_cache.write().entry(*account_tag).or_insert(bal);
        Ok(())
    }

    /// In-memory atomic check-and-charge for VIP quota (hot-path, <1µs, no fsync stall).
    /// Enforces Reservation-First: reserves persistence capacity BEFORE mutating RAM balance (A02-02).
    /// Dispatches permit into FIFO channel BEFORE dropping cache write lock to preserve strict ordering.
    pub fn try_charge_vip_in_memory(
        &self,
        account_tag: &[u8; 32],
        required: u64,
    ) -> Result<u64, IngressError> {
        let mut cache = self.vip_quota_cache.write();
        let bal = cache.entry(*account_tag).or_insert(0);
        if *bal < required {
            return Err(IngressError::QuotaExceeded {
                available: *bal,
                required,
            });
        }
        let permit = self
            .vip_persist_tx
            .try_reserve()
            .map_err(|_| IngressError::QuotaPersistenceUnavailable)?;
        *bal -= required;
        let remaining = *bal;
        permit.send(VipQuotaPersistOp {
            account_tag: *account_tag,
            remaining,
        });
        drop(cache);
        Ok(remaining)
    }

    /// Returns a reference to the decentralized network thermometer (Spec 09).
    pub fn thermometer(&self) -> Arc<RwLock<NetworkThermometer>> {
        self.thermometer.clone()
    }

    /// [INV-0907]
    /// Initializes the thermometer of a new node with the current peer median
    pub fn seed_from_peers(&self, peer_median: u64) {
        self.thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .seed_from_peers(peer_median);
    }

    /// [INV-0908]
    /// Fast re-seed on network merges (e.g., village A docks into the global mesh)
    pub fn fast_reseed_on_merge(&self, global_median: u64) {
        self.thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .fast_reseed_on_merge(global_median);
    }

    /// [INV-0922] Records a daily median in the 28-day slotted ring buffer
    pub fn record_daily_median(&self, median: u64) {
        self.thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .record_daily_median(median);
    }

    /// Returns the rolling 24-hour write daily rate in Byte-Years
    pub fn rolling_24h_average(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .rolling_24h_average()
    }

    /// Returns the rolling 24-hour write daily rate in Byte-Years at a specific second
    pub fn rolling_24h_average_at(&self, now_sec: u64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .rolling_24h_average_at(now_sec)
    }

    /// Returns the current raw write EMA in micro-Byte-Years (µBJ)
    pub fn current_write_ema_micro_bj(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .current_write_ema_micro_bj()
    }

    /// Returns the current raw read EMA in credits
    pub fn current_read_ema_credits(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .current_read_ema_credits()
    }

    /// Returns the current rolling 24-hour read daily rate in credits
    pub fn rolling_24h_read_average(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .rolling_24h_read_average()
    }

    /// Returns the rolling 24-hour read daily rate in credits at a specific second
    pub fn rolling_24h_read_average_at(&self, now_sec: u64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .rolling_24h_read_average_at(now_sec)
    }

    /// [INV-0923] Records a daily read median
    pub fn record_daily_read_median(&self, median: u64) {
        self.thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .record_daily_read_median(median);
    }

    /// [INV-0903/0904] Autonomous thermometer day roll-over (Spec 09 Phase 9 P1).
    ///
    /// Called periodically by the daemon ticker (hourly in production, fast in
    /// simulation mode). On epoch-day change (`now_ms / 86_400_000`) the locally
    /// measured 24h rolling rates are rotated into the 28-day slotted ring
    /// buffer so the moving median stays autonomous without manual intervention.
    ///
    /// Returns `Some(new_day)` when at least one daily slot was rotated,
    /// otherwise `None` (same day or cold-start init). Never fails; purely
    /// local time-based progression, no I/O, no peer telemetry coupling.
    pub fn advance_epoch_day(&self, now_ms: u64) -> Option<u64> {
        let day = self.current_epoch_day_at(now_ms);
        let last = self.last_thermometer_day.load(Ordering::Relaxed);
        if last == 0 {
            // Cold-start init: anchor to current day without recording a spurious median.
            let _ = self.last_thermometer_day.compare_exchange(
                0,
                day,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
            return None;
        }
        if day <= last {
            return None;
        }
        // Claim exactly one day-step at a time to avoid duplicate rotation under concurrency.
        if self
            .last_thermometer_day
            .compare_exchange(last, day, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        let now_sec = now_ms / 1000;
        let write_median = self.rolling_24h_average_at(now_sec);
        let read_median = self.rolling_24h_read_average_at(now_sec);
        // Catch up missed days (offline / downtime) in a bounded way (max 28 slots).
        let missed = (day.saturating_sub(last)).clamp(1, 28);
        for _ in 0..missed {
            self.record_daily_median(write_median);
            self.record_daily_read_median(read_median);
        }
        Some(day)
    }

    /// Returns the last thermometer day that was rotated into the ring buffer (0 = not yet anchored).
    pub fn last_thermometer_day(&self) -> u64 {
        self.last_thermometer_day.load(Ordering::Relaxed)
    }

    /// [INV-0924] Calculates effective reference value NCB_eff = max(Moving_Median, HARD_FLOOR_BASELINE_DAILY)
    pub fn effective_ncb(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .effective_ncb()
    }

    /// [INV-0925] Calculates effective reference value NCB_read_eff = max(Moving_Read_Median, HARD_FLOOR_READ_BASELINE_DAILY)
    pub fn effective_read_ncb(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .effective_read_ncb()
    }

    /// Calculates dynamic daily quota with 5x Whale Brake K <= 5.0 (Spec 09)
    pub fn calculate_daily_quota(&self, k_multiplier: f64, spread_damper: f64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .calculate_daily_quota(k_multiplier, spread_damper)
    }

    /// [INV-0927] Calculates daily read quota for a node:
    /// Read_Quota = NCB_read_eff * min(K, 5.0) * Spread_Damper
    pub fn calculate_daily_read_quota(&self, k_multiplier: f64, spread_damper: f64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .calculate_daily_read_quota(k_multiplier, spread_damper)
    }

    /// [INV-0928] Evaluates read quota for a client: Returns `Ok(())` if the read is within the daily budget.
    /// Returns `Err(IngressError::ReadQuotaExceeded)` if the budget is exceeded (silent dropping).
    pub fn evaluate_read_quota(
        &self,
        client_id: NodeId,
        credits: u64,
        epoch_day: u64,
        k_multiplier: f64,
    ) -> Result<(), IngressError> {
        self.evaluate_read_quota_with_time(client_id, credits, epoch_day, k_multiplier, None)
    }

    pub fn evaluate_read_quota_with_time(
        &self,
        client_id: NodeId,
        credits: u64,
        epoch_day: u64,
        k_multiplier: f64,
        now_ms: Option<u64>,
    ) -> Result<(), IngressError> {
        let daily_quota = self.calculate_daily_read_quota(k_multiplier, 1.0);
        let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
        if thermo.try_accept_read(epoch_day, client_id, credits, daily_quota) {
            let now_sec = match now_ms {
                Some(ms) => ms / 1000,
                None => epoch_day * 86_400,
            };
            thermo.record_read_ingress(now_sec, credits);
            Ok(())
        } else {
            let used = thermo.get_node_read_usage(client_id);
            let available = daily_quota.saturating_sub(used);
            Err(IngressError::ReadQuotaExceeded {
                available,
                required: credits,
            })
        }
    }

    /// Returns the epoch day since UNIX epoch for a given timestamp in milliseconds
    pub fn current_epoch_day_at(&self, now_ms: u64) -> u64 {
        now_ms / (86_400 * 1000)
    }

    /// Returns the current epoch day since UNIX epoch (using system time as fallback)
    pub fn current_epoch_day(&self) -> u64 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.current_epoch_day_at(now_ms)
    }

    /// Evaluates and registers dynamic ingress for F2F peers against daily quota (K=1.0)
    pub fn evaluate_f2f_quota(
        &self,
        peer_token: &str,
        required_byte_years: u64,
        epoch_day: u64,
    ) -> Result<(), IngressError> {
        let token_hash = *blake3::hash(peer_token.as_bytes()).as_bytes();
        let daily_quota = self.calculate_daily_quota(1.0, 1.0);
        let mut f2f_usage = self
            .f2f_daily_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if f2f_usage.0 != epoch_day {
            f2f_usage.0 = epoch_day;
            f2f_usage.1.clear();
        }
        let current_usage = f2f_usage.1.entry(token_hash).or_insert(0);
        if let Some(new_usage) = current_usage.checked_add(required_byte_years) {
            if new_usage <= daily_quota {
                *current_usage = new_usage;
                Ok(())
            } else {
                let available = daily_quota.saturating_sub(*current_usage);
                Err(IngressError::QuotaExceeded {
                    available,
                    required: required_byte_years,
                })
            }
        } else {
            Err(IngressError::QuotaExceeded {
                available: 0,
                required: required_byte_years,
            })
        }
    }

    /// Evaluates and registers dynamic ingress for VIP accounts against daily quota with 5x Whale Brake (K <= 5.0)
    pub fn evaluate_vip_quota(
        &self,
        account_tag: &[u8; 32],
        required_byte_years: u64,
        epoch_day: u64,
        k_multiplier: f64,
    ) -> Result<(), IngressError> {
        let daily_quota =
            self.calculate_daily_quota(k_multiplier.clamp(0.0, MAX_WHALE_MULTIPLIER), 1.0);
        let mut vip_usage = self
            .vip_daily_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if vip_usage.0 != epoch_day {
            vip_usage.0 = epoch_day;
            vip_usage.1.clear();
        }
        let current_usage = vip_usage.1.entry(*account_tag).or_insert(0);
        if let Some(new_usage) = current_usage.checked_add(required_byte_years) {
            if new_usage <= daily_quota {
                *current_usage = new_usage;
                Ok(())
            } else {
                let available = daily_quota.saturating_sub(*current_usage);
                Err(IngressError::QuotaExceeded {
                    available,
                    required: required_byte_years,
                })
            }
        } else {
            Err(IngressError::QuotaExceeded {
                available: 0,
                required: required_byte_years,
            })
        }
    }

    /// Evaluates and registers dynamic ingress for a network node against the 5x Whale Brake daily write limit.
    ///
    /// W4 (Audit 19): Sender-specific P2P write budgets are isolated by full 32-byte `NodePubKey`
    /// in `p2p_node_usage`, preventing 16-bit prefix contention across distinct network nodes.
    pub fn evaluate_node_write_quota(
        &self,
        sender_pubkey: &[u8; 32],
        required_byte_years: u64,
        epoch_day: u64,
    ) -> Result<(), IngressError> {
        let daily_quota = self.calculate_daily_quota(MAX_WHALE_MULTIPLIER, 1.0);
        let mut p2p_usage = self
            .p2p_node_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if p2p_usage.0 != epoch_day {
            p2p_usage.0 = epoch_day;
            p2p_usage.1.clear();
        }
        let current_usage = p2p_usage.1.entry(*sender_pubkey).or_insert(0);
        if let Some(new_usage) = current_usage.checked_add(required_byte_years) {
            if new_usage <= daily_quota {
                *current_usage = new_usage;
                drop(p2p_usage);
                Ok(())
            } else {
                let available = daily_quota.saturating_sub(*current_usage);
                Err(IngressError::QuotaExceeded {
                    available,
                    required: required_byte_years,
                })
            }
        } else {
            Err(IngressError::QuotaExceeded {
                available: 0,
                required: required_byte_years,
            })
        }
    }

    /// Refunds previously evaluated node write quota on duplicate idempotent retry or failed admission.
    pub fn refund_node_write_quota(
        &self,
        sender_pubkey: &[u8; 32],
        byte_years: u64,
        epoch_day: u64,
    ) {
        let mut p2p_usage = self
            .p2p_node_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if p2p_usage.0 == epoch_day {
            if let Some(usage) = p2p_usage.1.get_mut(sender_pubkey) {
                *usage = usage.saturating_sub(byte_years);
            }
        }
    }

    /// Evaluates and registers dynamic ingress for a network node against the 5x Whale Brake daily read limit.
    ///
    /// W4 (Audit 19): Sender-specific P2P read credits are isolated by full 32-byte `NodePubKey`
    /// in `p2p_node_read_usage`, preventing 16-bit prefix contention across distinct network nodes.
    pub fn evaluate_node_read_quota(
        &self,
        sender_pubkey: &[u8; 32],
        required_credits: u64,
        epoch_day: u64,
    ) -> Result<(), IngressError> {
        let daily_read_quota = self.calculate_daily_read_quota(MAX_WHALE_MULTIPLIER, 1.0);
        let mut p2p_read_usage = self
            .p2p_node_read_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if p2p_read_usage.0 != epoch_day {
            p2p_read_usage.0 = epoch_day;
            p2p_read_usage.1.clear();
        }
        let current_usage = p2p_read_usage.1.entry(*sender_pubkey).or_insert(0);
        if let Some(new_usage) = current_usage.checked_add(required_credits) {
            if new_usage <= daily_read_quota {
                *current_usage = new_usage;
                drop(p2p_read_usage);
                Ok(())
            } else {
                let available = daily_read_quota.saturating_sub(*current_usage);
                Err(IngressError::ReadQuotaExceeded {
                    available,
                    required: required_credits,
                })
            }
        } else {
            Err(IngressError::ReadQuotaExceeded {
                available: 0,
                required: required_credits,
            })
        }
    }

    /// Registers an auth token associated with a specific VIP account tag.
    pub fn register_vip_token(&self, token: impl Into<String>, account_tag: [u8; 32]) {
        let token_str = token.into();
        self.vip_tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token_str, account_tag);
        self.register_vip_tag(account_tag);
    }

    /// Registers an authorized VIP account tag directly.
    /// Idempotent with respect to cached balance: preserves an already-initialized or mutated balance.
    pub fn register_vip_tag(&self, account_tag: [u8; 32]) {
        self.vip_tags
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(account_tag);
        if !self.vip_quota_cache.read().contains_key(&account_tag) {
            if let Ok(bal) = self.storage.get_quota(&account_tag) {
                if bal > 0 {
                    self.vip_quota_cache
                        .write()
                        .entry(account_tag)
                        .or_insert(bal);
                }
            }
        }
    }

    /// Registers a trusted F2F client with optional friendly label and stores metadata.
    pub fn register_f2f_client(&self, token: &str, label: Option<&str>) {
        let token_trimmed = token.trim();
        let token_hash = hex::encode(blake3::hash(token_trimmed.as_bytes()).as_bytes());
        let client_label = match label {
            Some(l) if !l.trim().is_empty() => l.trim().to_string(),
            _ => format!("Client-{}", &token_hash[..8]),
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let meta = F2fClientMeta {
            token: token_trimmed.to_string(),
            token_hash: token_hash.clone(),
            label: client_label,
            registered_at_ms: now_ms,
            last_active_ms: None,
        };

        self.f2f_clients
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token_hash, meta);
        self.f2f_tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token_trimmed.to_string());
    }

    /// Registers a trusted F2F peer token.
    pub fn register_f2f_peer(&self, token: impl Into<String>) {
        let token_str = token.into();
        self.register_f2f_client(&token_str, None);
    }

    /// Removes an F2F client by token string or token hash. Returns true if removed.
    pub fn remove_f2f_client(&self, token_or_hash: &str) -> bool {
        let target = token_or_hash.trim();
        let mut clients = self.f2f_clients.write().unwrap_or_else(|e| e.into_inner());
        let mut tokens = self.f2f_tokens.write().unwrap_or_else(|e| e.into_inner());

        let mut found_hash = None;
        let mut found_token = None;

        for (h, meta) in clients.iter() {
            if h == target || meta.token == target {
                found_hash = Some(h.clone());
                found_token = Some(meta.token.clone());
                break;
            }
        }

        if let Some(h) = found_hash {
            clients.remove(&h);
            if let Some(t) = found_token {
                tokens.remove(&t);
            }
            true
        } else {
            tokens.remove(target)
        }
    }

    /// Lists all registered F2F clients with their today's writes and quota status.
    pub fn list_f2f_clients(&self, now_ms: u64, epoch_day: u64) -> Vec<F2fClientDto> {
        let clients = self.f2f_clients.read().unwrap_or_else(|e| e.into_inner());
        let daily_limit = self.calculate_daily_quota(1.0, 1.0);
        let f2f_usage = self
            .f2f_daily_usage
            .read()
            .unwrap_or_else(|e| e.into_inner());

        let mut list = Vec::with_capacity(clients.len());
        for meta in clients.values() {
            let token_hash = *blake3::hash(meta.token.as_bytes()).as_bytes();
            let writes_today = if f2f_usage.0 == epoch_day {
                f2f_usage.1.get(&token_hash).copied().unwrap_or(0)
            } else {
                0
            };
            let whale_brake_active = writes_today >= daily_limit;
            let last_active_sec = meta.last_active_ms.map(|t| now_ms.saturating_sub(t) / 1000);

            list.push(F2fClientDto {
                token_hash: meta.token_hash.clone(),
                label: meta.label.clone(),
                writes_today,
                daily_limit,
                whale_brake_active,
                last_active_sec,
                token: None,
            });
        }

        list.sort_by(|a, b| a.label.cmp(&b.label));
        list
    }

    /// [INV-0929] Evaluates tier credentials, validates authorization, deducts quota (for VIP), or validates PoW (for Public).
    pub async fn evaluate_and_charge(
        &self,
        auth_token: Option<&str>,
        peer_token: Option<&str>,
        pow_challenge: Option<&str>,
        pow_nonce: Option<u64>,
        ttl_seconds: u64,
        parent_lock: Option<&[u8; 32]>,
    ) -> Result<IngressTier, IngressError> {
        self.evaluate_and_charge_with_time(
            auth_token,
            peer_token,
            pow_challenge,
            pow_nonce,
            ttl_seconds,
            parent_lock,
            None,
        )
        .await
    }

    /// [INV-0929] Evaluates tier credentials with decentralized network time, validates authorization, deducts quota (for VIP), or validates PoW (for Public).
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_and_charge_with_time(
        &self,
        auth_token: Option<&str>,
        peer_token: Option<&str>,
        pow_challenge: Option<&str>,
        pow_nonce: Option<u64>,
        ttl_seconds: u64,
        parent_lock: Option<&[u8; 32]>,
        now_ms: Option<u64>,
    ) -> Result<IngressTier, IngressError> {
        self.evaluate_and_charge_with_time_and_retry(
            auth_token,
            peer_token,
            pow_challenge,
            pow_nonce,
            ttl_seconds,
            parent_lock,
            now_ms,
            false,
        )
        .await
    }

    /// [INV-0929] Evaluates tier credentials with decentralized network time, validates authorization,
    /// deducts quota (for VIP non-retries), or validates PoW (for Public).
    /// When `is_retry` is true, validates credentials and rate admission without double-charging storage or daily writes.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_and_charge_with_time_and_retry(
        &self,
        auth_token: Option<&str>,
        peer_token: Option<&str>,
        pow_challenge: Option<&str>,
        pow_nonce: Option<u64>,
        ttl_seconds: u64,
        parent_lock: Option<&[u8; 32]>,
        now_ms: Option<u64>,
        is_retry: bool,
    ) -> Result<IngressTier, IngressError> {
        let now_sec = match now_ms {
            Some(ms) => ms / 1000,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let footprint_micro_bj = ByteYears::micro_from_ttl_seconds(ttl_seconds);

        // 1. Check Tier 1 (VIP) - in-memory atomic cache, no synchronous fsync stall (INV-0929 hot-path)
        if let Some(token) = auth_token {
            let account_tag = self.resolve_account_tag(token)?;
            let epoch_day = match now_ms {
                Some(ms) => self.current_epoch_day_at(ms),
                None => self.current_epoch_day(),
            };
            let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
            let daily_quota = self.calculate_daily_quota(5.0, 1.0);

            if is_retry {
                let vip_usage = self
                    .vip_daily_usage
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                let used = if vip_usage.0 == epoch_day {
                    vip_usage.1.get(&account_tag).copied().unwrap_or(0)
                } else {
                    0
                };
                if used >= daily_quota {
                    let available = daily_quota.saturating_sub(used);
                    return Err(IngressError::QuotaExceeded {
                        available,
                        required: required_byte_years,
                    });
                }
                return Ok(IngressTier::Tier1Vip);
            }

            // Hydrate cold miss asynchronously before acquiring write lock (A05-01)
            self.ensure_vip_quota_cached(&account_tag).await?;

            // 1. Check daily quota first
            let mut vip_usage = self
                .vip_daily_usage
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if vip_usage.0 != epoch_day {
                vip_usage.0 = epoch_day;
                vip_usage.1.clear();
            }
            let current_usage = vip_usage.1.get(&account_tag).copied().unwrap_or(0);
            let new_usage = match current_usage.checked_add(required_byte_years) {
                Some(n) if n <= daily_quota => n,
                _ => {
                    let available = daily_quota.saturating_sub(current_usage);
                    return Err(IngressError::QuotaExceeded {
                        available,
                        required: required_byte_years,
                    });
                }
            };

            // 2. Check purchased credit balance in RAM cache
            let mut cache = self.vip_quota_cache.write();
            let bal = cache.entry(account_tag).or_insert(0);
            if *bal < required_byte_years {
                return Err(IngressError::QuotaExceeded {
                    available: *bal,
                    required: required_byte_years,
                });
            }

            // 3. Reserve persistence capacity BEFORE mutating RAM balance (A02-02)
            let permit = self
                .vip_persist_tx
                .try_reserve()
                .map_err(|_| IngressError::QuotaPersistenceUnavailable)?;

            // 4. All checks passed! Apply all mutations atomically with zero partial state on errors
            *bal = bal.saturating_sub(required_byte_years);
            let remaining = *bal;
            permit.send(VipQuotaPersistOp {
                account_tag,
                remaining,
            });
            drop(cache);

            vip_usage.1.insert(account_tag, new_usage);
            drop(vip_usage);

            self.vip_writes_today.fetch_add(1, Ordering::Relaxed);
            self.thermometer
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .record_write_ingress(now_sec, footprint_micro_bj);

            return Ok(IngressTier::Tier1Vip);
        }

        // 2. Check Tier 2 (F2F Peer) with Spec 09 dynamic daily quota
        if let Some(token) = peer_token {
            let token_trimmed = token.trim();
            let is_valid = self
                .f2f_tokens
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains(token_trimmed);
            if !is_valid {
                return Err(IngressError::InvalidPeerToken);
            }

            let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
            let epoch_day = match now_ms {
                Some(ms) => self.current_epoch_day_at(ms),
                None => self.current_epoch_day(),
            };
            let token_hash = *blake3::hash(token_trimmed.as_bytes()).as_bytes();
            let daily_quota = self.calculate_daily_quota(1.0, 1.0);

            let token_hash_hex = hex::encode(token_hash);
            let activity_ms = match now_ms {
                Some(ms) => ms,
                None => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            };
            if let Some(meta) = self
                .f2f_clients
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&token_hash_hex)
            {
                meta.last_active_ms = Some(activity_ms);
            }

            if is_retry {
                let f2f_usage = self
                    .f2f_daily_usage
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                let used = if f2f_usage.0 == epoch_day {
                    f2f_usage.1.get(&token_hash).copied().unwrap_or(0)
                } else {
                    0
                };
                if used >= daily_quota {
                    let available = daily_quota.saturating_sub(used);
                    return Err(IngressError::QuotaExceeded {
                        available,
                        required: required_byte_years,
                    });
                }
                return Ok(IngressTier::Tier2F2F);
            }

            self.evaluate_f2f_quota(token_trimmed, required_byte_years, epoch_day)?;
            self.f2f_writes_today.fetch_add(1, Ordering::Relaxed);
            self.thermometer
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .record_write_ingress(now_sec, footprint_micro_bj);

            return Ok(IngressTier::Tier2F2F);
        }

        // 3. Check Tier 3 (Public - BLAKE3 PoW)
        let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
        let epoch_day = match now_ms {
            Some(ms) => self.current_epoch_day_at(ms),
            None => self.current_epoch_day(),
        };
        let p = parent_lock.copied().unwrap_or([0u8; 32]);
        let daily_quota = self.calculate_daily_quota(1.0, 1.0);

        if self.pow_engine.default_difficulty() == 0 {
            if is_retry {
                let free_usage = self
                    .free_daily_usage
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                let used = if free_usage.0 == epoch_day {
                    free_usage.1.get(&p).copied().unwrap_or(0)
                } else {
                    0
                };
                if used >= daily_quota {
                    let available = daily_quota.saturating_sub(used);
                    return Err(IngressError::QuotaExceeded {
                        available,
                        required: required_byte_years,
                    });
                }
                return Ok(IngressTier::Tier3Public);
            }

            let mut free_usage = self
                .free_daily_usage
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if free_usage.0 != epoch_day {
                free_usage.0 = epoch_day;
                free_usage.1.clear();
            }
            let current_usage = free_usage.1.entry(p).or_insert(0);
            if let Some(new_usage) = current_usage.checked_add(required_byte_years) {
                if new_usage <= daily_quota {
                    *current_usage = new_usage;
                    drop(free_usage);
                    self.free_writes_today.fetch_add(1, Ordering::Relaxed);
                    self.thermometer
                        .write()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_write_ingress(now_sec, footprint_micro_bj);
                    return Ok(IngressTier::Tier3Public);
                } else {
                    let available = daily_quota.saturating_sub(*current_usage);
                    return Err(IngressError::QuotaExceeded {
                        available,
                        required: required_byte_years,
                    });
                }
            } else {
                return Err(IngressError::QuotaExceeded {
                    available: 0,
                    required: required_byte_years,
                });
            }
        }

        let load_factor = (self.rolling_24h_average_at(now_sec) as f64
            / self.effective_ncb().max(1) as f64)
            .clamp(0.0, 1.0);
        let dynamic_difficulty = self.pow_engine.required_difficulty_for_load(load_factor);

        match (pow_challenge, pow_nonce) {
            (Some(challenge), Some(nonce)) => {
                self.pow_engine
                    .verify_pow_for_parent(challenge, nonce, dynamic_difficulty, parent_lock)
                    .await?;

                if is_retry {
                    let free_usage = self
                        .free_daily_usage
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    let used = if free_usage.0 == epoch_day {
                        free_usage.1.get(&p).copied().unwrap_or(0)
                    } else {
                        0
                    };
                    if used >= daily_quota {
                        let available = daily_quota.saturating_sub(used);
                        return Err(IngressError::QuotaExceeded {
                            available,
                            required: required_byte_years,
                        });
                    }
                    return Ok(IngressTier::Tier3Public);
                }

                let mut free_usage = self
                    .free_daily_usage
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                if free_usage.0 != epoch_day {
                    free_usage.0 = epoch_day;
                    free_usage.1.clear();
                }
                let current_usage = free_usage.1.entry(p).or_insert(0);
                if let Some(new_usage) = current_usage.checked_add(required_byte_years) {
                    if new_usage <= daily_quota {
                        *current_usage = new_usage;
                        drop(free_usage);
                        self.free_writes_today.fetch_add(1, Ordering::Relaxed);
                        self.thermometer
                            .write()
                            .unwrap_or_else(|e| e.into_inner())
                            .record_write_ingress(now_sec, footprint_micro_bj);
                        Ok(IngressTier::Tier3Public)
                    } else {
                        let available = daily_quota.saturating_sub(*current_usage);
                        Err(IngressError::QuotaExceeded {
                            available,
                            required: required_byte_years,
                        })
                    }
                } else {
                    Err(IngressError::QuotaExceeded {
                        available: 0,
                        required: required_byte_years,
                    })
                }
            }
            _ => {
                let (challenge, _, expires_at) = self.pow_engine.generate_challenge_for_parent(&p);
                Err(IngressError::PoWRequired {
                    challenge,
                    difficulty: dynamic_difficulty,
                    expires_at,
                })
            }
        }
    }

    /// Resolves an account tag from an auth token.
    /// ONLY registered bearer secrets in `vip_tokens` can authenticate VIP ingress.
    /// Diagnostic IDs, hex representations, and unauthorized strings are strictly rejected.
    pub fn resolve_account_tag(&self, token: &str) -> Result<[u8; 32], IngressError> {
        // Strip optional "Bearer " prefix
        let token_cleaned = token.strip_prefix("Bearer ").unwrap_or(token).trim();

        // 1. Check registered token map
        if let Some(tag) = self
            .vip_tokens
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(token_cleaned)
        {
            return Ok(*tag);
        }

        Err(IngressError::InvalidAuthToken)
    }

    /// Returns the current epoch day and recorded VIP usage for the given account tag (for test assertion).
    pub fn vip_daily_usage_for_test(&self, account_tag: &[u8; 32]) -> (u64, u64) {
        let guard = self.vip_daily_usage.read().unwrap_or_else(|e| e.into_inner());
        let usage = guard.1.get(account_tag).copied().unwrap_or(0);
        (guard.0, usage)
    }

    /// Reserves a VIP persistence permit to simulate channel saturation for testing.
    /// Dropping the returned guard releases the permit back to the queue.
    pub fn reserve_persist_permit_for_test(&self) -> Option<Box<dyn std::any::Any + Send>> {
        self.vip_persist_tx
            .clone()
            .try_reserve_owned()
            .ok()
            .map(|permit| Box::new(permit) as Box<dyn std::any::Any + Send>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_tier_controller_vip_quota_deduction() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let controller = TierController::new(storage.clone(), pow);

        let account_tag = [0x55u8; 32];
        let token = "vip_secret_token_123";
        controller.register_vip_token(token, account_tag);

        // Initial quota: 1000 Byte-Years
        storage.set_quota(&account_tag, 1000).unwrap();

        // 1 Year TTL = 192 Byte-Years
        let tier = controller
            .evaluate_and_charge(Some(token), None, None, None, 31_536_000, None)
            .await
            .expect("VIP access");

        assert_eq!(tier, IngressTier::Tier1Vip);
        // In-memory cache must reflect deduction atomically (<1µs, no fsync stall)
        assert_eq!(
            controller.get_cached_vip_quota(&account_tag),
            Some(1000 - 192)
        );
        // Durable storage is updated asynchronously; wait for background persist
        for _ in 0..60 {
            if storage.get_quota(&account_tag).unwrap() == 1000 - 192 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(storage.get_quota(&account_tag).unwrap(), 1000 - 192);

        // Exceed quota
        let result = controller
            .evaluate_and_charge(
                Some(token),
                None,
                None,
                None,
                31_536_000 * 5, // 5 years = 960 BY, available is 808
                None,
            )
            .await;
        assert!(matches!(result, Err(IngressError::QuotaExceeded { .. })));
    }

    #[tokio::test]
    async fn test_tier_controller_f2f_peer() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_f2f.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let controller = TierController::new(storage, pow);
        controller.register_f2f_peer("friend_node_token_abc");

        let tier = controller
            .evaluate_and_charge(None, Some("friend_node_token_abc"), None, None, 60, None)
            .await
            .expect("F2F access");
        assert_eq!(tier, IngressTier::Tier2F2F);

        let err = controller
            .evaluate_and_charge(None, Some("unknown_peer"), None, None, 60, None)
            .await;
        assert!(matches!(err, Err(IngressError::InvalidPeerToken)));
    }

    #[tokio::test]
    async fn test_tier_controller_public_pow() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_pow.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let controller = TierController::new(storage, pow.clone());

        // Without PoW -> PoWRequired
        let err = controller
            .evaluate_and_charge(None, None, None, None, 60, None)
            .await;
        let challenge = match err {
            Err(IngressError::PoWRequired {
                challenge,
                difficulty,
                ..
            }) => {
                assert_eq!(difficulty, 8);
                challenge
            }
            _ => panic!("Expected PoWRequired"),
        };

        // Solve PoW
        let nonce = PowEngine::solve_pow(&challenge, 8, 5000).expect("Solve");
        let tier = controller
            .evaluate_and_charge(None, None, Some(&challenge), Some(nonce), 60, None)
            .await
            .expect("PoW accepted");
        assert_eq!(tier, IngressTier::Tier3Public);
    }

    #[tokio::test]
    async fn test_tier_controller_network_thermometer_seeding_and_fast_reseed() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_thermo.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let controller = TierController::new(storage, pow);

        // Initial state: default hard floor baseline
        assert_eq!(controller.effective_ncb(), 960_000);

        // Kaltstart / Seed from peers
        controller.seed_from_peers(2_000_000);
        assert_eq!(controller.effective_ncb(), 2_000_000);

        // Fast-Re-Seed on merge (z.B. Dorf dockt an Weltnetz an)
        controller.fast_reseed_on_merge(10_000_000);
        assert_eq!(controller.effective_ncb(), 10_000_000);

        // Hard-Floor guarantee: seeding below hard floor cannot drop below baseline
        controller.seed_from_peers(100);
        assert_eq!(controller.effective_ncb(), 960_000);

        // Push daily medians to 28-day slotted ring buffer
        for _ in 0..28 {
            controller.record_daily_median(1_500_000);
        }
        assert_eq!(controller.effective_ncb(), 1_500_000);
    }

    #[tokio::test]
    async fn test_tier_controller_dynamic_f2f_and_vip_quotas_with_whale_brake() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_quotas.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let controller = TierController::new(storage, pow);

        // Baseline: 960_000
        let quota_standard = controller.calculate_daily_quota(1.0, 1.0);
        assert_eq!(quota_standard, 960_000);

        // Whale brake: K clamped to 5.0
        let quota_whale_k5 = controller.calculate_daily_quota(5.0, 1.0);
        assert_eq!(quota_whale_k5, 960_000 * 5);

        let quota_whale_k10 = controller.calculate_daily_quota(10.0, 1.0);
        assert_eq!(
            quota_whale_k10,
            960_000 * 5,
            "Whale brake must clamp K <= 5.0"
        );

        // F2F dynamic quota evaluation
        let peer_token = "peer_token_dynamic_123";
        controller.register_f2f_peer(peer_token);

        // 1 Year TTL = 192 Byte-Years, fits easily into 960_000
        let res = controller.evaluate_f2f_quota(peer_token, 192, 1);
        assert!(
            matches!(res, Ok(())),
            "F2F quota 192 must be Ok, got {:?}",
            res
        );

        // Exceed daily quota in single epoch day
        let res_exceed = controller.evaluate_f2f_quota(peer_token, 960_000, 1);
        assert!(matches!(
            res_exceed,
            Err(IngressError::QuotaExceeded { .. })
        ));

        // Next epoch day resets usage
        let res_next_day = controller.evaluate_f2f_quota(peer_token, 192, 2);
        assert!(
            matches!(res_next_day, Ok(())),
            "next day quota must reset, got {:?}",
            res_next_day
        );

        // VIP dynamic quota evaluation
        let vip_tag = [0x77u8; 32];
        let res_vip = controller.evaluate_vip_quota(&vip_tag, 960_000 * 4, 1, 5.0);
        assert!(
            matches!(res_vip, Ok(())),
            "VIP quota must be Ok, got {:?}",
            res_vip
        );

        // Exceeding K=5.0 limit for VIP
        let res_vip_exceed = controller.evaluate_vip_quota(&vip_tag, 960_000 * 2, 1, 5.0);
        assert!(matches!(
            res_vip_exceed,
            Err(IngressError::QuotaExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_tier_controller_f2f_client_registration_and_list() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_f2f_clients.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let controller = TierController::new(storage, pow);

        let token = "my_pos_terminal_token_xyz";
        controller.register_f2f_client(token, Some("Kasse-1"));

        let now_ms = 1_700_000_000_000;
        let epoch_day = controller.current_epoch_day_at(now_ms);

        let clients = controller.list_f2f_clients(now_ms, epoch_day);
        assert_eq!(clients.len(), 1);
        let c = &clients[0];
        assert_eq!(c.label, "Kasse-1");
        assert_eq!(c.writes_today, 0);
        assert_eq!(c.daily_limit, 960_000);
        assert!(!c.whale_brake_active);
        assert_eq!(c.last_active_sec, None);
        assert_eq!(c.token, None);

        // Perform an authenticated F2F write
        let tier = controller
            .evaluate_and_charge_with_time(None, Some(token), None, None, 60, None, Some(now_ms))
            .await
            .expect("F2F write allowed");
        assert_eq!(tier, IngressTier::Tier2F2F);

        // Check list after 10 seconds
        let clients_after = controller.list_f2f_clients(now_ms + 10_000, epoch_day);
        assert_eq!(clients_after.len(), 1);
        assert_eq!(clients_after[0].last_active_sec, Some(10));
    }

    #[tokio::test]
    async fn test_tier_controller_f2f_client_removal() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_f2f_remove.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let controller = TierController::new(storage, pow);

        let token = "removable_client_token";
        controller.register_f2f_client(token, Some("Kasse-Alt"));

        let token_hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());

        // Remove by hash
        assert!(controller.remove_f2f_client(&token_hash));
        assert_eq!(controller.list_f2f_clients(0, 0).len(), 0);

        // Re-register and remove by token
        controller.register_f2f_client(token, None);
        assert_eq!(controller.list_f2f_clients(0, 0).len(), 1);
        assert!(controller.remove_f2f_client(token));
        assert_eq!(controller.list_f2f_clients(0, 0).len(), 0);

        // Non-existent returns false
        assert!(!controller.remove_f2f_client("non_existent"));
    }

    #[tokio::test]
    async fn test_a02_02_vip_quota_saturation_no_credit_loss() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_a02_02.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let account_tag = [0x42u8; 32];
        let initial_balance = 2000u64;
        storage.set_quota(&account_tag, initial_balance).unwrap();

        let controller = TierController::new(storage.clone(), pow);
        controller.register_vip_tag(account_tag);

        // Channel capacity is 1,024. Without yielding to the background persistence worker,
        // synchronously attempt 1,025 charges of 1 unit each.
        let mut success_count = 0;
        let mut saturated = false;
        for _ in 0..1025 {
            match controller.try_charge_vip_in_memory(&account_tag, 1) {
                Ok(_) => success_count += 1,
                Err(IngressError::QuotaPersistenceUnavailable) => {
                    saturated = true;
                    break;
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }

        assert!(
            saturated,
            "1025th charge must trigger QuotaPersistenceUnavailable"
        );
        assert_eq!(
            success_count, 1024,
            "Exactly 1,024 charges must succeed before saturation"
        );

        // Crucial invariant: Rejected debit must NOT decrement RAM balance!
        let ram_balance = controller.get_cached_vip_quota(&account_tag).unwrap();
        assert_eq!(
            ram_balance,
            initial_balance - 1024,
            "RAM balance must reflect only accepted debits (2000 - 1024 = 976)"
        );

        // Allow FIFO persistence worker to drain
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if storage.get_quota(&account_tag).unwrap() == ram_balance {
                break;
            }
        }

        let disk_balance = storage.get_quota(&account_tag).unwrap();
        assert_eq!(
            disk_balance, ram_balance,
            "Persisted balance must match RAM balance exactly; no debits lost!"
        );

        // Restarting controller from same database must hydrate the exact balance
        let restored_pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let restored_controller = TierController::new(storage.clone(), restored_pow);
        assert_eq!(
            restored_controller.get_cached_vip_quota(&account_tag),
            Some(ram_balance),
            "Startup hydration must restore exact persisted balance"
        );
    }

    #[tokio::test]
    async fn test_a02_02_strict_fifo_ordering_under_concurrency() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_fifo.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let account_tag = [0x99u8; 32];
        storage.set_quota(&account_tag, 10_000).unwrap();

        let controller = Arc::new(TierController::new(storage.clone(), pow));
        controller.register_vip_tag(account_tag);

        let mut tasks = Vec::new();
        // Spawn 20 tasks: 10 performing debits, 10 performing top-ups
        for i in 0..20 {
            let tc = controller.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..20 {
                    if i % 2 == 0 {
                        let _ = tc.try_charge_vip_in_memory(&account_tag, 5);
                    } else {
                        let _ = tc.topup_vip_quota(account_tag, 5);
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }

        for task in tasks {
            task.await.unwrap();
        }

        let ram_balance = controller.get_cached_vip_quota(&account_tag).unwrap();

        // Wait for FIFO worker to drain
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if storage.get_quota(&account_tag).unwrap() == ram_balance {
                break;
            }
        }

        let disk_balance = storage.get_quota(&account_tag).unwrap();
        assert_eq!(
            disk_balance, ram_balance,
            "FIFO ordering guarantees persisted balance matches RAM balance after concurrent mutations"
        );
    }

    #[tokio::test]
    async fn test_a05_01_startup_hydration_and_cold_miss_async() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_hydration.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let tag1 = [0x01u8; 32];
        let tag2 = [0x02u8; 32];
        let tag3 = [0x03u8; 32];
        storage.set_quota(&tag1, 100).unwrap();
        storage.set_quota(&tag2, 200).unwrap();
        storage.set_quota(&tag3, 300).unwrap();

        // Startup hydration: all 3 accounts must be present in RAM immediately
        let controller = TierController::new(storage.clone(), pow);
        assert_eq!(controller.get_cached_vip_quota(&tag1), Some(100));
        assert_eq!(controller.get_cached_vip_quota(&tag2), Some(200));
        assert_eq!(controller.get_cached_vip_quota(&tag3), Some(300));

        // Cold miss: tag4 is added to storage directly, bypassing controller
        let tag4 = [0x04u8; 32];
        storage.set_quota(&tag4, 500).unwrap();
        assert_eq!(controller.get_cached_vip_quota(&tag4), None);

        // ensure_vip_quota_cached hydrates asynchronously via spawn_blocking without write-lock stall
        controller.ensure_vip_quota_cached(&tag4).await.unwrap();
        assert_eq!(controller.get_cached_vip_quota(&tag4), Some(500));

        // Normal charge succeeds
        let remaining = controller.try_charge_vip_in_memory(&tag4, 50).unwrap();
        assert_eq!(remaining, 450);
        assert_eq!(controller.get_cached_vip_quota(&tag4), Some(450));
    }
}
